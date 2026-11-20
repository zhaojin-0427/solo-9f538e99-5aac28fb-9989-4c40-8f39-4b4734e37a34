"""Evidence seals, time-window proofs and offline verification.

Trust model
-----------
At seal time the service snapshots one *committed* verified prefix inside a
single ``BEGIN IMMEDIATE`` transaction.  Every sealed handover gets a leaf
hash; leaves feed a Merkle root and a manifest hash.  Sparse "digests"
(power-of-two positions, O(log n) of the sealed entries) bind the manifest
hash, Merkle root, leaf count and break boundary to individual leaves; they
may be retained outside the database.

Proofs are self-describing envelopes whose ``proof_hash`` covers every field.
Each in-window entry / neighbor carries its full leaf fields plus a Merkle
authentication path, so a verifier can recompute every leaf hash and check
its membership under the retained root without any database access.
Empty-window adjacency is proven by *index contiguity* (``after.idx ==
before.idx + 1``; one-sided windows are checked against index 0 /
leaf_count), which mathematically rules out a hidden handover between the
neighbors.  Later corrections, withdrawals, restarts or a replaced database
cannot change the verdict for an existing seal.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone

from . import services
from .database import transaction
from .schemas import (
    MerkleStep,
    ProofDigest,
    ProofEnvelope,
    ProofEntry,
    ProofNeighbor,
    ProofResponse,
    SealDigestOut,
    SealResponse,
    VerifyRequest,
    VerifyResponse,
    WindowRequest,
    payload_hash_of,
    to_utc_iso,
    utcnow_iso,
)

_STORAGE_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
_LEAF_DOMAIN = "sealed-handover-v1"
_DIGEST_DOMAIN = "seal-digest-v1"
_NODE_DOMAIN = "merkle-node-v1"
_EMPTY_ROOT_DOMAIN = "merkle-empty-v1"
_MANIFEST_DOMAIN = "seal-manifest-v1"
_PROOF_DOMAIN = "window-proof-v1"


# Reuse the chain service's domain errors so main.py's handlers map them.
DomainConflict = services.DomainConflict
DomainValidation = services.DomainValidation


# --------------------------------------------------------------------------- #
# Canonical hashing helpers
# --------------------------------------------------------------------------- #
def _sha256_blob(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _parse_ts(text: str) -> datetime:
    return datetime.strptime(text, _STORAGE_FMT).replace(tzinfo=timezone.utc)


def _parse_iso_utc(text: str) -> datetime:
    """Parse either the fixed storage format or a generic ISO-8601 instant."""
    try:
        return _parse_ts(text)
    except ValueError:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            raise
        return dt.astimezone(timezone.utc)


def _is_sha256_hex(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _iso(dt: datetime) -> str:
    return to_utc_iso(dt.astimezone(timezone.utc))


def sparse_indices(n: int) -> list[int]:
    """0, 1, 3, 7, ... positions: count grows as O(log n)."""
    out: list[int] = []
    i = 0
    while i < n:
        out.append(i)
        i = i * 2 + 1
    return out


def leaf_payload(
    waybill_id: str,
    idx: int,
    seq: int,
    scan_id: str,
    revision: int,
    ts_text: str,
    giver: str,
    receiver: str,
) -> dict:
    return {
        "type": _LEAF_DOMAIN,
        "waybill_id": waybill_id,
        "idx": idx,
        "seq": seq,
        "scan_id": scan_id,
        "revision": revision,
        "ts_utc": ts_text,
        "giver": giver,
        "receiver": receiver,
    }


def compute_leaf_hash(
    waybill_id: str,
    idx: int,
    seq: int,
    scan_id: str,
    revision: int,
    ts_text: str,
    giver: str,
    receiver: str,
) -> str:
    return payload_hash_of(
        leaf_payload(waybill_id, idx, seq, scan_id, revision, ts_text, giver, receiver)
    )


def compute_digest_hash(
    manifest_hash: str,
    root_hash: str,
    leaf_count: int,
    waybill_id: str,
    seal_id: str,
    idx: int,
    leaf_hash: str,
    first_break_ts: str | None,
    break_reason: str | None,
) -> str:
    # The Merkle root, leaf count and break boundary are all part of the
    # digest pre-image, so retained summaries alone anchor them: a forged
    # root/count/boundary in a proof cannot validate offline.
    return payload_hash_of(
        {
            "type": _DIGEST_DOMAIN,
            "seal_id": seal_id,
            "waybill_id": waybill_id,
            "manifest_hash": manifest_hash,
            "root_hash": root_hash,
            "leaf_count": leaf_count,
            "idx": idx,
            "leaf_hash": leaf_hash,
            "first_break_ts": first_break_ts,
            "break_reason": break_reason,
        }
    )


def _hash_node(left: str, right: str) -> str:
    return _sha256_blob(
        _NODE_DOMAIN.encode("utf-8")
        + left.encode("utf-8")
        + right.encode("utf-8")
    )


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return _sha256_blob(_EMPTY_ROOT_DOMAIN.encode("utf-8"))
    level = list(leaves)
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_hash_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node promoted
        level = nxt
    return level[0]


def merkle_path(leaves: list[str], idx: int) -> list[MerkleStep]:
    """Authentication path: sibling hashes from the leaf up to the root."""
    if not (0 <= idx < len(leaves)):
        raise ValueError(f"idx {idx} out of range for {len(leaves)} leaves")
    path: list[MerkleStep] = []
    level = list(leaves)
    pos = idx
    while len(level) > 1:
        if pos % 2 == 0:  # current node is a left child
            if pos + 1 < len(level):
                path.append(MerkleStep(side="R", hash=level[pos + 1]))
            # odd promoted node: no sibling at this level
        else:
            path.append(MerkleStep(side="L", hash=level[pos - 1]))
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_hash_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
        pos //= 2
    return path


def eval_merkle_path(leaf_hash: str, path: list[MerkleStep]) -> str:
    node = leaf_hash
    for step in path:
        if step.side == "L":
            node = _hash_node(step.hash, node)
        else:
            node = _hash_node(node, step.hash)
    return node


def manifest_hash(
    waybill_id: str,
    seal_id: str,
    origin_party: str,
    leaf_count: int,
    root_hash: str,
    first_break_ts: str | None,
    break_reason: str | None,
    break_scan_ids: list[str],
    leaves: list[str],
) -> str:
    return payload_hash_of(
        {
            "type": _MANIFEST_DOMAIN,
            "seal_id": seal_id,
            "waybill_id": waybill_id,
            "origin_party": origin_party,
            "leaf_count": leaf_count,
            "root_hash": root_hash,
            "first_break_ts": first_break_ts,
            "break_reason": break_reason,
            "first_break_scan_ids": break_scan_ids,
            "leaves": leaves,
        }
    )


# --------------------------------------------------------------------------- #
# Seal creation / lookup
# --------------------------------------------------------------------------- #
def create_seal(conn: sqlite3.Connection, waybill_id: str) -> SealResponse:
    """Snapshot the current committed verified prefix into an immutable seal."""
    waybill = services.get_waybill(conn, waybill_id)  # 404 if waybill missing
    origin_party = waybill["origin_party"]

    # BEGIN IMMEDIATE + reads inside one transaction: the seal and any
    # interleaved scan submission can only meet at a committed boundary, and
    # a failed submission leaves no trace behind.
    with transaction(conn):
        chain = services.compute_chain(conn, waybill_id)
        verified = chain.verified_prefix
        n = len(verified)

        seal_id = secrets.token_hex(16)
        leaves: list[str] = []
        rows: list[tuple] = []
        for idx, scan in enumerate(verified):
            ts_text = _iso(scan.ts_utc)
            seq = idx + 1
            leaf_hash = compute_leaf_hash(
                waybill_id,
                idx,
                seq,
                scan.scan_id,
                scan.revision,
                ts_text,
                scan.giver,
                scan.receiver,
            )
            leaves.append(leaf_hash)
            rows.append((idx, seq, scan, ts_text, leaf_hash))

        root = merkle_root(leaves)

        if chain.chain_intact or not chain.unverified_scans:
            first_break_ts_text: str | None = None
            break_reason_value: str | None = None
            break_scan_ids: list[str] = []
        else:
            first_break_ts_text = _iso(chain.unverified_scans[0].ts_utc)
            break_reason_value = chain.break_reason.value
            break_scan_ids = list(chain.break_scan_ids)

        manifest = manifest_hash(
            waybill_id,
            seal_id,
            origin_party,
            n,
            root,
            first_break_ts_text,
            break_reason_value,
            break_scan_ids,
            leaves,
        )

        # Parent row first: seal_entries references seals(seal_id).
        conn.execute(
            "INSERT INTO seals (seal_id, waybill_id, sealed_at, manifest_hash, "
            "root_hash, entry_count, leaf_count, first_break_ts, break_reason, "
            "first_break_scan_ids) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                seal_id,
                waybill_id,
                utcnow_iso(),
                manifest,
                root,
                n,
                n,
                first_break_ts_text,
                break_reason_value,
                json.dumps(break_scan_ids),
            ),
        )

        kept = set(sparse_indices(n))
        digest_rows: list[SealDigestOut] = []
        for idx, seq, scan, ts_text, leaf_hash in rows:
            digest = (
                compute_digest_hash(
                    manifest,
                    root,
                    n,
                    waybill_id,
                    seal_id,
                    idx,
                    leaf_hash,
                    first_break_ts_text,
                    break_reason_value,
                )
                if idx in kept
                else None
            )
            conn.execute(
                "INSERT INTO seal_entries (seal_id, idx, seq, scan_id, revision, "
                "ts_utc, giver, receiver, leaf_hash, digest) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    seal_id,
                    idx,
                    seq,
                    scan.scan_id,
                    scan.revision,
                    ts_text,
                    scan.giver,
                    scan.receiver,
                    leaf_hash,
                    digest,
                ),
            )
            if digest is not None:
                digest_rows.append(
                    SealDigestOut(
                        idx=idx,
                        seq=seq,
                        ts_utc=_parse_ts(ts_text),
                        scan_id=scan.scan_id,
                        leaf_hash=leaf_hash,
                        digest=digest,
                    )
                )

    return SealResponse(
        seal_id=seal_id,
        waybill_id=waybill_id,
        sealed_at=datetime.now(timezone.utc),
        entry_count=n,
        leaf_count=n,
        manifest_hash=manifest,
        root_hash=root,
        first_break_ts=(
            _parse_ts(first_break_ts_text) if first_break_ts_text else None
        ),
        break_reason=(chain.break_reason if break_reason_value else None),
        first_break_scan_ids=break_scan_ids,
        requested_digests=digest_rows,
    )


def _get_seal_row(conn: sqlite3.Connection, seal_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM seals WHERE seal_id = ?", (seal_id,)
    ).fetchone()
    if row is None:
        raise DomainValidation(f"seal {seal_id!r} not found")
    return row


def _get_seal_entries(conn: sqlite3.Connection, seal_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT idx, seq, scan_id, revision, ts_utc, giver, receiver, leaf_hash, digest "
        "FROM seal_entries WHERE seal_id = ? ORDER BY idx ASC",
        (seal_id,),
    ).fetchall()


def get_seal(conn: sqlite3.Connection, waybill_id: str, seal_id: str) -> SealResponse:
    seal = _get_seal_row(conn, seal_id)
    if seal["waybill_id"] != waybill_id:
        # Do not reveal seals belonging to another waybill.
        raise DomainValidation(f"seal {seal_id!r} not found")
    entries = _get_seal_entries(conn, seal_id)
    digests = [
        SealDigestOut(
            idx=e["idx"],
            seq=e["seq"],
            ts_utc=_parse_ts(e["ts_utc"]),
            scan_id=e["scan_id"],
            leaf_hash=e["leaf_hash"],
            digest=e["digest"],
        )
        for e in entries
        if e["digest"] is not None
    ]
    break_ids = json.loads(seal["first_break_scan_ids"])
    return SealResponse(
        seal_id=seal["seal_id"],
        waybill_id=seal["waybill_id"],
        sealed_at=_parse_iso_utc(seal["sealed_at"]),
        entry_count=seal["entry_count"],
        leaf_count=seal["leaf_count"],
        manifest_hash=seal["manifest_hash"],
        root_hash=seal["root_hash"],
        first_break_ts=(
            _parse_ts(seal["first_break_ts"]) if seal["first_break_ts"] else None
        ),
        break_reason=_break_reason_or_none(seal["break_reason"]),
        first_break_scan_ids=break_ids,
        requested_digests=digests,
    )


def _break_reason_or_none(value: str | None):
    from .schemas import BreakReason

    if value is None:
        return None
    return BreakReason(value)


# --------------------------------------------------------------------------- #
# Proof issuance
# --------------------------------------------------------------------------- #
def _entry_from_row(row: sqlite3.Row, leaves: list[str]) -> ProofEntry:
    return ProofEntry(
        idx=row["idx"],
        seq=row["seq"],
        scan_id=row["scan_id"],
        revision=row["revision"],
        ts_utc=_parse_ts(row["ts_utc"]),
        giver=row["giver"],
        receiver=row["receiver"],
        leaf_hash=row["leaf_hash"],
        auth_path=merkle_path(leaves, row["idx"]),
    )


def _neighbor_from_row(
    side: str, row: sqlite3.Row, leaves: list[str]
) -> ProofNeighbor:
    return ProofNeighbor(
        side=side,
        idx=row["idx"],
        seq=row["seq"],
        scan_id=row["scan_id"],
        revision=row["revision"],
        ts_utc=_parse_ts(row["ts_utc"]),
        giver=row["giver"],
        receiver=row["receiver"],
        leaf_hash=row["leaf_hash"],
        auth_path=merkle_path(leaves, row["idx"]),
    )


def _digests_from_rows(rows: list[sqlite3.Row]) -> list[ProofDigest]:
    return [
        ProofDigest(
            idx=r["idx"],
            seq=r["seq"],
            ts_utc=_parse_ts(r["ts_utc"]),
            scan_id=r["scan_id"],
            leaf_hash=r["leaf_hash"],
            digest=r["digest"],
        )
        for r in rows
        if r["digest"] is not None
    ]


def issue_proof(
    conn: sqlite3.Connection, waybill_id: str, req: WindowRequest
) -> ProofResponse:
    seal = _get_seal_row(conn, req.seal_id)
    if seal["waybill_id"] != waybill_id:
        raise DomainValidation(f"seal {req.seal_id!r} not found")

    entries = _get_seal_entries(conn, req.seal_id)
    leaves = [e["leaf_hash"] for e in entries]
    start = req.start_utc.astimezone(timezone.utc)
    end = req.end_utc.astimezone(timezone.utc)

    in_window_rows = [
        e for e in entries if start <= _parse_ts(e["ts_utc"]) < end
    ]

    break_reason = _break_reason_or_none(seal["break_reason"])
    first_break = (
        _parse_ts(seal["first_break_ts"]) if seal["first_break_ts"] else None
    )
    break_scan_ids = json.loads(seal["first_break_scan_ids"])

    if in_window_rows:
        result = "HAS_RECORD"
        neighbors: list[ProofNeighbor] = []
    elif first_break is not None and end > first_break:
        # No provable handover in the window, yet the window extends past the
        # first unverifiable point: the prefix alone cannot support an answer.
        result = "INSUFFICIENT_EVIDENCE"
        neighbors = []
    else:
        result = "EMPTY_WINDOW"
        before = [e for e in entries if _parse_ts(e["ts_utc"]) < start]
        after = [e for e in entries if _parse_ts(e["ts_utc"]) >= end]
        neighbors = []
        if before:
            neighbors.append(_neighbor_from_row("before", before[-1], leaves))
        if after:
            neighbors.append(_neighbor_from_row("after", after[0], leaves))

    envelope = ProofEnvelope(
        seal_id=seal["seal_id"],
        waybill_id=seal["waybill_id"],
        manifest_hash=seal["manifest_hash"],
        root_hash=seal["root_hash"],
        leaf_count=seal["leaf_count"],
        window_start_utc=start,
        window_end_utc=end,
        result=result,
        break_reason=break_reason,
        first_break_ts=first_break,
        break_scan_ids=break_scan_ids,
        in_window_entries=[_entry_from_row(r, leaves) for r in in_window_rows],
        neighbors=neighbors,
        requested_digests=_digests_from_rows(entries),
        proof_hash="",
    )
    envelope.proof_hash = payload_hash_of(proof_canonical_dict(envelope))
    return ProofResponse(proof=envelope)


# --------------------------------------------------------------------------- #
# Offline verification (no database access)
# --------------------------------------------------------------------------- #
def _recompute_leaf_hash(waybill_id: str, idx: int, seq: int, scan_id: str,
                         revision: int, ts: datetime, giver: str,
                         receiver: str) -> str:
    return compute_leaf_hash(
        waybill_id, idx, seq, scan_id, revision, _iso(ts), giver, receiver
    )


def _step_canonical(s: MerkleStep) -> dict:
    return {"side": s.side, "hash": s.hash}


def _digest_canonical(d: ProofDigest) -> dict:
    return {
        "idx": d.idx,
        "seq": d.seq,
        "ts_utc": _iso(d.ts_utc),
        "scan_id": d.scan_id,
        "leaf_hash": d.leaf_hash,
        "digest": d.digest,
    }


def proof_canonical_dict(p: ProofEnvelope) -> dict:
    """Deterministic pre-image of proof_hash, shared by issue and verify."""
    return {
        "type": _PROOF_DOMAIN,
        "seal_id": p.seal_id,
        "waybill_id": p.waybill_id,
        "manifest_hash": p.manifest_hash,
        "root_hash": p.root_hash,
        "leaf_count": p.leaf_count,
        "window_start_utc": _iso(p.window_start_utc),
        "window_end_utc": _iso(p.window_end_utc),
        "result": p.result,
        "break_reason": p.break_reason.value if p.break_reason else None,
        "first_break_ts": _iso(p.first_break_ts) if p.first_break_ts else None,
        "break_scan_ids": list(p.break_scan_ids),
        "in_window_entries": [
            {
                "leaf": leaf_payload(
                    p.waybill_id,
                    e.idx,
                    e.seq,
                    e.scan_id,
                    e.revision,
                    _iso(e.ts_utc),
                    e.giver,
                    e.receiver,
                ),
                "auth_path": [_step_canonical(s) for s in e.auth_path],
            }
            for e in p.in_window_entries
        ],
        "neighbors": [
            {
                "side": n.side,
                "leaf": leaf_payload(
                    p.waybill_id,
                    n.idx,
                    n.seq,
                    n.scan_id,
                    n.revision,
                    _iso(n.ts_utc),
                    n.giver,
                    n.receiver,
                ),
                "auth_path": [_step_canonical(s) for s in n.auth_path],
            }
            for n in p.neighbors
        ],
        "requested_digests": [_digest_canonical(d) for d in p.requested_digests],
    }


class _VerifyFail(Exception):
    """Internal control-flow exception for verification failures."""


def verify_proof(req: VerifyRequest) -> VerifyResponse:
    p = req.proof
    retained = list(req.retained_digests)
    base = VerifyResponse(
        valid=False,
        retained_digest_count=len(retained),
        retained_digest_used=0,
    )

    def fail(reason: str) -> VerifyResponse:
        base.reason = reason
        base.proof_hash = p.proof_hash
        return base

    # ---- identity / window binding --------------------------------------- #
    if p.waybill_id != req.waybill_id.strip():
        return fail("waybill_id does not match the proof envelope")
    if p.seal_id != req.seal_id.strip():
        return fail("seal_id does not match the proof envelope")
    if p.window_start_utc != req.start_utc or p.window_end_utc != req.end_utc:
        return fail("proof window does not match the submitted time window")
    if not _is_sha256_hex(p.manifest_hash):
        return fail("manifest_hash is not a valid sha256 hex digest")
    if not _is_sha256_hex(p.root_hash):
        return fail("root_hash is not a valid sha256 hex digest")
    if p.leaf_count < 0:
        return fail("leaf_count must be non-negative")

    # ---- proof_hash covers the whole envelope ----------------------------- #
    expected_proof_hash = payload_hash_of(proof_canonical_dict(p))
    if expected_proof_hash != p.proof_hash:
        return fail("proof_hash mismatch: envelope content was altered")

    start = p.window_start_utc.astimezone(timezone.utc)
    end = p.window_end_utc.astimezone(timezone.utc)
    break_ts = p.first_break_ts.astimezone(timezone.utc) if p.first_break_ts else None
    break_reason_value = p.break_reason.value if p.break_reason else None

    # ---- sparse digest set is canonical for the leaf count --------------- #
    expected_idx = sparse_indices(p.leaf_count)
    if sorted(d.idx for d in p.requested_digests) != expected_idx:
        return fail("requested_digests do not match the canonical sparse index set")

    retained_keyed: dict[int, ProofDigest] = {}
    for d in retained:
        if d.idx in retained_keyed:
            return fail(f"duplicate retained digest for idx={d.idx}")
        retained_keyed[d.idx] = d
    if set(retained_keyed) != set(expected_idx):
        return fail(
            "retained digests must be exactly the digests issued with the seal "
            f"(expected indices {expected_idx})"
        )

    known_leaves: dict[int, dict] = {}  # idx -> {"ts", "leaf_hash"}

    def remember(idx: int, ts: datetime, leaf_hash: str, where: str):
        if not (0 <= idx < p.leaf_count):
            raise _VerifyFail(f"{where} entry idx {idx} out of range [0,{p.leaf_count})")
        if not _is_sha256_hex(leaf_hash):
            raise _VerifyFail(f"{where} entry leaf_hash is not a valid sha256 hex")
        prev = known_leaves.get(idx)
        if prev is not None and (
            prev["leaf_hash"] != leaf_hash or prev["ts"] != ts
        ):
            raise _VerifyFail(f"conflicting statements about sealed leaf idx={idx}")
        known_leaves[idx] = {"ts": ts, "leaf_hash": leaf_hash}

    def check_auth_path(idx: int, leaf_hash: str, path: list[MerkleStep], where: str):
        for step in path:
            if step.side not in ("L", "R") or not _is_sha256_hex(step.hash):
                raise _VerifyFail(f"{where} entry idx={idx} has an invalid auth path")
        if eval_merkle_path(leaf_hash, path) != p.root_hash:
            raise _VerifyFail(
                f"{where} entry idx={idx} Merkle authentication path does not "
                "resolve to the sealed root_hash"
            )

    try:
        # ---- retained digests: recompute every hash ---------------------- #
        for d in p.requested_digests:
            want = retained_keyed.get(d.idx)
            if want is None or want != d:
                raise _VerifyFail(
                    f"retained digest for idx={d.idx} missing or altered"
                )
            recomputed = compute_digest_hash(
                p.manifest_hash,
                p.root_hash,
                p.leaf_count,
                p.waybill_id,
                p.seal_id,
                d.idx,
                d.leaf_hash,
                _iso(break_ts) if break_ts else None,
                break_reason_value,
            )
            if recomputed != d.digest:
                raise _VerifyFail(
                    f"digest hash mismatch at idx={d.idx}: seal/root/count/"
                    "break-boundary binding was altered"
                )
            remember(
                d.idx, d.ts_utc.astimezone(timezone.utc), d.leaf_hash, "digest"
            )

        # ---- in-window entries ------------------------------------------- #
        seen_idx: set[int] = set()
        for e in p.in_window_entries:
            if e.idx in seen_idx:
                raise _VerifyFail(f"duplicate in-window entry idx={e.idx}")
            seen_idx.add(e.idx)
            if e.seq != e.idx + 1:
                raise _VerifyFail(f"seq mismatch for idx={e.idx}")
            ts = e.ts_utc.astimezone(timezone.utc)
            if not (start <= ts < end):
                raise _VerifyFail(
                    f"in-window entry idx={e.idx} ts {ts} lies outside [{start}, {end})"
                )
            if _recompute_leaf_hash(
                p.waybill_id, e.idx, e.seq, e.scan_id, e.revision,
                ts, e.giver, e.receiver,
            ) != e.leaf_hash:
                raise _VerifyFail(
                    f"leaf hash mismatch for in-window entry idx={e.idx}: "
                    "timestamp/party/scan fields were altered"
                )
            check_auth_path(e.idx, e.leaf_hash, e.auth_path, "in-window")
            remember(e.idx, ts, e.leaf_hash, "in-window")

        # ---- neighbors (empty-window proofs only) ------------------------ #
        sides = [n.side for n in p.neighbors]
        if len(sides) != len(set(sides)):
            raise _VerifyFail("duplicate neighbor side")
        for n in p.neighbors:
            if n.seq != n.idx + 1:
                raise _VerifyFail(f"seq mismatch for neighbor idx={n.idx}")
            ts = n.ts_utc.astimezone(timezone.utc)
            if n.side == "before" and not ts < start:
                raise _VerifyFail(
                    "before-neighbor must be strictly earlier than window start"
                )
            if n.side == "after" and not ts >= end:
                raise _VerifyFail(
                    "after-neighbor must be at or after window end"
                )
            if _recompute_leaf_hash(
                p.waybill_id, n.idx, n.seq, n.scan_id, n.revision,
                ts, n.giver, n.receiver,
            ) != n.leaf_hash:
                raise _VerifyFail(
                    f"leaf hash mismatch for neighbor idx={n.idx}: fields were altered"
                )
            check_auth_path(n.idx, n.leaf_hash, n.auth_path, "neighbor")
            remember(n.idx, ts, n.leaf_hash, "neighbor")

        # ---- ordering: sealed leaves are time-ascending by idx ----------- #
        ordered = sorted(known_leaves.items())
        for (i1, v1), (i2, v2) in zip(ordered, ordered[1:]):
            if v1["ts"] > v2["ts"]:
                raise _VerifyFail(
                    f"timestamps not monotonic between idx={i1} and idx={i2}"
                )
    except _VerifyFail as exc:
        return fail(str(exc))

    # ---- re-derive the conclusion rule from scratch ---------------------- #
    if p.in_window_entries:
        if p.result != "HAS_RECORD":
            return fail("window contains verified handovers but result is not HAS_RECORD")
        if p.neighbors:
            return fail("HAS_RECORD proofs must not carry neighbors")
    else:
        if break_ts is not None and end > break_ts:
            expected_result = "INSUFFICIENT_EVIDENCE"
        else:
            expected_result = "EMPTY_WINDOW"
        if p.result != expected_result:
            return fail(
                f"result {p.result!r} contradicts the window/break rules; "
                f"expected {expected_result!r}"
            )
        if expected_result == "INSUFFICIENT_EVIDENCE":
            if p.neighbors:
                return fail("INSUFFICIENT_EVIDENCE proofs must not carry neighbors")
        else:
            # ---- empty window: prove adjacency by index contiguity ------ #
            by_side = {n.side: n for n in p.neighbors}
            before = by_side.get("before")
            after = by_side.get("after")
            if before and after:
                if after.idx != before.idx + 1:
                    return fail(
                        "neighbors are not adjacent sealed leaves: a closer "
                        "handover inside the window was skipped"
                    )
            elif before and not after:
                if before.idx != p.leaf_count - 1:
                    return fail(
                        "before-neighbor is not the last sealed leaf: a closer "
                        "following handover was skipped"
                    )
            elif after and not before:
                if after.idx != 0:
                    return fail(
                        "after-neighbor is not the first sealed leaf: a closer "
                        "preceding handover was skipped"
                    )
            else:
                if p.leaf_count != 0:
                    return fail(
                        "empty window with sealed leaves must carry adjacency neighbors"
                    )

            # Timestamp positions must be consistent with the stated sides.
            if before and not before.ts_utc.astimezone(timezone.utc) < start:
                return fail("before-neighbor timestamp is not before the window")
            if after and not after.ts_utc.astimezone(timezone.utc) >= end:
                return fail("after-neighbor timestamp is not after the window")

    if p.leaf_count == 0:
        if p.in_window_entries or p.requested_digests or known_leaves or p.neighbors:
            return fail("empty-prefix seal must not reference any sealed leaf")
        if p.root_hash != merkle_root([]):
            return fail("empty-prefix root_hash does not match the empty-tree root")

    base.valid = True
    base.result = p.result
    base.reason = None
    base.proof_hash = p.proof_hash
    base.retained_digest_used = len(retained)
    return base
