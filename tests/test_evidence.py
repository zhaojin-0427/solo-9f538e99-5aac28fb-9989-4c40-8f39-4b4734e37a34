"""Evidence seals, time-window proofs and offline verification.

Covers:
* seal snapshots the committed verified prefix + first break;
* the three proof outcomes and one-sided / empty-prefix boundary cases;
* offline verification with retained digests only (no DB reads);
* tamper resistance: timestamps, parties, leaf hashes, auth paths,
  waybill/seal swaps, skipped neighbors, break-boundary forgeries;
* O(log n) digest growth;
* seal immutability across later corrections / withdrawals;
* durability across a simulated restart;
* seal/scan interleaving only ever meets a committed state.
"""
from __future__ import annotations

import copy
import threading

from conftest import handover, make_waybill, withdrawal


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def build_waybill_with_gap(client, wid="AWB-1", n=8):
    """n verified hourly handovers (08:00..) followed by one GAP handover."""
    from datetime import datetime, timedelta, timezone

    make_waybill(client, wid=wid, origin="ORIG")
    base = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)

    def iso(i):
        return (base + timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ")

    for i in range(n):
        r = client.post(
            f"/api/waybills/{wid}/scans/batch",
            json={
                "scans": [
                    handover(
                        f"S{i+1}", 1, iso(i),
                        "ORIG" if i == 0 else f"P{i}",
                        f"P{i+1}",
                    )
                ]
            },
        )
        assert r.status_code == 200, r.text
    r = client.post(
        f"/api/waybills/{wid}/scans/batch",
        json={
            "scans": [
                handover("S-BREAK", 1, iso(n), "ZZZ", "P9")
            ]
        },
    )
    assert r.status_code == 200


def seal(client, wid="AWB-1"):
    r = client.post(f"/api/waybills/{wid}/seals")
    assert r.status_code == 201, r.text
    return r.json()


def issue(client, seal_id, start, end, wid="AWB-1"):
    r = client.post(
        f"/api/waybills/{wid}/proofs",
        json={"seal_id": seal_id, "start_utc": start, "end_utc": end},
    )
    assert r.status_code == 200, r.text
    return r.json()["proof"]


def verify(client, proof, digests, wid="AWB-1", seal_id=None, start=None, end=None):
    seal_id = seal_id or proof["seal_id"]
    start = start or proof["window_start_utc"]
    end = end or proof["window_end_utc"]
    r = client.post(
        "/api/verify",
        json={
            "waybill_id": wid,
            "seal_id": seal_id,
            "start_utc": start,
            "end_utc": end,
            "retained_digests": digests,
            "proof": proof,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def rehash(proof_obj):
    from app.evidence import proof_canonical_dict
    from app.schemas import ProofEnvelope, payload_hash_of

    proof_obj["proof_hash"] = payload_hash_of(
        proof_canonical_dict(ProofEnvelope(**proof_obj))
    )
    return proof_obj


# --------------------------------------------------------------------------- #
# Seal creation
# --------------------------------------------------------------------------- #
def test_seal_snapshots_verified_prefix_and_break(client):
    build_waybill_with_gap(client)
    body = seal(client)
    assert body["entry_count"] == 8
    assert body["leaf_count"] == 8
    assert body["break_reason"] == "GAP"
    assert body["first_break_ts"].startswith("2026-11-18T16:00:00")
    assert [d["idx"] for d in body["requested_digests"]] == [0, 1, 3, 7]
    for d in body["requested_digests"]:
        assert len(d["digest"]) == 64 and len(d["leaf_hash"]) == 64


def test_seal_on_empty_prefix_has_no_digests(client):
    make_waybill(client)
    body = seal(client)
    assert body["entry_count"] == 0
    assert body["requested_digests"] == []
    assert body["first_break_ts"] is None and body["break_reason"] is None
    # empty-tree root is a well-defined non-null digest
    assert len(body["root_hash"]) == 64


def test_digest_count_grows_logarithmically(client):
    from app.evidence import sparse_indices

    assert sparse_indices(0) == []
    assert sparse_indices(1) == [0]
    assert sparse_indices(2) == [0, 1]
    assert sparse_indices(7) == [0, 1, 3]
    assert sparse_indices(8) == [0, 1, 3, 7]
    assert sparse_indices(1000)[-1] == 511 and len(sparse_indices(1000)) == 10

    build_waybill_with_gap(client, n=16)
    body = seal(client)
    assert body["entry_count"] == 16
    assert [d["idx"] for d in body["requested_digests"]] == [0, 1, 3, 7, 15]


def test_seal_unknown_waybill_404(client):
    r = client.post("/api/waybills/NOPE/seals")
    assert r.status_code == 404


def test_get_seal_roundtrip_and_cross_waybill_hidden(client):
    build_waybill_with_gap(client)
    body = seal(client)
    r = client.get(f"/api/waybills/AWB-1/seals/{body['seal_id']}")
    assert r.status_code == 200
    assert r.json()["seal_id"] == body["seal_id"]
    assert len(r.json()["requested_digests"]) == 4

    make_waybill(client, wid="AWB-9", origin="O")
    r = client.get(f"/api/waybills/AWB-9/seals/{body['seal_id']}")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Proof issuance: the three outcomes
# --------------------------------------------------------------------------- #
def test_has_record_proof_half_open_window(client):
    build_waybill_with_gap(client)
    s = seal(client)
    p = issue(client, s["seal_id"], "2026-11-18T09:30:00Z", "2026-11-18T11:30:00Z")
    # [09:30, 11:30) covers 10:00 (S3, idx2) and 11:00 (S4, idx3)
    assert p["result"] == "HAS_RECORD"
    assert [e["scan_id"] for e in p["in_window_entries"]] == ["S3", "S4"]
    assert p["neighbors"] == []
    for e in p["in_window_entries"]:
        assert e["auth_path"], "every entry carries a Merkle authentication path"
        assert e["seq"] == e["idx"] + 1


def test_window_includes_start_excludes_end(client):
    build_waybill_with_gap(client)
    s = seal(client)
    # end exactly at 10:00 excludes S3 (10:00); only nothing at 09:00 boundary
    p = issue(client, s["seal_id"], "2026-11-18T09:00:00Z", "2026-11-18T10:00:00Z")
    assert p["result"] == "HAS_RECORD"
    assert [e["scan_id"] for e in p["in_window_entries"]] == ["S2"]
    # start exactly at 10:00 includes S3
    p2 = issue(client, s["seal_id"], "2026-11-18T10:00:00Z", "2026-11-18T11:00:00Z")
    assert [e["scan_id"] for e in p2["in_window_entries"]] == ["S3"]


def test_empty_window_proof_carries_adjacent_neighbors(client):
    build_waybill_with_gap(client)
    s = seal(client)
    p = issue(client, s["seal_id"], "2026-11-18T11:30:00Z", "2026-11-18T12:00:00Z")
    assert p["result"] == "EMPTY_WINDOW"
    assert [n["side"] for n in p["neighbors"]] == ["before", "after"]
    before, after = p["neighbors"]
    assert before["scan_id"] == "S4" and after["scan_id"] == "S5"
    assert after["idx"] == before["idx"] + 1
    for n in p["neighbors"]:
        assert n["auth_path"] and n["giver"] and n["receiver"]


def test_empty_window_one_sided_boundaries(client):
    build_waybill_with_gap(client)
    s = seal(client)
    left = issue(client, s["seal_id"], "2026-11-18T06:00:00Z", "2026-11-18T07:30:00Z")
    assert left["result"] == "EMPTY_WINDOW"
    assert [n["side"] for n in left["neighbors"]] == ["after"]
    assert left["neighbors"][0]["idx"] == 0

    right = issue(client, s["seal_id"], "2026-11-18T15:30:00Z", "2026-11-18T15:45:00Z")
    assert right["result"] == "EMPTY_WINDOW"
    assert [n["side"] for n in right["neighbors"]] == ["before"]
    assert right["neighbors"][0]["idx"] == 7


def test_insufficient_evidence_when_window_reaches_past_break(client):
    build_waybill_with_gap(client)
    s = seal(client)
    # no sealed handover in [15:30, 17:30), end (17:30) > break (16:00)
    p = issue(client, s["seal_id"], "2026-11-18T15:30:00Z", "2026-11-18T17:30:00Z")
    assert p["result"] == "INSUFFICIENT_EVIDENCE"
    assert p["neighbors"] == []
    assert p["first_break_ts"].startswith("2026-11-18T16:00:00")

    # end exactly at the break does NOT cross it -> still an empty window
    p2 = issue(client, s["seal_id"], "2026-11-18T15:30:00Z", "2026-11-18T16:00:00Z")
    assert p2["result"] == "EMPTY_WINDOW"


def test_window_validation(client):
    build_waybill_with_gap(client)
    s = seal(client)
    base = {"seal_id": s["seal_id"],
            "start_utc": "2026-11-18T10:00:00Z", "end_utc": "2026-11-18T10:00:00Z"}
    assert client.post("/api/waybills/AWB-1/proofs", json=base).status_code == 422
    base = {"seal_id": s["seal_id"],
            "start_utc": "2026-11-18T11:00:00Z", "end_utc": "2026-11-18T10:00:00Z"}
    assert client.post("/api/waybills/AWB-1/proofs", json=base).status_code == 422
    base = {"seal_id": s["seal_id"],
            "start_utc": "2026-11-18T10:00:00", "end_utc": "2026-11-18T11:00:00Z"}
    assert client.post("/api/waybills/AWB-1/proofs", json=base).status_code == 422
    base = {"seal_id": "deadbeef",
            "start_utc": "2026-11-18T10:00:00Z", "end_utc": "2026-11-18T11:00:00Z"}
    assert client.post("/api/waybills/AWB-1/proofs", json=base).status_code == 404


# --------------------------------------------------------------------------- #
# Offline verification: happy paths
# --------------------------------------------------------------------------- #
def test_verify_all_three_outcomes_and_empty_prefix(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]

    hp = issue(client, s["seal_id"], "2026-11-18T09:30:00Z", "2026-11-18T11:30:00Z")
    v = verify(client, hp, digests)
    assert v["valid"] and v["result"] == "HAS_RECORD"
    assert v["retained_digest_used"] == 4

    ep = issue(client, s["seal_id"], "2026-11-18T11:30:00Z", "2026-11-18T12:00:00Z")
    v = verify(client, ep, digests,
               start="2026-11-18T11:30:00Z", end="2026-11-18T12:00:00Z")
    assert v["valid"] and v["result"] == "EMPTY_WINDOW"

    ip = issue(client, s["seal_id"], "2026-11-18T15:30:00Z", "2026-11-18T17:30:00Z")
    v = verify(client, ip, digests,
               start="2026-11-18T15:30:00Z", end="2026-11-18T17:30:00Z")
    assert v["valid"] and v["result"] == "INSUFFICIENT_EVIDENCE"

    # empty prefix seal: no digests, one-sided-less empty window
    make_waybill(client, wid="AWB-2", origin="O2")
    s0 = seal(client, wid="AWB-2")
    p0 = issue(client, s0["seal_id"], "2026-11-18T00:00:00Z",
               "2026-11-19T00:00:00Z", wid="AWB-2")
    v = verify(client, p0, [], wid="AWB-2",
               start="2026-11-18T00:00:00Z", end="2026-11-19T00:00:00Z")
    assert v["valid"] and v["result"] == "EMPTY_WINDOW"


def test_verify_accepts_timezone_offset_window(client):
    build_waybill_with_gap(client)
    s = seal(client)
    # 17:30+08:00 == 09:30Z ; 19:30+08:00 == 11:30Z
    p = issue(client, s["seal_id"], "2026-11-18T17:30:00+08:00",
              "2026-11-18T19:30:00+08:00")
    v = client.post(
        "/api/verify",
        json={
            "waybill_id": "AWB-1",
            "seal_id": s["seal_id"],
            "start_utc": "2026-11-18T17:30:00+08:00",
            "end_utc": "2026-11-18T19:30:00+08:00",
            "retained_digests": s["requested_digests"],
            "proof": p,
        },
    ).json()
    assert v["valid"] and v["result"] == "HAS_RECORD"


# --------------------------------------------------------------------------- #
# Offline verification: tamper resistance
# --------------------------------------------------------------------------- #
def _expect_invalid(client, proof_obj, digests, start=None, end=None,
                    wid="AWB-1", seal_id=None):
    v = verify(client, proof_obj, digests, wid=wid, seal_id=seal_id,
               start=start, end=end)
    assert v["valid"] is False, v
    return v["reason"]


def test_tampered_timestamp_or_party_fails(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]
    hp = issue(client, s["seal_id"], "2026-11-18T09:30:00Z", "2026-11-18T11:30:00Z")

    t = copy.deepcopy(hp)
    t["in_window_entries"][0]["ts_utc"] = "2026-11-18T09:01:00Z"
    assert "proof_hash" in _expect_invalid(client, t, digests)

    t = copy.deepcopy(hp)
    t["in_window_entries"][0]["giver"] = "EVIL"
    assert "leaf hash" in _expect_invalid(client, rehash(t), digests)

    t = copy.deepcopy(hp)
    t["in_window_entries"][0]["receiver"] = "EVIL"
    assert "leaf hash" in _expect_invalid(client, rehash(t), digests)


def test_forged_leaf_or_auth_path_fails_at_root(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]
    hp = issue(client, s["seal_id"], "2026-11-18T09:30:00Z", "2026-11-18T11:30:00Z")

    t = copy.deepcopy(hp)
    t["in_window_entries"][0]["leaf_hash"] = "a" * 64
    assert "leaf hash mismatch" in _expect_invalid(client, rehash(t), digests)

    t = copy.deepcopy(hp)
    t["in_window_entries"][0]["auth_path"][0]["hash"] = "b" * 64
    assert "root_hash" in _expect_invalid(client, rehash(t), digests)


def test_waybill_and_seal_swaps_fail(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]
    hp = issue(client, s["seal_id"], "2026-11-18T09:30:00Z", "2026-11-18T11:30:00Z")

    make_waybill(client, wid="AWB-2", origin="O2")
    s0 = seal(client, wid="AWB-2")

    t = copy.deepcopy(hp)
    t["waybill_id"] = "AWB-2"
    _expect_invalid(client, rehash(t), digests, wid="AWB-2")

    t = copy.deepcopy(hp)
    t["seal_id"] = s0["seal_id"]
    _expect_invalid(client, rehash(t), digests, seal_id=s0["seal_id"])

    # proof from AWB-2 verified against AWB-1's identity must fail
    p0 = issue(client, s0["seal_id"], "2026-11-18T00:00:00Z",
               "2026-11-19T00:00:00Z", wid="AWB-2")
    _expect_invalid(client, p0, [], wid="AWB-1", seal_id=s0["seal_id"],
                    start="2026-11-18T00:00:00Z", end="2026-11-19T00:00:00Z")


def test_retained_digest_tampering_fails(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]
    hp = issue(client, s["seal_id"], "2026-11-18T09:30:00Z", "2026-11-18T11:30:00Z")

    bad = copy.deepcopy(digests)
    bad[0]["digest"] = "0" * 64
    _expect_invalid(client, hp, bad)

    bad = copy.deepcopy(digests)
    bad[1]["leaf_hash"] = "c" * 64
    _expect_invalid(client, hp, bad)

    _expect_invalid(client, hp, digests[:-1])  # missing digest
    extra = copy.deepcopy(digests)
    extra.append(copy.deepcopy(digests[0]))
    _expect_invalid(client, hp, extra)  # duplicate idx


def test_skipping_closer_neighbor_fails(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]

    # honest window [14:30,15:30) contains S8 (idx 7)
    honest = issue(client, s["seal_id"], "2026-11-18T14:30:00Z",
                   "2026-11-18T15:30:00Z")
    assert honest["result"] == "HAS_RECORD"
    assert [e["scan_id"] for e in honest["in_window_entries"]] == ["S8"]

    # forge EMPTY using the real S7 (idx 6) as the before-neighbor
    s7 = issue(client, s["seal_id"], "2026-11-18T13:30:00Z",
               "2026-11-18T14:30:00Z")["in_window_entries"][0]
    t = copy.deepcopy(honest)
    t["result"] = "EMPTY_WINDOW"
    t["in_window_entries"] = []
    t["neighbors"] = [{"side": "before", **s7}]
    reason = _expect_invalid(client, rehash(t), digests,
                             start="2026-11-18T14:30:00Z",
                             end="2026-11-18T15:30:00Z")
    assert "last sealed leaf" in reason

    # forge non-adjacent neighbors over a genuinely empty gap
    ep = issue(client, s["seal_id"], "2026-11-18T11:30:00Z",
               "2026-11-18T12:00:00Z")
    s2 = issue(client, s["seal_id"], "2026-11-18T08:30:00Z",
               "2026-11-18T09:30:00Z")["in_window_entries"][0]
    t = copy.deepcopy(ep)
    t["neighbors"][0] = {"side": "before", **s2}
    reason = _expect_invalid(client, rehash(t), digests,
                             start="2026-11-18T11:30:00Z",
                             end="2026-11-18T12:00:00Z")
    assert "adjacent" in reason


def test_break_boundary_and_root_forgery_fail(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]
    ip = issue(client, s["seal_id"], "2026-11-18T15:30:00Z",
               "2026-11-18T17:30:00Z")

    t = copy.deepcopy(ip)
    t["result"] = "EMPTY_WINDOW"
    t["first_break_ts"] = "2026-11-18T18:00:00Z"
    assert "digest hash mismatch" in _expect_invalid(
        client, rehash(t), digests,
        start="2026-11-18T15:30:00Z", end="2026-11-18T17:30:00Z")

    hp = issue(client, s["seal_id"], "2026-11-18T09:30:00Z",
               "2026-11-18T11:30:00Z")
    t = copy.deepcopy(hp)
    t["root_hash"] = "d" * 64
    assert "digest hash mismatch" in _expect_invalid(client, rehash(t), digests)

    t = copy.deepcopy(hp)
    t["leaf_count"] = 9
    assert "digest hash mismatch" in _expect_invalid(client, rehash(t), digests)


def test_window_binding_mismatch_fails(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]
    hp = issue(client, s["seal_id"], "2026-11-18T09:30:00Z",
               "2026-11-18T11:30:00Z")
    reason = _expect_invalid(client, hp, digests,
                             start="2026-11-18T09:00:00Z",
                             end="2026-11-18T11:30:00Z")
    assert "window does not match" in reason


# --------------------------------------------------------------------------- #
# Seal immutability, durability, concurrency
# --------------------------------------------------------------------------- #
def test_seal_is_immutable_against_later_revisions(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]

    # A failed (same-revision divergence) batch must leave no trace and must
    # not perturb the existing seal.
    bad = client.post(
        "/api/waybills/AWB-1/scans/batch",
        json={
            "scans": [
                handover("S1", 1, "2026-11-18T08:00:00Z", "ORIG", "TAMPERED")
            ]
        },
    )
    assert bad.status_code == 409

    # Later correction + withdrawal change the live chain...
    client.post(
        "/api/waybills/AWB-1/scans/batch",
        json={"scans": [withdrawal("S-BREAK", 2)]},
    )
    client.post(
        "/api/waybills/AWB-1/scans/batch",
        json={
            "scans": [
                handover("S2", 2, "2026-11-18T09:00:00Z", "P1", "P2X")
            ]
        },
    )
    # ...but the original seal still issues and verifies with old digests.
    p = issue(client, s["seal_id"], "2026-11-18T09:30:00Z",
              "2026-11-18T11:30:00Z")
    assert p["result"] == "HAS_RECORD"
    assert [e["scan_id"] for e in p["in_window_entries"]] == ["S3", "S4"]
    v = verify(client, p, digests)
    assert v["valid"]

    # and a fresh seal of the new state has a different manifest/root.
    s2 = seal(client)
    assert s2["manifest_hash"] != s["manifest_hash"]
    assert s2["seal_id"] != s["seal_id"]


def test_seal_and_proof_survive_restart(client):
    build_waybill_with_gap(client)
    s = seal(client)
    digests = s["requested_digests"]
    p = issue(client, s["seal_id"], "2026-11-18T09:30:00Z",
              "2026-11-18T11:30:00Z")

    import importlib

    from app import config, main

    importlib.reload(main)
    from fastapi.testclient import TestClient

    with TestClient(main.app) as new_client:
        r = new_client.get(f"/api/waybills/AWB-1/seals/{s['seal_id']}")
        assert r.status_code == 200
        p2 = new_client.post(
            "/api/waybills/AWB-1/proofs",
            json={
                "seal_id": s["seal_id"],
                "start_utc": "2026-11-18T09:30:00Z",
                "end_utc": "2026-11-18T11:30:00Z",
            },
        ).json()["proof"]
        assert p2["proof_hash"] == p["proof_hash"]
        v = new_client.post(
            "/api/verify",
            json={
                "waybill_id": "AWB-1",
                "seal_id": s["seal_id"],
                "start_utc": "2026-11-18T09:30:00Z",
                "end_utc": "2026-11-18T11:30:00Z",
                "retained_digests": digests,
                "proof": p2,
            },
        ).json()
        assert v["valid"]


def test_multiple_seals_are_independent_and_cross_digests_rejected(client):
    make_waybill(client)
    client.post(
        "/api/waybills/AWB-1/scans/batch",
        json={"scans": [handover("S1", 1, "2026-11-18T08:00:00Z", "ORIG", "A")]},
    )
    seal1 = seal(client)
    # introduce a GAP after the first seal
    client.post(
        "/api/waybills/AWB-1/scans/batch",
        json={"scans": [handover("S2", 1, "2026-11-18T09:00:00Z", "X", "Y")]},
    )
    seal2 = seal(client)

    assert seal1["seal_id"] != seal2["seal_id"]
    assert seal1["first_break_ts"] is None
    assert seal2["first_break_ts"].startswith("2026-11-18T09:00:00")
    assert seal1["manifest_hash"] != seal2["manifest_hash"]

    w = ("2026-11-18T08:30:00Z", "2026-11-18T10:00:00Z")
    # the old seal recorded no break -> the same window is an empty window
    p1 = issue(client, seal1["seal_id"], *w)
    assert p1["result"] == "EMPTY_WINDOW"
    assert verify(client, p1, seal1["requested_digests"], start=w[0], end=w[1])["valid"]

    # the new seal records the 09:00 break -> same window is insufficient
    p2 = issue(client, seal2["seal_id"], *w)
    assert p2["result"] == "INSUFFICIENT_EVIDENCE"
    assert verify(client, p2, seal2["requested_digests"], start=w[0], end=w[1])["valid"]

    # digests from the other seal must not validate this proof
    bad = verify(client, p2, seal1["requested_digests"], start=w[0], end=w[1])
    assert bad["valid"] is False


def test_interleaved_seals_only_see_committed_states(client):
    """Seals interleaved with batch submissions only observe committed states.

    Rounds are synchronized with events so the assertion is deterministic:
    every seal runs strictly after a batch has committed (plus one seal
    before any write), and torn / mixed-revision snapshots are impossible.
    """
    from datetime import datetime, timedelta, timezone

    from app import config, database, evidence, schemas, services

    make_waybill(client)
    db_path = config.DB_PATH
    rounds = 20
    committed = threading.Event()   # writer -> sealer: batch i is committed
    sealed = threading.Event()      # sealer -> writer: seal i is stored
    seal_leaf_counts: list[int] = []
    errors: list[str] = []

    def sealer() -> None:
        conn = database.connect(db_path)
        try:
            # seal the empty, pre-submission state
            seal_leaf_counts.append(evidence.create_seal(conn, "AWB-1").entry_count)
            for _ in range(rounds):
                committed.wait(timeout=30)
                committed.clear()
                seal_leaf_counts.append(
                    evidence.create_seal(conn, "AWB-1").entry_count
                )
                sealed.set()
        except Exception as exc:  # pragma: no cover - failure signal
            errors.append(str(exc))
        finally:
            conn.close()

    def writer() -> None:
        conn = database.connect(db_path)
        base = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)
        try:
            for i in range(rounds):
                batch = schemas.BatchSubmit(
                    scans=[
                        schemas.ScanEntry(
                            scan_id=f"S{i+1}",
                            revision=1,
                            # unique, ascending, spaced 15 min apart
                            ts_utc=base + timedelta(minutes=15 * i),
                            giver="ORIG" if i == 0 else f"R{i}",
                            receiver=f"R{i+1}",
                        )
                    ]
                )
                services.apply_batch(conn, "AWB-1", batch)  # commits, then releases
                committed.set()
                sealed.wait(timeout=30)
                sealed.clear()
        except Exception as exc:  # pragma: no cover - failure signal
            errors.append(str(exc))
            committed.set()
        finally:
            conn.close()

    t1 = threading.Thread(target=sealer)
    t2 = threading.Thread(target=writer)
    t1.start(); t2.start()
    t1.join(timeout=60); t2.join(timeout=60)

    assert not errors, errors
    # Seal sizes must be exactly 0..rounds: every seal reflects one whole
    # committed state, never a half-written or mixed-revision snapshot.
    assert seal_leaf_counts == list(range(rounds + 1))
