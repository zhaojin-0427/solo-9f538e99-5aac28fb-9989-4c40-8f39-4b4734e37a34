"""End-to-end HTTP smoke test against a running uvicorn instance."""
import json
import os
import sys
import urllib.request

BASE = "http://127.0.0.1:" + os.environ.get("SMOKE_PORT", "8011")


def call(method, path, body=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = resp.read()
            return resp.status, payload if raw else json.loads(payload)
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, json.loads(payload)
        except json.JSONDecodeError:
            return e.code, payload


def check(label, cond, extra=""):
    print(("PASS" if cond else "FAIL"), label, extra)
    if not cond:
        sys.exit(1)


st, body = call("POST", "/api/waybills", {"waybill_id": "AWB-SMOKE", "origin_party": "ORIG"})
check("create waybill", st == 201, body)

st, body = call("POST", "/api/waybills/AWB-SMOKE/scans/batch", {"scans": [
    {"scan_id": "S1", "revision": 1, "ts_utc": "2026-11-18T08:00:00Z", "giver": "ORIG", "receiver": "B"},
    {"scan_id": "S2", "revision": 1, "ts_utc": "2026-11-18T09:00:00Z", "giver": "B", "receiver": "C"},
    {"scan_id": "S3", "revision": 1, "ts_utc": "2026-11-18T10:00:00Z", "giver": "X", "receiver": "Y"},
]})
check("batch accepted", st == 200, st)
check("GAP detected", body["chain"]["break_reason"] == "GAP")
check("custodian stays at C", body["chain"]["current_custodian"] == "C")
check("S3 unverified", [s["scan_id"] for s in body["chain"]["unverified_scans"]] == ["S3"])

# same revision divergence -> 409, old chain preserved
st, body = call("POST", "/api/waybills/AWB-SMOKE/scans/batch", {"scans": [
    {"scan_id": "S3", "revision": 1, "ts_utc": "2026-11-18T10:00:00Z", "giver": "X", "receiver": "TAMPERED"},
]})
check("same-revision divergence -> 409", st == 409, body)

st, body = call("POST", "/api/waybills/AWB-SMOKE/scans/batch", {"scans": [
    {"scan_id": "S3", "revision": 2, "event_type": "WITHDRAWAL"},
]})
check("withdrawal accepted", st == 200, body)
st, body = call("POST", "/api/waybills/AWB-SMOKE/scans/batch", {"scans": [
    {"scan_id": "S3", "revision": 3, "ts_utc": "2026-11-18T10:00:00Z", "giver": "C", "receiver": "D"},
]})
check("correction accepted", st == 200, st)
check("chain healed", body["chain"]["chain_intact"] is True)
check("custodian now D", body["chain"]["current_custodian"] == "D")

# simultaneous timestamps
st, body = call("POST", "/api/waybills/AWB-SMOKE/scans/batch", {"scans": [
    {"scan_id": "S4", "revision": 1, "ts_utc": "2026-11-18T11:00:00Z", "giver": "D", "receiver": "E"},
    {"scan_id": "S5", "revision": 1, "ts_utc": "2026-11-18T11:00:00Z", "giver": "E", "receiver": "F"},
]})
check("simultaneous flagged", body["chain"]["break_reason"] == "SIMULTANEOUS")

st, body = call("GET", "/api/waybills/AWB-SMOKE/chain")
check("GET chain", st == 200 and body["waybill_id"] == "AWB-SMOKE")

st, body = call("GET", "/api/waybills")
check("list waybills", st == 200 and any(w["id"] == "AWB-SMOKE" for w in body["waybills"]))

st, body = call("GET", "/docs", raw=True)
check("swagger docs reachable", st == 200 and b"swagger" in body.lower())
st, body = call("GET", "/openapi.json")
check("openapi schema reachable", st == 200 and "paths" in body)
st, body = call("GET", "/", raw=True)
check("console page reachable", st == 200 and b"<!DOCTYPE html>" in body)

# validation: naive datetime
st, body = call("POST", "/api/waybills/AWB-SMOKE/scans/batch", {"scans": [
    {"scan_id": "S9", "revision": 1, "ts_utc": "2026-11-18T12:00:00", "giver": "D", "receiver": "E"},
]})
check("naive timestamp -> 422", st == 422)

# ---------------- evidence: seal -> proof -> offline verify ---------------- #
st, body = call("POST", "/api/waybills/AWB-SMOKE/seals")
check("seal created", st == 201, st)
seal_id = body["seal_id"]
digests = body["requested_digests"]
# S1(08:00),S2(09:00),S3(10:00) verified; S4/S5 simultaneous at 11:00 -> break
check("seal has 3 verified handovers", body["entry_count"] == 3, body["entry_count"])
check("seal digests are sparse", [d["idx"] for d in digests] == [0, 1], digests)
check("seal records the SIMULTANEOUS break",
      body["first_break_ts"] is not None and body["break_reason"] == "SIMULTANEOUS", body)

st, body = call("GET", f"/api/waybills/AWB-SMOKE/seals/{seal_id}")
check("get seal", st == 200 and body["seal_id"] == seal_id)

# HAS_RECORD window: [08:30, 10:30) covers S2 (09:00) and S3 (10:00)
window = {"seal_id": seal_id,
          "start_utc": "2026-11-18T08:30:00Z", "end_utc": "2026-11-18T10:30:00Z"}
st, body = call("POST", "/api/waybills/AWB-SMOKE/proofs", window)
check("HAS_RECORD proof", st == 200 and body["proof"]["result"] == "HAS_RECORD", body)
check("proof entries are S2,S3",
      [e["scan_id"] for e in body["proof"]["in_window_entries"]] == ["S2", "S3"])
check("entries carry Merkle paths",
      all(e["auth_path"] for e in body["proof"]["in_window_entries"]))
proof = body["proof"]
st, body = call("POST", "/api/verify", {
    "waybill_id": "AWB-SMOKE", "seal_id": seal_id,
    "start_utc": window["start_utc"], "end_utc": window["end_utc"],
    "retained_digests": digests, "proof": proof,
})
check("verify HAS_RECORD offline", st == 200 and body["valid"] is True and body["result"] == "HAS_RECORD", body)

# EMPTY_WINDOW after S3 (10:00), ending before the 11:00 break: before-only neighbor
window2 = {"seal_id": seal_id,
           "start_utc": "2026-11-18T10:30:00Z", "end_utc": "2026-11-18T10:45:00Z"}
st, body = call("POST", "/api/waybills/AWB-SMOKE/proofs", window2)
check("EMPTY_WINDOW proof", st == 200 and body["proof"]["result"] == "EMPTY_WINDOW", body)
check("empty proof has only the before neighbor",
      [n["side"] for n in body["proof"]["neighbors"]] == ["before"])
st, body = call("POST", "/api/verify", {
    "waybill_id": "AWB-SMOKE", "seal_id": seal_id,
    "start_utc": window2["start_utc"], "end_utc": window2["end_utc"],
    "retained_digests": digests, "proof": body["proof"],
})
check("verify EMPTY_WINDOW offline", st == 200 and body["valid"] is True, body)

# Window extending past the 11:00 break with no in-window handover -> insufficient
window3 = {"seal_id": seal_id,
           "start_utc": "2026-11-18T10:30:00Z", "end_utc": "2026-11-18T12:00:00Z"}
st, body = call("POST", "/api/waybills/AWB-SMOKE/proofs", window3)
check("INSUFFICIENT_EVIDENCE proof",
      st == 200 and body["proof"]["result"] == "INSUFFICIENT_EVIDENCE", body)
st, body = call("POST", "/api/verify", {
    "waybill_id": "AWB-SMOKE", "seal_id": seal_id,
    "start_utc": window3["start_utc"], "end_utc": window3["end_utc"],
    "retained_digests": digests, "proof": body["proof"],
})
check("verify INSUFFICIENT_EVIDENCE offline", st == 200 and body["valid"] is True, body)

# tamper: alter an entry timestamp -> verification must fail
import copy as _copy
bad = _copy.deepcopy(proof)
bad["in_window_entries"][0]["ts_utc"] = "2026-11-18T09:01:00Z"
st, body = call("POST", "/api/verify", {
    "waybill_id": "AWB-SMOKE", "seal_id": seal_id,
    "start_utc": window["start_utc"], "end_utc": window["end_utc"],
    "retained_digests": digests, "proof": bad,
})
check("tampered proof rejected", st == 200 and body["valid"] is False, body)

# waybill swap rejected
bad = _copy.deepcopy(proof)
st, body = call("POST", "/api/verify", {
    "waybill_id": "OTHER-WB", "seal_id": seal_id,
    "start_utc": window["start_utc"], "end_utc": window["end_utc"],
    "retained_digests": digests, "proof": bad,
})
check("waybill swap rejected", st == 200 and body["valid"] is False, body)

# invalid window: start == end -> 422
st, body = call("POST", "/api/waybills/AWB-SMOKE/proofs", {
    "seal_id": seal_id,
    "start_utc": "2026-11-18T10:00:00Z", "end_utc": "2026-11-18T10:00:00Z"})
check("zero-length window -> 422", st == 422, st)

# unknown seal -> 404
st, body = call("POST", "/api/waybills/AWB-SMOKE/proofs", {
    "seal_id": "nope",
    "start_utc": "2026-11-18T10:00:00Z", "end_utc": "2026-11-18T11:00:00Z"})
check("unknown seal -> 404", st == 404, st)

print("ALL SMOKE CHECKS PASSED")
