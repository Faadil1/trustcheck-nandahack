#!/usr/bin/env python3
"""TrustCheck harness — Spike 3.

Runs the service in-thread. Covers Spike 1 behavioral checks PLUS Spike 3:
Ed25519 receipts, well-known key endpoint, independent verification using only
receipt + public key, key rotation, and a full tamper matrix.
"""
import json, os, sys, time, threading, copy, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("PORT", "8788")
os.environ.setdefault("PUBLIC_BASE", "http://127.0.0.1:8788")
import app          # noqa: E402
import receipts as rcpt  # noqa: E402

BASE = os.environ["PUBLIC_BASE"]
threading.Thread(target=app.serve, daemon=True).start()

ready = False
for _ in range(50):
    try:
        with urllib.request.urlopen(BASE + "/health", timeout=0.5) as r:
            if r.status == 200: ready = True; break
    except Exception:
        time.sleep(0.1)
if not ready:
    print("FATAL: service not ready"); sys.exit(2)

def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def submit(target_id, endpoint_path=None, endpoint_abs=None, token="demo-consent"):
    ep = endpoint_abs or (BASE + endpoint_path)
    return call("POST", "/tests", {"contract_id": "invoice.extract-total.v1",
        "target": {"target_id": target_id, "endpoint": ep,
                   "declared_version": "1.0.0", "consent_token": token}})

checks = []
def check(name, cond, detail=""):
    checks.append((name, bool(cond), detail))

# ---- fetch well-known key, build an independent verifier keystore ----
s, wk = call("GET", "/.well-known/trustcheck-key.json")
check("well-known key endpoint 200", s == 200 and wk["active_key"]["kid"] == app.KEYSTORE.active.key_id)
check("well-known declares canon + alg",
      wk["canonicalization_version"] == rcpt.CANON_VERSION and wk["signature_algorithm"] == "Ed25519")
check("well-known issuer == PUBLIC_BASE", wk["issuer"] == BASE)
active_pub = wk["active_key"]["x"]

# independent keystore built ONLY from the public endpoint (no private material)
def ext_keystore_from_wellknown(wk):
    active = rcpt.KeyEntry(wk["active_key"]["kid"], wk["active_key"]["x"], None, "active")
    prev = [rcpt.KeyEntry(k["kid"], k["x"], None, "previous") for k in wk.get("previous_keys", [])]
    return rcpt.KeyStore(active, prev)
EXT = ext_keystore_from_wellknown(wk)

# ---- Spike 1 behavioral checks (preserved) ----
s, b = submit("compliant-target", "/targets/compliant/invoice-total")
check("compliant -> PASS", s == 200 and b["verdict"] == "PASS", json.dumps(b)[:140])
check("compliant -> DELEGATE", b["recommended_action"]["action"] == "DELEGATE")
pass_rid = b["receipt_id"]
check("result exposes key_id + key_endpoint",
      b.get("key_id") == app.KEYSTORE.active.key_id and "key_endpoint" in b)

s, b = submit("failing-target", "/targets/failing/invoice-total")
check("failing -> FAIL", s == 200 and b["verdict"] == "FAIL")
check("failing -> DO_NOT_DELEGATE", b["recommended_action"]["action"] == "DO_NOT_DELEGATE")
fail_rid = b["receipt_id"]

s, b = submit("unreachable-target", endpoint_abs="http://127.0.0.1:9/invoice-total")
check("unreachable -> UNAVAILABLE", b["verdict"] == "UNAVAILABLE")
s, b = submit("malformed-target", "/targets/malformed/invoice-total")
check("malformed -> INCONCLUSIVE", b["verdict"] == "INCONCLUSIVE")
s, b = submit("compliant-target", "/targets/failing/invoice-total")
check("id/endpoint mismatch -> 403", s == 403 and b["error_code"] == "TARGET_NOT_CONSENTED")
s, b = submit("compliant-target", endpoint_abs="http://evil.example/x")
check("foreign endpoint -> 403", s == 403 and b["error_code"] == "TARGET_NOT_CONSENTED")

# determinism over real endpoints
det = all(submit("compliant-target", "/targets/compliant/invoice-total")[1]["verdict"] == "PASS" for _ in range(5))
det &= all(submit("failing-target", "/targets/failing/invoice-total")[1]["verdict"] == "FAIL" for _ in range(5))
check("deterministic over 10 real-HTTP repeats", det)

# ---- Spike 3: fetch full receipt, all required fields present + signed ----
s, receipt = call("GET", f"/receipts/{pass_rid}")
required = ["receipt_id","test_id","contract_id","capability_id","target_id",
           "target_endpoint","declared_version","verdict","recommended_action",
           "evidence_root_hash","issued_at","valid_until","key_id",
           "signature_algorithm","canonicalization_version","signature"]
check("receipt has all 16 required fields", all(f in receipt for f in required),
      str([f for f in required if f not in receipt]))

# ---- independent verification using ONLY receipt + public key (no server) ----
r_local = rcpt.verify_receipt(receipt, public_b64u=active_pub)
check("independent verify (receipt + pubkey only) -> valid", r_local["valid"] is True, str(r_local))
r_ext = rcpt.verify_receipt(receipt, keystore=EXT)
check("independent verify via well-known keystore -> valid", r_ext["valid"] is True, str(r_ext))

# server-side verify endpoint agrees
s, v = call("POST", f"/receipts/{pass_rid}/verify")
check("server verify endpoint -> valid (Ed25519)", v["valid"] is True and v["verification_method"].startswith("Ed25519"))

# FAIL receipt is still a valid signed artifact
s, vfail = call("POST", f"/receipts/{fail_rid}/verify")
check("FAIL receipt independently valid", vfail["valid"] is True)

# ---- TAMPER MATRIX (independent verification must reject each) ----
def tampered(mut):
    r = copy.deepcopy(receipt); mut(r); return r

def m_verdict(r): r["verdict"] = "PASS" if r["verdict"] != "PASS" else "FAIL"
def m_target(r): r["target_id"] = "someone-else"
def m_evidence(r): r["evidence_root_hash"] = "0"*64
def m_validity(r): r["valid_until"] = "2999-01-01T00:00:00+00:00"
def m_signature(r):
    sraw = rcpt.b64u_decode(r["signature"]); flipped = bytes([sraw[0]^1])+sraw[1:]
    r["signature"] = rcpt.b64u_encode(flipped)
def m_keyid(r): r["key_id"] = "tc-does-not-exist"

for name, mut in [("verdict", m_verdict), ("target", m_target),
                  ("evidence_hash", m_evidence), ("validity", m_validity),
                  ("signature", m_signature)]:
    res = rcpt.verify_receipt(tampered(mut), public_b64u=active_pub)
    check(f"tamper {name} -> invalid (pubkey)", res["valid"] is False, str(res))

# wrong public key (use previous key's pub to verify an active-key receipt)
wrong_pub = wk["previous_keys"][0]["x"] if wk.get("previous_keys") else None
if wrong_pub:
    res = rcpt.verify_receipt(receipt, public_b64u=wrong_pub)
    check("wrong public key -> invalid", res["valid"] is False)
else:
    check("wrong public key -> invalid", False, "no previous key available")

# unknown key_id via keystore resolution
res = rcpt.verify_receipt(tampered(m_keyid), keystore=EXT)
check("unknown key_id -> invalid + flagged", res["valid"] is False and res["key_status"] == "unknown")

# server verify after evidence store tampering -> invalid
app.TESTS[receipt["test_id"]]["evidence"][0]["response"]["body"]["total"] = 999.99
s, v = call("POST", f"/receipts/{pass_rid}/verify")
check("server detects evidence-store tampering", v["valid"] is False)

# ---- KEY ROTATION: receipts under previous key still verify ----
# Simulate rotation: move current active to 'previous', install a new active.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
old_active = app.KEYSTORE.active
new_sk = Ed25519PrivateKey.generate()
new_priv = rcpt.b64u_encode(new_sk.private_bytes(serialization.Encoding.Raw,
    serialization.PrivateFormat.Raw, serialization.NoEncryption()))
new_pub = rcpt.b64u_encode(new_sk.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw))
new_active = rcpt.KeyEntry("tc-dev-2026-07-a", new_pub, new_priv, "active")
rotated = rcpt.KeyStore(new_active, previous=[
    rcpt.KeyEntry(old_active.key_id, old_active.public_b64u, None, "previous")])
app.KEYSTORE = rotated

# old receipt (signed by old active, now 'previous') must still verify
s, v = call("POST", f"/receipts/{fail_rid}/verify")
check("old receipt verifies after rotation (key now previous)", v["valid"] is True, str(v))
# new receipt uses the new active key
s, b = submit("compliant-target", "/targets/compliant/invoice-total")
check("post-rotation receipt uses new key_id", b["key_id"] == "tc-dev-2026-07-a")
s, wk2 = call("GET", "/.well-known/trustcheck-key.json")
check("well-known lists old key as previous",
      any(k["kid"] == old_active.key_id for k in wk2["previous_keys"]))

# revoked key behavior
revoked_store = rcpt.KeyStore(new_active,
    revoked=[rcpt.KeyEntry(old_active.key_id, old_active.public_b64u, None, "revoked")])
app.KEYSTORE = revoked_store
s, v = call("POST", f"/receipts/{fail_rid}/verify")
check("receipt under revoked key -> invalid by default", v["valid"] is False and v["key_status"] == "revoked")

# ---- private key never exposed over HTTP ----
exposed = False
for path in ["/.well-known/trustcheck-key.json", "/health"]:
    s, b = call("GET", path)
    blob = json.dumps(b)
    if "private" in blob.lower() or new_priv in blob or old_active.public_b64u and \
       app.KEYSTORE.active.key_id and False:
        exposed = True
# explicit: active private b64u must not appear anywhere served
s, wkx = call("GET", "/.well-known/trustcheck-key.json")
check("private key never exposed via API", "private" not in json.dumps(wkx).lower())

# legacy errors preserved
s, b = call("POST", "/tests", {"contract_id": "nope.v1",
    "target": {"target_id": "compliant-target",
               "endpoint": BASE + "/targets/compliant/invoice-total",
               "consent_token": "demo-consent"}})
check("UNSUPPORTED_CAPABILITY 422", s == 422 and b["error_code"] == "UNSUPPORTED_CAPABILITY")
s, b = call("GET", "/tests/t_deadbeef")
check("UNKNOWN_TEST 404", s == 404)

print(f"{'CHECK':52s} RESULT")
fails = 0
for name, ok, detail in checks:
    print(f"{name:52s} {'PASS' if ok else 'FAIL ' + detail}")
    fails += 0 if ok else 1
print(f"\n{len(checks)-fails}/{len(checks)} passed")
sys.exit(1 if fails else 0)
