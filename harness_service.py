#!/usr/bin/env python3
"""Patched Spike 1 harness. Runs the server IN-THREAD so the tamper test can
mutate stored evidence directly. All canaries travel over real HTTP."""
import json, os, sys, time, threading, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.setdefault("HOST", "127.0.0.1")
os.environ.setdefault("PORT", "8787")
os.environ.setdefault("PUBLIC_BASE", "http://127.0.0.1:8787")
import app  # noqa: E402

BASE = os.environ["PUBLIC_BASE"]
threading.Thread(target=app.serve, daemon=True).start()

# readiness polling (bounded)
ready = False
for _ in range(50):
    try:
        with urllib.request.urlopen(BASE + "/health", timeout=0.5) as r:
            if r.status == 200: ready = True; break
    except Exception:
        time.sleep(0.1)
if not ready:
    print("FATAL: service never became ready"); sys.exit(2)

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

# 1 compliant real HTTP -> PASS
s, b = submit("compliant-target", "/targets/compliant/invoice-total")
check("compliant real-HTTP -> PASS", s == 200 and b["verdict"] == "PASS", json.dumps(b)[:160])
check("compliant -> DELEGATE", b["recommended_action"]["action"] == "DELEGATE")
pass_tid, pass_rid = b["test_id"], b["receipt_id"]
check("absolute evidence/receipt/verify URLs",
      b["evidence_url"].startswith("http") and b["receipt_url"].startswith("http")
      and b["verify_url"].startswith("http"))

# 2 failing real HTTP -> FAIL
s, b = submit("failing-target", "/targets/failing/invoice-total")
check("failing real-HTTP -> FAIL", s == 200 and b["verdict"] == "FAIL")
check("failing -> DO_NOT_DELEGATE", b["recommended_action"]["action"] == "DO_NOT_DELEGATE")

# 3 nonexistent endpoint -> UNAVAILABLE
s, b = submit("unreachable-target", endpoint_abs="http://127.0.0.1:9/invoice-total")
check("unreachable -> UNAVAILABLE", s == 200 and b["verdict"] == "UNAVAILABLE", json.dumps(b)[:160])
check("unreachable retry_allowed true", b["recommended_action"]["retry_allowed"] is True)

# 4 malformed JSON -> INCONCLUSIVE
s, b = submit("malformed-target", "/targets/malformed/invoice-total")
check("malformed body -> INCONCLUSIVE", s == 200 and b["verdict"] == "INCONCLUSIVE")

# 5 compliant target_id with wrong endpoint -> TARGET_NOT_CONSENTED
s, b = submit("compliant-target", "/targets/failing/invoice-total")
check("id/endpoint mismatch -> TARGET_NOT_CONSENTED", s == 403
      and b["error_code"] == "TARGET_NOT_CONSENTED")
s, b = submit("compliant-target", endpoint_abs="http://evil.example/steal")
check("foreign endpoint -> TARGET_NOT_CONSENTED", s == 403
      and b["error_code"] == "TARGET_NOT_CONSENTED")

# 6 evidence records actually-called endpoint
s, ev = call("GET", f"/tests/{pass_tid}/evidence")
ep_recorded = ev["entries"][0]["request"]["endpoint"]
check("evidence records real called endpoint",
      ep_recorded == BASE + "/targets/compliant/invoice-total", ep_recorded)
check("evidence has raw_body_sha256 + status",
      ev["entries"][0]["response"]["raw_body_sha256"]
      and ev["entries"][0]["response"]["status_code"] == 200)

# 7 determinism over valid real endpoints (5x each)
det = all(submit("compliant-target", "/targets/compliant/invoice-total")[1]["verdict"] == "PASS"
          for _ in range(5))
det &= all(submit("failing-target", "/targets/failing/invoice-total")[1]["verdict"] == "FAIL"
           for _ in range(5))
check("deterministic over 10 real-HTTP repeats", det)

# 8 receipt verifies, then tamper -> invalid
s, v = call("POST", f"/receipts/{pass_rid}/verify")
check("receipt verifies valid pre-tamper", s == 200 and v["valid"] is True)
app.TESTS[pass_tid]["evidence"][0]["response"]["body"]["total"] = 999.99  # tamper
s, v = call("POST", f"/receipts/{pass_rid}/verify")
check("tampered evidence -> valid:false", s == 200 and v["valid"] is False, json.dumps(v))

# errors retained
s, b = call("POST", "/tests", {"contract_id": "nope.v1",
    "target": {"target_id": "compliant-target",
               "endpoint": BASE + "/targets/compliant/invoice-total",
               "consent_token": "demo-consent"}})
check("UNSUPPORTED_CAPABILITY 422", s == 422 and b["error_code"] == "UNSUPPORTED_CAPABILITY")
s, b = call("POST", "/tests", {"contract_id": "invoice.extract-total.v1"})
check("INVALID_CONTRACT 400", s == 400 and b["error_code"] == "INVALID_CONTRACT")
s, b = call("GET", "/tests/t_deadbeef")
check("UNKNOWN_TEST 404", s == 404 and b["error_code"] == "UNKNOWN_TEST")

print(f"{'CHECK':48s} RESULT")
fails = 0
for name, ok, detail in checks:
    print(f"{name:48s} {'PASS' if ok else 'FAIL ' + detail}")
    fails += 0 if ok else 1
print(f"\n{len(checks)-fails}/{len(checks)} passed")
sys.exit(1 if fails else 0)
