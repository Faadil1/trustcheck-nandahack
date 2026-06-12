#!/usr/bin/env python3
"""TrustCheck Spike 1 stub service — PATCHED.

Patch: canaries are now executed over real HTTP against target.endpoint
(stdlib urllib). Allowlist binds target_id <-> endpoint <-> consent_token.
Transport failures map to UNAVAILABLE/INCONCLUSIVE, never silently FAIL.
"""
import json, hashlib, hmac, time, uuid, re, os, urllib.request, urllib.error, socket
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIGNING_KEY = b"spike1-demo-key-not-for-production"
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8787"))
PUBLIC_BASE = os.getenv("PUBLIC_BASE", f"http://127.0.0.1:{PORT}")

# target_id -> binding. "path" = path on this service (endpoint must be
# <any-host-resolving-to-this-service>{path}); "endpoint" = exact absolute URL.
ALLOWED_TARGETS = {
    "compliant-target":  {"path": "/targets/compliant/invoice-total",  "consent_token": "demo-consent"},
    "failing-target":    {"path": "/targets/failing/invoice-total",    "consent_token": "demo-consent"},
    "malformed-target":  {"path": "/targets/malformed/invoice-total",  "consent_token": "demo-consent"},
    "unreachable-target": {"endpoint": "http://127.0.0.1:9/invoice-total", "consent_token": "demo-consent"},
}

CONTRACTS = {
    "invoice.extract-total.v1": {
        "contract_id": "invoice.extract-total.v1",
        "capability_id": "invoice.extract-total",
        "method": "POST",
        "request_template": {"invoice": "{{input.invoice}}"},
        "canaries": [{
            "input": {"invoice": {"subtotal": 110.00, "tax": 13.45, "currency": "CAD"}},
            "predicates": [
                {"type": "equals", "path": "$.currency", "expected": "CAD"},
                {"type": "equals", "path": "$.total", "expected": 123.45},
                {"type": "status_code", "expected": 200},
            ],
        }],
        "runs_per_canary": 3,
        "pass_threshold": 1.0,
        "timeout_ms": 5000,
        "validity_hours": 24,
    }
}

TESTS, RECEIPTS = {}, {}

def now_utc(): return datetime.now(timezone.utc)
def canon(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
def sha256(b): return hashlib.sha256(b).hexdigest()
def sign(h): return hmac.new(SIGNING_KEY, h.encode(), hashlib.sha256).hexdigest()

def consent_check(target):
    """Validate exact binding of target_id, endpoint, consent_token."""
    binding = ALLOWED_TARGETS.get(target.get("target_id"))
    if not binding or target.get("consent_token") != binding["consent_token"]:
        return False
    ep = target.get("endpoint", "")
    if "endpoint" in binding:
        return ep == binding["endpoint"]
    # path-bound: endpoint must parse and its path must equal the bound path
    m = re.fullmatch(r"https?://[^/]+(/.*)", ep)
    return bool(m) and m.group(1) == binding["path"]

# ---------------- real HTTP canary execution -------------------------------
def http_canary(endpoint, body, timeout_ms):
    t0 = time.perf_counter()
    rec = {"requested_url": endpoint}
    try:
        req = urllib.request.Request(endpoint, method="POST",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as r:
            raw = r.read()
            rec.update(status_code=r.status,
                       headers={k: v for k, v in r.headers.items()
                                if k.lower() in ("server", "x-target-version", "content-type")},
                       raw_body_sha256=sha256(raw),
                       transport="ok")
            try:
                rec["body"] = json.loads(raw)
            except json.JSONDecodeError:
                rec["body"] = None
                rec["transport"] = "non_json_body"
                rec["raw_body_preview"] = raw[:200].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        rec.update(status_code=e.code, raw_body_sha256=sha256(raw), transport="ok")
        try: rec["body"] = json.loads(raw)
        except json.JSONDecodeError:
            rec["body"], rec["transport"] = None, "non_json_body"
    except (urllib.error.URLError, ConnectionError, socket.timeout, OSError) as e:
        rec.update(status_code=None, body=None, raw_body_sha256=None,
                   transport="network_error", error=str(e)[:200])
    rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return rec

def jget(obj, path):
    m = re.fullmatch(r"\$\.([A-Za-z0-9_]+)", path)
    if not m or not isinstance(obj, dict): return None, False
    return obj.get(m.group(1)), m.group(1) in obj

def eval_predicates(preds, status, body):
    out, unsupported = [], False
    for p in preds:
        if p["type"] == "status_code":
            ok = status == p["expected"]
            out.append({"predicate": p, "observed": status, "passed": ok})
        elif p["type"] == "equals":
            v, found = jget(body, p["path"])
            ok = found and v == p["expected"]
            out.append({"predicate": p, "observed": v, "passed": ok})
        else:
            unsupported = True
            out.append({"predicate": p, "observed": None, "passed": False,
                        "note": "unsupported predicate type"})
    return out, unsupported

def run_test(contract, target):
    """Execute canaries over real HTTP. Verdict mapping:
    network error / timeout / 5xx -> UNAVAILABLE
    non-JSON body / unsupported predicate -> INCONCLUSIVE
    predicates all pass on all runs -> PASS ; predicate failure -> FAIL
    Severity order: UNAVAILABLE > INCONCLUSIVE > FAIL > PASS (any worse run
    dominates, since pass_threshold is 1.0 in this spike)."""
    entries, latencies = [], []
    saw_unavailable = saw_inconclusive = saw_fail = False
    for canary in contract["canaries"]:
        for run_i in range(contract["runs_per_canary"]):
            body = {"invoice": canary["input"]["invoice"]}
            rec = http_canary(target["endpoint"], body, contract["timeout_ms"])
            latencies.append(rec["latency_ms"])
            if rec["transport"] == "network_error" or (
                    rec["status_code"] is not None and rec["status_code"] >= 500):
                saw_unavailable = True
                pres = []
            elif rec["transport"] == "non_json_body":
                saw_inconclusive = True
                pres = []
            else:
                pres, unsupported = eval_predicates(
                    canary["predicates"], rec["status_code"], rec["body"])
                if unsupported: saw_inconclusive = True
                elif not all(r["passed"] for r in pres): saw_fail = True
            entry = {"run": run_i + 1,
                     "request": {"method": contract["method"],
                                 "endpoint": rec["requested_url"], "body": body},
                     "response": {"status_code": rec["status_code"],
                                  "headers": rec.get("headers", {}),
                                  "body": rec["body"],
                                  "raw_body_sha256": rec["raw_body_sha256"],
                                  "transport": rec["transport"],
                                  "error": rec.get("error")},
                     "latency_ms": rec["latency_ms"],
                     "predicate_results": pres,
                     "run_passed": bool(pres) and all(r["passed"] for r in pres)}
            entry["entry_hash"] = sha256(canon({k: entry[k] for k in
                ("run", "request", "response", "predicate_results")}))
            entries.append(entry)
    verdict = ("UNAVAILABLE" if saw_unavailable else
               "INCONCLUSIVE" if saw_inconclusive else
               "FAIL" if saw_fail else "PASS")
    ls = sorted(latencies)
    return verdict, entries, {"p50": ls[len(ls)//2], "max": ls[-1]}

def make_receipt(test_id, contract, target, verdict, entries, stats, ts, valid_until):
    chain = "0" * 64
    for e in entries:
        chain = sha256((chain + e["entry_hash"]).encode())
    body = {"receipt_id": "r_" + test_id[2:], "test_id": test_id,
            "capability_tested": contract["capability_id"],
            "contract_id": contract["contract_id"],
            "contract_hash": sha256(canon(contract)),
            "test_conditions": {"runs_per_canary": contract["runs_per_canary"],
                                "pass_threshold": contract["pass_threshold"],
                                "timeout_ms": contract["timeout_ms"]},
            "success_criteria": contract["canaries"][0]["predicates"],
            "verdict": verdict, "evidence_chain_hash": chain, "timestamp": ts,
            "target": {"target_id": target["target_id"],
                       "endpoint": target["endpoint"],
                       "declared_version": target.get("declared_version")},
            "latency_ms": stats,
            "limitations": [
                "Behavioral test of one declared capability only.",
                "Does not verify identity or schema legitimacy (consume NANDA AgentFacts).",
                "Receipt verification is server-side (HMAC) in this spike; independent public-key verification is planned (Ed25519, Spike 3).",
                "Verdict valid only until revalidation date."],
            "valid_until": valid_until}
    h = sha256(canon(body))
    body["receipt_hash"], body["signature"] = h, sign(h)
    body["signature_alg"] = "HMAC-SHA256 server-side (spike); Ed25519 planned"
    return body

def err(code, msg, hint, status=400):
    return status, {"error_code": code, "message": msg, "agent_action_hint": hint}

class Handler(BaseHTTPRequestHandler):
    def _send(self, status, obj):
        b = json.dumps(obj, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try: return json.loads(raw or b"{}"), None
        except json.JSONDecodeError:
            return None, err("INVALID_CONTRACT", "Request body is not valid JSON.",
                             "Resend POST with a valid JSON body matching the documented schema.")

    def log_message(self, *a): pass

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/") or "/"
        if p == "/health":
            return self._send(200, {"status": "ok",
                "signing_key_fingerprint": sha256(SIGNING_KEY)[:16],
                "time": now_utc().isoformat()})
        if p == "/contracts.json":
            return self._send(200, {"contracts": list(CONTRACTS.values())})
        m = re.fullmatch(r"/tests/(t_[a-f0-9]+)", p)
        if m:
            t = TESTS.get(m.group(1))
            if not t: return self._send(*err("UNKNOWN_TEST", "No test with that id.",
                "Check the test_id returned by POST /tests and retry GET /tests/{id}.", 404))
            return self._send(200, t["result"])
        m = re.fullmatch(r"/tests/(t_[a-f0-9]+)/evidence", p)
        if m:
            t = TESTS.get(m.group(1))
            if not t: return self._send(*err("UNKNOWN_TEST", "No test with that id.",
                "Check the test_id and retry.", 404))
            return self._send(200, {"test_id": m.group(1), "entries": t["evidence"]})
        m = re.fullmatch(r"/receipts/(r_[a-f0-9]+)", p)
        if m:
            r = RECEIPTS.get(m.group(1))
            if not r: return self._send(*err("UNKNOWN_TEST", "No receipt with that id.",
                "Use the receipt_id from the test result.", 404))
            return self._send(200, r)
        return self._send(*err("UNKNOWN_TEST", "Unknown path.",
                               "Use only the endpoints documented in SKILL.md.", 404))

    def do_POST(self):
        p = self.path.rstrip("/")
        body, e = self._body()
        if e: return self._send(*e)

        if p == "/targets/compliant/invoice-total":
            inv = body.get("invoice", {})
            return self._send(200, {"currency": inv.get("currency"),
                "total": round(float(inv.get("subtotal", 0)) + float(inv.get("tax", 0)), 2)})
        if p == "/targets/failing/invoice-total":
            inv = body.get("invoice", {})
            return self._send(200, {"currency": inv.get("currency"),
                                    "total": float(inv.get("subtotal", 0))})
        if p == "/targets/malformed/invoice-total":
            b = b"this is not json {{{"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return

        if p == "/tests":
            cid = body.get("contract_id")
            target = body.get("target") or {}
            if not cid or not isinstance(target, dict) or "target_id" not in target \
                    or "endpoint" not in target:
                return self._send(*err("INVALID_CONTRACT",
                    "Body must include contract_id and target {target_id, endpoint, consent_token}.",
                    "POST /tests with {\"contract_id\": \"...\", \"target\": {\"target_id\": \"...\", \"endpoint\": \"https://...\", \"consent_token\": \"...\"}}."))
            if cid not in CONTRACTS:
                return self._send(*err("UNSUPPORTED_CAPABILITY",
                    f"No published contract '{cid}'.",
                    "Call GET /contracts.json, pick a listed contract_id, or report UNSUPPORTED_CAPABILITY to the user.", 422))
            if not consent_check(target):
                return self._send(*err("TARGET_NOT_CONSENTED",
                    "target_id, endpoint, and consent_token do not match a consented binding.",
                    "Only test consented targets with their registered endpoint. Do not retry with this target/endpoint pair.", 403))
            contract = CONTRACTS[cid]
            test_id = "t_" + uuid.uuid4().hex[:8]
            ts = now_utc()
            verdict, evidence, stats = run_test(contract, target)
            valid_until = (ts + timedelta(hours=contract["validity_hours"])).isoformat()
            receipt = make_receipt(test_id, contract, target, verdict, evidence,
                                   stats, ts.isoformat(), valid_until)
            RECEIPTS[receipt["receipt_id"]] = receipt
            rec = {"PASS": {"action": "DELEGATE",
                            "reason": "All required predicates passed.", "retry_allowed": False},
                   "FAIL": {"action": "DO_NOT_DELEGATE",
                            "reason": "Returned output did not satisfy the contract.",
                            "retry_allowed": False},
                   "INCONCLUSIVE": {"action": "DO_NOT_DELEGATE",
                            "reason": "Result inconclusive (malformed response or untestable predicate); retry once, then do not delegate for consequential tasks.",
                            "retry_allowed": True},
                   "UNAVAILABLE": {"action": "DO_NOT_DELEGATE",
                            "reason": "Target unreachable, timed out, or returned a server error.",
                            "retry_allowed": True}}[verdict]
            result = {"test_id": test_id, "status": "complete",
                      "capability_id": contract["capability_id"],
                      "verdict": verdict, "recommended_action": rec,
                      "runs": contract["runs_per_canary"] * len(contract["canaries"]),
                      "latency_ms": stats,
                      "receipt_id": receipt["receipt_id"],
                      "evidence_url": f"{PUBLIC_BASE}/tests/{test_id}/evidence",
                      "receipt_url": f"{PUBLIC_BASE}/receipts/{receipt['receipt_id']}",
                      "verify_url": f"{PUBLIC_BASE}/receipts/{receipt['receipt_id']}/verify",
                      "valid_until": valid_until}
            TESTS[test_id] = {"result": result, "evidence": evidence}
            return self._send(200, result)

        m = re.fullmatch(r"/receipts/(r_[a-f0-9]+)/verify", p)
        if m:
            r = RECEIPTS.get(m.group(1))
            if not r: return self._send(*err("UNKNOWN_TEST", "No receipt with that id.",
                "Use the receipt_id from the test result.", 404))
            core = {k: v for k, v in r.items()
                    if k not in ("receipt_hash", "signature", "signature_alg")}
            h = sha256(canon(core))
            valid = (h == r["receipt_hash"]) and hmac.compare_digest(sign(h), r["signature"])
            t = TESTS.get(r["test_id"])
            chain = "0" * 64
            for entry in (t["evidence"] if t else []):
                recomputed = sha256(canon({k: entry[k] for k in
                    ("run", "request", "response", "predicate_results")}))
                if recomputed != entry["entry_hash"]: valid = False
                chain = sha256((chain + entry["entry_hash"]).encode())
            if t and chain != r["evidence_chain_hash"]: valid = False
            return self._send(200, {"receipt_id": r["receipt_id"], "valid": valid,
                "verification_scope": "server-side HMAC + evidence hash chain (spike)",
                "reasons": [] if valid else
                ["hash or signature mismatch — receipt or evidence altered"]})
        return self._send(*err("UNKNOWN_TEST", "Unknown path.",
                               "Use only the endpoints documented in SKILL.md.", 404))

def serve():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"TrustCheck spike stub on http://{HOST}:{PORT} (public base {PUBLIC_BASE})")
    srv.serve_forever()

if __name__ == "__main__":
    serve()
