---
name: trustcheck
description: Behaviorally verify that a target agent or service can actually perform ONE declared capability before delegating a consequential task to it. Use when you are about to delegate real work to an unverified target and a published TrustCheck contract exists for that capability. Returns PASS / FAIL / INCONCLUSIVE / UNAVAILABLE plus a signed, replayable evidence receipt.
---

# TrustCheck — Behavioral Capability Verification

TrustCheck tests one declared capability against one explicit test contract using
safe, consented canary requests. It is NOT a trust score, NOT identity
verification, and NOT a reputation system.

Base URL: provided by the user as TRUSTCHECK_URL (example below uses
`http://127.0.0.1:8787`).

## Use TrustCheck when ALL of these are true
- You are about to delegate a consequential (costly or hard-to-reverse) task.
- The target has not been behaviorally verified recently (no unexpired receipt).
- A compatible published contract exists in `GET /contracts.json` for the
  capability you need.

## Do NOT use TrustCheck when
- You need identity verification or AgentFacts schema validation (out of scope).
- The task is trivial or easily reversible — just attempt it.
- No compatible contract exists — report `UNSUPPORTED_CAPABILITY` to the user;
  do not invent a contract.
- The target has not consented (no valid `consent_token`).
- You want a universal reputation/trust score — TrustCheck does not provide one.

## Exact operating procedure
1. `GET {TRUSTCHECK_URL}/contracts.json` and find a contract whose
   `capability_id` matches the capability you need to delegate.
2. If no contract matches: stop and report `UNSUPPORTED_CAPABILITY`.
3. `POST {TRUSTCHECK_URL}/tests` with the `contract_id` and a `target` object
   (see worked example). Never modify or author contracts.
4. Store the returned `test_id`.
5. If the response `status` is already `"complete"`, use it directly. Otherwise
   poll `GET {TRUSTCHECK_URL}/tests/{test_id}` every 2 seconds, maximum 30
   polls; if still not complete, treat as UNAVAILABLE.
6. Interpret `verdict`:
   - `PASS` → verify the receipt (step 7); if valid, the capability is verified
     — proceed to delegate and cite `receipt_id`.
   - `FAIL` → do NOT delegate. Cite `evidence_url` in your report.
   - `INCONCLUSIVE` → retry the test once; if still inconclusive, do NOT
     delegate for consequential tasks.
   - `UNAVAILABLE` → wait 5 seconds, retry once; if still unavailable, report
     the target as unavailable and do not delegate now.
7. Verify the receipt. Two equivalent options:
   - Convenience: `POST {TRUSTCHECK_URL}/receipts/{receipt_id}/verify`.
   - Independent (recommended, zero server trust): fetch the issuer public key
     from `GET {TRUSTCHECK_URL}/.well-known/trustcheck-key.json`, then check the
     receipt's Ed25519 `signature` over its canonical signed fields using the
     key whose `kid` equals the receipt's `key_id`. No server secret is needed,
     so a compromised server cannot forge a passing receipt.
   Require `"valid": true` before citing the receipt or delegating. If
   `valid` is false, treat the result as INCONCLUSIVE.
8. Always follow `recommended_action.action` (`DELEGATE` /
   `DO_NOT_DELEGATE`) unless receipt verification failed. When
   `retry_allowed` is true (INCONCLUSIVE or UNAVAILABLE), you may retry the
   test exactly once before accepting DO_NOT_DELEGATE.
9. On any error response, read `agent_action_hint` and follow it exactly. After
   two failed recovery attempts, conclude UNAVAILABLE.
10. Never ask a human for clarification unless the user explicitly requested
    manual escalation. Every situation above has a defined action.

## Worked example (literal)

Goal: decide whether `compliant-target` can extract invoice totals.

**Step 1 — list contracts**
```
GET http://127.0.0.1:8787/contracts.json
```
Response (truncated):
```json
{"contracts": [{"contract_id": "invoice.extract-total.v1",
                "capability_id": "invoice.extract-total", "...": "..."}]}
```
`invoice.extract-total` matches → use `contract_id` `invoice.extract-total.v1`.

**Step 2 — submit test**
```
POST http://127.0.0.1:8787/tests
Content-Type: application/json

{
  "contract_id": "invoice.extract-total.v1",
  "target": {
    "target_id": "compliant-target",
    "endpoint": "http://127.0.0.1:8787/targets/compliant/invoice-total",
    "declared_version": "1.0.0",
    "consent_token": "demo-consent"
  }
}
```
Response:
```json
{
  "test_id": "t_ab12cd34",
  "status": "complete",
  "capability_id": "invoice.extract-total",
  "verdict": "PASS",
  "recommended_action": {"action": "DELEGATE",
                          "reason": "All required predicates passed.",
                          "retry_allowed": false},
  "runs": 3,
  "latency_ms": {"p50": 1.2, "max": 2.0},
  "receipt_id": "r_ab12cd34",
  "evidence_url": "http://127.0.0.1:8787/tests/t_ab12cd34/evidence",
  "receipt_url": "http://127.0.0.1:8787/receipts/r_ab12cd34",
  "verify_url": "http://127.0.0.1:8787/receipts/r_ab12cd34/verify",
  "valid_until": "2026-07-12T15:00:00+00:00"
}
```
`status` is `complete` → no polling needed.

**Step 3 — verify receipt**
```
POST http://127.0.0.1:8787/receipts/r_ab12cd34/verify
```
Response:
```json
{"receipt_id": "r_ab12cd34", "valid": true, "reasons": []}
```

**Step 4 — decide**
Verdict PASS + receipt valid → DELEGATE. Report: "Capability
invoice.extract-total verified PASS at <timestamp>, receipt r_ab12cd34
(valid until <valid_until>). Evidence: /tests/t_ab12cd34/evidence."

For the failing target, the same flow returns `"verdict": "FAIL"` and
`recommended_action.action = "DO_NOT_DELEGATE"` → report that delegation is
unsafe and include `evidence_url`. The receipt for a FAIL is still verifiable —
it proves the failure happened.

## Error codes
| error_code | meaning | what you do |
|---|---|---|
| INVALID_CONTRACT | malformed request body | fix body per `agent_action_hint`, resend once |
| UNSUPPORTED_CAPABILITY | no published contract | stop; report to user |
| TARGET_NOT_CONSENTED | target not allowlisted/consented | stop; do not retry this target |
| UNKNOWN_TEST | bad id | recheck stored id, retry once |
| RATE_LIMITED | too many tests | wait 60s, retry once |
| EXECUTOR_BUSY | service overloaded | wait 5s, retry once |

## Receipt verification (Ed25519, independent)

Every receipt is signed with Ed25519 and is independently verifiable — you do
not have to trust the TrustCheck server.

Signed fields (the signature covers exactly these, in canonical form):
`receipt_id, test_id, contract_id, capability_id, target_id, target_endpoint,
declared_version, verdict, recommended_action, evidence_root_hash, issued_at,
valid_until, key_id, signature_algorithm, canonicalization_version`.

To verify independently:
1. `GET {TRUSTCHECK_URL}/.well-known/trustcheck-key.json`.
2. Find the key whose `kid` == the receipt's `key_id` (check `active_key`, then
   `previous_keys`). If the `kid` is only in `revoked_keys`, treat as invalid.
3. Rebuild the canonical message: take the 15 signed fields above (NOT
   `signature`), serialize as compact JSON with sorted keys and UTF-8.
4. Verify the Ed25519 `signature` (base64url) against that message with the
   key's public bytes `x` (base64url).
5. Accept only if the signature verifies AND `canonicalization_version` is one
   you support (`tc-canon-1`).

If any signed field was altered (verdict, target, evidence_root_hash,
valid_until, ...), verification fails. The legacy `hmac_signature_DEPRECATED`
field must NOT be used; it remains only for backward compatibility.

## Result fields you must read
`verdict`, `recommended_action`, `receipt_id`, `evidence_url`, `receipt_url`,
`verify_url` (all absolute URLs), `valid_until`.
A verdict applies only to: the tested capability, the tested target version,
at the test timestamp, until `valid_until`. After expiry, re-test.
