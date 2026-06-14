# Spike 1 — Cold-Agent Test Protocol (TO BE EXECUTED BY OPERATOR)

## Setup
1. Deploy the stub: `python3 app.py` on a reachable host (or `ngrok http 8787`).
2. Note the public base URL = TRUSTCHECK_URL.

## Sessions (minimum 3 fresh sessions, no prior context)
- A: Claude (fresh chat, no system additions beyond skill)
- B: GPT (fresh chat)
- C: OpenClaw-compatible stock agent (when available)

## Per-session inputs — give ONLY these, verbatim
1. The full SKILL.md file contents.
2. "TRUSTCHECK_URL = <deployed URL>"
3. Objective (Scenario 1, failing):
   "Determine whether the service at <TRUSTCHECK_URL>/targets/failing/invoice-total
   (target_id: failing-target, declared_version 1.0.0, consent_token: demo-consent)
   can reliably extract an invoice total. Use TrustCheck and decide whether the
   task should be delegated."
4. New fresh session, Scenario 2 (compliant): same text with
   /targets/compliant/invoice-total and target_id compliant-target.

Do NOT answer questions. If the agent asks anything, record it as a failure
(unnecessary human clarification) and reply only: "Proceed using the skill."

## Per-run scoring checklist (all required to count as success)
[ ] selected contract invoice.extract-total.v1 from /contracts.json
[ ] called POST /tests with valid JSON (contract_id + target object)
[ ] retrieved/handled result (used inline complete status or polled correctly)
[ ] interpreted verdict correctly (FAIL for failing, PASS for compliant)
[ ] called POST /receipts/{id}/verify and required valid:true
[ ] final decision matches recommended_action (DO_NOT_DELEGATE / DELEGATE)
[ ] zero clarification questions

## Failure classification (tick one or more per failed run)
- skill-selection failure
- endpoint-selection failure
- request-format failure
- polling failure
- verdict-interpretation failure
- receipt-verification failure
- action-decision failure
- unnecessary human clarification

## Pass condition for the spike
3/3 sessions x 2 scenarios = 6/6 successful runs, zero incorrect delegation
decisions. Max 3 SKILL.md refinement iterations (delta-only edits).

---

## Spike 3 addendum — Independent receipt verification step

After the agent reaches a verdict, add one required step to each run:

[ ] agent (or operator) verifies the receipt INDEPENDENTLY using only the
    receipt JSON + the public key from `GET {TRUSTCHECK_URL}/.well-known/trustcheck-key.json`
    (e.g. `python3 verify_receipt.py receipt.json`), and requires `valid: true`
    before citing it.

Negative control (operator-run, not shown to agent): take a PASS receipt,
change `verdict` to `FAIL` (or alter `target_id`/`evidence_root_hash`), re-run
the independent verifier, and confirm it returns `valid: false`. This proves the
agent's trust is anchored in the signature, not in the server's word.

Updated pass condition: all Spike 1 criteria PLUS successful independent
verification on genuine receipts and correct rejection of the tampered control.
