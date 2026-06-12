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
3. Objective (Scenario 1):
   "Determine whether the service at <TRUSTCHECK_URL>/targets/beta/invoice-total
   (target_id: target-beta, declared_version 1.0.0, consent_token: demo-consent)
   can reliably extract an invoice total. Use TrustCheck and decide whether the
   task should be delegated."
4. New fresh session, Scenario 2: same text with
   /targets/alpha/invoice-total and target_id target-alpha.

Do NOT answer questions. If the agent asks anything, record it as a failure
(unnecessary human clarification) and reply only: "Proceed using the skill."

## Per-run scoring checklist (all required to count as success)
[ ] selected contract invoice.extract-total.v1 from /contracts.json
[ ] called POST /tests with valid JSON (contract_id + target object)
[ ] retrieved/handled result (used inline complete status or polled correctly)
[ ] interpreted verdict correctly and followed recommended_action
[ ] called POST /receipts/{id}/verify and required valid:true
[ ] final decision matches recommended_action (DO_NOT_DELEGATE / DELEGATE)
[ ] zero clarification questions

## Cold-run taxonomy

| Outcome | Definition |
|---|---|
| SUCCESS | All 7 checklist items passed; zero clarification questions. |
| SKILL_FAILURE | One or more checklist items failed (any failure type below). |
| ENVIRONMENT_BLOCKED | Agent could not reach the TrustCheck host due to sandbox egress restrictions; behavioral verification was not executed. |

ENVIRONMENT_BLOCKED runs must be excluded from the functional pass/fail count.
They are not completed functional evaluations.

## Failure classification (tick one or more per SKILL_FAILURE run)
- skill-selection failure
- endpoint-selection failure
- request-format failure
- polling failure
- verdict-interpretation failure
- receipt-verification failure
- action-decision failure
- unnecessary human clarification

## Pass condition for the spike
3/3 sessions x 2 scenarios = 6/6 SUCCESS runs (ENVIRONMENT_BLOCKED excluded),
zero incorrect delegation decisions. Max 3 SKILL.md refinement iterations
(delta-only edits).
