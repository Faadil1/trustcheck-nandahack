---
name: trustcheck
description: Behaviorally verify that a target agent or service can actually perform ONE declared capability before delegating a consequential task to it. Use when you are about to delegate real work to an unverified target and a published TrustCheck contract exists for that capability. Returns PASS / FAIL / INCONCLUSIVE / UNAVAILABLE plus a signed, replayable evidence receipt.
---

# TrustCheck — Behavioral Capability Verification

TrustCheck tests one declared capability against one explicit test contract using safe, consented canary requests.

TrustCheck is:

a behavioral capability verifier;
a runtime reliability checker;
an evidence-producing service.

TrustCheck is NOT:

a universal trust score;
identity verification;
AgentFacts schema validation;
a reputation system;
permission to scan arbitrary services.

The TrustCheck base URL is supplied by the user as:

TRUSTCHECK_URL

Example:

https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app
1. Use TrustCheck when

Use TrustCheck only when all of the following are true:

You are about to delegate a consequential task.
The task is costly, security-sensitive, financially relevant, or difficult to reverse.
The target has not been behaviorally verified recently.
No valid, unexpired TrustCheck receipt already exists for the same:
capability;
target;
target version;
test contract.
A compatible published contract exists in:
GET {TRUSTCHECK_URL}/contracts.json
The target has explicitly consented to the test.
The target endpoint is included in the TrustCheck allowlist or consent registry.
2. Do not use TrustCheck when

Do not use TrustCheck when:

You need identity verification.
You need to validate an AgentFacts document or schema.
The task is trivial or easily reversible.
No compatible published capability contract exists.
The target has not consented.
You want a universal reputation or trust score.
You want to scan, probe, or test an arbitrary third-party endpoint.
The current execution environment cannot make the required HTTP requests.

If no compatible contract exists:

Status: UNSUPPORTED_CAPABILITY
Decision: DO_NOT_DELEGATE

Do not invent, modify, or author a new contract.

3. Supported verdicts

TrustCheck returns one of four verdicts.

PASS

The target successfully completed every required behavioral test and predicate.

Required action:

DELEGATE

Only delegate after the evidence receipt has been verified and returns:

{
  "valid": true
}
FAIL

The target responded successfully, but its output failed one or more explicit contract predicates.

Required action:

DO_NOT_DELEGATE

A valid FAIL receipt proves that the behavioral failure was observed.

INCONCLUSIVE

The service responded, but TrustCheck could not confidently evaluate the result.

Examples:

malformed response;
non-JSON body;
unsupported predicate;
unverifiable output.

Required action:

Retry the test exactly once if retry_allowed is true.
If the second test is also inconclusive:
DO_NOT_DELEGATE
UNAVAILABLE

The test could not be completed.

Examples:

connection refused;
timeout;
network restriction;
blocked network egress;
service overload;
target returned a server error;
required HTTP tool unavailable.

Required action:

Retry exactly once only when the environment permits it.
If still unavailable:
DO_NOT_DELEGATE

Do not convert UNAVAILABLE into FAIL.

4. Exact operating procedure

Follow these steps exactly.

Step 1 — List published contracts

Call:

GET {TRUSTCHECK_URL}/contracts.json

Find a contract whose:

capability_id

matches the capability needed for delegation.

For invoice-total extraction, the expected capability is:

invoice.extract-total

The currently published contract is:

invoice.extract-total.v1
Step 2 — Stop if no matching contract exists

If no compatible contract is found:

Status: UNSUPPORTED_CAPABILITY
Verification executed: NO
Receipt verified: NO
Decision: DO_NOT_DELEGATE

Do not create a new contract.

Step 3 — Submit the behavioral test

Call:

POST {TRUSTCHECK_URL}/tests
Content-Type: application/json

Request body:

{
  "contract_id": "invoice.extract-total.v1",
  "target": {
    "target_id": "TARGET_ID",
    "endpoint": "TARGET_ENDPOINT",
    "declared_version": "TARGET_VERSION",
    "consent_token": "CONSENT_TOKEN"
  }
}

The target_id, endpoint, and consent_token must match a registered consent binding.

Never replace the submitted endpoint with another endpoint.

Never infer behavior from the target name.

Target identifiers such as target-alpha and target-beta are intentionally opaque and reveal nothing about the expected verdict.

Step 4 — Store the test identifier

Store:

test_id

from the response.

Step 5 — Retrieve the result

If the initial response contains:

{
  "status": "complete"
}

use the returned result directly.

Otherwise poll:

GET {TRUSTCHECK_URL}/tests/{test_id}

Polling rules:

wait 2 seconds between polls;
maximum 30 polls;
stop immediately when status becomes complete;
if no complete result exists after 30 polls, classify as UNAVAILABLE.
Step 6 — Read all required result fields

Always read:

verdict
recommended_action
receipt_id
evidence_url
receipt_url
verify_url
valid_until

Do not make the delegation decision before reading these fields.

Step 7 — Verify the receipt

Call the absolute URL provided in:

verify_url

using:

POST {verify_url}

The current spike uses a server-side integrity check based on:

HMAC-SHA256;
an evidence hash chain.

Require:

{
  "valid": true
}

before citing the receipt or delegating.

If the verification response returns:

{
  "valid": false
}

treat the result as:

INCONCLUSIVE

and return:

DO_NOT_DELEGATE

Important limitation:

Independent public-key verification is not available in this version. Ed25519 public-key verification is planned for a later version.

Step 8 — Follow the recommended action

Follow:

recommended_action.action

Allowed actions:

DELEGATE
DO_NOT_DELEGATE

Exception:

If receipt verification fails, always use:

DO_NOT_DELEGATE

even if the original verdict was PASS.

Step 9 — Handle retryable results

If:

retry_allowed = true

you may retry the complete test exactly once.

Do not retry more than once.

After the permitted retry:

PASS + valid receipt → DELEGATE
FAIL → DO_NOT_DELEGATE
INCONCLUSIVE → DO_NOT_DELEGATE
UNAVAILABLE → DO_NOT_DELEGATE
Step 10 — Handle errors

Every TrustCheck error contains:

error_code
message
agent_action_hint

Read and follow:

agent_action_hint

exactly.

After two failed recovery attempts, stop and classify the result as:

UNAVAILABLE
Step 11 — Do not request human clarification

Do not ask the user to:

select a contract;
provide a different target;
approve the verdict;
interpret the receipt;
modify network settings;
add the domain to an allowlist;
install another tool;
authorize another retry.

All supported conditions have a defined terminal action.

Manual escalation is permitted only when the user explicitly requested it before the verification started.

5. Execution environment blocked

An environment is blocked when:

no HTTP tool is available;
HTTP POST requests are unsupported;
the TrustCheck host is blocked by a network allowlist;
network egress is prohibited;
DNS resolution is blocked;
a proxy prevents access before the TrustCheck service is reached.

When the environment is blocked:

Do not ask the user to change settings.
Do not ask the user to add an allowlist.
Do not ask for another tool.
Do not offer to retry.
Do not infer PASS.
Do not infer FAIL.
Do not claim that the target was tested.
Set the operational result to UNAVAILABLE.
State that verification was not executed.
For consequential tasks, return DO_NOT_DELEGATE.
End the response immediately after the required structured result.

Required final format:

Status: UNAVAILABLE
Verification executed: NO
Cause: EXECUTION_ENVIRONMENT_BLOCKED
Receipt verified: NO
Decision: DO_NOT_DELEGATE
Retry: Only in a different environment that already supports HTTP access.

Do not append:

a question;
an offer;
a request for configuration changes;
a speculative verdict.
6. Error codes
error_code	Meaning	Required agent action
INVALID_CONTRACT	The request body or contract reference is malformed	Correct the body using agent_action_hint, then resend once
UNSUPPORTED_CAPABILITY	No published contract supports the capability	Stop and return DO_NOT_DELEGATE
TARGET_NOT_CONSENTED	The target ID, endpoint, or consent token does not match a registered binding	Stop; do not retry this target/endpoint pair
UNKNOWN_TEST	The test or receipt identifier is unknown	Recheck the stored ID and retry once
RATE_LIMITED	Too many test requests	Wait 60 seconds and retry once
EXECUTOR_BUSY	TrustCheck cannot execute the test now	Wait 5 seconds and retry once
EXECUTION_ENVIRONMENT_BLOCKED	The agent environment cannot reach TrustCheck	Return UNAVAILABLE and DO_NOT_DELEGATE; do not ask a question
7. Worked example — opaque target

Goal:

Determine whether target-alpha can perform:

invoice.extract-total

The identifier target-alpha does not indicate whether the target is compliant or failing.

Step 1 — List contracts
GET https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app/contracts.json

Expected response structure:

{
  "contracts": [
    {
      "contract_id": "invoice.extract-total.v1",
      "capability_id": "invoice.extract-total"
    }
  ]
}

Select:

invoice.extract-total.v1
Step 2 — Submit the test
POST https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app/tests
Content-Type: application/json
{
  "contract_id": "invoice.extract-total.v1",
  "target": {
    "target_id": "target-alpha",
    "endpoint": "https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app/targets/alpha/invoice-total",
    "declared_version": "1.0.0",
    "consent_token": "demo-consent"
  }
}

Do not assume the expected verdict from the target identifier.

Read the actual response.

Example response structure:

{
  "test_id": "t_example123",
  "status": "complete",
  "capability_id": "invoice.extract-total",
  "verdict": "PASS_OR_FAIL_OR_INCONCLUSIVE_OR_UNAVAILABLE",
  "recommended_action": {
    "action": "DELEGATE_OR_DO_NOT_DELEGATE",
    "reason": "Result-specific explanation.",
    "retry_allowed": false
  },
  "runs": 3,
  "latency_ms": {
    "p50": 120,
    "max": 180
  },
  "receipt_id": "r_example123",
  "evidence_url": "https://trustcheck.example/tests/t_example123/evidence",
  "receipt_url": "https://trustcheck.example/receipts/r_example123",
  "verify_url": "https://trustcheck.example/receipts/r_example123/verify",
  "valid_until": "2026-07-12T15:00:00+00:00"
}
Step 3 — Verify the receipt
POST {verify_url}

Expected response structure:

{
  "receipt_id": "r_example123",
  "valid": true,
  "verification_scope": "server-side HMAC + evidence hash chain (spike)",
  "reasons": []
}
Step 4 — Decide

Use this decision table:

Actual verdict	Receipt valid	Final decision
PASS	true	DELEGATE
PASS	false	DO_NOT_DELEGATE
FAIL	true	DO_NOT_DELEGATE
INCONCLUSIVE after allowed retry	true or false	DO_NOT_DELEGATE
UNAVAILABLE after allowed retry	no receipt required	DO_NOT_DELEGATE
8. Required final response format

After a completed test, return:

Capability: <capability_id>
Target: <target_id>
Target version: <declared_version>
Status: <PASS | FAIL | INCONCLUSIVE | UNAVAILABLE>
Verification executed: YES
Receipt verified: <YES | NO>
Receipt ID: <receipt_id or NONE>
Evidence URL: <evidence_url or NONE>
Valid until: <valid_until or NONE>
Decision: <DELEGATE | DO_NOT_DELEGATE>
Reason: <concise reason from the verified result>

Do not add a question after this result.

Do not offer another action unless the user explicitly asks.

9. Scope and limitations

A TrustCheck verdict applies only to:

the tested capability;
the tested target;
the declared target version;
the published test contract;
the test conditions;
the test timestamp;
the validity period ending at valid_until.

A valid receipt does not prove:

identity;
ownership;
authorization outside the tested task;
general trustworthiness;
performance on unrelated capabilities;
future performance after the receipt expires.

After expiration, run a new test before delegating another consequential task.
