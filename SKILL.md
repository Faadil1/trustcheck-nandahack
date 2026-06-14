---
name: trustcheck
description: Behaviorally verify that a target agent or service can actually perform ONE declared capability before delegating a consequential task to it. Use when you are about to delegate real work to an unverified target and a published TrustCheck contract exists for that capability. Returns PASS / FAIL / INCONCLUSIVE / UNAVAILABLE plus a signed, replayable evidence receipt.
---
---

name: trustcheck
description: Behaviorally verify whether a consented target agent or service can perform one declared capability before delegating consequential work. Use when a compatible published TrustCheck contract exists. Returns PASS, FAIL, INCONCLUSIVE, or UNAVAILABLE with an independently verifiable Ed25519 evidence receipt.
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# TrustCheck — Behavioral Capability Verification

TrustCheck runs safe, consented canary tests against one published capability contract.

TrustCheck is not:

* identity verification;
* AgentFacts schema validation;
* a reputation system;
* a universal trust score;
* permission to probe arbitrary endpoints.

The user supplies:

```text
TRUSTCHECK_URL
```

Example production service:

```text
https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app
```

Never replace `TRUSTCHECK_URL` with localhost, an example domain, or another host.

## When to use TrustCheck

Use TrustCheck only when all of these are true:

* You are about to delegate consequential, costly, sensitive, or difficult-to-reverse work.
* The target has not been verified recently with an unexpired receipt.
* A compatible contract exists in `GET {TRUSTCHECK_URL}/contracts.json`.
* The target supplied a valid consent token.
* The target ID and endpoint match a registered consent binding.

## When not to use TrustCheck

Do not use TrustCheck when:

* the task is trivial and easily reversible;
* identity verification is required;
* AgentFacts schema validation is required;
* no compatible published contract exists;
* the target has not consented;
* the target endpoint is not registered;
* a universal trust or reputation score is requested.

If no contract supports the required capability:

```text
Status: UNSUPPORTED_CAPABILITY
Decision: DO_NOT_DELEGATE
Independent receipt verification: NOT_EXECUTED
Receipt ID: NONE
Evidence URL: NONE
Valid until: NONE
Reason: No compatible published TrustCheck contract exists.
```

Do not invent, edit, or author a contract.

# Quick example

Given:

```text
TRUSTCHECK_URL=https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app
```

and this consented target:

```text
target_id: target-alpha
endpoint: https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app/targets/alpha/invoice-total
declared_version: 1.0.0
consent_token: demo-consent
required_capability: invoice.extract-total
```

First call:

```http
GET {TRUSTCHECK_URL}/contracts.json
```

Select the published contract whose `capability_id` is:

```text
invoice.extract-total
```

Then submit:

```http
POST {TRUSTCHECK_URL}/tests
Content-Type: application/json
```

```json
{
  "contract_id": "invoice.extract-total.v1",
  "target": {
    "target_id": "target-alpha",
    "endpoint": "https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app/targets/alpha/invoice-total",
    "declared_version": "1.0.0",
    "consent_token": "demo-consent"
  }
}
```

After receiving the result:

1. fetch `receipt_url`;
2. fetch `key_endpoint`;
3. verify the receipt's Ed25519 signature independently;
4. reject a revoked or unknown key;
5. follow the verified result's recommended action.

# Required operating procedure

## 1. Discover the contract

Call:

```http
GET {TRUSTCHECK_URL}/contracts.json
```

Find a contract whose `capability_id` exactly matches the capability needed for delegation.

For invoice-total extraction:

```text
capability_id: invoice.extract-total
contract_id: invoice.extract-total.v1
```

If no compatible contract exists, stop with `UNSUPPORTED_CAPABILITY`.

## 2. Submit the behavioral test

Call:

```http
POST {TRUSTCHECK_URL}/tests
Content-Type: application/json
```

Body:

```json
{
  "contract_id": "PUBLISHED_CONTRACT_ID",
  "target": {
    "target_id": "REGISTERED_TARGET_ID",
    "endpoint": "EXACT_REGISTERED_TARGET_ENDPOINT",
    "declared_version": "TARGET_VERSION",
    "consent_token": "CONSENT_TOKEN"
  }
}
```

Rules:

* use the exact supplied target ID;
* use the exact supplied endpoint;
* do not substitute another host or path;
* do not infer behavior from the target's name;
* do not modify the published contract;
* do not test an unconsented target.

## 3. Retrieve the result

Store the returned:

```text
test_id
```

If `status` is already `complete`, use the returned result.

Otherwise poll:

```http
GET {TRUSTCHECK_URL}/tests/{test_id}
```

Polling limits:

* wait 2 seconds between polls;
* maximum 30 polls;
* stop immediately when `status` becomes `complete`;
* after 30 incomplete polls, classify the result as `UNAVAILABLE`.

## 4. Read the required result fields

Always read:

```text
verdict
recommended_action
receipt_id
receipt_url
evidence_url
key_id
key_endpoint
valid_until
```

Do not make the final delegation decision before independently verifying the receipt.

## 5. Fetch the receipt

Call the absolute URL returned in:

```text
receipt_url
```

Do not alter the receipt before verification.

## 6. Fetch the public-key document

Call the absolute URL returned in:

```text
key_endpoint
```

The standard endpoint is:

```http
GET {TRUSTCHECK_URL}/.well-known/trustcheck-key.json
```

Require:

```text
issuer == TRUSTCHECK_URL
signature_algorithm == Ed25519
canonicalization_version == tc-canon-1
```

Find the public key whose `kid` equals the receipt's `key_id`.

Search:

1. `active_key`;
2. `previous_keys`.

If the key appears only in `revoked_keys`, reject the receipt.

If the key ID is unknown, reject the receipt.

## 7. Verify the receipt independently

The signature covers exactly these fields:

```text
receipt_id
test_id
contract_id
capability_id
target_id
target_endpoint
declared_version
verdict
recommended_action
evidence_root_hash
issued_at
valid_until
key_id
signature_algorithm
canonicalization_version
```

Canonicalization `tc-canon-1`:

1. exclude the `signature` field;
2. include exactly the signed fields listed above;
3. sort object keys lexicographically;
4. serialize as compact JSON using `,` and `:` separators;
5. encode as UTF-8;
6. decode the receipt signature from base64url;
7. decode the selected Ed25519 public key `x` from base64url;
8. verify the signature over the canonical bytes.

Accept the receipt only when all conditions hold:

```text
signature verifies
issuer matches TRUSTCHECK_URL
key_id exists
key is not revoked
signature_algorithm is Ed25519
canonicalization_version is tc-canon-1
receipt is not expired
```

The legacy field:

```text
hmac_signature_DEPRECATED
```

must not be used for independent verification.

The compatibility endpoint:

```http
POST {TRUSTCHECK_URL}/receipts/{receipt_id}/verify
```

may be used for diagnostics, but it is not sufficient as the sole verification mechanism. Independent Ed25519 verification is required before delegation.

Independent verification proves that the signed receipt has not been modified and was signed by the holder of the corresponding private key. It does not prevent a compromised issuer with access to that private key from creating fraudulent receipts.

## 8. Interpret the result

### PASS

Required conditions:

```text
verdict == PASS
independent receipt verification == VALID
recommended_action.action == DELEGATE
```

Final decision:

```text
DELEGATE
```

### FAIL

A valid FAIL receipt proves that the tested behavior failed its contract.

Final decision:

```text
DO_NOT_DELEGATE
```

### INCONCLUSIVE

Examples:

* malformed target response;
* non-JSON response;
* unsupported predicate;
* invalid or unverifiable receipt.

If `retry_allowed` is true, retry the complete test exactly once.

If still inconclusive:

```text
DO_NOT_DELEGATE
```

### UNAVAILABLE

Examples:

* timeout;
* connection failure;
* target server error;
* executor unavailable;
* polling limit reached.

If `retry_allowed` is true, retry the complete test exactly once.

If still unavailable:

```text
DO_NOT_DELEGATE
```

Do not convert `UNAVAILABLE` into `FAIL`.

# Decision table

| Test verdict | Independent receipt | Final decision                          |
| ------------ | ------------------- | --------------------------------------- |
| PASS         | VALID               | DELEGATE                                |
| PASS         | INVALID             | DO_NOT_DELEGATE                         |
| FAIL         | VALID               | DO_NOT_DELEGATE                         |
| FAIL         | INVALID             | DO_NOT_DELEGATE                         |
| INCONCLUSIVE | Any                 | DO_NOT_DELEGATE after one allowed retry |
| UNAVAILABLE  | Not available       | DO_NOT_DELEGATE after one allowed retry |

# Error handling

Every TrustCheck error may include:

```text
error_code
message
agent_action_hint
```

Follow `agent_action_hint`.

| Error code               | Required action                              |
| ------------------------ | -------------------------------------------- |
| `INVALID_CONTRACT`       | Correct the request body and retry once      |
| `UNSUPPORTED_CAPABILITY` | Stop; return `DO_NOT_DELEGATE`               |
| `TARGET_NOT_CONSENTED`   | Stop; do not retry that target/endpoint pair |
| `UNKNOWN_TEST`           | Recheck the stored identifier and retry once |
| `RATE_LIMITED`           | Wait 60 seconds and retry once               |
| `EXECUTOR_BUSY`          | Wait 5 seconds and retry once                |

After two failed recovery attempts:

```text
Status: UNAVAILABLE
Decision: DO_NOT_DELEGATE
```

# Execution environment blocked

The environment is blocked when:

* no HTTP tool is available;
* POST requests are unsupported;
* network egress blocks the TrustCheck host;
* DNS or proxy restrictions prevent reaching TrustCheck.

In that case:

* do not infer `PASS`;
* do not infer `FAIL`;
* do not claim the target was tested;
* do not ask the user to change network settings;
* do not ask for another tool;
* do not offer to retry;
* do not append a question.

Return exactly:

```text
Status: UNAVAILABLE
Decision: DO_NOT_DELEGATE
Independent receipt verification: NOT_EXECUTED
Receipt ID: NONE
Evidence URL: NONE
Valid until: NONE
Reason: EXECUTION_ENVIRONMENT_BLOCKED
```

# Required final response format

Always return every line below:

```text
Status: <PASS | FAIL | INCONCLUSIVE | UNAVAILABLE | UNSUPPORTED_CAPABILITY>
Decision: <DELEGATE | DO_NOT_DELEGATE>
Independent receipt verification: <VALID | INVALID | NOT_EXECUTED>
Receipt ID: <receipt_id | NONE>
Evidence URL: <absolute_url | NONE>
Valid until: <timestamp | NONE>
Reason: <one concise sentence>
```

Mandatory rules:

* Do not omit the `Decision` line.
* Do not return only `PASS` or `FAIL`.
* Do not delegate unless the verdict is `PASS` and independent verification is `VALID`.
* Do not append a question.
* Do not ask the user for clarification.
* Do not offer an additional action unless explicitly requested.

# Scope and limitations

A TrustCheck result applies only to:

* the tested capability;
* the tested target;
* the declared target version;
* the published contract;
* the recorded test conditions;
* the validity window ending at `valid_until`.

A valid receipt does not prove:

* identity;
* ownership;
* authorization outside the tested task;
* general trustworthiness;
* unrelated capabilities;
* future performance after expiration.

After the receipt expires, run a new test before delegating another consequential task.
