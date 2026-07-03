# TrustCheck Proof Bundle

This folder contains public, independently verifiable evidence from the live TrustCheck Cloud Run service.

Live service:

https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app

## What this proves

TrustCheck generated signed Ed25519 receipts for both behavioral outcomes:

- Alpha: PASS -> DELEGATE
- Beta: FAIL -> DO_NOT_DELEGATE

Each authentic receipt was independently verified using `verify_receipt.py`.

Locally altered copies were rejected after changing the signed `verdict` field.

## Files

- `key.json`: public Ed25519 key snapshot from `/.well-known/trustcheck-key.json`
- `alpha-pass/receipt.json`: authentic PASS receipt
- `alpha-pass/evidence.json`: Alpha evidence
- `alpha-pass/verify.log`: independent verification result for Alpha
- `alpha-pass/receipt-tampered.json`: altered Alpha receipt
- `alpha-pass/tamper-rejection.log`: rejected Alpha tamper proof
- `beta-fail/receipt.json`: authentic FAIL receipt
- `beta-fail/evidence.json`: Beta evidence
- `beta-fail/verify.log`: independent verification result for Beta
- `beta-fail/receipt-tampered.json`: altered Beta receipt
- `beta-fail/tamper-rejection.log`: rejected Beta tamper proof

## Alpha result

Receipt ID: `r_77910a21`

Expected outcome:

PASS -> DELEGATE

Independent verification:

{
  "receipt_id": "r_77910a21",
  "verdict": "PASS",
  "key_id": "tc-prod-2026-06-01",
  "valid": true,
  "reasons": [],
  "key_status": "active"
}

Tampered-copy result after changing the signed verdict from PASS to FAIL:

{
  "receipt_id": "r_77910a21",
  "verdict": "FAIL",
  "key_id": "tc-prod-2026-06-01",
  "valid": false,
  "reasons": [
    "signature verification failed (payload altered or wrong key)"
  ],
  "key_status": "active"
}

## Beta result

Receipt ID: `r_eb907eeb`

Expected outcome:

FAIL -> DO_NOT_DELEGATE

Independent verification:

{
  "receipt_id": "r_eb907eeb",
  "verdict": "FAIL",
  "key_id": "tc-prod-2026-06-01",
  "valid": true,
  "reasons": [],
  "key_status": "active"
}

Tampered-copy result after changing the signed verdict from FAIL to PASS:

{
  "receipt_id": "r_eb907eeb",
  "verdict": "PASS",
  "key_id": "tc-prod-2026-06-01",
  "valid": false,
  "reasons": [
    "signature verification failed (payload altered or wrong key)"
  ],
  "key_status": "active"
}

## How to verify locally

From the repository root:

BASE="https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app"

python verify_receipt.py proof/alpha-pass/receipt.json --well-known "$BASE/.well-known/trustcheck-key.json"

python verify_receipt.py proof/beta-fail/receipt.json --well-known "$BASE/.well-known/trustcheck-key.json"

Authentic receipts should return `"valid": true`.

Tampered receipts should return `"valid": false` with signature verification failure.

## Security boundary

This proof shows that the saved receipts were signed by the active TrustCheck key and that their signed fields were not modified.

It does not prove that a compromised issuer holding the private key could not forge receipts.

TrustCheck is a validated hackathon prototype, not a production-ready certificate authority or transparency-log-backed trust system.
