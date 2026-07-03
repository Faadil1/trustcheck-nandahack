# TrustCheck Evidence Summary

## Current status

TrustCheck is a live behavioral verification prototype for agent delegation.

Current phase:

BUILD FINAL — Build 3 in progress

Live service:

https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app

Current branch:

build-final

Latest proof bundle commit:

98abbd6 — Add live TrustCheck proof bundle

## Core claim

TrustCheck verifies whether a target can actually perform one declared capability before another agent delegates consequential work.

The current demonstration capability is:

invoice.extract-total

The invoice capability is the demonstration case, not the whole product. The reusable pattern is:

claim -> contract -> real HTTP canary test -> evidence -> signed receipt -> independent verification -> delegation decision

## Live service evidence

The following live endpoints were confirmed after redeployment:

- GET /health
- GET /contracts.json
- GET /.well-known/trustcheck-key.json
- POST /tests
- GET /tests/{test_id}/evidence
- GET /receipts/{receipt_id}

Live service health confirmed:

- status: ok
- active key ID: tc-prod-2026-06-01
- canonicalization version: tc-canon-1

Public key endpoint confirmed:

- issuer: https://trustcheck-nandahack-293749289787.northamerica-northeast1.run.app
- signature algorithm: Ed25519
- active key status: active
- active key ID: tc-prod-2026-06-01

## Deterministic local evidence

Previously validated local test results:

- harness_service.py: 33/33 PASS
- audit_spike3.py: 6/6 PASS

These tests validated service behavior, receipt generation, independent verification, tamper rejection, key handling, and security properties.

## Live Alpha proof

Target:

target-alpha

Capability:

invoice.extract-total

Live test result:

- test ID: t_77910a21
- receipt ID: r_77910a21
- verdict: PASS
- recommended action: DELEGATE
- key ID: tc-prod-2026-06-01

Independent verification result:

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

## Live Beta proof

Target:

target-beta

Capability:

invoice.extract-total

Live test result:

- test ID: t_eb907eeb
- receipt ID: r_eb907eeb
- verdict: FAIL
- recommended action: DO_NOT_DELEGATE
- key ID: tc-prod-2026-06-01

Independent verification result:

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

## Multi-model live evaluation

Approved wording:

Six successful live Ed25519 evaluations were completed across three Gemini model configurations in seven total attempts. One Flash-Lite attempt completed the technical verification correctly but omitted the explicit delegation action in its final response.

Do not describe this as 6/6 total attempts.

Models evaluated:

- gemini-2.5-flash
- gemini-2.5-flash-lite
- gemini-2.5-pro

Successful scenarios included both:

- target-alpha -> PASS -> DELEGATE
- target-beta -> FAIL -> DO_NOT_DELEGATE

## Proof bundle

The committed proof bundle is available under:

proof/

Inventory:

- proof/key.json
- proof/alpha-pass/receipt.json
- proof/alpha-pass/evidence.json
- proof/alpha-pass/verify.log
- proof/alpha-pass/receipt-tampered.json
- proof/alpha-pass/tamper-rejection.log
- proof/beta-fail/receipt.json
- proof/beta-fail/evidence.json
- proof/beta-fail/verify.log
- proof/beta-fail/receipt-tampered.json
- proof/beta-fail/tamper-rejection.log
- proof/README.md

## What this proves

This evidence shows that TrustCheck can:

1. publish a behavioral contract;
2. test a consented target through real HTTP calls;
3. distinguish a passing target from a failing target;
4. produce an Ed25519-signed receipt;
5. allow third-party independent receipt verification;
6. reject locally altered receipts;
7. return a safe delegation recommendation.

## Security boundary

Independent verification proves that the saved receipt was signed by the active TrustCheck key and that its signed fields were not modified.

It does not prove that a compromised issuer holding the private key could not forge receipts.

TrustCheck is a validated hackathon prototype, not a production-ready certificate authority, transparency log, or universal trust system.

## Known limitations

- Current storage is in-memory.
- Only one demonstration capability family is implemented.
- The evaluation used controlled phased orchestration.
- Production key rotation is designed and locally tested, but not exercised live.
- Public-key authenticity depends on TLS and trust in the well-known endpoint.
- A compromised issuer with private-key access could forge receipts.
- TrustCheck verifies one declared capability under one contract; it does not establish general trustworthiness.

## Final approved summary

TrustCheck passed 33 deterministic service checks and six security audit properties. Its live Cloud Run deployment produced independently verifiable Ed25519 receipts for both PASS and FAIL behavioral outcomes. Six successful live evaluations were completed across three Gemini model configurations in seven total attempts. Authentic receipts verified successfully, while locally altered receipts were rejected.
