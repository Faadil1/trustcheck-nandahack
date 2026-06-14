#!/usr/bin/env python3
"""TrustCheck receipts — Spike 3.

Publicly verifiable Ed25519 receipts. Canonicalization v1 is deterministic
(RFC 8785-style: sorted keys, no insignificant whitespace, UTF-8). Signing
covers every security-relevant field via the canonical bytes of the receipt
payload (all fields except the detached `signature`).

Key material:
  - Loaded from env/secret files (see load_keystore). Never hardcoded for prod.
  - Keystore holds one ACTIVE key (signs new receipts) and zero+ PREVIOUS keys
    (verify-only, for receipts issued before rotation). Optional REVOKED set.

Dependency: `cryptography` (well-maintained, standard Ed25519).
"""
import os, json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

CANON_VERSION = "tc-canon-1"
SIG_ALG = "Ed25519"

# ---- base64url helpers (no padding) ----
def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

# ---- canonicalization v1 ----
# Deterministic JSON: sorted keys, compact separators, ensure_ascii=False (UTF-8),
# stable float handling. The signed payload is the receipt WITHOUT `signature`.
def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---- keystore ----
class KeyEntry:
    def __init__(self, key_id, public_b64u, private_b64u=None, status="active"):
        self.key_id = key_id
        self.public_b64u = public_b64u
        self.status = status  # active | previous | revoked
        self._pub = Ed25519PublicKey.from_public_bytes(b64u_decode(public_b64u))
        self._priv = (Ed25519PrivateKey.from_private_bytes(b64u_decode(private_b64u))
                      if private_b64u else None)

    def sign(self, msg: bytes) -> bytes:
        if not self._priv:
            raise RuntimeError(f"key {self.key_id} has no private material (verify-only)")
        return self._priv.sign(msg)

    def verify(self, msg: bytes, sig: bytes) -> bool:
        try:
            self._pub.verify(sig, msg)
            return True
        except InvalidSignature:
            return False

    def public_jwk(self):
        return {"kty": "OKP", "crv": "Ed25519", "x": self.public_b64u,
                "kid": self.key_id, "status": self.status}


class KeyStore:
    def __init__(self, active: KeyEntry, previous=None, revoked=None):
        self.active = active
        self.previous = {k.key_id: k for k in (previous or [])}
        self.revoked = {k.key_id: k for k in (revoked or [])}
        self._all = {active.key_id: active, **self.previous, **self.revoked}

    def get(self, key_id):
        return self._all.get(key_id)

    def verifiable(self, key_id):
        """Return entry usable for verification, or None. Revoked keys are
        returned too (caller decides), but flagged via .status == 'revoked'."""
        return self._all.get(key_id)

    def well_known(self, public_base):
        return {
            "issuer": public_base,
            "canonicalization_version": CANON_VERSION,
            "signature_algorithm": SIG_ALG,
            "active_key": self.active.public_jwk(),
            "previous_keys": [k.public_jwk() for k in self.previous.values()],
            "revoked_keys": [{"kid": k.key_id, "status": "revoked"}
                             for k in self.revoked.values()],
        }


def _entry_from_obj(o, status):
    return KeyEntry(o["key_id"], o["public_b64u"], o.get("private_b64u"), status)

def load_keystore():
    """Load keys with this precedence:
       1. TRUSTCHECK_KEYS_FILE -> JSON file {active, previous[], revoked[]}
       2. TRUSTCHECK_ACTIVE_PRIVATE_B64U + TRUSTCHECK_ACTIVE_KEY_ID
          (+ optional TRUSTCHECK_ACTIVE_PUBLIC_B64U; derived if absent)
          + optional TRUSTCHECK_PREVIOUS_KEYS / TRUSTCHECK_REVOKED_KEYS (JSON)
       3. dev fallback: keys/dev-keys.json (local only; NOT for production)
    Production private keys must come from env/secret files, never hardcoded.
    """
    f = os.getenv("TRUSTCHECK_KEYS_FILE")
    if f and os.path.exists(f):
        obj = json.load(open(f))
        active = _entry_from_obj(obj["active"], "active")
        previous = [_entry_from_obj(o, "previous") for o in obj.get("previous", [])]
        revoked = [_entry_from_obj(o, "revoked") for o in obj.get("revoked", [])]
        return KeyStore(active, previous, revoked)

    priv = os.getenv("TRUSTCHECK_ACTIVE_PRIVATE_B64U")
    kid = os.getenv("TRUSTCHECK_ACTIVE_KEY_ID")
    if priv and kid:
        pub = os.getenv("TRUSTCHECK_ACTIVE_PUBLIC_B64U")
        if not pub:
            sk = Ed25519PrivateKey.from_private_bytes(b64u_decode(priv))
            from cryptography.hazmat.primitives import serialization
            pub = b64u_encode(sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        active = KeyEntry(kid, pub, priv, "active")
        previous = [_entry_from_obj(o, "previous")
                    for o in json.loads(os.getenv("TRUSTCHECK_PREVIOUS_KEYS", "[]"))]
        revoked = [_entry_from_obj(o, "revoked")
                   for o in json.loads(os.getenv("TRUSTCHECK_REVOKED_KEYS", "[]"))]
        return KeyStore(active, previous, revoked)

    dev = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys", "dev-keys.json")
    if os.path.exists(dev):
        obj = json.load(open(dev))
        active = _entry_from_obj(obj["active"], "active")
        previous = [_entry_from_obj(o, "previous") for o in obj.get("previous", [])]
        return KeyStore(active, previous)
    raise RuntimeError("No key material found. Set TRUSTCHECK_KEYS_FILE or "
                       "TRUSTCHECK_ACTIVE_PRIVATE_B64U + TRUSTCHECK_ACTIVE_KEY_ID.")


# ---- receipt build + sign ----
SIGNED_FIELDS = [
    "receipt_id", "test_id", "contract_id", "capability_id",
    "target_id", "target_endpoint", "declared_version",
    "verdict", "recommended_action",
    "evidence_root_hash", "issued_at", "valid_until",
    "key_id", "signature_algorithm", "canonicalization_version",
]

def build_signed_receipt(keystore: KeyStore, fields: dict) -> dict:
    """fields must include every SIGNED_FIELDS entry except the key/alg/canon
    triplet, which is injected here from the active key."""
    payload = {k: fields[k] for k in SIGNED_FIELDS
               if k not in ("key_id", "signature_algorithm", "canonicalization_version")}
    payload["key_id"] = keystore.active.key_id
    payload["signature_algorithm"] = SIG_ALG
    payload["canonicalization_version"] = CANON_VERSION
    msg = canonical_bytes(payload)
    sig = keystore.active.sign(msg)
    receipt = dict(payload)
    receipt["signature"] = b64u_encode(sig)
    return receipt


def verify_receipt(receipt: dict, keystore: KeyStore = None,
                   public_b64u: str = None, allow_revoked: bool = False) -> dict:
    """Independent verification. Either:
       - pass a keystore (resolves key_id), or
       - pass an explicit public_b64u (verify against exactly that key).
    Returns {valid: bool, reasons: [...], key_status: ...}.
    No server secret required. Recomputes canonical bytes from the receipt's
    own signed fields, so any altered signed field breaks verification.
    """
    reasons = []
    if receipt.get("canonicalization_version") != CANON_VERSION:
        reasons.append(f"unsupported canonicalization_version "
                       f"{receipt.get('canonicalization_version')!r}")
    if receipt.get("signature_algorithm") != SIG_ALG:
        reasons.append(f"unexpected signature_algorithm "
                       f"{receipt.get('signature_algorithm')!r}")
    missing = [f for f in SIGNED_FIELDS if f not in receipt] + \
              (["signature"] if "signature" not in receipt else [])
    if missing:
        reasons.append("missing fields: " + ",".join(missing))
        return {"valid": False, "reasons": reasons, "key_status": None}

    key_status = None
    pub = None
    if public_b64u is not None:
        pub = public_b64u
    elif keystore is not None:
        entry = keystore.verifiable(receipt["key_id"])
        if entry is None:
            reasons.append(f"unknown key_id {receipt['key_id']!r}")
            return {"valid": False, "reasons": reasons, "key_status": "unknown"}
        key_status = entry.status
        if entry.status == "revoked" and not allow_revoked:
            reasons.append(f"key_id {receipt['key_id']} is revoked")
        pub = entry.public_b64u
    else:
        reasons.append("no keystore or public key supplied")
        return {"valid": False, "reasons": reasons, "key_status": None}

    payload = {k: receipt[k] for k in SIGNED_FIELDS}
    msg = canonical_bytes(payload)
    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(pub)).verify(
            b64u_decode(receipt["signature"]), msg)
        sig_ok = True
    except (InvalidSignature, Exception):
        sig_ok = False
    if not sig_ok:
        reasons.append("signature verification failed (payload altered or wrong key)")

    valid = sig_ok and not reasons
    return {"valid": bool(valid), "reasons": reasons, "key_status": key_status}
