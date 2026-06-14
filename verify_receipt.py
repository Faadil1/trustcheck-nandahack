#!/usr/bin/env python3
"""Independent TrustCheck receipt verifier.

Usage:
    python3 verify_receipt.py receipt.json [--well-known URL] [--pubkey B64U]

Verifies an Ed25519 receipt using ONLY the receipt and a public key. Fetches
the key from the issuer's /.well-known/trustcheck-key.json unless --pubkey is
given. Requires no TrustCheck server secret and does not trust the issuer at
verification time beyond its published public key. Exit code 0 = valid.
"""
import sys, json, argparse, urllib.request
import receipts as rcpt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt")
    ap.add_argument("--well-known", help="URL of trustcheck-key.json")
    ap.add_argument("--pubkey", help="explicit base64url Ed25519 public key")
    a = ap.parse_args()
    receipt = json.load(open(a.receipt))

    if a.pubkey:
        res = rcpt.verify_receipt(receipt, public_b64u=a.pubkey)
    else:
        url = a.well_known or receipt.get("verification", {}).get("key_endpoint")
        if not url:
            print("ERROR: no --pubkey and no key endpoint in receipt"); sys.exit(2)
        with urllib.request.urlopen(url, timeout=10) as r:
            wk = json.load(r)
        active = rcpt.KeyEntry(wk["active_key"]["kid"], wk["active_key"]["x"], None, "active")
        prev = [rcpt.KeyEntry(k["kid"], k["x"], None, "previous")
                for k in wk.get("previous_keys", [])]
        revoked = [rcpt.KeyEntry(k["kid"], k.get("x", "A"*43), None, "revoked")
                   for k in wk.get("revoked_keys", []) if "x" in k]
        ks = rcpt.KeyStore(active, prev, revoked)
        res = rcpt.verify_receipt(receipt, keystore=ks)

    print(json.dumps({"receipt_id": receipt.get("receipt_id"),
                      "verdict": receipt.get("verdict"),
                      "key_id": receipt.get("key_id"), **res}, indent=2))
    sys.exit(0 if res["valid"] else 1)

if __name__ == "__main__":
    main()
