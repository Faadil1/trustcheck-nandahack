#!/usr/bin/env python3
"""Spike 3 audit: verify each required audit property explicitly."""
import os, sys, json, threading, time, copy, urllib.request, urllib.error
HERE=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,HERE)
os.environ.setdefault("HOST","127.0.0.1"); os.environ.setdefault("PORT","8790")
os.environ.setdefault("PUBLIC_BASE","http://127.0.0.1:8790")
import urllib.error
import app, receipts as rcpt
BASE=os.environ["PUBLIC_BASE"]
threading.Thread(target=app.serve,daemon=True).start()
for _ in range(50):
    try:
        urllib.request.urlopen(BASE+"/health",timeout=0.5); break
    except Exception: time.sleep(0.1)
def call(m,p,b=None):
    r=urllib.request.Request(BASE+p,method=m,data=json.dumps(b).encode() if b is not None else None,headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=20) as x: return x.status,json.loads(x.read())
    except urllib.error.HTTPError as e: return e.code,json.loads(e.read())

audit=[]
def A(name,cond,d=""): audit.append((name,bool(cond),d))

s,b=call("POST","/tests",{"contract_id":"invoice.extract-total.v1","target":{"target_id":"target-alpha","endpoint":BASE+"/targets/alpha/invoice-total","declared_version":"1.0.0","consent_token":"demo-consent"}})
s,receipt=call("GET","/receipts/"+b["receipt_id"])

# 1 signing covers every security-relevant field: mutate EACH signed field -> invalid
s,wk=call("GET","/.well-known/trustcheck-key.json"); pub=wk["active_key"]["x"]
all_break=True
for f in rcpt.SIGNED_FIELDS:
    r=copy.deepcopy(receipt)
    r[f]="__TAMPERED__" if isinstance(r[f],str) else 123456789
    if rcpt.verify_receipt(r,public_b64u=pub)["valid"]: all_break=False; break
A("signing covers every signed field (mutating any -> invalid)", all_break)

# 2 canonicalization deterministic: reorder keys, re-serialize -> same bytes
import collections
shuffled=collections.OrderedDict(sorted(receipt.items(),reverse=True))
payload={k:receipt[k] for k in rcpt.SIGNED_FIELDS}
payload_shuf=collections.OrderedDict(sorted(payload.items(),reverse=True))
A("canonicalization deterministic regardless of key order",
  rcpt.canonical_bytes(payload)==rcpt.canonical_bytes(payload_shuf))

# 3 key endpoint cannot be confused across envs: issuer bound to PUBLIC_BASE
A("key endpoint carries issuer == PUBLIC_BASE", wk["issuer"]==BASE)

# 4 old receipts verify during rotation (covered in harness) — re-assert minimal
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
old=app.KEYSTORE.active
sk=Ed25519PrivateKey.generate()
npriv=rcpt.b64u_encode(sk.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
npub=rcpt.b64u_encode(sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
app.KEYSTORE=rcpt.KeyStore(rcpt.KeyEntry("tc-new",npub,npriv,"active"),
    previous=[rcpt.KeyEntry(old.key_id,old.public_b64u,None,"previous")])
s,v=call("POST","/receipts/"+receipt["receipt_id"]+"/verify")
A("old receipt verifies during rotation", v["valid"] is True)

# 5 tampering -> failure (covered); 6 server cannot silently change receipt:
#   change a signed field on the stored receipt -> verify fails
app.RECEIPTS[receipt["receipt_id"]]["verdict"]="PASS" if receipt["verdict"]!="PASS" else "FAIL"
s,v=call("POST","/receipts/"+receipt["receipt_id"]+"/verify")
A("server cannot silently alter issued receipt (signature breaks)", v["valid"] is False)

# 8 private key never exposed
A("private key material absent from well-known", "private" not in json.dumps(wk).lower() and npriv not in json.dumps(wk))

print(f"{'AUDIT PROPERTY':58s} RESULT")
fails=0
for n,ok,d in audit:
    print(f"{n:58s} {'PASS' if ok else 'FAIL '+d}"); fails+=0 if ok else 1
print(f"\n{len(audit)-fails}/{len(audit)} audit properties verified")
sys.exit(1 if fails else 0)
