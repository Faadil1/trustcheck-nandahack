# TrustCheck — Spike 1 (Cold Agent + SKILL.md)

**Positionnement :** AgentFacts déclare ce qu'un agent prétend savoir faire.
TrustCheck exécute des tests canaris comportementaux sûrs pour vérifier qu'une
capacité déclarée fonctionne réellement, et retourne un reçu de preuve signé
et rejouable. Verdicts : PASS / FAIL / INCONCLUSIVE / UNAVAILABLE. Pas de
score de confiance universel, pas de vérification d'identité.

## Contenu
| Fichier | Rôle |
|---|---|
| `app.py` | Service stub complet (stdlib uniquement) + 2 cibles contrôlées + cibles de test transport |
| `SKILL.md` | Skill v0 (example-first) — le seul document donné à l'agent froid |
| `harness_service.py` | Harnais déterministe : 18 vérifications, exécution HTTP réelle |
| `COLD-AGENT-PROTOCOL.md` | Protocole d'évaluation des agents froids (à exécuter par l'opérateur) |
| `run.sh` | Lancement local |
| `Dockerfile` | Déploiement conteneur |

## Démarrage rapide (local)
```bash
python3 app.py                      # http://0.0.0.0:8787
python3 harness_service.py          # attendu : 18/18 passed
```

## Déploiement public (pour les tests cold-agent)
```bash
# Option ngrok
python3 app.py &
ngrok http 8787
PUBLIC_BASE=https://<votre-url>.ngrok.app python3 app.py   # relancer avec la bonne base

# Option Docker
docker build -t trustcheck-spike1 .
docker run -e PUBLIC_BASE=https://votre-domaine -p 8787:8787 trustcheck-spike1
```
`PUBLIC_BASE` contrôle les URLs absolues (`evidence_url`, `receipt_url`,
`verify_url`) retournées par l'API.

## Variables d'environnement
- `HOST` (défaut `0.0.0.0`)
- `PORT` (défaut `8787`)
- `PUBLIC_BASE` (défaut `http://127.0.0.1:8787`)

## Statut du spike
- Couche service : **18/18 PROUVÉ** (exécution HTTP réelle, mapping des verdicts,
  binding de consentement, chaîne de hachage des preuves, détection de falsification).
- Hypothèse centrale (agent froid réussit avec SKILL.md seul) : **NON EXÉCUTÉE** —
  suivre `COLD-AGENT-PROTOCOL.md`.

## Limites connues (spike)
HMAC côté serveur uniquement (Ed25519 prévu au Spike 3) ; pas de TLS géré par
l'app ; cibles allowlistées uniquement ; une seule famille de capacité
(`invoice.extract-total.v1`).

---

## Spike 3 — Reçus Ed25519 vérifiables publiquement

Les reçus sont désormais signés en **Ed25519** et **vérifiables indépendamment**
par tout agent externe, sans secret serveur.

### Nouveaux éléments
- `receipts.py` — canonicalisation `tc-canon-1`, signature/vérification Ed25519,
  keystore avec rotation (active / previous / revoked), chargement sécurisé des clés.
- `GET /.well-known/trustcheck-key.json` — clé publique active + précédentes + révoquées.
- `POST /receipts/{id}/verify` — vérification Ed25519 (la voie indépendante reste préférée).
- `verify_receipt.py` — vérificateur autonome (reçu + clé publique uniquement).
- HMAC hérité conservé sous `hmac_signature_DEPRECATED` (compatibilité uniquement).

### Vérification indépendante (sans confiance au serveur)
```bash
# récupère la clé publique depuis l'endpoint du reçu et vérifie
python3 verify_receipt.py receipt.json
# ou avec une clé explicite
python3 verify_receipt.py receipt.json --pubkey <base64url_pub>
```

### Clés en production (Cloud Run)
Ne jamais coder en dur une clé privée. Fournir les clés par variable
d'environnement ou secret monté :
```bash
# Générer une paire (exemple)
python3 - << 'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
sk=Ed25519PrivateKey.generate()
b=lambda x: base64.urlsafe_b64encode(x).decode().rstrip('=')
priv=b(sk.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
pub=b(sk.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
print("TRUSTCHECK_ACTIVE_KEY_ID=tc-prod-2026-06-a")
print("TRUSTCHECK_ACTIVE_PRIVATE_B64U="+priv)
print("TRUSTCHECK_ACTIVE_PUBLIC_B64U="+pub)
PY
```
Déploiement Cloud Run :
```bash
gcloud run deploy trustcheck \
  --source . \
  --set-env-vars PUBLIC_BASE=https://<service-url>,TRUSTCHECK_ACTIVE_KEY_ID=tc-prod-2026-06-a \
  --set-secrets TRUSTCHECK_ACTIVE_PRIVATE_B64U=trustcheck-active-priv:latest \
  --allow-unauthenticated
```
`PUBLIC_BASE` doit correspondre à l'URL Cloud Run pour que `issuer` et les URLs
absolues (evidence/receipt/verify/key_endpoint) soient cohérents.

### Dépendance
`cryptography` (voir `requirements.txt`). Le reste est stdlib.

### Statut Spike 3
- `harness_service.py` : **33/33 PASS** (exécuté)
- `audit_spike3.py` : **6/6 propriétés d'audit PASS** (exécuté)
- Statut : **PROVEN**
