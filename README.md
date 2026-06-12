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
| `harness_service.py` | Harnais déterministe : 22 vérifications, exécution HTTP réelle |
| `COLD-AGENT-PROTOCOL.md` | Protocole d'évaluation des agents froids (à exécuter par l'opérateur) |
| `run.sh` | Lancement local |
| `Dockerfile` | Déploiement conteneur |

## Démarrage rapide (local)
```bash
python3 app.py                      # http://0.0.0.0:8787
python3 harness_service.py          # attendu : 22/22 passed
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
- Couche service : **22/22 PROUVÉ** (exécution HTTP réelle, mapping des verdicts,
  binding de consentement, chaîne de hachage des preuves, détection de falsification,
  opacité du mapping comportemental des cibles).
- Hypothèse centrale (agent froid réussit avec SKILL.md seul) : **NON EXÉCUTÉE** —
  suivre `COLD-AGENT-PROTOCOL.md`.

## Limites connues (spike)
HMAC côté serveur uniquement (Ed25519 prévu au Spike 3) ; pas de TLS géré par
l'app ; cibles allowlistées uniquement ; une seule famille de capacité
(`invoice.extract-total.v1`).
