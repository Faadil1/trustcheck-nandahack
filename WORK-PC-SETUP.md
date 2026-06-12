# TrustCheck Spike 1 — Guide poste Windows d’entreprise

## Règles importantes

- Respecter les politiques informatiques de l’employeur.
- Ne pas contourner les restrictions administrateur, proxy, pare-feu ou antivirus.
- Ne pas utiliser de données internes ou confidentielles.
- Utiliser uniquement les cibles de démonstration incluses dans le projet.
- Pour un tunnel public, demander l’autorisation si la politique de l’entreprise l’exige.

## Étape 1 — Vérifier les outils

Dans VS Code, ouvrir Terminal > New Terminal, puis exécuter :

```powershell
python --version
py --version
git --version
code --version
```

Un seul de `python` ou `py` doit fonctionner.

## Étape 2 — Ouvrir le dossier

Extraire l’archive dans un dossier où vous avez les droits, par exemple :

```text
C:\Users\<votre-utilisateur>\Documents\trustcheck-spike1
```

Dans VS Code :

File > Open Folder > sélectionner `trustcheck-spike1`

## Étape 3 — Lancer le service

Dans le terminal VS Code :

```powershell
python app.py
```

Si `python` ne fonctionne pas :

```powershell
py app.py
```

Résultat attendu :

```text
TrustCheck spike stub on http://0.0.0.0:8787
```

Laisser ce terminal ouvert.

## Étape 4 — Tester le harnais

Ouvrir un deuxième terminal VS Code :

Terminal > New Terminal

Puis :

```powershell
python harness_service.py
```

ou :

```powershell
py harness_service.py
```

Résultat attendu :

```text
18/18 passed
```

## Étape 5 — Vérifier manuellement

Dans un troisième terminal :

```powershell
curl.exe http://127.0.0.1:8787/health
curl.exe http://127.0.0.1:8787/contracts.json
```

Si `curl.exe` est bloqué, utiliser PowerShell :

```powershell
Invoke-RestMethod http://127.0.0.1:8787/health
Invoke-RestMethod http://127.0.0.1:8787/contracts.json
```

## Étape 6 — Utiliser Claude Code dans VS Code

Depuis le dossier du projet, ouvrir Claude Code et demander :

```text
Inspect this TrustCheck Spike 1 project.
Do not modify files yet.
Run the local harness if allowed.
Report:
1. whether Python is available,
2. whether app.py starts,
3. whether harness_service.py reaches 18/18,
4. any corporate-environment limitations,
5. the safest next step without bypassing restrictions.
```

## Si un blocage apparaît

Ne pas tenter de contourner le blocage.

Copier le message d’erreur exact et demander une solution compatible avec les droits disponibles.
