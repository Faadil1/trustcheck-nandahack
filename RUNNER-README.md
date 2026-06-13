# TrustCheck Controlled Cold-Agent Runner

The runner gives a fresh Gemini session only `SKILL.md`, one visible scenario,
and two constrained HTTP tools. Hidden expected verdicts are used only after
execution for scoring.

## Cloud Shell setup

```bash
gcloud services enable aiplatform.googleapis.com
python3 -m venv .runner-venv
source .runner-venv/bin/activate
pip install --upgrade pip
pip install -r runner-requirements.txt
export GOOGLE_CLOUD_PROJECT="$(gcloud config get-value project)"
export GOOGLE_CLOUD_LOCATION="us-central1"
```

Cloud Shell normally provides Application Default Credentials. The project/user
must have permission to call Vertex AI.

## Run one fresh scenario

```bash
python agent_runner.py --scenario alpha
python agent_runner.py --scenario beta
```

## Outputs

Each run appends to `COLD-AGENT-RESULTS.yaml` and creates a complete
`run-<scenario>-<timestamp>.json` trace.

A run passes only if the model lists contracts, selects the right contract,
submits the correct target, reads the real verdict, verifies the receipt,
returns the correct decision, and asks no question.

## Security boundary

The HTTP tool rejects non-HTTPS calls, other hosts, and paths outside
`/health`, `/contracts.json`, `/tests`, and `/receipts/`.
