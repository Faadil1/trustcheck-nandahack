#!/usr/bin/env bash
set -euo pipefail
export GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project)}"
export GOOGLE_CLOUD_LOCATION="${GOOGLE_CLOUD_LOCATION:-us-central1}"
python agent_runner.py --scenario alpha
python agent_runner.py --scenario beta
