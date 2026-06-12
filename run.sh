#!/usr/bin/env bash
set -euo pipefail
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-8787}"
export PUBLIC_BASE="${PUBLIC_BASE:-http://127.0.0.1:$PORT}"
exec python3 "$(dirname "$0")/app.py"
