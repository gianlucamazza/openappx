#!/usr/bin/env bash
# Thin wrapper: pack a layout with the pure-Python backend.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m openappx.pack "$@"
