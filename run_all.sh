#!/bin/bash
# Rebuild provenance and recompute every v1.1 score, statistic, verdict, table, and figure
# from the saved assessor outputs in runs/<CANONICAL>/. No model calls.
# Version: 1.1.0
# Owner: Rock Lambros
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"

# Environment must match the lock file.
"$PY" -m pip freeze --exclude-editable | diff -q - requirements.lock >/dev/null || { echo "environment differs from requirements.lock"; exit 1; }

# Derived outputs are rebuilt from scratch so nothing stale survives.
rm -rf "$ROOT/results_v11"

"$PY" -I scripts/provenance_v11.py
"$PY" -I scripts/build_rubric_v11.py
"$PY" -I scripts/build_packets_v11.py
"$PY" -I scripts/build_bridge_prompts.py
"$PY" -I scripts/analyze_v11.py
"$PY" -I scripts/build_notebook_v11.py
"$PY" -m nbconvert --to notebook --execute --inplace --ExecutePreprocessor.timeout=1800 AIVSS-field-experiment-RockLambros-v1.1.ipynb
"$PY" -I scripts/self_check_v11.py
echo "Recompute complete. See results_v11/ and the executed notebook."
