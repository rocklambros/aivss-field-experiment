#!/bin/bash
# Secure AIVSS Experiment Execution Script
# Version: 1.2.0
# Owner: Rock Lambros
# Always runs from the experiment directory, regardless of the caller's cwd.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "Starting AIVSS experiment from $ROOT"
echo "=================================================="

# Check if pass is available
if ! command -v pass &> /dev/null; then
    echo "❌ Error: pass utility not found. Please install pass."
    exit 1
fi

# Check if API key is available in pass
echo "🔑 Verifying API key access..."
if ! pass show openrouter/api-key >/dev/null 2>&1; then
    echo "❌ Error: API key not found in pass. Run: pass insert openrouter/api-key"
    exit 1
fi

# Check environment
echo "🔧 Checking environment..."
if [ ! -d "packets" ]; then
    echo "❌ Error: packets directory not found"
    exit 1
fi

if [ ! -f "findings.json" ]; then
    echo "❌ Error: findings.json not found"
    exit 1
fi

# Activate virtual environment
echo "⚡ Activating virtual environment..."
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    echo "⚠️ Warning: Virtual environment not found, proceeding anyway"
fi

# Verify calculator
echo "📊 Verifying AIVSS calculator..."
if command -v aivss-calc &> /dev/null; then
    echo "✅ AIVSS calculator available"
    aivss-calc verify
else
    echo "⚠️ Warning: AIVSS calculator not found, but continuing"
fi


# Phase 2: blind triple scoring (real model calls, US-pinned, metered against the cap).
echo "Phase 2: blind triple scoring"
"$ROOT/.venv/bin/python" scripts/execute_raters_secure.py

# Calculator scoring, agreement, Phase 4 analysis. No model calls.
echo "Calculator scoring, agreement, and Phase 4 analysis"
"$ROOT/run_all.sh"

echo "Done. Outputs: raters/, scores/, phase4/, results.json, logs/"
