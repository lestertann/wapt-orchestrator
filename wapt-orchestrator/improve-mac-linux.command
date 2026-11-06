#!/usr/bin/env bash
# ===== WAPT orchestrator - benchmark + self-improve (macOS / Linux) =====
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi

echo
echo "  [1/2] Running the benchmark (scores the tool, writes gap_report.md)..."
$PY bench.py

echo
if [ -z "$ANTHROPIC_API_KEY" ]; then
  echo "  [2/2] Self-improve SKIPPED: no ANTHROPIC_API_KEY set."
  echo "        To let it improve itself:  export ANTHROPIC_API_KEY=sk-ant-..."
  echo "        then run this again. The benchmark + gap_report.md above still work."
else
  echo "  [2/2] Self-improving (bounded; only keeps changes that pass all tests)..."
  $PY -m pip install --quiet requests >/dev/null 2>&1 || \
    $PY -m pip install --quiet --break-system-packages requests >/dev/null 2>&1
  $PY autoimprove.py --iterations 5
fi
echo
read -r -p "  Press Enter to close." _
