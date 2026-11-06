#!/usr/bin/env bash
# ===== WAPT orchestrator - one-click start (macOS / Linux) =====
# macOS: double-click this file (you may need: right-click > Open the first time).
# Linux: run  ./start-mac-linux.command  (or double-click if your file manager allows).
# It installs what's needed, starts the engine, and opens the dashboard.

cd "$(dirname "$0")" || exit 1
echo
echo "  Starting WAPT orchestrator..."
echo

# find python3
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else
  echo "  Python is not installed."
  echo "  macOS: install from https://www.python.org/downloads/ then run this again."
  echo "  Linux: sudo apt install python3 python3-pip"
  echo
  read -r -p "  Press Enter to close." _
  exit 1
fi

echo "  Installing a small helper library (first time only)..."
$PY -m pip install --quiet requests >/dev/null 2>&1 || \
  $PY -m pip install --quiet --break-system-packages requests >/dev/null 2>&1

echo "  Launching the dashboard..."
$PY run.py --serve --open --mode lab

echo
echo "  Stopped. You can close this window."
read -r -p "  Press Enter to close." _
