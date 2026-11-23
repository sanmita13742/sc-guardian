#!/usr/bin/env sh
# Starts SC Guardian using the self-contained environment in .venv (creates it on first run).
set -e
cd "$(dirname "$0")"
if [ ! -x ".venv/bin/python" ] && [ ! -x ".venv/Scripts/python.exe" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv 2>/dev/null || python -m venv .venv
  PY=".venv/bin/python"; [ -x "$PY" ] || PY=".venv/Scripts/python.exe"
  "$PY" -m pip install --upgrade pip
  "$PY" -m pip install -r requirements.txt
fi
PY=".venv/bin/python"; [ -x "$PY" ] || PY=".venv/Scripts/python.exe"
"$PY" scripts/verify_environment.py --offline || true
exec "$PY" -m streamlit run app.py
