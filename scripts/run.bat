@echo off
REM Starts SC Guardian using the self-contained environment in .venv (creates it on first run).
cd /d "%~dp0.."
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    py -3.11 -m venv .venv || python -m venv .venv
    ".venv\Scripts\python.exe" -m pip install --upgrade pip
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)
".venv\Scripts\python.exe" scripts\verify_environment.py --offline
".venv\Scripts\python.exe" -m streamlit run app.py
