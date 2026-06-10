@echo off
cd /d "%~dp0"

set "PY=.venv\Scripts\python.exe"

if not exist "%PY%" (
    python -m venv .venv
    goto install
)

"%PY%" -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [run.bat] Virtualenv rusak, membuat ulang...
    rmdir /s /q .venv
    python -m venv .venv
)

:install
"%PY%" -m pip install --upgrade pip -q
"%PY%" -m pip install -r requirements.txt -q

"%PY%" netcut.py %*
