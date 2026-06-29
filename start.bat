@echo off
title SecDrop - Encrypted Pastebin
cd /d "%~dp0"
if not exist ".venv" (
    echo   Creating virtual environment...
    python -m venv .venv
    .venv\Scripts\pip install -q -r requirements.txt
)
echo.
echo   =========================================
echo     SEC/DROP -- Self-hosted Pastebin
echo   =========================================
echo.
echo   Starting server...
echo   Open: http://127.0.0.1:5000
echo.
.venv\Scripts\python app.py
pause
