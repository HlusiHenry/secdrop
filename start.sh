#!/bin/bash
cd "$(dirname "$0")"
if [ ! -d ".venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
fi
echo ""
echo "  ========================================="
echo "    SEC/DROP -- Self-hosted Pastebin"
echo "  ========================================="
echo ""
echo "  Starting server..."
echo "  Open: http://127.0.0.1:5000"
echo ""
# Optional: set master password
# export SECDROP_MASTER_PW="yourpassword"
# Telegram Bot
export TELEGRAM_BOT_TOKEN="8938421556:AAGFatMTojEMAGv0f9YxsKgoMASb0vVRHlA"
export TELEGRAM_ADMIN_IDS=""   # Deine Chat-ID von @userinfobot
.venv/bin/python app.py
