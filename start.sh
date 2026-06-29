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
# Optional: Telegram Bot
# export TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
# export TELEGRAM_ADMIN_IDS="123456789"
.venv/bin/python app.py
