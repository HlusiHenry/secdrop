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
# Telegram Bot
export TELEGRAM_BOT_TOKEN="8938..."...rt TELEGRAM_ADMIN_IDS="8797262973"

# Cloud Sync (optional): set to Dropbox/Drive folder for multi-device data
# export SECDROP_DATA_DIR="/home/henry/Dropbox/SecDropData"

.venv/bin/python app.py
