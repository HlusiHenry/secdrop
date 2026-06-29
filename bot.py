#!/usr/bin/env python3
"""SecDrop Telegram Bot — polling-based, raw API, no dependencies"""
import os, json, time, threading, urllib.request

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_IDS = set(int(x) for x in os.environ.get("TELEGRAM_ADMIN_IDS", "").split(",") if x.strip())
BASE = f"https://api.telegram.org/bot{TOKEN}"
_offset = 0
_notify_queue: list[str] = []  # messages to send to all admins

def _api(method, data=None):
    """Call Telegram API"""
    url = f"{BASE}/{method}"
    if data:
        req = urllib.request.Request(url, json.dumps(data).encode(), {"Content-Type": "application/json"})
    else:
        req = urllib.request.Request(url)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except Exception as e:
        print(f"[BOT] API error: {e}")
        return None

def notify(message: str):
    """Send notification to all admin chat IDs"""
    global _notify_queue
    _notify_queue.append(message)

def send_message(chat_id: int, text: str):
    return _api("sendMessage", {"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML"})

def _process_updates():
    global _offset
    result = _api("getUpdates", {"offset": _offset, "timeout": 30})
    if not result or not result.get("ok"):
        return
    for update in result["result"]:
        _offset = max(_offset, update["update_id"] + 1)
        msg = update.get("message")
        if not msg:
            continue
        chat_id = msg["chat"]["id"]
        text = (msg.get("text") or "").strip()
        user = msg.get("from", {}).get("first_name", "?")

        if text == "/start":
            send_message(chat_id, f"🤖 <b>SecDrop Bot</b>\nChat ID: <code>{chat_id}</code>\n"
                          f"Gib diese ID in TELEGRAM_ADMIN_IDS ein.\n\n"
                          f"Befehle: /stats, /block IP, /unblock IP, /locks, /paste text")
        elif not ADMIN_IDS or chat_id in ADMIN_IDS:
            _handle_admin_command(chat_id, text, user)
        else:
            send_message(chat_id, "⛔ Keine Berechtigung.")

def _handle_admin_command(chat_id, text, user):
    if text == "/stats":
        # Import here to avoid circular imports
        from app import get_db
        db = get_db()
        users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        pastes = db.execute("SELECT COUNT(*) as c FROM pastes").fetchone()["c"]
        db.close()
        send_message(chat_id, f"📊 <b>Stats</b>\nUsers: {users}\nPastes: {pastes}")
    elif text.startswith("/block "):
        ip = text.split(" ", 1)[1].strip()
        from app import block_ip, is_ip_blocked
        block_ip(ip)
        send_message(chat_id, f"🚫 IP <code>{ip}</code> blockiert.")
    elif text.startswith("/unblock "):
        ip = text.split(" ", 1)[1].strip()
        from app import unblock_ip
        unblock_ip(ip)
        send_message(chat_id, f"✅ IP <code>{ip}</code> freigegeben.")
    elif text == "/locks":
        from app import _login_fails, _admin_fails, _register_times, _upload_counts
        lines = ["🔒 <b>Aktive Locks:</b>"]
        for k, v in _login_fails.items():
            recent = [t for t in v if time.time() - t < 60]
            if len(recent) >= 5: lines.append(f"  Login-Lock: {k} ({len(recent)})")
        if _admin_fails:
            recent = [t for t in _admin_fails if time.time() - t < 60]
            if len(recent) >= 5: lines.append(f"  Admin-Lock ({len(recent)})")
        for k, v in _register_times.items():
            recent = [t for t in v if time.time() - t < 60]
            if len(recent) >= 5: lines.append(f"  Reg-Flood: {k} ({len(recent)})")
        for k, v in _upload_counts.items():
            recent = [t for t in v if time.time() - t < 3600]
            if len(recent) >= 30: lines.append(f"  Upload-Limit: {k} ({len(recent)})")
        send_message(chat_id, "\n".join(lines) if len(lines) > 1 else "✅ Keine aktiven Locks.")
    elif text.startswith("/paste "):
        content = text.split(" ", 1)[1]
        import secrets
        from app import get_db, encrypt, generate_id
        pid = generate_id()
        db = get_db()
        db.execute("INSERT INTO pastes (id, type, content, expires_at) VALUES (?,?,?,datetime('now','+24 hours'))",
                   (pid, "text", encrypt(content.encode())))
        db.commit()
        db.close()
        send_message(chat_id, f"📝 Paste erstellt: <code>{pid}</code>")

def _process_notifications():
    global _notify_queue
    while _notify_queue:
        msg = _notify_queue.pop(0)
        for aid in ADMIN_IDS:
            try:
                send_message(aid, msg)
            except:
                pass

def bot_loop():
    print("[BOT] Telegram Bot gestartet" if TOKEN else "[BOT] Kein TELEGRAM_BOT_TOKEN — Bot deaktiviert")
    while TOKEN:
        try:
            _process_updates()
            _process_notifications()
        except Exception as e:
            print(f"[BOT] Error: {e}")
            time.sleep(5)

def start_bot():
    if TOKEN:
        t = threading.Thread(target=bot_loop, daemon=True)
        t.start()
