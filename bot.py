"""SecDrop Telegram Bot — webhook mode, works behind restrictive firewalls"""
import os, json, time, threading, urllib.request

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_IDS = set(int(x) for x in os.environ.get("TELEGRAM_ADMIN_IDS", "").split(",") if x.strip())
BASE = f"https://api.telegram.org/bot{TOKEN}"
_notify_queue = []

def _api(method, data=None):
    url = f"{BASE}/{method}"
    req = urllib.request.Request(url, json.dumps(data).encode() if data else None,
                                  {"Content-Type": "application/json"} if data else {})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except Exception as e:
        print(f"[BOT] API error: {e}")
        return None

def notify(message: str):
    _notify_queue.append(message)

def send_message(chat_id: int, text: str):
    return _api("sendMessage", {"chat_id": chat_id, "text": text[:4000], "parse_mode": "HTML"})

def setup_webhook(public_url: str):
    """Register webhook so Telegram pushes updates to us"""
    url = f"{public_url}/api/telegram-webhook"
    result = _api("setWebhook", {"url": url})
    if result and result.get("ok"):
        print(f"[BOT] Webhook gesetzt: {url}")
    else:
        print(f"[BOT] Webhook fehlgeschlagen: {result}")

def process_update(update: dict):
    msg = update.get("message")
    if not msg:
        return
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()
    user = msg.get("from", {}).get("first_name", "?")

    if text == "/start":
        send_message(chat_id, f"🤖 <b>SecDrop Bot</b>\nChat ID: <code>{chat_id}</code>\n\n"
                      f"Befehle: /stats, /block IP, /unblock IP, /locks, /paste text")
    elif not ADMIN_IDS or chat_id in ADMIN_IDS:
        if text == "/stats":
            try:
                from app import get_db
                db = get_db()
                users = db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
                pastes = db.execute("SELECT COUNT(*) as c FROM pastes").fetchone()["c"]
                db.close()
                send_message(chat_id, f"📊 <b>Stats</b>\nUsers: {users}\nPastes: {pastes}")
            except Exception as e:
                send_message(chat_id, f"Fehler: {e}")
        elif text.startswith("/block "):
            ip = text.split(" ", 1)[1].strip()
            from app import block_ip
            block_ip(ip)
            send_message(chat_id, f"🚫 IP <code>{ip}</code> blockiert.")
        elif text.startswith("/unblock "):
            ip = text.split(" ", 1)[1].strip()
            from app import unblock_ip
            unblock_ip(ip)
            send_message(chat_id, f"✅ IP <code>{ip}</code> freigegeben.")
        elif text == "/locks":
            from app import _login_fails, _admin_fails, _register_times, _upload_counts, _request_counts
            from app import MAX_LOGIN_FAILS, MAX_REGISTERS_PER_MIN, UPLOAD_LIMIT_PER_HOUR, MAX_REQUESTS_PER_MIN
            lines = ["🔒 <b>Sperren:</b>"]
            any_found = False
            for k, v in _login_fails.items():
                recent = [t for t in v if time.time() - t < 60]
                if recent:
                    lines.append(f"  Login {k}: {len(recent)}/{MAX_LOGIN_FAILS}{' 🚫' if len(recent)>=MAX_LOGIN_FAILS else ''}")
                    any_found = True
            recent_admin = [t for t in _admin_fails if time.time() - t < 60]
            if recent_admin:
                lines.append(f"  Admin: {len(recent_admin)}/{MAX_LOGIN_FAILS}{' 🚫' if len(recent_admin)>=MAX_LOGIN_FAILS else ''}")
                any_found = True
            for k, v in _register_times.items():
                recent = [t for t in v if time.time() - t < 60]
                if recent:
                    lines.append(f"  Reg {k}: {len(recent)}/{MAX_REGISTERS_PER_MIN}{' 🚫' if len(recent)>=MAX_REGISTERS_PER_MIN else ''}")
                    any_found = True
            for k, v in _upload_counts.items():
                recent = [t for t in v if time.time() - t < 3600]
                if recent:
                    lines.append(f"  Upload {k}: {len(recent)}/{UPLOAD_LIMIT_PER_HOUR}{' 🚫' if len(recent)>=UPLOAD_LIMIT_PER_HOUR else ''}")
                    any_found = True
            for k, v in _request_counts.items():
                recent = [t for t in v if time.time() - t < 60]
                if recent:
                    lines.append(f"  Req {k}: {len(recent)}/{MAX_REQUESTS_PER_MIN}{' 🚫' if len(recent)>=MAX_REQUESTS_PER_MIN else ''}")
                    any_found = True
            if not any_found:
                lines.append("  ✅ Keine Aktivität")
            send_message(chat_id, "\n".join(lines))
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
    else:
        send_message(chat_id, "⛔ Keine Berechtigung.")

def webhook_worker():
    """Process notifications in background"""
    while True:
        try:
            while _notify_queue:
                msg = _notify_queue.pop(0)
                for aid in ADMIN_IDS:
                    send_message(aid, msg)
        except Exception as e:
            print(f"[BOT] Notify error: {e}")
        time.sleep(2)

def start_bot():
    if TOKEN:
        print(f"[BOT] Bot gestartet (Webhook-Mode)")
        # Start notification worker
        t = threading.Thread(target=webhook_worker, daemon=True)
        t.start()
