#!/usr/bin/env python3
"""
SecDrop — Self-hosted encrypted pastebin & file drop
Dark terminal aesthetic. SQLite. No cloud.
"""

import os, sys, time, sqlite3, secrets, hashlib, mimetypes, socket, random
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from flask import Flask, request, jsonify, render_template, send_file, abort
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import qrcode
import io

# ── Config ──────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
DB_PATH = BASE_DIR / "secdrop.db"
FILES_DIR = BASE_DIR / "files"
FILES_DIR.mkdir(exist_ok=True)
BASE_URL = os.environ.get("SECDROP_URL", "").rstrip("/")  # e.g. http://10.117.3.201:5000

# Auto-detect LAN IP
def get_lan_url(port=5000):
    """Detect the main LAN IP (skip loopback and tunnel/VPN /32 interfaces)"""
    try:
        # Use default route to find the primary interface
        import subprocess, re
        out = subprocess.check_output(["ip", "-4", "-br", "addr", "show"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                iface, state, cidr = parts[0], parts[1], parts[2]
                ip = cidr.split("/")[0]
                # Skip loopback, skip /32 tunnels, only take UP interfaces
                if ip != "127.0.0.1" and state == "UP" and not cidr.endswith("/32"):
                    return f"http://{ip}:{port}"
    except Exception:
        pass
    return f"http://127.0.0.1:{port}"

DETECTED_URL = get_lan_url()

def get_public_url(request=None):
    """Return the best public URL: request host (if from internet), or detected LAN IP"""
    if request and request.host_url:
        host = request.host_url.rstrip("/")
        # Detect scheme from proxy header (ngrok sends HTTPS → HTTP to Flask)
        scheme = request.headers.get("X-Forwarded-Proto", "")
        if scheme == "https":
            host = host.replace("http://", "https://", 1)
        # If accessed via localhost, fall through to LAN IP
        if "127.0.0.1" not in host and "localhost" not in host:
            return host
    return BASE_URL or DETECTED_URL

# ── Human-friendly word IDs ──────────────────────────────────
WORDS = [
    "ace","air","ape","arc","ash","axe","bad","bag","bar","bat","bay","bed","bee",
    "bit","box","bug","bus","cab","cap","car","cat","cop","cow","cub","cup","cut",
    "day","dew","dig","dim","dog","dot","dry","dub","dug","ear","eat","eel","egg",
    "elm","emu","end","era","eve","eye","fan","far","fat","fax","fig","fin","fir",
    "fit","fix","fly","fog","fox","fun","fur","gap","gas","gem","gig","gin","gnu",
    "gum","gun","gut","gym","ham","hat","hay","hen","hex","hid","hip","hit","hog",
    "hop","hot","hub","hue","hug","hut","ice","ink","inn","ion","ivy","jam","jar",
    "jaw","jay","jet","jig","job","jog","joy","jug","jut","keg","ken","key","kid",
    "kin","kit","lab","lad","lag","lap","law","leg","lid","lip","lit","log","lot",
    "low","lug","mac","mad","map","mat","maw","max","mix","mob","mod","mop","mow",
    "mud","mug","nab","nag","nap","net","new","nil","nip","nit","nod","nor","not",
    "now","nun","nut","oak","oar","oat","odd","ode","off","oft","oil","old","orb",
    "ore","our","out","owl","own","pad","pal","pan","paw","pea","peg","pen","pet",
    "pie","pig","pin","pit","pod","pop","pot","pro","pub","pug","pun","pup","put",
    "rag","ram","ran","rap","rat","raw","ray","red","ref","rib","rid","rig","rim",
    "rip","rob","rod","rot","row","rub","rug","rum","run","rut","sad","sap","saw",
    "say","sea","set","shy","sin","sip","sir","sit","six","ski","sky","sly","sob",
    "sod","son","sop","sot","sow","soy","spa","spy","sum","sun","tab","tag","tan",
    "tap","tar","tax","tea","ten","the","tie","tin","tip","toe","ton","too","top",
    "tow","toy","try","tub","tug","van","vat","vet","via","vow","war","wax","web",
    "wet","wig","win","wit","woe","wok","won","woo","yak","yam","yap","yaw","yea",
    "yes","yet","yew","zen","zip","zoo",
]

def generate_id():
    """Generate human-friendly ID like 'blue-fox-42'"""
    a = random.choice(WORDS)
    b = random.choice(WORDS)
    while b == a:
        b = random.choice(WORDS)
    n = random.randint(10, 99)
    return f"{a}-{b}-{n}"

# Generate or load Fernet key for encryption
KEY_FILE = BASE_DIR / ".seckey"
if KEY_FILE.exists():
    FERNET_KEY = KEY_FILE.read_bytes()
else:
    FERNET_KEY = Fernet.generate_key()
    KEY_FILE.write_bytes(FERNET_KEY)
    os.chmod(KEY_FILE, 0o600)
fernet = Fernet(FERNET_KEY)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB

# ── Rate limiting ────────────────────────────────────────────
_password_fails: dict[str, list[float]] = defaultdict(list)  # paste_id -> [timestamps]
MAX_PASSWORD_TRIES = 5
PASSWORD_LOCKOUT_SECS = 60

def check_rate_limit(paste_id: str) -> tuple[bool, str]:
    """Returns (allowed, message). Blocks after MAX_PASSWORD_TRIES in window."""
    now = time.time()
    attempts = _password_fails[paste_id]
    # Purge old attempts
    attempts[:] = [t for t in attempts if now - t < PASSWORD_LOCKOUT_SECS]
    if len(attempts) >= MAX_PASSWORD_TRIES:
        remaining = int(PASSWORD_LOCKOUT_SECS - (now - attempts[0]))
        return False, f"Too many attempts. Wait {remaining}s."
    return True, ""

def record_failed_attempt(paste_id: str):
    _password_fails[paste_id].append(time.time())

# ── Database ────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,       -- 'text' or 'file'
            content TEXT,             -- encrypted text or file metadata
            filename TEXT,
            mime_type TEXT,
            size_bytes INTEGER,
            password_hash TEXT,
            burn_after INTEGER DEFAULT 0,
            expires_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            views INTEGER DEFAULT 0
        )
    """)
    db.commit()
    db.close()

# ── Crypto helpers ──────────────────────────────────────────
def encrypt(data: bytes) -> str:
    return fernet.encrypt(data).decode()

def decrypt(token: str) -> bytes:
    return fernet.decrypt(token.encode())

def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = kdf.derive(pw.encode())
    return base64.b64encode(salt + key).decode()

def check_password(pw: str, stored: str) -> bool:
    try:
        decoded = base64.b64decode(stored)
        salt, key = decoded[:16], decoded[16:]
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        kdf.verify(pw.encode(), key)
        return True
    except Exception:
        return False

# ── Cleanup expired pastes ─────────────────────────────────
def cleanup_expired():
    db = get_db()
    now = datetime.utcnow().isoformat()
    expired = db.execute(
        "SELECT id, type FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?", (now,)
    ).fetchall()
    for row in expired:
        if row["type"] == "file":
            file_path = FILES_DIR / row["id"]
            if file_path.exists():
                file_path.unlink()
        db.execute("DELETE FROM pastes WHERE id = ?", (row["id"],))
    db.commit()
    db.close()

# ── Routes ──────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/paste", methods=["POST"])
def create_paste():
    cleanup_expired()

    paste_id = generate_id()
    paste_type = request.form.get("type", "text")
    password = request.form.get("password", "").strip()
    expire = request.form.get("expire", "").strip()  # 1h, 24h, 7d, 30d, never
    burn = request.form.get("burn", "0")

    expires_at = None
    expire_map = {"1h": 1/24, "24h": 1, "7d": 7, "30d": 30}
    if expire in expire_map:
        expires_at = (datetime.utcnow() + timedelta(days=expire_map[expire])).isoformat()

    password_hash = hash_password(password) if password else None

    if paste_type == "text":
        content = request.form.get("content", "")
        encrypted = encrypt(content.encode())
        db = get_db()
        db.execute(
            "INSERT INTO pastes (id, type, content, password_hash, burn_after, expires_at) VALUES (?,?,?,?,?,?)",
            (paste_id, "text", encrypted, password_hash, int(burn), expires_at),
        )
        db.commit()
        db.close()
    elif paste_type == "file":
        file = request.files.get("file")
        if not file:
            return jsonify({"error": "No file"}), 400
        data = file.read()
        original_name = file.filename or "unnamed"
        encrypted = encrypt(data)
        db = get_db()
        db.execute(
            "INSERT INTO pastes (id, type, content, filename, mime_type, size_bytes, password_hash, burn_after, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (paste_id, "file", encrypted, original_name,
             file.mimetype or "application/octet-stream",
             len(data), password_hash, int(burn), expires_at),
        )
        db.commit()
        db.close()

    return jsonify({"id": paste_id, "url": f"{get_public_url(request)}/{paste_id}"})

@app.route("/<paste_id>")
def view_paste(paste_id):
    cleanup_expired()
    db = get_db()
    paste = db.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()
    if not paste:
        db.close()
        abort(404)
    db.close()
    return render_template("view.html", paste=paste)

@app.route("/api/paste/<paste_id>", methods=["POST"])
def access_paste(paste_id):
    cleanup_expired()
    db = get_db()
    paste = db.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()

    if not paste:
        db.close()
        return jsonify({"error": "Not found or expired"}), 404

    if paste["password_hash"]:
        pw = request.json.get("password", "")
        # Rate limiting
        allowed, msg = check_rate_limit(paste_id)
        if not allowed:
            db.close()
            return jsonify({"error": msg}), 429
        if not check_password(pw, paste["password_hash"]):
            record_failed_attempt(paste_id)
            db.close()
            return jsonify({"error": "Wrong password"}), 403

    # Increment views
    db.execute("UPDATE pastes SET views = views + 1 WHERE id = ?", (paste_id,))
    db.commit()

    try:
        decrypted = decrypt(paste["content"])
        result = {
            "type": paste["type"],
            "filename": paste["filename"],
            "mime_type": paste["mime_type"],
            "size_bytes": paste["size_bytes"],
            "created_at": paste["created_at"],
            "views": paste["views"] + 1,
            "burn_after": bool(paste["burn_after"]),
        }
        if paste["type"] == "text":
            result["content"] = decrypted.decode()
        else:
            result["content_b64"] = base64.b64encode(decrypted).decode()
    except Exception as e:
        db.close()
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

    # Burn after reading — only for text (files burn on actual download)
    if paste["burn_after"]:
        if paste["type"] == "text":
            db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
            db.commit()
            result["destroyed"] = True
        else:
            # File: don't burn yet, user needs to click download first
            result["burn_pending"] = True

    db.close()
    return jsonify(result)

@app.route("/api/raw/<paste_id>", methods=["POST"])
def raw_paste(paste_id):
    """Direct download for files"""
    cleanup_expired()
    db = get_db()
    paste = db.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()
    if not paste:
        db.close()
        return jsonify({"error": "Not found"}), 404

    if paste["password_hash"]:
        pw = request.json.get("password", "")
        allowed, msg = check_rate_limit(paste_id)
        if not allowed:
            db.close()
            return jsonify({"error": msg}), 429
        if not check_password(pw, paste["password_hash"]):
            record_failed_attempt(paste_id)
            db.close()
            return jsonify({"error": "Wrong password"}), 403

    try:
        decrypted = decrypt(paste["content"])
    except Exception:
        db.close()
        return jsonify({"error": "Decryption failed"}), 500

    if paste["burn_after"]:
        fp = FILES_DIR / paste_id
        if fp.exists():
            fp.unlink()
        db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
        db.commit()

    db.close()
    return send_file(
        io.BytesIO(decrypted),
        mimetype=paste["mime_type"] or "application/octet-stream",
        as_attachment=True,
        download_name=paste["filename"] or "download",
    )

@app.route("/api/qr/<paste_id>")
def qr_code(paste_id):
    base = get_public_url(request)
    img = qrcode.make(f"{base}/{paste_id}")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("404.html"), 404

# ── Main ────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print(f"""
    ╔══════════════════════════════════════════════╗
    ║  █▀▀ █▀▀ █▀▀ █▀▄ █▀▄ █▀█ █▀█                ║
    ║  ▀▀█ █▀▀ █   █▀▄ █▀▄ █ █ █▀▀                ║
    ║  ▀▀▀ ▀▀▀ ▀▀▀ ▀▀  ▀ ▀ ▀▀▀ ▀                   ║
    ║  Self-hosted encrypted pastebin & file drop  ║
    ╠══════════════════════════════════════════════╣
    ║  Local:   http://127.0.0.1:5000              ║
    ║  Network: {DETECTED_URL:<42}║
    ╚══════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5000, debug=False)
