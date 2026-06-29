#!/usr/bin/env python3
"""
SecDrop — Self-hosted encrypted pastebin & file drop
Dark terminal aesthetic. SQLite. No cloud.
"""

import os, sys, time, sqlite3, secrets, hashlib, mimetypes, socket, random, re
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from flask import Flask, request, jsonify, render_template, send_file, abort, session, redirect
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
    """Return the best public URL: request host (if from trusted proxy), or detected LAN IP"""
    if request and request.host_url:
        host = request.host_url.rstrip("/")
        # Only trust known proxy/reverse-proxy hosts
        trusted = ("ngrok-free.", "trycloudflare.com", "loca.lt", "localhost", "127.0.0.1")
        is_local = "127.0.0.1" in host or "localhost" in host
        is_trusted = any(t in host for t in trusted)
        if is_local:
            return BASE_URL or DETECTED_URL
        if is_trusted:
            scheme = request.headers.get("X-Forwarded-Proto", "")
            if scheme == "https":
                host = host.replace("http://", "https://", 1)
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
app.secret_key = secrets.token_hex(32)  # For session cookies
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB

# Admin password (set via env SECDROP_ADMIN_PW or changed via dashboard)
ADMIN_PW_FILE = BASE_DIR / ".admin_pw"
if ADMIN_PW_FILE.exists():
    ADMIN_PW = ADMIN_PW_FILE.read_text().strip()
else:
    ADMIN_PW = os.environ.get("SECDROP_ADMIN_PW", "secdrop").strip()

# ── Security headers ────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Server"] = ""  # Hide Werkzeug version
    return response

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

# IP-based rate limiting for login/register
_login_fails: dict[str, list[float]] = defaultdict(list)  # ip or username -> timestamps
_register_times: dict[str, list[float]] = defaultdict(list)  # ip -> timestamps
MAX_LOGIN_FAILS = 5
MAX_REGISTERS_PER_MIN = 5

def get_client_ip():
    """Get real client IP, considering proxies like ngrok"""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def check_login_bruteforce(identifier: str) -> tuple[bool, str]:
    """Check if this IP/username is locked from login attempts"""
    now = time.time()
    attempts = _login_fails[identifier]
    attempts[:] = [t for t in attempts if now - t < PASSWORD_LOCKOUT_SECS]
    if len(attempts) >= MAX_LOGIN_FAILS:
        remaining = int(PASSWORD_LOCKOUT_SECS - (now - attempts[0]))
        return False, f"Too many login attempts. Wait {remaining}s."
    return True, ""

def check_register_flood(ip: str) -> tuple[bool, str]:
    """Check if this IP is flooding registrations"""
    now = time.time()
    times = _register_times[ip]
    times[:] = [t for t in times if now - t < 60]
    if len(times) >= MAX_REGISTERS_PER_MIN:
        return False, "Too many registrations. Wait."
    return True, ""

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
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            ip_address TEXT,
            last_ip TEXT,
            last_login TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS pastes (
            id TEXT PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            creator_ip TEXT,
            type TEXT NOT NULL,
            content TEXT,
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
    # Auto-migrate: add missing columns
    for table, cols in [
        ("users", ["ip_address", "last_ip", "last_login"]),
        ("pastes", ["user_id", "creator_ip"]),
    ]:
        existing = {r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()}
        for col in cols:
            if col not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
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

# ── User Auth ─────────────────────────────────────────────────
def get_current_user():
    uid = session.get("user_id")
    if uid:
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        db.close()
        return user
    return None

@app.route("/api/register", methods=["POST"])
def register():
    ip = get_client_ip()
    allowed, msg = check_register_flood(ip)
    if not allowed:
        return jsonify({"error": msg}), 429
    _register_times[ip].append(time.time())

    data = request.get_json() or {}
    username = (data.get("username") or "").strip()[:32]
    password = (data.get("password") or "").strip()
    if len(username) < 2 or len(password) < 3:
        return jsonify({"error": "Username min 2 chars, password min 3"}), 400
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return jsonify({"error": "Username: only letters, numbers, -,_"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "Username already taken"}), 409

    db.execute("INSERT INTO users (username, password_hash, ip_address, last_ip, last_login) VALUES (?, ?, ?, ?, datetime('now'))",
               (username, hash_password(password), ip, ip))
    db.commit()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    db.close()
    session["user_id"] = user["id"]
    return jsonify({"username": user["username"], "id": user["id"]})

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = get_client_ip()
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    # Check brute-force: by username AND by IP
    allowed, msg = check_login_bruteforce(username)
    if not allowed:
        return jsonify({"error": msg}), 429
    allowed2, msg2 = check_login_bruteforce(f"ip:{ip}")
    if not allowed2:
        return jsonify({"error": msg2}), 429

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not check_password(password, user["password_hash"]):
        _login_fails[username].append(time.time())
        _login_fails[f"ip:{ip}"].append(time.time())
        db.close()
        return jsonify({"error": "Wrong username or password"}), 401
    db.execute("UPDATE users SET last_ip = ?, last_login = datetime('now') WHERE id = ?", (ip, user["id"]))
    db.commit()
    db.close()
    session["user_id"] = user["id"]
    return jsonify({"username": user["username"], "id": user["id"]})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/me")
def api_me():
    user = get_current_user()
    if user:
        return jsonify({"username": user["username"], "id": user["id"]})
    return jsonify({"username": None})

@app.route("/api/change-password", methods=["POST"])
def change_password():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    old_pw = (data.get("old_password") or "").strip()
    new_pw = (data.get("new_password") or "").strip()
    if len(new_pw) < 3:
        return jsonify({"error": "New password min 3 chars"}), 400
    if not check_password(old_pw, user["password_hash"]):
        return jsonify({"error": "Wrong current password"}), 403
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (hash_password(new_pw), user["id"]))
    db.commit()
    db.close()
    return jsonify({"ok": True, "message": "Password changed"})

# ── Admin Dashboard ───────────────────────────────────────────
def is_admin():
    return session.get("admin_ok") == True

_admin_fails: list[float] = []  # timestamps of failed admin login attempts

@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if request.method == "POST":
        # Rate limiting for admin login
        now = time.time()
        global _admin_fails
        _admin_fails[:] = [t for t in _admin_fails if now - t < PASSWORD_LOCKOUT_SECS]
        if len(_admin_fails) >= MAX_LOGIN_FAILS:
            remaining = int(PASSWORD_LOCKOUT_SECS - (now - _admin_fails[0]))
            return render_template("admin_login.html", error=f"Too many attempts. Wait {remaining}s.")

        pw = (request.form.get("password") or "").strip()
        if pw == ADMIN_PW:
            session["admin_ok"] = True
        else:
            _admin_fails.append(now)
            return render_template("admin_login.html", error="Wrong admin password")

    if not is_admin():
        return render_template("admin_login.html")

    db = get_db()
    users = db.execute("SELECT id, username, created_at FROM users ORDER BY id").fetchall()
    total_pastes = db.execute("SELECT COUNT(*) as c FROM pastes").fetchone()["c"]
    total_files = db.execute("SELECT COUNT(*) as c FROM pastes WHERE type='file'").fetchone()["c"]
    user_stats = db.execute("""
        SELECT u.username, COUNT(p.id) as paste_count
        FROM users u LEFT JOIN pastes p ON u.id = p.user_id
        GROUP BY u.id ORDER BY paste_count DESC
    """).fetchall()
    db.close()
    return render_template("admin.html",
        users=users, total_pastes=total_pastes, total_files=total_files,
        user_stats=user_stats)

@app.route("/api/admin/users")
def api_admin_users():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    db = get_db()
    users = db.execute("SELECT id, username, ip_address, last_ip, last_login, created_at FROM users ORDER BY id").fetchall()
    db.close()
    return jsonify([dict(u) for u in users])

@app.route("/api/admin/pastes")
def api_admin_pastes():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    db = get_db()
    pastes = db.execute("""
        SELECT p.id, p.type, p.filename, p.size_bytes, p.burn_after, p.expires_at, p.created_at, p.views,
               p.creator_ip, COALESCE(u.username, 'anonymous') as username
        FROM pastes p LEFT JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC LIMIT 100
    """).fetchall()
    db.close()
    return jsonify([dict(p) for p in pastes])

@app.route("/api/admin/extend/<paste_id>", methods=["POST"])
def admin_extend_paste(paste_id):
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    days = int(data.get("days", 7))
    new_expiry = (datetime.utcnow() + timedelta(days=days)).isoformat()
    db = get_db()
    db.execute("UPDATE pastes SET expires_at = ? WHERE id = ?", (new_expiry, paste_id))
    db.commit()
    db.close()
    return jsonify({"ok": True, "new_expiry": new_expiry})

@app.route("/api/admin/stats")
def api_admin_stats():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    db = get_db()
    now = time.time()
    # Count currently locked IPs/usernames for login
    locked_logins = sum(1 for k, v in _login_fails.items()
                        if len([t for t in v if now - t < PASSWORD_LOCKOUT_SECS]) >= MAX_LOGIN_FAILS)
    blocked_reg_ips = sum(1 for k, v in _register_times.items()
                          if len([t for t in v if now - t < 60]) >= MAX_REGISTERS_PER_MIN)
    stats = {
        "total_users": db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"],
        "total_pastes": db.execute("SELECT COUNT(*) as c FROM pastes").fetchone()["c"],
        "text_pastes": db.execute("SELECT COUNT(*) as c FROM pastes WHERE type='text'").fetchone()["c"],
        "file_pastes": db.execute("SELECT COUNT(*) as c FROM pastes WHERE type='file'").fetchone()["c"],
        "total_views": db.execute("SELECT COALESCE(SUM(views),0) as c FROM pastes").fetchone()["c"],
        "password_protected": db.execute("SELECT COUNT(*) as c FROM pastes WHERE password_hash IS NOT NULL").fetchone()["c"],
        "burn_after": db.execute("SELECT COUNT(*) as c FROM pastes WHERE burn_after=1").fetchone()["c"],
        "locked_logins": locked_logins,
        "blocked_reg_ips": blocked_reg_ips,
    }
    db.close()
    return jsonify(stats)

@app.route("/api/admin/is-default-pw")
def api_admin_default_pw():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({"is_default": ADMIN_PW == "secdrop"})

@app.route("/api/admin/blocked")
def api_admin_blocked():
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    now = time.time()
    blocked = []
    for key, attempts in _login_fails.items():
        recent = [t for t in attempts if now - t < PASSWORD_LOCKOUT_SECS]
        if len(recent) >= MAX_LOGIN_FAILS:
            blocked.append({"target": key, "attempts": len(recent), "type": "login"})
    for ip, times in _register_times.items():
        recent = [t for t in times if now - t < 60]
        if len(recent) >= MAX_REGISTERS_PER_MIN:
            blocked.append({"target": ip, "attempts": len(recent), "type": "register"})
    return jsonify(blocked)

@app.route("/api/admin/reset-pw/<int:user_id>", methods=["POST"])
def admin_reset_password(user_id):
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    new_pw = (data.get("new_password") or "").strip()
    if len(new_pw) < 3:
        return jsonify({"error": "Min 3 chars"}), 400
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (hash_password(new_pw), user_id))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.route("/api/admin/delete-user/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    if user_id == 1:
        return jsonify({"error": "Cannot delete admin"}), 403
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.route("/api/admin/change-pw", methods=["POST"])
def admin_change_password():
    global ADMIN_PW
    if not is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    old_pw = (data.get("old_password") or "").strip()
    new_pw = (data.get("new_password") or "").strip()
    if old_pw != ADMIN_PW:
        return jsonify({"error": "Wrong current admin password"}), 403
    if len(new_pw) < 4:
        return jsonify({"error": "Min 4 chars"}), 400
    ADMIN_PW_FILE.write_text(new_pw)
    ADMIN_PW = new_pw
    return jsonify({"ok": True})

# ── Routes ──────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/paste", methods=["POST"])
def create_paste():
    user = get_current_user()
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
        uid = user["id"] if user else None
        cip = get_client_ip()
        db.execute(
            "INSERT INTO pastes (user_id, creator_ip, id, type, content, password_hash, burn_after, expires_at) VALUES (?,?,?,?,?,?,?,?)",
            (uid, cip, paste_id, "text", encrypted, password_hash, int(burn), expires_at),
        )
        db.commit()
        db.close()
    elif paste_type == "file":
        file = request.files.get("file")
        if not file:
            return jsonify({"error": "No file"}), 400
        data = file.read()
        original_name = file.filename or "unnamed"
        # Sanitize: strip path, remove HTML/control chars
        original_name = re.sub(r'[<>"\'\\/\x00-\x1f]', '', original_name)[:255]
        encrypted = encrypt(data)
        db = get_db()
        uid = user["id"] if user else None
        cip = get_client_ip()
        db.execute(
            "INSERT INTO pastes (user_id, creator_ip, id, type, content, filename, mime_type, size_bytes, password_hash, burn_after, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (uid, cip, paste_id, "file", encrypted, original_name,
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
        pw = request.json.get("password", "").strip()
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
        pw = request.json.get("password", "").strip()
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

@app.route("/api/pastes")
def list_pastes():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Login required"}), 401
    db = get_db()
    pastes = db.execute(
        "SELECT id, type, filename, size_bytes, burn_after, expires_at, created_at, views FROM pastes WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
        (user["id"],)
    ).fetchall()
    db.close()
    return jsonify([dict(p) for p in pastes])

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
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
