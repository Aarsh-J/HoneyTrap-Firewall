# ===========================================
# HoneyTrap Firewall - Core Rules Engine
# ===========================================
import hashlib
import hmac
import logging
import secrets
import time

from . import config
from . import db

logger = logging.getLogger(__name__)


def _coerce_port(port):
    """Ports arrive as either int or str depending on the caller; normalize
    to int so SQLite comparisons against the INTEGER `port` column are exact."""
    try:
        return int(port)
    except (TypeError, ValueError):
        return port

# ----------------------
# Password Hashing
# ----------------------
# Passwords are never stored or compared in plaintext. Each password gets a
# random per-user salt, hashed with PBKDF2-HMAC-SHA256, and verified with a
# constant-time comparison to avoid leaking timing information.
HASH_ITERATIONS = config.HASH_ITERATIONS

def hash_password(password, salt=None):
    """Hash a password with a random (or given) salt. Returns (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)

    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, HASH_ITERATIONS)
    return digest.hex(), salt.hex()

def verify_password(password, salt_hex, hash_hex):
    """Check a password against a stored salt+hash using a constant-time comparison."""
    candidate_hash, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(candidate_hash, hash_hex)

# ----------------------
# Constants
# ----------------------
# Admin credentials come from config (which reads them from the environment),
# so the real password never lives in source control.
ADMIN_USERNAME = config.ADMIN_USERNAME
ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT = hash_password(config.ADMIN_PASSWORD_RAW)
INACTIVITY_LIMIT = config.INACTIVITY_LIMIT

# ----------------------
# Firewall Rules
# ----------------------
def create_user(username, password):
    """Create a new user if username doesn't exist"""
    with db.get_connection() as conn:
        existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return False, "Username already exists"

        password_hash, salt = hash_password(password)
        conn.execute(
            "INSERT INTO users (username, hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt),
        )
    return True, "User created successfully"

def check_login(username, password, ip_address, port):
    """
    Validates login and applies firewall rules.
    Returns:
        - "admin" if admin credentials
        - "valid" if valid user
        - "fake" if user should be directed to fake page
        - "error" if login failed
    """
    port = _coerce_port(port)

    # Admin login check - must be first to bypass all other checks
    if username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_SALT, ADMIN_PASSWORD_HASH):
        return "admin", None

    with db.get_connection() as conn:
        # Check if IP is banned
        banned = conn.execute("SELECT 1 FROM banned_ips WHERE ip = ?", (ip_address,)).fetchone()
        if banned:
            return "fake", "IP address banned"

        # Basic validation
        if len(username) < 3 or len(password) < 3:
            return "error", "Invalid username/password length"

        # Check if the port has honeypot enabled
        port_row = conn.execute(
            "SELECT honeypot FROM ports WHERE port = ? AND status = 'active'", (port,)
        ).fetchone()
        port_honeypot_enabled = bool(port_row["honeypot"]) if port_row else False

        # If honeypot is active, always send to fake page
        if port_honeypot_enabled:
            return "fake", None

        # Regular user login
        user_row = conn.execute(
            "SELECT hash, salt FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user_row and verify_password(password, user_row["salt"], user_row["hash"]):
            # Reset login attempts for this user+IP if successful
            key = f"{username}:{ip_address}"
            conn.execute("DELETE FROM login_attempts WHERE key = ?", (key,))

            now = time.time()
            conn.execute(
                "INSERT INTO sessions (username, login_time, last_activity_time, ip, port) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(username) DO UPDATE SET "
                "login_time = excluded.login_time, "
                "last_activity_time = excluded.last_activity_time, "
                "ip = excluded.ip, port = excluded.port",
                (username, now, now, ip_address, port),
            )
            return "valid", None

        # Failed attempt handling
        key = f"{username}:{ip_address}"
        row = conn.execute("SELECT count FROM login_attempts WHERE key = ?", (key,)).fetchone()
        count = (row["count"] if row else 0) + 1
        now = time.time()

        if row:
            conn.execute(
                "UPDATE login_attempts SET count = ?, last_attempt_at = ? WHERE key = ?",
                (count, now, key),
            )
        else:
            conn.execute(
                "INSERT INTO login_attempts (key, count, first_attempt_at, last_attempt_at) "
                "VALUES (?, ?, ?, ?)",
                (key, count, now, now),
            )

        # Check number of failed attempts - Allow 2 incorrect attempts
        if count >= 2:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO potential_attackers "
                "(username, ip, attempted_port, attempts, reason, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(username, ip) DO UPDATE SET "
                "attempted_port = excluded.attempted_port, "
                "attempts = excluded.attempts, "
                "reason = excluded.reason, "
                "timestamp = excluded.timestamp",
                (username, ip_address, port, count, "2 or more failed login attempts", timestamp),
            )

            # Enable honeypot on this port
            conn.execute(
                "UPDATE ports SET honeypot = 1, last_triggered = ? WHERE port = ?",
                (timestamp, port),
            )

            return "fake", None

        return "error", "Incorrect username/password"

def logout_user(username):
    """Remove a user's session when they log out properly"""
    with db.get_connection() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        return cur.rowcount > 0

def check_inactivity():
    """Check for inactive users and flag them as potential attackers if inactive beyond limit"""
    current_time = time.time()

    with db.get_connection() as conn:
        sessions = conn.execute("SELECT * FROM sessions").fetchall()

        for session in sessions:
            username = session["username"]
            if username == ADMIN_USERNAME:
                continue

            port = session["port"] if session["port"] is not None else "unknown"
            inactive_time = current_time - session["last_activity_time"]

            # Only mark as potential attackers if they've been inactive beyond limit
            if inactive_time > INACTIVITY_LIMIT:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

                conn.execute(
                    "INSERT INTO potential_attackers "
                    "(username, ip, attempted_port, attempts, reason, timestamp) "
                    "VALUES (?, ?, ?, NULL, ?, ?) "
                    "ON CONFLICT(username, ip) DO UPDATE SET "
                    "attempted_port = excluded.attempted_port, "
                    "attempts = excluded.attempts, "
                    "reason = excluded.reason, "
                    "timestamp = excluded.timestamp",
                    (username, session["ip"], port, "Inactive for 5+ minutes", timestamp),
                )

                # Enable honeypot for this session's port
                conn.execute(
                    "UPDATE ports SET honeypot = 1, last_triggered = ? WHERE port = ?",
                    (timestamp, port),
                )

                # Remove the session
                conn.execute("DELETE FROM sessions WHERE username = ?", (username,))

def update_activity(username):
    """Update user activity timestamp"""
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET last_activity_time = ? WHERE username = ?",
            (time.time(), username),
        )
    return True

def get_port_status(port):
    """Check if port is active and if honeypot is enabled"""
    port = _coerce_port(port)
    with db.get_connection() as conn:
        row = conn.execute("SELECT status, honeypot FROM ports WHERE port = ?", (port,)).fetchone()
    if row:
        return {"active": row["status"] == "active", "honeypot": bool(row["honeypot"])}
    return {"active": False, "honeypot": False}

def toggle_port_status(port, status=None, honeypot=None):
    """Update port status or honeypot setting"""
    port = _coerce_port(port)
    with db.get_connection() as conn:
        row = conn.execute("SELECT 1 FROM ports WHERE port = ?", (port,)).fetchone()
        if not row:
            return False

        if status is not None:
            conn.execute("UPDATE ports SET status = ? WHERE port = ?", (status, port))
        if honeypot is not None:
            conn.execute(
                "UPDATE ports SET honeypot = ? WHERE port = ?",
                (1 if honeypot else 0, port),
            )
    return True

def get_attackers():
    """Return the list of attackers"""
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT username, ip, attempted_port, reason, timestamp FROM attackers ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]

def get_ports():
    """Return the list of ports"""
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT port, status, honeypot, last_triggered FROM ports ORDER BY port"
        ).fetchall()
    return [
        {
            "port": row["port"],
            "status": row["status"],
            "honeypot": bool(row["honeypot"]),
            "last_triggered": row["last_triggered"],
        }
        for row in rows
    ]

def get_potential_attackers():
    """Return the list of potential attackers"""
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT username, ip, attempted_port, attempts, reason, timestamp "
            "FROM potential_attackers ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]

def ban_ip(ip_address):
    """Add an IP to the banned list"""
    with db.get_connection() as conn:
        conn.execute("INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)", (ip_address,))
    return True

def unban_ip(ip_address):
    """Remove an IP from the banned list"""
    with db.get_connection() as conn:
        conn.execute("DELETE FROM banned_ips WHERE ip = ?", (ip_address,))
    return True

def get_banned_ips():
    """Get the list of banned IPs"""
    with db.get_connection() as conn:
        rows = conn.execute("SELECT ip FROM banned_ips ORDER BY ip").fetchall()
    return [row["ip"] for row in rows]

def get_active_users():
    """Get the list of currently active users with their session details"""
    current_time = time.time()
    with db.get_connection() as conn:
        sessions = conn.execute("SELECT * FROM sessions").fetchall()

    active_users = []
    for session in sessions:
        session_length = current_time - session["login_time"]
        last_activity = current_time - session["last_activity_time"]

        active_users.append({
            "username": session["username"],
            "ip": session["ip"],
            "port": session["port"] if session["port"] is not None else "unknown",
            "login_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session["login_time"])),
            "last_activity": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session["last_activity_time"])),
            "session_length": f"{int(session_length / 60)} mins",
            "inactive_for": f"{int(last_activity / 60)} mins"
        })

    return active_users

# Initialize the database on import
def initialize_files():
    """Create the database (if needed) and seed default ports/a test user."""
    try:
        db.init_db()
        with db.get_connection() as conn:
            port_count = conn.execute("SELECT COUNT(*) AS c FROM ports").fetchone()["c"]
            if port_count == 0:
                default_ports = [
                    (8001, "active", 0, "Never"),
                    (8002, "active", 0, "Never"),
                    (8003, "active", 0, "Never"),
                    (8004, "inactive", 0, "Never"),
                    (8005, "inactive", 0, "Never"),
                ]
                conn.executemany(
                    "INSERT INTO ports (port, status, honeypot, last_triggered) VALUES (?, ?, ?, ?)",
                    default_ports,
                )

            user_count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            if user_count == 0:
                # Create a default test user if none exist
                password_hash, salt = hash_password("password")
                conn.execute(
                    "INSERT INTO users (username, hash, salt) VALUES (?, ?, ?)",
                    ("user", password_hash, salt),
                )

    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# Initialize on import
initialize_files()
