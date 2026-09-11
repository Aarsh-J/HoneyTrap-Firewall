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
# Risk scoring
# ----------------------
# Different suspicious signals (repeated failed logins, malformed protocol
# messages, touching many ports quickly) all add points to a single per-IP
# score, instead of each having its own hardcoded threshold. The score is
# itself a *sum over a sliding window* (RISK_SCORE_WINDOW_SECONDS) rather
# than an ever-growing counter - each event is stored with its own
# timestamp, so one stale event from long ago can't keep counting against
# an IP forever. Crossing HONEYPOT_TRIGGER_THRESHOLD is what actually flags
# a honeypot - see check_login() for how a crossing gets tied to a port.
_EVENT_POINTS = {
    "failed_login": lambda: config.FAILED_LOGIN_POINTS,
    "malformed_message": lambda: config.MALFORMED_MESSAGE_POINTS,
    "port_scan": lambda: config.PORT_SCAN_POINTS,
}

def record_suspicious_event(ip_address, event_type, conn=None):
    """Record a suspicious event and add its points to the IP's windowed score.

    Pass an existing `conn` when calling from inside a function that already
    holds an open db.get_connection() - SQLite only allows one writer at a
    time, so nesting a second, separate connection while the first is still
    uncommitted would deadlock. Standalone callers (outside any existing
    transaction) can omit it.

    Returns (new_score, triggered) where triggered is True only on the exact
    call that pushes the windowed score from below HONEYPOT_TRIGGER_THRESHOLD
    to at or above it.
    """
    points = _EVENT_POINTS.get(event_type, lambda: 0)()
    now = time.time()
    window_start = now - config.RISK_SCORE_WINDOW_SECONDS

    def _apply(c):
        previous_score = c.execute(
            "SELECT COALESCE(SUM(points), 0) AS s FROM risk_events WHERE ip = ? AND occurred_at >= ?",
            (ip_address, window_start),
        ).fetchone()["s"]

        c.execute(
            "INSERT INTO risk_events (ip, event_type, points, occurred_at) VALUES (?, ?, ?, ?)",
            (ip_address, event_type, points, now),
        )
        # Housekeeping: drop events that have aged out of every IP's window
        # so this table doesn't grow forever.
        c.execute("DELETE FROM risk_events WHERE occurred_at < ?", (window_start,))

        return previous_score, previous_score + points

    if conn is not None:
        previous_score, new_score = _apply(conn)
    else:
        with db.get_connection() as c:
            previous_score, new_score = _apply(c)

    triggered = previous_score < config.HONEYPOT_TRIGGER_THRESHOLD <= new_score
    return new_score, triggered

def get_ip_risk_score(ip_address):
    """Return an IP's current windowed risk score (0 if none in-window)."""
    window_start = time.time() - config.RISK_SCORE_WINDOW_SECONDS
    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(points), 0) AS s FROM risk_events WHERE ip = ? AND occurred_at >= ?",
            (ip_address, window_start),
        ).fetchone()
    return row["s"]

def record_port_touch(ip_address, port, conn=None):
    """Record that an IP attempted to use a given (virtual/simulated) port,
    and treat touching several distinct ports in a short window as a port
    scan. See record_suspicious_event() for the `conn` reuse rule.

    Returns True if this touch caused the honeypot trigger threshold to be
    crossed via the resulting "port_scan" event.
    """
    port = _coerce_port(port)
    now = time.time()
    window_start = now - config.PORT_SCAN_WINDOW_SECONDS

    def _apply(c):
        c.execute(
            "INSERT INTO port_touches (ip, port, touched_at) VALUES (?, ?, ?)",
            (ip_address, port, now),
        )
        c.execute("DELETE FROM port_touches WHERE touched_at < ?", (window_start,))

        distinct_ports = c.execute(
            "SELECT COUNT(DISTINCT port) AS c FROM port_touches WHERE ip = ? AND touched_at >= ?",
            (ip_address, window_start),
        ).fetchone()["c"]

        if distinct_ports < config.PORT_SCAN_DISTINCT_PORTS:
            return False

        _, triggered = record_suspicious_event(ip_address, "port_scan", conn=c)
        return triggered

    if conn is not None:
        return _apply(conn)
    with db.get_connection() as c:
        return _apply(c)

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

        # Port-scan detection: touching many different (virtual) ports
        # quickly is itself suspicious, independent of whether the
        # credentials on any given attempt are correct. If this pushes the
        # IP's risk score over the threshold, flag *this* port's honeypot
        # immediately - the lookup right below will then see it.
        if port is not None:
            scan_triggered = record_port_touch(ip_address, port, conn=conn)
            if scan_triggered:
                conn.execute(
                    "UPDATE ports SET honeypot = 1, last_triggered = ? WHERE port = ?",
                    (time.strftime("%Y-%m-%d %H:%M:%S"), port),
                )

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

        # Failed attempt handling - a sliding window rather than an
        # all-time counter, so attempts from long ago don't keep counting
        # against a user forever.
        key = f"{username}:{ip_address}"
        now = time.time()
        window_start = now - config.LOGIN_ATTEMPT_WINDOW_SECONDS

        row = conn.execute(
            "SELECT count, first_attempt_at FROM login_attempts WHERE key = ?", (key,)
        ).fetchone()

        if row and row["first_attempt_at"] >= window_start:
            count = row["count"] + 1
            first_attempt_at = row["first_attempt_at"]
        else:
            # First-ever attempt, or the previous streak fell outside the
            # window - start a fresh streak.
            count = 1
            first_attempt_at = now

        conn.execute(
            "INSERT INTO login_attempts (key, count, first_attempt_at, last_attempt_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET count = excluded.count, "
            "first_attempt_at = excluded.first_attempt_at, "
            "last_attempt_at = excluded.last_attempt_at",
            (key, count, first_attempt_at, now),
        )

        _, triggered = record_suspicious_event(ip_address, "failed_login", conn=conn)

        if triggered:
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
                (username, ip_address, port, count, f"{count} failed login attempts within {config.LOGIN_ATTEMPT_WINDOW_SECONDS}s", timestamp),
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

# ----------------------
# Audit log
# ----------------------
# A persisted, queryable history of admin actions - bans, unbans, port
# changes, and admin logins - separate from the general log file so it can
# be queried/displayed (e.g. in the admin panel) rather than just grepped.
def log_audit(actor_ip, action, details=""):
    """Record an admin action in the audit trail."""
    with db.get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (timestamp, actor_ip, action, details) VALUES (?, ?, ?, ?)",
            (time.strftime("%Y-%m-%d %H:%M:%S"), actor_ip, action, details),
        )

def get_audit_log():
    """Return the full audit trail, most recent first."""
    with db.get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp, actor_ip, action, details FROM audit_log ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]

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
