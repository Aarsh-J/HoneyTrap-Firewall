# ===============================
# SQLite Storage Layer
# ===============================
# Replaces the old flat-JSON-file "database". A fresh connection is opened
# per call (mirrors the old open/close-per-call load_json/save_json pattern)
# rather than sharing one connection across threads, since firewall.py's
# functions will eventually be invoked from a thread pool (see the async
# server rewrite) and sqlite3 connections aren't safe to share across
# threads without extra care.
import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    salt TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    username TEXT PRIMARY KEY,
    login_time REAL NOT NULL,
    last_activity_time REAL NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER
);

CREATE TABLE IF NOT EXISTS ports (
    port INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    honeypot INTEGER NOT NULL DEFAULT 0,
    last_triggered TEXT
);

CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS attackers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip TEXT,
    attempted_port INTEGER,
    reason TEXT,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS potential_attackers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    attempted_port INTEGER,
    attempts INTEGER,
    reason TEXT,
    timestamp TEXT,
    UNIQUE(username, ip)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    first_attempt_at REAL,
    last_attempt_at REAL
);

CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    event_type TEXT NOT NULL,
    points INTEGER NOT NULL,
    occurred_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_events_ip_time ON risk_events(ip, occurred_at);

CREATE TABLE IF NOT EXISTS port_touches (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    touched_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_port_touches_ip_time ON port_touches(ip, touched_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor_ip TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT
);
"""


@contextmanager
def get_connection():
    """Yield a connection that commits on a clean exit and rolls back on error."""
    conn = sqlite3.connect(str(config.DB_PATH), timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if they don't already exist. Safe to call repeatedly."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
        conn.execute("PRAGMA journal_mode=WAL")
