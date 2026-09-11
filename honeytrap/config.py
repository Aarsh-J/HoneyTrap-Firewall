# ===============================
# Centralized Configuration
# ===============================
# Single source of truth for ports, hosts, file paths, and secrets. Every
# other module imports from here instead of hardcoding its own constants -
# e.g. a multi-PC setup now means editing .env, not editing adapter.py.
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file(path=None):
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Only sets variables that aren't already set, so real environment
    variables always take precedence over the file.
    """
    path = path or (BASE_DIR / ".env")
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())
    except FileNotFoundError:
        pass


_load_env_file()

# ----------------------
# Network
# ----------------------
SERVER_HOST = os.environ.get("HONEYTRAP_SERVER_HOST", "localhost")
BIND_HOST = os.environ.get("HONEYTRAP_BIND_HOST", "0.0.0.0")
CONTROL_PORT = int(os.environ.get("HONEYTRAP_CONTROL_PORT", 5000))
DATA_PORT = int(os.environ.get("HONEYTRAP_DATA_PORT", 5001))

# ----------------------
# TLS
# ----------------------
CERT_DIR = BASE_DIR / "certs"
CERT_PATH = str(CERT_DIR / "server.crt")
KEY_PATH = str(CERT_DIR / "server.key")

# ----------------------
# Storage (SQLite database)
# ----------------------
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "honeytrap.db"

# ----------------------
# Auth / firewall rules
# ----------------------
ADMIN_USERNAME = os.environ.get("HONEYTRAP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_RAW = os.environ.get("HONEYTRAP_ADMIN_PASSWORD", "admin123")
HASH_ITERATIONS = 100_000
INACTIVITY_LIMIT = 300  # 5 minutes

# ----------------------
# Honeypot trigger scoring
# ----------------------
# Different suspicious signals add points to a per-IP risk score; crossing
# the threshold triggers the honeypot. Defaults keep today's "2 failed
# logins" behavior (2 x FAILED_LOGIN_POINTS == HONEYPOT_TRIGGER_THRESHOLD)
# while allowing other signals to combine toward the same threshold.
FAILED_LOGIN_POINTS = int(os.environ.get("HONEYTRAP_FAILED_LOGIN_POINTS", 3))
MALFORMED_MESSAGE_POINTS = int(os.environ.get("HONEYTRAP_MALFORMED_MESSAGE_POINTS", 5))
PORT_SCAN_POINTS = int(os.environ.get("HONEYTRAP_PORT_SCAN_POINTS", 10))
HONEYPOT_TRIGGER_THRESHOLD = int(os.environ.get("HONEYTRAP_TRIGGER_THRESHOLD", 6))

# A sliding window (not "all-time") for counting repeated failed logins.
LOGIN_ATTEMPT_WINDOW_SECONDS = int(os.environ.get("HONEYTRAP_LOGIN_ATTEMPT_WINDOW_SECONDS", 60))

# The risk score itself is also windowed (a sum of recent events, not an
# ever-growing counter) - otherwise one stale event from long ago would
# count against an IP forever. Generous enough to comfortably span the
# login-attempt and port-scan windows above.
RISK_SCORE_WINDOW_SECONDS = int(os.environ.get("HONEYTRAP_RISK_SCORE_WINDOW_SECONDS", 120))

# Port-scan detection: an IP touching this many distinct (virtual/simulated)
# ports within this window during login attempts looks like scanning.
PORT_SCAN_WINDOW_SECONDS = int(os.environ.get("HONEYTRAP_PORT_SCAN_WINDOW_SECONDS", 30))
PORT_SCAN_DISTINCT_PORTS = int(os.environ.get("HONEYTRAP_PORT_SCAN_DISTINCT_PORTS", 3))

# ----------------------
# Logging
# ----------------------
LOG_DIR = BASE_DIR / "logs"
LOG_LEVEL = os.environ.get("HONEYTRAP_LOG_LEVEL", "INFO")

# Ensure runtime directories exist regardless of the current working directory
DATA_DIR.mkdir(exist_ok=True)
CERT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
