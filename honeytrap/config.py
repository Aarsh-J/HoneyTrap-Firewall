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
# Logging
# ----------------------
LOG_DIR = BASE_DIR / "logs"
LOG_LEVEL = os.environ.get("HONEYTRAP_LOG_LEVEL", "INFO")

# Ensure runtime directories exist regardless of the current working directory
DATA_DIR.mkdir(exist_ok=True)
CERT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
