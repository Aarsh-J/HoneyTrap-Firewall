# ===============================
# Logging Configuration
# ===============================
import logging
import logging.handlers

from . import config


def configure_logging():
    """Configure root logging once, from an entry point, before anything else runs."""
    log_file = config.LOG_DIR / "honeytrap.log"

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    console_handler = logging.StreamHandler()

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[file_handler, console_handler],
    )
