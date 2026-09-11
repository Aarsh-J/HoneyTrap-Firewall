# ===============================
# Logging Configuration
# ===============================
import json
import logging
import logging.handlers

from . import config


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per line - what a SIEM/log-aggregation pipeline
    would actually want to ingest, as opposed to the human-readable text
    format used on the console. Any fields passed via `extra=...` on a log
    call are included under "extra" alongside the standard ones."""

    # Standard attributes every LogRecord carries (plus "message"/"asctime",
    # which Formatter.format()/formatTime() add) - anything else on the
    # record is something the caller passed via `extra=...`.
    _RESERVED = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "asctime", "taskName",
    }

    def format(self, record):
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in self._RESERVED
        }
        if extras:
            payload["extra"] = extras

        return json.dumps(payload)


def configure_logging():
    """Configure root logging once, from an entry point, before anything else runs."""
    log_file = config.LOG_DIR / "honeytrap.log"

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(JsonFormatter())

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
        handlers=[file_handler, console_handler],
    )
