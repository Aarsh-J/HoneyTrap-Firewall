import json
import logging
import sys

from honeytrap.logging_setup import JsonFormatter


def _make_record(**extra):
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="something happened",
        args=(),
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def test_json_formatter_produces_valid_parseable_json():
    output = JsonFormatter().format(_make_record())

    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test.logger"
    assert parsed["message"] == "something happened"
    assert "timestamp" in parsed


def test_json_formatter_includes_extra_fields():
    record = _make_record(ip_address="1.2.3.4", action="ban_ip")
    parsed = json.loads(JsonFormatter().format(record))

    assert parsed["extra"] == {"ip_address": "1.2.3.4", "action": "ban_ip"}


def test_json_formatter_omits_extra_key_when_no_extras():
    parsed = json.loads(JsonFormatter().format(_make_record()))
    assert "extra" not in parsed


def test_json_formatter_includes_exception_info():
    try:
        raise ValueError("boom")
    except ValueError:
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test.logger", level=logging.ERROR, pathname=__file__, lineno=1,
        msg="failed", args=(), exc_info=exc_info,
    )
    parsed = json.loads(JsonFormatter().format(record))

    assert "ValueError" in parsed["exc_info"]
    assert "boom" in parsed["exc_info"]


def test_json_formatter_handles_message_with_percent_args():
    record = logging.LogRecord(
        name="test.logger", level=logging.WARNING, pathname=__file__, lineno=1,
        msg="port %s flagged for %s", args=(8001, "scan"), exc_info=None,
    )
    parsed = json.loads(JsonFormatter().format(record))
    assert parsed["message"] == "port 8001 flagged for scan"
