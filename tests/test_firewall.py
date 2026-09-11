import time

import pytest

from honeytrap import config, db, firewall


@pytest.fixture
def fw(tmp_path, monkeypatch):
    """Point the SQLite database at a temp file and reseed it, so tests
    never touch the real data/ directory and don't leak state between
    tests."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    firewall.initialize_files()
    return firewall


def _set_session_last_activity(username, value):
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE sessions SET last_activity_time = ? WHERE username = ?",
            (value, username),
        )


# ----------------------
# Password hashing
# ----------------------

def test_hash_and_verify_password_roundtrip(fw):
    hash_hex, salt_hex = fw.hash_password("correct-horse")
    assert fw.verify_password("correct-horse", salt_hex, hash_hex) is True


def test_verify_password_rejects_wrong_password(fw):
    hash_hex, salt_hex = fw.hash_password("correct-horse")
    assert fw.verify_password("wrong-password", salt_hex, hash_hex) is False


def test_hash_password_uses_random_salt_by_default(fw):
    hash1, salt1 = fw.hash_password("same-password")
    hash2, salt2 = fw.hash_password("same-password")
    assert salt1 != salt2
    assert hash1 != hash2


# ----------------------
# create_user
# ----------------------

def test_create_user_success(fw):
    ok, message = fw.create_user("alice", "hunter2")
    assert ok is True

    status, _ = fw.check_login("alice", "hunter2", "127.0.0.1", 8001)
    assert status == "valid"


def test_create_user_duplicate_rejected(fw):
    fw.create_user("alice", "hunter2")
    ok, message = fw.create_user("alice", "different-password")
    assert ok is False
    assert "already exists" in message.lower()


# ----------------------
# check_login
# ----------------------

def test_check_login_admin_credentials(fw, monkeypatch):
    monkeypatch.setattr(fw, "ADMIN_USERNAME", "admin")
    admin_hash, admin_salt = fw.hash_password("admin-secret")
    monkeypatch.setattr(fw, "ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setattr(fw, "ADMIN_PASSWORD_SALT", admin_salt)

    status, error = fw.check_login("admin", "admin-secret", "127.0.0.1", 8001)
    assert status == "admin"
    assert error is None


def test_check_login_valid_user(fw):
    # initialize_files() seeds a default "user"/"password" account and port 8001 is active
    status, error = fw.check_login("user", "password", "127.0.0.1", 8001)
    assert status == "valid"
    assert error is None

    active = fw.get_active_users()
    assert any(u["username"] == "user" for u in active)


def test_check_login_wrong_password_first_attempt_is_error(fw):
    status, error = fw.check_login("user", "wrong-password", "127.0.0.1", 8001)
    assert status == "error"


def test_check_login_two_failed_attempts_triggers_honeypot(fw):
    fw.check_login("user", "wrong-password", "127.0.0.1", 8001)
    status, error = fw.check_login("user", "wrong-password", "127.0.0.1", 8001)

    assert status == "fake"

    ports = fw.get_ports()
    port_8001 = next(p for p in ports if p["port"] == 8001)
    assert port_8001["honeypot"] is True

    potential_attackers = fw.get_potential_attackers()
    assert any(a["username"] == "user" and a["ip"] == "127.0.0.1" for a in potential_attackers)


def test_check_login_banned_ip_returns_fake(fw):
    fw.ban_ip("6.6.6.6")
    status, error = fw.check_login("user", "password", "6.6.6.6", 8001)
    assert status == "fake"
    assert "banned" in error.lower()


def test_check_login_honeypot_port_returns_fake_even_with_correct_credentials(fw):
    fw.toggle_port_status(8001, honeypot=True)
    status, error = fw.check_login("user", "password", "127.0.0.1", 8001)
    assert status == "fake"


# ----------------------
# check_inactivity
# ----------------------

def test_check_inactivity_flags_and_removes_stale_session(fw, monkeypatch):
    monkeypatch.setattr(fw, "INACTIVITY_LIMIT", 300)

    fw.check_login("user", "password", "127.0.0.1", 8001)
    _set_session_last_activity("user", time.time() - 301)  # push it just past the limit

    fw.check_inactivity()

    active_after = fw.get_active_users()
    assert not any(u["username"] == "user" for u in active_after)

    potential_attackers = fw.get_potential_attackers()
    assert any(a["username"] == "user" and "inactive" in a["reason"].lower() for a in potential_attackers)

    ports = fw.get_ports()
    port_8001 = next(p for p in ports if p["port"] == 8001)
    assert port_8001["honeypot"] is True


def test_check_inactivity_leaves_active_session_alone(fw):
    fw.check_login("user", "password", "127.0.0.1", 8001)
    fw.check_inactivity()

    active_after = fw.get_active_users()
    assert any(u["username"] == "user" for u in active_after)


# ----------------------
# IP ban management
# ----------------------

def test_ban_and_unban_ip(fw):
    assert fw.get_banned_ips() == []

    fw.ban_ip("1.2.3.4")
    assert "1.2.3.4" in fw.get_banned_ips()

    fw.unban_ip("1.2.3.4")
    assert "1.2.3.4" not in fw.get_banned_ips()


def test_ban_ip_is_idempotent(fw):
    fw.ban_ip("1.2.3.4")
    fw.ban_ip("1.2.3.4")
    assert fw.get_banned_ips().count("1.2.3.4") == 1


# ----------------------
# Port management
# ----------------------

def test_toggle_port_status_updates_status_and_honeypot(fw):
    assert fw.toggle_port_status(8004, status="active", honeypot=True) is True

    ports = fw.get_ports()
    port_8004 = next(p for p in ports if p["port"] == 8004)
    assert port_8004["status"] == "active"
    assert port_8004["honeypot"] is True


def test_toggle_port_status_unknown_port_returns_false(fw):
    assert fw.toggle_port_status(9999, status="active") is False


# ----------------------
# Risk scoring (record_suspicious_event)
# ----------------------

def test_record_suspicious_event_accumulates_score(fw, monkeypatch):
    monkeypatch.setattr(config, "FAILED_LOGIN_POINTS", 3)
    monkeypatch.setattr(config, "HONEYPOT_TRIGGER_THRESHOLD", 100)  # keep it from triggering here

    fw.record_suspicious_event("9.9.9.9", "failed_login")
    fw.record_suspicious_event("9.9.9.9", "failed_login")

    assert fw.get_ip_risk_score("9.9.9.9") == 6


def test_record_suspicious_event_triggers_only_on_the_crossing_call(fw, monkeypatch):
    monkeypatch.setattr(config, "FAILED_LOGIN_POINTS", 5)
    monkeypatch.setattr(config, "HONEYPOT_TRIGGER_THRESHOLD", 10)

    _, triggered1 = fw.record_suspicious_event("9.9.9.9", "failed_login")  # score 5
    assert triggered1 is False

    _, triggered2 = fw.record_suspicious_event("9.9.9.9", "failed_login")  # score 10 - crosses
    assert triggered2 is True

    _, triggered3 = fw.record_suspicious_event("9.9.9.9", "failed_login")  # score 15 - already over
    assert triggered3 is False


def test_record_suspicious_event_unknown_type_scores_zero(fw):
    new_score, triggered = fw.record_suspicious_event("9.9.9.9", "something_undefined")
    assert new_score == 0
    assert triggered is False


# ----------------------
# Port-scan detection (record_port_touch)
# ----------------------

def test_record_port_touch_ignores_repeated_same_port(fw):
    for _ in range(5):
        triggered = fw.record_port_touch("9.9.9.9", 8001)
        assert triggered is False


def test_record_port_touch_detects_distinct_port_scan(fw, monkeypatch):
    monkeypatch.setattr(config, "PORT_SCAN_DISTINCT_PORTS", 3)
    monkeypatch.setattr(config, "PORT_SCAN_POINTS", 10)
    monkeypatch.setattr(config, "HONEYPOT_TRIGGER_THRESHOLD", 10)

    assert fw.record_port_touch("9.9.9.9", 8001) is False
    assert fw.record_port_touch("9.9.9.9", 8002) is False
    assert fw.record_port_touch("9.9.9.9", 8003) is True  # 3rd distinct port crosses threshold


def test_check_login_port_scan_flags_the_current_port(fw, monkeypatch):
    monkeypatch.setattr(config, "PORT_SCAN_DISTINCT_PORTS", 3)
    monkeypatch.setattr(config, "PORT_SCAN_POINTS", 10)
    monkeypatch.setattr(config, "HONEYPOT_TRIGGER_THRESHOLD", 10)

    fw.check_login("user", "wrong-password", "9.9.9.9", 8001)
    fw.check_login("user", "wrong-password", "9.9.9.9", 8002)
    status, _ = fw.check_login("user", "wrong-password", "9.9.9.9", 8003)

    assert status == "fake"
    ports = fw.get_ports()
    port_8003 = next(p for p in ports if p["port"] == 8003)
    assert port_8003["honeypot"] is True


def test_login_attempts_streak_resets_after_window_expires(fw, monkeypatch):
    """The failed-attempt *count* used for the potential_attackers record
    should restart, not accumulate, once the previous streak has aged out
    of LOGIN_ATTEMPT_WINDOW_SECONDS - independent of the separately-windowed
    risk score checked in the record_suspicious_event tests above."""
    monkeypatch.setattr(config, "LOGIN_ATTEMPT_WINDOW_SECONDS", 60)

    fw.check_login("user", "wrong-password", "127.0.0.1", 8001)

    # Simulate the first attempt having happened well outside the window
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE login_attempts SET first_attempt_at = ?, last_attempt_at = ? WHERE key = ?",
            (time.time() - 120, time.time() - 120, "user:127.0.0.1"),
        )

    fw.check_login("user", "wrong-password", "127.0.0.1", 8001)

    with db.get_connection() as conn:
        row = conn.execute(
            "SELECT count FROM login_attempts WHERE key = ?", ("user:127.0.0.1",)
        ).fetchone()

    assert row["count"] == 1  # streak restarted rather than becoming 2


# ----------------------
# Audit log
# ----------------------

def test_log_audit_records_an_entry(fw):
    fw.log_audit("10.0.0.1", "ban_ip", "Banned 1.2.3.4")

    entries = fw.get_audit_log()
    assert len(entries) == 1
    assert entries[0]["actor_ip"] == "10.0.0.1"
    assert entries[0]["action"] == "ban_ip"
    assert entries[0]["details"] == "Banned 1.2.3.4"


def test_get_audit_log_orders_most_recent_first(fw):
    fw.log_audit("10.0.0.1", "ban_ip", "first")
    fw.log_audit("10.0.0.1", "unban_ip", "second")

    entries = fw.get_audit_log()
    assert [e["action"] for e in entries] == ["unban_ip", "ban_ip"]


def test_get_audit_log_empty_by_default(fw):
    assert fw.get_audit_log() == []
