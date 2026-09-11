# Feature Roadmap: Tests, SQLite, Smarter Honeypot, Audit Log, Structured Logging, Async Rewrite

## Context

The project (TLS + package restructure already done and verified in a prior
session) is now feature-complete for the interview. The plan is to keep
building it out afterward into a more complete portfolio piece:

- **Quick**: unit tests, audit log of admin actions, type hints
- **Medium** (excluding CA-signed certs): SQLite migration, structured JSON
  logging, and port stealth — scoped down to a documentation fix, since
  genuine packet-level stealth needs raw-socket/firewall access this Windows
  dev machine can't reliably guarantee
- **Bigger**: async I/O rewrite — scoped to **both server and client**, with
  the Tkinter GUI files left untouched (see Phase 6 design)

Because several of these features build on each other, this plan sequences
them to minimize rework: tests first (a safety net before anything moves),
then the storage swap (SQLite) that the new features persist into, then the
features themselves, then the big concurrency rewrite last (once everything
else is stable, so it only has to be ported to asyncio once), then a final
type-hint/polish pass once the shape of the code has stopped changing.

## Phase 1 — Safety net: unit tests + port-stealth doc fix

**Goal:** lock down current behavior before touching storage or concurrency.

- Add `pytest` to `requirements.txt` (or a new `requirements-dev.txt`).
- New `tests/test_firewall.py` covering `honeytrap/firewall.py`'s public API
  only (not its internals) so the tests keep working after Phase 2 swaps
  JSON for SQLite:
  - `create_user` (success + duplicate-username rejection)
  - `check_login`: admin path, valid user, wrong password, honeypot-active
    port, banned IP, the 2-failed-attempts-triggers-honeypot path
  - `check_inactivity` (session past `INACTIVITY_LIMIT` gets flagged + removed)
  - `hash_password`/`verify_password` roundtrip + wrong-password rejection
  - `ban_ip`/`unban_ip`/`get_banned_ips`
  - `toggle_port_status`
  - A pytest fixture that points `config.DATA_DIR` (and therefore
    `firewall.USER_DB` etc.) at a `tmp_path` before each test via
    `monkeypatch`, so tests never touch the real `data/` directory.
- Fix the port-stealth claim: update `README.md`'s "Port Stealth" section and
  `firewall_interview.md` to say inactive ports simply aren't listened on
  (today's actual behavior — the OS TCP stack replies with a normal RST,
  which nmap reports as "closed"), and drop the "invisible to nmap" /
  "filtered" framing, since true invisibility needs dropping SYN packets at
  the firewall/OS level, which is out of scope here.

**Verify:** `pytest tests/` passes; re-read the two doc files to confirm the
port-stealth claim now matches reality.

## Phase 2 — SQLite migration

**Goal:** replace the JSON-file "database" with SQLite, without changing
`firewall.py`'s public function signatures or return shapes, so nothing
calling it (`server.py`, `adapter.py`, the Phase 1 tests) needs to change.

- New `honeytrap/db.py`: `get_connection()` opens a fresh
  `sqlite3.connect(config.DB_PATH, timeout=5)` per call (mirrors the
  existing open/close-per-call pattern of `load_json`/`save_json`, so
  concurrent access from multiple threads later — Phase 6's executor calls —
  doesn't require sharing a connection across threads); `init_db()` creates
  tables if missing and sets `PRAGMA journal_mode=WAL` for better concurrent
  read/write behavior.
- Schema: `users`, `sessions`, `ports`, `banned_ips`, `attackers`,
  `potential_attackers`, `login_attempts` (replaces the in-memory
  `LOGIN_ATTEMPTS` dict so attempt counts survive a server restart — also
  needed as the foundation for Phase 3's sliding-window logic).
- Add `config.DB_PATH = DATA_DIR / "honeytrap.db"`; call `db.init_db()` once
  at server startup (`honeytrap/server.py main()`).
- Rewrite each function in `honeytrap/firewall.py` (`create_user`,
  `check_login`, `check_inactivity`, `ban_ip`, `unban_ip`, `get_*`,
  `toggle_port_status`, etc.) to run SQL via `db.get_connection()` instead of
  `load_json`/`save_json`, keeping identical inputs/outputs (e.g.
  `get_ports()` still returns a list of dicts shaped like today's JSON rows).
- Keep `data/*.json` file removal/migration simple: since this is a personal
  dev project with no real production data, just delete the old JSON files
  after confirming the new DB path works rather than writing a migration
  script.

**Verify:** re-run the full Phase 1 test suite with fixtures updated to
point at a temp SQLite path instead of a temp JSON directory (test bodies/
assertions should barely change — that's the point of testing through the
public API); manually run `run_server.py` + `run_client.py`, log in, check
honeypot triggering and ban/unban still work, confirm `data/honeytrap.db` is
created and populated.

## Phase 3 — Rate-limited / scored honeypot triggers

**Goal:** replace the flat "2 failed logins ever" rule with something closer
to real intrusion detection.

- Config additions (`honeytrap/config.py`): `FAILED_LOGIN_POINTS`,
  `MALFORMED_MESSAGE_POINTS`, `PORT_SCAN_POINTS`,
  `HONEYPOT_TRIGGER_THRESHOLD`, `LOGIN_ATTEMPT_WINDOW_SECONDS` (sliding
  window, e.g. 60s instead of "all-time").
- New table `ip_risk_scores(ip, score, updated_at)` (Phase 2's schema).
- New `firewall.record_suspicious_event(ip, event_type, port=None)`:
  increments the IP's score, and if it crosses
  `HONEYPOT_TRIGGER_THRESHOLD`, flags the relevant port's honeypot the same
  way `check_login` does today.
- Wire it in from three places:
  - `check_login`'s failure path, using the `login_attempts` table's
    timestamps to only count attempts inside the sliding window (replacing
    the hard "if attempts >= 2").
  - `honeytrap/server_base.py`'s `json.JSONDecodeError` branch (malformed
    message from a client — a real client/GUI would never send garbage).
  - A new lightweight port-scan detector: track `(ip, port, timestamp)` on
    each accepted connection, and flag an IP that touches N distinct ports
    within a short window.

**Verify:** unit tests for `record_suspicious_event` (score accumulates,
resets/expires outside the window, crosses threshold correctly); a manual
test hitting 3 distinct ports quickly from one client to confirm the scan
detector fires.

## Phase 4 — Audit log of admin actions

**Goal:** a persisted, queryable history of admin activity — currently bans/
unbans/port changes only go to the log file, not a structured record.

- New table `audit_log(id, timestamp, actor_ip, action, details)`.
- New `firewall.log_audit(actor_ip, action, details="")` and
  `firewall.get_audit_log()`.
- Call `log_audit` from `server.py`'s `handle_ban_ip`, `handle_unban_ip`,
  `handle_update_port`, and from `handle_login` specifically on the admin
  path (an "admin logged in from X" entry).
- New `GET_AUDIT_LOG` message type (`protocol.py`) + client method + admin
  panel tab (`honeytrap/gui/admin_panel.py`) reusing the existing
  `ttk.Treeview` pattern already used for the attackers/ports/users tabs, so
  the audit trail is actually visible, not just backend data.

**Verify:** unit tests confirming audit rows get created on ban/unban/admin
login; manual check that the new admin panel tab populates and refreshes.

## Phase 5 — Structured JSON logging

**Goal:** logs a SIEM/log-aggregation pipeline could actually ingest.

- `honeytrap/logging_setup.py`: add a `JsonFormatter` (subclasses
  `logging.Formatter`) emitting one JSON object per line — timestamp, level,
  logger name, message, and any `extra` fields passed in.
- Keep the **console** handler human-readable (nice for watching
  `run_server.py` live) and make the **file** handler JSON — a common real
  pattern worth explaining as-is in an interview. Add a
  `HONEYTRAP_LOG_FORMAT` config knob only if useful; otherwise hardcode this
  split.

**Verify:** unit test that `JsonFormatter.format()` produces valid,
parseable JSON with the expected keys; manually tail `logs/honeytrap.log`
and confirm each line parses as JSON.

## Phase 6 — Async I/O rewrite (server AND client; GUI files untouched)

**Goal:** replace thread-per-connection with `asyncio` on both ends. This is
the highest-risk phase, so it happens last, once storage (Phase 2) and
features (3-5) are stable — the executor-wrapping pattern below only needs
to be applied once, to the final set of blocking calls.

**Server** (`honeytrap/server_base.py`, `honeytrap/server.py`):
- Replace manual `socket`/`select`/thread-per-connection with
  `asyncio.start_server(handler, host, port, ssl=self.ssl_context)` for both
  control and data listeners — asyncio's streams handle the TLS handshake
  and record buffering natively, which also **eliminates the class of bug**
  fixed earlier this session (the `select()` + TLS `NewSessionTicket` hang
  that needed a manual `pending()`/timeout workaround around raw sockets).
- Per-connection handling becomes `async def handle_connection(reader,
  writer, channel_type)` using `protocol.recv_framed_async`/
  `send_framed_async` (new async counterparts added to `protocol.py`
  alongside the existing sync ones, using `reader.readexactly()` /
  `writer.write()` + `await writer.drain()`).
- Message handlers (`handle_login`, `handle_ban_ip`, etc.) **stay synchronous**
  — they still call the (blocking) SQLite-backed `firewall.*` functions —
  but are invoked via `await loop.run_in_executor(None, handler, message,
  connection_info)` so a slow DB call can't stall the event loop. This keeps
  Phase 2-4's handler code completely unchanged.
- Background loops (inactivity checker, Phase 3's port-scan window cleanup)
  become `asyncio.create_task(...)` instead of daemon threads, also wrapping
  their blocking `firewall.*` calls in `run_in_executor`.
- **Windows gotcha to flag explicitly**: `loop.add_signal_handler()` (the
  normal asyncio graceful-shutdown pattern) isn't supported on Windows'
  default proactor event loop. Keep relying on catching `KeyboardInterrupt`
  around `asyncio.run(main_async())`, same as today.

**Client** (`honeytrap/client.py`) — async core, synchronous facade so
`adapter.py` and every GUI file need **zero changes**:
- `connect()` starts a dedicated `asyncio` event loop on a background daemon
  thread (`asyncio.new_event_loop()` + `loop.run_forever()` in a thread),
  then uses `asyncio.run_coroutine_threadsafe(self._connect_async(),
  self._loop).result(timeout=...)` to actually open both connections via
  `asyncio.open_connection(..., ssl=self.ssl_context)`.
- `_listen_async()` (one per channel, scheduled as a task on that background
  loop) replaces `listen_for_messages` — reads with `recv_framed_async` and
  calls the existing (unchanged) `process_message()`.
- `response_event` becomes an `asyncio.Event()` instead of
  `threading.Event()` — safe because everything that touches it
  (`_send_request_async`, `_listen_async`) runs on the same background
  loop/thread; only the public methods cross the thread boundary.
- Public methods (`login`, `get_ports`, `ban_ip`, `send_request`, etc.) keep
  their exact current synchronous signatures and return values — each one
  internally does `asyncio.run_coroutine_threadsafe(self._x_async(...),
  self._loop).result(timeout=...)`. This is what keeps `adapter.py` and the
  Tkinter GUI (`app.py`, `admin_panel.py`, `user_portal.py`) untouched: from
  their point of view the client still just returns a value synchronously.
- `start_keep_alive`'s background thread stays a plain
  `threading.Thread` calling the (now-bridging) sync `update_activity()` —
  no change needed there.

**Verify:**
- Add `pytest-asyncio`; write async tests spinning up the new server on a
  random free port and hitting it with a small async test client.
- Critically, also re-run the **existing** `full_smoke.py`-style manual
  script from this session (login, get_ports, ban/unban, honeypot trigger,
  logout) against the rewritten server/client to prove the wire-level
  behavior didn't change even though the internals were fully replaced.
- Manually launch `run_client.py` (the real Tkinter app) and confirm login,
  signup, admin panel, and the honeypot fake-portal flow all still work
  exactly as before — this is the real test that the sync facade holds up.

## Phase 7 — Type hints + final polish

**Goal:** a consistency pass now that the code's shape has stopped changing.

- Add type hints to public functions/methods across every `honeytrap/*.py`
  module (skip the Tkinter GUI files if hinting them is low-value/awkward —
  judgment call at the time).
- Add `mypy` (dev dependency) with a practical, not maximally-strict config;
  fix what it flags.
- Final full regression pass: `pytest tests/` (including the Phase 6 async
  tests), then a full manual walkthrough — server start, client login
  (admin + regular user), honeypot trigger, ban/unban, audit log tab, and a
  `logs/honeytrap.log` spot-check for valid JSON lines.

## Notes on ordering and commits

Each phase above ends with its own verify step. **Do not commit** — after
finishing and verifying a phase, `git add` the relevant files (stage only)
and hand the user a suggested commit message; the user will test the system
themselves and commit manually. Don't start Phase 3 until Phase 2's SQLite
migration is confirmed working end-to-end, since Phase 3 writes to a table
Phase 2 creates, and don't start Phase 6 until Phases 2-5 are stable, since
Phase 6 is a one-time rewrite of however the code looks at that point.
