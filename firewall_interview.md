# HoneyTrap Firewall — Interview Script

## 1. The Pitch (say this first, 30-45 sec)

"I built a firewall system with a twist — instead of just blocking suspicious
users, it tricks them. If someone fails login a couple times, or connects and
sits idle too long, the system quietly redirects them to a fake, decoy
interface instead of kicking them out. They think they're in; meanwhile the
admin can see who's attacking, from what IP, and ban them. It's client-server,
built with raw Python sockets — no web framework — with a Tkinter GUI on top
for the admin and user side, and the connection between client and server is
encrypted with TLS."

## 2. Why This, Not a Plain Firewall (if asked)

"A plain firewall or a port scanner just blocks or alerts — that's reactive.
I wanted to try active defense: instead of only detecting an attack, the
system studies the attacker in real time while protecting the real service.
A firewall tells you no. A honeypot lets the attacker think 'yes' while you
watch."

## 3. Architecture (HLD) — walk through this if asked "how is it structured"

Three layers, describe top to bottom:

1. **Presentation layer** — Tkinter GUI: admin panel, user portal, fake portal
   (the honeypot decoy screen).
2. **Communication layer** — custom socket protocol over two TLS-encrypted
   TCP channels: a control port (5000) for login/admin commands, and a data
   port (5001). Messages are JSON, framed with a 4-byte length prefix.
3. **Logic + storage layer** — `firewall.py` decides valid/fake/admin/attacker
   and manages honeypot + ban state; JSON files (`users.json`, `sessions.json`,
   `ports.json`, `banned_ips.json`) act as a lightweight database.

One-liner: "It's a 3-tier design — GUI on top, a socket-based server in the
middle doing auth and honeypot decisions, and JSON files as storage underneath."

**Repo layout** (say this only if they ask to see the code structure):
```
run_server.py / run_client.py   - entry points
honeytrap/                       - the actual package
    config.py                      - all settings/env vars in one place
    logging_setup.py                - logging configuration
    protocol.py, tls.py, server_base.py, server.py, client.py, firewall.py, adapter.py
    gui/                              - app.py, admin_panel.py, user_portal.py
data/ certs/ logs/                - runtime files, all gitignored
```

## 4. Core CN Concepts to Mention (pick 3-4, don't dump all)

- **Client-server over sockets** — server listens, clients connect, raw TCP.
- **Two separate channels** — control vs data, kept apart on purpose.
- **Length-prefixed message framing** — TCP is a byte stream, not a message
  stream, so every message is sent as `[4-byte length][JSON payload]` so the
  receiver knows exactly where one message ends and the next begins.
- **TLS encryption** — both channels are wrapped in `ssl.SSLContext` with a
  self-signed certificate, so traffic (including credentials) isn't sent in
  plain text over the network.
- **Passwords hashed + salted** (PBKDF2), never stored in plain text.
- **Thread-per-connection** — each client connection is handled on its own
  thread so multiple clients can connect at once.

## 5. How the Honeypot Gets Triggered

Two rules, both in `firewall.py`:

1. **Failed logins** — 2 failed attempts (same username+IP) → that port is
   flagged `honeypot = True` permanently until an admin turns it off.
2. **Inactivity** — a logged-in session idle for 5+ minutes → same port gets
   flagged.

Once a port is flagged, **everyone** connecting to it — real or fake — gets
redirected to the decoy interface.

## 6. Pseudocode — Raw Socket Communication (describe, don't need to show code)

**Server:**
```
create TCP socket, bind to (host, port), listen

loop forever:
    accept new client connection
    complete TLS handshake on the accepted connection
    start a new thread for this client

# inside each client's thread:
loop while connected:
    read 4 bytes -> length of incoming message
    read that many bytes -> the JSON message
    parse it, find the "command"
    run matching logic (firewall.py rules)
    send response back the same way: [4-byte length][JSON]
```

**Client:**
```
create TCP socket, connect to (server_host, server_port)
wrap the socket in TLS

to send a request:
    build JSON message (command + params)
    send [4-byte length][JSON]
    wait for response the same way (read length, then payload)
```

**Why length-prefixing, if asked "why not just recv() directly":**
"TCP is just a stream of bytes — it doesn't preserve message boundaries. If I
just call recv() and hope I got one full JSON message, I might get half of
it, or two messages stuck together. Prefixing every message with its length
tells the receiver exactly how many bytes to wait for before parsing."

**Why TLS, if asked "how is this secured":**
"The socket API calls stay the same — send/recv — but TLS wraps the socket so
everything going over the wire is encrypted. There's a handshake first where
the server presents a certificate and both sides agree on a shared key; after
that, all the JSON messages (including passwords) are encrypted in transit."

## 7. Where the Code Actually Lives (for your own reference, not to recite)

- Message framing: `honeytrap/protocol.py` — `send_framed()`, `recv_framed()`,
  `recv_exact()`
- TLS cert generation/contexts: `honeytrap/tls.py` — `generate_self_signed_cert()`,
  `get_server_ssl_context()`, `get_client_ssl_context()`
- Server socket setup/accept/threading: `honeytrap/server_base.py` —
  `setup_sockets()`, `accept_connections()`, `handle_client_messages()`
- Client connect/send/receive: `honeytrap/client.py` — `connect()`,
  `listen_for_messages()`, `send_and_wait()`
- Honeypot/firewall logic: `honeytrap/firewall.py` — `check_login()`,
  `check_inactivity()`, `hash_password()`
- Centralized settings: `honeytrap/config.py`

---

# Potential Questions & Answers

**Q: Why sockets instead of a web framework (Flask/Django)?**
A: "I wanted to understand networking at a lower level — actually opening
connections and sending/receiving raw data — rather than have a framework
hide that from me."

**Q: What is a socket?**
A: "An endpoint for sending and receiving data over a network — one on the
server side, one on the client side, connected together."

**Q: TCP or UDP, and why?**
A: "TCP — I need reliable, ordered delivery. Login credentials and commands
can't get lost or arrive out of order like they could with UDP."

**Q: What's the length-prefix thing for?**
A: (see section 6 above)

**Q: How does the honeypot actually get triggered?**
A: (see section 5 above)

**Q: What else could trigger the honeypot / how would you improve the logic?**
A: "Right now it's just a flat counter — 2 failed logins. Better versions
I'd consider: rate-based detection (3 fails in 60 seconds, not all-time),
flagging an IP that touches multiple ports quickly (scan behavior), flagging
malformed/garbage messages that don't follow the protocol (a real GUI would
never send that), or a simple risk-scoring system where different suspicious
actions add points and crossing a threshold triggers the honeypot — instead
of one hardcoded rule."

**Q: How do you know it's an attacker and not a user who mistyped their password?**
A: "It's not perfect — a couple of failed attempts is a simple heuristic, not
real behavioral analysis. This project was about demonstrating the concept,
not enterprise-grade detection."

**Q: Are passwords stored securely?**
A: "Yes — hashed with a per-user random salt using PBKDF2 (100,000 rounds),
and verified with a constant-time comparison so even if the storage file
leaked, passwords aren't recoverable directly, and timing can't leak info
either."

**Q: Did you use encryption (SSL/TLS)?**
A: "Yes — both the control and data channels are wrapped in TLS. A
self-signed certificate is generated automatically on first server startup,
and the client trusts that specific certificate rather than a public CA
chain, which is the right model for a LAN/dev deployment but wouldn't be
appropriate for the public internet as-is."

**Q: What would a public-internet-ready version need that this doesn't have?**
A: "A certificate signed by a real CA instead of self-signed, and hostname
verification turned on instead of trusting one pinned cert file."

**Q: How many clients can it handle at once?**
A: "Each connection gets its own thread, so it works for a handful to maybe
a few dozen clients. It's not built to scale to thousands — that would need
an event-driven model instead of thread-per-client."

**Q: What's the biggest weakness / what would you improve?**
A: "Data like users and sessions is stored in plain JSON files, not a real
database — fine for a small project, but not safe under concurrent writes or
at scale. I'd swap that for SQLite or Postgres next."

**Q: What was the hardest part?**
A: "Getting the TLS handshake to play well with my threading model — a
select()-based read loop can report a socket as readable when there's no
real application data behind it yet (TLS has its own protocol-level messages
that don't count as your data), so I had to add a bounded timeout to avoid a
thread hanging on a read that would never complete."

**Q: What's the architecture (HLD)?**
A: (see section 3 above)

**Q: Walk me through what happens when a user logs in.**
A: "The client sends a login message (username, password, port) over the
TLS-encrypted control channel, framed with its length. The server reads it,
checks the firewall rules — is this admin, is the IP banned, is the port
already a honeypot, are the credentials valid. Based on that it replies
'admin', 'valid', 'fake', or 'error', and the client's GUI opens the matching
screen — real portal, admin panel, or the fake decoy."

**Q: Why did you restructure the project into a package (`honeytrap/`)?**
A: "Originally everything was flat .py files in the root with hardcoded
constants scattered across files. I organized it into a proper package with
one `config.py` as the single source of truth for ports/hosts/paths, and
added real logging instead of print statements — more in line with how a
production codebase would actually be organized."

**Q: If you don't know something — safe fallback answer:**
A: "I focused more on getting the client-server and detection logic working
than deep-diving that part — happy to look into it."
