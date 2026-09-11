# HoneyTrap Firewall

A comprehensive security system for detecting and monitoring potential network attackers using honeypot technology.

## Project Overview

HoneyTrap Firewall is a sophisticated security system that employs deception-based defense mechanisms to identify and monitor network threats. The system uses customizable honeypot ports to detect unauthorized access attempts and malicious behavior, providing administrators with real-time visibility into potential attacks.

## Features

### Multi-Server/Client Architecture
- Supports any number of servers and clients
- Parallel channels for data and control transmission
- No rewriting or recompiling code required
- Custom socket handling without third-party libraries

### User Authentication System
- Secure login/signup mechanism
- Session tracking and management
- Real-time activity monitoring

### Advanced Port Management
- Ports can be marked active/inactive; inactive ports simply aren't listened
  on, so a scan sees the OS's normal "closed" response (RST) rather than any
  active deception — see the Port Stealth note under Security Features
- Individual port status (active/inactive)
- Honeypot capability per port

### Honeypot Technology
- Configurable honeypots that can be enabled per port
- Automatic redirection to fake interfaces
- Attacker information collection

### Attacker Detection and Monitoring
- Failed login attempt tracking
- Automatic flagging of suspicious behavior
- IP banning capability
- Inactivity monitoring

### SSL/TLS Implementation
- Both the control and data channels are wrapped in TLS (`ssl.SSLContext`)
- A self-signed certificate/key pair (`server.crt` / `server.key`) is generated
  automatically on first server startup via `tls.py` if one doesn't already exist
- The client trusts that specific certificate file rather than a public CA chain,
  which is appropriate for a LAN/dev deployment but not for the public internet

### Graceful Termination
- Proper connection cleanup
- No bind errors on restart
- Signal handling

### Administrator Controls
- Real-time monitoring dashboard
- Attacker logs and IP management
- Port configuration controls
- System status overview

## How It Works

When a user attempts to log in, their credentials and behavior are analyzed by the firewall rules engine. If suspicious activity is detected (multiple failed logins, unusual connection patterns), the system can automatically enable honeypot mode for the port they're connecting to.

In honeypot mode, users are redirected to a fake interface that appears legitimate but actually monitors their actions and collects information. This allows administrators to study potential attack patterns while keeping the real system safe.

Inactive ports are simply not listened on, so a scan sees a normal "closed"
response from the OS TCP stack. Making a port genuinely invisible to a
scanner (nmap reporting "filtered" rather than "closed") requires silently
dropping SYN packets at the firewall/OS level, which is out of scope for a
plain Python socket program without raw-packet/firewall access — see the
Port Stealth note under Security Features.

## File Structure

```
run_server.py           - Entry point: starts the server
run_client.py            - Entry point: starts the client GUI
honeytrap/
    config.py             - Centralized configuration (reads .env / environment)
    logging_setup.py       - Logging configuration
    protocol.py             - Communication protocol definitions
    tls.py                   - Self-signed cert generation, TLS contexts
    server_base.py            - Base server socket handling
    server.py                  - Main server implementation (firewall rule wiring)
    client.py                   - Client communication module
    firewall.py                  - Core rules engine
    adapter.py                    - Socket adapter used by the GUI
    gui/
        app.py                     - Main client application (login/signup)
        admin_panel.py               - Admin interface
        user_portal.py                - User / fake honeypot interface
data/                       - Runtime JSON "database" files (gitignored)
certs/                       - Self-signed TLS cert/key (gitignored)
logs/                         - Log output (gitignored)
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/honeytrap-firewall.git
cd honeytrap-firewall
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env` and adjust values as needed.

## Usage

### Starting the Server
```bash
python run_server.py
```

### Starting the Client
```bash
python run_client.py
```

### Default Admin Credentials
- Username: `admin`
- Password: `admin123` (override via the `HONEYTRAP_ADMIN_USERNAME` / `HONEYTRAP_ADMIN_PASSWORD` environment variables in `.env`; the password is never stored in plaintext, only as a salted PBKDF2 hash in memory)

### Default User Credentials
- Username: `user`
- Password: `password`

## Multi-PC Setup

To run the HoneyTrap Firewall in a multi-PC environment:

1. On the server machine:
   ```bash
   python run_server.py
   ```
   Note the IP address displayed on startup.

2. On the client machine:
   - In `.env`, set `HONEYTRAP_SERVER_HOST` to the server's IP address:
   ```
   HONEYTRAP_SERVER_HOST=192.168.1.x
   ```
   - Run the client:
   ```bash
   python run_client.py
   ```

## Security Features

### Port Stealth
Inactive ports simply aren't listened on, so the OS TCP stack replies with a
normal RST — nmap reports this as "closed", the same as any unused port on
any machine. This is *not* true stealth: genuinely hiding a port (nmap
reporting "filtered", i.e. no response at all) requires dropping incoming
SYN packets at the firewall/OS level (e.g. an `iptables`/Windows Firewall
rule, or raw-packet interception), which needs privileges and platform
access beyond what a portable Python socket program can rely on. This is a
known, deliberate scope limitation rather than an implemented feature.

### Honeypot Mode
When enabled on a port, all connections to that port are redirected to a fake interface that mimics legitimate functionality while monitoring activity.

### Attacker Detection
The system automatically flags potential attackers based on:
- Multiple failed login attempts
- Unusual connection patterns
- Extended inactivity periods

### IP Banning
Administrators can ban IP addresses of known attackers, which automatically redirects all connection attempts to the honeypot interface.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Acknowledgements

- This project was developed as a comprehensive solution for network security using deception-based defense techniques.
- Special thanks to all contributors and testers who helped improve the system.
