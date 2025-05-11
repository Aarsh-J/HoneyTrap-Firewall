# HoneyTrap-Firewall
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
- Port visibility control (hides ports from nmap scans)
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

### SSL Implementation
- Secure communications
- Self-signed certificate generation
- Proper SSL socket wrapping

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

The port stealth feature implements RST packet handling to make inactive ports invisible to network scanning tools like nmap, adding another layer of security.

## File Structure

- `server.py` - Main server implementation
- `server_base.py` - Base server functionality
- `client.py` - Client communication module
- `adapter.py` - Socket adapter for different components
- `protocol.py` - Communication protocol definitions
- `firewall.py` - Core rules engine
- `main.py` - Main client application
- `admin_panel.py` - Admin interface
- `user_portal.py` - User interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/honeytrap-firewall.git
cd honeytrap-firewall
```

2. Install dependencies:
```bash
pip install tkinter
```

## Usage

### Starting the Server
```bash
python server.py
```

### Starting the Client
```bash
python main.py
```

### Default Admin Credentials
- Username: `admin`
- Password: `admin123`

### Default User Credentials
- Username: `user`
- Password: `password`

## Multi-PC Setup

To run the HoneyTrap Firewall in a multi-PC environment:

1. On the server machine:
   ```bash
   python server.py
   ```
   Note the IP address displayed on startup.

2. On the client machine:
   - Edit `adapter.py` and set `SERVER_HOST` to the server's IP address
   ```python
   SERVER_HOST = '192.168.1.x'  # Replace with server's IP address
   ```
   - Run the client:
   ```bash
   python main.py
   ```

## Security Features

### Port Stealth
Inactive ports are hidden from nmap scans using a technique that responds with RST packets to scanning attempts.

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
