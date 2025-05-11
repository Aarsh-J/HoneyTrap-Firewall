# ===========================================
# HoneyTrap Firewall - Core Rules Engine
# ===========================================
import json
import time

# ----------------------
#  JSON Utility Functions
# ----------------------
def load_json(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {} if "users" in file or "sessions" in file else []

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# ----------------------
# Constants
# ----------------------
USER_DB = "users.json"
ATTACKER_LOG = "attackers.json"
POTENTIAL_ATTACKERS = "potential_attackers.json"
SESSIONS_DB = "sessions.json"
PORTS_DB = "ports.json"
BANNED_IPS = "banned_ips.json"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
INACTIVITY_LIMIT = 300  # 5 minutes for inactivity timeout

# Track login attempts
LOGIN_ATTEMPTS = {}

# ----------------------
# Firewall Rules
# ----------------------
def create_user(username, password):
    """Create a new user if username doesn't exist"""
    users = load_json(USER_DB)
    
    # Check if username already exists
    if username in users:
        return False, "Username already exists"
    
    # Create new user
    users[username] = password
    save_json(USER_DB, users)
    return True, "User created successfully"

def check_login(username, password, ip_address, port):
    """
    Validates login and applies firewall rules.
    Returns: 
        - "admin" if admin credentials
        - "valid" if valid user
        - "fake" if user should be directed to fake page
        - "error" if login failed
    """
    users = load_json(USER_DB)
    banned_ips = load_json(BANNED_IPS)
    ports = load_json(PORTS_DB)
    potential_attackers = load_json(POTENTIAL_ATTACKERS)
    
    # Admin login check - must be first to bypass all other checks
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return "admin", None
    
    # Check if IP is banned
    if ip_address in banned_ips:
        return "fake", "IP address banned"
    
    # Basic validation
    if len(username) < 3 or len(password) < 3:
        return "error", "Invalid username/password length"

    # Check if the port has honeypot enabled
    port_honeypot_enabled = False
    for p in ports:
        if str(p["port"]) == str(port) and p["status"] == "active":
            port_honeypot_enabled = p.get("honeypot", False)
            break
    
    # If honeypot is active, always send to fake page
    if port_honeypot_enabled:
        return "fake", None
    
    # Regular user login
    if username in users and users[username] == password:
        # Reset login attempts for this user+IP if successful
        key = f"{username}:{ip_address}"
        if key in LOGIN_ATTEMPTS:
            del LOGIN_ATTEMPTS[key]
            
        sessions = load_json(SESSIONS_DB)
        sessions[username] = {
            "login_time": time.time(),
            "last_activity_time": time.time(),
            "ip": ip_address,
            "port": port
        }
        save_json(SESSIONS_DB, sessions)
        return "valid", None

    # Failed attempt handling
    key = f"{username}:{ip_address}"
    LOGIN_ATTEMPTS[key] = LOGIN_ATTEMPTS.get(key, 0) + 1
    
    # Check number of failed attempts - Allow 2 incorrect attempts
    if LOGIN_ATTEMPTS[key] >= 2:
        # Two or more failed attempts - flag as a potential attacker
        potential_attacker_entry = {
            "username": username,
            "ip": ip_address,
            "attempted_port": port,
            "attempts": LOGIN_ATTEMPTS[key],
            "reason": "2 or more failed login attempts",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Check if this IP+username already exists in potential_attackers
        existing = False
        for i, entry in enumerate(potential_attackers):
            if entry["username"] == username and entry["ip"] == ip_address:
                potential_attackers[i] = potential_attacker_entry
                existing = True
                break
        
        if not existing:
            potential_attackers.append(potential_attacker_entry)
        
        save_json(POTENTIAL_ATTACKERS, potential_attackers)
        
        # Enable honeypot on this port
        for p in ports:
            if str(p["port"]) == str(port):
                p["honeypot"] = True
                p["last_triggered"] = time.strftime("%Y-%m-%d %H:%M:%S")
                break
        save_json(PORTS_DB, ports)
        
        return "fake", None
    
    return "error", "Incorrect username/password"

def logout_user(username):
    """Remove a user's session when they log out properly"""
    sessions = load_json(SESSIONS_DB)
    if username in sessions:
        # Remove the session entry
        del sessions[username]
        save_json(SESSIONS_DB, sessions)
        return True
    return False

def check_inactivity():
    """Check for inactive users and flag them as potential attackers if inactive beyond limit"""
    sessions = load_json(SESSIONS_DB)
    potential_attackers = load_json(POTENTIAL_ATTACKERS)
    current_time = time.time()
    
    for username, session in list(sessions.items()):
        if username == ADMIN_USERNAME:
            continue

        port = session.get("port", "unknown")
        inactive_time = current_time - session["last_activity_time"]
        
        # Only mark as potential attackers if they've been inactive beyond limit
        if inactive_time > INACTIVITY_LIMIT:
            # Add to potential attackers
            potential_attacker_entry = {
                "username": username,
                "ip": session["ip"],
                "attempted_port": port,
                "reason": "Inactive for 5+ minutes",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Check if already in potential attackers
            existing = False
            for i, entry in enumerate(potential_attackers):
                if entry["username"] == username and entry["ip"] == session["ip"]:
                    potential_attackers[i] = potential_attacker_entry
                    existing = True
                    break
            
            if not existing:
                potential_attackers.append(potential_attacker_entry)
            
            save_json(POTENTIAL_ATTACKERS, potential_attackers)
            
            # Enable honeypot for this session's port
            ports = load_json(PORTS_DB)
            for p in ports:
                if str(p["port"]) == str(port):
                    p["honeypot"] = True
                    p["last_triggered"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    break
            save_json(PORTS_DB, ports)
            
            # Remove the session
            del sessions[username]
            save_json(SESSIONS_DB, sessions)

    save_json(SESSIONS_DB, sessions)

def update_activity(username):
    """Update user activity timestamp"""
    sessions = load_json(SESSIONS_DB)
    if username in sessions:
        sessions[username]["last_activity_time"] = time.time()
        save_json(SESSIONS_DB, sessions)
    return True

def get_port_status(port):
    """Check if port is active and if honeypot is enabled"""
    ports = load_json(PORTS_DB)
    for p in ports:
        if str(p["port"]) == str(port):
            return {
                "active": p["status"] == "active",
                "honeypot": p.get("honeypot", False)
            }
    return {"active": False, "honeypot": False}

def toggle_port_status(port, status=None, honeypot=None):
    """Update port status or honeypot setting"""
    ports = load_json(PORTS_DB)
    for p in ports:
        if str(p["port"]) == str(port):
            if status is not None:
                p["status"] = status
            if honeypot is not None:
                p["honeypot"] = honeypot
            save_json(PORTS_DB, ports)
            return True
    return False

def get_attackers():
    """Return the list of attackers"""
    return load_json(ATTACKER_LOG)

def get_ports():
    """Return the list of ports"""
    return load_json(PORTS_DB)

def get_potential_attackers():
    """Return the list of potential attackers"""
    return load_json(POTENTIAL_ATTACKERS)

def ban_ip(ip_address):
    """Add an IP to the banned list"""
    banned_ips = load_json(BANNED_IPS)
    if ip_address not in banned_ips:
        banned_ips.append(ip_address)
        save_json(BANNED_IPS, banned_ips)
    return True

def unban_ip(ip_address):
    """Remove an IP from the banned list"""
    banned_ips = load_json(BANNED_IPS)
    if ip_address in banned_ips:
        banned_ips.remove(ip_address)
        save_json(BANNED_IPS, banned_ips)
    return True

def get_banned_ips():
    """Get the list of banned IPs"""
    return load_json(BANNED_IPS)

def get_active_users():
    """Get the list of currently active users with their session details"""
    sessions = load_json(SESSIONS_DB)
    active_users = []
    
    current_time = time.time()
    for username, session in sessions.items():
        # Calculate how long they've been active and inactive
        session_length = current_time - session["login_time"]
        last_activity = current_time - session["last_activity_time"]
        
        # Add formatted details
        active_users.append({
            "username": username,
            "ip": session["ip"],
            "port": session.get("port", "unknown"),
            "login_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session["login_time"])),
            "last_activity": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(session["last_activity_time"])),
            "session_length": f"{int(session_length / 60)} mins",
            "inactive_for": f"{int(last_activity / 60)} mins"
        })
    
    return active_users

# Initialize JSON files on import
def initialize_files():
    """Initialize necessary JSON files with default values if they don't exist"""
    try:
        # Initialize ports
        ports = load_json(PORTS_DB)
        if not ports:
            # Create default ports
            default_ports = [
                {"port": 8001, "status": "active", "honeypot": False, "last_triggered": "Never"},
                {"port": 8002, "status": "active", "honeypot": False, "last_triggered": "Never"},
                {"port": 8003, "status": "active", "honeypot": False, "last_triggered": "Never"},
                {"port": 8004, "status": "inactive", "honeypot": False, "last_triggered": "Never"},
                {"port": 8005, "status": "inactive", "honeypot": False, "last_triggered": "Never"}
            ]
            save_json(PORTS_DB, default_ports)
        
        # Initialize other JSON files if they don't exist
        potential_attackers = load_json(POTENTIAL_ATTACKERS)
        save_json(POTENTIAL_ATTACKERS, potential_attackers)
        
        banned_ips = load_json(BANNED_IPS)
        save_json(BANNED_IPS, banned_ips)
        
        sessions = load_json(SESSIONS_DB)
        save_json(SESSIONS_DB, sessions)
        
        attackers = load_json(ATTACKER_LOG)
        save_json(ATTACKER_LOG, attackers)
        
        users = load_json(USER_DB)
        if not users:
            # Create a default test user if none exist
            users = {"user": "password"}
            save_json(USER_DB, users)
            
    except Exception as e:
        print(f"Error initializing files: {e}")

# Initialize on import
initialize_files()