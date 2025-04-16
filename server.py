# ===============================
# 🛡️ HoneyTrap Server (Flask App)
# ===============================
from flask import Flask, request, jsonify
import json, time, threading

app = Flask(__name__)

# -------------------------------
# 🔧 Constants and Configurations
# -------------------------------
USER_DB = "users.json"
ATTACKER_LOG = "attackers.json"
SESSIONS_DB = "sessions.json"
PORTS_DB = "ports.json"

ADMIN_USERNAME = "aarsh"
ADMIN_PASSWORD = "00186"
INACTIVITY_LIMIT = 900  # 15 minutes

# -----------------------------
# 📁 JSON Utility Functions
# -----------------------------
def load_json(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {} if "users" in file or "ports" in file else []

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# ----------------------------------
# 🔍 Inactivity Detection Thread
# ----------------------------------
def check_inactivity():
    while True:
        time.sleep(300)  # Every 5 minutes
        sessions = load_json(SESSIONS_DB)
        attackers = load_json(ATTACKER_LOG)
        current_time = time.time()

        for username, session in list(sessions.items()):
            if username == ADMIN_USERNAME:
                continue

            if current_time - session["last_activity_time"] > INACTIVITY_LIMIT:
                print(f"[SECURITY] {username} flagged as attacker due to inactivity")
                attackers.append({
                    "username": username,
                    "ip": session["ip"],
                    "reason": "Unusual Session Behavior (Inactive for 15 min)",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                save_json(ATTACKER_LOG, attackers)
                del sessions[username]

        save_json(SESSIONS_DB, sessions)

# Start thread to monitor inactivity
threading.Thread(target=check_inactivity, daemon=True).start()

# ------------------------
# 🔐 Login Functionality
# ------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]
    users = load_json(USER_DB)
    attackers = load_json(ATTACKER_LOG)

    if len(username) < 3 or len(password) < 3:
        return jsonify({"status": "error", "message": "Invalid username/password length"})

    # Admin login check
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return jsonify({"status": "admin"})

    # Regular user login
    if username in users and users[username] == password:
        sessions = load_json(SESSIONS_DB)
        sessions[username] = {
            "login_time": time.time(),
            "last_activity_time": time.time(),
            "ip": request.remote_addr
        }
        save_json(SESSIONS_DB, sessions)
        return jsonify({"status": "valid"})

    # Failed attempt handling
    previous_attempts = [a for a in attackers if a["username"] == username and a["ip"] == request.remote_addr]
    if len(previous_attempts) >= 1:
        # Log as attacker on 2nd wrong try
        attackers.append({
            "username": username,
            "password": password,
            "ip": request.remote_addr,
            "attempted_port": request.environ.get('REMOTE_PORT', 'unknown'),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        save_json(ATTACKER_LOG, attackers)
        return jsonify({"status": "fake"})

    return jsonify({"status": "error", "message": "Incorrect username/password"})

# -------------------------------
# 🔄 Update Last Activity Endpoint
# -------------------------------
@app.route("/update_activity", methods=["POST"])
def update_activity():
    data = request.json
    username = data.get("username")
    
    sessions = load_json(SESSIONS_DB)
    if username in sessions:
        sessions[username]["last_activity_time"] = time.time()
        save_json(SESSIONS_DB, sessions)
    
    return jsonify({"status": "updated"})

# --------------------------
# ⚙️ Port Management Utility
# --------------------------
def load_ports():
    try:
        with open(PORTS_DB, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_ports(data):
    with open(PORTS_DB, "w") as f:
        json.dump(data, f, indent=4)

# -----------------------------
# 📡 Port Configuration Routes
# -----------------------------
@app.route("/ports", methods=["GET"])
def get_ports():
    return jsonify(load_ports())

@app.route("/update_port", methods=["POST"])
def update_port():
    data = request.json
    port = str(data.get("port"))
    status = data.get("status")
    firewall = data.get("firewall")

    ports = load_ports()
    if port not in ports:
        ports[port] = {}
    ports[port].update({"status": status, "firewall": firewall})

    save_ports(ports)
    return jsonify({"status": "success", "message": "Port updated"})

# --------------------
# 🚀 Run Flask App
# ---------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
