# ===============================
# 🛡️ HoneyTrap Server (Flask App)
# ===============================
from flask import Flask, request, jsonify
import threading, time
import firewall

app = Flask(__name__)

# Start thread to monitor inactivity
def check_inactivity_thread():
    while True:
        time.sleep(300)  # Every 5 minutes
        firewall.check_inactivity()

threading.Thread(target=check_inactivity_thread, daemon=True).start()

# ------------------------
# 🔐 User Authentication
# ------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username, password = data["username"], data["password"]
    
    if len(username) < 3 or len(password) < 3:
        return jsonify({"status": "error", "message": "Username and password must be at least 3 characters"})
    
    success, message = firewall.create_user(username, password)
    
    if success:
        return jsonify({"status": "success", "message": message})
    else:
        return jsonify({"status": "error", "message": message})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data["username"], data["password"]
    ip_address = request.remote_addr
    port = request.environ.get('REMOTE_PORT', 'unknown')
    
    status, error_message = firewall.check_login(username, password, ip_address, port)
    
    if error_message:
        return jsonify({"status": status, "message": error_message})
    return jsonify({"status": status})

# -------------------------------
# 🔄 Update Last Activity Endpoint
# -------------------------------
@app.route("/update_activity", methods=["POST"])
def update_activity():
    data = request.json
    username = data.get("username")
    
    if firewall.update_activity(username):
        return jsonify({"status": "updated"})
    return jsonify({"status": "error", "message": "User not found"})

#--------------Attacker route--------------------
@app.route('/attackers', methods=['GET'])
def get_attackers():
    attackers = firewall.get_attackers()
    return jsonify(attackers)

# -----------------------------
# 📡 Security Management Routes
# -----------------------------
@app.route("/potential_attackers", methods=["GET"])
def get_potential_attackers():
    return jsonify(firewall.get_potential_attackers())

@app.route("/ban_ip", methods=["POST"])
def ban_ip():
    data = request.json
    ip_address = data.get("ip")
    
    if not ip_address:
        return jsonify({"status": "error", "message": "IP address is required"}), 400
    
    if firewall.ban_ip(ip_address):
        return jsonify({"status": "success", "message": f"IP {ip_address} has been banned"})
    return jsonify({"status": "error", "message": "Failed to ban IP"}), 500

@app.route("/unban_ip", methods=["POST"])
def unban_ip():
    data = request.json
    ip_address = data.get("ip")
    
    if not ip_address:
        return jsonify({"status": "error", "message": "IP address is required"}), 400
    
    if firewall.unban_ip(ip_address):
        return jsonify({"status": "success", "message": f"IP {ip_address} has been unbanned"})
    return jsonify({"status": "error", "message": "Failed to unban IP"}), 500

@app.route("/banned_ips", methods=["GET"])
def get_banned_ips():
    return jsonify(firewall.get_banned_ips())

@app.route("/active_users", methods=["GET"])
def get_active_users():
    return jsonify(firewall.get_active_users())
@app.route("/ports", methods=["GET"])
def get_ports():
    return jsonify(firewall.get_ports())

@app.route("/update_port", methods=["POST"])
def update_port():
    data = request.json
    port = data.get("port")
    new_status = data.get("status")
    new_honeypot = data.get("honeypot")

    if firewall.toggle_port_status(port, new_status, new_honeypot):
        return jsonify({"status": "success", "message": "Port updated"})
    return jsonify({"status": "error", "message": "Port not found"}), 404

# --------------------
# 🚀 Run Flask App
# ---------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
