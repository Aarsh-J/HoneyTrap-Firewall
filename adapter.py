# ===============================
# Socket Adapter for Main Application
# ===============================
import tkinter as tk
import random
import os
import sys
import subprocess
from client import HoneyTrapClient

# ----------------------
# Connection Setup
# ----------------------
# For multi-PC setup: Change 'localhost' to the server's IP address
SERVER_HOST = 'localhost'  # localhost / IP address (e.g., 192.168.1.5)
CONTROL_PORT = 5000
DATA_PORT = 5001

def get_client():
    """Get a singleton client instance"""
    if not hasattr(get_client, 'instance'):
        get_client.instance = HoneyTrapClient(SERVER_HOST, CONTROL_PORT, DATA_PORT, use_ssl=False)
        get_client.instance.connect()
    return get_client.instance

# ----------------------
# Login Management
# ----------------------
class LoginHandler:
    @staticmethod
    def login(username, password, port=None):
        """Handle login through socket connection"""
        client = get_client()
        
        if len(username) < 3 or len(password) < 3:
            return {"status": "error", "message": "Username and password must be at least 3 characters"}
        
        # Check if these are admin credentials before applying firewall rules
        from firewall import ADMIN_USERNAME, ADMIN_PASSWORD
        admin_login = (username == ADMIN_USERNAME and password == ADMIN_PASSWORD)
        
        # For admin login, ensure we use a non-honeypot port
        if admin_login and port is None:
            ports = client.get_ports()
            # Find ports without honeypot
            safe_ports = [p for p in ports if p["status"] == "active" and not p.get("honeypot", False)]
            if safe_ports:
                port = safe_ports[0]["port"]  # Use the first safe port
        
        # Perform login with port information
        login_status = client.login(username, password, port)
        
        # Get available ports
        ports = client.get_ports()
        active_ports = [p for p in ports if p["status"] == "active"]
        
        if not active_ports and login_status != 'admin':
            return {"status": "error", "message": "No active ports available"}
        
        # Select port for connection (use the provided port or a random one)
        if port is None and login_status != 'admin':
            selected_port = random.choice(active_ports)
            port_number = selected_port["port"]
        else:
            port_number = port
        
        if login_status == 'admin':
            return {"status": "admin", "port": port_number}
        elif login_status == 'valid':
            return {"status": "valid", "port": port_number}
        elif login_status == 'fake':
            return {"status": "fake", "port": port_number}
        else:
            return {"status": "error", "message": "Incorrect username or password"}
    
    @staticmethod
    def signup(username, password):
        """Handle signup through socket connection"""
        client = get_client()
        
        result = client.signup(username, password)
        
        if result:
            return {"status": "success", "message": "Account created successfully"}
        else:
            return {"status": "error", "message": "Username already exists"}
    
    @staticmethod
    def get_ports():
        """Get ports from server"""
        client = get_client()
        return client.get_ports()

# ----------------------
# Admin Functions
# ----------------------
class AdminHandler:
    @staticmethod
    def get_attackers():
        """Get attackers through socket connection"""
        client = get_client()
        return client.get_attackers()
    
    @staticmethod
    def get_potential_attackers():
        """Get potential attackers through socket connection"""
        client = get_client()
        return client.get_potential_attackers()
    
    @staticmethod
    def ban_ip(ip_address):
        """Ban IP through socket connection"""
        client = get_client()
        return client.ban_ip(ip_address)
    
    @staticmethod
    def unban_ip(ip_address):
        """Unban IP through socket connection"""
        client = get_client()
        return client.unban_ip(ip_address)
    
    @staticmethod
    def get_banned_ips():
        """Get banned IPs through socket connection"""
        client = get_client()
        return client.get_banned_ips()
    
    @staticmethod
    def get_active_users():
        """Get active users through socket connection"""
        client = get_client()
        return client.get_active_users()
    
    @staticmethod
    def get_ports():
        """Get ports through socket connection"""
        client = get_client()
        return client.get_ports()
    
    @staticmethod
    def update_port(port, status=None, honeypot=None):
        """Update port through socket connection"""
        client = get_client()
        return client.update_port(port, status, honeypot)

# ----------------------
# User Functions
# ----------------------
class UserHandler:
    @staticmethod
    def update_activity(username):
        """Update user activity through socket connection"""
        client = get_client()
        client.username = username  # Set username for the client
        client.logged_in = True     # Mark as logged in
        return client.update_activity()
    
    @staticmethod
    def start_keep_alive(username):
        """Start keep-alive thread"""
        client = get_client()
        client.username = username  # Set username for the client
        client.logged_in = True     # Mark as logged in
        client.start_keep_alive()

    @staticmethod
    def logout():
        """Logout through socket connection"""
        client = get_client()
        client.logout()
        client.disconnect()
        
        # Reset client instance to force new connection on next use
        if hasattr(get_client, 'instance'):
            delattr(get_client, 'instance')
            
    @staticmethod
    def get_client_instance():
        """Get client instance for direct operations"""
        try:
            return get_client()
        except Exception:
            return None

# ----------------------
# Portal Integration
# ----------------------
def open_socket_user_portal(port, username="user"):
    """Open user portal with socket communication"""
    # Import within function to avoid circular imports
    from user_portal import open_user_portal
    
    # Launch regular portal, but with socket backend already initialized
    UserHandler.start_keep_alive(username)  # Start keep-alive with username
    open_user_portal(port)
    
    # Logout after portal is closed
    UserHandler.logout()

def open_socket_fake_portal(port):
    """Open fake portal with socket communication"""
    # Import within function to avoid circular imports
    from user_portal import open_fake_portal
    
    # Launch fake portal, but with socket backend already initialized
    UserHandler.start_keep_alive("attacker")  # Log activity as "attacker"
    open_fake_portal(port)
    
    # Logout after portal is closed
    UserHandler.logout()