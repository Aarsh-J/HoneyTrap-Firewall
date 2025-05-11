# =============================
# 🔄 HoneyTrap Socket Protocol
# =============================
# This file defines the protocol used for socket-based communication

import json
import time

# ----------------------
# 🔤 Message Types
# ----------------------
class MessageType:
    # Authentication
    LOGIN = "login"
    SIGNUP = "signup"
    LOGOUT = "logout"
    
    # Activity
    UPDATE_ACTIVITY = "update_activity"
    
    # Admin operations
    GET_ATTACKERS = "get_attackers"
    GET_POTENTIAL_ATTACKERS = "get_potential_attackers"
    BAN_IP = "ban_ip"
    UNBAN_IP = "unban_ip"
    GET_BANNED_IPS = "get_banned_ips"
    GET_ACTIVE_USERS = "get_active_users"
    
    # Port management
    GET_PORTS = "get_ports"
    UPDATE_PORT = "update_port"


# Protocol version
PROTOCOL_VERSION = "1.0"

# ----------------------
# 📝 Message Creation Helpers
# ----------------------
def create_login_message(username, password, port=None):
    """Create a properly formatted login message"""
    params = {
        'username': username,
        'password': password
    }
    
    if port is not None:
        params['port'] = port
        
    return {
        'command': MessageType.LOGIN,
        'params': params,
        'timestamp': time.time()
    }

def create_signup_message(username, password):
    """Create a properly formatted signup message"""
    return {
        'command': MessageType.SIGNUP,
        'params': {
            'username': username,
            'password': password
        },
        'timestamp': time.time()
    }

def create_logout_message(username):
    """Create a properly formatted logout message"""
    return {
        'command': MessageType.LOGOUT,
        'params': {
            'username': username
        },
        'timestamp': time.time()
    }

def create_update_activity_message(username):
    """Create a properly formatted activity update message"""
    return {
        'command': MessageType.UPDATE_ACTIVITY,
        'params': {
            'username': username
        },
        'timestamp': time.time()
    }

def create_get_ports_message():
    """Create a properly formatted get ports message"""
    return {
        'command': MessageType.GET_PORTS,
        'params': {},
        'timestamp': time.time()
    }

def create_update_port_message(port, status=None, honeypot=None):
    """Create a properly formatted port update message"""
    params = {'port': port}
    if status is not None:
        params['status'] = status
    if honeypot is not None:
        params['honeypot'] = honeypot
    
    return {
        'command': MessageType.UPDATE_PORT,
        'params': params,
        'timestamp': time.time()
    }

def create_ban_ip_message(ip_address):
    """Create a properly formatted ban IP message"""
    return {
        'command': MessageType.BAN_IP,
        'params': {
            'ip': ip_address
        },
        'timestamp': time.time()
    }

def create_unban_ip_message(ip_address):
    """Create a properly formatted unban IP message"""
    return {
        'command': MessageType.UNBAN_IP,
        'params': {
            'ip': ip_address
        },
        'timestamp': time.time()
    }