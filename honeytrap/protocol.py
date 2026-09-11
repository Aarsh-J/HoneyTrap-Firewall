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
# 📦 Message Framing
# ----------------------
# TCP is a byte stream, not a message stream: a single send() can arrive
# split across several recv() calls, and several small send() calls can
# coalesce into one recv(). A raw recv(4096) -> json.loads() assumes message
# boundaries that TCP doesn't guarantee, so every message is prefixed with a
# 4-byte big-endian length header.
HEADER_SIZE = 4

def recv_exact(sock, num_bytes):
    """Read exactly num_bytes from sock, blocking until they arrive.

    Returns None if the connection is closed before num_bytes are read.
    """
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def send_framed(sock, message):
    """Encode message as JSON and send it prefixed with its length."""
    payload = json.dumps(message).encode('utf-8')
    header = len(payload).to_bytes(HEADER_SIZE, byteorder='big')
    sock.sendall(header + payload)

def recv_framed(sock):
    """Receive one length-prefixed JSON message from sock.

    Returns None if the connection was closed.
    Raises json.JSONDecodeError if the payload isn't valid JSON.
    """
    header = recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None

    length = int.from_bytes(header, byteorder='big')
    payload = recv_exact(sock, length)
    if payload is None:
        return None

    return json.loads(payload.decode('utf-8'))

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