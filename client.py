# ===============================
# HoneyTrap Socket Client
# ===============================
import socket
import json
import threading
import time
import select
from protocol import MessageType

class HoneyTrapClient:
    """Client for connecting to the HoneyTrap server"""
    def __init__(self, host='localhost', control_port=5000, data_port=5001):
        self.host = host
        self.control_port = control_port
        self.data_port = data_port
        
        # Connection variables
        self.control_socket = None
        self.data_socket = None
        self.ssl_context = None
        self.connected = False
        
        # User information
        self.username = None
        self.logged_in = False
        
        # Response handling
        self.last_response = None
        self.response_event = threading.Event()
        self.response_lock = threading.Lock()
        self.response_queue = {}
        
        # Listener thread
        self.listener_thread = None
        self.active = False
        
        # Message handlers
        self.message_handlers = {}
        self.register_handler("response", self.handle_response)
    
    def connect(self, verify_cert=False):
        """Connect to the server's control and data channels"""
        try:

            # Connect to control channel
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.connect((self.host, self.control_port))
            
            # Connect to data channel
            self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_socket.connect((self.host, self.data_port))
             
            self.connected = True
            self.active = True
            
            # Start listener thread for incoming messages
            self.listener_thread = threading.Thread(target=self.listen_for_messages)
            self.listener_thread.daemon = True
            self.listener_thread.start()
            
            return True
        
        except socket.error:
            self.disconnect()
            return False
        
        except Exception:
            self.disconnect()
            return False
    
    def disconnect(self):
        """Disconnect from the server"""
        self.active = False
        self.connected = False
        self.logged_in = False
        
        # Close sockets
        if self.control_socket:
            try:
                self.control_socket.close()
            except:
                pass
            self.control_socket = None
        
        if self.data_socket:
            try:
                self.data_socket.close()
            except:
                pass
            self.data_socket = None
    
    def register_handler(self, command, handler_function):
        """Register a function to handle specific incoming messages"""
        self.message_handlers[command] = handler_function
    
    def handle_response(self, message, channel_type):
        """Handle response messages from the server"""
        message_id = message.get('id')
        
        if message_id:
            with self.response_lock:
                if message_id in self.response_queue:
                    self.response_queue[message_id] = message
                    return
        
        # If no message ID, treat as general response
        self.last_response = message
        self.response_event.set()
    
    def send_control_message(self, message):
        """Send a message on the control channel"""
        if not self.connected or not self.control_socket:
            return False
        
        try:
            message_data = json.dumps(message).encode('utf-8')
            self.control_socket.sendall(message_data)
            return True
        except Exception:
            self.disconnect()
            return False
    
    def send_data_message(self, message):
        """Send a message on the data channel"""
        if not self.connected or not self.data_socket:
            return False
        
        try:
            message_data = json.dumps(message).encode('utf-8')
            self.data_socket.sendall(message_data)
            return True
        except Exception:
            self.disconnect()
            return False
    
    def listen_for_messages(self):
        """Listen for incoming messages on both channels"""
        while self.active and self.connected:
            try:
                # Check both sockets with timeout
                readable, _, _ = select.select(
                    [self.control_socket, self.data_socket], [], [], 1.0
                )
                
                for sock in readable:
                    try:
                        data = sock.recv(4096)
                        
                        if not data:
                            # Server disconnected
                            self.disconnect()
                            return
                        
                        # Process the message
                        message = json.loads(data.decode('utf-8'))
                        channel_type = "control" if sock == self.control_socket else "data"
                        self.process_message(message, channel_type)
                        
                    except json.JSONDecodeError:
                        pass
                    except Exception:
                        pass
            
            except Exception:
                if self.active:
                    self.disconnect()
                    return
    
    def process_message(self, message, channel_type):
        """Process an incoming message"""
        # Check for response messages (status field indicates a response)
        if message.get('status') is not None:
            # Set the last_response regardless of whether it has an ID
            self.last_response = message
            self.response_event.set()
            
            # Also call the response handler for any processing
            self.handle_response(message, channel_type)
            return
            
        # Otherwise, check for command handlers
        command = message.get('command')
        
        if command in self.message_handlers:
            self.message_handlers[command](message, channel_type)
    
    def send_and_wait(self, message, timeout=5.0, use_control_channel=True):
        """Send a message and wait for a response"""
        self.response_event.clear()
        self.last_response = None
        
        # Generate a unique message ID
        message_id = str(time.time()) + str(threading.get_ident())
        message['id'] = message_id
        
        # Send the message
        if use_control_channel:
            if not self.send_control_message(message):
                return None
        else:
            if not self.send_data_message(message):
                return None
        
        # Wait for the response event to be set
        if self.response_event.wait(timeout):
            return self.last_response
        
        return None
    
    def send_request(self, command, params=None, use_control_channel=True, timeout=5.0):
        """Send a request with command and params, wait for response"""
        if not params:
            params = {}
        
        # Create message
        message = {
            'command': command,
            'params': params,
            'timestamp': time.time()
        }
        
        return self.send_and_wait(message, timeout, use_control_channel)
    
    # ============== Authentication Methods ==============
    
    def login(self, username, password, port=None):
        """Log in to the server"""
        params = {
            'username': username,
            'password': password
        }
        
        if port is not None:
            params['port'] = port
            
        response = self.send_request(MessageType.LOGIN, params)
        
        if response and response.get('status') in ('admin', 'valid'):
            self.username = username
            self.logged_in = True
            return response.get('status')
        
        elif response and response.get('status') == 'fake':
            # Honeypot triggered
            return 'fake'
        
        return None
    
    def signup(self, username, password):
        """Sign up a new user"""
        params = {
            'username': username,
            'password': password
        }
        
        response = self.send_request(MessageType.SIGNUP, params)
        
        if response and response.get('status') == 'success':
            return True
        return False
    
    def logout(self):
        """Log out from the server"""
        if not self.logged_in:
            return True
        
        params = {
            'username': self.username
        }
        
        response = self.send_request(MessageType.LOGOUT, params)
        if response and response.get('status') == 'success':
            self.logged_in = False
            self.username = None
            return True
        return False
    
    # ============== User Activity Methods ==============
    
    def update_activity(self):
        """Update user activity on the server"""
        if not self.logged_in:
            return False
        
        params = {
            'username': self.username
        }
        
        response = self.send_request(MessageType.UPDATE_ACTIVITY, params)
        return response and response.get('status') == 'updated'
    
    def start_keep_alive(self, interval=60):
        """Start a thread to periodically send keep-alive messages"""
        def keep_alive_worker():
            while self.connected and self.logged_in:
                self.update_activity()
                time.sleep(interval)
        
        keep_alive_thread = threading.Thread(target=keep_alive_worker)
        keep_alive_thread.daemon = True
        keep_alive_thread.start()
    
    # ============== Port Management Methods ==============
    
    def get_ports(self):
        """Get available ports"""
        response = self.send_request(MessageType.GET_PORTS, {})
        if response and response.get('status') == 'success':
            return response.get('data', [])
        return []
    
    def update_port(self, port, status=None, honeypot=None):
        """Update port settings"""
        params = {'port': port}
        if status is not None:
            params['status'] = status
        if honeypot is not None:
            params['honeypot'] = honeypot
        
        response = self.send_request(MessageType.UPDATE_PORT, params)
        return response and response.get('status') == 'success'
    
    # ============== Security Management Methods ==============
    
    def get_attackers(self):
        """Get list of attackers"""
        response = self.send_request(MessageType.GET_ATTACKERS, {})
        if response and response.get('status') == 'success':
            return response.get('data', [])
        return []
    
    def get_potential_attackers(self):
        """Get list of potential attackers"""
        response = self.send_request(MessageType.GET_POTENTIAL_ATTACKERS, {})
        if response and response.get('status') == 'success':
            return response.get('data', [])
        return []
    
    def get_banned_ips(self):
        """Get list of banned IPs"""
        response = self.send_request(MessageType.GET_BANNED_IPS, {})
        if response and response.get('status') == 'success':
            return response.get('data', [])
        return []
    
    def ban_ip(self, ip_address):
        """Ban an IP address"""
        params = {
            'ip': ip_address
        }
        
        response = self.send_request(MessageType.BAN_IP, params)
        return response and response.get('status') == 'success'
    
    def unban_ip(self, ip_address):
        """Unban an IP address"""
        params = {
            'ip': ip_address
        }
        
        response = self.send_request(MessageType.UNBAN_IP, params)
        return response and response.get('status') == 'success'
    
    def get_active_users(self):
        """Get list of active users"""
        response = self.send_request(MessageType.GET_ACTIVE_USERS, {})
        if response and response.get('status') == 'success':
            return response.get('data', [])
        return []