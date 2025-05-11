# ===============================
# Enhanced HoneyTrap Socket Server
# ===============================
import socket
import threading
import json
import time
import select
import signal
import sys

class EnhancedSocketServer:
    def __init__(self, host='0.0.0.0', control_port=5000, data_port=5001):
        """Initialize the socket server with separate control and data ports"""
        self.host = host
        self.control_port = control_port
        self.data_port = data_port
        
        # Create sockets
        self.control_socket = None
        self.data_socket = None
        
        # SSL contexts
        self.ssl_context = None
        
        # Connection lists
        self.control_connections = []
        self.data_connections = []
        
        # Message handlers
        self.message_handlers = {}
        
        # Active status (for graceful termination)
        self.active = False
        
        # Setup signal handlers for graceful termination
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_sockets(self):
        """Setup both control and data sockets with proper options"""
        try:
            # Setup control socket
            self.control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Setup data socket
            self.data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind sockets
            self.control_socket.bind((self.host, self.control_port))
            self.control_socket.listen(5)
            
            self.data_socket.bind((self.host, self.data_port))
            self.data_socket.listen(5)
            
            return True
        
        except socket.error as e:
            print(f"[-] Socket bind error: {e}")
            return False
    
    def register_handler(self, command, handler_function):
        """Register a function to handle a specific command"""
        self.message_handlers[command] = handler_function
    
    def start(self):
        """Start the server with retry mechanism"""
        retry_count = 0
        max_retries = 5
        
        while retry_count < max_retries:
            if self.setup_sockets():
                self.active = True
                
                # Start threads for accepting connections
                control_thread = threading.Thread(target=self.accept_connections, 
                                               args=(self.control_socket, self.control_connections, "control"))
                data_thread = threading.Thread(target=self.accept_connections, 
                                            args=(self.data_socket, self.data_connections, "data"))
                
                control_thread.daemon = True
                data_thread.daemon = True
                
                control_thread.start()
                data_thread.start()
                
                return True
            
            # Failed to bind, wait and retry
            retry_count += 1
            backoff_time = 2 ** retry_count  # Exponential backoff
            print(f"[-] Retry {retry_count}/{max_retries} in {backoff_time} seconds...")
            time.sleep(backoff_time)
        
        print("[-] Failed to start server after multiple retries")
        return False
    
    def accept_connections(self, sock, connection_list, channel_type):
        """Accept incoming connections on the specified socket"""
        while self.active:
            try:
                # Accept connection with timeout to allow checking active status
                sock.settimeout(1.0)
                try:
                    client_socket, client_address = sock.accept()

                except socket.timeout:
                    continue
                except Exception:
                    if self.active:
                        print("[-] Error accepting connection")
                    continue
                
                sock.settimeout(None)
                
                print(f"[+] New {channel_type} connection from {client_address[0]}:{client_address[1]}")
                
                # Add to connection list
                connection_info = {
                    'socket': client_socket,
                    'address': client_address,
                    'channel': channel_type,
                    'last_activity': time.time()
                }
                connection_list.append(connection_info)
                
                # Start a thread to handle client messages
                client_thread = threading.Thread(target=self.handle_client_messages, 
                                             args=(connection_info,))
                client_thread.daemon = True
                client_thread.start()
                
            except socket.timeout:
                continue
            except socket.error:
                if not self.active:
                    break
            except Exception:
                if not self.active:
                    break
        
    def handle_client_messages(self, connection_info):
        """Handle messages from a client"""
        client_socket = connection_info['socket']
        channel = connection_info['channel']
        
        while self.active:
            try:
                # Use select to implement non-blocking receive with timeout
                ready = select.select([client_socket], [], [], 1.0)
                
                if ready[0]:
                    # Socket has data to read
                    data = client_socket.recv(4096)
                    
                    if not data:
                        # Client disconnected
                        self.close_connection(connection_info)
                        break
                    
                    # Update last activity time
                    connection_info['last_activity'] = time.time()
                    
                    # Try to parse JSON message
                    try:
                        message_str = data.decode('utf-8')
                        
                        message = json.loads(message_str)
                        
                        # Extract command and handle it
                        command = message.get('command')
                        
                        if command in self.message_handlers:
                            response = self.message_handlers[command](message, connection_info)
                            if response:
                                # Send response back to client
                                self.send_message(client_socket, response)
                        else:
                            # Unknown command
                            response = {'status': 'error', 'message': f"Unknown command: {command}"}
                            self.send_message(client_socket, response)
                    
                    except json.JSONDecodeError:
                        response = {'status': 'error', 'message': "Invalid request format"}
                        self.send_message(client_socket, response)
            
            except ConnectionError:
                self.close_connection(connection_info)
                break
                
            except Exception:
                self.close_connection(connection_info)
                break
    
    def send_message(self, client_socket, message):
        """Send a JSON message to a client"""
        try:
            response_data = json.dumps(message).encode('utf-8')
            client_socket.sendall(response_data)
            return True
        except Exception:
            return False
    
    def broadcast_control_message(self, message):
        """Broadcast a message to all control channel clients"""
        for conn in self.control_connections[:]:
            try:
                self.send_message(conn['socket'], message)
            except:
                # If failed, remove the connection
                self.close_connection(conn)
    
    def close_connection(self, connection_info):
        """Close a client connection and remove from list"""
        try:
            connection_info['socket'].close()
        except:
            pass
        
        # Remove from the appropriate connection list
        if connection_info['channel'] == 'control':
            if connection_info in self.control_connections:
                self.control_connections.remove(connection_info)
        else:
            if connection_info in self.data_connections:
                self.data_connections.remove(connection_info)
    
    def check_inactive_connections(self, timeout=300):
        """Check for and close inactive connections"""
        current_time = time.time()
        
        # Check control connections
        for conn in self.control_connections[:]:
            if current_time - conn['last_activity'] > timeout:
                self.close_connection(conn)
        
        # Check data connections
        for conn in self.data_connections[:]:
            if current_time - conn['last_activity'] > timeout:
                self.close_connection(conn)
    
    def signal_handler(self, sig, frame):
        """Handle termination signals for graceful shutdown"""
        print("\n[*] Received termination signal, shutting down...")
        self.stop()
    
    def stop(self):
        """Stop the server and close all connections"""
        self.active = False
        
        # Close all client connections
        for conn in self.control_connections[:]:
            self.close_connection(conn)
        
        for conn in self.data_connections[:]:
            self.close_connection(conn)
        
        # Close server sockets
        if self.control_socket:
            try:
                self.control_socket.close()
            except:
                pass
        
        if self.data_socket:
            try:
                self.data_socket.close()
            except:
                pass
        
        print("[*] Server shutdown complete")