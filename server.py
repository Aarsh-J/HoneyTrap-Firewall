# ===============================
# 🛡️ HoneyTrap Server Implementation
# ===============================
import socket
import threading
import json
import time
import firewall
from server_base import EnhancedSocketServer
from protocol import MessageType

#import port_stealth

class HoneyTrapServer:
    def __init__(self, host='0.0.0.0', control_port=5000, data_port=5001):
        """Initialize the HoneyTrap server"""
        self.socket_server = EnhancedSocketServer(host, control_port, data_port)
        self.register_message_handlers()
        self.inactivity_thread = None
    
    def register_message_handlers(self):
        """Register all message handlers"""
        # Authentication handlers
        self.socket_server.register_handler(MessageType.LOGIN, self.handle_login)
        self.socket_server.register_handler(MessageType.SIGNUP, self.handle_signup)
        self.socket_server.register_handler(MessageType.LOGOUT, self.handle_logout)
        
        # Activity handlers
        self.socket_server.register_handler(MessageType.UPDATE_ACTIVITY, self.handle_update_activity)
        
        # Admin handlers
        self.socket_server.register_handler(MessageType.GET_ATTACKERS, self.handle_get_attackers)
        self.socket_server.register_handler(MessageType.GET_POTENTIAL_ATTACKERS, self.handle_get_potential_attackers)
        self.socket_server.register_handler(MessageType.BAN_IP, self.handle_ban_ip)
        self.socket_server.register_handler(MessageType.UNBAN_IP, self.handle_unban_ip)
        self.socket_server.register_handler(MessageType.GET_BANNED_IPS, self.handle_get_banned_ips)
        self.socket_server.register_handler(MessageType.GET_ACTIVE_USERS, self.handle_get_active_users)
        
        # Port management handlers
        self.socket_server.register_handler(MessageType.GET_PORTS, self.handle_get_ports)
        self.socket_server.register_handler(MessageType.UPDATE_PORT, self.handle_update_port)
    
    def start(self):
        """Start the socket server and inactivity checker"""
        if self.socket_server.start():
            # Start inactivity checker thread
            self.inactivity_thread = threading.Thread(target=self.check_inactivity_loop)
            self.inactivity_thread.daemon = True
            self.inactivity_thread.start()
            return True
        return False
    
    def stop(self):
        """Stop the server"""
        self.socket_server.stop()
    
    def check_inactivity_loop(self):
        """Thread function to periodically check for inactive users"""
        while self.socket_server.active:
            # Check for inactive clients
            self.socket_server.check_inactive_connections()
            
            # Check for inactive users in the firewall system
            try:
                firewall.check_inactivity()
            except Exception as e:
                print(f"[-] Error checking inactivity: {e}")
            
            # Sleep for 5 minutes
            for _ in range(30):  # Check every 10 seconds if server is still active
                if not self.socket_server.active:
                    break
                time.sleep(10)
    
    #===================================
    # Message Handlers
    #===================================
    
    def handle_login(self, message, connection_info):
        """Handle login message"""
        params = message.get('params', {})
        username = params.get('username')
        password = params.get('password')
        port = params.get('port')  # Extract the port parameter
        
        if not username or not password:
            return {'status': 'error', 'message': 'Username and password required'}
        
        client_ip = connection_info['address'][0]
        
        # Use firewall to validate login
        status, error_message = firewall.check_login(username, password, client_ip, port)
        
        if error_message:
            return {'status': status, 'message': error_message}
        return {'status': status}
    
    def handle_signup(self, message, connection_info):
        """Handle signup message"""
        params = message.get('params', {})
        username = params.get('username')
        password = params.get('password')
        
        if not username or not password:
            return {'status': 'error', 'message': 'Username and password required'}
        
        if len(username) < 3 or len(password) < 3:
            return {'status': 'error', 'message': 'Username and password must be at least 3 characters'}
        
        # Use firewall to create user
        success, message = firewall.create_user(username, password)
        
        if success:
            return {'status': 'success', 'message': message}
        else:
            return {'status': 'error', 'message': message}
    
    def handle_logout(self, message, connection_info):
        """Handle logout message"""
        params = message.get('params', {})
        username = params.get('username')
        
        if username:
            firewall.logout_user(username)
        
        return {'status': 'success', 'message': 'Logged out successfully'}
    
    def handle_update_activity(self, message, connection_info):
        """Handle update activity message"""
        params = message.get('params', {})
        username = params.get('username')
        
        if not username:
            return {'status': 'error', 'message': 'Username required'}
        
        if firewall.update_activity(username):
            return {'status': 'updated'}
        return {'status': 'error', 'message': 'User not found'}
    
    def handle_get_attackers(self, message, connection_info):
        """Handle get attackers message"""
        attackers = firewall.get_attackers()
        return {'status': 'success', 'data': attackers}
    
    def handle_get_potential_attackers(self, message, connection_info):
        """Handle get potential attackers message"""
        potential_attackers = firewall.get_potential_attackers()
        return {'status': 'success', 'data': potential_attackers}
    
    def handle_ban_ip(self, message, connection_info):
        """Handle ban IP message"""
        params = message.get('params', {})
        ip_address = params.get('ip')
        
        if not ip_address:
            return {'status': 'error', 'message': 'IP address required'}
        
        if firewall.ban_ip(ip_address):
            print(f"[SERVER] IP {ip_address} has been banned by admin from {connection_info['address'][0]}")
            return {'status': 'success', 'message': f'IP {ip_address} has been banned'}
        return {'status': 'error', 'message': 'Failed to ban IP'}
    
    def handle_unban_ip(self, message, connection_info):
        """Handle unban IP message"""
        params = message.get('params', {})
        ip_address = params.get('ip')
        
        if not ip_address:
            return {'status': 'error', 'message': 'IP address required'}
        
        if firewall.unban_ip(ip_address):
            print(f"[SERVER] IP {ip_address} has been unbanned by admin from {connection_info['address'][0]}")
            return {'status': 'success', 'message': f'IP {ip_address} has been unbanned'}
        return {'status': 'error', 'message': 'Failed to unban IP'}
    
    def handle_get_banned_ips(self, message, connection_info):
        """Handle get banned IPs message"""
        banned_ips = firewall.get_banned_ips()
        return {'status': 'success', 'data': banned_ips}
    
    def handle_get_active_users(self, message, connection_info):
        """Handle get active users message"""
        active_users = firewall.get_active_users()
        return {'status': 'success', 'data': active_users}
    
    def handle_get_ports(self, message, connection_info):
        """Handle get ports message"""
        ports = firewall.get_ports()
        return {'status': 'success', 'data': ports}
    
    def handle_update_port(self, message, connection_info):
        """Handle update port message"""
        params = message.get('params', {})
        port = params.get('port')
        status = params.get('status')
        honeypot = params.get('honeypot')
        
        if not port:
            return {'status': 'error', 'message': 'Port required'}
        
        if firewall.toggle_port_status(port, status, honeypot):
            # If port status was changed, update port stealth settings
            if status is not None:
                try:
                    is_active = (status == "active")
                    #port_stealth.update_port_visibility(port, is_active)
                    print(f"[SERVER] Port {port} status changed to {status} by admin from {connection_info['address'][0]}")
                except Exception as e:
                    print(f"[-] Error updating port visibility: {e}")
            
            # If honeypot status was changed
            if honeypot is not None:
                honeypot_status = "enabled" if honeypot else "disabled"
                print(f"[SERVER] Honeypot {honeypot_status} for port {port} by admin from {connection_info['address'][0]}")
            
            return {'status': 'success', 'message': 'Port updated'}
        return {'status': 'error', 'message': 'Port not found'}

# Main function to run the server
def main():
    try:
        print("=" * 60)
        print("🛡️  HoneyTrap Firewall Server")
        print("=" * 60)
        
        # Display network information to help with multi-PC setup
        try:
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"Server hostname: {hostname}")
            print(f"Server local IP: {local_ip}")
        except Exception as e:
            print(f"Error getting network info: {e}")
        
        # Sync all ports with firewall rules for stealth
        #try:
        #    port_stealth.sync_all_ports()
        #    print("[+] Port stealth feature initialized")
        #except Exception as e:
        #    print(f"[-] Warning: Port stealth initialization error: {e}")
        
        # Start the server with SSL disabled
        # To run on multiple PCs, use host='0.0.0.0' to listen on all network interfaces
        server = HoneyTrapServer(host='0.0.0.0', control_port=5000, data_port=5001)
        
        if server.start():
            print("[+] HoneyTrap Server started successfully")
            print("[+] Ready to accept connections")
            print("=" * 60)
            
            try:
                # Keep the main thread running
                while server.socket_server.active:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Shutting down server...")
            finally:
                server.stop()
                print("[*] Server shutdown complete")
                import sys
                sys.exit(0)
        else:
            print("[-] Failed to start HoneyTrap Server")
            import sys
            sys.exit(1)
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        import sys
        sys.exit(1)

# Add logout_user to firewall.py if it doesn't exist
if not hasattr(firewall, 'logout_user'):
    def logout_user(username):
        """Remove a user's session when they log out properly"""
        sessions = firewall.load_json(firewall.SESSIONS_DB)
        if username in sessions:
            # Remove the session entry
            del sessions[username]
            firewall.save_json(firewall.SESSIONS_DB, sessions)
            return True
        return False
    
    # Add the function to the firewall module
    firewall.logout_user = logout_user

# This makes sure the server starts when the script is executed directly
if __name__ == "__main__":
    # Print debug info for troubleshooting
    print("Debug: Starting server main function")
    main()
    print("Debug: Server function returned")