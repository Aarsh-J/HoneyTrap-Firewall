# ===============================
# Enhanced HoneyTrap Socket Server
# ===============================
import socket
import threading
import json
import logging
import time
import select
import signal
import ssl
import sys

from . import config
from . import tls
from .protocol import send_framed, recv_framed

logger = logging.getLogger(__name__)

class EnhancedSocketServer:
    def __init__(self, host=None, control_port=None, data_port=None,
                 use_ssl=False, certfile=None, keyfile=None):
        """Initialize the socket server with separate control and data ports"""
        self.host = host or config.BIND_HOST
        self.control_port = control_port or config.CONTROL_PORT
        self.data_port = data_port or config.DATA_PORT

        # Create sockets
        self.control_socket = None
        self.data_socket = None

        # SSL context (None means plaintext)
        certfile = certfile or config.CERT_PATH
        keyfile = keyfile or config.KEY_PATH
        self.ssl_context = tls.get_server_ssl_context(certfile, keyfile) if use_ssl else None

        # Connection lists
        self.control_connections = []
        self.data_connections = []

        # Message handlers
        self.message_handlers = {}

        # Optional hook for a malformed (non-JSON) message from a client -
        # kept as a callback rather than a direct firewall.py import so this
        # transport class stays application-agnostic.
        self.on_malformed_message = None

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
            logger.error(f"Socket bind error: {e}")
            return False

    def register_handler(self, command, handler_function):
        """Register a function to handle a specific command"""
        self.message_handlers[command] = handler_function

    def register_malformed_message_handler(self, handler_function):
        """Register a function called with connection_info whenever a
        client sends a non-JSON / unparseable message."""
        self.on_malformed_message = handler_function

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
            logger.warning(f"Retry {retry_count}/{max_retries} in {backoff_time} seconds...")
            time.sleep(backoff_time)

        logger.error("Failed to start server after multiple retries")
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
                        logger.error("Error accepting connection")
                    continue

                sock.settimeout(None)

                # If TLS is enabled, complete the handshake before treating
                # this as a usable connection. A bad handshake (e.g. a plain
                # nmap probe, not a real TLS client) should just drop this
                # one connection, not take down the accept loop.
                if self.ssl_context:
                    try:
                        client_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    except ssl.SSLError:
                        logger.warning(f"TLS handshake failed for {client_address[0]}:{client_address[1]}")
                        client_socket.close()
                        continue

                    # A bounded read timeout so a spurious select() wake-up
                    # (e.g. TLS control-layer bytes with no application data
                    # behind them) can't block this connection's handler
                    # thread forever - see the note in handle_client_messages().
                    client_socket.settimeout(2.0)

                logger.info(f"New {channel_type} connection from {client_address[0]}:{client_address[1]}")

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
                    # With TLS, select() reporting a socket "readable"
                    # doesn't guarantee an application message is waiting -
                    # TLS control-layer bytes (e.g. a post-handshake session
                    # ticket) can make the raw fd readable even though no
                    # decrypted application data follows. A blocking recv()
                    # there would hang; the per-socket timeout (set in
                    # accept_connections()) turns that into a caught
                    # socket.timeout so we just go back to select().
                    #
                    # Separately, a TLS socket can already hold more
                    # decrypted application data than select() will report
                    # as readable a second time, since select() only sees
                    # bytes still sitting on the raw fd, not what the SSL
                    # layer has already buffered. Drain everything pending()
                    # reports before going back to select(), or a second
                    # request arriving in the same TLS record as the first
                    # can sit unread until new bytes happen to arrive on the
                    # wire.
                    while True:
                        try:
                            message = recv_framed(client_socket)
                        except socket.timeout:
                            # Spurious wake-up (see note above) with no real
                            # message behind it - just go back to select().
                            break
                        except json.JSONDecodeError:
                            response = {'status': 'error', 'message': "Invalid request format"}
                            self.send_message(client_socket, response)
                            if self.on_malformed_message:
                                try:
                                    self.on_malformed_message(connection_info)
                                except Exception:
                                    logger.error("Error in malformed-message handler", exc_info=True)
                            break

                        if message is None:
                            # Client disconnected
                            self.close_connection(connection_info)
                            return

                        # Update last activity time
                        connection_info['last_activity'] = time.time()

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

                        if not (isinstance(client_socket, ssl.SSLSocket) and client_socket.pending() > 0):
                            break

            except ConnectionError:
                self.close_connection(connection_info)
                break

            except Exception:
                self.close_connection(connection_info)
                break

    def send_message(self, client_socket, message):
        """Send a JSON message to a client"""
        try:
            send_framed(client_socket, message)
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
        logger.info("Received termination signal, shutting down...")
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

        logger.info("Server shutdown complete")
