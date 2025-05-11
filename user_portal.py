# HoneyTrap User Portal
# ===============================
import tkinter as tk
import time
import threading
import random
import sys
import os
import subprocess
import socket

# Import socket adapter
from adapter import UserHandler, open_socket_fake_portal

# ========================
# User Portal Class
# ========================
class UserPortal:
    def __init__(self, root, port):
        self.root = root
        self.root.title(f"User Portal - Port {port}")
        self.port = port
        self.root.geometry("600x500")

        # Main content
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill="both", expand=True)
        
        # Header
        tk.Label(self.main_frame, text=f"HoneyTrap Firewall", font=("Arial", 16, "bold")).pack(pady=10)
        tk.Label(self.main_frame, text=f"Connected to Port {port}", font=("Arial", 12)).pack(pady=5)
        tk.Label(self.main_frame, text="Secured Connection", font=("Arial", 10)).pack()
        
        # Create a frame for the project information with scrollbar
        info_frame = tk.Frame(self.main_frame)
        info_frame.pack(pady=10, fill="both", expand=True, padx=20)
        
        # Add scrollbar
        scrollbar = tk.Scrollbar(info_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Add text widget for project description
        self.info_text = tk.Text(info_frame, wrap="word", height=15, 
                                 yscrollcommand=scrollbar.set, 
                                 padx=10, pady=10)
        self.info_text.pack(fill="both", expand=True)
        scrollbar.config(command=self.info_text.yview)
        
        # Add project information
        self.add_project_info()
        
        # Make text read-only
        self.info_text.config(state="disabled")
        
        # Logout button at bottom
        button_frame = tk.Frame(self.main_frame)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Refresh", command=self.refresh_status, width=10).pack(side="left", padx=10)
        tk.Button(button_frame, text="Logout", command=self.logout, width=10).pack(side="left", padx=10)
        
        # Status label
        self.status_label = tk.Label(self.main_frame, text="")
        self.status_label.pack(pady=10)
        
        # Start activity update thread
        self.keep_alive_thread = threading.Thread(target=self.keep_session_alive, daemon=True)
        self.keep_alive_thread.start()

    def add_project_info(self):
        """Add project description to the text widget"""
        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        
        project_info = """
🛡️ HoneyTrap Firewall Project 🛡️

Welcome to the HoneyTrap Firewall system! This project implements an advanced security mechanism to detect and monitor potential network attackers.

Project Features:
-----------------

1. Multi-Server/Client Architecture
   • Supports any number of servers and clients
   • Parallel channels for data and control transmission
   • No rewriting or recompiling code required
   • Custom socket handling without third-party libraries

2. User Authentication System
   • Secure login/signup mechanism
   • Session tracking and management
   • Real-time activity monitoring

3. Advanced Port Management
   • Port visibility control (hides ports from nmap scans)
   • Individual port status (active/inactive)
   • Honeypot capability per port

4. Honeypot Technology
   • Configurable honeypots that can be enabled per port
   • Automatic redirection to fake interfaces
   • Attacker information collection

5. Attacker Detection and Monitoring
   • Failed login attempt tracking
   • Automatic flagging of suspicious behavior
   • IP banning capability
   • Inactivity monitoring

6. SSL Implementation
   • Secure communications
   • Self-signed certificate generation
   • Proper SSL socket wrapping

7. Graceful Termination
   • Proper connection cleanup
   • No bind errors on restart
   • Signal handling

8. Administrator Controls
   • Real-time monitoring dashboard
   • Attacker logs and IP management
   • Port configuration controls
   • System status overview

How The System Works:
---------------------
When a user attempts to log in, their credentials and behavior are analyzed by the firewall rules engine. If suspicious activity is detected (multiple failed logins, unusual connection patterns), the system can automatically enable honeypot mode for the port they're connecting to.

In honeypot mode, users are redirected to a fake interface that appears legitimate but actually monitors their actions and collects information. This allows administrators to study potential attack patterns while keeping the real system safe.

The port stealth feature implements RST packet handling to make inactive ports invisible to network scanning tools like nmap, adding another layer of security.

Thank you for using the HoneyTrap Firewall system!
"""
        self.info_text.insert(tk.END, project_info)
        self.info_text.config(state="disabled")

    def logout(self):
        """Close this window and return to login page"""
        self.root.destroy()
        # Start the main application again
        script_dir = os.path.dirname(os.path.abspath(__file__))
        main_path = os.path.join(script_dir, "main.py")
        
        # Check if we're running from .py file or executable
        if getattr(sys, 'frozen', False):
            # If running as executable (compiled version)
            main_executable = sys.executable
            subprocess.Popen([main_executable])
        else:
            # If running as script
            python_executable = sys.executable
            subprocess.Popen([python_executable, main_path])
    
    def keep_session_alive(self):
        """Periodically update activity to prevent inactivity timeout"""
        while True:
            time.sleep(60)  # Every minute
            try:
                # Use socket adapter instead of HTTP
                UserHandler.update_activity("user")
            except:
                # Silently fail if server is unreachable
                pass

    def refresh_status(self):
        """Check current port and user status from server and react accordingly"""
        try:
            # Update the status label
            self.status_label.config(text="Checking server status...", fg="blue")
            self.root.update()
            
            # 1. Get the current port status
            client = UserHandler.get_client_instance()
            if not client:
                self.status_label.config(text="Could not connect to server", fg="red")
                return
                
            # 2. Check if IP is banned
            banned_ips = client.get_banned_ips()
            local_ip = "127.0.0.1"  # Fallback value
            try:
                import socket
                local_ip = socket.gethostbyname(socket.gethostname())
            except:
                pass
                
            if local_ip in banned_ips:
                self.status_label.config(text="Redirecting to security page...", fg="red")
                self.root.after(1500, self.redirect_to_fake)
                return
                
            # 3. Check port status
            ports = client.get_ports()
            current_port = None
            for port_info in ports:
                if port_info["port"] == self.port:
                    current_port = port_info
                    break
                    
            if not current_port:
                self.status_label.config(text="Port no longer exists", fg="red")
                self.root.after(1500, self.logout)
                return
                
            # Check if port is disabled
            if current_port["status"] == "inactive":
                self.status_label.config(text="Port has been disabled", fg="red")
                self.root.after(1500, self.logout)
                return
                
            # Check if honeypot is enabled
            if current_port.get("honeypot", False):
                self.status_label.config(text="Redirecting to security page...", fg="red")
                self.root.after(1500, self.redirect_to_fake)
                return
                
            # All checks passed
            self.status_label.config(text="Connection is secure", fg="green")
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}", fg="red")
            
    def redirect_to_fake(self):
        """Redirect to fake portal"""
        # Close current window
        self.root.destroy()
        
        # Open fake portal with current port
        open_socket_fake_portal(self.port)# ===============================


# ========================
# Fake Portal Class
# ========================
class FakePortal:
    def __init__(self, root, port):
        self.root = root
        self.root.title(f"User Portal - Port {port}")
        self.port = port
        self.root.geometry("500x350")
        
        # Main content
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill="both", expand=True)
        
        tk.Label(self.main_frame, text=f"HoneyTrap Firewall", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.main_frame, text=f"Connected to Port {port}", font=("Arial", 12)).pack(pady=5)
        tk.Label(self.main_frame, text="Establishing secure connection...", font=("Arial", 10)).pack()
        
        # Create a progress bar
        self.progress = tk.StringVar()
        self.progress.set("Loading security modules... (0%)")
        tk.Label(self.main_frame, textvariable=self.progress).pack(pady=20)
        
        self.progress_bar = tk.Canvas(self.main_frame, width=300, height=20)
        self.progress_bar.pack(pady=5)
        self.progress_bar.create_rectangle(0, 0, 0, 20, fill="green", tags="progress")
        
        # Status message
        self.status_label = tk.Label(self.main_frame, text="Please wait while system configures...", fg="blue")
        self.status_label.pack(pady=10)
        
        # Create a fake loading process
        self.progress_value = 0
        self.root.after(1000, self.update_progress)
        
        # Collect data about the "attacker"
        self.collect_info()
    
    def update_progress(self):
        """Simulate a slow loading process"""
        if self.progress_value < 100:
            self.progress_value += random.randint(1, 5)
            if self.progress_value > 100:
                self.progress_value = 100
            
            # Update progress bar
            self.progress_bar.coords("progress", 0, 0, 3 * self.progress_value, 20)
            self.progress.set(f"Loading security modules... ({self.progress_value}%)")
            
            # Random delay for next update
            delay = random.randint(500, 1500)
            self.root.after(delay, self.update_progress)
            
            # Occasionally show "issues" in the status
            if random.random() < 0.2:
                statuses = [
                    "Synchronizing network configuration...",
                    "Validating credentials...",
                    "Security module load delayed...",
                    "Checking port availability...",
                    "Waiting for server response..."
                ]
                self.status_label.config(text=random.choice(statuses))
        else:
            # Finished loading
            self.status_label.config(text="System error: Connection reset. Please try again later.", fg="red")
            # Add a logout button
            tk.Button(self.main_frame, text="Close Connection", command=self.logout).pack(pady=20)
    
    def collect_info(self):
        """Collect information about the system (simulated)"""
        try:
            # Use socket adapter instead of HTTP
            UserHandler.update_activity("attacker")
        except:
            # Silently fail if server is unreachable
            pass
            
    def logout(self):
        """Close this window and return to login page"""
        self.root.destroy()
        # Start the main application again
        script_dir = os.path.dirname(os.path.abspath(__file__))
        main_path = os.path.join(script_dir, "main.py")
        
        # Check if we're running from .py file or executable
        if getattr(sys, 'frozen', False):
            # If running as executable (compiled version)
            main_executable = sys.executable
            subprocess.Popen([main_executable])
        else:
            # If running as script
            python_executable = sys.executable
            subprocess.Popen([python_executable, main_path])

# ----------------------
# Launch Functions
# ----------------------
def open_user_portal(port):
    root = tk.Tk()
    app = UserPortal(root, port)
    root.mainloop()

def open_fake_portal(port):
    root = tk.Tk()
    app = FakePortal(root, port)
    root.mainloop()