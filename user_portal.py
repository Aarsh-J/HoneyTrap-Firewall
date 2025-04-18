# ------------------------ Imports & Setup ------------------------
import tkinter as tk
import requests
import time
import threading
import random
import sys
import os
import subprocess

SERVER_URL = "http://localhost:5000"

# ------------------------ User Portal Class ------------------------
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
        tk.Button(self.main_frame, text="Logout", command=self.logout).pack(pady=20)
        
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

1. User Authentication System
   • Secure login/signup mechanism
   • Session tracking and management
   • Real-time activity monitoring

2. Honeypot Technology
   • Ports can individually have honeypot feature enabled/disabled
   • When honeypot is active, all connections are redirected to a fake interface
   • Automatic attacker detection based on login attempts and behavior

3. Attacker Detection Rules
   • Failed login attempts are tracked and analyzed
   • Users with multiple failed login attempts are flagged as potential attackers
   • Inactive sessions are monitored and can trigger security alerts
   • When a user is flagged as an attacker, honeypot is automatically enabled on their port

4. Port Management
   • Support for multiple ports with individual settings
   • Port status (active/inactive) can be controlled from admin panel
   • Honeypot status can be toggled per port

5. Admin Controls
   • Comprehensive dashboard for system monitoring
   • Real-time attacker logs with detailed information
   • Fine-grained control over port and honeypot settings
   • System status monitoring with key metrics


How Firewall Rules Work:
------------------------
• All ports have honeypot functionality OFF by default for normal operation
• Administrators can manually enable honeypot on specific ports for security testing
• If honeypot is active on a port, all users connecting to that port are directed to a fake interface
• When a user is detected as a potential attacker, honeypot is automatically enabled for their port
• The system logs all suspicious activities including login attempts, credentials used, and timestamps

This project demonstrates advanced security concepts including deception technology, behavior-based threat detection, and real-time security monitoring.

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
                requests.post(f"{SERVER_URL}/update_activity", 
                             json={"username": "user", "port": self.port})
            except:
                # Silently fail if server is unreachable
                pass

# ------------------------ Fake Portal Class ------------------------
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
            # In a real honeypot, this would collect more information about the attacker
            # but for this simulation, we'll just log that the fake portal was accessed
            requests.post(f"{SERVER_URL}/update_activity", 
                         json={"username": "attacker", "port": self.port})
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

# ------------------------ Launch Functions ------------------------
def open_user_portal(port):
    root = tk.Tk()
    app = UserPortal(root, port)
    root.mainloop()

def open_fake_portal(port):
    root = tk.Tk()
    app = FakePortal(root, port)
    root.mainloop()

# ------------------------ Main Entry Point (Test Only) ------------------------
if __name__ == '__main__':
    # Uncomment one of these to test
    # open_user_portal(8001)
    open_fake_portal(8001)
