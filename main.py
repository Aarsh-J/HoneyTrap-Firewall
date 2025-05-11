# ===============================
# HoneyTrap Firewall Main Application
# ===============================
import tkinter as tk
from tkinter import messagebox
import random

# Import for user portal
from user_portal import open_user_portal, open_fake_portal

# Import socket adapter
from adapter import LoginHandler, open_socket_user_portal, open_socket_fake_portal

# ========================
# Main Application
# ========================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HoneyTrap Firewall")
        self.geometry("500x350")
        self.frames = {}
        self.show_frame("LoginPage")

    def show_frame(self, cont):
        # Close existing frame if it exists
        if hasattr(self, 'current_frame') and self.current_frame:
            self.current_frame.destroy()
        
        # Create new frame based on string name or class
        if isinstance(cont, str):
            if cont == "LoginPage":
                frame = LoginPage(self)
            elif cont == "SignupPage":
                frame = SignupPage(self)
            elif cont == "AdminPanel":
                # Import here to avoid circular imports
                from admin_panel import AdminPanel
                frame = AdminPanel(self)
            else:
                raise ValueError(f"Unknown frame: {cont}")
        else:
            frame = cont(self)
            
        self.current_frame = frame
        frame.pack(fill="both", expand=True)

# ========================
# Login Page
# ========================
class LoginPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="HoneyTrap Firewall Login", font=("Arial", 16)).pack(pady=20)
        
        tk.Label(self, text="Username:").pack(pady=10)
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        tk.Label(self, text="Password:").pack(pady=10)
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.login_attempts = 0
        
        # Get available ports from server
        self.ports = self.get_active_ports()

        # Button frame for login and signup
        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Login", command=self.login, width=10).pack(side="left", padx=10)
        tk.Button(button_frame, text="Signup", command=self.goto_signup, width=10).pack(side="left", padx=10)
    
    def goto_signup(self):
        self.master.show_frame("SignupPage")
    
    def get_active_ports(self):
        try:
            ports = LoginHandler.get_ports()
            return [p for p in ports if p["status"] == "active"]
        except Exception:
            messagebox.showerror("Error", "Could not connect to server")
            return []

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Basic Validation
        if len(username) < 3 or len(password) < 3:
            messagebox.showerror("Invalid", "Username must be at least 3 and Password at least 3 characters.")
            return
        
        # Assign a random port if available
        if not self.ports:
            messagebox.showerror("Error", "No active ports available")
            return
        
        selected_port = random.choice(self.ports)
        port_number = selected_port["port"]

        # Send Login Request
        try:
            # Use socket adapter with port number
            result = LoginHandler.login(username, password, port_number)
            
            # Handle Login Responses
            if result["status"] == "admin":
                self.master.show_frame("AdminPanel")
            elif result["status"] == "valid":
                # Open user portal with the assigned port
                self.master.destroy()  # Close the login window 
                open_socket_user_portal(port_number, username)
            elif result["status"] == "fake":
                # Open fake portal for potential attackers
                self.master.destroy()  # Close the login window
                open_socket_fake_portal(port_number)
            else:
                messagebox.showwarning("Incorrect", "Incorrect username or password. Try again.")
                self.login_attempts += 1
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")

# ========================
# Signup Page
# ========================
class SignupPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="Create New Account", font=("Arial", 16)).pack(pady=20)
        
        tk.Label(self, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        tk.Label(self, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()
        
        tk.Label(self, text="Confirm Password:").pack(pady=5)
        self.confirm_password_entry = tk.Entry(self, show="*")
        self.confirm_password_entry.pack()

        # Button frame for signup and back
        button_frame = tk.Frame(self)
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Signup", command=self.signup, width=10).pack(side="left", padx=10)
        tk.Button(button_frame, text="Back to Login", command=self.back_to_login, width=15).pack(side="left", padx=10)
    
    def back_to_login(self):
        self.master.show_frame("LoginPage")
    
    def signup(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        # Basic validation
        if len(username) < 3 or len(password) < 3:
            messagebox.showerror("Invalid", "Username and password must be at least 3 characters.")
            return
        
        if password != confirm_password:
            messagebox.showerror("Password Mismatch", "Passwords do not match.")
            return
        
        # Send signup request using socket adapter
        try:
            result = LoginHandler.signup(username, password)
            
            if result["status"] == "success":
                messagebox.showinfo("Success", "Account created successfully! Please login.")
                self.master.show_frame("LoginPage")
            else:
                messagebox.showerror("Error", result.get("message", "Signup failed"))
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")

# ========================
# Main Entry Point
# ========================
if __name__ == "__main__":
    app = App()
    app.mainloop()