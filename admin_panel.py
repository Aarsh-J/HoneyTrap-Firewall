# ===============================
# HoneyTrap Admin Panel
# ===============================
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import time
import threading

# Import socket adapter
from adapter import AdminHandler

# ========================
# Admin Panel Class
# ========================
class AdminPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.pack(fill="both", expand=True)
        self.create_widgets()

        # Initial data load
        self.view_logs()
        self.view_ports(latest_only=True)
        
        # Auto-refresh data every 30 seconds
        self.start_auto_refresh()

    # ----------------------
    # UI Setup
    # ----------------------
    def create_widgets(self):
        self.master.title("HoneyTrap Admin Panel")
        self.master.geometry("1000x600")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Tab 1: Attackers Management (merged attackers and potential attackers)
        self.attackers_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attackers_tab, text="Attackers Management")
        
        # Tab 2: Active Users
        self.users_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.users_tab, text="Active Users")
        
        # Tab 3: Ports Management
        self.ports_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.ports_tab, text="Ports Management")
        
        # Tab 4: System Status
        self.status_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.status_tab, text="System Status")
        
        # Set up each tab's content
        self.setup_attackers_tab()
        self.setup_users_tab()
        self.setup_ports_tab()
        self.setup_status_tab()
        
        # Add logout button at the bottom
        tk.Button(self, text="Logout", command=self.logout).pack(pady=10)

    # ----------------------
    # Tab Setup Methods
    # ----------------------
    def setup_attackers_tab(self):
        """Setup the merged attackers management tab"""
        # Use a notebook inside this tab to organize content
        attackers_notebook = ttk.Notebook(self.attackers_tab)
        attackers_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Sub-tab 1: All Attackers
        attackers_tab = ttk.Frame(attackers_notebook)
        attackers_notebook.add(attackers_tab, text="All Attackers")
        
        # Sub-tab 2: Banned IPs
        banned_tab = ttk.Frame(attackers_notebook)
        attackers_notebook.add(banned_tab, text="Banned IPs")
        
        # Setup All Attackers sub-tab
        tk.Label(attackers_tab, text="Attacker Activities", font=("Arial", 16)).pack(pady=10)
        
        # Create Treeview for logs
        columns = ("timestamp", "username", "ip", "port", "reason")
        self.log_table = ttk.Treeview(attackers_tab, columns=columns, show="headings")

        for col in columns:
            self.log_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.log_table.column("timestamp", width=150, anchor="center")
        self.log_table.column("username", width=100, anchor="center")
        self.log_table.column("ip", width=100, anchor="center")
        self.log_table.column("port", width=80, anchor="center")
        self.log_table.column("reason", width=200, anchor="center")

        self.log_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a scroll bar
        scrollbar = ttk.Scrollbar(attackers_tab, orient="vertical", command=self.log_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_table.configure(yscrollcommand=scrollbar.set)
        
        # Button frame for attackers
        button_frame = tk.Frame(attackers_tab)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Refresh", command=self.view_logs).pack(side="left", padx=5)
        tk.Button(button_frame, text="Ban Selected IP", command=self.ban_selected_attacker).pack(side="left", padx=5)
        
        # Setup Banned IPs sub-tab
        tk.Label(banned_tab, text="Banned IP Addresses", font=("Arial", 16)).pack(pady=10)
        
        # Create Treeview for banned IPs
        columns = ("ip", "actions")
        self.banned_table = ttk.Treeview(banned_tab, columns=columns, show="headings")

        for col in columns:
            self.banned_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.banned_table.column("ip", width=150, anchor="center")
        self.banned_table.column("actions", width=100, anchor="center")

        self.banned_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a scroll bar
        scrollbar = ttk.Scrollbar(banned_tab, orient="vertical", command=self.banned_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.banned_table.configure(yscrollcommand=scrollbar.set)
        
        # Actions frame for banned IPs
        action_frame = tk.Frame(banned_tab)
        action_frame.pack(pady=10)
        
        tk.Button(action_frame, text="Refresh", command=self.view_banned_ips).pack(side="left", padx=5)
        tk.Button(action_frame, text="Unban Selected IP", command=self.unban_selected_ip).pack(side="left", padx=5)
        
        # Load initial data
        self.view_banned_ips()
    
    def setup_users_tab(self):
        """Setup the active users tab with ban functionality"""
        tk.Label(self.users_tab, text="Active Users", font=("Arial", 16)).pack(pady=10)
        
        # Create Treeview for active users
        columns = ("username", "ip", "port", "login_time", "last_activity", "session_length", "inactive_for")
        self.users_table = ttk.Treeview(self.users_tab, columns=columns, show="headings")

        for col in columns:
            self.users_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.users_table.column("username", width=100, anchor="center")
        self.users_table.column("ip", width=100, anchor="center")
        self.users_table.column("port", width=80, anchor="center")
        self.users_table.column("login_time", width=150, anchor="center")
        self.users_table.column("last_activity", width=150, anchor="center")
        self.users_table.column("session_length", width=100, anchor="center")
        self.users_table.column("inactive_for", width=100, anchor="center")

        self.users_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a scroll bar
        scrollbar = ttk.Scrollbar(self.users_tab, orient="vertical", command=self.users_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.users_table.configure(yscrollcommand=scrollbar.set)
        
        # Actions frame
        action_frame = tk.Frame(self.users_tab)
        action_frame.pack(pady=10)
        
        tk.Button(action_frame, text="Refresh", command=self.view_active_users).pack(side="left", padx=5)
        tk.Button(action_frame, text="Ban Selected User", command=self.ban_selected_user).pack(side="left", padx=5)
        
        # Load initial data
        self.view_active_users()

    def setup_ports_tab(self):
        """Setup ports tab with table selection"""
        # Title
        tk.Label(self.ports_tab, text="Ports Configuration", font=("Arial", 16)).pack(pady=10)
        
        # Create frame for ports table and actions
        ports_frame = tk.Frame(self.ports_tab)
        ports_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create table for ports on the left
        ports_list_frame = tk.Frame(ports_frame)
        ports_list_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Create actions frame on the right
        port_actions_frame = tk.Frame(ports_frame)
        port_actions_frame.pack(side="right", fill="y", padx=5, pady=5)
        
        # Ports treeview
        columns_ports = ("port", "status", "honeypot", "last_triggered")
        self.port_table = ttk.Treeview(ports_list_frame, columns=columns_ports, show="headings")

        for col in columns_ports:
            self.port_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.port_table.column("port", width=100, anchor="center")
        self.port_table.column("status", width=100, anchor="center")
        self.port_table.column("honeypot", width=100, anchor="center")
        self.port_table.column("last_triggered", width=150, anchor="center")

        self.port_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a scroll bar
        scrollbar = ttk.Scrollbar(ports_list_frame, orient="vertical", command=self.port_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.port_table.configure(yscrollcommand=scrollbar.set)
        
        # Action buttons for the selected port
        tk.Label(port_actions_frame, text="Port Actions:", font=("Arial", 12)).pack(pady=10)
        tk.Button(port_actions_frame, text="Enable Port", command=lambda: self.toggle_port_status("active")).pack(pady=5, fill="x")
        tk.Button(port_actions_frame, text="Disable Port", command=lambda: self.toggle_port_status("inactive")).pack(pady=5, fill="x")
        tk.Button(port_actions_frame, text="Enable Honeypot", command=lambda: self.toggle_honeypot(True)).pack(pady=5, fill="x")
        tk.Button(port_actions_frame, text="Disable Honeypot", command=lambda: self.toggle_honeypot(False)).pack(pady=5, fill="x")
        
        # View options
        button_frame = tk.Frame(self.ports_tab)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="View All Ports", command=self.view_ports_full).pack(side="left", padx=5)
        tk.Button(button_frame, text="View Active Ports", command=lambda: self.view_ports(latest_only=False)).pack(side="left", padx=5)
        tk.Button(button_frame, text="View Disabled Ports", command=self.view_disabled_ports).pack(side="left", padx=5)
        
        # Load initial data
        self.view_ports()

    def setup_status_tab(self):
        tk.Label(self.status_tab, text="System Status", font=("Arial", 16)).pack(pady=10)
        
        # System info frame
        info_frame = tk.Frame(self.status_tab)
        info_frame.pack(pady=20, fill="x")
        
        # Status indicators
        self.server_status = tk.StringVar(value="Checking...")
        self.active_ports = tk.StringVar(value="0")
        self.honeypot_ports = tk.StringVar(value="0")
        self.attacker_count = tk.StringVar(value="0")
        self.potential_count = tk.StringVar(value="0")
        self.banned_count = tk.StringVar(value="0")
        self.user_count = tk.StringVar(value="0")
        
        # Display in a grid
        status_grid = tk.Frame(info_frame)
        status_grid.pack()
        
        # Row 1
        tk.Label(status_grid, text="Server Status:", font=("Arial", 12)).grid(row=0, column=0, sticky="w", pady=5, padx=10)
        tk.Label(status_grid, textvariable=self.server_status, font=("Arial", 12)).grid(row=0, column=1, sticky="w", pady=5, padx=10)
        
        # Row 2
        tk.Label(status_grid, text="Active Ports:", font=("Arial", 12)).grid(row=1, column=0, sticky="w", pady=5, padx=10)
        tk.Label(status_grid, textvariable=self.active_ports, font=("Arial", 12)).grid(row=1, column=1, sticky="w", pady=5, padx=10)
        
        # Row 3
        tk.Label(status_grid, text="Honeypot Enabled:", font=("Arial", 12)).grid(row=2, column=0, sticky="w", pady=5, padx=10)
        tk.Label(status_grid, textvariable=self.honeypot_ports, font=("Arial", 12)).grid(row=2, column=1, sticky="w", pady=5, padx=10)
        
        # Row 4
        tk.Label(status_grid, text="Attackers Detected:", font=("Arial", 12)).grid(row=3, column=0, sticky="w", pady=5, padx=10)
        tk.Label(status_grid, textvariable=self.attacker_count, font=("Arial", 12)).grid(row=3, column=1, sticky="w", pady=5, padx=10)
        
        # Row 5
        tk.Label(status_grid, text="Potential Attackers:", font=("Arial", 12)).grid(row=4, column=0, sticky="w", pady=5, padx=10)
        tk.Label(status_grid, textvariable=self.potential_count, font=("Arial", 12)).grid(row=4, column=1, sticky="w", pady=5, padx=10)
        
        # Row 6
        tk.Label(status_grid, text="Banned IPs:", font=("Arial", 12)).grid(row=5, column=0, sticky="w", pady=5, padx=10)
        tk.Label(status_grid, textvariable=self.banned_count, font=("Arial", 12)).grid(row=5, column=1, sticky="w", pady=5, padx=10)
        
        # Row 7
        tk.Label(status_grid, text="Active Users:", font=("Arial", 12)).grid(row=6, column=0, sticky="w", pady=5, padx=10)
        tk.Label(status_grid, textvariable=self.user_count, font=("Arial", 12)).grid(row=6, column=1, sticky="w", pady=5, padx=10)
        
        # Refresh button
        tk.Button(self.status_tab, text="Refresh Status", command=self.update_system_status).pack(pady=20)

    # ----------------------
    # Auto-refresh Functionality
    # ----------------------
    def start_auto_refresh(self):
        """Start auto-refresh thread"""
        self.auto_refresh_thread = threading.Thread(target=self._auto_refresh_worker, daemon=True)
        self.auto_refresh_thread.start()
    
    def _auto_refresh_worker(self):
        """Background thread to refresh data periodically"""
        while True:
            try:
                # Update UI in the main thread
                self.master.after(0, self.view_logs)  
                self.master.after(0, self.view_ports, True)
                self.master.after(0, self.update_system_status)
                self.master.after(0, self.view_banned_ips)
                self.master.after(0, self.view_active_users)
            except Exception:
                pass
            
            # Wait for 30 seconds
            time.sleep(30)

    # ----------------------
    # Attacker Management
    # ----------------------
    def view_logs(self):
        try:
            # Get attackers and potential attackers via socket
            attackers = AdminHandler.get_attackers()
            potential_attackers = AdminHandler.get_potential_attackers()
            
            # Combine both lists
            all_attackers = attackers + potential_attackers
            
            # Sort by timestamp descending
            all_attackers.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        except Exception:
            messagebox.showerror("Error", "Failed to fetch attackers")
            return

        for item in self.log_table.get_children():
            self.log_table.delete(item)

        for entry in all_attackers:
            self.log_table.insert("", "end", values=(
                entry.get("timestamp", "N/A"),
                entry.get("username", "N/A"),
                entry.get("ip", "N/A"),
                entry.get("attempted_port", "N/A"),
                entry.get("reason", "N/A"),
            ))

    def ban_selected_attacker(self):
        selected_item = self.log_table.selection()
        if not selected_item:
            messagebox.showwarning("Select Entry", "Please select an entry to ban.")
            return
        
        # Get the IP from the selected item
        ip = self.log_table.item(selected_item[0])['values'][2]  # IP is at index 2
        
        try:
            result = AdminHandler.ban_ip(ip)
            if result:
                messagebox.showinfo("Success", f"IP {ip} has been banned.")
                # Print to terminal
                print(f"[ADMIN] IP {ip} has been banned")
                self.view_logs()
                self.view_banned_ips()
            else:
                messagebox.showerror("Error", "Failed to ban IP")
        except Exception:
            messagebox.showerror("Error", "Failed to ban IP")

    # ----------------------
    # Banned IPs Management
    # ----------------------
    def view_banned_ips(self):
        try:
            banned_ips = AdminHandler.get_banned_ips()
        except Exception:
            messagebox.showerror("Error", "Failed to fetch banned IPs")
            return

        for item in self.banned_table.get_children():
            self.banned_table.delete(item)

        for ip in banned_ips:
            self.banned_table.insert("", "end", values=(ip, "Unban"))
    
    def unban_selected_ip(self):
        selected_item = self.banned_table.selection()
        if not selected_item:
            messagebox.showwarning("Select Entry", "Please select an IP to unban.")
            return
        
        # Get the IP from the selected item
        ip = self.banned_table.item(selected_item[0])['values'][0]
        
        try:
            result = AdminHandler.unban_ip(ip)
            if result:
                messagebox.showinfo("Success", f"IP {ip} has been unbanned.")
                # Print to terminal
                print(f"[ADMIN] IP {ip} has been unbanned")
                self.view_banned_ips()
            else:
                messagebox.showerror("Error", "Failed to unban IP")
        except Exception:
            messagebox.showerror("Error", "Failed to unban IP")

    # ----------------------
    # Active Users Management
    # ----------------------
    def view_active_users(self):
        try:
            active_users = AdminHandler.get_active_users()
        except Exception:
            messagebox.showerror("Error", "Failed to fetch active users")
            return

        for item in self.users_table.get_children():
            self.users_table.delete(item)

        for user in active_users:
            self.users_table.insert("", "end", values=(
                user.get("username", "N/A"),
                user.get("ip", "N/A"),
                user.get("port", "N/A"),
                user.get("login_time", "N/A"),
                user.get("last_activity", "N/A"),
                user.get("session_length", "N/A"),
                user.get("inactive_for", "N/A")
            ))

    def ban_selected_user(self):
        """Ban the IP of the selected user"""
        selected_item = self.users_table.selection()
        if not selected_item:
            messagebox.showwarning("Select User", "Please select a user to ban.")
            return
        
        # Get the IP from the selected item
        ip = self.users_table.item(selected_item[0])['values'][1]  # IP is at index 1
        
        if messagebox.askyesno("Confirm Ban", f"Are you sure you want to ban IP {ip}?"):
            try:
                result = AdminHandler.ban_ip(ip)
                if result:
                    messagebox.showinfo("Success", f"IP {ip} has been banned.")
                    # Print to terminal
                    print(f"[ADMIN] IP {ip} has been banned")
                    self.view_active_users()
                    self.view_banned_ips()
                else:
                    messagebox.showerror("Error", "Failed to ban IP")
            except Exception:
                messagebox.showerror("Error", "Failed to ban IP")

    # ----------------------
    # Ports Management
    # ----------------------
    def view_ports(self, latest_only=True):
        try:
            ports = AdminHandler.get_ports()
        except Exception:
            messagebox.showerror("Error", "Failed to fetch ports")
            return

        active_ports = [p for p in ports if p["status"] == "active"]
        if latest_only:
            active_ports = active_ports[:5]

        for item in self.port_table.get_children():
            self.port_table.delete(item)

        for port in active_ports:
            honeypot = "ON" if port.get("honeypot") else "OFF"
            self.port_table.insert("", "end", values=(
                port.get("port", "N/A"),
                port.get("status", "N/A"),
                honeypot,
                port.get("last_triggered", "N/A")
            ))

    def view_ports_full(self):
        try:
            ports = AdminHandler.get_ports()
        except Exception:
            messagebox.showerror("Error", "Failed to fetch ports")
            return

        for item in self.port_table.get_children():
            self.port_table.delete(item)

        for port in ports:
            honeypot = "ON" if port.get("honeypot") else "OFF"
            self.port_table.insert("", "end", values=(
                port.get("port", "N/A"),
                port.get("status", "N/A"),
                honeypot,
                port.get("last_triggered", "N/A")
            ))

    def view_disabled_ports(self):
        try:
            ports = AdminHandler.get_ports()
        except Exception:
            messagebox.showerror("Error", "Failed to fetch ports")
            return

        disabled_ports = [p for p in ports if p["status"] == "inactive"]

        for item in self.port_table.get_children():
            self.port_table.delete(item)

        for port in disabled_ports:
            honeypot = "ON" if port.get("honeypot") else "OFF"
            self.port_table.insert("", "end", values=(
                port.get("port", "N/A"),
                port.get("status", "N/A"),
                honeypot,
                port.get("last_triggered", "N/A")
            ))

    def toggle_port_status(self, status):
        """Toggle port status using table selection"""
        selected_item = self.port_table.selection()
        
        if not selected_item:
            messagebox.showwarning("Select Port", "Please select a port from the table.")
            return
        
        # Get the port from the selected item
        port = self.port_table.item(selected_item[0])['values'][0]  # Port is at index 0
        
        try:
            result = AdminHandler.update_port(int(port), status=status)
            if result:
                action = "enabled" if status == "active" else "disabled"
                messagebox.showinfo("Success", f"Port {port} status set to {status}.")
                # Print to terminal
                print(f"[ADMIN] Port {port} {action}")
                self.view_ports_full()  # Refresh to show all ports
            else:
                messagebox.showerror("Error", "Failed to update port status")
        except Exception:
            messagebox.showerror("Error", "Failed to update port")

    def toggle_honeypot(self, enabled):
        """Toggle honeypot using table selection"""
        selected_item = self.port_table.selection()
        
        if not selected_item:
            messagebox.showwarning("Select Port", "Please select a port from the table.")
            return
        
        # Get the port from the selected item
        port = self.port_table.item(selected_item[0])['values'][0]  # Port is at index 0
        
        try:
            result = AdminHandler.update_port(int(port), honeypot=enabled)
            if result:
                status = "enabled" if enabled else "disabled"
                messagebox.showinfo("Success", f"Honeypot for Port {port} {status}.")
                # Print to terminal
                print(f"[ADMIN] Honeypot {status} for Port {port}")
                self.view_ports_full()  # Refresh to show all ports
            else:
                messagebox.showerror("Error", "Failed to toggle honeypot")
        except Exception:
            messagebox.showerror("Error", "Failed to toggle honeypot")

    # ----------------------
    # System Status
    # ----------------------
    def update_system_status(self):
        """Update the system status indicators"""
        try:
            # Check server status
            try:
                # Check if we can get ports as a connectivity test
                ports = AdminHandler.get_ports()
                self.server_status.set("Online")
                
                # Count active and honeypot ports
                active_count = len([p for p in ports if p["status"] == "active"])
                honeypot_count = len([p for p in ports if p.get("honeypot", False)])
                
                self.active_ports.set(str(active_count))
                self.honeypot_ports.set(str(honeypot_count))
            except:
                self.server_status.set("Offline")
            
            # Get attacker count
            attackers = AdminHandler.get_attackers()
            self.attacker_count.set(str(len(attackers)))
            
            # Get potential attacker count
            potential_attackers = AdminHandler.get_potential_attackers()
            self.potential_count.set(str(len(potential_attackers)))
            
            # Get banned IP count
            banned_ips = AdminHandler.get_banned_ips()
            self.banned_count.set(str(len(banned_ips)))
            
            # Get active user count
            active_users = AdminHandler.get_active_users()
            self.user_count.set(str(len(active_users)))
            
        except Exception:
            self.server_status.set("Error")

    # ----------------------
    # Logout Functionality
    # ----------------------
    def logout(self):
        if hasattr(self.master, 'show_frame'):
            # Using string to avoid circular import issues
            self.master.show_frame("LoginPage")
        else:
            self.master.destroy()