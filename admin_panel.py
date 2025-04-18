#============Import Libraries=============
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import requests
import time
import threading

#---------------Global Variables---------------------------
SERVER_URL = "http://localhost:5000"

#============AdminPanel Class Definition=============
class AdminPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.pack(fill="both", expand=True)
        self.create_widgets()

        # Initial data load
        self.view_logs(latest_only=True)
        self.view_ports(latest_only=True)
        
        # Auto-refresh data every 30 seconds
        self.start_auto_refresh()

#=================================Widgets================================================
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
        
        # Tab 1: Attacker Logs
        self.attacker_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attacker_tab, text="Attacker Logs")
        
        # Tab 2: Potential Attackers
        self.potential_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.potential_tab, text="Potential Attackers")
        
        # Tab 3: Banned IPs
        self.banned_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.banned_tab, text="Banned IPs")
        
        # Tab 4: Active Users
        self.users_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.users_tab, text="Active Users")
        
        # Tab 5: Ports Management
        self.ports_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.ports_tab, text="Ports Management")
        
        # Tab 6: System Status
        self.status_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.status_tab, text="System Status")
        
        # Set up each tab's content
        self.setup_attacker_tab()
        self.setup_potential_tab()
        self.setup_banned_tab()
        self.setup_users_tab()
        self.setup_ports_tab()
        self.setup_status_tab()
        
        # Add logout button at the bottom
        tk.Button(self, text="Logout", command=self.logout).pack(pady=10)

#==============================Tab Setup Methods==============================
    def setup_attacker_tab(self):
        tk.Label(self.attacker_tab, text="Attacker Activities", font=("Arial", 16)).pack(pady=10)
        
        # Create Treeview for logs
        columns = ("timestamp", "username", "password", "ip", "port", "reason")
        self.log_table = ttk.Treeview(self.attacker_tab, columns=columns, show="headings")

        for col in columns:
            self.log_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.log_table.column("timestamp", width=150, anchor="center")
        self.log_table.column("username", width=100, anchor="center")
        self.log_table.column("password", width=100, anchor="center")
        self.log_table.column("ip", width=100, anchor="center")
        self.log_table.column("port", width=80, anchor="center")
        self.log_table.column("reason", width=200, anchor="center")

        self.log_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a scroll bar
        scrollbar = ttk.Scrollbar(self.attacker_tab, orient="vertical", command=self.log_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_table.configure(yscrollcommand=scrollbar.set)
        
        # Buttons frame
        button_frame = tk.Frame(self.attacker_tab)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="View Latest Logs", command=lambda: self.view_logs(latest_only=True)).pack(side="left", padx=5)
        tk.Button(button_frame, text="View All Logs", command=lambda: self.view_logs(latest_only=False)).pack(side="left", padx=5)

    def setup_potential_tab(self):
        """Setup the potential attackers tab"""
        tk.Label(self.potential_tab, text="Potential Attackers", font=("Arial", 16)).pack(pady=10)
        
        # Create Treeview for potential attackers
        columns = ("timestamp", "username", "ip", "port", "reason", "actions")
        self.potential_table = ttk.Treeview(self.potential_tab, columns=columns, show="headings")

        for col in columns:
            self.potential_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.potential_table.column("timestamp", width=150, anchor="center")
        self.potential_table.column("username", width=100, anchor="center")
        self.potential_table.column("ip", width=100, anchor="center")
        self.potential_table.column("port", width=80, anchor="center")
        self.potential_table.column("reason", width=200, anchor="center")
        self.potential_table.column("actions", width=100, anchor="center")

        self.potential_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a scroll bar
        scrollbar = ttk.Scrollbar(self.potential_tab, orient="vertical", command=self.potential_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.potential_table.configure(yscrollcommand=scrollbar.set)
        
        # Actions frame
        action_frame = tk.Frame(self.potential_tab)
        action_frame.pack(pady=10)
        
        tk.Button(action_frame, text="Refresh", command=self.view_potential_attackers).pack(side="left", padx=5)
        tk.Button(action_frame, text="Ban Selected IP", command=self.ban_selected_ip).pack(side="left", padx=5)
        
        # Load initial data
        self.view_potential_attackers()
    
    def setup_banned_tab(self):
        """Setup the banned IPs tab"""
        tk.Label(self.banned_tab, text="Banned IP Addresses", font=("Arial", 16)).pack(pady=10)
        
        # Create Treeview for banned IPs
        columns = ("ip", "actions")
        self.banned_table = ttk.Treeview(self.banned_tab, columns=columns, show="headings")

        for col in columns:
            self.banned_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.banned_table.column("ip", width=150, anchor="center")
        self.banned_table.column("actions", width=100, anchor="center")

        self.banned_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a scroll bar
        scrollbar = ttk.Scrollbar(self.banned_tab, orient="vertical", command=self.banned_table.yview)
        scrollbar.pack(side="right", fill="y")
        self.banned_table.configure(yscrollcommand=scrollbar.set)
        
        # Actions frame
        action_frame = tk.Frame(self.banned_tab)
        action_frame.pack(pady=10)
        
        tk.Button(action_frame, text="Refresh", command=self.view_banned_ips).pack(side="left", padx=5)
        tk.Button(action_frame, text="Unban Selected IP", command=self.unban_selected_ip).pack(side="left", padx=5)
        
        # Load initial data
        self.view_banned_ips()
    
    def setup_users_tab(self):
        """Setup the active users tab"""
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
        
        # Load initial data
        self.view_active_users()

    def setup_ports_tab(self):
        tk.Label(self.ports_tab, text="Ports Configuration", font=("Arial", 16)).pack(pady=10)
        
        # Ports treeview
        columns_ports = ("port", "status", "honeypot", "last_triggered")
        self.port_table = ttk.Treeview(self.ports_tab, columns=columns_ports, show="headings")

        for col in columns_ports:
            self.port_table.heading(col, text=col.capitalize())

        # Adjust column widths
        self.port_table.column("port", width=100, anchor="center")
        self.port_table.column("status", width=100, anchor="center")
        self.port_table.column("honeypot", width=100, anchor="center")
        self.port_table.column("last_triggered", width=150, anchor="center")

        self.port_table.pack(fill="both", expand=True, padx=5, pady=5)
        
        # View options
        button_frame = tk.Frame(self.ports_tab)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="View Active Ports", command=self.view_ports_full).pack(side="left", padx=5)
        tk.Button(button_frame, text="View Disabled Ports", command=self.view_disabled_ports).pack(side="left", padx=5)

        # Port management section
        management_frame = tk.Frame(self.ports_tab)
        management_frame.pack(pady=10, fill="x")
        
        # Left column - Port selector
        left_col = tk.Frame(management_frame)
        left_col.pack(side="left", padx=20)
        
        tk.Label(left_col, text="Select Port:", font=("Arial", 12)).pack(pady=5)
        self.port_selector = ttk.Combobox(left_col, state="readonly", width=15)
        self.port_selector.pack(pady=5)
        
        # Right column - Actions
        right_col = tk.Frame(management_frame)
        right_col.pack(side="left", padx=20)
        
        tk.Button(right_col, text="Enable Port", command=lambda: self.toggle_port_status("active")).pack(pady=5, fill="x")
        tk.Button(right_col, text="Disable Port", command=lambda: self.toggle_port_status("inactive")).pack(pady=5, fill="x")
        tk.Button(right_col, text="Enable Honeypot", command=lambda: self.toggle_honeypot(True)).pack(pady=5, fill="x")
        tk.Button(right_col, text="Disable Honeypot", command=lambda: self.toggle_honeypot(False)).pack(pady=5, fill="x")
        
        self.refresh_port_list()

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

#==============================Auto-refresh==============================
    def start_auto_refresh(self):
        """Start auto-refresh thread"""
        self.auto_refresh_thread = threading.Thread(target=self._auto_refresh_worker, daemon=True)
        self.auto_refresh_thread.start()
    
    def _auto_refresh_worker(self):
        """Background thread to refresh data periodically"""
        while True:
            try:
                # Update UI in the main thread
                self.master.after(0, self.view_logs, True)  # True for latest_only
                self.master.after(0, self.view_ports, True)
                self.master.after(0, self.update_system_status)
                self.master.after(0, self.view_potential_attackers)
                self.master.after(0, self.view_banned_ips)
                self.master.after(0, self.view_active_users)
            except Exception as e:
                print(f"Auto-refresh error: {e}")
            
            # Wait for 30 seconds
            time.sleep(30)

#==============================Attackers Log==============================
    def view_logs(self, latest_only=False):
        try:
            response = requests.get(f"{SERVER_URL}/attackers")
            logs = response.json()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch logs: {e}")
            return

        logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        if latest_only:
            logs = logs[:5]

        for item in self.log_table.get_children():
            self.log_table.delete(item)

        for entry in logs:
            self.log_table.insert("", "end", values=(
                entry.get("timestamp", "N/A"),
                entry.get("username", "N/A"),
                entry.get("password", "N/A"),
                entry.get("ip", "N/A"),
                entry.get("attempted_port", "N/A"),
                entry.get("reason", "Login attempt")
            ))

#==============================Potential Attackers==============================
    def view_potential_attackers(self):
        try:
            response = requests.get(f"{SERVER_URL}/potential_attackers")
            potential_attackers = response.json()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch potential attackers: {e}")
            return

        for item in self.potential_table.get_children():
            self.potential_table.delete(item)

        for entry in potential_attackers:
            self.potential_table.insert("", "end", values=(
                entry.get("timestamp", "N/A"),
                entry.get("username", "N/A"),
                entry.get("ip", "N/A"),
                entry.get("attempted_port", "N/A"),
                entry.get("reason", "N/A"),
                "Ban"
            ))
    
    def ban_selected_ip(self):
        selected_item = self.potential_table.selection()
        if not selected_item:
            messagebox.showwarning("Select Entry", "Please select an entry to ban.")
            return
        
        # Get the IP from the selected item
        ip = self.potential_table.item(selected_item[0])['values'][2]
        
        try:
            response = requests.post(f"{SERVER_URL}/ban_ip", json={"ip": ip})
            if response.status_code == 200:
                messagebox.showinfo("Success", f"IP {ip} has been banned.")
                self.view_potential_attackers()
                self.view_banned_ips()
            else:
                messagebox.showerror("Error", response.text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to ban IP: {e}")

#==============================Banned IPs==============================
    def view_banned_ips(self):
        try:
            response = requests.get(f"{SERVER_URL}/banned_ips")
            banned_ips = response.json()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch banned IPs: {e}")
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
            response = requests.post(f"{SERVER_URL}/unban_ip", json={"ip": ip})
            if response.status_code == 200:
                messagebox.showinfo("Success", f"IP {ip} has been unbanned.")
                self.view_banned_ips()
            else:
                messagebox.showerror("Error", response.text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unban IP: {e}")

#==============================Active Users==============================
    def view_active_users(self):
        try:
            response = requests.get(f"{SERVER_URL}/active_users")
            active_users = response.json()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch active users: {e}")
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

#==============================Ports Section==============================
    def view_ports(self, latest_only=True):
        try:
            response = requests.get(f"{SERVER_URL}/ports")
            ports = response.json()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch ports: {e}")
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
        
        # Also refresh the port list in the dropdown
        self.refresh_port_list()

    def view_ports_full(self):
        self.view_ports(latest_only=False)

    def view_disabled_ports(self):
        try:
            response = requests.get(f"{SERVER_URL}/ports")
            ports = response.json()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch ports: {e}")
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

#==============================Toggle port======================
    def refresh_port_list(self):
        try:
            response = requests.get(f"{SERVER_URL}/ports")
            ports = response.json()
            port_list = [str(p["port"]) for p in ports]
            self.port_selector['values'] = port_list
            if port_list:
                self.port_selector.current(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load ports: {e}")

    def toggle_port_status(self, status):
        selected = self.port_selector.get()
        if not selected:
            messagebox.showwarning("Select Port", "Please select a port.")
            return
        try:
            response = requests.post(f"{SERVER_URL}/update_port", json={"port": int(selected), "status": status})
            if response.status_code == 200:
                messagebox.showinfo("Success", f"Port {selected} status set to {status}.")
                self.view_ports()
            else:
                messagebox.showerror("Error", response.text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update port: {e}")

#==============================Honeypot port======================
    def toggle_honeypot(self, enabled):
        selected = self.port_selector.get()
        if not selected:
            messagebox.showwarning("Select Port", "Please select a port.")
            return
        try:
            response = requests.post(f"{SERVER_URL}/update_port", json={"port": int(selected), "honeypot": enabled})
            if response.status_code == 200:
                status = "enabled" if enabled else "disabled"
                messagebox.showinfo("Success", f"Honeypot for Port {selected} {status}.")
                self.view_ports()
            else:
                messagebox.showerror("Error", response.text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle honeypot: {e}")

#==============================System Status==============================
    def update_system_status(self):
        """Update the system status indicators"""
        try:
            # Check server status
            try:
                requests.get(f"{SERVER_URL}/ports", timeout=1)
                self.server_status.set("Online")
            except:
                self.server_status.set("Offline")
            
            # Get port statistics
            response = requests.get(f"{SERVER_URL}/ports")
            ports = response.json()
            active_count = len([p for p in ports if p["status"] == "active"])
            honeypot_count = len([p for p in ports if p.get("honeypot", False)])
            
            self.active_ports.set(str(active_count))
            self.honeypot_ports.set(str(honeypot_count))
            
            # Get attacker count
            response = requests.get(f"{SERVER_URL}/attackers")
            attackers = response.json()
            self.attacker_count.set(str(len(attackers)))
            
            # Get potential attacker count
            response = requests.get(f"{SERVER_URL}/potential_attackers")
            potential_attackers = response.json()
            self.potential_count.set(str(len(potential_attackers)))
            
            # Get banned IP count
            response = requests.get(f"{SERVER_URL}/banned_ips")
            banned_ips = response.json()
            self.banned_count.set(str(len(banned_ips)))
            
            # Get active user count
            response = requests.get(f"{SERVER_URL}/active_users")
            active_users = response.json()
            self.user_count.set(str(len(active_users)))
            
        except Exception as e:
            print(f"Error updating system status: {e}")
            self.server_status.set("Error")

#==============================Logout==============================
    def logout(self):
        if hasattr(self.master, 'show_frame'):
            # Using string to avoid circular import issues
            self.master.show_frame("LoginPage")
        else:
            self.master.destroy()

#==============================Run GUI==============================
if __name__ == "__main__":
    root = tk.Tk()
    app = AdminPanel(root)
    root.mainloop()
