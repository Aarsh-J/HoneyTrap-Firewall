#============Import Libraries=============
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import requests

#---------------Global Variables---------------------------
SERVER_URL = "http://localhost:5000"

#============AdminPanel Class Definition=============
class AdminPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.pack(fill="both", expand=True)
        self.create_widgets()

        # Show the latest logs and ports by default
        self.view_logs(latest_only=True)
        self.view_ports(latest_only=True)

#=================================Widgets================================================
    def create_widgets(self):
        tk.Label(self, text="Admin Panel", font=("Arial", 16)).pack(pady=10)
        # Logout Button
        tk.Button(self, text="Logout", command=self.logout).pack(pady=20)

        # Create a PanedWindow to divide the left and right sections
        paned_window = tk.PanedWindow(self, orient="horizontal")
        paned_window.pack(fill="both", expand=True)

        # Left side for Attacker Logs
        left_frame = tk.Frame(paned_window)
        paned_window.add(left_frame, width=400)  # Set a fixed width for the left pane

        # --------------------Attacker Log Section--------------------
        tk.Label(left_frame, text="Attacker's Log", font=("Arial", 12)).pack(pady=5)
        columns = ("timestamp", "username", "password", "ip", "port")
        self.log_table = ttk.Treeview(left_frame, columns=columns, show="headings", height=8)

        self.log_table.heading("timestamp", text="Timestamp")
        self.log_table.heading("username", text="Username")
        self.log_table.heading("password", text="Password")
        self.log_table.heading("ip", text="IP Address")
        self.log_table.heading("port", text="Port")

        self.log_table.column("timestamp", width=120)
        self.log_table.column("username", width=100)
        self.log_table.column("password", width=100)
        self.log_table.column("ip", width=120)
        self.log_table.column("port", width=60)

        self.log_table.pack(pady=10)
        tk.Button(left_frame, text="View Full Attacker Log", command=lambda: self.view_logs(latest_only=False)).pack(pady=10)

        # Right side for Port Settings
        right_frame = tk.Frame(paned_window)
        paned_window.add(right_frame, width=500)  # Set a fixed width for the right pane

        # --------------------Port Control Section--------------------
        tk.Label(right_frame, text="Active Ports", font=("Arial", 12)).pack(pady=5)

        # Ports table similar to attacker log
        columns_ports = ("port", "status", "honeypot", "last_triggered")
        self.port_table = ttk.Treeview(right_frame, columns=columns_ports, show="headings", height=8)

        self.port_table.heading("port", text="Port")
        self.port_table.heading("status", text="Status")
        self.port_table.heading("honeypot", text="Honeypot")
        self.port_table.heading("last_triggered", text="Last Triggered")

        self.port_table.column("port", width=60)
        self.port_table.column("status", width=80)
        self.port_table.column("honeypot", width=80)
        self.port_table.column("last_triggered", width=150)

        self.port_table.pack(pady=10)
        tk.Button(right_frame, text="View Full Port Status", command=self.view_ports_full).pack(pady=10)

        # --------------------Port Toggle Controls--------------------
        tk.Label(right_frame, text="Select a Port to Manage", font=("Arial", 12)).pack(pady=5)

        self.port_selector = ttk.Combobox(right_frame, state="readonly")
        self.port_selector.pack(pady=5)
        self.refresh_port_list()  # Populate it on load

        tk.Button(right_frame, text="Toggle Port Status", command=self.toggle_port_status).pack(pady=3)
        tk.Button(right_frame, text="Toggle Honeypot", command=self.toggle_honeypot).pack(pady=3)

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
                entry.get("attempted_port", "N/A")
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
            self.port_table.insert(
                "", "end", values=(
                    port.get("port", "N/A"),
                    port.get("status", "N/A"),
                    honeypot,
                    port.get("last_triggered", "N/A")
                )
            )

    def view_ports_full(self):
        self.view_ports(latest_only=False)

#==============================Toggle port======================
    def refresh_port_list(self):
        try:
            response = requests.get(f"{SERVER_URL}/ports")
            ports = response.json()
            port_list = [str(p["port"]) for p in ports]
            self.port_selector['values'] = port_list
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load ports: {e}")

    def toggle_port_status(self):
        selected = self.port_selector.get()
        if not selected:
            messagebox.showwarning("Select Port", "Please select a port.")
            return
        try:
            response = requests.post(f"{SERVER_URL}/update_port", json={"port": int(selected), "status": "inactive"})
            if response.status_code == 200:
                messagebox.showinfo("Success", f"Port {selected} status toggled.")
                self.view_ports()
            else:
                messagebox.showerror("Error", response.text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle port: {e}")

#==============================Honeypot port======================
    def toggle_honeypot(self):
        selected = self.port_selector.get()
        if not selected:
            messagebox.showwarning("Select Port", "Please select a port.")
            return
        try:
            response = requests.post(f"{SERVER_URL}/update_port", json={"port": int(selected), "honeypot": True})
            if response.status_code == 200:
                messagebox.showinfo("Success", f"Honeypot for Port {selected} toggled.")
                self.view_ports()
            else:
                messagebox.showerror("Error", response.text)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle honeypot: {e}")

#==============================Logout==============================
    def logout(self):
        self.master.show_frame(self.master.frames["LoginPage"])

#==============================Run GUI==============================
if __name__ == "__main__":
    root = tk.Tk()
    app = AdminPanel(root)
    root.mainloop()
