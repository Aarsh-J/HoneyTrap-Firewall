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
        #Logout Button
        tk.Button(self, text="Logout", command=self.logout).pack(pady=20)

        #--------------------Attacker Log Section--------------------
        tk.Label(self, text="Attacker's Log", font=("Arial", 12)).pack(pady=5)
        columns = ("timestamp", "username", "password", "ip", "port")
        self.log_table = ttk.Treeview(self, columns=columns, show="headings", height=8)

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
        tk.Button(self, text="View Full Attacker Log", command=lambda: self.view_logs(latest_only=False)).pack(pady=10)

        #--------------------Port Control Section--------------------
        tk.Label(self, text="Active Ports", font=("Arial", 12)).pack(pady=5)

        self.port_status_text = tk.Text(self, height=7, width=60, state="disabled")
        self.port_status_text.pack(pady=5)

        self.port_button = tk.Button(self, text="View Full Port Status", command=self.view_ports_full)
        self.port_button.pack(pady=5)

        #--------------------Port Toggle Controls--------------------
        tk.Label(self, text="Select a Port to Manage", font=("Arial", 12)).pack(pady=5)

        self.port_selector = ttk.Combobox(self, state="readonly")
        self.port_selector.pack(pady=5)
        self.refresh_port_list()  # Populate it on load

        tk.Button(self, text="Toggle Port Status", command=self.toggle_port_status).pack(pady=3)
        tk.Button(self, text="Toggle Honeypot", command=self.toggle_honeypot).pack(pady=3)


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

        self.port_status_text.configure(state="normal")
        self.port_status_text.delete(1.0, tk.END)
        for port in active_ports:
            honeypot = "ON" if port.get("honeypot") else "OFF"
            self.port_status_text.insert(
                tk.END,
                f"Port {port.get('port')} | Status: Active | Honeypot: {honeypot}\n"
            )
        self.port_status_text.configure(state="disabled")

    def view_ports_full(self):
        self.view_ports(latest_only=False)

#==============================Logout==============================
    def logout(self):
        self.master.show_frame(self.master.frames["LoginPage"])

#==============================Run GUI==============================
if __name__ == "__main__":
    root = tk.Tk()
    app = AdminPanel(root)
    root.mainloop()
