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

        self.view_logs(latest_only=True)
        self.view_ports(latest_only=True)

#=================================Widgets================================================
    def create_widgets(self):
        self.master.title("HoneyTrap Admin Panel")
        self.master.geometry("1000x600")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        tk.Label(self, text="Admin Panel", font=("Arial", 16)).pack(pady=10)

        tk.Button(self, text="Logout", command=self.logout).pack(pady=20)

        # ======= Updated: Make PanedWindow resize evenly ==========
        paned_window = tk.PanedWindow(self, orient="horizontal", sashrelief="raised")
        paned_window.pack(fill="both", expand=True, padx=10, pady=10)

        # Left Frame
        left_frame = tk.Frame(paned_window)
        paned_window.add(left_frame)
        paned_window.paneconfig(left_frame, stretch="always", minsize=400)

        tk.Label(left_frame, text="Attacker Settings", font=("Arial", 12)).pack(pady=5)
        columns = ("timestamp", "username", "password", "ip", "port")
        self.log_table = ttk.Treeview(left_frame, columns=columns, show="headings")

        for col in columns:
            self.log_table.heading(col, text=col.capitalize())

        # ======= Updated column widths for attacker log ==========
        self.log_table.column("timestamp", width=130, anchor="center")
        self.log_table.column("username", width=100, anchor="center")
        self.log_table.column("password", width=100, anchor="center")
        self.log_table.column("ip", width=100, anchor="center")
        self.log_table.column("port", width=80, anchor="center")

        self.log_table.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Button(left_frame, text="View Full Attacker Log", command=lambda: self.view_logs(latest_only=False)).pack(pady=10)

        # Right Frame
        right_frame = tk.Frame(paned_window)
        paned_window.add(right_frame)
        paned_window.paneconfig(right_frame, stretch="always", minsize=400)

        tk.Label(right_frame, text="Ports Settings", font=("Arial", 12)).pack(pady=5)

        columns_ports = ("port", "status", "honeypot", "last_triggered")
        self.port_table = ttk.Treeview(right_frame, columns=columns_ports, show="headings")

        for col in columns_ports:
            self.port_table.heading(col, text=col.capitalize())

        # ======= Updated column widths for ports table ==========
        self.port_table.column("port", width=70, anchor="center")
        self.port_table.column("status", width=100, anchor="center")
        self.port_table.column("honeypot", width=100, anchor="center")
        self.port_table.column("last_triggered", width=150, anchor="center")

        self.port_table.pack(fill="both", expand=True, padx=5, pady=5)

        button_frame = tk.Frame(right_frame)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="View Active Ports", command=self.view_ports_full).pack(side="left", padx=5)
        tk.Button(button_frame, text="View Disabled Ports", command=self.view_disabled_ports).pack(side="left", padx=5)

        # Port Selection Section
        tk.Label(right_frame, text="Select a Port to Manage", font=("Arial", 12)).pack(pady=(20, 5))

        self.port_selector = ttk.Combobox(right_frame, state="readonly")
        self.port_selector.pack(pady=5)
        self.refresh_port_list()

        toggle_button_frame = tk.Frame(right_frame)
        toggle_button_frame.pack(pady=10)

        tk.Button(toggle_button_frame, text="Toggle Port Status", command=self.toggle_port_status, width=20).pack(side="left", padx=10)
        tk.Button(toggle_button_frame, text="Toggle Honeypot", command=self.toggle_honeypot, width=20).pack(side="left", padx=10)

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
            self.port_table.insert("", "end", values=(
                port.get("port", "N/A"),
                port.get("status", "N/A"),
                honeypot,
                port.get("last_triggered", "N/A")
            ))

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
