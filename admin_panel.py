#============Import Libraries=============
import tkinter as tk
from tkinter import messagebox
import requests

#============Global Variables=============
SERVER_URL = "http://localhost:5000"

#============AdminPanel Class Definition=============
class AdminPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.pack(fill="both", expand=True)
        self.create_widgets()

    def create_widgets(self):
        #============Title Section=============
        tk.Label(self, text="Admin Panel", font=("Arial", 16)).pack(pady=10)

        #============Attacker Logs Button=============
        tk.Button(self, text="View Attacker Logs", command=self.view_logs).pack(pady=10)

        #============Port Control Section=============
        self.port_button = tk.Button(self, text="View Port Status", command=self.view_ports)
        self.port_button.pack(pady=10)

        #============Logout Section=============
        tk.Button(self, text="Logout", command=self.logout).pack(pady=20)

        #============Logs Display Section=============
        self.log_text = tk.Text(self, height=10, width=50)
        self.log_text.pack(pady=10)

        #============Port Status Section=============
        self.port_status_text = tk.Text(self, height=5, width=50)
        self.port_status_text.pack(pady=10)

    def view_logs(self):
        #============Fetch Attacker Logs from Server=============
        response = requests.get(f"{SERVER_URL}/attackers")
        logs = response.json()

        #============Display Logs in Text Box=============
        self.log_text.delete(1.0, tk.END)
        for entry in logs:
            self.log_text.insert(tk.END, f"{entry['timestamp']} | {entry['username']} : {entry['password']}\n")

    def view_ports(self):
        #============Fetch Port Status from Server=============
        response = requests.get(f"{SERVER_URL}/ports")
        ports = response.json()

        #============Display Port Status in Text Box=============
        self.port_status_text.delete(1.0, tk.END)
        for port in ports:
            status = "Active" if port["status"] == "active" else "Inactive"
            honeypot = "ON" if port["honeypot"] else "OFF"
            self.port_status_text.insert(tk.END, f"Port {port['port']} | Status: {status} | Honeypot: {honeypot}\n")

    def logout(self):
        #============Logout and Return to Login Page=============
        self.master.show_frame(self.master.frames["LoginPage"])

#============Main Execution for Admin Panel=============
if __name__ == "__main__":
    root = tk.Tk()
    app = AdminPanel(root)
    root.mainloop()
