# ------------------------ Imports & Setup ------------------------
import tkinter as tk
import requests

# ------------------------ User Portal Class ------------------------
class UserPortal:
    def __init__(self, root, port):
        self.root = root
        self.root.title(f"User Portal - Port {port}")
        self.port = port

        tk.Label(root, text=f"You are connected to port {port}").pack(pady=10)
        tk.Label(root, text="Simulating User Interaction on Firewall System").pack(pady=5)
        tk.Button(root, text="Send Data", command=self.send_data).pack(pady=5)
        self.status_label = tk.Label(root, text="")
        self.status_label.pack(pady=10)

    # ------------------------ Send Data Logic ------------------------
    def send_data(self):
        self.status_label.config(text="Data sent successfully (simulated)")

# ------------------------ Launch User Portal ------------------------
def open_user_portal(port):
    root = tk.Tk()
    app = UserPortal(root, port)
    root.mainloop()

# ------------------------ Main Entry Point (Test Only) ------------------------
if __name__ == '__main__':
    open_user_portal("8001")
