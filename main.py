#============Import Libraries=============
import tkinter as tk
from tkinter import messagebox
import requests

#============Global Variables=============
SERVER_URL = "http://localhost:5000"

#============App Class Definition=============
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HoneyTrap Firewall")
        self.geometry("500x350")
        self.frames = {}
        for F in (LoginPage, AdminPanel, UserPortal, FakeLoading):
            frame = F(self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(LoginPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

#============LoginPage Class Definition=============
class LoginPage(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="Username:").pack(pady=10)
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        tk.Label(self, text="Password:").pack(pady=10)
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.login_attempts = 0

        tk.Button(self, text="Login", command=self.login).pack(pady=20)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        #============Basic Validation=============
        if len(username) < 3 or len(password) < 3:
            messagebox.showerror("Invalid", "Username must be at least 3 and Password at least 3 characters.")
            return

        #============Send Login Request=============
        response = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
        status = response.json().get("status")

        #============Handle Login Responses=============
        if status == "admin":
            self.master.show_frame(AdminPanel)
        elif status == "valid":
            self.master.show_frame(UserPortal)
        else:
            self.login_attempts += 1
            if self.login_attempts >= 2:
                self.master.show_frame(FakeLoading)
            else:
                messagebox.showwarning("Incorrect", "Incorrect username or password. Try again.")

#============AdminPanel Class Definition=============
class AdminPanel(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="Admin Panel", font=("Arial", 16)).pack(pady=10)
        tk.Button(self, text="View Attacker Logs", command=self.view_logs).pack()
        self.log_text = tk.Text(self, height=10, width=50)
        self.log_text.pack(pady=10)
        tk.Button(self, text="Logout", command=lambda: master.show_frame(LoginPage)).pack(pady=10)

    def view_logs(self):
        response = requests.get(f"{SERVER_URL}/attackers")
        logs = response.json()
        self.log_text.delete(1.0, tk.END)
        for entry in logs:
            self.log_text.insert(tk.END, f"{entry['timestamp']} | {entry['username']} : {entry['password']}\n")

#============UserPortal Class Definition=============
class UserPortal(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="Project Description", font=("Arial", 16)).pack(pady=10)
        tk.Label(self, text="This is a HoneyTrap Firewall to detect suspicious activity.\n"
                            "It detects attacker attempts, stores data, and allows port control.",
                 wraplength=400, justify="center").pack(pady=10)
        tk.Button(self, text="Logout", command=lambda: master.show_frame(LoginPage)).pack(pady=20)

#============FakeLoading Class Definition=============
class FakeLoading(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        tk.Label(self, text="Loading... Please Wait", font=("Arial", 16)).pack(pady=20)
        tk.Label(self, text="Simulating secure environment.", font=("Arial", 12)).pack()
        tk.Button(self, text="Back to Login", command=lambda: master.show_frame(LoginPage)).pack(pady=30)

#============Main Execution=============
if __name__ == "__main__":
    app = App()
    app.mainloop()