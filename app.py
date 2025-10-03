import tkinter as tk
from PIL import Image, ImageTk
from tkinter import messagebox
import json
import os
from cryptography.fernet import Fernet
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64
import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip


colour1 = '#020f12'
colour2 = '#05d7ff'
colour3 ='#65e7ff'
colour4 = 'BLACK'

FILEPATH = "passwords.json.enc"

def derive_key(master_password: str, salt: bytes) -> bytes:
    key = PBKDF2(master_password.encode(), salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)
    return base64.urlsafe_b64encode(key)

def encrypt_json_file(filename: str, data: dict, key: bytes, salt: bytes):
    fernet = Fernet(key)
    payload = json.dumps(data).encode()
    encrypted = fernet.encrypt(payload)
    with open(filename, "wb") as f:
        f.write(salt + encrypted)

def decrypt_json_file(filename: str, master_password: str):
    with open(filename, "rb") as f:
        file_data = f.read()
    salt = file_data[:16]
    encrypted = file_data[16:]
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)
    return json.loads(decrypted), key, salt

class PasswordManager:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Manager")
        self.master.geometry("600x500")
        self.master.resizable(width=False, height=False)
        self.data = {}
        self.key = None
        self.salt = None
        self.filepath = FILEPATH

        # Logo
        logo = Image.open("file.jpg")
        logo = logo.resize((200, 150))
        self.img = ImageTk.PhotoImage(logo)
        tk.Label(master, image=self.img).pack(pady=20)

        # Master password input
        self.input_frame = tk.Frame(master,bg=colour1)
        self.input_frame.pack(pady=10)

        tk.Label(self.input_frame, text="Enter Master Password:").grid(row=0, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.input_frame, width=20, font=("Arial", 10), show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)

        self.toggle_btn = tk.Button(self.input_frame, text="Show", command=self.toggle_password)
        self.toggle_btn.grid(row=0, column=2, padx=5, pady=5)

        self.submit_button = tk.Button(self.input_frame, text="Submit", command=self.submit_master_password)
        self.submit_button.grid(row=1, column=0, columnspan=3, pady=10)

    def toggle_password(self):
        """Toggle password visibility"""
        if self.password_entry.cget('show') == "":
            self.password_entry.config(show="*")
            self.toggle_btn.config(text="Show")
        else:
            self.password_entry.config(show="")
            self.toggle_btn.config(text="Hide")

    def submit_master_password(self):
        master_password = self.password_entry.get()
        if not master_password:
            messagebox.showwarning("Input Required", "Please enter the master password!")
            return

        if os.path.exists(self.filepath):
            try:
                self.data, self.key, self.salt = decrypt_json_file(self.filepath, master_password)
            except Exception:
                messagebox.showerror("Error", "Incorrect master password or corrupted file!")
                return
        else:
            self.salt = os.urandom(16)
            self.key = derive_key(master_password, self.salt)
            self.data = {}
            encrypt_json_file(self.filepath, self.data, self.key, self.salt)

        self.show_password_list()

    def show_password_list(self):
        # Clear all widgets
        for widget in self.master.winfo_children():
            widget.destroy()

        tk.Label(self.master, text="Saved Passwords", font=("Arial", 16, "bold")).pack(pady=10)

        # Search frame
        search_frame = tk.Frame(self.master,bg=colour1,pady=40)
        search_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=5)
        self.search_entry = tk.Entry(search_frame, width=20, font=("Arial", 10))
        self.search_entry.grid(row=0, column=1, padx=5)

        tk.Button(search_frame, text="Search", command=self.search_passwords).grid(row=0, column=2, padx=5)

        # List frame
        self.list_frame = tk.Frame(self.master,bg=colour1)
        self.list_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        # Buttons
        tk.Button(self.master, text="Add New Password", command=self.add_new_password_screen).pack(pady=5)
        tk.Button(self.master, text="Generate New Password", command=self.generate_new_password).pack(pady=5)
        tk.Button(self.master, text="Exit", command=self.master.destroy).pack(pady=5)

        # Display all passwords initially
        self.display_results(self.data)

    def display_results(self, filtered_data):

        for widget in self.list_frame.winfo_children():
            widget.destroy()
    
        if not filtered_data:
            tk.Label(self.list_frame, text="No matching passwords found.").pack()
        else:
            for website, creds in filtered_data.items():
                entry_frame = tk.Frame(self.list_frame,bg=colour1)
                entry_frame.pack(fill="x", padx=20, pady=2)

                tk.Label(entry_frame, text=f"{website} | Username: {creds['username']} | Password: ", anchor="w").pack(side="left")
                
                # Password label (hidden by default)
                pwd_var = tk.StringVar(value="*" * len(creds['password']))
                pwd_label = tk.Label(entry_frame, textvariable=pwd_var)
                pwd_label.pack(side="left", padx=5)

                def toggle(pwd_var=pwd_var, real_pwd=creds['password'], btn=None):
                    if pwd_var.get().startswith("*"):
                        pwd_var.set(real_pwd)
                        if btn:
                            btn.config(text="Hide")
                    else:
                        pwd_var.set("*" * len(real_pwd))
                        if btn:
                            btn.config(text="Show")

                show_btn = tk.Button(entry_frame, text="Show", command=lambda v=pwd_var, r=creds['password'], b=None: toggle(v, r, b))
                show_btn.pack(side="left", padx=5)

                # Pass the button itself to update text
                show_btn.config(command=lambda v=pwd_var, r=creds['password'], b=show_btn: toggle(v, r, b))

    def search_passwords(self):
        query = self.search_entry.get().lower()
        if not query:
            self.display_results(self.data)
            return
        filtered = {}
        for website, creds in self.data.items():
            if (query in website.lower() or query in creds['username'].lower() or query in creds['password'].lower()):
                filtered[website] = creds
        self.display_results(filtered)

    def add_new_password_screen(self):
        # Clear current widgets
        for widget in self.master.winfo_children():
            widget.destroy()

        tk.Label(self.master, text="Add New Password", font=("Arial", 16, "bold")).pack(pady=10)

        form_frame = tk.Frame(self.master,bg=colour1)
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Website:").grid(row=0, column=0, padx=5, pady=5)
        tk.Label(form_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5)
        tk.Label(form_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5)

        self.website_entry = tk.Entry(form_frame, width=30)
        self.username_entry = tk.Entry(form_frame, width=30)
        self.new_password_entry = tk.Entry(form_frame, width=30)

        self.website_entry.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)
        self.new_password_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Button(form_frame, text="Add Password", command=self.add_password).grid(row=3, column=1, pady=10)
        tk.Button(form_frame, text="Back", command=self.show_password_list).grid(row=3, column=0, pady=10)

    def add_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.new_password_entry.get()

        if not website or not username or not password:
            messagebox.showwarning("Input Error", "Please fill all fields.")
            return

        self.data[website] = {"username": username, "password": password}
        encrypt_json_file(self.filepath, self.data, self.key, self.salt)
        messagebox.showinfo("Saved", f"Password for {website} saved!")

        # Return to the password list screen
        self.show_password_list()

    def generate_new_password(self):
        # Create a new window
        gen_win = tk.Toplevel(self.master)
        gen_win.title("Generate New Password")
        gen_win.geometry("400x300")

        # Generate strong random password
        def generate_password(length=16):
            chars = string.ascii_letters + string.digits + string.punctuation
            return ''.join(random.choice(chars) for _ in range(length))

        password = generate_password()

        tk.Label(gen_win, text="Website:").grid(row=0, column=0, padx=5, pady=5)
        tk.Label(gen_win, text="Username:").grid(row=1, column=0, padx=5, pady=5)
        tk.Label(gen_win, text="Generated Password:").grid(row=2, column=0, padx=5, pady=5)

        website_entry = tk.Entry(gen_win, width=30)
        username_entry = tk.Entry(gen_win, width=30)
        password_var = tk.StringVar(value=password)
        password_entry = tk.Entry(gen_win, width=30, textvariable=password_var, state="readonly")

        website_entry.grid(row=0, column=1, padx=5, pady=5)
        username_entry.grid(row=1, column=1, padx=5, pady=5)
        password_entry.grid(row=2, column=1, padx=5, pady=5)

        # Copy password
        def copy_password():
            pyperclip.copy(password_var.get())
            messagebox.showinfo("Copied", "Password copied to clipboard!")

        # Save password
        def save_password():
            website = website_entry.get()
            username = username_entry.get()
            pwd = password_var.get()

            if not website or not username or not pwd:
                messagebox.showwarning("Input Error", "Please fill all fields.")
                return

            self.data[website] = {"username": username, "password": pwd}
            encrypt_json_file(self.filepath, self.data, self.key, self.salt)
            messagebox.showinfo("Saved", f"Password for {website} saved!")

            gen_win.destroy()
            self.show_password_list()

        tk.Button(gen_win, text="Copy Password", command=copy_password).grid(row=3, column=0, pady=10)
        tk.Button(gen_win, text="Save", command=save_password).grid(row=3, column=1, pady=10)
        tk.Button(gen_win, text="Cancel", command=gen_win.destroy).grid(row=4, column=0, columnspan=2, pady=10)
        


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
