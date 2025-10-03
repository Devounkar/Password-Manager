import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import json
import os
import random
import string
import pyperclip
import base64
import re
from cryptography.fernet import Fernet
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# --- UI STYLING CONSTANTS ---
BG_COLOR = "#2c3e50"        # Dark Slate Blue
FG_COLOR = "#ecf0f1"        # Light Gray (Clouds)
PRIMARY_COLOR = "#3498db"   # Peter River Blue
SECONDARY_COLOR = "#2980b9" # Belize Hole Blue
SUCCESS_COLOR = "#2ecc71"   # Emerald Green
TEXT_COLOR = "#ffffff"      # White
ENTRY_BG_COLOR = "#34495e"  # Wet Asphalt
WEAK_COLOR = "#e74c3c"      # Red
MEDIUM_COLOR = "#f39c12"    # Orange
STRONG_COLOR = "#2ecc71"    # Green
VERY_STRONG_COLOR = "#27ae60" # Darker Green

FONT_BOLD = ("Segoe UI", 12, "bold")
FONT_NORMAL = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 18, "bold")

FILEPATH = "passwords.json.enc"

# --- BACKEND LOGIC (Unchanged) ---
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
        self.master.geometry("800x600")
        self.master.configure(bg=BG_COLOR)
        self.master.resizable(width=False, height=False)
        
        self.data = {}
        self.key = None
        self.salt = None
        self.filepath = FILEPATH

        self.show_login_screen()

    def clear_screen(self):
        for widget in self.master.winfo_children():
            widget.destroy()

    def style_button(self, button, color=PRIMARY_COLOR, hover_color=SECONDARY_COLOR):
        button.config(
            bg=color,
            fg=TEXT_COLOR,
            activebackground=hover_color,
            activeforeground=TEXT_COLOR,
            relief=tk.FLAT,
            font=FONT_BOLD,
            padx=10,
            pady=5,
            borderwidth=0
        )
        button.bind("<Enter>", lambda e, c=hover_color: e.widget.config(bg=c))
        button.bind("<Leave>", lambda e, c=color: e.widget.config(bg=c))

    def show_login_screen(self):
        self.clear_screen()
        try:
            logo = Image.open("file.png.jpeg")
            logo = logo.resize((150, 120))
            self.img = ImageTk.PhotoImage(logo)
            tk.Label(self.master, image=self.img, bg=BG_COLOR).pack(pady=20)
        except FileNotFoundError:
            tk.Label(self.master, text="🔒", font=("Segoe UI", 60), bg=BG_COLOR, fg=PRIMARY_COLOR).pack(pady=20)
        self.input_frame = tk.Frame(self.master, bg=BG_COLOR)
        self.input_frame.pack(pady=20, padx=20)
        tk.Label(self.input_frame, text="Enter Master Password:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_BOLD).grid(row=0, column=0, columnspan=3, pady=(0, 10))
        self.password_entry = tk.Entry(self.input_frame, width=30, font=FONT_NORMAL, show="*", bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, relief=tk.FLAT)
        self.password_entry.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        self.password_entry.focus()
        self.toggle_btn = tk.Button(self.input_frame, text="Show", command=self.toggle_master_password, font=FONT_NORMAL, relief=tk.FLAT)
        self.toggle_btn.grid(row=1, column=2, padx=5, pady=5)
        self.submit_button = tk.Button(self.input_frame, text="Unlock", command=self.submit_master_password)
        self.style_button(self.submit_button, color=SUCCESS_COLOR, hover_color="#27ae60")
        self.submit_button.grid(row=2, column=0, columnspan=3, pady=20)
        self.master.bind('<Return>', lambda event=None: self.submit_button.invoke())

    def toggle_master_password(self):
        if self.password_entry.cget('show') == '*':
            self.password_entry.config(show='')
            self.toggle_btn.config(text='Hide')
        else:
            self.password_entry.config(show='*')
            self.toggle_btn.config(text='Show')

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
        self.clear_screen()
        self.master.unbind('<Return>')
        top_frame = tk.Frame(self.master, bg=BG_COLOR)
        top_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Label(top_frame, text="Search:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_BOLD).pack(side=tk.LEFT, padx=(0,10))
        self.search_entry = tk.Entry(top_frame, width=30, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT, insertbackground=TEXT_COLOR)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_passwords())
        add_btn = tk.Button(top_frame, text="✚ Add New", command=self.add_new_password_screen)
        self.style_button(add_btn, color=SUCCESS_COLOR, hover_color="#27ae60")
        add_btn.pack(side=tk.RIGHT, padx=(10, 0))
        list_container = tk.Frame(self.master, bg=BG_COLOR)
        list_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        canvas = tk.Canvas(list_container, bg=ENTRY_BG_COLOR, highlightthickness=0)
        scrollbar = tk.Scrollbar(list_container, orient="vertical", command=canvas.yview)
        self.list_frame = tk.Frame(canvas, bg=ENTRY_BG_COLOR)
        self.list_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        bottom_frame = tk.Frame(self.master, bg=BG_COLOR)
        bottom_frame.pack(fill=tk.X, padx=20, pady=10)
        gen_btn = tk.Button(bottom_frame, text="Generate Password", command=self.generate_new_password)
        self.style_button(gen_btn)
        gen_btn.pack(side=tk.LEFT)
        exit_btn = tk.Button(bottom_frame, text="Lock", command=self.show_login_screen)
        self.style_button(exit_btn, color="#e74c3c", hover_color="#c0392b")
        exit_btn.pack(side=tk.RIGHT)
        self.display_results(self.data)

    def display_results(self, filtered_data):
        for widget in self.list_frame.winfo_children(): widget.destroy()
        if not filtered_data:
            tk.Label(self.list_frame, text="No passwords saved yet.", font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=FG_COLOR).pack(pady=20)
        else:
            for i, (website, creds) in enumerate(filtered_data.items()):
                bg = BG_COLOR if i % 2 == 0 else ENTRY_BG_COLOR
                entry_frame = tk.Frame(self.list_frame, bg=bg)
                entry_frame.pack(fill="x")
                entry_frame.grid_columnconfigure(0, weight=2); entry_frame.grid_columnconfigure(1, weight=2); entry_frame.grid_columnconfigure(2, weight=2); entry_frame.grid_columnconfigure(3, weight=3)
                tk.Label(entry_frame, text=website, font=FONT_BOLD, anchor="w", bg=bg, fg=FG_COLOR).grid(row=0, column=0, sticky="ew", padx=10, pady=5)
                tk.Label(entry_frame, text=creds['username'], font=FONT_NORMAL, anchor="w", bg=bg, fg=FG_COLOR).grid(row=0, column=1, sticky="ew", padx=10, pady=5)
                pwd_var = tk.StringVar(value="*" * len(creds['password']))
                tk.Label(entry_frame, textvariable=pwd_var, font=FONT_NORMAL, anchor="w", bg=bg, fg=FG_COLOR).grid(row=0, column=2, sticky="ew", padx=10, pady=5)
                action_frame = tk.Frame(entry_frame, bg=bg)
                action_frame.grid(row=0, column=3, sticky="e", padx=10, pady=5)
                def toggle_list_pwd(pv=pwd_var, real_pwd=creds['password'], btn=None):
                    if pv.get().startswith("*"): pv.set(real_pwd); btn.config(text="Hide")
                    else: pv.set("*" * len(real_pwd)); btn.config(text="Show")
                show_btn = tk.Button(action_frame, text="Show", width=6)
                show_btn.config(command=lambda v=pwd_var, r=creds['password'], b=show_btn: toggle_list_pwd(v, r, b))
                self.style_button(show_btn, color=PRIMARY_COLOR, hover_color=SECONDARY_COLOR); show_btn.pack(side=tk.LEFT, padx=5)
                copy_btn = tk.Button(action_frame, text="Copy", width=6, command=lambda p=creds['password']: self.copy_to_clipboard(p))
                self.style_button(copy_btn, color=SECONDARY_COLOR, hover_color=PRIMARY_COLOR); copy_btn.pack(side=tk.LEFT, padx=5)
                del_btn = tk.Button(action_frame, text="Delete", width=6, command=lambda w=website: self.delete_password(w))
                self.style_button(del_btn, color="#c0392b", hover_color="#e74c3c"); del_btn.pack(side=tk.LEFT, padx=5)
    
    def copy_to_clipboard(self, password):
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def delete_password(self, website):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the password for {website}?"):
            del self.data[website]
            encrypt_json_file(self.filepath, self.data, self.key, self.salt)
            self.display_results(self.data)

    def search_passwords(self):
        query = self.search_entry.get().lower()
        if not query: self.display_results(self.data); return
        filtered = {w: c for w, c in self.data.items() if query in w.lower() or query in c['username'].lower()}
        self.display_results(filtered)

    def check_password_strength(self, password):
        score = 0
        if len(password) >= 8: score += 1
        if len(password) >= 12: score += 1
        if re.search(r"[a-z]", password): score += 1
        if re.search(r"[A-Z]", password): score += 1
        if re.search(r"\d", password): score += 1
        if re.search(r"\W", password): score += 1
        
        # Total score is now 0-6
        if score < 3: return "Weak", WEAK_COLOR, score
        if score < 5: return "Medium", MEDIUM_COLOR, score
        if score == 5: return "Strong", STRONG_COLOR, score
        if score == 6: return "Very Strong", VERY_STRONG_COLOR, score
        return "Weak", WEAK_COLOR, score # Default case for score 0, 1, 2

    # --- THIS IS THE CORRECTED METHOD ---
    def add_new_password_screen(self):
        self.clear_screen()
        tk.Label(self.master, text="Add New Password", font=FONT_TITLE, bg=BG_COLOR, fg=FG_COLOR).pack(pady=20)
        form_frame = tk.Frame(self.master, bg=BG_COLOR)
        form_frame.pack(pady=10, padx=40, fill="x")

        tk.Label(form_frame, text="Website:", font=FONT_BOLD, bg=BG_COLOR, fg=FG_COLOR).grid(row=0, column=0, sticky="w", pady=5)
        tk.Label(form_frame, text="Username:", font=FONT_BOLD, bg=BG_COLOR, fg=FG_COLOR).grid(row=1, column=0, sticky="w", pady=5)
        tk.Label(form_frame, text="Password:", font=FONT_BOLD, bg=BG_COLOR, fg=FG_COLOR).grid(row=2, column=0, sticky="w", pady=5)

        self.website_entry = tk.Entry(form_frame, width=40, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT)
        self.username_entry = tk.Entry(form_frame, width=40, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT)
        
        self.password_strength_var = tk.StringVar()
        self.password_strength_var.trace_add("write", self.update_strength_bar)
        self.new_password_entry = tk.Entry(form_frame, width=40, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT, textvariable=self.password_strength_var)

        self.website_entry.grid(row=0, column=1, pady=5, padx=10)
        self.username_entry.grid(row=1, column=1, pady=5, padx=10)
        self.new_password_entry.grid(row=2, column=1, pady=5, padx=10)

        # --- FIX: Using a more stable .grid() layout for the strength bar itself ---
        strength_frame = tk.Frame(form_frame, bg=BG_COLOR)
        strength_frame.grid(row=3, column=1, sticky="ew", padx=10, pady=(5,0))
        strength_frame.grid_columnconfigure(0, weight=1) # Label column
        strength_frame.grid_columnconfigure(1, weight=4) # Bar container column

        self.strength_label = tk.Label(strength_frame, text="", font=("Segoe UI", 9, "bold"), bg=BG_COLOR)
        self.strength_label.grid(row=0, column=0, sticky='w')
        
        bar_container = tk.Frame(strength_frame, bg=BG_COLOR)
        bar_container.grid(row=0, column=1, sticky='ew', padx=5)

        self.strength_bar_segments = []
        for i in range(6): # FIX: Changed to 6 segments to match the max score
            segment = tk.Frame(bar_container, bg=ENTRY_BG_COLOR, height=10)
            segment.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=1)
            self.strength_bar_segments.append(segment)
        # --- END FIX ---
        
        button_frame = tk.Frame(self.master, bg=BG_COLOR)
        button_frame.pack(pady=20)
        add_btn = tk.Button(button_frame, text="Add Password", command=self.add_password)
        self.style_button(add_btn, color=SUCCESS_COLOR, hover_color="#27ae60")
        add_btn.pack(side=tk.LEFT, padx=10)
        back_btn = tk.Button(button_frame, text="Back", command=self.show_password_list)
        self.style_button(back_btn, color="#95a5a6", hover_color="#7f8c8d")
        back_btn.pack(side=tk.LEFT, padx=10)

        self.update_strength_bar()

    # --- THIS HELPER METHOD IS ALSO CORRECTED ---
    def update_strength_bar(self, *args):
        password = self.password_strength_var.get()
        if not password:
            label, color, score = "Enter a password", FG_COLOR, 0
        else:
            label, color, score = self.check_password_strength(password)
        
        self.strength_label.config(text=label, fg=color)
        
        # Update colors of the segments based on score
        for i, segment in enumerate(self.strength_bar_segments):
            if i < score:
                segment.config(bg=color)
            else:
                segment.config(bg=ENTRY_BG_COLOR)
    
    def add_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.new_password_entry.get()
        if not all([website, username, password]): messagebox.showwarning("Input Error", "Please fill all fields."); return
        self.data[website] = {"username": username, "password": password}
        encrypt_json_file(self.filepath, self.data, self.key, self.salt)
        messagebox.showinfo("Saved", f"Password for {website} saved!")
        self.show_password_list()

    def generate_new_password(self):
        gen_win = tk.Toplevel(self.master)
        gen_win.title("Generate New Password")
        gen_win.geometry("450x300")
        gen_win.configure(bg=BG_COLOR)
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for _ in range(16))
        form_frame = tk.Frame(gen_win, bg=BG_COLOR)
        form_frame.pack(pady=20, padx=20)
        tk.Label(form_frame, text="Website:", font=FONT_BOLD, bg=BG_COLOR, fg=FG_COLOR).grid(row=0, column=0, sticky="w", pady=5)
        tk.Label(form_frame, text="Username:", font=FONT_BOLD, bg=BG_COLOR, fg=FG_COLOR).grid(row=1, column=0, sticky="w", pady=5)
        tk.Label(form_frame, text="Generated Password:", font=FONT_BOLD, bg=BG_COLOR, fg=FG_COLOR).grid(row=2, column=0, sticky="w", pady=5)
        website_entry = tk.Entry(form_frame, width=30, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT)
        username_entry = tk.Entry(form_frame, width=30, font=FONT_NORMAL, bg=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT)
        password_var = tk.StringVar(value=password)
        password_entry = tk.Entry(form_frame, width=30, textvariable=password_var, state="readonly", font=FONT_NORMAL, readonlybackground=ENTRY_BG_COLOR, fg=TEXT_COLOR, relief=tk.FLAT)
        website_entry.grid(row=0, column=1, pady=5, padx=10)
        username_entry.grid(row=1, column=1, pady=5, padx=10)
        password_entry.grid(row=2, column=1, pady=5, padx=10)
        label, color, _ = self.check_password_strength(password)
        tk.Label(form_frame, text=label, font=("Segoe UI", 9, "bold"), bg=BG_COLOR, fg=color).grid(row=3, column=1, sticky="w", padx=10)
        def copy_and_close():
            pyperclip.copy(password_var.get())
            messagebox.showinfo("Copied", "Password copied to clipboard!", parent=gen_win)
        def save_and_close():
            website = website_entry.get()
            username = username_entry.get()
            pwd = password_var.get()
            if not all([website, username, pwd]): messagebox.showwarning("Input Error", "Please fill all fields.", parent=gen_win); return
            self.data[website] = {"username": username, "password": pwd}
            encrypt_json_file(self.filepath, self.data, self.key, self.salt)
            messagebox.showinfo("Saved", f"Password for {website} saved!", parent=gen_win)
            gen_win.destroy()
            self.show_password_list()
        button_frame = tk.Frame(gen_win, bg=BG_COLOR)
        button_frame.pack(pady=20)
        copy_btn = tk.Button(button_frame, text="Copy Password", command=copy_and_close)
        self.style_button(copy_btn)
        copy_btn.pack(side=tk.LEFT, padx=10)
        save_btn = tk.Button(button_frame, text="Save", command=save_and_close)
        self.style_button(save_btn, color=SUCCESS_COLOR, hover_color="#27ae60")
        save_btn.pack(side=tk.LEFT, padx=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()