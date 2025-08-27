"""encryption.py

GUI for simple, educational encryption and hashing demos.

Features:
- Generate / load / save a Fernet symmetric key
- Encrypt / Decrypt text using the key
- Compute SHA-256 hash of input text (defensive/educational)

This module is for local, educational purposes only.
"""
from __future__ import annotations
import os
import sys
import base64
import hashlib
import threading
import customtkinter as ctk
from tkinter import filedialog

# Try importing cryptography; GUI will show a warning if missing
CRYPTO_AVAILABLE = True
try:
    from cryptography.fernet import Fernet
except Exception:
    CRYPTO_AVAILABLE = False


class EncryptionGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Encryption / Decryption")
        self.resizable(True, True)
        window_width, window_height = 800, 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height-20)
        self.scrollable_frame.pack(fill="both", expand=True)

        self.header = ctk.CTkLabel(self.scrollable_frame, text="Encryption / Decryption", font=("Arial", 24, "bold"))
        self.header.pack(pady=(20, 8))

        # Key controls
        key_frame = ctk.CTkFrame(self.scrollable_frame)
        key_frame.pack(fill="x", padx=20, pady=(0, 12))

        self.key_label = ctk.CTkLabel(key_frame, text="Key (base64):")
        self.key_label.grid(row=0, column=0, sticky="w", padx=6, pady=6)

        self.key_entry = ctk.CTkEntry(key_frame, width=520)
        self.key_entry.grid(row=0, column=1, padx=6, pady=6)

        self.gen_key_btn = ctk.CTkButton(key_frame, text="Generate Key", command=self.generate_key)
        self.gen_key_btn.grid(row=0, column=2, padx=6, pady=6)

        self.load_key_btn = ctk.CTkButton(key_frame, text="Load Key", command=self.load_key)
        self.load_key_btn.grid(row=1, column=1, sticky="w", padx=6, pady=6)

        self.save_key_btn = ctk.CTkButton(key_frame, text="Save Key", command=self.save_key)
        self.save_key_btn.grid(row=1, column=2, padx=6, pady=6)

        # Text areas for encrypt/decrypt
        text_frame = ctk.CTkFrame(self.scrollable_frame)
        text_frame.pack(fill="both", padx=20, pady=(0, 12), expand=True)

        self.plain_label = ctk.CTkLabel(text_frame, text="Plaintext")
        self.plain_label.grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.cipher_label = ctk.CTkLabel(text_frame, text="Ciphertext (base64)")
        self.cipher_label.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        self.plain_text = ctk.CTkTextbox(text_frame, width=340, height=200, font=("Consolas", 12))
        self.plain_text.grid(row=1, column=0, padx=6, pady=6)

        self.cipher_text = ctk.CTkTextbox(text_frame, width=340, height=200, font=("Consolas", 12))
        self.cipher_text.grid(row=1, column=1, padx=6, pady=6)

        btn_frame = ctk.CTkFrame(self.scrollable_frame)
        btn_frame.pack(padx=20, pady=(0, 12), fill="x")

        self.encrypt_btn = ctk.CTkButton(btn_frame, text="Encrypt →", width=140, command=self.encrypt_text)
        self.encrypt_btn.pack(side="left", padx=6)

        self.decrypt_btn = ctk.CTkButton(btn_frame, text="← Decrypt", width=140, command=self.decrypt_text)
        self.decrypt_btn.pack(side="left", padx=6)

        # Hashing area
        hash_frame = ctk.CTkFrame(self.scrollable_frame)
        hash_frame.pack(fill="x", padx=20, pady=(0, 12))

        self.hash_label = ctk.CTkLabel(hash_frame, text="SHA-256 Hash of input text (educational)")
        self.hash_label.pack(anchor="w", padx=6, pady=6)

        self.hash_box = ctk.CTkTextbox(hash_frame, width=740, height=80, font=("Consolas", 12))
        self.hash_box.pack(padx=6, pady=6)
        self.hash_box.configure(state="disabled")

        self.hash_btn = ctk.CTkButton(hash_frame, text="Compute Hash", command=self.compute_hash)
        self.hash_btn.pack(padx=6, pady=6, anchor="e")

        # Status
        self.status = ctk.CTkLabel(self.scrollable_frame, text="Status: Ready")
        self.status.pack(pady=(6, 12))

        if not CRYPTO_AVAILABLE:
            # Disable crypto buttons and inform user
            self.gen_key_btn.configure(state="disabled")
            self.load_key_btn.configure(state="disabled")
            self.save_key_btn.configure(state="disabled")
            self.encrypt_btn.configure(state="disabled")
            self.decrypt_btn.configure(state="disabled")
            self.append_status("cryptography package not installed — install via requirements.txt to enable encryption features")

    def append_status(self, text: str):
        self.status.configure(text=f"Status: {text}")

    def generate_key(self):
        if not CRYPTO_AVAILABLE:
            return
        key = Fernet.generate_key()
        self.key_entry.delete(0, ctk.END)
        self.key_entry.insert(0, key.decode())
        self.append_status("New key generated")

    def load_key(self):
        path = filedialog.askopenfilename(filetypes=[("Key files", "*.key"), ("All files", "*")])
        if not path:
            return
        try:
            with open(path, 'rb') as f:
                data = f.read().strip()
                # accept raw 32-byte or base64
                try:
                    decoded = data.decode()
                except Exception:
                    decoded = base64.b64encode(data).decode()
                self.key_entry.delete(0, ctk.END)
                self.key_entry.insert(0, decoded)
                self.append_status(f"Key loaded from {os.path.basename(path)}")
        except Exception as e:
            self.append_status(f"Failed to load key: {e}")

    def save_key(self):
        path = filedialog.asksaveasfilename(defaultextension='.key', filetypes=[("Key files","*.key"),("All files","*")])
        if not path:
            return
        try:
            key = self.key_entry.get().strip().encode()
            with open(path, 'wb') as f:
                f.write(key)
            self.append_status(f"Key saved to {os.path.basename(path)}")
        except Exception as e:
            self.append_status(f"Failed to save key: {e}")

    def encrypt_text(self):
        if not CRYPTO_AVAILABLE:
            return
        key = self.key_entry.get().strip().encode()
        try:
            f = Fernet(key)
        except Exception:
            self.append_status("Invalid key format")
            return
        plain = self.plain_text.get("1.0", ctk.END).rstrip('\n')
        if not plain:
            self.append_status("No plaintext to encrypt")
            return

        def _work():
            try:
                token = f.encrypt(plain.encode())
                b64 = token.decode()
                self.cipher_text.delete("1.0", ctk.END)
                self.cipher_text.insert(ctk.END, b64)
                self.append_status("Encrypted")
            except Exception as e:
                self.append_status(f"Encryption failed: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def decrypt_text(self):
        if not CRYPTO_AVAILABLE:
            return
        key = self.key_entry.get().strip().encode()
        try:
            f = Fernet(key)
        except Exception:
            self.append_status("Invalid key format")
            return
        token = self.cipher_text.get("1.0", ctk.END).strip()
        if not token:
            self.append_status("No ciphertext to decrypt")
            return

        def _work():
            try:
                plain = f.decrypt(token.encode()).decode()
                self.plain_text.delete("1.0", ctk.END)
                self.plain_text.insert(ctk.END, plain)
                self.append_status("Decrypted")
            except Exception as e:
                self.append_status(f"Decryption failed: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def compute_hash(self):
        text = self.plain_text.get("1.0", ctk.END).rstrip('\n')
        if not text:
            self.append_status("No text to hash")
            return
        h = hashlib.sha256(text.encode()).hexdigest()
        self.hash_box.configure(state="normal")
        self.hash_box.delete("1.0", ctk.END)
        self.hash_box.insert(ctk.END, h)
        self.hash_box.configure(state="disabled")
        self.append_status("Hash computed")


def run(on_close=None):
    app = EncryptionGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()
