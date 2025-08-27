"""Encryption/Decryption GUI (educational)

Provides safe, local demonstrations:
- SHA-256 hashing
- PBKDF2 (password-based key derivation) demo
- Symmetric encryption/decryption using Fernet (if cryptography is installed)

All operations are local-only and intended for learning.
"""
from __future__ import annotations
import hashlib
import base64
import os
import threading
import customtkinter as ctk
from tkinter import messagebox

# Optional dependency: cryptography (Fernet)
FERNET_AVAILABLE = True
try:
    from cryptography.fernet import Fernet
except Exception:
    FERNET_AVAILABLE = False


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def pbkdf2_hex(password: str, salt: str, iterations: int = 100_000, dklen: int = 32) -> str:
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations, dklen=dklen)
    return dk.hex()


def generate_fernet_key() -> bytes:
    return Fernet.generate_key()


def encrypt_with_fernet(key: bytes, plaintext: str) -> bytes:
    f = Fernet(key)
    return f.encrypt(plaintext.encode('utf-8'))


def decrypt_with_fernet(key: bytes, token: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode('utf-8')


class EncryptionGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Encryption/Decryption")
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
        self.header.pack(pady=(18, 8))

        # Hashing frame
        hframe = ctk.CTkFrame(self.scrollable_frame)
        hframe.pack(fill="x", padx=20, pady=(6, 12))

        self.input_label = ctk.CTkLabel(hframe, text="Input text:")
        self.input_label.grid(row=0, column=0, padx=6, pady=6)
        self.input_entry = ctk.CTkEntry(hframe, width=420)
        self.input_entry.grid(row=0, column=1, padx=6, pady=6)

        self.hash_btn = ctk.CTkButton(hframe, text="Compute SHA-256", command=self.do_hash)
        self.hash_btn.grid(row=0, column=2, padx=6, pady=6)

        self.hash_result = ctk.CTkEntry(hframe, width=740)
        self.hash_result.grid(row=1, column=0, columnspan=3, padx=6, pady=(6, 12))

        # PBKDF2 frame
        pframe = ctk.CTkFrame(self.scrollable_frame)
        pframe.pack(fill="x", padx=20, pady=(0, 12))

        self.pw_label = ctk.CTkLabel(pframe, text="Password:")
        self.pw_label.grid(row=0, column=0, padx=6, pady=6)
        self.pw_entry = ctk.CTkEntry(pframe, width=220, placeholder_text="password")
        self.pw_entry.grid(row=0, column=1, padx=6, pady=6)

        self.salt_label = ctk.CTkLabel(pframe, text="Salt:")
        self.salt_label.grid(row=0, column=2, padx=6, pady=6)
        self.salt_entry = ctk.CTkEntry(pframe, width=220, placeholder_text="salt")
        self.salt_entry.insert(0, os.urandom(8).hex())
        self.salt_entry.grid(row=0, column=3, padx=6, pady=6)

        self.pbkdf2_btn = ctk.CTkButton(pframe, text="Derive PBKDF2", command=self.do_pbkdf2)
        self.pbkdf2_btn.grid(row=0, column=4, padx=6, pady=6)

        self.pbkdf2_result = ctk.CTkEntry(pframe, width=740)
        self.pbkdf2_result.grid(row=1, column=0, columnspan=5, padx=6, pady=(6, 12))

        # Fernet symmetric demo
        fframe = ctk.CTkFrame(self.scrollable_frame)
        fframe.pack(fill="x", padx=20, pady=(0, 12))

        self.fernet_note = ctk.CTkLabel(fframe, text="Symmetric encryption (Fernet) - requires 'cryptography' package.")
        self.fernet_note.grid(row=0, column=0, columnspan=3, padx=6, pady=6)

        self.key_entry = ctk.CTkEntry(fframe, width=420, placeholder_text="base64 key (generated)")
        self.key_entry.grid(row=1, column=0, padx=6, pady=6)

        self.gen_key_btn = ctk.CTkButton(fframe, text="Generate Key", command=self.generate_key)
        self.gen_key_btn.grid(row=1, column=1, padx=6, pady=6)

        self.encrypt_btn = ctk.CTkButton(fframe, text="Encrypt", command=self.encrypt_text)
        self.encrypt_btn.grid(row=1, column=2, padx=6, pady=6)

        self.decrypt_btn = ctk.CTkButton(fframe, text="Decrypt", command=self.decrypt_text)
        self.decrypt_btn.grid(row=1, column=3, padx=6, pady=6)

        self.fernet_result = ctk.CTkEntry(fframe, width=740)
        self.fernet_result.grid(row=2, column=0, columnspan=4, padx=6, pady=(6, 12))

        if not FERNET_AVAILABLE:
            self.gen_key_btn.configure(state="disabled")
            self.encrypt_btn.configure(state="disabled")
            self.decrypt_btn.configure(state="disabled")
            self.fernet_note.configure(text="cryptography not installed — Fernet disabled. Install with: pip install cryptography")

    def do_hash(self):
        txt = self.input_entry.get() or ""
        h = sha256_hex(txt)
        self.hash_result.delete(0, ctk.END)
        self.hash_result.insert(0, h)

    def do_pbkdf2(self):
        pwd = self.pw_entry.get() or ""
        salt = self.salt_entry.get() or ""
        # run in thread to avoid UI blocking
        def _work():
            h = pbkdf2_hex(pwd, salt)
            self.pbkdf2_result.delete(0, ctk.END)
            self.pbkdf2_result.insert(0, h)
        threading.Thread(target=_work, daemon=True).start()

    def generate_key(self):
        if not FERNET_AVAILABLE:
            messagebox.showinfo("Unavailable", "cryptography not installed")
            return
        key = generate_fernet_key()
        self.key_entry.delete(0, ctk.END)
        self.key_entry.insert(0, key.decode('utf-8'))

    def encrypt_text(self):
        if not FERNET_AVAILABLE:
            return
        key_b64 = self.key_entry.get().strip()
        if not key_b64:
            messagebox.showinfo("Key missing", "Generate or paste a base64 Fernet key first")
            return
        try:
            token = encrypt_with_fernet(key_b64.encode('utf-8'), self.input_entry.get() or "")
            self.fernet_result.delete(0, ctk.END)
            self.fernet_result.insert(0, token.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Encrypt failed", str(e))

    def decrypt_text(self):
        if not FERNET_AVAILABLE:
            return
        key_b64 = self.key_entry.get().strip()
        token_b64 = self.fernet_result.get().strip()
        if not key_b64 or not token_b64:
            messagebox.showinfo("Missing data", "Ensure key and token are provided")
            return
        try:
            plaintext = decrypt_with_fernet(key_b64.encode('utf-8'), token_b64.encode('utf-8'))
            # show plaintext in the input entry for convenience
            self.input_entry.delete(0, ctk.END)
            self.input_entry.insert(0, plaintext)
        except Exception as e:
            messagebox.showerror("Decrypt failed", str(e))


def run(on_close=None):
    app = EncryptionGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()
