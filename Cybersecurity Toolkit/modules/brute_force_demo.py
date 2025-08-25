"""
brute_force_demo.py

Safe, educational GUI demonstration of brute-force concepts.

This module intentionally does NOT provide tools to attack real systems.
It simulates guessing locally and shows how keyspace size, attempts/sec,
hashing, and defensive mitigations affect time-to-crack estimates.

Use only in legal, authorized lab environments.
"""
from __future__ import annotations
import hashlib
import time
import threading
import os
import sys
import customtkinter as ctk
from typing import Iterable, Tuple


def estimate_keyspace(charset_size: int, length: int) -> int:
    return charset_size ** length


def time_to_crack_seconds(keyspace: int, attempts_per_sec: float) -> float:
    if attempts_per_sec <= 0:
        raise ValueError("attempts_per_sec must be > 0")
    return (keyspace / 2) / attempts_per_sec


def hash_password(password: str, salt: str = "") -> str:
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()


def simulate_local_guess(secret_hash: str, candidates: Iterable[str], salt: str = "") -> Tuple[bool, str, float]:
    start = time.time()
    for c in candidates:
        if hash_password(c, salt) == secret_hash:
            return True, c, time.time() - start
    return False, "", time.time() - start


class BruteForceDemoGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brute-force Demo (Educational)")
        self.resizable(True, True)
        window_width, window_height = 800, 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height-80)
        self.scrollable_frame.pack(fill="both", expand=True)

        self.header = ctk.CTkLabel(self.scrollable_frame, text="Brute-force Demo", font=("Arial", 24, "bold"))
        self.header.pack(pady=(18, 8))

        # Keyspace inputs
        inp_frame = ctk.CTkFrame(self.scrollable_frame)
        inp_frame.pack(padx=20, pady=(0, 10), fill="x")

        self.charset_label = ctk.CTkLabel(inp_frame, text="Charset: (toggle groups)")
        self.charset_label.grid(row=0, column=0, sticky="w", padx=6, pady=6)

        self.lower_var = ctk.StringVar(value="on")
        self.upper_var = ctk.StringVar(value="on")
        self.digit_var = ctk.StringVar(value="on")

        # Use CTkSwitch for a more modern look
        self.lower_sw = ctk.CTkSwitch(inp_frame, text="lowercase", command=lambda s: None)
        self.lower_sw.select()
        self.lower_sw.grid(row=0, column=1, padx=6, pady=6)
        self.upper_sw = ctk.CTkSwitch(inp_frame, text="UPPERCASE", command=lambda s: None)
        self.upper_sw.select()
        self.upper_sw.grid(row=0, column=2, padx=6, pady=6)
        self.digit_sw = ctk.CTkSwitch(inp_frame, text="digits", command=lambda s: None)
        self.digit_sw.select()
        self.digit_sw.grid(row=0, column=3, padx=6, pady=6)

        self.length_label = ctk.CTkLabel(inp_frame, text="Length:")
        self.length_label.grid(row=1, column=0, padx=6, pady=6)
        self.length_entry = ctk.CTkEntry(inp_frame, width=120)
        self.length_entry.insert(0, "6")
        self.length_entry.grid(row=1, column=1, padx=6, pady=6)

        self.attempts_label = ctk.CTkLabel(inp_frame, text="Attempts/sec:")
        self.attempts_label.grid(row=1, column=2, padx=6, pady=6)
        self.attempts_entry = ctk.CTkEntry(inp_frame, width=160)
        self.attempts_entry.insert(0, "1000")
        self.attempts_entry.grid(row=1, column=3, padx=6, pady=6)

        self.estimate_btn = ctk.CTkButton(self.scrollable_frame, text="Estimate Keyspace & Time", command=self.start_estimate, width=280)
        self.estimate_btn.pack(pady=(6, 12))

        self.result_box = ctk.CTkTextbox(self.scrollable_frame, width=740, height=160, font=("Consolas", 12))
        self.result_box.pack(pady=(0, 12))
        self.result_box.configure(state="disabled")

        # Local demo area
        demo_frame = ctk.CTkFrame(self.scrollable_frame)
        demo_frame.pack(padx=20, pady=(0, 10), fill="x")

        self.demo_label = ctk.CTkLabel(demo_frame, text="Local Hash Demo (controlled)")
        self.demo_label.grid(row=0, column=0, sticky="w", padx=6, pady=6)

        self.password_entry = ctk.CTkEntry(demo_frame, placeholder_text="secret (for demo only)")
        self.password_entry.insert(0, "Ab1")
        self.password_entry.grid(row=1, column=0, padx=6, pady=6)

        self.salt_entry = ctk.CTkEntry(demo_frame, placeholder_text="salt (optional)")
        self.salt_entry.insert(0, "demo_salt")
        self.salt_entry.grid(row=1, column=1, padx=6, pady=6)

        self.candidates_entry = ctk.CTkEntry(demo_frame, placeholder_text="comma-separated candidate list")
        self.candidates_entry.insert(0, "a,b,ab,Ab,Ab1")
        self.candidates_entry.grid(row=2, column=0, columnspan=2, sticky="ew", padx=6, pady=6)

        self.demo_btn = ctk.CTkButton(demo_frame, text="Run Local Demo", command=self.start_demo)
        self.demo_btn.grid(row=2, column=2, padx=6, pady=6)

        # Defensive takeaways footer
        self.footer = ctk.CTkLabel(self.scrollable_frame, text="Defensive: use long passphrases, slow hashes (bcrypt/argon2), rate-limits; practice only in authorized labs.", wraplength=700, justify="left")
        self.footer.pack(pady=(8, 18))

        self._worker = None

    def append_result(self, text: str):
        def _add():
            self.result_box.configure(state="normal")
            self.result_box.insert(ctk.END, text + "\n")
            self.result_box.see(ctk.END)
            self.result_box.configure(state="disabled")
        try:
            self.after(0, _add)
        except Exception:
            _add()

    def start_estimate(self):
        try:
            length = int(self.length_entry.get())
            attempts = float(self.attempts_entry.get())
        except Exception:
            self.append_result("Invalid length or attempts/sec input")
            return

        charset_size = 0
        if self.lower_sw.get() == 1 or self.lower_sw.get() == True:
            charset_size += 26
        if self.upper_sw.get() == 1 or self.upper_sw.get() == True:
            charset_size += 26
        if self.digit_sw.get() == 1 or self.digit_sw.get() == True:
            charset_size += 10

        if charset_size == 0:
            self.append_result("Select at least one charset group")
            return

        def _work():
            ks = estimate_keyspace(charset_size, length)
            secs = time_to_crack_seconds(ks, attempts)
            days = secs / (60 * 60 * 24)
            self.append_result(f"Keyspace: {ks:,} combinations")
            self.append_result(f"Avg time to crack at {attempts:.0f} attempts/sec: {days:.2f} days")

        threading.Thread(target=_work, daemon=True).start()

    def start_demo(self):
        pwd = self.password_entry.get()
        salt = self.salt_entry.get() or ""
        candidates = [c.strip() for c in self.candidates_entry.get().split(',') if c.strip()]
        secret_hash = hash_password(pwd, salt)

        self.append_result(f"Starting local demo (hidden hash {secret_hash[:12]}...) with {len(candidates)} candidates")

        def _work():
            found, cand, elapsed = simulate_local_guess(secret_hash, candidates, salt)
            if found:
                self.append_result(f"Found locally: '{cand}' in {elapsed:.4f}s")
            else:
                self.append_result(f"Not found in local list (elapsed {elapsed:.4f}s)")

        threading.Thread(target=_work, daemon=True).start()


def run(on_close=None):
    app = BruteForceDemoGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()

