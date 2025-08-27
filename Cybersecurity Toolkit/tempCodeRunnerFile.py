"""
Cybersecurity Toolkit - Main Entry Point (GUI)
"""
import sys
import os
# Ensure the current package directory is on sys.path so `import modules` works
sys.path.insert(0, os.path.dirname(__file__))
import customtkinter as ctk
import platform
import socket
import threading
import time
import requests
from typing import Optional

from modules import port_scanner, vuln_scanner, packet_sniffer, encryption, web_tools, ml_security, brute_force_demo


class ToolkitGUI(ctk.CTk):
    """Single-window CTk app with pages: Main Menu, Dashboard, and Module container.

    It attempts to embed modules if they expose `create_frame(parent, on_close=None)`.
    Otherwise it offers an "Open in new window" fallback which calls the module's
    existing `run(on_close=...)` API.
    """

    def __init__(self):
        super().__init__()
        self.title("Cybersecurity Toolkit")
        self.resizable(True, True)
        window_width, window_height = 1000, 700
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Top header
        header = ctk.CTkLabel(self, text="Cybersecurity Toolkit", font=("Arial", 26, "bold"))
        header.pack(fill="x", pady=(10, 0))

        # Main container where pages render
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True, padx=16, pady=12)

        # Pages
        self.pages = {}
        self._create_main_menu()
        self._create_dashboard()
        self._create_module_page()

        self.show_page("main")

    # --- Pages -------------------------------------------------
    def _create_main_menu(self):
        frame = ctk.CTkFrame(self.container)
        left = ctk.CTkFrame(frame, width=300)
        left.pack(side="left", fill="y", padx=(12, 8), pady=12)

        logo = ctk.CTkLabel(left, text="Menu", font=("Arial", 18, "bold"))
        logo.pack(pady=(6, 12))

        # Main navigation buttons
        btn_dash = ctk.CTkButton(left, text="Dashboard", width=260, command=lambda: self.show_page("dashboard"))
        btn_dash.pack(pady=6)

        tools = [
            ("Port Scanner", port_scanner),
            ("Vulnerability Scanner", vuln_scanner),
            ("Packet Sniffer", packet_sniffer),
            ("Brute-force Demo", brute_force_demo),
            ("Encryption/Decryption", encryption),
            ("Web Tools", web_tools),
            ("ML Security", ml_security),
        ]

        for name, module in tools:
            b = ctk.CTkButton(left, text=name, width=260, command=lambda m=module, n=name: self.show_module(m, n))
            b.pack(pady=6)

        exit_btn = ctk.CTkButton(left, text="Exit", fg_color="#d9534f", hover_color="#c9302c", width=260, command=self.quit)
        exit_btn.pack(side="bottom", pady=12)

        # Right: welcome + quick info
        right = ctk.CTkFrame(frame)
        right.pack(side="right", fill="both", expand=True, padx=(8, 12), pady=12)

        title = ctk.CTkLabel(right, text="Welcome — pick a tool to begin", font=("Arial", 20, "bold"))
        title.pack(pady=(18, 6))

        desc = ctk.CTkLabel(right, text=("This toolkit is designed for education and exploration. "
                                          "Use the Dashboard for quick intelligence and AI demos."), wraplength=700)
        desc.pack(pady=(6, 12))

        self.pages["main"] = frame

    def _create_dashboard(self):
        frame = ctk.CTkFrame(self.container)
        # Top summary
        summary = ctk.CTkFrame(frame)
        summary.pack(fill="x", padx=12, pady=(12, 8))

        self.sys_label = ctk.CTkLabel(summary, text="System: ..", anchor="w")
        self.sys_label.pack(fill="x", padx=12, pady=4)

        self.net_label = ctk.CTkLabel(summary, text="Network: ..", anchor="w")
        self.net_label.pack(fill="x", padx=12, pady=4)

        # Middle: AI demos / quick tasks
        mid = ctk.CTkFrame(frame)
        mid.pack(fill="both", expand=True, padx=12, pady=8)

        left = ctk.CTkFrame(mid)
        left.pack(side="left", fill="both", expand=True, padx=(8,6), pady=8)

        right = ctk.CTkFrame(mid)
        right.pack(side="right", fill="both", expand=True, padx=(6,8), pady=8)

        # Quick ML demo
        self.ml_output = ctk.CTkTextbox(left, width=420, height=240)
        self.ml_output.pack(padx=12, pady=12)
        self.ml_output.configure(state="disabled")

        ml_btn = ctk.CTkButton(left, text="Run Quick ML Demo", command=self._run_quick_ml)
        ml_btn.pack(pady=(6, 12))

        # CVE / Threat feed (optional)
        self.cve_box = ctk.CTkTextbox(right, width=420, height=240)
        self.cve_box.pack(padx=12, pady=12)
        self.cve_box.configure(state="disabled")

        cve_btn = ctk.CTkButton(right, text="Fetch recent CVEs (optional)", command=self._fetch_cves)
        cve_btn.pack(pady=(6, 12))

        back = ctk.CTkButton(frame, text="Back to Menu", width=160, command=lambda: self.show_page("main"))
        back.pack(side="bottom", pady=(6, 12))

        self.pages["dashboard"] = frame

    def _create_module_page(self):
        frame = ctk.CTkFrame(self.container)
        header = ctk.CTkLabel(frame, text="Module", font=("Arial", 20, "bold"))
        header.pack(pady=(12,6))

        self.module_title = ctk.CTkLabel(frame, text="", font=("Arial", 16))
        self.module_title.pack(pady=(4,8))
        self.module_frame = ctk.CTkFrame(frame)
        self.module_frame.pack(fill="both", expand=True, padx=12, pady=8)

        footer = ctk.CTkFrame(frame)
        footer.pack(fill="x", padx=12, pady=8)

        # Buttons: Open (previous behavior) and Embed (when supported)
        self.open_prev_btn = ctk.CTkButton(footer, text="Open (previous behavior)", command=lambda: None)
        self.open_prev_btn.pack(side="right", padx=6)

        self.embed_btn = ctk.CTkButton(footer, text="Embed (if supported)", command=lambda: None)
        self.embed_btn.pack(side="right", padx=6)

        back_btn = ctk.CTkButton(footer, text="Back", command=lambda: self.show_page("main"))
        back_btn.pack(side="left", padx=6)

        self.pages["module"] = frame

    # --- Page switching ---------------------------------------
    def show_page(self, name: str):
        for p in self.pages.values():
            p.pack_forget()
        page = self.pages.get(name)
        if page:
            page.pack(fill="both", expand=True)
        if name == "dashboard":
            self._refresh_dashboard()

    # --- Module handling --------------------------------------
    def show_module(self, module, title: str):
        # Clear module frame
        for w in self.module_frame.winfo_children():
            w.destroy()

        self.module_title.configure(text=title)
        # Default behavior: open previous behavior (hide main and call run)
        def open_prev():
            # hide main and run module in its own window, re-show main on close
            self.withdraw()
            def _show_main():
                self.deiconify()
            try:
                module.run(on_close=_show_main)
            except Exception as e:
                ctk.CTkLabel(self.module_frame, text=f"Failed to open module: {e}").pack(padx=12, pady=12)

        self.open_prev_btn.configure(command=open_prev)

        # Embed if supported
        create_frame = getattr(module, "create_frame", None)
        if callable(create_frame):
            def do_embed():
                for w in self.module_frame.winfo_children():
                    w.destroy()
                try:
                    embedded = create_frame(self.module_frame, on_close=lambda: self.show_page("main"))
                    if hasattr(embedded, "pack"):
                        embedded.pack(fill="both", expand=True)
                except Exception as e:
                    ctk.CTkLabel(self.module_frame, text=f"Embedding failed: {e}").pack(padx=12, pady=12)
            self.embed_btn.configure(command=do_embed)
            ctk.CTkLabel(self.module_frame, text=("This module supports embedding. Use 'Embed' to render it inside the toolkit, "
                                                   "or 'Open (previous behavior)' to run it in a separate window."), wraplength=720).pack(padx=12, pady=12)
        else:
            self.embed_btn.configure(state="disabled")
            ctk.CTkLabel(self.module_frame, text=("This module does not support embedding. Click 'Open (previous behavior)' to launch it in its own window."), wraplength=720).pack(padx=12, pady=12)

        self.show_page("module")

    def _setup_open_new_window(self, module):
        def opener():
            # Open module in a new window but keep this app running; pass on_close to navigate back
            module.run(on_close=lambda: self.show_page("main"))
    # Legacy helper removed; use open_prev_btn configured in show_module instead.

    # --- Dashboard helpers -----------------------------------
    def _refresh_dashboard(self):
        # System
        sys_text = f"Platform: {platform.system()} {platform.release()} | Python: {platform.python_version()}"
        self.sys_label.configure(text=sys_text)

        # Local IPs (simple)
        try:
            hostname = socket.gethostname()
            ips = socket.gethostbyname_ex(hostname)[2]
            net_text = f"Host: {hostname} | IPs: {', '.join(ips)}"
        except Exception:
            net_text = "Network: unavailable"
        self.net_label.configure(text=net_text)

    def _run_quick_ml(self):
        def work():
            self._append_ml("Starting quick ML demo (synthetic dataset)...")
            try:
                # lightweight synthetic logistic regression demo
                from sklearn.datasets import make_classification
                from sklearn.linear_model import LogisticRegression
                from sklearn.model_selection import train_test_split
                X, y = make_classification(n_samples=300, n_features=12, n_informative=6, random_state=1)
                Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=1)
                model = LogisticRegression(max_iter=200)
                model.fit(Xtr, ytr)
                acc = model.score(Xte, yte)
                self._append_ml(f"Quick ML demo done — accuracy: {acc:.3f}")
                self._append_ml("Tip: use the ML Security module for adversarial examples and deeper explanations.")
            except Exception as e:
                self._append_ml(f"ML demo failed: {e}\n(install scikit-learn and numpy to run this demo)")

        threading.Thread(target=work, daemon=True).start()

    def _append_ml(self, text: str):
        def _add():
            self.ml_output.configure(state="normal")
            self.ml_output.insert(ctk.END, text + "\n")
            self.ml_output.see(ctk.END)
            self.ml_output.configure(state="disabled")
        self.after(0, _add)

    def _fetch_cves(self):
        def work():
            self._append_cve("Fetching recent CVEs (this may take a moment)...")
            try:
                # public CVE feed (3rd-party); optional and best-effort
                r = requests.get("https://cve.circl.lu/api/last", timeout=8)
                if r.status_code == 200:
                    data = r.json()
                    for item in data[:6]:
                        self._append_cve(f"{item.get('id')}: {item.get('summary')[:140]}")
                else:
                    self._append_cve(f"Feed returned status {r.status_code}")
            except Exception as e:
                self._append_cve(f"Failed to fetch CVEs: {e}")

        threading.Thread(target=work, daemon=True).start()

    def _append_cve(self, text: str):
        def _add():
            self.cve_box.configure(state="normal")
            self.cve_box.insert(ctk.END, text + "\n\n")
            self.cve_box.see(ctk.END)
            self.cve_box.configure(state="disabled")
        self.after(0, _add)

    def quit(self):
        self.destroy()
        sys.exit(0)


if __name__ == "__main__":
    app = ToolkitGUI()
    app.mainloop()
