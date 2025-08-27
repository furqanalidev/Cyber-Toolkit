"""Web Tools GUI

Safe, non-intrusive web utilities: fetch HTTP headers, retrieve robots.txt,
check URL status and timing. All operations use `requests` with timeouts.
"""
from __future__ import annotations
import threading
import time
import requests
import customtkinter as ctk


class WebToolsGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Web Tools")
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

        self.header = ctk.CTkLabel(self.scrollable_frame, text="Web Tools", font=("Arial", 28, "bold"))
        self.header.pack(pady=(18, 8))

        # Input
        input_frame = ctk.CTkFrame(self.scrollable_frame)
        input_frame.pack(fill="x", padx=20, pady=(6, 10))

        self.url_entry = ctk.CTkEntry(input_frame, width=520, placeholder_text="https://example.com")
        self.url_entry.grid(row=0, column=0, padx=6, pady=6)

        self.headers_btn = ctk.CTkButton(input_frame, text="Fetch Headers", command=self.fetch_headers)
        self.headers_btn.grid(row=0, column=1, padx=6, pady=6)

        self.robots_btn = ctk.CTkButton(input_frame, text="Check robots.txt", command=self.fetch_robots)
        self.robots_btn.grid(row=0, column=2, padx=6, pady=6)

        # Status checker (multiple URLs)
        self.urls_entry = ctk.CTkEntry(input_frame, width=520, placeholder_text="comma-separated URLs for status check")
        self.urls_entry.grid(row=1, column=0, columnspan=2, padx=6, pady=6)
        self.urls_entry.insert(0, "https://example.com, https://httpbin.org/status/200")
        self.urls_btn = ctk.CTkButton(input_frame, text="Check URLs", command=self.check_urls)
        self.urls_btn.grid(row=1, column=2, padx=6, pady=6)

        # Output box
        self.output = ctk.CTkTextbox(self.scrollable_frame, width=740, height=360, font=("Consolas", 11))
        self.output.pack(padx=20, pady=(6, 18))
        self.output.configure(state="disabled")

    def append(self, text: str):
        def _add():
            self.output.configure(state="normal")
            self.output.insert(ctk.END, text + "\n")
            self.output.see(ctk.END)
            self.output.configure(state="disabled")
        try:
            self.after(0, _add)
        except Exception:
            _add()

    def fetch_headers(self):
        url = self.url_entry.get().strip()
        if not url:
            self.append("Please enter a URL")
            return

        def _work():
            self.append(f"Fetching headers for {url}...")
            try:
                start = time.time()
                r = requests.head(url, timeout=6, allow_redirects=True)
                elapsed = time.time() - start
                self.append(f"Status: {r.status_code} ({elapsed:.2f}s)")
                for k, v in r.headers.items():
                    self.append(f"{k}: {v}")
            except Exception as e:
                self.append(f"Error fetching headers: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def fetch_robots(self):
        url = self.url_entry.get().strip()
        if not url:
            self.append("Please enter a URL")
            return
        if url.endswith('/'):
            base = url.rstrip('/')
        else:
            base = url

        def _work():
            robots_url = base + '/robots.txt'
            self.append(f"Checking {robots_url} ...")
            try:
                r = requests.get(robots_url, timeout=6)
                self.append(f"Status: {r.status_code}")
                if r.status_code == 200:
                    self.append(r.text[:200] + ('...' if len(r.text) > 200 else ''))
                else:
                    self.append('robots.txt not found or inaccessible')
            except Exception as e:
                self.append(f"Error fetching robots.txt: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def check_urls(self):
        raw = self.urls_entry.get().strip()
        if not raw:
            self.append('Please enter one or more URLs (comma-separated)')
            return
        urls = [u.strip() for u in raw.split(',') if u.strip()]

        def _work():
            for u in urls:
                self.append(f"Checking {u} ...")
                try:
                    start = time.time()
                    r = requests.get(u, timeout=6)
                    elapsed = time.time() - start
                    self.append(f"{u} -> {r.status_code} ({elapsed:.2f}s)")
                except Exception as e:
                    self.append(f"{u} -> error: {e}")

        threading.Thread(target=_work, daemon=True).start()


def run(on_close=None):
    app = WebToolsGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()


class WebToolsFrame(ctk.CTkFrame):
    """Embeddable frame version of Web Tools for the toolkit container."""
    def __init__(self, parent, on_close=None):
        super().__init__(parent)
        self.on_close = on_close
        # Build a compact version of the UI inside the provided parent frame
        header = ctk.CTkLabel(self, text="Web Tools", font=("Arial", 20, "bold"))
        header.pack(pady=(6, 8))

        input_frame = ctk.CTkFrame(self)
        input_frame.pack(fill="x", padx=6, pady=(4, 8))

        self.url_entry = ctk.CTkEntry(input_frame, width=420, placeholder_text="https://example.com")
        self.url_entry.grid(row=0, column=0, padx=6, pady=6)
        self.headers_btn = ctk.CTkButton(input_frame, text="Fetch Headers", command=self.fetch_headers)
        self.headers_btn.grid(row=0, column=1, padx=6, pady=6)
        self.robots_btn = ctk.CTkButton(input_frame, text="robots.txt", command=self.fetch_robots)
        self.robots_btn.grid(row=0, column=2, padx=6, pady=6)

        self.urls_entry = ctk.CTkEntry(input_frame, width=420, placeholder_text="comma-separated URLs")
        self.urls_entry.grid(row=1, column=0, columnspan=2, padx=6, pady=6)
        self.urls_entry.insert(0, "https://example.com, https://httpbin.org/status/200")
        self.urls_btn = ctk.CTkButton(input_frame, text="Check URLs", command=self.check_urls)
        self.urls_btn.grid(row=1, column=2, padx=6, pady=6)

        self.output = ctk.CTkTextbox(self, width=720, height=240, font=("Consolas", 11))
        self.output.pack(padx=6, pady=(6, 12))
        self.output.configure(state="disabled")

    def append(self, text: str):
        def _add():
            self.output.configure(state="normal")
            self.output.insert(ctk.END, text + "\n")
            self.output.see(ctk.END)
            self.output.configure(state="disabled")
        try:
            self.after(0, _add)
        except Exception:
            _add()

    def fetch_headers(self):
        url = self.url_entry.get().strip()
        if not url:
            self.append("Please enter a URL")
            return

        def _work():
            self.append(f"Fetching headers for {url}...")
            try:
                start = time.time()
                r = requests.head(url, timeout=6, allow_redirects=True)
                elapsed = time.time() - start
                self.append(f"Status: {r.status_code} ({elapsed:.2f}s)")
                for k, v in r.headers.items():
                    self.append(f"{k}: {v}")
            except Exception as e:
                self.append(f"Error fetching headers: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def fetch_robots(self):
        url = self.url_entry.get().strip()
        if not url:
            self.append("Please enter a URL")
            return
        base = url.rstrip('/') if url.endswith('/') else url

        def _work():
            robots_url = base + '/robots.txt'
            self.append(f"Checking {robots_url} ...")
            try:
                r = requests.get(robots_url, timeout=6)
                self.append(f"Status: {r.status_code}")
                if r.status_code == 200:
                    self.append(r.text[:200] + ('...' if len(r.text) > 200 else ''))
                else:
                    self.append('robots.txt not found or inaccessible')
            except Exception as e:
                self.append(f"Error fetching robots.txt: {e}")

        threading.Thread(target=_work, daemon=True).start()

    def check_urls(self):
        raw = self.urls_entry.get().strip()
        if not raw:
            self.append('Please enter one or more URLs (comma-separated)')
            return
        urls = [u.strip() for u in raw.split(',') if u.strip()]

        def _work():
            for u in urls:
                self.append(f"Checking {u} ...")
                try:
                    start = time.time()
                    r = requests.get(u, timeout=6)
                    elapsed = time.time() - start
                    self.append(f"{u} -> {r.status_code} ({elapsed:.2f}s)")
                except Exception as e:
                    self.append(f"{u} -> error: {e}")

        threading.Thread(target=_work, daemon=True).start()


def create_frame(parent, on_close=None):
    return WebToolsFrame(parent, on_close=on_close)
