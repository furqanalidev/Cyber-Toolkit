def run():
    print("\n--- Vulnerability Scanner ---")
    print("Feature coming soon!")

import os
import sys
import socket
import datetime
import ssl
import threading
import customtkinter as ctk

# import shared port scanner
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../utils')))
from portscanner_lib import scan_ports
import requests


class VulnScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Scanner")
        self.resizable(True, True)
        window_width, window_height = 800, 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Decorative header frame (simple beautiful background)
        self.header_frame = ctk.CTkFrame(self, corner_radius=0)
        self.header_frame.pack(fill="x")
        self.header = ctk.CTkLabel(self.header_frame, text="Vulnerability Scanner", font=("Arial", 26, "bold"))
        self.header.pack(padx=20, pady=16)

        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height-80)
        self.scrollable_frame.pack(fill="both", expand=True)

        # Input area
        self.target_label = ctk.CTkLabel(self.scrollable_frame, text="Target (IP or domain)", font=("Arial", 14))
        self.target_label.pack(pady=(20, 6))
        self.target_entry = ctk.CTkEntry(self.scrollable_frame, width=420, placeholder_text="example.com")
        self.target_entry.pack(pady=(0, 12))

        self.range_label = ctk.CTkLabel(self.scrollable_frame, text="Port range (e.g. 1-1024)", font=("Arial", 14))
        self.range_label.pack(pady=(6, 6))
        self.range_entry = ctk.CTkEntry(self.scrollable_frame, width=420, placeholder_text="1-1024")
        self.range_entry.pack(pady=(0, 12))

        self.scan_btn = ctk.CTkButton(self.scrollable_frame, text="Scan for Vulnerabilities", width=260, height=44, command=self.start_scan)
        self.scan_btn.pack(pady=10)

        self.result_box = ctk.CTkTextbox(self.scrollable_frame, width=740, height=300, font=("Consolas", 12))
        self.result_box.pack(pady=12)
        self.result_box.configure(state="disabled")

    def start_scan(self):
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", ctk.END)
        self.result_box.insert(ctk.END, "Starting vulnerability scan...\n")
        self.result_box.configure(state="disabled")
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        target = self.target_entry.get().strip()
        port_range = self.range_entry.get().strip() or "1-1024"
        try:
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
        except Exception:
            self.show_result("Invalid port range format. Use start-end (e.g. 1-1024).")
            return

        self.append_result(f"Resolving target: {target}...")
        try:
            host_ip = socket.gethostbyname(target)
        except Exception as e:
            self.show_result(f"Could not resolve {target}: {e}")
            return

        self.append_result(f"IP: {host_ip}\nScanning ports {start_port}-{end_port} (this may take a while)...")
        scan = scan_ports(target, port_start=start_port, port_end=end_port, timeout=0.01)

        output_lines = [f"Target: {target} ({scan.get('host_ip')})", f"Scan duration: {scan.get('duration')}"]
        open_ports = scan.get('open_ports', [])
        if open_ports:
            output_lines.append("\nOpen ports:")
            for p in open_ports:
                output_lines.append(f" - {p['port']}: {p.get('service','Unknown')}")
        else:
            output_lines.append("\nNo open ports found.")

        # HTTP/HTTPS checks
        http_ports = {80: 'http', 443: 'https'}
        issues = []
        for p in open_ports:
            port = p['port']
            if port in http_ports:
                scheme = http_ports[port]
                url = f"{scheme}://{target}"
                try:
                    self.append_result(f"Checking {url} ...")
                    resp = requests.get(url, timeout=5, allow_redirects=True, headers={"User-Agent": "CyberToolkitScanner/1.0"})
                    headers = resp.headers
                    # Check common security headers
                    missing = []
                    for hdr in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']:
                        if hdr not in headers:
                            missing.append(hdr)
                    if missing:
                        issues.append(f"{scheme.upper()} at port {port} missing security headers: {', '.join(missing)}")
                    # Expose Server header
                    server = headers.get('Server')
                    if server:
                        issues.append(f"{scheme.upper()} at port {port} reveals Server: {server}")
                    # robots.txt check (non-intrusive)
                    try:
                        r2 = requests.get(f"{url.rstrip('/')}/robots.txt", timeout=3)
                        if r2.status_code == 200:
                            issues.append(f"robots.txt available at {url}/robots.txt (may reveal paths)")
                    except Exception:
                        pass
                except Exception as e:
                    issues.append(f"Failed to check HTTP service on port {port}: {e}")
            # TLS certificate check for 443
            if port == 443:
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                        s.settimeout(3)
                        s.connect((target, 443))
                        cert = s.getpeercert()
                        # get expiry
                        notAfter = cert.get('notAfter')
                        if notAfter:
                            expiry = datetime.datetime.strptime(notAfter, "%b %d %H:%M:%S %Y %Z") if isinstance(notAfter, str) else None
                            if expiry and expiry < datetime.datetime.utcnow():
                                issues.append("TLS certificate is expired")
                except Exception as e:
                    issues.append(f"TLS certificate check failed: {e}")

        if issues:
            output_lines.append("\nPotential issues found:")
            output_lines.extend([f" - {i}" for i in issues])
        else:
            output_lines.append("\nNo obvious issues found by these basic checks.")

        self.show_result("\n".join(output_lines))

    def append_result(self, text):
        self.result_box.configure(state="normal")
        self.result_box.insert(ctk.END, text + "\n")
        self.result_box.configure(state="disabled")

    def show_result(self, text):
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", ctk.END)
        self.result_box.insert(ctk.END, text)
        self.result_box.configure(state="disabled")


def run(on_close=None):
    app = VulnScannerGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()
