"""
Port Scanner Module - GUI Version
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../utils')))
from portscanner_lib import scan_ports
import customtkinter as ctk
import threading

class PortScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
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

        self.label = ctk.CTkLabel(self.scrollable_frame, text="Port Scanner", font=("Arial", 28, "bold"))
        self.label.pack(pady=20)

        self.target_entry = ctk.CTkEntry(self.scrollable_frame, width=300, placeholder_text="Target IP or domain")
        self.target_entry.pack(pady=10)

        self.range_label = ctk.CTkLabel(self.scrollable_frame, text="Port Range (e.g. 20-80):", font=("Arial", 14))
        self.range_label.pack(pady=(10, 0))
        self.range_entry = ctk.CTkEntry(self.scrollable_frame, width=300, placeholder_text="e.g. 20-80")
        self.range_entry.pack(pady=5)

        self.scan_btn = ctk.CTkButton(self.scrollable_frame, text="Scan", command=self.start_scan)
        self.scan_btn.pack(pady=10)

        self.result_box = ctk.CTkTextbox(self.scrollable_frame, width=700, height=180, font=("Consolas", 12))
        self.result_box.pack(pady=10)
        self.result_box.configure(state="disabled")

    def start_scan(self):
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", ctk.END)
        self.result_box.insert(ctk.END, "Scanning...\n")
        self.result_box.configure(state="disabled")
        threading.Thread(target=self.scan_ports, daemon=True).start()

    def scan_ports(self):
        # Only call scan_ports from portscanner_lib and display results
        target = self.target_entry.get().strip()
        port_range = self.range_entry.get().strip()
        try:
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
            else:
                start_port = end_port = int(port_range)
        except Exception:
            self.show_result("Invalid port range.")
            return
        result = scan_ports(target, port_start=start_port, port_end=end_port)
        if result["error"]:
            self.show_result(f"Error: {result['error']}")
            return
        output = [f"Host: {result['host']} ({result['host_ip']})"]
        output.append(f"Scanned ports: {start_port}-{end_port}")
        output.append(f"Scan duration: {result['duration']}")
        if result["open_ports"]:
            output.append("\nOpen Ports:")
            for portinfo in result["open_ports"]:
                output.append(f"Port {portinfo['port']}: OPEN ({portinfo['service']})")
        else:
            output.append("\nNo open ports found in range.")
        self.show_result("\n".join(output))

    def show_result(self, text):
        self.result_box.configure(state="normal")
        self.result_box.delete("1.0", ctk.END)
        self.result_box.insert(ctk.END, text)
        self.result_box.configure(state="disabled")

def run(on_close=None):
    app = PortScannerGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()
