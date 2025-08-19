
import customtkinter as ctk
from tkinter import messagebox
import threading
import os
import sys
from core.portscanner_lib import scan_ports
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PortScannerApp(ctk.CTk):
	def __init__(self):
		super().__init__()
		self.title("Port Scanner")
		self.geometry("500x500")
		self.resizable(False, False)

		self.host_label = ctk.CTkLabel(self, text="Enter Host:", font=("Arial", 16))
		self.host_label.pack(pady=(30, 5))
		self.host_entry = ctk.CTkEntry(self, width=300, font=("Arial", 14))
		self.host_entry.pack(pady=5)

		self.port_range_label = ctk.CTkLabel(self, text="Port Range (e.g. 1-1024):", font=("Arial", 14))
		self.port_range_label.pack(pady=(20, 5))
		self.port_range_entry = ctk.CTkEntry(self, width=200, font=("Arial", 12))
		self.port_range_entry.insert(0, "1-1024")
		self.port_range_entry.pack(pady=5)

		self.scan_button = ctk.CTkButton(self, text="Scan", command=self.start_scan, font=("Arial", 16), fg_color="#1e90ff")
		self.scan_button.pack(pady=20)

        # Add a frame for textbox and scrollbar
		self.result_frame = ctk.CTkFrame(self)
		self.result_frame.pack(pady=10, fill="both", expand=True)
		self.result_box = ctk.CTkTextbox(self.result_frame, width=430, height=250, font=("Consolas", 12), wrap="none")
		self.result_box.pack(side="left", fill="both", expand=True)
		self.scrollbar = ctk.CTkScrollbar(self.result_frame, orientation="vertical", command=self.result_box.yview)
		self.scrollbar.pack(side="right", fill="y")
		self.result_box.configure(yscrollcommand=self.scrollbar.set)
		self.result_box.insert("end", "Results will appear here...\n")
		self.result_box.configure(state="disabled")

	def start_scan(self):
		host = self.host_entry.get().strip()
		port_range = self.port_range_entry.get().strip()
		if not host:
			messagebox.showerror("Input Error", "Please enter a host.")
			return
		try:
			port_start, port_end = map(int, port_range.split("-"))
		except Exception:
			messagebox.showerror("Input Error", "Port range must be in the format start-end, e.g. 1-1024.")
			return
		self.result_box.configure(state="normal")
		self.result_box.delete("1.0", "end")
		self.result_box.insert("end", f"Scanning {host} ({port_start}-{port_end})...\n")
		self.result_box.configure(state="disabled")
		threading.Thread(target=self.run_scan, args=(host, port_start, port_end), daemon=True).start()

	def run_scan(self, host, port_start, port_end):
		result = scan_ports(host, port_start, port_end)
		self.result_box.configure(state="normal")
		self.result_box.delete("1.0", "end")
		if result["error"]:
			self.result_box.insert("end", f"Error: {result['error']}\n")
		else:
			self.result_box.insert("end", f"Host: {result['host']} ({result['host_ip']})\n")
			if result['open_ports']:
				self.result_box.insert("end", f"{'Port':<8}{'Service':<20}\n")
				self.result_box.insert("end", f"{'-'*28}\n")
				for portinfo in result['open_ports']:
					self.result_box.insert("end", f"{portinfo['port']:<8}{portinfo['service']:<20}\n")
			else:
				self.result_box.insert("end", "No open ports found.\n")
			self.result_box.insert("end", f"\nTime taken: {result['duration']}\n")
		self.result_box.configure(state="disabled")

if __name__ == "__main__":
	app = PortScannerApp()
	app.mainloop()
