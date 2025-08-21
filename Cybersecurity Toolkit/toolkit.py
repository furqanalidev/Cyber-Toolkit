"""
Cybersecurity Toolkit - Main Entry Point (GUI)
"""
import sys
import os
import customtkinter as ctk
from modules import port_scanner, vuln_scanner, packet_sniffer, encryption, web_tools, ml_security


class ToolkitGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cybersecurity Toolkit")
        self.resizable(True, True)
        window_width, window_height = 800, 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = int((screen_width / 2) - (window_width / 2))
        y = int((screen_height / 2) - (window_height / 2))
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Scrollable frame for content
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height-20)
        self.scrollable_frame.pack(fill="both", expand=True)

        self.header = ctk.CTkLabel(self.scrollable_frame, text="Cybersecurity Toolkit", font=("Arial", 28, "bold"))
        self.header.pack(pady=(30, 10))

        self.desc = ctk.CTkLabel(self.scrollable_frame, text="Select a tool to launch", font=("Arial", 16))
        self.desc.pack(pady=(0, 30))

        self.buttons = []
        tools = [
            ("Port Scanner", port_scanner.run),
            ("Vulnerability Scanner", vuln_scanner.run),
            ("Packet Sniffer", packet_sniffer.run),
            ("Encryption/Decryption", encryption.run),
            ("Web Tools", web_tools.run),
            ("ML Security", ml_security.run)
        ]
        for idx, (name, func) in enumerate(tools):
            btn = ctk.CTkButton(self.scrollable_frame, text=name, font=("Arial", 18), width=320, height=50, command=lambda f=func: self.launch_feature(f))
            btn.pack(pady=10)
            self.buttons.append(btn)

        self.exit_btn = ctk.CTkButton(self.scrollable_frame, text="Exit", font=("Arial", 16), fg_color="#d9534f", hover_color="#c9302c", width=120, height=40, command=self.quit)
        self.exit_btn.pack(pady=(40, 10))

    def launch_feature(self, feature_func):
        self.withdraw()  # Hide main window
        def show_main():
            self.deiconify()
        feature_func(on_close=show_main)

    def quit(self):
        self.destroy()
        sys.exit(0)

if __name__ == "__main__":
    app = ToolkitGUI()
    app.mainloop()
