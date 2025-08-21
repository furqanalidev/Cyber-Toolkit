def run():
    print("\n--- Vulnerability Scanner ---")
    print("Feature coming soon!")

import customtkinter as ctk
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

        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height-20)
        self.scrollable_frame.pack(fill="both", expand=True)

        self.header = ctk.CTkLabel(self.scrollable_frame, text="Vulnerability Scanner", font=("Arial", 28, "bold"))
        self.header.pack(pady=(30, 10))

        self.desc = ctk.CTkLabel(self.scrollable_frame, text="Feature coming soon!", font=("Arial", 16))
        self.desc.pack(pady=(0, 30))

def run(on_close=None):
    app = VulnScannerGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()
