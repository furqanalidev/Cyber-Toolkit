y = int((screen_height / 2) - (window_height / 2))
self.geometry(f"{window_width}x{window_height}+{x}+{y}")
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

        # Scrollable frame for content
self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height-20)
self.scrollable_frame.pack(fill="both", expand=True)

self.header = ctk.CTkLabel(self.scrollable_frame, text="Cybersecurity Toolkit", font=("Arial", 28, "bold"))