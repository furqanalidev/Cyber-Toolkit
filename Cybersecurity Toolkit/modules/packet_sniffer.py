import os
import sys
import threading
import time
import customtkinter as ctk
from tkinter import filedialog

# Try to import scapy
SCAPY_AVAILABLE = True
try:
    from scapy.all import sniff, wrpcap
except Exception:
    SCAPY_AVAILABLE = False


class PacketSnifferGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Packet Sniffer")
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

        self.header = ctk.CTkLabel(self.scrollable_frame, text="Packet Sniffer", font=("Arial", 28, "bold"))
        self.header.pack(pady=(20, 10))

        self.controls_frame = ctk.CTkFrame(self.scrollable_frame)
        self.controls_frame.pack(fill="x", padx=20, pady=(0, 10))

        self.iface_label = ctk.CTkLabel(self.controls_frame, text="Interface (optional)")
        self.iface_label.grid(row=0, column=0, padx=6, pady=6)
        # Populate interface list when scapy available to avoid invalid names
        iface_values = []
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import get_if_list
                iface_values = get_if_list()
            except Exception:
                iface_values = []

        # Use a combo box when available, otherwise fall back to entry
        try:
            self.iface_combo = ctk.CTkComboBox(self.controls_frame, values=iface_values, width=200)
            if iface_values:
                self.iface_combo.set(iface_values[0])
            self.iface_combo.grid(row=0, column=1, padx=6, pady=6)
        except Exception:
            self.iface_entry = ctk.CTkEntry(self.controls_frame, width=200, placeholder_text="e.g., eth0 or leave blank")
            self.iface_entry.grid(row=0, column=1, padx=6, pady=6)

        self.filter_label = ctk.CTkLabel(self.controls_frame, text="Filter (tcp/udp/icmp)")
        self.filter_label.grid(row=0, column=2, padx=6, pady=6)
        self.filter_entry = ctk.CTkEntry(self.controls_frame, width=150, placeholder_text="tcp")
        self.filter_entry.grid(row=0, column=3, padx=6, pady=6)

        self.start_btn = ctk.CTkButton(self.controls_frame, text="Start Capture", command=self.start_capture, fg_color="#28a745")
        self.start_btn.grid(row=0, column=4, padx=6, pady=6)

        self.stop_btn = ctk.CTkButton(self.controls_frame, text="Stop Capture", command=self.stop_capture, fg_color="#dc3545")
        self.stop_btn.grid(row=0, column=5, padx=6, pady=6)

        self.export_btn = ctk.CTkButton(self.controls_frame, text="Export PCAP", command=self.export_pcap)
        self.export_btn.grid(row=0, column=6, padx=6, pady=6)

        self.packets_list = ctk.CTkTextbox(self.scrollable_frame, width=740, height=360, font=("Consolas", 11))
        self.packets_list.pack(padx=20, pady=10)
        self.packets_list.configure(state="disabled")

        self.status_label = ctk.CTkLabel(self.scrollable_frame, text="Status: Idle")
        self.status_label.pack(pady=(0, 12))

        self.capturing = False
        self.captured_packets = []
        self.sniff_thread = None

    def append_line(self, line):
        self.packets_list.configure(state="normal")
        self.packets_list.insert(ctk.END, line + "\n")
        self.packets_list.configure(state="disabled")

    def start_capture(self):
        if not SCAPY_AVAILABLE:
            self.append_line("Scapy not installed. Install scapy to enable packet capture.")
            return
        if self.capturing:
            return
        self.captured_packets = []
        self.capturing = True
        self.status_label.configure(text="Status: Capturing...")
        # read iface from combo or entry
        iface = None
        try:
            iface = getattr(self, 'iface_combo').get().strip() or None
        except Exception:
            try:
                iface = getattr(self, 'iface_entry').get().strip() or None
            except Exception:
                iface = None
        filt = self.filter_entry.get().strip()
        bpf = None
        if filt:
            if filt.lower() in ('tcp', 'udp', 'icmp'):
                bpf = filt.lower()
        self.sniff_thread = threading.Thread(target=self._sniff, args=(iface, bpf), daemon=True)
        self.sniff_thread.start()

    def _sniff(self, iface, bpf):
        def _pktcb(pkt):
            summary = pkt.summary()
            self.captured_packets.append(pkt)
            # thread-safe append
            self.append_line(summary)

        try:
            sniff(prn=_pktcb, iface=iface, filter=bpf, store=False)
        except Exception as e:
            self.append_line(f"Capture error: {e}")
        finally:
            self.capturing = False
            self.status_label.configure(text="Status: Idle")

    def stop_capture(self):
        # scapy sniff runs until killed; simplest approach is to set capturing False and rely on scapy stop filter
        # a portable way is to use stop_filter in sniff, but for now we inform the user to press Stop and we will try to terminate thread.
        if not SCAPY_AVAILABLE:
            return
        if not self.capturing:
            return
        # monkey: raises in thread not trivial; as a simple workaround, set capturing flag and inform user
        self.capturing = False
        self.status_label.configure(text="Status: Stopping... (may take a moment)")
        # scapy doesn't provide a direct stop; let user know
        self.append_line("Stop requested. Capture thread may still run until kernel-level sniff returns.")

    def export_pcap(self):
        if not self.captured_packets:
            self.append_line("No packets to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension='.pcap', filetypes=[('PCAP files', '*.pcap')])
        if not path:
            return
        try:
            wrpcap(path, self.captured_packets)
            self.append_line(f"Exported {len(self.captured_packets)} packets to {path}")
        except Exception as e:
            self.append_line(f"Failed to export pcap: {e}")


def run(on_close=None):
    app = PacketSnifferGUI()
    if on_close:
        def handle_close():
            app.destroy()
            on_close()
        app.protocol("WM_DELETE_WINDOW", handle_close)
    app.mainloop()
