import os
import sys
import threading
import time
import subprocess
import re
import customtkinter as ctk
from tkinter import filedialog

# Try to import scapy
SCAPY_AVAILABLE = True
try:
    from scapy.all import sniff, wrpcap, AsyncSniffer, get_if_list
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
                # Prefer Windows-aware listing if available
                try:
                    from scapy.all import get_windows_if_list
                    win_ifaces = get_windows_if_list()
                    # get_windows_if_list returns a list of dicts with 'name' and 'description' and 'guid'
                    iface_values = [f"{i.get('name')} ({i.get('description')})" if i.get('description') else i.get('name') for i in win_ifaces]
                except Exception:
                    # Fallback to generic list and attempt to map GUIDs to friendly names
                    from scapy.all import get_if_list
                    raw_ifaces = get_if_list()
                    iface_values = []
                    # Try to map NPF_{GUID} to friendly names via wmic (Windows). If not available, keep raw names
                    guid_pattern = re.compile(r"NPF_\{([0-9A-Fa-f\-]+)\}")
                    try:
                        # Query WMI for network adapters (GUID and NetConnectionID/Name)
                        wmic = subprocess.run(["wmic", "nic", "get", "GUID,NetConnectionID,Name"], capture_output=True, text=True, timeout=3)
                        w_out = wmic.stdout if wmic.returncode == 0 else ''
                        # Parse lines to build a GUID->friendly map
                        guid_map = {}
                        for line in w_out.splitlines():
                            parts = [p.strip() for p in line.split(None, 2)]
                            if len(parts) >= 1:
                                # heuristics: GUID is first or last; look for GUID pattern
                                m = re.search(r"\{[0-9A-Fa-f\-]+\}", line)
                                if m:
                                    guid = m.group(0).strip('{}')
                                    # attempt to extract NetConnectionID
                                    nid = ''
                                    # crude split by two spaces
                                    cols = [c.strip() for c in line.split('  ') if c.strip()]
                                    if len(cols) >= 2:
                                        nid = cols[0]
                                    guid_map[guid.upper()] = nid or line.strip()
                        for iface in raw_ifaces:
                            m = guid_pattern.search(iface)
                            if m:
                                g = m.group(1).upper()
                                friendly = guid_map.get(g)
                                if friendly:
                                    iface_values.append(f"{iface} ({friendly})")
                                else:
                                    iface_values.append(iface)
                            else:
                                iface_values.append(iface)
                    except Exception:
                        iface_values = raw_ifaces
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

        self.packets_list = ctk.CTkTextbox(self.scrollable_frame, width=740, height=260, font=("Consolas", 11))
        self.packets_list.pack(padx=20, pady=10)
        self.packets_list.configure(state="disabled")

        # Packet detail box (click a packet line above to view full packet.show() dump)
        self.detail_box = ctk.CTkTextbox(self.scrollable_frame, width=740, height=120, font=("Consolas", 11))
        self.detail_box.pack(padx=20, pady=(0, 10))
        self.detail_box.configure(state="disabled")
        # Bind mouse click to show details
        try:
            self.packets_list.bind("<ButtonRelease-1>", self.on_packet_click)
        except Exception:
            pass

        self.status_label = ctk.CTkLabel(self.scrollable_frame, text="Status: Idle")
        self.status_label.pack(pady=(0, 12))

    self.capturing = False
    self.captured_packets = []
    self.sniffer = None

    def append_line(self, line):
        # Ensure UI updates happen on the main thread
        def _append():
            self.packets_list.configure(state="normal")
            self.packets_list.insert(ctk.END, line + "\n")
            self.packets_list.see(ctk.END)
            self.packets_list.configure(state="disabled")
        try:
            self.after(0, _append)
        except Exception:
            _append()

    def on_packet_click(self, event):
        try:
            idx = self.packets_list.index(f"@{event.x},{event.y}")
            line_no = int(idx.split('.')[0]) - 1
            if 0 <= line_no < len(self.captured_packets):
                pkt = self.captured_packets[line_no]
                try:
                    dump = pkt.show(dump=True)
                except Exception:
                    dump = repr(pkt)
                self.show_packet_details(dump)
        except Exception:
            pass

    def show_packet_details(self, text):
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", ctk.END)
        self.detail_box.insert(ctk.END, text)
        self.detail_box.configure(state="disabled")

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
        if filt and filt.lower() in ('tcp', 'udp', 'icmp'):
            bpf = filt.lower()

        # Use AsyncSniffer for reliable start/stop
        try:
            def _pktcb(pkt):
                summary = pkt.summary()
                self.captured_packets.append(pkt)
                self.append_line(summary)

            self.sniffer = AsyncSniffer(prn=_pktcb, iface=iface, filter=bpf, store=False)
            self.sniffer.start()
        except Exception as e:
            self.append_line(f"Failed to start capture: {e}")
            self.capturing = False
            self.status_label.configure(text="Status: Idle")

    def _sniff(self, iface, bpf):
        # kept for backward compatibility if called directly; prefer AsyncSniffer
        def _pktcb(pkt):
            summary = pkt.summary()
            self.captured_packets.append(pkt)
            self.append_line(summary)

        try:
            sniff(prn=_pktcb, iface=iface, filter=bpf, store=False)
        except Exception as e:
            self.append_line(f"Capture error: {e}")
        finally:
            self.capturing = False
            self.status_label.configure(text="Status: Idle")

    def stop_capture(self):
        if not SCAPY_AVAILABLE:
            return
        if not self.capturing:
            return
        self.status_label.configure(text="Status: Stopping...")
        try:
            if self.sniffer:
                # AsyncSniffer provides stop()
                self.sniffer.stop()
                try:
                    self.sniffer.join(timeout=2)
                except Exception:
                    pass
                self.sniffer = None
            self.capturing = False
            self.append_line("Capture stopped.")
            self.status_label.configure(text="Status: Idle")
        except Exception as e:
            self.append_line(f"Error stopping capture: {e}")
            self.status_label.configure(text="Status: Idle")

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
