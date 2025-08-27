import os
import sys
import threading
import time
import subprocess
import re
import customtkinter as ctk
from tkinter import filedialog
import collections
import json

# Try to import sklearn IsolationForest
SKLEARN_AVAILABLE = True
try:
    from sklearn.ensemble import IsolationForest
except Exception:
    SKLEARN_AVAILABLE = False

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

        # Main scrollable area
        self.scrollable_frame = ctk.CTkScrollableFrame(self, width=window_width, height=window_height - 20)
        self.scrollable_frame.pack(fill="both", expand=True)

        self.header = ctk.CTkLabel(self.scrollable_frame, text="Packet Sniffer", font=("Arial", 28, "bold"))
        self.header.pack(pady=(20, 10))

        # Controls frame
        self.controls_frame = ctk.CTkFrame(self.scrollable_frame)
        self.controls_frame.pack(fill="x", padx=20, pady=(0, 10))

        self.iface_label = ctk.CTkLabel(self.controls_frame, text="Interface (optional)")
        self.iface_label.grid(row=0, column=0, padx=6, pady=6)

        # Populate interface list when scapy is available
        iface_values = []
        if SCAPY_AVAILABLE:
            try:
                try:
                    from scapy.all import get_windows_if_list
                    win_ifaces = get_windows_if_list()
                    iface_values = [f"{i.get('name')} ({i.get('description')})" if i.get('description') else i.get('name') for i in win_ifaces]
                except Exception:
                    from scapy.all import get_if_list
                    raw_ifaces = get_if_list()
                    iface_values = list(raw_ifaces)
            except Exception:
                iface_values = []

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

        # Anomaly detection controls
        self.anom_switch = ctk.CTkSwitch(self.controls_frame, text="Anomaly Detection", command=self._toggle_anomaly)
        self.anom_switch.grid(row=1, column=0, padx=6, pady=6)
        self.sens_label = ctk.CTkLabel(self.controls_frame, text="Sensitivity")
        self.sens_label.grid(row=1, column=1, padx=6, pady=6)
        self.sens_slider = ctk.CTkSlider(self.controls_frame, from_=0.005, to=0.2, number_of_steps=39)
        self.sens_slider.set(0.05)
        self.sens_slider.grid(row=1, column=2, columnspan=2, padx=6, pady=6, sticky="we")
        self.anom_export_btn = ctk.CTkButton(self.controls_frame, text="Export Alerts", command=self.export_alerts)
        self.anom_export_btn.grid(row=1, column=4, padx=6, pady=6)

        # Alerts box
        self.alerts_box = ctk.CTkTextbox(self.scrollable_frame, width=740, height=100, font=("Consolas", 11))
        self.alerts_box.pack(padx=20, pady=(0, 10))
        self.alerts_box.configure(state="disabled")

        # Packet list and detail boxes
        self.packets_list = ctk.CTkTextbox(self.scrollable_frame, width=740, height=260, font=("Consolas", 11))
        self.packets_list.pack(padx=20, pady=10)
        self.packets_list.configure(state="disabled")

        self.detail_box = ctk.CTkTextbox(self.scrollable_frame, width=740, height=120, font=("Consolas", 11))
        self.detail_box.pack(padx=20, pady=(0, 10))
        self.detail_box.configure(state="disabled")
        try:
            self.packets_list.bind("<ButtonRelease-1>", self.on_packet_click)
        except Exception:
            pass

        self.status_label = ctk.CTkLabel(self.scrollable_frame, text="Status: Idle")
        self.status_label.pack(pady=(0, 12))

        self.capturing = False
        self.captured_packets = []
        self.sniffer = None
        self.anomaly_detector = AnomalyDetector(report_cb=self._report_alert)

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

    def _toggle_anomaly(self):
        enabled = getattr(self.anom_switch, 'get', lambda: False)()
        if enabled:
            self.anomaly_detector.set_sensitivity(self.sens_slider.get())
            self.anomaly_detector.start()
            self.append_line("Anomaly detection enabled")
        else:
            self.anomaly_detector.stop()
            self.append_line("Anomaly detection disabled")

    def _report_alert(self, alert: dict):
        # show alert in alerts_box and also append to packet list
        text = f"ALERT: {alert.get('time')} score={alert.get('score'):.3f} reason={alert.get('reason')}"
        try:
            self.after(0, lambda: self._append_alert(text))
        except Exception:
            self._append_alert(text)

    def _append_alert(self, text: str):
        self.alerts_box.configure(state="normal")
        self.alerts_box.insert(ctk.END, text + "\n")
        self.alerts_box.see(ctk.END)
        self.alerts_box.configure(state="disabled")

    def export_alerts(self):
        if not self.anomaly_detector or not self.anomaly_detector.alerts:
            self.append_line("No alerts to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON files', '*.json')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.anomaly_detector.alerts, f, indent=2)
            self.append_line(f"Exported {len(self.anomaly_detector.alerts)} alerts to {path}")
        except Exception as e:
            self.append_line(f"Failed to export alerts: {e}")

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
                # send to anomaly detector
                try:
                    self.anomaly_detector.add_packet(pkt)
                except Exception:
                    pass

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


class PacketSnifferFrame(ctk.CTkFrame):
    """Embeddable frame wrapper for PacketSnifferGUI functionality."""
    def __init__(self, parent, on_close=None):
        super().__init__(parent)
        self.on_close = on_close

        # Header
        header = ctk.CTkLabel(self, text="Packet Sniffer", font=("Arial", 20, "bold"))
        header.pack(pady=(8, 6))

        # Controls row
        controls = ctk.CTkFrame(self)
        controls.pack(fill="x", padx=6, pady=(0, 6))

        self.iface_entry = ctk.CTkEntry(controls, width=240, placeholder_text="Interface (optional)")
        self.iface_entry.grid(row=0, column=0, padx=6, pady=6)
        self.filter_entry = ctk.CTkEntry(controls, width=140, placeholder_text="tcp")
        self.filter_entry.grid(row=0, column=1, padx=6, pady=6)
        self.start_btn = ctk.CTkButton(controls, text="Start Capture", command=self.start_capture)
        self.start_btn.grid(row=0, column=2, padx=6, pady=6)
        self.stop_btn = ctk.CTkButton(controls, text="Stop Capture", command=self.stop_capture)
        self.stop_btn.grid(row=0, column=3, padx=6, pady=6)

        # Anomaly controls
        self.anom_switch = ctk.CTkSwitch(controls, text="Anomaly Detection", command=self._toggle_anomaly)
        self.anom_switch.grid(row=1, column=0, padx=6, pady=6)
        self.sens_slider = ctk.CTkSlider(controls, from_=0.005, to=0.2, number_of_steps=39)
        self.sens_slider.set(0.05)
        self.sens_slider.grid(row=1, column=1, columnspan=2, padx=6, pady=6, sticky="we")

        # Alerts box
        self.alerts_box = ctk.CTkTextbox(self, width=720, height=80, font=("Consolas", 11))
        self.alerts_box.pack(padx=6, pady=(0, 6))
        self.alerts_box.configure(state="disabled")

        # Detector will be lazily used when enabled
        self.anomaly_detector = AnomalyDetector(report_cb=self._report_alert)

        # Packet list and detail boxes
        self.packets_list = ctk.CTkTextbox(self, width=720, height=220, font=("Consolas", 11))
        self.packets_list.pack(padx=6, pady=6)
        self.packets_list.configure(state="disabled")

        self.detail_box = ctk.CTkTextbox(self, width=720, height=120, font=("Consolas", 11))
        self.detail_box.pack(padx=6, pady=(0, 6))
        self.detail_box.configure(state="disabled")

        self.capturing = False
        self.captured_packets = []
        self.sniffer = None

    def append_line(self, line):
        def _append():
            self.packets_list.configure(state="normal")
            self.packets_list.insert(ctk.END, line + "\n")
            self.packets_list.see(ctk.END)
            self.packets_list.configure(state="disabled")
        try:
            self.after(0, _append)
        except Exception:
            _append()

    def start_capture(self):
        if not SCAPY_AVAILABLE:
            self.append_line("Scapy not installed. Install scapy to enable packet capture.")
            return
        if self.capturing:
            return
        self.captured_packets = []
        self.capturing = True
        iface = self.iface_entry.get().strip() or None
        filt = self.filter_entry.get().strip()
        bpf = filt.lower() if filt and filt.lower() in ('tcp', 'udp', 'icmp') else None

        try:
            def _pktcb(pkt):
                summary = pkt.summary()
                self.captured_packets.append(pkt)
                self.append_line(summary)
                try:
                    self.anomaly_detector.add_packet(pkt)
                except Exception:
                    pass

            self.sniffer = AsyncSniffer(prn=_pktcb, iface=iface, filter=bpf, store=False)
            self.sniffer.start()
        except Exception as e:
            self.append_line(f"Failed to start capture: {e}")
            self.capturing = False

    def stop_capture(self):
        if not SCAPY_AVAILABLE:
            return
        if not self.capturing:
            return
        try:
            if self.sniffer:
                self.sniffer.stop()
                try:
                    self.sniffer.join(timeout=2)
                except Exception:
                    pass
                self.sniffer = None
            self.capturing = False
            self.append_line("Capture stopped.")
            # stop detector
            try:
                self.anomaly_detector.stop()
            except Exception:
                pass
        except Exception as e:
            self.append_line(f"Error stopping capture: {e}")


def create_frame(parent, on_close=None):
    return PacketSnifferFrame(parent, on_close=on_close)


class AnomalyDetector:
    """Simple rolling-window anomaly detector.

    Uses IsolationForest when available; falls back to z-score on packet rate.
    """
    def __init__(self, report_cb=None, window_seconds=5, baseline_windows=6):
        self.report_cb = report_cb
        self.window_seconds = window_seconds
        self.baseline_windows = baseline_windows
        self.lock = threading.Lock()
        self.events = collections.deque()  # store (ts, length, proto)
        self.running = False
        self.thread = None
        self.model = None
        self.window_history = []  # list of feature dicts
        self.alerts = []
        self.sensitivity = 0.05

    def set_sensitivity(self, val: float):
        self.sensitivity = float(val)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
            self.thread = None

    def add_packet(self, pkt):
        try:
            ts = getattr(pkt, 'time', time.time())
            length = len(pkt) if hasattr(pkt, '__len__') else 0
            proto = pkt.__class__.__name__
        except Exception:
            ts = time.time(); length = 0; proto = 'UNK'
        with self.lock:
            self.events.append((ts, length, proto))
            # keep a rolling buffer (e.g., 5 mins)
            cutoff = ts - 300
            while self.events and self.events[0][0] < cutoff:
                self.events.popleft()

    def _extract_window_features(self, events_window):
        if not events_window:
            return None
        pkt_count = len(events_window)
        byte_count = sum(e[1] for e in events_window)
        avg_size = byte_count / pkt_count if pkt_count else 0
        protos = collections.Counter(e[2] for e in events_window)
        unique_dst_ports = 0
        # best-effort extract ports from repr if available
        dst_ports = set()
        for e in events_window:
            # attempt to parse port numbers from stringified pkt
            try:
                s = repr(e)
            except Exception:
                s = ''
            for m in re.findall(r"\b(\d{2,5})\b", s):
                dst_ports.add(int(m))
        unique_dst_ports = len(dst_ports)
        features = {
            'pkt_count': pkt_count,
            'byte_count': byte_count,
            'avg_size': avg_size,
            'tcp_ratio': protos.get('TCP', 0) / pkt_count if pkt_count else 0,
            'udp_ratio': protos.get('UDP', 0) / pkt_count if pkt_count else 0,
            'icmp_ratio': protos.get('ICMP', 0) / pkt_count if pkt_count else 0,
            'unique_dst_ports': unique_dst_ports,
        }
        return features

    def _loop(self):
        # Slide by window_seconds
        while self.running:
            time.sleep(self.window_seconds)
            with self.lock:
                now = time.time()
                window_start = now - self.window_seconds
                window_events = [e for e in self.events if e[0] >= window_start]
            feat = self._extract_window_features(window_events)
            if not feat:
                continue
            self.window_history.append(feat)
            # simple numeric vector
            vec = [feat['pkt_count'], feat['byte_count'], feat['avg_size'], feat['unique_dst_ports'], feat['tcp_ratio'], feat['udp_ratio'], feat['icmp_ratio']]
            # if sklearn available and we have enough history, fit or predict
            try:
                if SKLEARN_AVAILABLE:
                    if self.model is None and len(self.window_history) >= max(3, self.baseline_windows):
                        # fit on recent history as baseline
                        X = [[w['pkt_count'], w['byte_count'], w['avg_size'], w['unique_dst_ports'], w['tcp_ratio'], w['udp_ratio'], w['icmp_ratio']] for w in self.window_history[-self.baseline_windows:]]
                        self.model = IsolationForest(contamination=self.sensitivity, random_state=1)
                        self.model.fit(X)
                        continue
                    elif self.model is not None:
                        Xp = [vec]
                        score = float(self.model.decision_function(Xp)[0])
                        # lower score more anomalous; invert to anomaly score
                        anomaly_score = -score
                        if anomaly_score > (1.0 - self.sensitivity) * 2:  # heuristic threshold
                            alert = {'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)), 'score': anomaly_score, 'reason': 'isolation_forest_anomaly', 'features': feat}
                            self.alerts.append(alert)
                            if self.report_cb:
                                try:
                                    self.report_cb(alert)
                                except Exception:
                                    pass
                else:
                    # fallback: simple z-score on pkt_count using history
                    counts = [w['pkt_count'] for w in self.window_history]
                    if len(counts) >= 3:
                        mean = sum(counts)/len(counts)
                        var = sum((c-mean)**2 for c in counts)/len(counts)
                        std = var**0.5
                        if std > 0 and abs(feat['pkt_count'] - mean) > 3*std:
                            alert = {'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)), 'score': abs(feat['pkt_count']-mean)/std, 'reason': 'zscore_pkt_count', 'features': feat}
                            self.alerts.append(alert)
                            if self.report_cb:
                                try:
                                    self.report_cb(alert)
                                except Exception:
                                    pass
            except Exception:
                # swallow model errors
                pass
