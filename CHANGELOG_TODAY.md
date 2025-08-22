Changelog - Changes made on 2025-08-22

Summary:
- Updated main launcher GUI (`toolkit.py`) to ensure the package directory is on sys.path so `modules` import reliably.
- Implemented a GUI Vulnerability Scanner (`modules/vuln_scanner.py`) with safe HTTP/TLS checks and port-range scanning using the shared scanner utility.
- Improved Packet Sniffer (`modules/packet_sniffer.py`) to enumerate interfaces (scapy), provide an interface selector, start/stop/export controls, and a live packet list.
- Port scanner GUI wired to shared `utils/portscanner_lib.scan_ports` (performance and single implementation).
- Added `requests` to `Cybersecurity Toolkit/requirements.txt`.
- Added test harness `tests/run_checks.py` and generated `tests/check_output.json` with verification output.

Notes:
- Packet capture on Windows requires Npcap/WinPcap and may require running the app with admin privileges for L2 capture.
- The changelog is a brief summary; see individual files for implementation details.
