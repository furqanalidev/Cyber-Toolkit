Cyber-Toolkit — Project Description
=================================

1. Project overview

-------------------
Cyber-Toolkit is an educational cybersecurity toolkit implemented in Python. It provides a collection of user-facing tools (with a consistent GUI) and utility libraries intended for learning, lab exercises, and defensive research. The design emphasizes safe, local-only demonstrations for potentially sensitive capabilities and clarifies environmental requirements and legal constraints.

2. Goals

--------

- Provide a modern, consistent GUI launcher for several security-related modules.
- Centralize shared functionality (for example, a performant port scanning helper) to avoid duplication.
- Offer safe, educational demonstrations (e.g., brute-force estimation) and non-destructive reconnaissance checks (HTTP header checks, TLS inspection).
- Include a packet capture UI that uses scapy where available; document platform dependencies and limitations.

3. Architecture and components

-----------------------------
Top-level layout (relevant files/folders):

- `Cybersecurity Toolkit/` — main GUI and modules folder.
  - `toolkit.py` — main GUI launcher (CustomTkinter) that exposes all tools and hides/shows individual tool windows.
  - `modules/` — individual tool modules, each exposing a `run(on_close=None)` entrypoint for the launcher:
    - `port_scanner.py` — graphical port scanner UI (delegates scanning to the shared utility).
    - `vuln_scanner.py` — vulnerability scanner UI performing safe HTTP/TLS checks and robots.txt checks.
    - `packet_sniffer.py` — GUI for packet capture using scapy (AsyncSniffer) with interface selection and packet detail inspector.
    - `brute_force_demo.py` — educational brute-force estimation and local-only demo with a CTk GUI.
    - `encryption.py`, `web_tools.py`, `ml_security.py` — placeholder or auxiliary modules with consistent GUI style.

- `utils/` — shared libraries:
  - `portscanner_lib.py` — a centralized, efficient port scanning helper function `scan_ports(host, port_start, port_end, timeout)` used across modules.

- `tests/` — lightweight verification scripts and outputs (for local validation):
  - `run_checks.py` — import/test harness used during development to validate modules and environment.

4. Technical details and dependencies

-----------------------------------

- Language: Python 3.11+ (project has been validated on Python 3.13 in development environment).
- GUI: CustomTkinter (`customtkinter`) is used for a modern look-and-feel.
- Networking/capture:
  - `scapy` is used for packet capture and interface enumeration. On Windows, full layer-2 capture requires Npcap (WinPcap-compatible) installed and running with appropriate privileges.
  - Socket-based scanning uses a centralized `portscanner_lib` implementation.
- HTTP/TLS checks rely on `requests` and the Python `ssl`/`socket` libraries.
- Optional crypto timing examples may require `bcrypt` or `argon2-cffi` if added later.

5. Running the toolkit (developer / user notes)

----------------------------------------------

1. Create and activate a Python virtual environment (recommended).
2. Install required packages (example):

   pip install -r "Cybersecurity Toolkit/requirements.txt"

3. Launch the GUI from the project root:

   python "Cybersecurity Toolkit/toolkit.py"

4. From the launcher, select a tool. Tools open in their own window and the main launcher is hidden while a tool is running; closing a tool will re-show the main launcher.

6. Security, legal, and safe-use guidance

----------------------------------------

- This repository contains educational and defensive tools. Do NOT use them against systems you do not own or do not have explicit permission to test.
- Packet capture on networks may capture sensitive data. Use only on networks where you have authorization.
- Brute-force and active scanning code is restricted to safe, local demonstrations in this project. The code intentionally avoids providing network-based brute-force attack tooling.
- If you plan to use the project in a lab or for training, prefer isolated environments such as local VMs, intentionally vulnerable appliances (DVWA, Metasploitable), or cloud sandboxes where you have permission.

7. Contributing and development workflow

---------------------------------------

- Branching: work on feature branches and open PRs against `main` (the repository currently uses `main` as default).
- Tests: add small unit tests for pure functions (estimation, hashing helpers) and run `tests/run_checks.py` for quick environment validation.
- Formatting: maintain consistent style with existing code (PEP8-style spacing). Keep UI and public APIs stable for importable `run(on_close)` entrypoints.

8. Known limitations and future work

----------------------------------

- Packet capture stop semantics were improved using `AsyncSniffer`, but OS-level driver requirements remain on Windows (install Npcap and run with elevated privileges for full functionality).
- Friendly mapping of Windows NPF GUIDs to adapter names uses heuristics; can be improved with platform-specific libraries (pywin32/WMI).
- Additional security demonstrations (bcrypt/argon2 timings, rate-limit emulators) can be added as optional modules with explicit defensive labeling.

9. Licensing

------------
This repository does not include a license file by default. Add a license (e.g., MIT, Apache-2.0) if you intend to publish or share broadly. If you want, I can add an explicit LICENSE file.

10. Contact / maintainers

-------------------------
Owner: furqanalidev (GitHub)
Project branch for current work: `fix/pyc-ignore-async-sniffer`
