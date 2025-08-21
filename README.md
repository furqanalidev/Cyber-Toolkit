🛡️ Cybersecurity Toolkit 
📌 Project Overview

The Cybersecurity Toolkit is a Python-based application that integrates multiple ethical hacking and security testing tools into a single interface (CLI/GUI/Web).
It is designed for educational purposes only to help students and developers understand the basics of cybersecurity, networking, cryptography, and anomaly detection.

🎯 Objectives

Provide a multi-tool platform for common security tasks.

Demonstrate Python programming concepts through real-world security use cases.

Enable modular development: each tool can run independently or as part of the main dashboard.

Encourage a cybersecurity mindset while ensuring safe and responsible usage.

🗂️ Core Modules

Port Scanner

Scan open ports and detect running services.

Uses: socket, threading, optional nmap library.

Vulnerability Scanner

Crawl websites, check for SQLi, XSS, and open admin panels.

Uses: requests, BeautifulSoup4, regex.

Password/Brute Force Tool (Demo)

Simulated brute-force login attempts with a wordlist.

Hash cracking demo using hashlib (MD5, SHA256).

Encryption/Decryption Module

Supports Caesar Cipher, AES, DES, RSA.

Provides text and file encryption utilities.

Uses: cryptography library.

Keylogger (Safe Demo)

Captures keystrokes and logs them locally with timestamps.

Optional: email log sending (demo).

Network Sniffer & Anomaly Detection

Capture live packets using scapy.

Train ML model for anomaly detection (IsolationForest/KMeans).

Uses: scikit-learn, pandas, numpy.

Reporting Dashboard

GUI (Tkinter) or Web (Flask).

Summarize results with visualizations.

Export reports as PDF/CSV.

Uses: matplotlib, seaborn, sqlite3.

🛠️ Technologies & Libraries

Networking: socket, scapy, requests

Web Scraping: BeautifulSoup4

Security: hashlib, cryptography

Machine Learning: scikit-learn, pandas, numpy

Database: sqlite3

Visualization: matplotlib, seaborn

Interface: Tkinter (desktop) OR Flask (web)

Others: threading, logging, argparse

🔹 Features
1. Port Scanner

Scans open ports on a target IP or domain

Identifies running services using socket and python-nmap

Detects basic vulnerabilities related to services

2. Vulnerability Scanner

Detects weak configurations

Finds outdated software signatures (basic CVE checks – can be extended with APIs like Shodan)

3. Packet Sniffer & Analyzer

Captures live packets on selected interfaces (via scapy)

Analyzes TCP, UDP, ICMP, ARP, and HTTP traffic

Detects suspicious patterns in captured packets

4. Encryption / Decryption

Symmetric Encryption (AES, Fernet)

Asymmetric Encryption (RSA)

File & text encryption/decryption

Password hashing with bcrypt

5. Web Tools

Web crawler for extracting links (requests, BeautifulSoup)

WHOIS lookup for domains

Header & SSL certificate analysis

Subdomain discovery (basic brute-force)

6. Machine Learning Security (optional)

Uses ML models to detect anomalies in traffic data

Features included:

Outlier detection (e.g., DoS patterns)

Supervised ML models (scikit-learn)

Option to extend with tensorflow or torch

7. Visualization & Reporting

Interactive dashboards (plotly, dash, streamlit)

Charts and graphs for network scans and vulnerabilities

Export reports in CSV, JSON, or HTML

🔹 Architecture
Cybersecurity Toolkit/
│
├── toolkit.py              # Main entry point
├── modules/
│   ├── port_scanner.py     # Handles port scanning
│   ├── vuln_scanner.py     # Vulnerability detection
│   ├── packet_sniffer.py   # Packet analysis
│   ├── encryption.py       # Encryption/Decryption
│   ├── web_tools.py        # Web utilities
│   └── ml_security.py      # ML anomaly detection
│
└── README.txt              # Documentation

🔹 Installation
1. Clone the Repository
git clone https://github.com/yourusername/cybersecurity-toolkit.git
cd cybersecurity-toolkit

2. Create a Virtual Environment (Recommended)
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux/Mac

3. Install Dependencies
pip install -r requirements.txt

🔹 Requirements

The toolkit uses the following main Python libraries:

🔐 Cryptography

cryptography

pycryptodome

bcrypt

🌐 Networking & Security

scapy

python-nmap

paramiko

requests

requests-html

🕸️ Web Scraping

beautifulsoup4

lxml

📊 Data Science / ML

numpy, pandas

scikit-learn

matplotlib, seaborn

tensorflow or torch (optional for advanced ML)

📈 Visualization & Dashboard

plotly

dash

streamlit

🎨 Utilities

colorama

qrcode

flask

🔹 Usage

Run the main program:

python toolkit.py

Example Commands

Scan ports on a host

python toolkit.py --scan 192.168.1.1


Encrypt a file

python toolkit.py --encrypt secret.txt --method AES


Packet sniffing

python toolkit.py --sniff eth0


Run web tools

python toolkit.py --whois example.com


Generate interactive dashboard

python toolkit.py --dashboard

🔹 Legal Disclaimer

⚠️ This toolkit is for educational, ethical hacking, and research purposes only.
You must not use it on networks or systems you do not own or have explicit permission to test. Unauthorized usage is illegal and punishable under cybercrime laws.

The developers are not responsible for any misuse of this tool.