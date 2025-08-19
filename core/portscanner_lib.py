# This file allows importing the port scanner as a function
import socket
import datetime

def scan_ports(host, port_start=1, port_end=1024, timeout=0.001):
    result = {
        "host": host,
        "host_ip": None,
        "open_ports": [],  # List of dicts: {"port": int, "service": str}
        "error": None,
        "duration": None,
    }
    try:
        host_ip = socket.gethostbyname(host)
        result["host_ip"] = host_ip
        start_time = datetime.datetime.now()
        for port in range(port_start, port_end + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((host_ip, port)) == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except Exception:
                    service = "Unknown"
                result["open_ports"].append({"port": port, "service": service})
            sock.close()
        end_time = datetime.datetime.now()
        result["duration"] = (end_time - start_time)
    except socket.gaierror:
        result["error"] = "Hostname could not be resolved."
    except socket.error:
        result["error"] = "Couldn't connect to the server."
    return result
