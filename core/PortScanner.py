import socket
import sys
import datetime

try:
    host = input("Enter host: ")
    host_ip = socket.gethostbyname(host)
    print(f"Scanning {host} ({host_ip})...")
    start_time = datetime.datetime.now()
    print("start time: {start_time}")
    for port in range(1, 1025):
        # AF_INET->means IP4. AF_INET6->means IP6
        # SOCK_STREAM->means TCP. SOCK_DGRAM->means UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.001)
        result = sock.connect_ex((host_ip, port))
        if result == 0:
            print(f"Port {port} is open")
        sock.close()
    end_time = datetime.datetime.now()
    print("end time: {end_time}")
    print(f"Scanning completed in {end_time - start_time}")
except socket.gaierror:
    print("Hostname could not be resolved.")
except socket.error:
    print("Couldn't connect to the server.")