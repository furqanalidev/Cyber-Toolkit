import subprocess, sys
base = r'c:\Users\HP\Desktop\BSCYS\Programming\Python\Project\Cybersecurity Toolkit'
mods = ['toolkit','modules.port_scanner','modules.vuln_scanner','modules.web_tools','modules.encryption','modules.ml_security','modules.brute_force_demo','modules.packet_sniffer']
for m in mods:
    cmd = [sys.executable, '-c', f"import sys; sys.path.insert(0, r'{base}'); import importlib; importlib.import_module('{m}'); print('ok')"]
    print('---- running import for', m)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        print('returncode', res.returncode)
        print('stdout:', res.stdout.strip())
        print('stderr:', res.stderr.strip())
    except subprocess.TimeoutExpired:
        print('TIMEOUT importing', m)
    except Exception as e:
        print('ERROR running subprocess for', m, e)
