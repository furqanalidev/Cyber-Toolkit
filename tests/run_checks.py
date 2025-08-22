import sys, os, json
# ensure project root and Cybersecurity Toolkit folder are on sys.path
proj_root = r'c:\Users\HP\Desktop\BSCYS\Programming\Python\Project'
cs_toolkit = os.path.join(proj_root, 'Cybersecurity Toolkit')
if proj_root not in sys.path:
    sys.path.insert(0, proj_root)
if cs_toolkit not in sys.path:
    sys.path.insert(0, cs_toolkit)

results = {}

# Check utils.portscanner_lib
try:
    from utils.portscanner_lib import scan_ports
    r = scan_ports('127.0.0.1', 1, 50, timeout=0.01)
    results['portscanner_lib'] = {'ok': True, 'host_ip': r.get('host_ip'), 'open_ports_count': len(r.get('open_ports')), 'error': r.get('error')}
except Exception as e:
    results['portscanner_lib'] = {'ok': False, 'error': str(e)}

# Check modules imports
modules_to_check = ['vuln_scanner', 'packet_sniffer', 'port_scanner']
for m in modules_to_check:
    try:
        mod = __import__(f'modules.{m}', fromlist=['*'])
        results[f'modules.{m}'] = {'ok': True, 'has_run': hasattr(mod, 'run')}
    except Exception as e:
        results[f'modules.{m}'] = {'ok': False, 'error': str(e)}

# Check scapy availability and interfaces
try:
    import scapy.all as scapy
    try:
        if_list = scapy.get_if_list()
    except Exception as e:
        if_list = f'get_if_list error: {e}'
    results['scapy'] = {'ok': True, 'version': getattr(scapy, '__version__', 'unknown'), 'interfaces': if_list}
except Exception as e:
    results['scapy'] = {'ok': False, 'error': str(e)}

print(json.dumps(results, indent=2))
