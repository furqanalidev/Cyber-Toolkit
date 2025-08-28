import sys, time, importlib
sys.path.insert(0, r'c:\Users\HP\Desktop\BSCYS\Programming\Python\Project\Cybersecurity Toolkit')
mods = ['toolkit','modules.port_scanner','modules.vuln_scanner','modules.packet_sniffer','modules.encryption','modules.web_tools','modules.ml_security','modules.brute_force_demo']

for m in mods:
    print('---- importing', m)
    sys.stdout.flush()
    t0 = time.time()
    try:
        importlib.import_module(m)
        print('OK', m, round(time.time()-t0,2), 'sec')
    except Exception as e:
        print('ERROR', m, repr(e))
    sys.stdout.flush()
