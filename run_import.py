import sys, importlib
base = r'c:\Users\HP\Desktop\BSCYS\Programming\Python\Project\Cybersecurity Toolkit'
if len(sys.argv) < 2:
    print('usage: run_import.py <module>')
    sys.exit(2)
mod = sys.argv[1]
sys.path.insert(0, base)
try:
    importlib.import_module(mod)
    print('OK', mod)
except Exception as e:
    print('ERR', mod, e)
    raise
