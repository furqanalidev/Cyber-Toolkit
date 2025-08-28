import datetime
from .portscanner_lib import scan_ports

# Simple password strength advisor
def password_strength(pwd: str) -> str:
    score = 0
    if len(pwd) >= 8:
        score += 1
    if any(c.islower() for c in pwd) and any(c.isupper() for c in pwd):
        score += 1
    if any(c.isdigit() for c in pwd):
        score += 1
    if any(not c.isalnum() for c in pwd):
        score += 1
    advice = []
    if score <= 1:
        advice.append("Very weak — use longer passphrases with mixed character types.")
    elif score == 2:
        advice.append("Weak — increase length and add digits/symbols.")
    elif score == 3:
        advice.append("Good — consider using a passphrase for extra security.")
    else:
        advice.append("Strong — good job. Consider using a password manager.")
    advice.append(f"Length: {len(pwd)} | Score: {score}/4")
    return "\n".join(advice)

# Very small experiment logger (append JSON lines)
def log_experiment(name: str, meta: str, result: str):
    try:
        with open('experiments.log', 'a', encoding='utf-8') as f:
            f.write(f"{datetime.datetime.utcnow().isoformat()}\t{name}\t{meta}\t{result}\n")
    except Exception:
        pass

__all__ = ['scan_ports', 'password_strength', 'log_experiment']
