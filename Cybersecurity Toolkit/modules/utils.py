"""
utils.py - shared helpers for AI-like advice and logging
"""

import sqlite3
import re

DB_FILE = "experiments.db"

# --- Password Strength Advisor ---
def password_strength(password: str) -> str:
    """
    Simple AI-like heuristic advisor for password strength.
    """
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password too short (use at least 12 chars).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("⚠️ Add uppercase letters.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("⚠️ Add lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("⚠️ Add digits.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("⚠️ Add symbols (!@#$ etc).")

    if score >= 6:
        return "✅ Strong password. Good job!"
    elif score >= 4:
        return "🟡 Medium strength. Improvements:\n" + "\n".join(feedback)
    else:
        return "🔴 Weak password. Please improve:\n" + "\n".join(feedback)

# --- Database Logger ---
def log_experiment(module: str, action: str, result: str):
    """
    Logs experiment results into SQLite DB.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS experiments (id INTEGER PRIMARY KEY, module TEXT, action TEXT, result TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        cur.execute("INSERT INTO experiments (module, action, result) VALUES (?, ?, ?)", (module, action, result))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] {e}")
