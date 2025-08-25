"""
brute_force_demo.py

Safe, educational demonstration of brute-force concepts.

This module intentionally does NOT provide tools to attack real systems.
It simulates guessing using a small local candidate list and shows how
keyspace size, attempts/sec, hashing, salting, and rate-limits affect
time-to-crack estimates.

Use this module only in legal, isolated lab environments (your own machines or authorized labs).
"""
from __future__ import annotations
import hashlib
import time
from typing import Iterable, Tuple


def estimate_keyspace(charset_size: int, length: int) -> int:
    """Return number of possible combinations for given charset and length."""
    return charset_size ** length


def time_to_crack_seconds(keyspace: int, attempts_per_sec: float) -> float:
    """Estimate average time to find a secret (assumes uniform random, average = keyspace/2)."""
    if attempts_per_sec <= 0:
        raise ValueError("attempts_per_sec must be > 0")
    return (keyspace / 2) / attempts_per_sec


def hash_password(password: str, salt: str = "") -> str:
    """Return a simple SHA-256 hex digest of password+salt (for demo only)."""
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()


def simulate_local_guess(secret_hash: str, candidates: Iterable[str], salt: str = "") -> Tuple[bool, str, float]:
    """
    Try a small iterable of candidates against the secret hash.

    This is a controlled local simulation: candidates must be provided by the learner.
    The function does not generate passwords or perform network requests.

    Returns (found, candidate, elapsed_seconds)
    """
    start = time.time()
    for c in candidates:
        if hash_password(c, salt) == secret_hash:
            return True, c, time.time() - start
    return False, "", time.time() - start


def run_demo() -> None:
    """Run a short interactive demo printed to stdout."""
    print("brute_force_demo: Safe educational demo")
    print("1) Keyspace math example")
    charset_size = 26 + 26 + 10  # lowercase + uppercase + digits
    length = 6
    ks = estimate_keyspace(charset_size, length)
    print(f"   charset_size={charset_size}, length={length} => keyspace={ks:,}")

    attempts_per_sec = 1000.0  # example attacker speed (attempts/sec)
    secs = time_to_crack_seconds(ks, attempts_per_sec)
    days = secs / (60 * 60 * 24)
    print(f"   At {attempts_per_sec:.0f} attempts/sec, avg time to crack ~ {days:.1f} days")

    print('\n2) Hash & local candidate demonstration (controlled)')
    password = "Ab1"  # intentionally tiny for demo
    salt = "demo_salt"
    secret_hash = hash_password(password, salt)
    print(f"   Secret (hidden) hash: {secret_hash[:16]}... (sha256)")

    candidates = ["a", "b", "ab", "Ab", "Ab1"]  # tiny controlled list
    print(f"   Trying {len(candidates)} local candidates...")
    found, candidate, elapsed = simulate_local_guess(secret_hash, candidates, salt)
    if found:
        print(f"   Found locally: '{candidate}' in {elapsed:.4f}s")
    else:
        print(f"   Not found in local list (elapsed {elapsed:.4f}s)")

    print('\n3) Defensive takeaways:')
    print('   - Use long, high-entropy passwords or passphrases (increase keyspace).')
    print('   - Use slow, salted password hashes (bcrypt/argon2) to reduce effective attempts/sec.')
    print('   - Implement rate-limiting, exponential backoff, and account lockouts to defend online services.')
    print('   - Practice only on authorized targets (DVWA, OWASP Juice Shop, or local labs).')


if __name__ == "__main__":
    run_demo()
