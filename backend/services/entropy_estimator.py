"""
Entropy-style estimation.  Theoretical entropy ~ L * log2(N)
  L = password length, N = estimated character pool.
LIMITATION: this assumes every character was chosen uniformly at random. Humans do not do that,
so "Password123!" gets an optimistic number. We therefore also compute an EFFECTIVE estimate that
gives no credit to characters covered by detected patterns. Both are educational estimates only.
"""
import math


def pool_size(password):
    pool = 0
    if any(c.islower() and c.isascii() for c in password): pool += 26
    if any(c.isupper() and c.isascii() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c.isascii() and not c.isalnum() for c in password): pool += 33   # punctuation + space
    if any(not c.isascii() for c in password): pool += 64                   # rough allowance for Unicode
    return pool


def estimate_theoretical_entropy(password):
    pool = pool_size(password)
    bits = len(password) * math.log2(pool) if pool > 1 else 0.0
    return round(bits, 1), pool


def estimate_effective_entropy(password, covered_chars):
    """Entropy credit only for characters NOT covered by predictable patterns."""
    pool = pool_size(password)
    if pool <= 1:
        return 0.0
    return round(max(0, len(password) - covered_chars) * math.log2(pool), 1)


def guess_resistance_label(effective_bits):
    """Very rough, deliberately vague bands. Educational estimate only (assumes ~1e10 offline guesses/s
    against a FAST hash; real resistance depends on attacker model, hashing algorithm, work factor,
    rate limiting and online vs offline scenario)."""
    if effective_bits < 28: return "Trivially guessable"
    if effective_bits < 40: return "Hours to days (offline, fast hash)"
    if effective_bits < 60: return "Weeks to years (offline, fast hash)"
    if effective_bits < 80: return "Many years (offline, fast hash)"
    return "Centuries or more (if truly random)"
