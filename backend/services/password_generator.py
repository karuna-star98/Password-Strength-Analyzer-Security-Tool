"""
Secure generators. We use `secrets` (OS cryptographically secure randomness) instead of `random`
(Mersenne Twister: predictable if an attacker observes enough output). Generated values are never stored.
"""
import math, secrets, string
from backend.utils.data_loader import dictionary_words

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
ALLOWED_LENGTHS = range(12, 65)


def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True):
    if length not in ALLOWED_LENGTHS:
        raise ValueError("Length must be between 12 and 64.")
    pools = [p for ok, p in ((upper, string.ascii_uppercase), (lower, string.ascii_lowercase),
                             (digits, string.digits), (symbols, SYMBOLS)) if ok]
    if not pools:
        raise ValueError("Select at least one character type.")
    chars = [secrets.choice(p) for p in pools]                       # guarantee one of each chosen type
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=5, sep="-"):
    """EDUCATIONAL: uses our small demo list (~186 words). For real use pick a 7,776-word diceware list."""
    if not 4 <= words <= 10:
        raise ValueError("Word count must be between 4 and 10.")
    wl = sorted(dictionary_words())
    phrase = sep.join(secrets.choice(wl) for _ in range(words))
    return phrase, round(words * math.log2(len(wl)), 1)
