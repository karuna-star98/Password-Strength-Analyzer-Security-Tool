"""
EDUCATIONAL password-storage demo (synthetic password only; NOT connected to the analyzer).
Password -> random salt -> slow password-hashing function (scrypt) -> stored "scrypt$n$r$p$salt$hash".
Hashing is one-way verification; encryption is reversible with a key. Fast hashes (MD5/SHA-1/SHA-256 alone)
are unsuitable for password storage because fast = cheap to guess. Prefer Argon2id (argon2-cffi) or bcrypt
in production; scrypt from the standard library is used here so the demo needs no extra install.
"""
import base64, hashlib, hmac, os

N, R, P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, dklen=32)
    return "$".join(["scrypt", str(N), str(R), str(P), base64.b64encode(salt).decode(), base64.b64encode(h).decode()])


def verify_password(password: str, stored: str) -> bool:
    _, n, r, p, salt, h = stored.split("$")
    cand = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    return hmac.compare_digest(cand, base64.b64decode(h))      # constant-time comparison


if __name__ == "__main__":
    demo = "Demo-Only-Example-9xQ!"                            # synthetic, never reuse
    a, b = hash_password(demo), hash_password(demo)
    print("Same password, different salts -> different stored values:", a != b)
    print("Correct password verifies:", verify_password(demo, a))
    print("Wrong password verifies:  ", verify_password("wrong-guess", a))
