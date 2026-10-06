"""Loads local word lists once. Lists are small, public and contain no personal data."""
from functools import lru_cache
from backend.config import DATA_DIR


def _read(name):
    path = DATA_DIR / name
    if not path.exists():
        return frozenset()
    lines = (l.strip().lower() for l in path.read_text(encoding="utf-8").splitlines())
    return frozenset(l for l in lines if l and not l.startswith("#"))


@lru_cache(maxsize=1)
def common_passwords():
    return _read("common_passwords.txt")


@lru_cache(maxsize=1)
def dictionary_words():
    return _read("dictionary_words.txt")
