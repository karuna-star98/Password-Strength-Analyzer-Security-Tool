"""
Pattern detectors. Each returns finding dicts:
    {"type", "severity", "description", "spans": [(start, end), ...]}
`spans` stay INSIDE the backend (used to measure how much of a password is predictable);
they are stripped before anything is returned to the client.
"""
import re
from backend.utils.data_loader import common_passwords, dictionary_words

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1q2w3e4r5t6y7u8i9o0p",
                 "1qaz2wsx3edc4rfv", "qazwsxedcrfvtgb", "zaq12wsxcde3"]
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "0": "o", "$": "s", "5": "s", "1": "i", "!": "i", "7": "t"})


def _finding(ftype, severity, desc, spans):
    return {"type": ftype, "severity": severity, "description": desc, "spans": spans}


def normalize_leet(text):
    """Undo common substitutions (p@ssw0rd -> password) so predictable variants are caught."""
    return text.lower().translate(LEET)


def _kind(ch):
    return "d" if ch.isdigit() else "a" if ch.isascii() and ch.isalpha() else "x"


def detect_sequences(password, min_len=3):
    """Ascending/descending runs such as 1234, 9876, abcd, dcba."""
    s, n, spans, i = password.lower(), len(password), [], 0
    while i < n - 1:
        step = ord(s[i + 1]) - ord(s[i])
        if step in (1, -1) and _kind(s[i]) == _kind(s[i + 1]) != "x":
            j = i + 1
            while j + 1 < n and ord(s[j + 1]) - ord(s[j]) == step and _kind(s[j + 1]) == _kind(s[i]):
                j += 1
            if j - i + 1 >= min_len:
                spans.append((i, j + 1))
            i = j
        else:
            i += 1
    if not spans:
        return []
    return [_finding("sequence", "medium",
                     "Your password contains a predictable ascending or descending sequence (like 1234 or abcd).", spans)]


def detect_keyboard_patterns(password, window=4):
    """Keyboard walks such as qwerty, asdf, zxcv, 1qaz2wsx (forwards or backwards)."""
    s, spans = password.lower(), []
    for row in KEYBOARD_ROWS:
        for r in (row, row[::-1]):
            for i in range(len(r) - window + 1):
                chunk = r[i:i + window]
                start = s.find(chunk)
                while start != -1:
                    spans.append((start, start + window))
                    start = s.find(chunk, start + 1)
    if not spans:
        return []
    return [_finding("keyboard_pattern", "medium",
                     "Your password contains a keyboard pattern (like qwerty or asdf) that attackers try early.",
                     _merge(spans))]


def detect_repetition(password):
    """Repeated characters (aaaa, 1111) and repeated substrings (ababab, abcabcabc)."""
    out = []
    runs = [(m.start(), m.end()) for m in re.finditer(r"(.)\1{2,}", password)]
    if runs:
        out.append(_finding("repeated_characters", "medium",
                            "Your password repeats the same character several times in a row.", runs))
    subs = [(m.start(), m.end()) for m in re.finditer(r"(.{2,6}?)\1+", password.lower())
            if len(set(m.group(1))) > 1]
    if subs:
        out.append(_finding("repeated_substring", "medium",
                            "Your password repeats a short chunk of characters (like abab or abcabc).", subs))
    return out


def detect_predictable_structure(password):
    """Common word + trailing numbers/symbols (welcome123, Password123!, admin2026) and year/date patterns."""
    out = []
    suffix = re.search(r"[^A-Za-z]+$", password)
    covered_year = False
    if suffix:
        stem, tail = password[:suffix.start()], suffix.group()
        known = common_passwords() | dictionary_words()
        if len(stem) >= 3 and normalize_leet(stem) in known:
            out.append(_finding("word_plus_number", "high",
                                "Your password looks like a common word followed by numbers or symbols, "
                                "a pattern attackers try very early.", [(0, len(password))]))
            covered_year = True
    if not covered_year:
        yrs = [(m.start(), m.end()) for m in re.finditer(r"(?<!\d)(19\d{2}|20\d{2})(?!\d)", password)]
        if yrs:
            out.append(_finding("year_pattern", "medium",
                                "Your password contains a year-like number, which is easy to guess.", yrs))
    return out


def detect_dictionary_words(password, min_len=4):
    """Returns (findings, distinct_words_found). Words are matched after undoing leetspeak."""
    s, spans, found = normalize_leet(password), [], set()
    for w in dictionary_words():
        if len(w) < min_len:
            continue
        start = s.find(w)
        while start != -1:
            spans.append((start, start + len(w)))
            found.add(w)
            start = s.find(w, start + 1)
    if not spans:
        return [], set()
    return [_finding("dictionary_word", "low",
                     "Your password contains common dictionary words, which are easier to guess.",
                     _merge(spans))], found


def _merge(spans):
    spans = sorted(spans)
    merged = [list(spans[0])]
    for a, b in spans[1:]:
        if a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [tuple(x) for x in merged]


def covered_length(findings):
    spans = [sp for f in findings for sp in f["spans"]]
    return sum(b - a for a, b in _merge(spans)) if spans else 0
