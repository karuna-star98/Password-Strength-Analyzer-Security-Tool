"""
Scoring engine (0-100). Project-defined rubric for learning, NOT a universal standard.
Positive:  length 35 | diversity 15 | unique ratio 10 | pattern resistance 20 | non-common 10 | unpredictability 10
Penalties: common -40 | keyboard -15 | sequence -12 | repetition -15..-30 | personal info -20 | word+number -15 | ...
"""
from backend.config import CLASS_BANDS

PENALTIES = {"common_password": 40, "keyboard_pattern": 15, "sequence": 12, "repeated_characters": 15,
             "repeated_substring": 12, "personal_info": 20, "word_plus_number": 15, "year_pattern": 10,
             "dictionary_word": 8}


def length_points(n):
    if n < 8:   return float(n)                      # 0-7
    if n < 12:  return 12 + (n - 8) * 2              # 12-18
    if n < 16:  return 22 + (n - 12) * 2             # 22-28
    return min(35.0, 30 + (n - 16) * 1.25)           # 30-35


def classify(score):
    for upper, label in CLASS_BANDS:
        if score <= upper:
            return label
    return CLASS_BANDS[-1][1]


def compute_score(length, type_count, unique_ratio, findings, effective_bits, is_common, rep_coverage=0.0):
    active = [f for f in findings if f["severity"] != "info"]
    pattern_kinds = {f["type"] for f in active if f["type"] != "common_password"}
    b = {
        "length": length_points(length),
        "character_diversity": min(15.0, type_count * 3.75),
        "unique_ratio": round(unique_ratio * 10, 2),
        "pattern_resistance": max(0, 20 - 7 * len(pattern_kinds)),
        "non_common": 0 if is_common else 10,
        "unpredictability": round(min(10.0, effective_bits / 80 * 10), 2),
    }
    penalty = 0.0
    for f in active:
        p = PENALTIES.get(f["type"], 0)
        if f["type"] == "repeated_characters":
            p += 15 * rep_coverage            # more of the password repeated => bigger penalty
        penalty += p
    b["penalties"] = -round(penalty, 2)
    raw = sum(b.values())
    # Short passwords can never rank high, whatever else they contain (length is the base requirement).
    cap = 20 if length < 8 else 60 if length < 12 else 100
    score = int(round(max(0, min(cap, raw))))
    return score, classify(score), b
