"""
Main analysis engine. analyze_password() runs entirely in memory: the password is never logged,
stored, hashed for storage, or included in the returned structure.
"""
import re
from backend.config import MAX_PASSWORD_LENGTH, LENGTH_BANDS, DEFAULT_POLICY
from backend.utils.data_loader import common_passwords
from backend.services import pattern_detector as pd
from backend.services.entropy_estimator import (estimate_theoretical_entropy, estimate_effective_entropy,
                                                guess_resistance_label)
from backend.services.scoring_engine import compute_score
from backend.services.suggestion_engine import generate_suggestions

DISCLAIMER = ("Scores are project-defined estimates, not a guarantee. Password strength cannot be perfectly "
              "determined by one formula.")


class PasswordTooLongError(ValueError):
    pass


def analyze_length(password):
    n = len(password)
    label = next(lbl for limit, lbl in LENGTH_BANDS if n < limit)
    note = "Length helps, but long passwords can still be predictable (e.g. one repeated character)."
    return {"length": n, "band": label, "note": note}


def analyze_characters(password):
    lower = sum(c.islower() for c in password); upper = sum(c.isupper() for c in password)
    digit = sum(c.isdigit() for c in password); space = password.count(" ")
    symbol = sum(not c.isalnum() and c != " " for c in password)
    types = sum(x > 0 for x in (lower, upper, digit, symbol, space))
    uniq = len(set(password))
    return {"lowercase": lower, "uppercase": upper, "digits": digit, "symbols": symbol, "spaces": space,
            "unique_character_count": uniq, "character_type_count": types,
            "unique_character_ratio": round(uniq / len(password), 3) if password else 0.0}


def is_common_password(password):
    p = password.lower()
    common = common_passwords()
    return p in common or pd.normalize_leet(password) in common


def check_personal_context(password, context):
    """Compares optional, user-supplied demo context locally. Context is never stored or echoed."""
    if not context:
        return []
    low, norm = password.lower(), pd.normalize_leet(password)
    tokens = []
    name = str(context.get("first_name", "") or "").strip().lower()
    org = str(context.get("organization", "") or "").strip().lower()
    year = str(context.get("birth_year", "") or "").strip()
    if len(name) >= 3: tokens.append(name)
    tokens += [w for w in re.split(r"\W+", org) if len(w) >= 3]
    if re.fullmatch(r"(19|20)\d{2}", year): tokens += [year]
    for t in tokens:
        if t in low or t in norm:
            return [{"type": "personal_info", "severity": "high",
                     "description": "Your password appears to contain personal information you provided "
                                    "(name, birth year or organization).", "spans": [(0, len(password))]}]
    return []


def evaluate_policy(password, context, findings, policy=None):
    """POLICY PASS/FAIL is separate from strength: a policy-compliant password can still be weak."""
    pol = {**DEFAULT_POLICY, **(policy or {})}
    types = {f["type"] for f in findings}
    try:
        min_len = max(1, min(int(pol["minimum_length"]), MAX_PASSWORD_LENGTH))
    except (TypeError, ValueError):
        min_len = DEFAULT_POLICY["minimum_length"]
    rules = [{"rule": f"Minimum length {min_len}", "passed": len(password) >= min_len},
             {"rule": f"Maximum length {MAX_PASSWORD_LENGTH} (spaces allowed)", "passed": len(password) <= MAX_PASSWORD_LENGTH}]
    if pol["common_password_check"]:
        rules.append({"rule": "Not a common password", "passed": "common_password" not in types})
    if pol["personal_info_check"]:
        rules.append({"rule": "No personal information", "passed": "personal_info" not in types})
    return {"passed": all(r["passed"] for r in rules), "rules": rules,
            "note": "Policy compliance is not the same as strength."}


def _public(findings):
    return [{k: v for k, v in f.items() if k != "spans"} for f in findings]


def analyze_password(password, context=None, policy=None):
    if not isinstance(password, str):
        raise ValueError("Password must be a string.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordTooLongError(f"Password exceeds the maximum supported length of {MAX_PASSWORD_LENGTH}.")

    length, chars = analyze_length(password), analyze_characters(password)
    findings, strengths = [], []
    common = bool(password) and is_common_password(password)

    if not password:
        findings.append({"type": "empty", "severity": "high", "description": "No password entered.", "spans": []})
    if common:
        findings.append({"type": "common_password", "severity": "high",
                         "description": "Your password matches a commonly used password pattern and should not be used.",
                         "spans": [(0, len(password))]})
    if password:
        findings += pd.detect_sequences(password) + pd.detect_keyboard_patterns(password) + pd.detect_repetition(password)
        structure = pd.detect_predictable_structure(password)
        findings += structure
        dict_f, words = pd.detect_dictionary_words(password)
        passphrase_like = len(words) >= 3 and len(password) >= 16
        if passphrase_like:
            strengths.append("Looks like a multi-word passphrase (only strong if the words were chosen randomly).")
        elif dict_f and not structure and not common:
            findings += dict_f
        findings += check_personal_context(password, context)

    active = [f for f in findings if f["severity"] != "info"]
    covered = pd.covered_length(active)
    rep_cov = pd.covered_length([f for f in active if f["type"] == "repeated_characters"]) / max(1, len(password))
    theo_bits, pool = estimate_theoretical_entropy(password)
    eff_bits = estimate_effective_entropy(password, covered)
    score, label, breakdown = compute_score(len(password), chars["character_type_count"],
                                            chars["unique_character_ratio"], active, eff_bits, common or not password, rep_cov)
    if not password:
        score, label = 0, "VERY WEAK"

    if len(password) >= 12: strengths.append("Good length")
    if chars["character_type_count"] >= 3: strengths.append("Character variety (helpful, but not sufficient on its own)")
    if password and not common: strengths.append("Not found in the local common-password list")
    if password and not any(f["type"] in ("sequence", "keyboard_pattern", "repeated_characters", "repeated_substring") for f in findings):
        strengths.append("No sequences, keyboard walks or repetition detected")

    metrics = {**length, **chars, "pool_size": pool, "theoretical_entropy_bits": theo_bits,
               "effective_entropy_bits": eff_bits, "guess_resistance_estimate": guess_resistance_label(eff_bits),
               "guess_resistance_disclaimer": "Educational estimate only.",
               "pattern_count": len({f["type"] for f in active}), "score_breakdown": breakdown}
    return {"score": score, "classification": label, "findings": _public(active), "strengths": strengths,
            "suggestions": generate_suggestions(active, len(password), score), "metrics": metrics,
            "policy": evaluate_policy(password, context, active, policy), "disclaimer": DISCLAIMER}
