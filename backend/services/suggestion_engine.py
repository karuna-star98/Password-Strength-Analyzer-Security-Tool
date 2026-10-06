"""Generates specific suggestions. NEVER includes the password itself."""

BY_TYPE = {
    "common_password": "Choose something that is not a commonly used password; these are the first guesses attackers try.",
    "sequence": "Remove predictable sequences such as 1234 or abcd and replace them with unrelated characters.",
    "keyboard_pattern": "Avoid keyboard sequences such as qwerty or asdf.",
    "repeated_characters": "Avoid repeating the same character many times in a row.",
    "repeated_substring": "Avoid repeating the same chunk of characters (like abab or abcabc).",
    "word_plus_number": "Adding numbers or symbols to a common word does not make it unpredictable. Use unrelated random words or a generated password.",
    "year_pattern": "Avoid years and dates; they are easy to guess.",
    "dictionary_word": "A single dictionary word is guessable. Combine 4+ unrelated random words into a passphrase.",
    "personal_info": "Avoid including your name, birth year, or organization name.",
}


def generate_suggestions(findings, length, score):
    out, seen = [], set()
    for f in findings:
        s = BY_TYPE.get(f["type"])
        if s and f["type"] not in seen:
            seen.add(f["type"]); out.append(s)
    if length < 12:
        out.append("Use a longer password: at least 12 characters, ideally 16+ or a long passphrase.")
    if score < 81:
        out.append("Consider a long passphrase of randomly chosen words, or let a password manager generate one.")
    out.append("Use a unique password for every account; reuse lets one breach unlock many accounts.")
    out.append("Use a password manager to generate and store unique passwords.")
    out.append("Enable multi-factor authentication (MFA) wherever it is available.")
    return out
