# Password Strength Analyzer & Security Suggestion Tool

> Privacy-focused cybersecurity tool for evaluating password strength using length, predictability, common-password checks, pattern analysis, entropy concepts, and personalized security recommendations.

## Overview
A defensive web tool that analyzes a password **in memory**, gives a 0–100 score, a classification (VERY WEAK → VERY STRONG), the specific weaknesses found, and actionable suggestions. It never stores, logs, or transmits passwords to third parties.

## Problem Statement
Weak and reused passwords remain a top cause of account takeover. Composition rules (upper+lower+digit+symbol) wrongly rate `Password123!` as fine.

## Objectives
Assess **length + unpredictability + pattern resistance + common-password checks + context**, explain findings clearly, teach password hygiene, and prove a privacy-by-design approach.

## Cybersecurity Relevance
Mirrors controls in NIST SP 800-63B and OWASP ASVS: block common passwords, favour length/passphrases, don't force composition rules or periodic rotation, protect secrets in transit/at rest. Relevant to Cybersecurity, AppSec, IAM and SOC roles.

## Features
Real-time meter · show/hide · length & character analysis · common-password check · sequence / keyboard / repetition detection · word+number & year patterns · optional personal-context check · entropy estimates · suggestions · passphrase education · secure generator · policy checker (PASS/FAIL separate from strength) · privacy-safe SQLite analytics · 4-chart dashboard · hashing demo.

## Architecture
```
Browser (HTML/CSS/JS) ──POST /api/analyze──▶ Flask
   password field                              │ in-memory only
                                               ▼
  Length · Characters · Common · Sequence · Keyboard · Repetition · Context · Entropy
                                               ▼
                    Scoring engine → Classification → Suggestion engine
                                               ▼
              JSON (no password)   ──optional──▶ SQLite (metadata only) ▶ Dashboard
```
```
backend/ app.py · config.py · routes/api.py · models/analytics.py · utils/ · services/
         password_analyzer · pattern_detector · entropy_estimator · scoring_engine · suggestion_engine · password_generator
frontend/ index.html · css/ · js/        data/ common_passwords.txt, dictionary_words.txt
tests/ (47 tests)   demos/hashing_demo.py   scripts/seed_demo.py   docs/   screenshots/   reports/
```

## Technology Stack
Python 3.10+, Flask, SQLite, vanilla JS, Chart.js (CDN). Chosen over React/FastAPI for beginner-friendliness (no build step); the analyzer in `services/` is framework-independent, so a FastAPI/React front end can reuse it.

## Password Analysis
`analyze_password(password, context=None, policy=None)` returns `score`, `classification`, `findings`, `strengths`, `suggestions`, `metrics`, `policy`.

## Length Analysis
Bands (educational, configurable in `config.py`): <8 very short · 8–11 short · 12–15 better · 16+ strong contribution. Length alone is not security: `aaaaaaaaaaaaaaaaaaaa` is long but predictable.

## Pattern Detection
Ascending/descending sequences (`1234`, `dcba`), keyboard walks (`qwerty`, `1qaz2wsx`), repeated characters/substrings (`aaaa`, `abcabc`), word+number (`welcome123`), years, dictionary words (a 3+ word long passphrase is treated differently), leetspeak normalization (`p@ssw0rd`).

## Common Password Detection
Small educational list in `data/common_passwords.txt` (no leaked credentials, no personal data).

## Entropy Estimation
`Entropy ≈ L × log2(N)` assumes random choice, so it is **optimistic** for human passwords. We also compute an **effective** estimate that gives no credit to characters covered by detected patterns.

## Strength Scoring
Length 35 · diversity 15 · unique ratio 10 · pattern resistance 20 · non-common 10 · unpredictability 10, minus penalties (common −40, keyboard −15, sequence −12, repetition −15…−30, personal info −20, word+number −15, year −10). Passwords under 8 characters are capped at 20 and under 12 at 60. Bands: 0–20 VERY WEAK, 21–40 WEAK, 41–60 MODERATE, 61–80 STRONG, 81–100 VERY STRONG. **These are project-defined bands, not a universal standard.**

## Security Suggestions
Specific, never containing the password (e.g. "Remove predictable sequences such as 1234…"), plus unique passwords, password manager, MFA.

## Password Generator
`secrets` (OS CSPRNG), not `random` (predictable Mersenne Twister). Lengths 16/20/24, selectable types, ≥1 of each chosen type, never stored. Passphrase mode uses a small *demo* word list (≈7.5 bits/word); use a 7,776-word list for real passphrases.

## Password Policy Checker
Configurable `minimum_length`, `common_password_check`, `personal_info_check`; max 128, spaces allowed, no forced rotation. Shown as POLICY PASS/FAIL **separately** from the score.

## Privacy Design
Password: processed transiently · not logged · not in DB · not in responses/errors · not in URLs · no web storage · analytics record only on explicit click, only `score, classification, length, unique ratio, weakness count, timestamp, finding types`. No hash is stored (a leaked table of fast hashes would become a guessing oracle).

## Installation
```bash
git clone <repository-url> && cd Password-Strength-Analyzer-Security-Tool
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
```bash
python -m scripts.seed_demo       # optional: synthetic data for the dashboard
python -m backend.app             # open http://127.0.0.1:5000
python demos/hashing_demo.py      # salted scrypt hashing demo
```
Try (synthetic): `123456` → VERY WEAK · `Password123!` → WEAK · `aaaaaaaaaaaaaaaa` → WEAK · `qwerty2026!` → WEAK · generator output → VERY STRONG. Never reuse demo passwords.

## API Documentation
| Method & path | Purpose |
|---|---|
| `POST /api/analyze` `{password, context?, policy?, record?}` | 200 result · 400 bad JSON · 413 too large · 422 invalid/too long · 429 rate limited |
| `POST /api/generate-password` `{mode, length, uppercase, lowercase, numbers, symbols}` | secure password / passphrase |
| `GET /api/dashboard/stats` · `GET /api/analytics/weaknesses` | aggregate metadata |

Errors use fixed messages and never echo input. Rate limiting is per-IP in memory (use a gateway in production). **Use HTTPS in production** so passwords are protected in transit.

## Testing
`python -m unittest discover -s tests -v` — 47 tests: engine (empty, short, common, repeated, sequences, keyboard, personal context, Unicode, spaces, max length, score boundaries, suggestions, generator) and privacy/API.

## Security Testing
Verified by tests: password absent from API responses, errors, logs, database file and schema; analytics metadata only; no web storage/console in JS; `type="password"` input; `Cache-Control: no-store`; rate limiting.

## Results
All 47 tests pass. Demo calibration: `123456` 0 · `Password123!` 35 · `aaaaaaaaaaaaaaaa` 27 · `qwerty2026!` 24 · passphrase ≈88 · random 20-char ≈98.

## Limitations
Heuristic scoring; small word lists; no breach-corpus check; no multilingual dictionaries; not a substitute for MFA, rate limiting and proper hashing.

## Future Improvements
zxcvbn-style estimation · bigger licensed wordlists · privacy-preserving breach check (k-anonymity prefix) · configurable enterprise policies · passkeys/WebAuthn education · accessibility & localization · org-level aggregate reports.

## Screenshots
Add to `screenshots/` (see `docs/GITHUB_AND_PROOF.md`), then embed: `![Analyzer](screenshots/03_analyzer_home.png)`. Use synthetic passwords only.

## Learning Outcomes
Secure coding, privacy-by-design, pattern detection, entropy limits, password-storage concepts (salt, scrypt/Argon2id/bcrypt), policy design, API security, testing.

## Security Disclaimer
Educational tool. Only enter demo passwords. Never type a real password into any tool you don't fully trust. Not a password cracker; contains no guessing/cracking functionality.

## Author
Your Name · LinkedIn · GitHub
