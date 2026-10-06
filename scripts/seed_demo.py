"""Fills the analytics DB with SYNTHETIC demo passwords (for dashboard screenshots). Run from project root."""
from backend import config
from backend.models.analytics import AnalyticsStore
from backend.services.password_analyzer import analyze_password
from backend.services.password_generator import generate_password

DEMO = ["123456", "password", "Password123!", "qwerty2026!", "aaaaaaaaaaaaaaaa", "welcome123", "admin2026",
        "letmein", "abcd1234", "Summer2024!", "hello1234", "ababababab", "velvet-galaxy-harbor-orchid",
        "monkey", "11111111", "Rahul@123", "correct-horse-staple-demo", "iloveyou", "zxcvbnm123", "Tr0ub4dor&3"]

if __name__ == "__main__":
    store = AnalyticsStore(config.ANALYTICS_DB)
    ctx = {"first_name": "Rahul"}
    for p in DEMO:
        store.record(analyze_password(p, ctx))
    for n in (16, 20, 24, 20, 16):
        store.record(analyze_password(generate_password(n)))
    print("Seeded", len(DEMO) + 5, "synthetic analyses (metadata only).")
