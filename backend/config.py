"""Central configuration. Everything is read from environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"

MAX_PASSWORD_LENGTH = 128          # inputs longer than this are rejected (DoS protection)
MAX_REQUEST_BYTES = 4096           # request body cap
ANALYTICS_ENABLED = os.environ.get("ANALYTICS_ENABLED", "true").lower() == "true"
ANALYTICS_DB = os.environ.get("ANALYTICS_DB", str(BASE_DIR / "analytics.db"))
RATE_LIMIT_PER_MIN = int(os.environ.get("RATE_LIMIT_PER_MIN", "300"))

# Educational length bands (project-defined, NOT a universal standard)
LENGTH_BANDS = [(8, "Very short"), (12, "Short"), (16, "Better length"), (10**9, "Strong length contribution")]

# Project-defined classification bands (upper bound inclusive)
CLASS_BANDS = [(20, "VERY WEAK"), (40, "WEAK"), (60, "MODERATE"), (80, "STRONG"), (100, "VERY STRONG")]

DEFAULT_POLICY = {"minimum_length": 12, "common_password_check": True, "personal_info_check": True}
