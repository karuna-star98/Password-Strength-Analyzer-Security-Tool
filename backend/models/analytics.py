"""
Privacy-safe analytics (SQLite). There is intentionally NO password column, NO hash and NO partial value.
Even hashes of arbitrary user-submitted passwords are avoided: a leaked table of fast hashes of real
passwords would become a guessing oracle, and aggregate dashboards do not need them.
"""
import sqlite3, uuid
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id TEXT PRIMARY KEY,
    score INTEGER NOT NULL,
    classification TEXT NOT NULL,
    password_length INTEGER NOT NULL,
    unique_character_ratio REAL NOT NULL,
    weakness_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id),
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL
);
"""
CLASSES = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"]


class AnalyticsStore:
    def __init__(self, path):
        self.path = path
        with closing(self._conn()) as c:
            c.executescript(SCHEMA); c.commit()

    def _conn(self):
        return sqlite3.connect(self.path)

    def record(self, result):
        """Stores ONLY derived metadata taken from the analysis result."""
        aid = uuid.uuid4().hex
        m = result["metrics"]
        with closing(self._conn()) as c:
            c.execute("INSERT INTO analyses VALUES (?,?,?,?,?,?,?)",
                      (aid, result["score"], result["classification"], m["length"],
                       m["unique_character_ratio"], m["pattern_count"],
                       datetime.now(timezone.utc).isoformat(timespec="seconds")))
            c.executemany("INSERT INTO findings (analysis_id, finding_type, severity, description) VALUES (?,?,?,?)",
                          [(aid, f["type"], f["severity"], f["description"]) for f in result["findings"]])
            c.commit()
        return aid

    def stats(self):
        with closing(self._conn()) as c:
            total, avg = c.execute("SELECT COUNT(*), COALESCE(AVG(score),0) FROM analyses").fetchone()
            by_class = dict(c.execute("SELECT classification, COUNT(*) FROM analyses GROUP BY classification"))
            scores = [r[0] for r in c.execute("SELECT score FROM analyses")]
            lengths = [r[0] for r in c.execute("SELECT password_length FROM analyses")]
        bins = [f"{i}-{i + 9}" for i in range(0, 100, 10)]
        score_dist = {b: 0 for b in bins}
        for s in scores:
            score_dist[bins[min(s // 10, 9)]] += 1
        lb = {"<8": 0, "8-11": 0, "12-15": 0, "16-19": 0, "20+": 0}
        for n in lengths:
            lb["<8" if n < 8 else "8-11" if n < 12 else "12-15" if n < 16 else "16-19" if n < 20 else "20+"] += 1
        return {"total_analyses": total, "average_score": round(avg, 1),
                "strength_distribution": {k: by_class.get(k, 0) for k in CLASSES},
                "score_distribution": score_dist, "length_distribution": lb}

    def weaknesses(self):
        with closing(self._conn()) as c:
            rows = c.execute("SELECT finding_type, COUNT(*) FROM findings GROUP BY finding_type ORDER BY 2 DESC").fetchall()
        return {"weaknesses": dict(rows)}
