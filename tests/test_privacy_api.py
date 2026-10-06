"""Privacy / API tests: the password must never be stored, logged, or returned."""
import json, logging, os, sqlite3, tempfile, unittest, io, re, pathlib
from backend.app import create_app
from backend.models.analytics import AnalyticsStore
from backend.services.password_analyzer import analyze_password

SECRET = "ZebraUnicorn-Test-Secret-7731"      # synthetic marker password


class TestPrivacy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(); self.db = os.path.join(self.tmp, "t.db")
        self.app = create_app({"STORE": AnalyticsStore(self.db), "TESTING": False})
        self.c = self.app.test_client()

    def post(self, **extra):
        return self.c.post("/api/analyze", json={"password": SECRET, **extra})

    def test_34_not_in_response(self):
        r = self.post(); self.assertEqual(r.status_code, 200); self.assertNotIn(SECRET, r.get_data(as_text=True))
    def test_35_not_in_database(self):
        self.post(record=True)
        with open(self.db, "rb") as f: raw = f.read()
        self.assertNotIn(SECRET.encode(), raw)
    def test_36_schema_has_no_password_column(self):
        cols = [r[1].lower() for t in ("analyses", "findings") for r in sqlite3.connect(self.db).execute(f"PRAGMA table_info({t})")]
        self.assertFalse({"password", "plaintext", "password_hash", "hash"} & set(cols))  # password_length is just a number
    def test_37_not_logged(self):
        buf = io.StringIO(); h = logging.StreamHandler(buf); root = logging.getLogger(); root.addHandler(h); root.setLevel(logging.DEBUG)
        try: self.post(record=True)
        finally: root.removeHandler(h)
        self.assertNotIn(SECRET, buf.getvalue())
    def test_38_analytics_metadata_only(self):
        self.post(record=True); s = self.c.get("/api/dashboard/stats").get_json()
        self.assertEqual(s["total_analyses"], 1); self.assertNotIn(SECRET, json.dumps(s))
    def test_39_no_record_by_default(self):
        self.post(); self.assertEqual(self.c.get("/api/dashboard/stats").get_json()["total_analyses"], 0)
    def test_40_error_does_not_echo(self):
        r = self.c.post("/api/analyze", json={"password": SECRET * 20}); self.assertEqual(r.status_code, 422)
        self.assertNotIn(SECRET, r.get_data(as_text=True))
    def test_41_bad_requests(self):
        self.assertEqual(self.c.post("/api/analyze", data="nope").status_code, 400)
        self.assertEqual(self.c.post("/api/analyze", json={"password": 123}).status_code, 422)
    def test_42_rate_limit(self):
        self.app.config["LIMITER"].limit = 2
        codes = [self.post().status_code for _ in range(4)]; self.assertIn(429, codes)
    def test_43_no_store_headers(self):
        self.assertEqual(self.post().headers["Cache-Control"], "no-store")
    def test_44_generate_endpoint(self):
        r = self.c.post("/api/generate-password", json={"length": 24}); self.assertEqual(len(r.get_json()["password"]), 24)
        self.assertEqual(self.c.post("/api/generate-password", json={"length": 3}).status_code, 422)
    def test_45_findings_never_contain_password(self):
        self.assertNotIn(SECRET, json.dumps(analyze_password(SECRET, {"first_name": "Zebra"})))
    def test_46_frontend_no_web_storage(self):
        js = (pathlib.Path(__file__).parent.parent / "frontend/js/app.js").read_text()
        code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))
        self.assertNotRegex(code, r"localStorage|sessionStorage|console\.|document\.cookie")
    def test_47_password_input_type(self):
        html = (pathlib.Path(__file__).parent.parent / "frontend/index.html").read_text()
        self.assertRegex(html, r'id="pw" type="password"')


if __name__ == "__main__":
    unittest.main()
