"""Unit tests for the analysis engine (run: python -m unittest discover -s tests -v)."""
import unittest
from backend.services.password_analyzer import analyze_password as A, PasswordTooLongError, analyze_length, analyze_characters
from backend.services.password_generator import generate_password, generate_passphrase
from backend.services.entropy_estimator import estimate_theoretical_entropy
from backend.services.scoring_engine import classify
from backend.services import pattern_detector as pd


def types(r): return {f["type"] for f in r["findings"]}


class TestAnalyzer(unittest.TestCase):
    def test_01_empty(self):
        r = A(""); self.assertEqual((r["score"], r["classification"]), (0, "VERY WEAK"))
    def test_02_one_char(self): self.assertEqual(A("x")["classification"], "VERY WEAK")
    def test_03_short_numeric(self): self.assertEqual(A("2468")["classification"], "VERY WEAK")
    def test_04_common(self):
        r = A("123456"); self.assertIn("common_password", types(r)); self.assertEqual(r["classification"], "VERY WEAK")
    def test_05_long_repeated(self):
        r = A("aaaaaaaaaaaaaaaa"); self.assertIn("repeated_characters", types(r)); self.assertEqual(r["classification"], "WEAK")
    def test_06_lowercase_only(self): self.assertEqual(analyze_characters("kjhgtfd")["character_type_count"], 1)
    def test_07_uppercase_only(self): self.assertEqual(analyze_characters("KJHGTFD")["uppercase"], 7)
    def test_08_numbers_only(self): self.assertEqual(analyze_characters("48203")["digits"], 5)
    def test_09_symbols_only(self): self.assertEqual(analyze_characters("#$%^&*")["symbols"], 6)
    def test_10_mixed(self): self.assertEqual(analyze_characters("aB3$")["character_type_count"], 4)
    def test_11_sequential_numbers(self): self.assertIn("sequence", types(A("x1234y")))
    def test_12_reverse_numeric(self): self.assertIn("sequence", types(A("zz9876zz")))
    def test_13_sequential_letters(self): self.assertIn("sequence", types(A("Kabcdef")))
    def test_14_keyboard(self): self.assertIn("keyboard_pattern", types(A("my-qwerty-key")))
    def test_15_repeated_chars(self): self.assertTrue(pd.detect_repetition("a1111b"))
    def test_16_repeated_substring(self): self.assertIn("repeated_substring", types(A("abcabcabc")))
    def test_17_word_plus_number(self): self.assertIn("word_plus_number", types(A("hello1234")))
    def test_18_word_year(self): self.assertIn("word_plus_number", types(A("admin2026")))
    def test_19_personal_name(self):
        r = A("Rahul@123", {"first_name": "Rahul"}); self.assertIn("personal_info", types(r))
    def test_20_birth_year(self): self.assertIn("personal_info", types(A("zk#2004#Qw", {"birth_year": "2004"})))
    def test_21_passphrase(self):
        r = A("velvet-galaxy-harbor-orchid"); self.assertGreaterEqual(r["score"], 61)
    def test_22_unicode(self):
        r = A("pässwörd-ключ-密码-Ωmega"); self.assertIn(r["classification"], {"MODERATE", "STRONG", "VERY STRONG", "WEAK"})
    def test_23_spaces(self): self.assertEqual(analyze_characters("a b c")["spaces"], 2)
    def test_24_max_length(self):
        A("a" * 128)
        with self.assertRaises(PasswordTooLongError): A("a" * 129)
    def test_25_boundaries(self):
        for s, c in [(0, "VERY WEAK"), (20, "VERY WEAK"), (21, "WEAK"), (40, "WEAK"), (41, "MODERATE"),
                     (60, "MODERATE"), (61, "STRONG"), (80, "STRONG"), (81, "VERY STRONG"), (100, "VERY STRONG")]:
            self.assertEqual(classify(s), c)
    def test_26_suggestions_specific(self):
        r = A("qwerty1234"); s = " ".join(r["suggestions"]).lower()
        self.assertIn("sequence", s); self.assertIn("mfa", s)
    def test_27_generator(self):
        for n in (16, 20, 24):
            p = generate_password(n); self.assertEqual(len(p), n)
            self.assertTrue(any(c.isupper() for c in p) and any(c.isdigit() for c in p))
        self.assertGreaterEqual(A(generate_password(20))["score"], 61)
        with self.assertRaises(ValueError): generate_password(20, False, False, False, False)
        self.assertEqual(len(generate_passphrase(5)[0].split("-")), 5)
    def test_28_composition_not_enough(self):
        r = A("Password123!"); self.assertEqual(r["metrics"]["character_type_count"], 4); self.assertLessEqual(r["score"], 60)
    def test_29_entropy_optimistic_vs_effective(self):
        r = A("Password123!"); self.assertGreater(r["metrics"]["theoretical_entropy_bits"], r["metrics"]["effective_entropy_bits"])
        self.assertGreater(estimate_theoretical_entropy("aB3$aB3$")[0], 0)
    def test_30_policy_separate_from_score(self):
        r = A("Password123!"); self.assertTrue(r["policy"]["passed"]); self.assertLess(r["score"], 61)
    def test_31_length_bands(self):
        self.assertEqual(analyze_length("a" * 5)["band"], "Very short"); self.assertEqual(analyze_length("a" * 17)["band"], "Strong length contribution")
    def test_32_leet_common(self): self.assertIn("common_password", types(A("p@ssw0rd")))
    def test_33_demo_cases(self):
        self.assertEqual(A("qwerty2026!")["classification"], "WEAK")
        self.assertIn(A("Password123!")["classification"], {"WEAK", "MODERATE"})


if __name__ == "__main__":
    unittest.main()
