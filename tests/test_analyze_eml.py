import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from analyze_eml import defang_ioc, parse_eml

class AnalyzeEmlTests(unittest.TestCase):
    def test_defang_https_url(self):
        self.assertEqual(defang_ioc("https://evil.example/path"), "hxxps://evil[.]example/path")

    def test_defang_domain(self):
        self.assertEqual(defang_ioc("evil.example"), "evil[.]example")

    def test_parse_sample_subject_and_headers(self):
        result = parse_eml(ROOT / "samples" / "examplepay-fictional.eml")
        self.assertIn("URGENT", result["subject"])
        self.assertIn("From", result["headers"])
        self.assertIn("Authentication-Results", result["headers"])

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            parse_eml(ROOT / "does-not-exist.eml")

    def test_parse_url_from_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.eml"
            p.write_text(
                "From: analyst@example.com\nSubject: Test\nContent-Type: text/plain; charset=utf-8\n\n"
                "Visit https://evil.example/login\n", encoding="utf-8"
            )
            result = parse_eml(p)
            self.assertEqual(result["urls"], ["https://evil.example/login"])

if __name__ == "__main__":
    unittest.main()
