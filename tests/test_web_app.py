import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app as web_app  # noqa: E402


class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        web_app.app.config.update(TESTING=True)
        cls.sample = ROOT / "samples" / "examplepay-fictional.eml"

    def setUp(self):
        self.client = web_app.app.test_client()

    def test_homepage(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Email investigation", response.data)
        self.assertIn(b"/static/js/app.js", response.data)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")
        self.assertTrue(response.json["parser_available"])

    def test_valid_fictional_email_upload(self):
        response = self.client.post(
            "/api/analyze",
            data={"file": (io.BytesIO(self.sample.read_bytes()), "examplepay-fictional.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("URGENT", payload["result"]["subject"])
        self.assertTrue(payload["result"]["headers"].get("From"))
        self.assertIn("verdict", payload["result"])

    def test_missing_upload(self):
        response = self.client.post("/api/analyze", data={}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json["ok"])

    def test_invalid_extension(self):
        response = self.client.post(
            "/api/analyze", data={"file": (io.BytesIO(b"Subject: hello\n\nbody"), "email.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 415)

    def test_empty_upload(self):
        response = self.client.post(
            "/api/analyze", data={"file": (io.BytesIO(b""), "empty.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_malformed_message_is_handled(self):
        response = self.client.post(
            "/api/analyze", data={"file": (io.BytesIO(b"this is not a normal email"), "malformed.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.json["ok"])
        self.assertEqual(response.json["result"]["subject"], "(No subject)")

    def test_script_like_content_is_not_rendered_as_html(self):
        raw = b"From: analyst@example.com\nSubject: <script>alert(1)</script>\nContent-Type: text/plain; charset=utf-8\n\n<script>alert('x')</script>"
        response = self.client.post(
            "/api/analyze", data={"file": (io.BytesIO(raw), "script-test.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("<script>alert(1)</script>", response.json["result"]["subject"])
        # JSON data is consumed by the frontend via textContent, not HTML insertion.
        self.assertIn(b"textContent", (ROOT / "static" / "js" / "app.js").read_bytes())

    def test_nul_bytes_rejected(self):
        response = self.client.post(
            "/api/analyze", data={"file": (io.BytesIO(b"From: a@example.com\x00\n\nbody"), "bad.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)

    def test_oversized_upload(self):
        original = web_app.app.config["MAX_CONTENT_LENGTH"]
        web_app.app.config["MAX_CONTENT_LENGTH"] = 256
        try:
            response = self.client.post(
                "/api/analyze", data={"file": (io.BytesIO(b"A" * 2048), "large.eml")},
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 413)
            self.assertFalse(response.json["ok"])
        finally:
            web_app.app.config["MAX_CONTENT_LENGTH"] = original

    def test_report_routes(self):
        response = self.client.get("/reports/incident-report")
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"EXISTING PROJECT DOCUMENT", response.data)
        finally:
            response.close()

        pdf = self.client.get("/reports/incident-report.pdf")
        try:
            self.assertEqual(pdf.status_code, 200)
            self.assertTrue(pdf.data.startswith(b"%PDF"))
        finally:
            pdf.close()

    def test_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))

    def test_parser_error_is_safely_reported(self):
        with patch.object(web_app, "parse_eml", side_effect=ValueError("sensitive local path C:\\private")):
            response = self.client.post(
                "/api/analyze", data={"file": (io.BytesIO(b"Subject: x\n\nbody"), "error.eml")},
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("C:\\private", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
