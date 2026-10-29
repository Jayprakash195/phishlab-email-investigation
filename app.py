"""Flask web interface for the offline phishing-email training parser."""
from __future__ import annotations

import io
import os
import re
import tempfile
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
REPORT_MD = ROOT / "reports" / "incident-report.md"
REPORT_PDF = ROOT / "reports" / "incident-report.pdf"
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024)))

# The existing parser is deliberately reused; it is not duplicated here.
import sys
sys.path.insert(0, str(ROOT / "src"))
from analyze_eml import defang_ioc, parse_eml  # noqa: E402

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["JSON_SORT_KEYS"] = False


def _first(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name, [])
    return values[0] if values else ""


def _address_domains(value: str) -> set[str]:
    domains: set[str] = set()
    for _name, address in getaddresses([value]):
        if "@" in address:
            domain = address.rsplit("@", 1)[1].strip().strip(".>").lower()
            if domain:
                domains.add(domain)
    return domains


def _analyse_indicators(parsed: dict[str, Any]) -> tuple[list[dict[str, str]], str]:
    headers = parsed.get("headers", {})
    indicators: list[dict[str, str]] = []
    from_value = _first(headers, "From")
    reply_to = _first(headers, "Reply-To")
    from_domains = _address_domains(from_value)
    reply_domains = _address_domains(reply_to)

    if from_domains and reply_domains and from_domains.isdisjoint(reply_domains):
        indicators.append({
            "level": "review",
            "title": "From and Reply-To domains differ",
            "detail": "The visible sender and reply destination use different domains. This can be legitimate, but should be reviewed in context.",
        })

    auth_values = headers.get("Authentication-Results", [])
    auth_text = " ".join(auth_values).lower()
    for mechanism in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mechanism}\s*=\s*(fail|softfail|permerror|temperror|none)\b", auth_text):
            indicators.append({
                "level": "review",
                "title": f"Authentication header reports {mechanism.upper()} issue",
                "detail": f"The supplied Authentication-Results header contains a {mechanism.upper()} result that merits review. The application does not independently verify this header.",
            })

    if parsed.get("urls"):
        indicators.append({
            "level": "info",
            "title": f"{len(parsed['urls'])} URL(s) extracted",
            "detail": "URLs were extracted from the message body. Their reputation and safety have not been checked; do not open them from the email.",
        })

    if indicators:
        verdict = "Needs further investigation"
    else:
        verdict = "No obvious indicators found"
    return indicators, verdict


def _make_result(parsed: dict[str, Any], filename: str) -> dict[str, Any]:
    indicators, verdict = _analyse_indicators(parsed)
    headers = parsed.get("headers", {})
    return {
        "filename": filename,
        "subject": parsed.get("subject", "") or "(No subject)",
        "headers": headers,
        "from": _first(headers, "From"),
        "to": _first(headers, "To"),
        "reply_to": _first(headers, "Reply-To"),
        "date": _first(headers, "Date"),
        "message_id": _first(headers, "Message-ID"),
        "urls": [{"original_extracted": url, "defanged": defang_ioc(url)} for url in parsed.get("urls", [])],
        "ips": parsed.get("ips", []),
        "indicators": indicators,
        "verdict": verdict,
        "limitations": [
            "This parser extracts message data; it does not independently authenticate email headers.",
            "URL reputation, malware scanning, attachment analysis, and live threat-intelligence checks are not performed.",
            "A lack of observed indicators does not prove an email is safe.",
        ],
    }


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    return response


@app.errorhandler(RequestEntityTooLarge)
def handle_too_large(_error):
    message = f"File is too large. Maximum upload size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": message}), 413
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024), page="overview", startup_error=message), 413


@app.route("/")
def index():
    return render_template("index.html", max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024), page="overview")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "parser_available": callable(parse_eml)})


@app.post("/api/analyze")
def analyze_email():
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"ok": False, "error": "Choose an .eml file before starting analysis."}), 400

    filename = secure_filename(upload.filename or "")
    if not filename:
        return jsonify({"ok": False, "error": "The uploaded file must have a filename."}), 400
    if Path(filename).suffix.lower() != ".eml":
        return jsonify({"ok": False, "error": "Only .eml files are accepted."}), 415

    raw = upload.read(MAX_UPLOAD_BYTES + 1)
    if not raw:
        return jsonify({"ok": False, "error": "The uploaded file is empty."}), 400
    if len(raw) > MAX_UPLOAD_BYTES:
        return jsonify({"ok": False, "error": f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit."}), 413
    # Basic content sanity check: .eml is a textual message format. The parser still
    # handles malformed messages defensively; this is not a security verdict.
    if b"\x00" in raw[:8192]:
        return jsonify({"ok": False, "error": "The file does not look like a valid text-based .eml message."}), 400

    try:
        with tempfile.TemporaryDirectory(prefix="phish-investigation-") as tmp_dir:
            temp_path = Path(tmp_dir) / "uploaded-message.eml"
            temp_path.write_bytes(raw)
            parsed = parse_eml(temp_path)
        result = _make_result(parsed, filename)
    except (OSError, ValueError, UnicodeError) as exc:
        app.logger.warning("Email parsing failed (%s)", type(exc).__name__)
        return jsonify({"ok": False, "error": "The email could not be parsed. Check that it is a readable .eml file."}), 422
    except Exception:
        app.logger.exception("Unexpected parser error")
        return jsonify({"ok": False, "error": "An unexpected error occurred while analyzing the email."}), 500

    return jsonify({"ok": True, "result": result})


@app.get("/reports/incident-report")
def incident_report():
    if not REPORT_MD.is_file():
        return render_template("report.html", report_text="Incident report file is not available."), 404
    # Render as escaped plain text, not as HTML or Markdown supplied by a file.
    return render_template("report.html", report_text=REPORT_MD.read_text(encoding="utf-8", errors="replace"))


@app.get("/reports/incident-report.pdf")
def incident_report_pdf():
    if not REPORT_PDF.is_file():
        return "Incident report PDF is not available.", 404
    return send_file(REPORT_PDF, mimetype="application/pdf", as_attachment=False, download_name="incident-report.pdf")


if __name__ == "__main__":
    # Development only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
