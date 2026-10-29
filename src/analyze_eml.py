#!/usr/bin/env python3
"""Safe, offline parser for training .eml files. Does not open URLs or execute attachments."""
from email import policy
from email.parser import BytesParser
from pathlib import Path
import argparse
import hashlib
import re
import sys

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def defang_ioc(value: str) -> str:
    """Defang a URL/domain-like string for safe documentation."""
    value = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    # Defang dots in host-like values without altering path separators.
    if "://" in value:
        scheme, rest = value.split("://", 1)
        host, sep, tail = rest.partition("/")
        host = host.replace(".", "[.]")
        return scheme + "://" + host + (sep + tail if sep else "")
    if "." in value and " " not in value:
        return value.replace(".", "[.]")
    return value

def parse_eml(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(f"Email file not found: {path}")
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    headers = {}
    for name in ("From", "To", "Reply-To", "Return-Path", "Subject", "Date",
                 "Message-ID", "Received", "Authentication-Results"):
        vals = message.get_all(name, [])
        if vals:
            headers[name] = [str(v) for v in vals]
    body_parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "text" and part.get_content_disposition() != "attachment":
                try:
                    body_parts.append(part.get_content())
                except (LookupError, UnicodeDecodeError):
                    pass
    else:
        try:
            body_parts.append(message.get_content())
        except (LookupError, UnicodeDecodeError):
            pass
    body = "\n".join(str(p) for p in body_parts)
    urls = sorted(set(URL_RE.findall(body)))
    ips = sorted(set(IP_RE.findall("\n".join(sum(headers.values(), []) + [body]))))
    return {"headers": headers, "urls": urls, "ips": ips, "subject": str(message.get("Subject", ""))}

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("eml", type=Path, help="Path to an .eml file; parsed offline")
    args = parser.parse_args(argv)
    try:
        result = parse_eml(args.eml)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Subject: {result['subject']}")
    for name, values in result["headers"].items():
        for value in values:
            print(f"{name}: {value}")
    print("URLs (defanged for display):")
    for url in result["urls"]:
        print(f"  {defang_ioc(url)}")
    print("IP addresses (review context before treating as IOCs):")
    for ip in result["ips"]:
        print(f"  {ip}")
    print("Note: this parser extracts strings only; it does not validate reputation or verdicts.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
