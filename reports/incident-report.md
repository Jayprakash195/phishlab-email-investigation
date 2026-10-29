# Incident Report: Credential-Harvesting Phishing Email Impersonating ExamplePay

**Status:** Fictional training case  
**Verdict:** True Positive — phishing (expected verdict in the supplied guide)  
**Evidence status:** Email content and header values are simulated; no external scanner results were obtained.

## Executive summary
A fictional email impersonating “ExamplePay Support” uses urgent account-suspension language and requests identity verification through a lookalike domain. The sample includes simulated SPF and DMARC failures, no DKIM signature, a mismatched Reply-To, and a referenced HTML attachment. Combined indicators support the training verdict of phishing/credential harvesting.

## Reported by / time
Training scenario. No real reporter or production timestamp. The email's displayed date is fictional.

## Header analysis
- **From:** `service@examp1epay-support.example` — lookalike spelling uses digit `1` in place of `l`.
- **Return-Path:** `bounce@mail-secure-support.example` — different domain from visible From.
- **Reply-To:** `recovery.team@freemail.example` — different destination domain.
- **Authentication-Results:** simulated `spf=fail`, `dkim=none`, `dmarc=fail`.
- **Received IP:** `203.0.113.45` — documentation-only address, not a real sender reputation indicator.
- **Subject:** urgency and threat of suspension within 24 hours.
- **URL:** `hxxps://examp1epay-support[.]example/verify/login.php?id=88231` (defanged).
- **Attachment:** `Account_Verification.html` is referenced; no attachment file is included.

## IOCs (fictional)
| Type | Value | Status |
|---|---|---|
| Sender domain | `examp1epay-support.example` | Simulated |
| Return-Path domain | `mail-secure-support.example` | Simulated |
| Reply-To domain | `freemail.example` | Simulated |
| IP | `203.0.113.45` | Documentation range; do not treat as live threat intel |
| URL | `hxxps://examp1epay-support[.]example/verify/login.php?id=88231` | Simulated and defanged |
| Attachment | `Account_Verification.html` | Referenced only; hash not available |

## Findings and verdict
The lookalike domain, urgency, sender/reply mismatch, simulated authentication failures, suspicious login path, and HTML attachment reference are consistent with credential-harvesting phishing in this fictional exercise. A failed authentication check alone would not be sufficient. The expected training verdict is **True Positive**.

## MITRE ATT&CK
- **T1566.002 — Spearphishing Link:** relevant to the link-based lure in the scenario.
- **T1566.001 — Spearphishing Attachment:** relevant as a possible attachment delivery technique; actual execution is not demonstrated.
- **T1204 — User Execution:** do not assert this occurred; there is no evidence of user interaction in the sample.

## Impact
Unknown in the fictional scenario. No evidence indicates delivery to real users, clicks, credential submission, or endpoint compromise.

## Actions
**Recommended, not performed:** search mail/SIEM logs for matching indicators; block confirmed malicious indicators through authorized controls; remove matching messages; if credentials were submitted, reset credentials and revoke sessions; if an attachment executed, escalate and follow endpoint isolation procedures.

## External checks
VirusTotal, URLScan.io, AbuseIPDB, WHOIS, and sandbox checks have **not** been run for this report. The domains are reserved examples and the IP is a documentation address, so real-world reputation results would not be meaningful.

## Limitations and next steps
- Collect genuine screenshots from actual tool workflows using suitable public or authorized indicators.
- Safely analyze 5–10 public samples in an isolated VM if required by the course.
- Update the analysis log with observed evidence and timestamps.
- Do not present simulated findings as a real incident investigation.
