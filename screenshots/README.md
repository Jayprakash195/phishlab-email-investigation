# Screenshot and Evidence Checklist

No real external-tool screenshots are included in this package. Capture genuine screenshots only after running the tools.

| Suggested filename | Action | Supports |
|---|---|---|
| `01-email-headers.png` | Open fictional `.eml` as text; capture relevant header lines | Header analysis |
| `02-header-analyzer.png` | Submit only safe, fictional headers to an analyzer if allowed; capture actual result | Parsed header fields |
| `03-virustotal.png` | Search an appropriate public indicator/hash and capture actual result | Reputation evidence |
| `04-urlscan.png` | Submit a safe, defanged/approved URL only if scanner workflow accepts it; capture result | Redirects/page behavior |
| `05-whois.png` | Look up a real authorized test domain or a relevant public indicator | Registration evidence |
| `06-hash-terminal.png` | Run `sha256sum` against a local training file and capture output | Hash calculation |
| `07-analysis-log.png` | Capture completed analysis log | Verdict/evidence traceability |
| `08-incident-report.png` | Open generated PDF and capture a readable page | Final report |

Never submit confidential email or sensitive files to public tools. Reserved `.example` domains and `203.0.113.0/24` documentation IPs are fictional and will not yield meaningful real reputation results. Mark unavailable evidence as pending rather than inventing results.
