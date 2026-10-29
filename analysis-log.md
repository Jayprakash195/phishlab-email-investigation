# Analysis Log

**Important:** Rows below are simulated training cases, not real investigations or external scanner results. Update the evidence and verdict after performing actual checks.

| ID | Subject | Sender domain | SPF/DKIM/DMARC | Key indicators | Evidence | Verdict/status |
|---|---|---|---|---|---|---|
| SIM-01 | URGENT: Your account will be suspended in 24 hours | `examp1epay-support.example` | fail / none / fail (simulated) | Lookalike domain, urgent threat, Reply-To mismatch, HTML attachment reference | `samples/examplepay-fictional.eml`; PDF guide's fictional walkthrough | Simulated TP — phishing |
| SIM-02 | Overdue invoice — urgent payment requested | `invoice-check.example` | neutral / none / none (simulated) | Urgency, payment request, process bypass | `samples/fake-invoice-fictional.eml` | Inconclusive until evidence review |
| SIM-03 | Review your updated employee policy | `employee-portal.example` | fail / none / fail (simulated) | Sender/reply mismatch, authentication failures | `samples/fake-hr-fictional.eml` | Inconclusive until evidence review |
| SIM-04 | Password expires today | `account-reset.example` | fail / none / fail (simulated) | Credential/OTP request, urgency | `samples/password-reset-fictional.eml` | Simulated suspicious; verify evidence |
| SIM-05 | Monthly security awareness session | `company.example` | pass / pass / pass (simulated) | No live link; illustrative passing checks | `samples/benign-comparison-fictional.eml` | Simulated benign comparison; not proof of legitimacy |

## Required fields for real/public samples
Record source and acquisition date, sample ID, subject, sender, authentication results, URL/domain/IP/hash indicators, scanner evidence, screenshot filenames, verdict, confidence, analyst notes, and whether the finding is observed or simulated.

## Pending
The guide's suggested 5–10 public-sample investigations have not been performed in this package. Do not report them as completed until you have safely analyzed real samples in an isolated VM.
