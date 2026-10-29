# Phishing Email Investigation Playbook — L1 SOC

## 1. Triage
- Preserve the original `.eml` and relevant metadata.
- Record reporter, receipt time/time zone, recipients, subject, and affected mailbox.
- Ask whether anyone clicked, opened an attachment, entered credentials, approved MFA, or sent money.
- Prioritize credential exposure, executed attachments, executives, and financial requests.

## 2. Analyze
- Inspect From, Return-Path, Reply-To, Received, Message-ID, and Authentication-Results.
- Interpret SPF (sending IP authorization), DKIM (message signature), and DMARC (policy and alignment).
- Compare visible sender and reply/bounce domains.
- Defang URLs and record the exact evidence source.
- Inspect attachments as text; compute hashes and identify file types without execution.
- Check reputation using approved tools. Record time, source, result, and limitations.

## 3. Scope
- Search authorized mail gateway, endpoint, proxy, identity, and SIEM logs for sender, subject, URL, domain, hash, and Message-ID.
- Determine recipients, delivery, opens/clicks where telemetry exists, credential submissions if known, and related messages.
- Do not claim a click or execution from an email alone.

## 4. Verdict
- **True Positive:** sufficient combined evidence supports malicious/phishing activity.
- **False Positive:** evidence supports legitimate activity and no meaningful malicious indicators remain.
- **Inconclusive:** evidence is insufficient or conflicting.
- An SPF/DKIM/DMARC failure alone does not prove phishing.

## 5. Containment (authorized responders only)
- Recommend blocking confirmed malicious senders/domains/URLs/IPs using approved controls.
- Search for and remove matching messages from mailboxes under established procedures.
- If credentials may have been exposed: reset password, revoke sessions/tokens, inspect MFA changes, mailbox rules, and sign-in logs.
- If a suspicious attachment was executed: preserve evidence, isolate the endpoint through approved EDR procedures, and escalate to L2/incident response.
- Record what was actually done separately from what is recommended.

## 6. Recovery and post-incident
- Restore access only after account/endpoint checks are satisfactory.
- Update detections/blocklists as justified by evidence.
- Notify affected users, provide awareness guidance, and document lessons learned.

## Decision flow
1. Suspicious indicators present? If no, document and close only under policy; if uncertain, gather more evidence.
2. Header/content/link/attachment evidence consistent with phishing? If yes, assess scope and assign TP; if mixed, mark inconclusive.
3. User clicked or supplied credentials? Investigate proxy and sign-in logs; initiate credential/session response if indicated.
4. Attachment executed? Escalate to L2 and follow endpoint isolation/evidence procedures.
5. Complete incident report, record evidence, and communicate outcome.

## Escalate immediately when
- Credentials/OTP or payment may have been provided.
- An attachment was executed or endpoint behavior is suspicious.
- Multiple users or executive/financial accounts are affected.
- Evidence suggests active compromise or the analyst lacks authorization to contain.
