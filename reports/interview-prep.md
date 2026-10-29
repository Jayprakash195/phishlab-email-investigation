# SOC L1 Interview Preparation

## 30-second explanation
“I created a phishing email investigation project based on fictional training emails. I reviewed email headers and simulated SPF/DKIM/DMARC results, identified suspicious sender and Reply-To mismatches, documented defanged IOCs, and built an L1 response playbook. I also created a local parsing helper and tests. External scanner evidence and public-sample investigations are clearly marked pending until I perform them.”

## Questions and answers
1. **How do you investigate a phishing email?** Preserve the `.eml`, inspect headers and authentication, review body/links/attachments safely, extract IOCs, scope in authorized logs, decide a verdict, and document response.
2. **What is SPF?** A DNS-based mechanism to indicate which sending hosts are authorized for a domain.
3. **What is DKIM?** A cryptographic signature that helps validate message integrity and domain-associated signing.
4. **What is DMARC?** A policy and alignment mechanism using SPF/DKIM results to guide handling of messages claiming a domain.
5. **From vs Return-Path?** From is the visible author; Return-Path identifies the envelope sender used for bounces.
6. **Why inspect Reply-To?** It may route replies to a different or suspicious domain.
7. **What is an IOC?** An indicator such as a domain, IP, URL, or file hash used in investigation/detection.
8. **Why defang IOCs?** To reduce the chance that someone accidentally clicks or visits them.
9. **What is typosquatting?** A lookalike domain designed to be confused with a legitimate name.
10. **What is a True Positive?** An alert supported by evidence of malicious activity.
11. **What is a False Positive?** An alert incorrectly identified as malicious after evidence review.
12. **When is inconclusive appropriate?** When evidence is insufficient or conflicting.
13. **What if a user clicked a link?** Check proxy/browser and sign-in logs, assess credential exposure, revoke sessions/reset credentials when indicated, and escalate per policy.
14. **How do you inspect an attachment safely?** Avoid execution; identify type, hash it, inspect text/metadata, and use an approved isolated sandbox when authorized.
15. **What is MITRE ATT&CK T1566?** The phishing technique family; choose sub-techniques only when delivery evidence supports them.
16. **What is T1204?** User Execution; do not claim it without evidence of user interaction.
17. **What would you search in Splunk?** Search authorized proxy/mail logs for the URL/domain, then summarize by user and source IP using actual field names.
18. **Why isn't SPF failure alone proof?** Legitimate forwarding or configuration issues can affect results; combine it with content, domain, and other evidence.
19. **What if credentials were entered?** Escalate, reset credentials, revoke sessions, inspect MFA and mailbox rules, and review sign-in logs.
20. **What belongs in an incident report?** Summary, evidence, IOCs, verdict/reasoning, scope/impact, actions, recommendations, and limitations.

## Resume wording — use only after completing relevant tasks
“Built a phishing email investigation workflow covering email header analysis, SPF/DKIM/DMARC interpretation, IOC documentation, incident response playbooks, and local `.eml` parsing tests. Investigated external reputation and public samples only after completing those manual evidence steps.”
