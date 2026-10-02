# IR-007 — Live Gmail Attachment Alert

| Field | Value |
|---|---|
| Investigation date | 2026-10-02 |
| Analyst | Naufal |
| Alert | DE-007 Suspicious Email Attachment Double Extension |
| Alert time | 2026-10-02 14:47:01 SE Asia Standard Time |
| Severity | Medium |
| Verdict | True Positive — Authorized Attack Simulation |
| Status | Closed — validation complete |

## Summary

Two authorized Gmail messages carrying `Invoice-October.pdf.html` were ingested into Splunk through a Python Gmail API collector and HTTPS HEC. DE-007 correctly matched the attachment naming pattern and produced a scheduled digest alert. The attachment was a harmless static HTML training artifact; no malware or credential collection was established.

## Architecture

```text
Lab sender Gmail -> Lab analyst Gmail -> Gmail API collector on host
                                         -> HTTPS HEC (localhost:8088)
                                         -> email_security -> DE-007 -> Triggered Alerts
```

Gmail analyst access and earlier email analysis were performed in the Windows VM. The API collector ran on the Windows host. API collection occurs independently of whether the recipient browser is open.

## Observed Messages

| Email time in Splunk | Subject | Gmail ID hash |
|---|---|---|
| 2026-10-02 14:41:35 | [SOC LAB] PH-005 Invoice overdue — action required today | `40437ba0a51273530f226eb20e08427e0c133337083c876a0e5ff3de01f99912` |
| 2026-10-02 14:46:04 | [SOC LAB] PH-005 Alert validation | `1088c51b167df53596111e44cf0c80a8a48810bb04bdaffea1a218e44d1fa026` |

Both messages show sender domain `gmail.com`, attachment `Invoice-October.pdf.html`, and passing SPF, DKIM, and DMARC results. The collector records email delivery time as `_time`, with collection time in a separate field.

## Investigation Findings

1. Baseline ingestion confirmed an email without attachments produced `attachment_count=0` and `double_extension=false`.
2. Each new PH-005 message was accepted by HEC and subsequently found in an indexed search.
3. JSON extraction initially displayed duplicate field values; the final SPL normalizes them with `mvdedup`.
4. Scheduler evidence showed `success` and `result_count=2` at `14:47:01.496`.
5. The Triggered Alerts screenshot confirms a scheduled medium-severity digest at `14:47:01`.

## Attachment Context

The sent training file was previously inspected during PH-003. It is HTML, with a double extension intended to resemble a PDF, and contains a simulated invoice login prompt. It has no scripts, forms, active links, or credential collection.

Original training file SHA-256: `95F89ECBB7748673AB59615D08B940522C5C512E4D0B4867DE4F606579C970A7`.

This hash belongs to the local source file. The PH-005 collector did not download and hash the recipient-side attachment, so recipient-copy hash integrity was not established.

## Troubleshooting Resolved

- HTTPS validation initially failed with Splunk's default certificate. A private lab CA and localhost certificate were installed for HEC, and the collector trusts the public CA file.
- HEC code 4 identified an invalid token. A length check showed the input contained one character; entering the complete token through a credential prompt resolved it.
- One collection returned zero new messages; a later run collected the new validation email. Exact delivery/indexing latency was not measured.

## Verdict and Response

**True Positive — Authorized Attack Simulation**, for correct detection of the targeted filename pattern. This does not classify the actual harmless attachment as malware.

No account compromise, malicious execution, or credential submission was demonstrated. No blocking, deletion, or account reset was performed. In a real case, preserve the message, verify the invoice with the sender through a trusted channel, inspect the attachment in isolation, and establish recipient interaction before determining impact and containment.

## Evidence and Related Case

- [DE-007 query and settings](../detections/DE-007-email-attachment-double-extension.md)
- [Gmail collector](../integrations/gmail/README.md)
- [Baseline ingestion](../screenshots/DE-007-email-attachment-double-extension/15-gmail-splunk-ingestion.png)
- [Triggered alert](../screenshots/DE-007-email-attachment-double-extension/16-de007-triggered-alert.png)
- [Alert results](../screenshots/DE-007-email-attachment-double-extension/17-de007-alert-results.png)
- [PH-005 phishing investigation](https://github.com/naufalfauzanst/soc-phishing-investigation-lab/blob/main/cases/PH-005-live-gmail-attachment.md)

Only sanitized domains, subjects, filenames, and hashed identifiers are included. OAuth secrets, HEC tokens, private certificates, runtime state, and full Gmail addresses are excluded from Git.
