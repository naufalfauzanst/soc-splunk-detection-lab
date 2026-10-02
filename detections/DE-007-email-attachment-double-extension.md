# DE-007 — Suspicious Email Attachment Double Extension

## Objective

Detect misleading double extensions in Gmail attachment filenames, including `Invoice-October.pdf.html`. The signal identifies a suspicious naming pattern and does not establish malware content or user execution.

## Data Source

| Field | Value |
|---|---|
| Index | `email_security` |
| Source | `gmail:api` |
| Sourcetype | `gmail:lab:json` |
| Collector | [Gmail lab collector](../integrations/gmail/README.md) |

The collector reads lab-tagged messages through Gmail API and sends selected metadata via HTTPS HEC. Its `double_extension` flag matches a document-like extension (`pdf`, `doc`, `docx`, `xls`, `xlsx`, or `txt`) followed by `html`, `htm`, `exe`, `js`, `vbs`, `scr`, or `lnk`.

## Validated SPL

```spl
index=email_security source="gmail:api" earliest=-15m latest=now
| spath
| foreach subject sender_domain spf dkim dmarc gmail_id_hash double_extension [ eval <<FIELD>>=mvdedup('<<FIELD>>') ]
| where double_extension="true"
| dedup gmail_id_hash
| eval attachment_names=mvdedup('attachment_names{}')
| eval detection_name="Suspicious Email Attachment Double Extension"
| eval severity="medium"
| table _time subject sender_domain attachment_names spf dkim dmarc detection_name severity gmail_id_hash
| sort - _time
```

`spath` explicitly extracts JSON. In this lab, automatic extraction plus `spath` displayed duplicate values; `mvdedup` removes identical values within each field. `dedup gmail_id_hash` removes repeated message rows within a search.

## Alert Settings

| Setting | Value |
|---|---|
| Title | DE-007 Suspicious Email Attachment Double Extension |
| Type | Scheduled |
| Cron | `2-59/5 * * * *` |
| Search range | Last 15 minutes |
| Trigger condition | Number of Results greater than 0 |
| Trigger mode | Once / digest |
| Action | Add to Triggered Alerts |
| Severity | Medium |

Overlapping windows can produce repeat alerts for the same message. Per-message suppression across scheduled runs was not configured or validated.

## Validation

- Baseline Gmail email: zero attachments; `double_extension=false`.
- PH-005 email at `2026-10-02 14:41:35`: one `Invoice-October.pdf.html` attachment; `double_extension=true`.
- New validation email at `2026-10-02 14:46:04`: same filename pattern detected.
- Scheduler completed at `2026-10-02 14:47:01.496`, status `success`, result count `2`.
- Triggered Alerts recorded a medium-severity digest at `2026-10-02 14:47:01 SE Asia Standard Time`.
- Both detected messages passed SPF, DKIM, and DMARC.

## Triage and Limitations

Review the original message, sender context, actual file type, file hash, and recipient activity. Authentication results do not replace content review. Legitimate filenames can also match, so business context is required before containment.

The collector examines attachment metadata rather than downloading or scanning attachment bytes. It does not detect every misleading filename, Unicode trick, archive payload, or phishing message. A changed collector or alternate email source can change the flag's meaning. No automatic deletion or blocking is performed.

Potential ATT&CK context: spearphishing attachment (T1566.001). The filename alone cannot establish that technique or a malicious incident.

## Evidence

- [Baseline ingestion](../screenshots/DE-007-email-attachment-double-extension/15-gmail-splunk-ingestion.png)
- [Triggered alert](../screenshots/DE-007-email-attachment-double-extension/16-de007-triggered-alert.png)
- [Scheduled search results](../screenshots/DE-007-email-attachment-double-extension/17-de007-alert-results.png)
- [IR-007 investigation](../investigations/IR-007-email-attachment-double-extension.md)
