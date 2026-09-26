# Screenshot Guide

Store only sanitized evidence in this directory. Remove passwords, license information, email addresses, session tokens, public IP addresses, and unrelated personal data before committing an image.

Directory structure:

```text
screenshots/
├── lab-setup/
│   ├── 01-lab-architecture.png
│   ├── 02-forwarder-active.png
│   └── 03-sysmon-events.png
├── DE-001-encoded-powershell/
    ├── 04-de-001-search-result.png
    ├── 05-de-001-triggered-alert.png
    ├── 06-event-correlation.png
    ├── 07-decoded-payload.png
    └── 08-investigation-verdict.png
└── DE-002-repeated-failed-logons/
    ├── 09-de-002-search-result.png
    └── 10-de-002-triggered-alert.png
```

Each screenshot should show enough context to support a claim in the README. Crop unrelated browser tabs and desktop content.

## Lab setup evidence

- [Architecture](lab-setup/01-lab-architecture.png)
- [Active forward destination](lab-setup/02-forwarder-active.png)
- [Sysmon events in Splunk](lab-setup/03-sysmon-events.png)

## DE-001 evidence

- [Detection search result](DE-001-encoded-powershell/04-de-001-search-result.png)
- [Triggered alert](DE-001-encoded-powershell/05-de-001-triggered-alert.png)
- [Correlated events](DE-001-encoded-powershell/06-event-correlation.png)
- [Decoded payload](DE-001-encoded-powershell/07-decoded-payload.png)
- [Investigation verdict](DE-001-encoded-powershell/08-investigation-verdict.png)

## DE-002 evidence

- [Detection search result](DE-002-repeated-failed-logons/09-de-002-search-result.png)
- [Triggered alert](DE-002-repeated-failed-logons/10-de-002-triggered-alert.png)
