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
├── DE-002-repeated-failed-logons/
    ├── 09-de-002-search-result.png
    ├── 10-de-002-triggered-alert.png
    └── 11-de-002-investigation-verdict.png
└── DE-003-bitsadmin-network-transfer/
    ├── 12-de-003-search-result.png
    ├── 13-de-003-triggered-alert.png
    ├── 14-de-003-downloaded-file-hash.png
    └── 15-de-003-investigation-verdict.png
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
- [Investigation verdict](DE-002-repeated-failed-logons/11-de-002-investigation-verdict.png)

## DE-003 evidence

- [Detection search result](DE-003-bitsadmin-network-transfer/12-de-003-search-result.png)
- [Triggered alert](DE-003-bitsadmin-network-transfer/13-de-003-triggered-alert.png)
- [Downloaded file and SHA-256](DE-003-bitsadmin-network-transfer/14-de-003-downloaded-file-hash.png)
- [Investigation verdict](DE-003-bitsadmin-network-transfer/15-de-003-investigation-verdict.png)
