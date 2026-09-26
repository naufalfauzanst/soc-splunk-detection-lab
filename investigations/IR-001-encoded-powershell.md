# IR-001: Encoded PowerShell Alert Investigation

## Case summary

| Field | Value |
|---|---|
| Investigation ID | IR-001 |
| Alert | DE-001 Encoded PowerShell Execution |
| Endpoint | SOC-ENDPOINT-01 |
| User | naufal |
| Severity | High |
| MITRE ATT&CK | T1059.001 PowerShell |
| Disposition | Benign Positive |
| Status | Closed |

## Alert context

The scheduled Splunk search detected `powershell.exe` with an encoded command argument on `SOC-ENDPOINT-01`. The event was generated during an authorized detection validation exercise.

## Evidence reviewed

| Evidence | Purpose | Finding |
|---|---|---|
| Sysmon Event ID 1 | Process creation | Recorded PowerShell, its command line, parent, user, and hashes |
| PowerShell Event ID 4104 | Script content | Recorded the decoded script block text |
| Security Event ID 4688 | Windows process audit | Confirmed process creation context |
| Base64 payload | Command intent | Decoded to a harmless `Write-Output` command |

## Decoded command

```powershell
Write-Output "SOC_ALERT_VALIDATION_001"
```

## Analysis

The command was launched manually as part of the lab validation. The decoded content did not download a file, contact an external command-and-control service, create persistence, access credentials, or modify security controls. The supporting events matched the same endpoint and test period.

## Verdict

**Benign Positive.** The detection worked as designed, but the activity was authorized and harmless.

## Response taken

- Confirmed the test with the lab owner.
- Decoded and reviewed the payload.
- Correlated Sysmon, PowerShell, and Security telemetry.
- Preserved the event details for the portfolio.
- Closed the case without endpoint containment.

## Evidence still to add

- [ ] Alert timestamp
- [ ] Exact event timestamps
- [ ] Process GUID or process ID
- [ ] Parent process path
- [ ] SHA-256 hash
- [ ] Detection result screenshot
- [ ] Triggered alert screenshot
- [ ] Correlation screenshot
- [ ] Payload decoding screenshot

## Analyst notes

Add any additional observations, tuning decisions, and lessons learned here.
