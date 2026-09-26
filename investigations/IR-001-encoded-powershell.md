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
| Event timestamp | 2026-09-26 02:00:22.271 |
| Alert timestamp | 2026-09-26 02:05:01 SE Asia Standard Time |
| Disposition | Benign Positive |
| Status | Closed |

## Alert context

The scheduled Splunk search detected `powershell.exe` with an encoded command argument on `SOC-ENDPOINT-01`. The event was generated during an authorized detection validation exercise.

## Process details

| Field | Value |
|---|---|
| Process image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process GUID | `{3f37587f-c4c6-6ab6-8312-000000000d00}` |
| Process ID | `3832` |
| SHA-256 | `8BB6FA8C283B4D92120B1EF249A9B311B0F804D4CABBE9981159976C8BE76A5E` |
| Command option | `-NoProfile -EncodedCommand` |

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

## Evidence

- [x] [Detection result](../screenshots/DE-001-encoded-powershell/04-de-001-search-result.png)
- [x] [Triggered alert](../screenshots/DE-001-encoded-powershell/05-de-001-triggered-alert.png)
- [x] [Correlated telemetry](../screenshots/DE-001-encoded-powershell/06-event-correlation.png)
- [x] [Payload decoding](../screenshots/DE-001-encoded-powershell/07-decoded-payload.png)
- [x] [Investigation verdict](../screenshots/DE-001-encoded-powershell/08-investigation-verdict.png)

Case fields completed:

- [x] Exact event and alert timestamps
- [x] Process GUID and Process ID
- [x] Parent process path
- [x] SHA-256 hash

## Analyst notes

The scheduled alert fired approximately four minutes and 39 seconds after the process event. The repeated events observed during analysis were duplicate indexed copies of the same Sysmon record, so the investigation used the Process GUID to identify the unique process execution.
