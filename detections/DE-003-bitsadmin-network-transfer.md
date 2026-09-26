# DE-003: Suspicious BITSAdmin Network Transfer

## Metadata

| Field | Value |
|---|---|
| Detection ID | DE-003 |
| Data source | Sysmon Event ID 1 |
| MITRE ATT&CK | [T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197/) |
| Related technique | [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| Severity | Medium |
| Status | Implemented and validated |
| Alert type | Scheduled search |
| Schedule | Every five minutes |
| Search window | Last 10 minutes |

## Objective

Detect `bitsadmin.exe` process creation when its command line contains network-transfer arguments and an HTTP or HTTPS URL. BITS is a legitimate Windows transfer service, but adversaries can abuse BITS jobs for download, execution, persistence, and defense evasion.

## SPL

```spl
index=windows_endpoint host="SOC-ENDPOINT-01"
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest=-10m latest=now
"<EventID>1</EventID>"
| rex field=_raw "<EventRecordID>(?<record_id>\d+)</EventRecordID>"
| rex field=_raw "<Data Name='ProcessGuid'>(?<process_guid>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<process_path>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<command>[^<]+)</Data>"
| rex field=command "(?i)(?<url>https?://[^\s\"]+)"
| where match(lower(process_path),"bitsadmin\.exe$")
    AND match(lower(command),"(/transfer|/download|/addfile|/setnotifycmdline|/resume)")
    AND isnotnull(url)
| dedup host process_guid
| eval detection_name="Suspicious BITSAdmin Network Transfer"
| eval severity="medium"
| eval mitre_technique="T1197"
| table _time host User process_guid process_path command url detection_name severity mitre_technique
| sort - _time
```

## Safe validation

The validation transferred the public Example Domain page to a temporary HTML file:

```powershell
bitsadmin.exe /transfer DE003FINAL /download /priority normal "https://example.com/" "$env:TEMP\de003-final.html"
```

No executable content was downloaded or launched.

## Validation result

| Field | Value |
|---|---|
| Event time | 2026-09-26 21:38:28.960 |
| Alert time | 2026-09-26 21:40:01 SE Asia Standard Time |
| Host | SOC-ENDPOINT-01 |
| User | SOC-ENDPOINT-01\naufal |
| Process | `C:\Windows\System32\bitsadmin.exe` |
| Process GUID | `{3f37587f-d8e4-6ab7-be01-000000001000}` |
| Job name | DE003FINAL |
| URL | `https://example.com/` |
| Destination | `C:\Users\naufal\AppData\Local\Temp\de003-final.html` |
| File size | 559 bytes |
| File SHA-256 | `FF67A9D764D6A2367A187734E697F6A53217DB9A21C101D410A113CA871A299D` |

## Triage guidance

1. Review the complete command, URL, destination, user, parent process, and Process GUID.
2. Determine whether the domain, job name, and destination are expected for the endpoint.
3. Calculate the downloaded file hash and inspect its type, signature, and reputation.
4. Look for `/setnotifycmdline`, execution of the downloaded file, persistence, or follow-on child processes.
5. Review related BITS Client Operational logs and Sysmon network or file events when available.
6. Escalate when the destination is executable, the domain is untrusted, or execution follows the transfer.

## Known false positives

- Authorized software deployment
- Enterprise update tools using BITS
- Administrator-managed file transfers
- Security testing and lab validation

Direct interactive use of `bitsadmin.exe` is less common than application-managed BITS transfers and deserves review.

## Tuning notes

- The detection requires both a transfer-related argument and an HTTP or HTTPS URL.
- Process GUID deduplication prevents duplicate indexed copies from producing multiple results.
- The search window is 10 minutes to tolerate ingestion delay.
- Alert throttling is set to 30 minutes.
- Raise severity when the command includes `/setnotifycmdline`, downloads an executable or script, uses an unknown domain, or is followed by process execution.

## Evidence

- [Detection search result](../screenshots/DE-003-bitsadmin-network-transfer/12-de-003-search-result.png)
- [Triggered alert](../screenshots/DE-003-bitsadmin-network-transfer/13-de-003-triggered-alert.png)
- [Downloaded file and SHA-256](../screenshots/DE-003-bitsadmin-network-transfer/14-de-003-downloaded-file-hash.png)
