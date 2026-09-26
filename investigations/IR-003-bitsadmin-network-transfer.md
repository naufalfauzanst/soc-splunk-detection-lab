# IR-003: Suspicious BITSAdmin Network Transfer

## Case summary

| Field | Value |
|---|---|
| Investigation ID | IR-003 |
| Alert | DE-003 Suspicious BITSAdmin Network Transfer |
| Endpoint | SOC-ENDPOINT-01 |
| User | SOC-ENDPOINT-01\naufal |
| Severity | Medium |
| MITRE ATT&CK | T1197 BITS Jobs |
| Event timestamp | 2026-09-26 21:38:28.960 |
| Alert timestamp | 2026-09-26 21:40:01 SE Asia Standard Time |
| Disposition | Benign Positive |
| Status | Closed |

## Alert context

Splunk detected `bitsadmin.exe` using `/transfer` and `/download` with an HTTPS URL. The command created a BITS job named `DE003FINAL` and transferred a file into the user's temporary directory.

## Process and file details

| Field | Value |
|---|---|
| Process image | `C:\Windows\System32\bitsadmin.exe` |
| Process GUID | `{3f37587f-d8e4-6ab7-be01-000000001000}` |
| Job name | `DE003FINAL` |
| Source URL | `https://example.com/` |
| Destination | `C:\Users\naufal\AppData\Local\Temp\de003-final.html` |
| File size | 559 bytes |
| SHA-256 | `FF67A9D764D6A2367A187734E697F6A53217DB9A21C101D410A113CA871A299D` |

## Evidence reviewed

| Evidence | Finding |
|---|---|
| Sysmon Event ID 1 | Recorded BITSAdmin process creation, user, command line, path, and Process GUID |
| Command line | Contained `/transfer`, `/download`, an HTTPS URL, and a temporary destination |
| Downloaded file | Public Example Domain HTML, 559 bytes |
| File hash | SHA-256 collected for repeatable identification |
| Scheduled alert | Triggered successfully after the corrected 10-minute search window was applied |

## Analysis

The transfer was initiated manually as an authorized validation exercise. The source was the public `example.com` documentation domain. The downloaded object was a 559-byte HTML page, not an executable or script, and it was not launched. The observed user, command, job name, destination, timestamp, and hash all matched the planned test.

The first saved alert briefly used an all-time search and returned an older validation event. The alert was corrected to `earliest=-10m latest=now`, then validated again with the `DE003FINAL` job. The final alert only returned recent BITSAdmin transfers.

## Verdict

**Benign Positive.** The rule detected the intended BITSAdmin behavior, but the activity was authorized and the downloaded file was harmless.

## Response taken

- Reviewed the BITSAdmin command, URL, destination, user, and Process GUID.
- Confirmed that the source domain and file content matched the validation plan.
- Collected the destination file size and SHA-256.
- Confirmed that the file was not executed.
- Corrected the scheduled alert time range and repeated validation.
- Closed the case without containment.

## Evidence

- [Detection result](../screenshots/DE-003-bitsadmin-network-transfer/12-de-003-search-result.png)
- [Triggered alert](../screenshots/DE-003-bitsadmin-network-transfer/13-de-003-triggered-alert.png)
- [Downloaded file and SHA-256](../screenshots/DE-003-bitsadmin-network-transfer/14-de-003-downloaded-file-hash.png)

## Analyst conclusion

No malicious activity was identified. In a production environment, a BITS transfer should be escalated when it uses an untrusted domain, downloads an executable or script, creates a notification command, establishes persistence, or is followed by execution.
