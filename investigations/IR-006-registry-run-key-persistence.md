# IR-006: Registry Run Key Persistence

## Case summary

| Field | Value |
|---|---|
| Investigation ID | IR-006 |
| Alert | DE-006 Registry Run Key Persistence |
| Endpoint | SOC-ENDPOINT-01 |
| User | SOC-ENDPOINT-01\naufal |
| Severity | High |
| MITRE ATT&CK | T1547.001 Registry Run Keys / Startup Folder |
| Event timestamp | 2026-09-27 15:29:06.345 |
| Alert timestamp | 2026-09-27 15:31:01 SE Asia Standard Time |
| Disposition | True Positive - Authorized Attack Simulation |
| Status | Closed |

## Alert context

Splunk detected `reg.exe` writing `DE006-Final-Validation` under the current user's Windows Run key. The configured command would write a harmless marker string to a text file when the user next logged in.

## Registry details

| Field | Value |
|---|---|
| Process image | `C:\WINDOWS\system32\reg.exe` |
| Process GUID | `{3f37587f-d3d2-6ab8-6502-000000001200}` |
| Event Record ID | 8115 |
| Target value | `HKU\...\Software\Microsoft\Windows\CurrentVersion\Run\DE006-Final-Validation` |
| Value data | `cmd.exe /c echo DE006_FINAL_VALIDATION > C:\Windows\Temp\de006-final-validation.txt` |

## Evidence reviewed

| Evidence | Finding |
|---|---|
| Sysmon Event ID 13 | Recorded the registry value write, process, user, target, data, and Process GUID |
| Registry location | Matched a Run key that executes values at user logon |
| Configured action | Contained only a harmless text-file marker command |
| Scheduled alert | Triggered using the tuned 10-minute search window |
| Endpoint cleanup | The test value was deleted and a follow-up query confirmed it no longer existed |

## Analysis

The registry write created a working logon-persistence mechanism. The activity was intentionally generated in the isolated lab, the value data was harmless, and no logout or restart occurred. The behavior therefore took place and was detected as designed, while remaining controlled and authorized.

The first broad search also identified Microsoft Edge AutoLaunch values. These were confirmed as expected application behavior and excluded through a narrow value-name pattern before the alert was saved. This tuning reduced observed noise without suppressing unrelated Run-key changes.

## Verdict

**True Positive - Authorized Attack Simulation.** The Run-key persistence behavior occurred and was detected. The activity was authorized, the command was harmless, and the registry value was removed after validation.

## Response taken

- Verified the process path, user, Process GUID, registry target, and value data.
- Reviewed and tuned the Microsoft Edge AutoLaunch false positive.
- Confirmed that the scheduled alert returned the final validation event.
- Confirmed that the Run-key action did not execute.
- Deleted `DE006-Final-Validation` and verified its removal.
- Closed the case without further containment.

## Evidence

- [Detection result](../screenshots/DE-006-registry-run-key-persistence/22-de-006-search-result.png)
- [Triggered alert](../screenshots/DE-006-registry-run-key-persistence/23-de-006-triggered-alert.png)
- [Investigation verdict](../screenshots/DE-006-registry-run-key-persistence/24-de-006-investigation-verdict.png)

## Analyst conclusion

No unauthorized activity was identified. In production, an unexpected Run-key value should be escalated when its owner or deployment source cannot be verified, it points to a user-writable location, or it launches a script interpreter or unknown binary.
