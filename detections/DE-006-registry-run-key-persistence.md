# DE-006: Registry Run Key Persistence

## Metadata

| Field | Value |
|---|---|
| Detection ID | DE-006 |
| Data source | Sysmon Event ID 13 |
| MITRE ATT&CK | [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |
| Tactics | Persistence, Privilege Escalation |
| Severity | High |
| Status | Implemented, tuned, and validated |
| Alert type | Scheduled search |
| Schedule | Every five minutes, offset by one minute |
| Search window | Last 10 minutes |

## Objective

Detect values written to Windows `Run` and `RunOnce` registry keys. Programs referenced by these values execute when a user logs in, which makes the locations useful for legitimate startup software and for persistence.

## SPL

```spl
index=windows_endpoint host="SOC-ENDPOINT-01"
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest=-10m latest=now
"<EventID>13</EventID>"
| rex field=_raw "<EventRecordID>(?<record_id>\d+)</EventRecordID>"
| rex field=_raw "<Data Name='ProcessGuid'>(?<process_guid>[^<]+)</Data>"
| rex field=_raw "<Data Name='Image'>(?<process_path>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetObject'>(?<target_object>[^<]+)</Data>"
| rex field=_raw "<Data Name='Details'>(?<details>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<user>[^<]+)</Data>"
| where match(lower(target_object),"\\\\currentversion\\\\run(once)?\\\\")
    AND NOT match(lower(target_object),"\\\\run\\\\microsoftedgeautolaunch_")
| dedup host process_guid target_object
| eval detection_name="Registry Run Key Persistence"
| eval severity="high"
| eval mitre_technique="T1547.001"
| table _time host user process_path process_guid target_object details record_id detection_name severity mitre_technique
| sort - _time
```

## Safe validation

The validation created a current-user Run value with a harmless command:

```powershell
reg.exe ADD `
  "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" `
  /v "DE006-Final-Validation" `
  /t REG_SZ `
  /d "cmd.exe /c echo DE006_FINAL_VALIDATION > C:\Windows\Temp\de006-final-validation.txt" `
  /f
```

The endpoint was not logged out or restarted, so the configured action did not run. The value was deleted after validation.

## Validation result

| Field | Value |
|---|---|
| Event time | 2026-09-27 15:29:06.345 |
| Alert time | 2026-09-27 15:31:01 SE Asia Standard Time |
| Host | SOC-ENDPOINT-01 |
| User | SOC-ENDPOINT-01\naufal |
| Process | `C:\WINDOWS\system32\reg.exe` |
| Process GUID | `{3f37587f-d3d2-6ab8-6502-000000001200}` |
| Event Record ID | 8115 |
| Registry value | DE006-Final-Validation |
| Value data | `cmd.exe /c echo DE006_FINAL_VALIDATION > C:\Windows\Temp\de006-final-validation.txt` |

## False-positive tuning

The first version matched every observed Run-key write and classified Microsoft Edge AutoLaunch entries as high severity. Those entries used a value name beginning with `MicrosoftEdgeAutoLaunch_` and referenced the installed Edge binary under `Program Files (x86)`.

The final rule excludes that validated value-name pattern. This removes the observed noise while retaining visibility for other Run and RunOnce changes. The exclusion should be reviewed if the endpoint software baseline changes.

## Triage guidance

1. Review the registry hive, value name, value data, user, process path, and Process GUID.
2. Identify the binary or script that will execute at logon and verify its signature and hash.
3. Check whether the path is user-writable or points to a command interpreter.
4. Correlate the Process GUID with process, file, and network activity.
5. Compare the entry with the approved software and endpoint-management baseline.
6. Preserve evidence and remove unauthorized persistence during incident response.

## Known false positives

- Browser and application auto-start entries
- Authorized login scripts and productivity software
- Endpoint management and monitoring agents
- Software installers and updaters
- Security testing and lab validation

## Tuning notes

- Maintain narrow exclusions based on validated value name, signer, path, and deployment source.
- Raise priority for script interpreters, encoded commands, user-writable paths, or unknown binaries.
- Review exclusions periodically rather than suppressing the entire Run key.
- Process GUID and target-object deduplication limits duplicate indexed results.
- The alert runs at minutes `01, 06, 11`, and so on to reduce simultaneous scheduler load.

## Evidence

- [Detection search result](../screenshots/DE-006-registry-run-key-persistence/22-de-006-search-result.png)
- [Triggered alert](../screenshots/DE-006-registry-run-key-persistence/23-de-006-triggered-alert.png)
