# DE-005: Suspicious Scheduled Task Creation

## Metadata

| Field | Value |
|---|---|
| Detection ID | DE-005 |
| Data source | Sysmon Event ID 1 |
| MITRE ATT&CK | [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Tactics | Execution, Persistence, Privilege Escalation |
| Severity | High |
| Status | Implemented and validated |
| Alert type | Scheduled search |
| Schedule | Every five minutes |
| Search window | Last 10 minutes |

## Objective

Detect `schtasks.exe` process creation when its command line contains `/Create`. Windows Task Scheduler is legitimate administration functionality, but an attacker can create a task to execute code at logon, startup, or another scheduled time.

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
| rex field=_raw "<Data Name='ParentImage'>(?<parent_process>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<user>[^<]+)</Data>"
| where match(lower(process_path),"schtasks\.exe$")
    AND match(lower(command),"/create")
| dedup host process_guid
| eval detection_name="Suspicious Scheduled Task Creation"
| eval severity="high"
| eval mitre_technique="T1053.005"
| table _time host user parent_process process_path command process_guid record_id detection_name severity mitre_technique
| sort - _time
```

## Safe validation

The validation created an `ONLOGON` task with a harmless action that would only write a marker string to a text file:

```powershell
schtasks.exe /Create `
  /TN "DE005-Final-Validation" `
  /TR "cmd.exe /c echo DE005_FINAL_VALIDATION > C:\Windows\Temp\de005-final-validation.txt" `
  /SC ONLOGON `
  /F
```

The endpoint was not logged out or restarted, so the action did not run. The task was deleted after validation.

## Validation result

| Field | Value |
|---|---|
| Event time | 2026-09-27 10:32:11.614 |
| Alert time | 2026-09-27 10:35:01 SE Asia Standard Time |
| Host | SOC-ENDPOINT-01 |
| User | SOC-ENDPOINT-01\naufal |
| Parent process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process | `C:\Windows\System32\schtasks.exe` |
| Process GUID | `{3f37587f-8e3b-6ab8-0002-000000001100}` |
| Event Record ID | 5611 |
| Task name | DE005-Final-Validation |
| Schedule | ONLOGON |

## Triage guidance

1. Review the task name, trigger, action, user, command line, and parent process.
2. Determine whether the task belongs to approved software or administration activity.
3. Inspect the executable, script, or command configured as the task action.
4. Look for tasks that run at logon or startup, execute from user-writable paths, or run as SYSTEM.
5. Correlate the Process GUID with related process, file, registry, and network events.
6. Disable and preserve suspicious tasks before removing them during incident response.

## Known false positives

- Authorized system administration
- Software installation and update tasks
- Endpoint management and monitoring agents
- Enterprise deployment tooling
- Security testing and lab validation

## Tuning notes

- Allowlist verified task names, management tools, parent processes, and signed software paths.
- Raise priority for encoded commands, script interpreters, user-writable paths, remote creation, or SYSTEM execution.
- The current rule detects direct `schtasks.exe /Create` activity. Tasks created through PowerShell cmdlets, WMI, COM, or direct registry changes require additional telemetry and rules.
- Process GUID deduplication prevents duplicate indexed events from producing repeated results.
- The 10-minute window accounts for observed ingestion delay in the lab.

## Evidence

- [Detection search result](../screenshots/DE-005-scheduled-task-creation/19-de-005-search-result.png)
- [Triggered alert](../screenshots/DE-005-scheduled-task-creation/20-de-005-triggered-alert.png)
- [Investigation verdict](../screenshots/DE-005-scheduled-task-creation/21-de-005-investigation-verdict.png)
