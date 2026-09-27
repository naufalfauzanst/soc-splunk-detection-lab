# IR-005: Suspicious Scheduled Task Creation

## Case summary

| Field | Value |
|---|---|
| Investigation ID | IR-005 |
| Alert | DE-005 Suspicious Scheduled Task Creation |
| Endpoint | SOC-ENDPOINT-01 |
| User | SOC-ENDPOINT-01\naufal |
| Severity | High |
| MITRE ATT&CK | T1053.005 Scheduled Task |
| Event timestamp | 2026-09-27 10:32:11.614 |
| Alert timestamp | 2026-09-27 10:35:01 SE Asia Standard Time |
| Disposition | True Positive - Authorized Attack Simulation |
| Status | Closed |

## Alert context

Splunk detected `schtasks.exe` creating the `DE005-Final-Validation` task with an `ONLOGON` trigger. The configured action used `cmd.exe` to write a harmless marker string to a text file.

## Process and task details

| Field | Value |
|---|---|
| Parent process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process image | `C:\Windows\System32\schtasks.exe` |
| Process GUID | `{3f37587f-8e3b-6ab8-0002-000000001100}` |
| Event Record ID | 5611 |
| Task name | DE005-Final-Validation |
| Trigger | ONLOGON |
| Action | Write `DE005_FINAL_VALIDATION` to a temporary text file |

## Evidence reviewed

| Evidence | Finding |
|---|---|
| Sysmon Event ID 1 | Recorded `schtasks.exe`, the parent process, user, Process GUID, and complete command line |
| Command line | Contained `/Create`, the task name, an `ONLOGON` trigger, and the harmless action |
| Scheduled alert | Triggered after the corrected 10-minute search window was applied |
| Task state | The task was not executed because no logout or restart occurred |
| Endpoint cleanup | The validation task was deleted after the alert fired |

## Analysis

The observed activity matched a common scheduled-task persistence pattern: `schtasks.exe` created a task that would run a command at user logon. The activity was intentionally generated in the isolated lab to validate detection coverage. Although the payload was harmless and the test was authorized, the simulated persistence behavior occurred and the rule correctly detected it.

The initial saved search used an all-time range and returned an older validation event. The alert was corrected to `earliest=-10m latest=now`, and a new final task was created. The final alert returned only the recent `DE005-Final-Validation` event.

## Verdict

**True Positive - Authorized Attack Simulation.** The scheduled-task persistence behavior occurred and was detected as designed. The action was authorized, contained, harmless, and removed after validation.

## Response taken

- Verified the process path, command line, parent process, user, Process GUID, and task trigger.
- Confirmed that the task and action matched the validation plan.
- Corrected the alert search window and repeated the validation.
- Confirmed that the task action did not execute.
- Deleted `DE005-Final-Validation` from Task Scheduler.
- Closed the case without further containment.

## Evidence

- [Detection result](../screenshots/DE-005-scheduled-task-creation/19-de-005-search-result.png)
- [Triggered alert](../screenshots/DE-005-scheduled-task-creation/20-de-005-triggered-alert.png)
- [Investigation verdict](../screenshots/DE-005-scheduled-task-creation/21-de-005-investigation-verdict.png)

## Analyst conclusion

No unauthorized activity was identified. In a production environment, an unexpected scheduled task should be escalated when it runs from a user-writable path, launches a script interpreter, uses encoded content, executes as SYSTEM, or cannot be tied to approved administration or software.
