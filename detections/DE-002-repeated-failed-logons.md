# DE-002: Repeated Failed Windows Logons

## Metadata

| Field | Value |
|---|---|
| Detection ID | DE-002 |
| Data source | Windows Security Event ID 4625 |
| MITRE ATT&CK | T1110.001 Password Guessing |
| Severity | Medium |
| Status | Implemented and validated |
| Alert type | Scheduled search |
| Schedule | Every five minutes |
| Search window | Last 10 minutes |
| Detection window | Five-minute rolling window |
| Threshold | Five unique failed logons |

## Objective

Detect five or more failed Windows logons for the same host, target account, and source address within a rolling five-minute window. The search deduplicates `EventRecordID` before counting because duplicate indexed copies of the same Windows event must not increase the threshold.

## SPL

```spl
index=windows_endpoint host="SOC-ENDPOINT-01"
source="WinEventLog:Security"
earliest=-10m latest=now
"<EventID>4625</EventID>"
| rex field=_raw "<EventRecordID>(?<record_id>\d+)</EventRecordID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<target_user>[^<]+)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<source_ip>[^<]+)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<logon_type>\d+)</Data>"
| rex field=_raw "<Data Name='SubStatus'>(?<sub_status>[^<]+)</Data>"
| dedup host record_id
| sort 0 _time
| streamstats time_window=5m count AS failed_logons earliest(_time) AS first_failure latest(_time) AS last_failure by host target_user source_ip
| where failed_logons>=5
| eval detection_name="Repeated Failed Windows Logons"
| eval severity="medium"
| eval mitre_technique="T1110.001"
| eval failure_detail=case(
    sub_status="0xc0000064","Account does not exist",
    sub_status="0xc000006a","Incorrect password",
    true(),"Other authentication failure"
)
| dedup host target_user source_ip
| convert ctime(first_failure) ctime(last_failure)
| table first_failure last_failure host target_user source_ip logon_type failed_logons failure_detail detection_name severity mitre_technique
```

## Safe validation

The validation used a nonexistent account so no real account was at risk of lockout:

```powershell
runas /user:SOC-ENDPOINT-01\soc_test_de002 cmd.exe
```

The command was run five times with an intentionally incorrect password.

## Validation result

| Field | Value |
|---|---|
| First failure | 2026-09-26 20:43:16.141 |
| Last failure | 2026-09-26 20:43:21.111 |
| Host | SOC-ENDPOINT-01 |
| Target user | soc_test_de002 |
| Source IP | `::1` |
| Logon type | 2, Interactive |
| Unique failures | 5 |
| Failure detail | Account does not exist |
| Alert time | 2026-09-26 20:45:00 SE Asia Standard Time |

## Triage guidance

1. Confirm whether the target account exists and whether it is privileged.
2. Review the source address, workstation, logon type, authentication package, status, and substatus.
3. Verify that counted events have unique Event Record IDs.
4. Search for a successful logon, Event ID 4624, from the same source and account after the failures.
5. Review activity from the source endpoint for additional targeted accounts.
6. Escalate if failures involve real users, remote addresses, privileged accounts, multiple accounts, or a subsequent successful logon.

## Known false positives

- Users entering an outdated password
- Stale service or scheduled-task credentials
- Mapped drives using old credentials
- Security testing and authorized password audits
- Lab validation commands

## Tuning notes

- The scheduled search examines 10 minutes of data to tolerate ingestion delay and schedule boundaries.
- `streamstats time_window=5m` enforces the actual detection window.
- Deduplication by host and Event Record ID prevents duplicate ingestion from creating a false threshold match.
- Alert throttling is set to 10 minutes to reduce repeated notifications for the same activity.

## Evidence

- [Detection search result](../screenshots/DE-002-repeated-failed-logons/09-de-002-search-result.png)
- [Triggered alert](../screenshots/DE-002-repeated-failed-logons/10-de-002-triggered-alert.png)
