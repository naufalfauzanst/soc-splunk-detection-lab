# IR-002: Repeated Failed Windows Logons

## Case summary

| Field | Value |
|---|---|
| Investigation ID | IR-002 |
| Alert | DE-002 Repeated Failed Windows Logons |
| Endpoint | SOC-ENDPOINT-01 |
| Target account | soc_test_de002 |
| Source IP | `::1`, IPv6 loopback |
| Severity | Medium |
| MITRE ATT&CK | T1110.001 Password Guessing |
| First failure | 2026-09-26 20:43:16.141 |
| Last failure | 2026-09-26 20:43:21.111 |
| Alert timestamp | 2026-09-26 20:45:00 SE Asia Standard Time |
| Disposition | Benign Positive |
| Status | Closed |

## Alert context

Splunk detected five unique Windows Security Event ID 4625 records for `soc_test_de002` within approximately five seconds. All events originated from the endpoint's IPv6 loopback address and used interactive Logon Type 2.

## Evidence reviewed

| Evidence | Finding |
|---|---|
| Event ID | 4625, failed logon |
| Unique event count | Five after deduplicating Event Record ID |
| Target user | `soc_test_de002` |
| Source address | `::1`, local IPv6 loopback |
| Logon type | 2, Interactive |
| Status | `0xc000006d`, logon failure |
| SubStatus | `0xc0000064`, account does not exist |
| Alert execution | Scheduled alert fired successfully |

## Analysis

The target account did not exist and the activity originated locally from `SOC-ENDPOINT-01`. The failed logons were generated with `runas` as an authorized validation exercise. There was no real user account to compromise or lock out. The event timing, source address, target name, and failure code matched the planned test.

The raw data contained duplicate indexed copies of some Windows events. The detection removed duplicates using the host and Event Record ID before applying the threshold, preventing a single failed login from being counted more than once.

## Verdict

**Benign Positive.** The detection and scheduled alert worked as designed. The activity was authorized and did not affect a real account.

## Response taken

- Confirmed the event count using unique Event Record IDs.
- Reviewed the source address, target account, logon type, status, and substatus.
- Confirmed that the target was a nonexistent validation account.
- Closed the case without containment or account reset.

## Evidence

- [Detection result](../screenshots/DE-002-repeated-failed-logons/09-de-002-search-result.png)
- [Triggered alert](../screenshots/DE-002-repeated-failed-logons/10-de-002-triggered-alert.png)

## Analyst conclusion

No malicious activity was identified. In a production environment, the same pattern would require escalation when it targets a real or privileged account, originates from a remote address, affects multiple accounts, or is followed by a successful logon.
