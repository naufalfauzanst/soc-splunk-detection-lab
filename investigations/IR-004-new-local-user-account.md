# IR-004: New Local User Account Created

## Case summary

| Field | Value |
|---|---|
| Investigation ID | IR-004 |
| Alert | DE-004 New Local User Account Created |
| Endpoint | SOC-ENDPOINT-01 |
| Created by | naufal |
| New account | soc_de004_alert |
| Severity | Medium |
| MITRE ATT&CK | T1136.001 Create Account: Local Account |
| Event timestamp | 2026-09-26 22:24:35.248 |
| Alert timestamp | 2026-09-26 22:30:01 SE Asia Standard Time |
| Disposition | Benign Positive |
| Status | Closed |

## Alert context

Splunk detected Windows Security Event ID 4720 when the local account `soc_de004_alert` was created on `SOC-ENDPOINT-01`. The event identified `naufal` as the account creator and supplied Event Record ID `45826` for correlation and deduplication.

## Account details

| Field | Value |
|---|---|
| Target user | soc_de004_alert |
| SAM account name | soc_de004_alert |
| Target domain | SOC-ENDPOINT-01 |
| Created by | naufal |
| Event ID | 4720 |
| Event Record ID | 45826 |

## Evidence reviewed

| Evidence | Finding |
|---|---|
| Windows Security Event ID 4720 | Confirmed creation of the local account |
| Account creator | Matched the authorized lab administrator |
| Account name and description | Matched the planned DE-004 validation activity |
| Scheduled alert | Triggered successfully using the 10-minute search window |
| Endpoint cleanup | Both DE-004 test accounts were removed after validation |

## Analysis

The account was created manually as an authorized validation exercise. Its name, description, creator, endpoint, and creation time matched the test plan. No unauthorized use was identified, and the temporary accounts were removed after the alert fired.

## Verdict

**Benign Positive.** The detection correctly identified local account creation, but the activity was authorized and limited to the lab validation procedure.

## Response taken

- Verified the Security Event ID, Event Record ID, creator, target account, and endpoint.
- Confirmed that the account matched the planned validation activity.
- Confirmed that the scheduled alert produced the expected result.
- Removed `soc_de004_test` and `soc_de004_alert` after testing.
- Closed the case without containment or escalation.

## Evidence

- [Detection result](../screenshots/DE-004-new-local-user-account/16-de-004-search-result.png)
- [Triggered alert](../screenshots/DE-004-new-local-user-account/17-de-004-triggered-alert.png)
- [Investigation verdict](../screenshots/DE-004-new-local-user-account/18-de-004-investigation-verdict.png)

## Analyst conclusion

No malicious activity was identified. In a production environment, an unexpected local account should be escalated when its creator or purpose cannot be verified, it receives privileged group membership, or it begins authenticating shortly after creation.
