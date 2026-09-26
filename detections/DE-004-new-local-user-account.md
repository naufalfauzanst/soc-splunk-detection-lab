# DE-004: New Local User Account Created

## Metadata

| Field | Value |
|---|---|
| Detection ID | DE-004 |
| Data source | Windows Security Event ID 4720 |
| MITRE ATT&CK | [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) |
| Tactic | Persistence |
| Severity | Medium |
| Status | Implemented and validated |
| Alert type | Scheduled search |
| Schedule | Every five minutes |
| Search window | Last 10 minutes |

## Objective

Detect the creation of a local Windows account. New local accounts may provide persistent access to a compromised endpoint, but they can also result from authorized administration, software installation, or user provisioning.

## SPL

```spl
index=windows_endpoint host="SOC-ENDPOINT-01"
source="WinEventLog:Security"
earliest=-10m latest=now
"<EventID>4720</EventID>"
| rex field=_raw "<EventRecordID>(?<record_id>\d+)</EventRecordID>"
| rex field=_raw "<Data Name='SubjectUserName'>(?<created_by>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetUserName'>(?<target_user>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetDomainName'>(?<target_domain>[^<]+)</Data>"
| rex field=_raw "<Data Name='SamAccountName'>(?<sam_account>[^<]+)</Data>"
| dedup host record_id
| eval detection_name="New Local User Account Created"
| eval severity="medium"
| eval mitre_technique="T1136.001"
| table _time host created_by target_user target_domain sam_account record_id detection_name severity mitre_technique
| sort - _time
```

## Safe validation

The validation account was created with PowerShell while its password was entered through a secure prompt:

```powershell
$password = Read-Host "Enter validation account password" -AsSecureString
New-LocalUser `
  -Name "soc_de004_alert" `
  -Password $password `
  -Description "DE-004 alert validation account"
```

The account was removed after the alert was validated.

## Validation result

| Field | Value |
|---|---|
| Event time | 2026-09-26 22:24:35.248 |
| Alert time | 2026-09-26 22:30:01 SE Asia Standard Time |
| Host | SOC-ENDPOINT-01 |
| Created by | naufal |
| New account | soc_de004_alert |
| Target domain | SOC-ENDPOINT-01 |
| Event Record ID | 45826 |

## Triage guidance

1. Confirm who created the account and whether the change was authorized.
2. Review the account name, description, creation time, endpoint, and target domain.
3. Check whether the account was added to privileged local groups.
4. Look for interactive or remote logons performed with the new account.
5. Review nearby process creation events to identify the tool used to create it.
6. Disable the account and escalate when its purpose or owner cannot be verified.

## Known false positives

- Authorized administrator activity
- Employee onboarding or support workflows
- Application or service account provisioning
- Automated endpoint management
- Security testing and lab validation

## Tuning notes

- Maintain an allowlist for approved provisioning systems and service-account naming conventions.
- Raise severity if the account is added to the local Administrators group or begins authenticating shortly after creation.
- Process events near the account creation time can distinguish interactive administration from automated provisioning.
- Event Record ID deduplication prevents duplicate indexed copies from creating repeated results.
- The 10-minute search window allows for observed ingestion delay in the lab.

## Evidence

- [Detection search result](../screenshots/DE-004-new-local-user-account/16-de-004-search-result.png)
- [Triggered alert](../screenshots/DE-004-new-local-user-account/17-de-004-triggered-alert.png)
- [Investigation verdict](../screenshots/DE-004-new-local-user-account/18-de-004-investigation-verdict.png)
