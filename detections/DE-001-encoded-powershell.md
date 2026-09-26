# DE-001: Encoded PowerShell Execution

## Metadata

| Field | Value |
|---|---|
| Detection ID | DE-001 |
| Data source | Sysmon Event ID 1 |
| MITRE ATT&CK | T1059.001 PowerShell |
| Severity | High |
| Status | Implemented and validated |
| Alert type | Scheduled search |
| Search window | Last 5 minutes |

## Objective

Detect PowerShell process creation containing an encoded command argument. The rule extracts the Base64 value into `encoded_payload` so the analyst can decode and review it.

Encoded commands are suspicious but are not proof of compromise. Administrators and legitimate software can also use this option.

## SPL

```spl
index=windows_endpoint
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
sourcetype="XmlWinEventLog"
EventCode=1
earliest=-5m latest=now
| eval command=coalesce(CommandLine, process_command_line)
| eval process_path=coalesce(Image, process, process_path)
| eval parent=coalesce(ParentImage, parent_process_path, parent_process_name)
| rex field=command "(?i)(?:^|\s)-(?:e|en|enc|enco|encodedcommand)\s+(?<encoded_payload>[A-Za-z0-9+/=]+)"
| where isnotnull(encoded_payload)
| eval payload_length=len(encoded_payload)
| eval detection_name="Encoded PowerShell Execution"
| eval severity="high"
| eval mitre_technique="T1059.001"
| table _time host User parent process_path command encoded_payload payload_length Hashes detection_name severity mitre_technique
| sort - _time
```

## Safe validation

Run only inside the lab VM:

```powershell
$payload = 'Write-Output "SOC_ALERT_VALIDATION_001"'
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($payload)
)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Expected decoded content:

```powershell
Write-Output "SOC_ALERT_VALIDATION_001"
```

## Triage fields

- Host and user
- Process path and parent process
- Complete command line
- Decoded payload
- File hash
- Related PowerShell Event ID 4104
- Related Security Event ID 4688
- Activity before and after execution

## Known false positives

- Authorized administration scripts
- Software deployment tools
- Security products and management agents
- Lab validation commands

## Tuning ideas

- Allowlist a known script only after validating its signer, path, parent process, user, and expected payload.
- Increase severity when the parent process is an Office application, browser, archive utility, or unusual service.
- Increase severity when the decoded content includes download, execution, persistence, credential access, or security-control bypass behavior.
- Keep the original command and decoded payload as investigation evidence.

## Validation result

The rule detected the test command and triggered the scheduled alert. Correlated telemetry was available from Sysmon Event ID 1, PowerShell Event ID 4104, and Security Event ID 4688. The test was classified as a Benign Positive because the command only printed a validation string.
