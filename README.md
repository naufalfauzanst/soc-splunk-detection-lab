# Windows SOC Detection Lab with Splunk and Sysmon

Home SOC lab for collecting Windows telemetry, writing Splunk detections, validating alerts, and documenting investigation results.

> **Project status:** In progress. The core log pipeline and four detections are working.

## Project overview

This project simulates a small SOC environment with one Windows endpoint and one Splunk server. The endpoint sends Windows Event Logs and Sysmon telemetry to Splunk through a Universal Forwarder. The collected data is used to build and test detection rules.

Current capabilities:

- Collect Windows Security, System, Application, PowerShell, Microsoft Defender, and Sysmon logs.
- Forward events from a Windows virtual machine to Splunk over TCP port `9997`.
- Search endpoint telemetry in the `windows_endpoint` index.
- Detect encoded PowerShell execution.
- Detect repeated failed Windows logons, suspicious BITSAdmin transfers, and local account creation.
- Correlate Sysmon process creation, PowerShell Script Block Logging, and Windows Security events.
- Create scheduled alerts and document investigation findings.

## Lab architecture

```text
Windows VM: SOC-ENDPOINT-01
  |  Windows Event Logs + Sysmon
  |  Splunk Universal Forwarder
  |  TCP 9997
  v
Splunk Enterprise: NAUFAL
  |  Index: windows_endpoint
  v
Searches, detections, alerts, and investigations
```

<!-- Add an architecture image later, for example: screenshots/lab-architecture.png -->

## Technology stack

| Component | Purpose |
|---|---|
| Oracle VirtualBox | Runs the isolated Windows endpoint |
| Windows 11 VM | Generates endpoint telemetry |
| Splunk Enterprise | Stores, searches, and analyzes events |
| Splunk Universal Forwarder | Sends endpoint logs to Splunk |
| Sysmon | Records detailed process and system activity |
| Splunk Add-on for Microsoft Sysmon | Parses and normalizes Sysmon fields |
| PowerShell | Generates safe validation activity |

<!-- Add exact product versions here after checking each installation. -->

## Data pipeline

1. Windows and Sysmon write events on `SOC-ENDPOINT-01`.
2. Splunk Universal Forwarder reads the configured event channels.
3. The forwarder sends events to the Splunk server at `10.0.2.2:9997`.
4. Splunk stores the events in the `windows_endpoint` index.
5. Detection searches evaluate the indexed events and create alerts when their conditions match.

## Collected data sources

| Data source | Important events | Detection value |
|---|---:|---|
| Windows Security | 4625, 4688 | Failed logons and process creation |
| PowerShell Operational | 4104 | Script Block Logging and command content |
| Sysmon Operational | 1 and other configured IDs | Process creation and endpoint behavior |
| Microsoft Defender Operational | Varies | Malware and protection activity |
| Windows System | Varies | Services, drivers, and operating system activity |
| Windows Application | Varies | Application errors and operational events |

## Universal Forwarder input

The endpoint uses the following Sysmon input. Other Windows Event Log channels are configured in the same `inputs.conf` file.

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
start_from = newest
current_only = 0
checkpointInterval = 5
renderXml = true
index = windows_endpoint
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
sourcetype = XmlWinEventLog
```

Do not publish passwords, tokens, license data, or other secrets from local configuration files.

## Detection coverage

| ID | Detection | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|
| DE-001 | Encoded PowerShell Execution | T1059.001 | High | Implemented and validated |
| DE-002 | Repeated Failed Windows Logons | T1110.001 | Medium | Implemented and validated |
| DE-003 | Suspicious BITSAdmin Network Transfer | T1197 | Medium | Implemented and validated |
| DE-004 | New Local User Account Created | T1136.001 | Medium | Implemented and validated |

## DE-001: Encoded PowerShell Execution

### Detection objective

Detect PowerShell processes launched with an encoded command argument. Attackers may use encoded commands to hide command content from basic inspection. Encoded PowerShell also has legitimate administrative uses, so every alert requires context and payload analysis.

### Detection query

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

### Safe validation

The following command creates a harmless Base64-encoded PowerShell payload and executes it inside the lab VM.

```powershell
$payload = 'Write-Output "SOC_ALERT_VALIDATION_001"'
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($payload)
)
powershell.exe -NoProfile -EncodedCommand $encoded
```

Decoded payload:

```powershell
Write-Output "SOC_ALERT_VALIDATION_001"
```

### Validation result

- Sysmon recorded the process as Event ID `1`.
- Splunk received the event in the `windows_endpoint` index.
- The scheduled alert `DE-001 Encoded PowerShell Execution` triggered successfully.
- PowerShell Event ID `4104` and Windows Security Event ID `4688` provided supporting context.
- The decoded command only printed a test string.
- Final disposition: **Benign Positive**, expected lab validation activity.

<!-- Add screenshots of the detection result, triggered alert, related events, and decoded payload here. -->

## Investigation workflow

The investigation for DE-001 follows these steps:

1. Confirm the affected host, user, process path, command line, parent process, and timestamp.
2. Extract and decode the Base64 payload using UTF-16LE, which is the encoding expected by Windows PowerShell `-EncodedCommand`.
3. Correlate the Sysmon process event with PowerShell Event ID `4104` and Security Event ID `4688`.
4. Review the parent-child process chain and file hashes.
5. Determine whether the action was authorized and whether the payload caused harmful changes.
6. Record the verdict and supporting evidence.

## Investigation record

| Field | Value |
|---|---|
| Investigation ID | IR-001 |
| Alert | DE-001 Encoded PowerShell Execution |
| Host | SOC-ENDPOINT-01 |
| Technique | T1059.001 PowerShell |
| Verdict | Benign Positive |
| Reason | Authorized validation command with no harmful action |
| Evidence | Sysmon 1, PowerShell 4104, Security 4688, decoded payload |

## Evidence

- [x] [Lab architecture](screenshots/lab-setup/01-lab-architecture.png)
- [x] [Forwarder connection and active destination](screenshots/lab-setup/02-forwarder-active.png)
- [x] [Sysmon events received by Splunk](screenshots/lab-setup/03-sysmon-events.png)
- [x] [DE-001 search result](screenshots/DE-001-encoded-powershell/04-de-001-search-result.png)
- [x] [Triggered alert](screenshots/DE-001-encoded-powershell/05-de-001-triggered-alert.png)
- [x] [Correlated Sysmon 1, PowerShell 4104, and Security 4688 events](screenshots/DE-001-encoded-powershell/06-event-correlation.png)
- [x] [Decoded Base64 payload](screenshots/DE-001-encoded-powershell/07-decoded-payload.png)
- [x] [Final investigation verdict](screenshots/DE-001-encoded-powershell/08-investigation-verdict.png)
- [x] [DE-002 search result](screenshots/DE-002-repeated-failed-logons/09-de-002-search-result.png)
- [x] [DE-002 triggered alert](screenshots/DE-002-repeated-failed-logons/10-de-002-triggered-alert.png)
- [x] [DE-002 investigation verdict](screenshots/DE-002-repeated-failed-logons/11-de-002-investigation-verdict.png)
- [x] [DE-003 search result](screenshots/DE-003-bitsadmin-network-transfer/12-de-003-search-result.png)
- [x] [DE-003 triggered alert](screenshots/DE-003-bitsadmin-network-transfer/13-de-003-triggered-alert.png)
- [x] [DE-003 downloaded file and SHA-256](screenshots/DE-003-bitsadmin-network-transfer/14-de-003-downloaded-file-hash.png)
- [x] [DE-003 investigation verdict](screenshots/DE-003-bitsadmin-network-transfer/15-de-003-investigation-verdict.png)
- [x] [DE-004 search result](screenshots/DE-004-new-local-user-account/16-de-004-search-result.png)
- [x] [DE-004 triggered alert](screenshots/DE-004-new-local-user-account/17-de-004-triggered-alert.png)

## Skills demonstrated

- Windows endpoint telemetry collection
- Splunk Universal Forwarder configuration
- Sysmon deployment and event analysis
- SPL search and detection engineering
- MITRE ATT&CK mapping
- Alert validation and tuning
- Process tree and command-line analysis
- Multi-source event correlation
- SOC investigation documentation

## Roadmap

- [x] Build a Windows endpoint VM.
- [x] Forward Windows logs to Splunk.
- [x] Install and collect Sysmon telemetry.
- [x] Implement and validate encoded PowerShell detection.
- [x] Create a scheduled Splunk alert.
- [x] Document the first investigation and verdict.
- [x] Add sanitized screenshots and an architecture diagram.
- [ ] Export and document the complete forwarder configuration.
- [x] Add repeated failed-logon detection.
- [x] Add a suspicious LOLBin detection.
- [x] Add a local account creation detection.
- [ ] Add alert tuning notes and known false positives.
- [ ] Add response recommendations for every detection.

## Repository structure

```text
soc-splunk-detection-lab/
├── README.md
├── architecture/
├── configs/
├── detections/
├── investigations/
└── screenshots/
    ├── lab-setup/
    ├── DE-001-encoded-powershell/
    ├── DE-002-repeated-failed-logons/
    ├── DE-003-bitsadmin-network-transfer/
    └── DE-004-new-local-user-account/
```

## Project files

- [Architecture and network flow](architecture/README.md)
- [Sanitized Splunk configuration examples](configs/README.md)
- [DE-001 detection documentation](detections/DE-001-encoded-powershell.md)
- [IR-001 investigation report](investigations/IR-001-encoded-powershell.md)
- [DE-002 detection documentation](detections/DE-002-repeated-failed-logons.md)
- [IR-002 investigation report](investigations/IR-002-repeated-failed-logons.md)
- [DE-003 detection documentation](detections/DE-003-bitsadmin-network-transfer.md)
- [IR-003 investigation report](investigations/IR-003-bitsadmin-network-transfer.md)
- [DE-004 detection documentation](detections/DE-004-new-local-user-account.md)
- [IR-004 investigation report](investigations/IR-004-new-local-user-account.md)
- [Screenshot naming and sanitization guide](screenshots/README.md)

## Disclaimer

This repository documents a personal training environment. Validation commands are designed for an isolated lab. Do not run untrusted commands or expose sensitive event data, credentials, public IP addresses, or personal information in screenshots.

## Author

**Naufal Fauzan**

<!-- Add LinkedIn, email, portfolio website, and relevant certifications here. -->
