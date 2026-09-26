# Lab Architecture

## Network and log flow

```mermaid
flowchart LR
    VM["Windows 11 VM<br/>SOC-ENDPOINT-01<br/>10.0.2.15"]
    UF["Splunk Universal Forwarder"]
    SE["Splunk Enterprise<br/>NAUFAL<br/>10.0.2.2"]
    IDX["windows_endpoint index"]
    DET["Searches and scheduled alerts"]

    VM -->|"Windows Event Logs and Sysmon"| UF
    UF -->|"TCP 9997"| SE
    SE --> IDX
    IDX --> DET
```

## Components

| System | Role | Main services |
|---|---|---|
| `SOC-ENDPOINT-01` | Monitored Windows endpoint | Sysmon and Splunk Universal Forwarder |
| `NAUFAL` | Splunk server and analyst workstation | Splunk Enterprise and Splunk Web |

## Ports

| Port | Direction | Purpose |
|---:|---|---|
| `9997/TCP` | Endpoint to Splunk server | Receives forwarded events |
| `8000/TCP` | Analyst browser to Splunk server | Splunk Web interface |
| `8089/TCP` | Local Splunk management | Splunk management service |

## Data flow validation

Use these checks when troubleshooting the pipeline:

1. Confirm the `SplunkForwarder` service is running on the endpoint.
2. Confirm `10.0.2.2:9997` appears under active forward destinations.
3. Confirm the Splunk server is listening on TCP port `9997`.
4. Search `index=windows_endpoint host="SOC-ENDPOINT-01"` in Splunk.
5. Compare the latest event time with the current endpoint time.

Replace this Mermaid diagram with a polished exported diagram later if needed.
