# Configuration Files

This directory contains sanitized examples from the lab. Review paths, addresses, indexes, and channel names before reusing them.

## Files

- `inputs.conf.example`: Windows Event Log channels collected by the Universal Forwarder.
- `outputs.conf.example`: Destination used by the Universal Forwarder.

The real Splunk configuration may contain credentials or deployment-specific values. Only sanitized copies belong in this repository.

## Source locations on the endpoint

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf
```

After changing a configuration, validate the effective settings with `btool` and restart the `SplunkForwarder` service from an elevated PowerShell session.
