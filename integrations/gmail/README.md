# Gmail lab collector

Status: live Gmail authorization, HTTPS HEC ingestion, and DE-007 scheduled alert validated on 2026-10-02. The collector was run manually using `--once`; continuous operation was not validated.

This collector reads lab messages from an analyst-owned Gmail mailbox and sends selected metadata to Splunk's `email_security` index. Gmail access uses the read-only OAuth scope. Keep the Google application in Testing and add the analyst account as a test user.

## Local setup

Run from this directory on the host computer:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
New-Item -ItemType Directory -Force private
```

Place the downloaded desktop OAuth credentials at `private/gmail-client-secret.json`. Never publish this folder. It also stores the OAuth refresh token and successful-delivery state.

Authorize the analyst account, then preview events:

```powershell
.\.venv\Scripts\python.exe collector.py --authorize
.\.venv\Scripts\python.exe collector.py --dry-run
```

The default Gmail query selects subjects containing `[SOC LAB]` in the last seven days, including spam and trash. Keep this tag on all simulation emails. Read-only OAuth permission technically covers the mailbox; the query limits what this program collects.

## Splunk connection

Local TLS setup scripts are provided as `prepare_hec_tls.py` and `install_hec_tls.ps1`. The preparation script generates a localhost certificate, private key, and local CA under the ignored `private/hec-tls` folder. Installation requires Administrator privileges, backs up the existing HEC configuration, and restarts Splunkd. Review the script before use. Do not publish private keys or installation settings. This setup applies to a local Windows Splunk installation at `C:\Program Files\Splunk`; the certificate is valid for localhost and loopback addresses only.

In the validated setup, set `SPLUNK_HEC_CA_FILE` to `private/hec-tls/hec-ca.pem` using an absolute path. The token is entered locally through a credential prompt. HEC status codes are reported without displaying tokens; code 4 means invalid token, and code 7 means invalid index.

HEC must accept index `email_security`. Use JSON sourcetype `gmail:lab:json`; configure JSON search-time extraction if Splunk does not automatically extract its fields. The collector supplies this sourcetype in each request.

Set `SPLUNK_HEC_TOKEN` in the local process environment without putting it in scripts or screenshots. The default URL is `https://localhost:8088/services/collector/event`; override it through `SPLUNK_HEC_URL` if needed. TLS verification is enabled. For a private certificate, set `SPLUNK_HEC_CA_FILE` to the trusted PEM certificate chain and use a URL whose hostname matches the certificate. Do not disable verification.

After authorization and TLS setup:

```powershell
.\.venv\Scripts\python.exe collector.py --once
```

Omit `--once` to poll every 60 seconds. The program runs only while its process is active.

## Event content and privacy

Events include subject, address domains, authentication results from `mx.google.com`, MIME attachment names, URL hostnames, Gmail labels, and hashed message identifiers. Subjects and filenames have email addresses masked. Email bodies, raw headers, full addresses, URL paths, query strings, attachment contents, and OAuth tokens are not sent to Splunk.

Treat subjects and filenames as potentially sensitive even with address masking; use a dedicated lab mailbox and inspect `--dry-run` before live ingestion.

## Delivery behavior

An identifier is saved after HEC reports success. Failed requests do not advance the state. A crash after HEC accepts an event but before the local state is saved can cause a duplicate on retry. Deduplicate searches by `gmail_id_hash` where necessary. A HEC success response must be followed by an indexed search to validate the complete pipeline.

No scheduled service is installed by this repository. Testing-mode OAuth tokens may require reauthorization. Nothing is sent, modified, or deleted through Gmail.
