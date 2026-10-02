"""Read lab Gmail messages and send selected, sanitized metadata to Splunk."""

import argparse
import base64
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


class HECError(RuntimeError):
    """A diagnostic containing only status and standard HEC codes."""


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def gmail_service():
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    token_path = PRIVATE / "gmail-token.json"
    credentials = None
    if token_path.exists():
        credentials = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if credentials and credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
    if not credentials or not credentials.valid:
        client_path = PRIVATE / "gmail-client-secret.json"
        if not client_path.exists():
            raise RuntimeError("Place gmail-client-secret.json in the private folder first.")
        flow = InstalledAppFlow.from_client_secrets_file(str(client_path), SCOPES)
        credentials = flow.run_local_server(port=0)
    save_json(token_path, json.loads(credentials.to_json()))
    return build("gmail", "v1", credentials=credentials, cache_discovery=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact_addresses(value):
    return re.sub(r"[\w.!#$%&'*+/=?^`{|}~-]+@([\w.-]+)", r"redacted@\1", value)


def domain(value):
    from email.utils import parseaddr

    address = parseaddr(value)[1]
    return address.rsplit("@", 1)[-1].lower() if "@" in address else ""


def auth_result(header, method):
    match = re.search(r"\b" + method + r"\s*=\s*([a-z]+)", header, re.I)
    return match.group(1).lower() if match else "unknown"


def walk_parts(part):
    yield part
    for child in part.get("parts", []):
        yield from walk_parts(child)


def event_from_message(message):
    payload = message.get("payload", {})
    headers = {}
    for item in payload.get("headers", []):
        headers.setdefault(item["name"].lower(), []).append(item["value"])
    get = lambda name: headers.get(name, [""])[0]
    # Only use the receiving Gmail service's result, not ARC or arbitrary headers.
    receiver_auth = next(
        (value for value in headers.get("authentication-results", [])
         if re.match(r"^\s*mx\.google\.com\s*;", value, re.I)), ""
    )
    filenames = []
    url_domains = set()
    for part in walk_parts(payload):
        filename = part.get("filename", "")
        if filename:
            filenames.append(redact_addresses(filename))
            continue
        data = part.get("body", {}).get("data")
        if data and part.get("mimeType") in {"text/plain", "text/html"}:
            body = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode(
                "utf-8", errors="replace"
            )
            for url in re.findall(r"(?:https?|hxxps?)://[^\s<>\"']+", body, re.I):
                normalized = re.sub(r"^hxxp", "http", url, flags=re.I).replace("[.]", ".")
                hostname = urlsplit(normalized).hostname
                if hostname:
                    url_domains.add(hostname.lower())
    message_id = get("message-id") or message["id"]
    return {
        "gmail_id_hash": digest(message["id"]),
        "message_id_hash": digest(message_id),
        "subject": redact_addresses(get("subject")),
        "sender_domain": domain(get("from")),
        "recipient_domain": domain(get("to")),
        "reply_to_domain": domain(get("reply-to")),
        "return_path_domain": domain(get("return-path")),
        "spf": auth_result(receiver_auth, "spf"),
        "dkim": auth_result(receiver_auth, "dkim"),
        "dmarc": auth_result(receiver_auth, "dmarc"),
        "authentication_source": "mx.google.com" if receiver_auth else "unknown",
        "attachment_names": filenames,
        "attachment_count": len(filenames),
        "double_extension": any(
            re.search(r"\.(pdf|docx?|xlsx?|txt)\.(html?|exe|js|vbs|scr|lnk)$", name, re.I)
            for name in filenames
        ),
        "url_domains": sorted(url_domains),
        "labels": message.get("labelIds", []),
        "collector": "gmail-lab-collector",
        "collection_time": time.time(),
    }


def send_hec(message, event):
    import requests

    token = os.environ.get("SPLUNK_HEC_TOKEN")
    if not token:
        raise RuntimeError("Set SPLUNK_HEC_TOKEN locally before sending events.")
    url = os.environ.get("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
    if urlsplit(url).scheme != "https":
        raise RuntimeError("SPLUNK_HEC_URL must use HTTPS.")
    response = requests.post(
        url,
        headers={"Authorization": "Splunk " + token},
        json={
            "time": int(message["internalDate"]) / 1000,
            "host": "gmail-lab",
            "source": "gmail:api",
            "sourcetype": "gmail:lab:json",
            "index": "email_security",
            "event": event,
        },
        timeout=30,
        verify=os.environ.get("SPLUNK_HEC_CA_FILE") or True,
    )
    try:
        code = response.json().get("code")
    except (ValueError, AttributeError):
        code = None
    if not response.ok or code != 0:
        reasons = {
            1: "Token disabled", 2: "Token required", 3: "Invalid authorization",
            4: "Invalid token", 5: "No data", 6: "Invalid event format",
            7: "Invalid index", 8: "Internal server error", 9: "Server busy",
            10: "Data channel missing", 11: "Invalid data channel",
            12: "Event field required", 13: "Event field empty", 14: "ACK disabled",
        }
        safe_code = code if type(code) is int else "unknown"
        reason = reasons.get(safe_code, "Unrecognized HEC response")
        raise HECError(f"HEC HTTP {response.status_code}, code {safe_code}: {reason}")


def collect(service, query, dry_run):
    state_path = PRIVATE / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    seen = set(state.get("sent_ids", []))
    page_token = None
    processed = 0
    while True:
        listing = service.users().messages().list(
            userId="me", q=query, includeSpamTrash=True,
            maxResults=100, pageToken=page_token,
        ).execute()
        for item in listing.get("messages", []):
            identity = digest(item["id"])
            if identity in seen and not dry_run:
                continue
            message = service.users().messages().get(
                userId="me", id=item["id"], format="full"
            ).execute()
            event = event_from_message(message)
            if dry_run:
                print(json.dumps(event, ensure_ascii=True))
            else:
                send_hec(message, event)
                seen.add(identity)
                save_json(state_path, {"sent_ids": sorted(seen)})
            processed += 1
        page_token = listing.get("nextPageToken")
        if not page_token:
            break
    print(f"{'Previewed' if dry_run else 'Accepted by HEC'}: {processed} message(s).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize", action="store_true", help="Authorize Gmail only.")
    parser.add_argument("--dry-run", action="store_true", help="Preview metadata without sending.")
    parser.add_argument("--once", action="store_true", help="Perform one collection cycle.")
    parser.add_argument("--query", default='subject:"[SOC LAB]" newer_than:7d')
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    if args.interval < 10:
        parser.error("--interval must be at least 10 seconds")
    logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)
    try:
        service = gmail_service()
        if args.authorize:
            print("Gmail authorization completed. No email events sent.")
            return
        while True:
            collect(service, args.query, args.dry_run)
            if args.once or args.dry_run:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Collector stopped.")
    except HECError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        # Exception bodies can contain addresses or tokens; print the class only.
        print(f"Collector failed ({type(error).__name__}). Check local credentials, permissions, HEC settings, and TLS trust.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
