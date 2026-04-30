"""Poll Google Workspace Alert Center for active security alerts.

GWS Alert Center surfaces high-fidelity native alerts (suspicious login,
mass email send, policy violations). Streams them to the Wazuh-monitored
JSONL file so they get correlated with other sources.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def poll_alerts(since_minutes: int = 60, output_path: str = "/var/log/corpsec/gws-alerts.jsonl") -> int:
    """Pull alerts from GWS Alert Center API."""
    from googleapiclient.discovery import build
    from google.oauth2 import service_account

    sa_file = os.getenv("GWS_SERVICE_ACCOUNT_FILE", "/run/secrets/gws-service-account.json")
    delegated = os.getenv("GWS_DELEGATED_USER")
    scopes = ["https://www.googleapis.com/auth/apps.alerts"]

    creds = service_account.Credentials.from_service_account_file(sa_file, scopes=scopes)
    if delegated:
        creds = creds.with_subject(delegated)

    service = build("alertcenter", "v1beta1", credentials=creds, cache_discovery=False)

    start_time = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    page_token = None
    with out.open("a", encoding="utf-8") as f:
        while True:
            request = service.alerts().list(
                filter=f'createTime >= "{start_time}"',
                pageToken=page_token,
                pageSize=100,
            )
            resp = request.execute()
            for alert in resp.get("alerts", []):
                event = {
                    "source": "google_workspace",
                    "subsource": "alert_center",
                    "alert_id": alert.get("alertId"),
                    "alert_type": alert.get("type"),
                    "source_application": alert.get("source"),
                    "create_time": alert.get("createTime"),
                    "data": alert.get("data", {}),
                }
                f.write(json.dumps(event) + "\n")
                written += 1
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

    logger.info("Polled %d Alert Center alerts since %s", written, start_time)
    return written


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", default="1h")
    parser.add_argument("--output", default="/var/log/corpsec/gws-alerts.jsonl")
    args = parser.parse_args()
    minutes = int(args.since.rstrip("hm")) * (60 if args.since.endswith("h") else 1)
    print(f"polled {poll_alerts(minutes, args.output)} alerts")


if __name__ == "__main__":
    main()
