"""Stream Google Workspace audit logs to Wazuh-monitored JSONL."""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

from integrations.google_workspace.gws_admin_client import GWSAdminClient

logger = logging.getLogger(__name__)


def stream(applications: list[str], since_minutes: int = 60, output_path: str = "/var/log/corpsec/gws-audit.jsonl") -> int:
    client = GWSAdminClient()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out.open("a", encoding="utf-8") as f:
        for app in applications:
            try:
                activities = client.get_audit_activities(app, since_minutes)
            except Exception as exc:
                logger.warning("GWS %s pull failed: %s", app, exc)
                continue
            for item in activities:
                event = {
                    "source": "google_workspace",
                    "application": app,
                    "timestamp": item.get("id", {}).get("time"),
                    "actor": item.get("actor", {}),
                    "ip_address": item.get("ipAddress"),
                    "events": item.get("events", []),
                }
                f.write(json.dumps(event) + "\n")
                written += 1
    logger.info("Streamed %d GWS events across %d apps", written, len(applications))
    return written


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--apps", default="login,admin,drive,token,user_accounts")
    parser.add_argument("--since", default="1h")
    parser.add_argument("--output", default="/var/log/corpsec/gws-audit.jsonl")
    args = parser.parse_args()
    minutes = int(args.since.rstrip("hm")) * (60 if args.since.endswith("h") else 1)
    apps = args.apps.split(",")
    print(f"streamed {stream(apps, minutes, args.output)} events")


if __name__ == "__main__":
    main()
