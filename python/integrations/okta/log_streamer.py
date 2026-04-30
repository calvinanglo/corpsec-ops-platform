"""Stream Okta System Log events to a Wazuh-monitored JSONL file.

Run periodically (every minute) via cron or n8n schedule trigger.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from integrations.okta.okta_client import OktaClient

logger = logging.getLogger(__name__)


def stream_logs(since_minutes: int = 60, output_path: str = "/var/log/corpsec/okta-events.jsonl") -> int:
    """Pull Okta system logs from N minutes ago and write to Wazuh-monitored file."""
    client = OktaClient()
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    logs = client.get_system_logs(since)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out.open("a", encoding="utf-8") as f:
        for log in logs:
            log["source"] = "okta"
            f.write(json.dumps(log) + "\n")
            written += 1
    logger.info("Streamed %d Okta events since %s", written, since)
    return written


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", default="1h", help="Time window (e.g., 1h, 30m)")
    parser.add_argument("--output", default="/var/log/corpsec/okta-events.jsonl")
    args = parser.parse_args()

    minutes = int(args.since.rstrip("hm")) * (60 if args.since.endswith("h") else 1)
    count = stream_logs(minutes, args.output)
    print(f"streamed {count} events")


if __name__ == "__main__":
    main()
