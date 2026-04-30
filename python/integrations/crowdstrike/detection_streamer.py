"""Stream CrowdStrike detections to a Wazuh-monitored JSONL file."""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from integrations.crowdstrike.falcon_client import FalconClient

logger = logging.getLogger(__name__)


def stream(since_minutes: int = 60, output_path: str = "/var/log/corpsec/crowdstrike-detections.jsonl") -> int:
    client = FalconClient()
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    detections = client.query_detections(since)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out.open("a", encoding="utf-8") as f:
        for det in detections:
            event = {
                "source": "crowdstrike",
                "timestamp": det.get("created_timestamp"),
                "detection": {
                    "id": det.get("detection_id"),
                    "tactic": det.get("tactic"),
                    "technique": det.get("technique"),
                    "description": det.get("description"),
                    "behavior": det.get("behaviors_processed", [{}])[0].get("display_name") if det.get("behaviors_processed") else None,
                    "filename": (det.get("behaviors_processed") or [{}])[0].get("filename"),
                },
                "severity_int": det.get("max_severity"),
                "severity_label": det.get("max_severity_displayname"),
                "device": {
                    "device_id": det.get("device", {}).get("device_id"),
                    "hostname": det.get("device", {}).get("hostname"),
                    "platform": det.get("device", {}).get("platform_name"),
                },
            }
            f.write(json.dumps(event) + "\n")
            written += 1
    logger.info("Streamed %d CrowdStrike detections", written)
    return written


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", default="1h")
    parser.add_argument("--output", default="/var/log/corpsec/crowdstrike-detections.jsonl")
    args = parser.parse_args()
    minutes = int(args.since.rstrip("hm")) * (60 if args.since.endswith("h") else 1)
    print(f"streamed {stream(minutes, args.output)} detections")


if __name__ == "__main__":
    main()
