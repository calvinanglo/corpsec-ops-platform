"""Stream Intune device events (compliance changes, enrollments) to Wazuh JSONL."""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

from integrations.intune.graph_client import GraphClient

logger = logging.getLogger(__name__)


def stream(output_path: str = "/var/log/corpsec/intune-events.jsonl") -> int:
    client = GraphClient()
    devices = client.get_managed_devices()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out.open("a", encoding="utf-8") as f:
        for d in devices:
            event = {
                "source": "intune",
                "activityType": "device_status_check",
                "complianceState": d.get("complianceState"),
                "device": {
                    "id": d.get("id"),
                    "deviceName": d.get("deviceName"),
                    "operatingSystem": d.get("operatingSystem"),
                    "osVersion": d.get("osVersion"),
                    "isEncrypted": d.get("isEncrypted"),
                    "isSupervised": d.get("isSupervised"),
                    "jailBroken": d.get("jailBroken"),
                },
                "user": {
                    "userPrincipalName": d.get("userPrincipalName"),
                    "userId": d.get("userId"),
                },
                "lastSyncDateTime": d.get("lastSyncDateTime"),
            }
            f.write(json.dumps(event) + "\n")
            written += 1
    logger.info("Streamed %d Intune device events", written)
    return written


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", default="1h")  # Unused for now — Graph doesn't filter device list by time, but kept for CLI consistency
    parser.add_argument("--output", default="/var/log/corpsec/intune-events.jsonl")
    args = parser.parse_args()
    print(f"streamed {stream(args.output)} events")


if __name__ == "__main__":
    main()
