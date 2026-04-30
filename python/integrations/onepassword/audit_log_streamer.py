"""Stream 1Password Events API audit log to Wazuh-monitored JSONL.

Uses the 1Password Events Reporting API (separate from CLI). Requires an
Events API token, NOT a service account token.
Docs: https://developer.1password.com/docs/events-api/reference/
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class OnePasswordEvents:
    """1Password Events Reporting API wrapper."""

    BASE_URL = "https://events.1password.com"

    def __init__(self, api_token: str | None = None):
        self.api_token = api_token or os.getenv("OP_AUDIT_LOG_API_KEY")
        if not self.api_token:
            raise RuntimeError("OP_AUDIT_LOG_API_KEY must be set")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        })
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def get_audit_events(self, since_iso: str, limit: int = 1000) -> list[dict]:
        body = {"limit": limit, "start_time": since_iso}
        r = self.session.post(f"{self.BASE_URL}/api/v1/auditevents", json=body)
        r.raise_for_status()
        return r.json().get("items", [])

    def get_signin_attempts(self, since_iso: str, limit: int = 1000) -> list[dict]:
        body = {"limit": limit, "start_time": since_iso}
        r = self.session.post(f"{self.BASE_URL}/api/v1/signinattempts", json=body)
        r.raise_for_status()
        return r.json().get("items", [])

    def get_item_usages(self, since_iso: str, limit: int = 1000) -> list[dict]:
        body = {"limit": limit, "start_time": since_iso}
        r = self.session.post(f"{self.BASE_URL}/api/v1/itemusages", json=body)
        r.raise_for_status()
        return r.json().get("items", [])


def stream(since_minutes: int = 60, output_path: str = "/var/log/corpsec/onepassword-audit.jsonl") -> int:
    client = OnePasswordEvents()
    since_iso = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with out.open("a", encoding="utf-8") as f:
        for category, fetcher in (
            ("audit", client.get_audit_events),
            ("signin", client.get_signin_attempts),
            ("item_usage", client.get_item_usages),
        ):
            try:
                items = fetcher(since_iso)
            except Exception as exc:
                logger.warning("1Password %s pull failed: %s", category, exc)
                continue
            for item in items:
                event = {"source": "onepassword", "category": category, **item}
                f.write(json.dumps(event) + "\n")
                written += 1
    logger.info("Streamed %d 1Password events", written)
    return written


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", default="1h")
    parser.add_argument("--output", default="/var/log/corpsec/onepassword-audit.jsonl")
    args = parser.parse_args()
    minutes = int(args.since.rstrip("hm")) * (60 if args.since.endswith("h") else 1)
    print(f"streamed {stream(minutes, args.output)} events")


if __name__ == "__main__":
    main()
