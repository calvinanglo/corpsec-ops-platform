"""corpsec-ops-platform — DNS query monitor.

Tails DNS query logs (Wazuh-monitored DNS server, Bind9, dnsmasq, or Pi-hole)
and feeds queries into the AIExfilDetector.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from ai_detection.detector import AIExfilDetector

logger = logging.getLogger(__name__)


# Bind9 query log pattern: 21-Apr-2026 15:32:45.123 client @0x... 192.168.1.10#52341 (chat.openai.com): query: chat.openai.com IN A
BIND9_RE = re.compile(
    r"(?P<timestamp>\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)"
    r".*?client\s+(?:@0x[0-9a-f]+\s+)?(?P<src_ip>[\d.]+)#\d+"
    r".*?query:\s+(?P<host>[^\s]+)"
)

# dnsmasq query log: Apr 21 15:32:45 dnsmasq[1234]: query[A] chat.openai.com from 192.168.1.10
DNSMASQ_RE = re.compile(
    r"(?P<timestamp>[A-Za-z]+\s+\d+\s+\d{2}:\d{2}:\d{2}).*?"
    r"query\[\w+\]\s+(?P<host>[^\s]+)\s+from\s+(?P<src_ip>[\d.]+)"
)

# JSON format from Wazuh-forwarded DNS events
JSON_FIELDS = {"timestamp", "host", "user", "src_ip"}


class DNSMonitor:
    """Tail DNS log file and analyze queries."""

    def __init__(self, detector: AIExfilDetector, ip_to_user: dict[str, str] | None = None):
        self.detector = detector
        self.ip_to_user = ip_to_user or {}

    def parse_line(self, line: str) -> dict | None:
        """Parse one log line into normalized fields."""
        line = line.strip()
        if not line:
            return None

        # Try JSON first
        if line.startswith("{"):
            try:
                d = json.loads(line)
                if JSON_FIELDS & d.keys():
                    return d
            except json.JSONDecodeError:
                pass

        # Bind9
        m = BIND9_RE.search(line)
        if m:
            return {
                "timestamp": m["timestamp"],
                "host": m["host"],
                "src_ip": m["src_ip"],
            }

        # dnsmasq
        m = DNSMASQ_RE.search(line)
        if m:
            return {
                "timestamp": m["timestamp"],
                "host": m["host"],
                "src_ip": m["src_ip"],
            }

        return None

    def process_line(self, line: str) -> int:
        """Process one line. Returns number of alerts emitted."""
        parsed = self.parse_line(line)
        if not parsed:
            return 0
        host = parsed.get("host", "").rstrip(".")
        if not host:
            return 0
        user = parsed.get("user") or self.ip_to_user.get(parsed.get("src_ip", ""), parsed.get("src_ip", "unknown"))
        alert = self.detector.analyze_dns_query(user, host)
        if alert:
            self.detector.emit(alert)
            logger.info("DNS alert: [%s] %s → %s", alert.severity, user, alert.ai_service)
            return 1
        return 0

    def tail(self, log_path: Path | str, follow: bool = True) -> None:
        """Tail a log file like `tail -f`."""
        path = Path(log_path)
        if not path.exists():
            logger.error("DNS log not found: %s", path)
            return

        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)  # Seek to end
            while True:
                line = f.readline()
                if line:
                    self.process_line(line)
                elif follow:
                    time.sleep(0.5)
                else:
                    break


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="corpsec-ops DNS monitor for AI exfiltration")
    parser.add_argument("--log", required=True, help="Path to DNS query log (Bind9, dnsmasq, or JSON)")
    parser.add_argument("--ip-map", help="Optional JSON file mapping IPs to user emails")
    parser.add_argument("--no-follow", action="store_true", help="Process existing content and exit")
    args = parser.parse_args()

    ip_to_user = {}
    if args.ip_map:
        ip_to_user = json.loads(Path(args.ip_map).read_text())

    detector = AIExfilDetector()
    monitor = DNSMonitor(detector, ip_to_user)
    monitor.tail(args.log, follow=not args.no_follow)


if __name__ == "__main__":
    main()
