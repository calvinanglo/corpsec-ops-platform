"""corpsec-ops-platform — Proxy log analyzer for AI exfiltration.

Parses HTTP proxy / firewall logs (Squid, Suricata HTTP events, NGINX) for
POST/PUT/PATCH requests to AI service endpoints with payload size tracking.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import time
from pathlib import Path

from ai_detection.detector import AIExfilDetector

logger = logging.getLogger(__name__)


# Squid native log: timestamp elapsed remotehost code/status bytes method URL rfc931 peerstatus/peerhost type
# 1738339565.123  234 192.168.1.10 TCP_TUNNEL/200 250000 POST https://api.openai.com/v1/chat/completions - HIER_DIRECT/52.1.2.3 -
SQUID_RE = re.compile(
    r"(?P<ts>\d+\.\d+)\s+\d+\s+(?P<src_ip>[\d.]+)\s+\S+\s+(?P<bytes>\d+)\s+"
    r"(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(?P<url>\S+)"
)


class ProxyLogAnalyzer:
    """Analyze HTTP proxy logs for AI service uploads."""

    def __init__(self, detector: AIExfilDetector, ip_to_user: dict[str, str] | None = None):
        self.detector = detector
        self.ip_to_user = ip_to_user or {}

    def parse_line(self, line: str) -> dict | None:
        line = line.strip()
        if not line:
            return None

        # JSON format (e.g., from custom log forwarder)
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

        # Squid native
        m = SQUID_RE.search(line)
        if m:
            return {
                "src_ip": m["src_ip"],
                "method": m["method"],
                "url": m["url"],
                "bytes": int(m["bytes"]),
            }
        return None

    def process_line(self, line: str) -> int:
        parsed = self.parse_line(line)
        if not parsed:
            return 0
        method = parsed.get("method", "GET").upper()
        if method not in ("POST", "PUT", "PATCH"):
            return 0
        url = parsed.get("url", "")
        if not url:
            return 0
        upload_bytes = int(parsed.get("bytes", 0) or parsed.get("upload_bytes", 0))
        user = parsed.get("user") or self.ip_to_user.get(parsed.get("src_ip", ""), parsed.get("src_ip", "unknown"))

        alert = self.detector.analyze_proxy_log(user, url, method, upload_bytes)
        if alert:
            self.detector.emit(alert)
            logger.info(
                "Proxy alert: [%s] %s %s → %s (%d bytes)",
                alert.severity, user, method, alert.ai_service, upload_bytes,
            )
            return 1
        return 0

    def tail(self, log_path: Path | str, follow: bool = True) -> None:
        path = Path(log_path)
        if not path.exists():
            logger.error("Proxy log not found: %s", path)
            return

        with path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
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
    parser = argparse.ArgumentParser(description="corpsec-ops proxy log analyzer")
    parser.add_argument("--log", required=True, help="Squid/JSON proxy log path")
    parser.add_argument("--ip-map", help="JSON mapping of src_ip -> user_email")
    parser.add_argument("--no-follow", action="store_true")
    args = parser.parse_args()

    ip_to_user = {}
    if args.ip_map:
        ip_to_user = json.loads(Path(args.ip_map).read_text())

    detector = AIExfilDetector()
    analyzer = ProxyLogAnalyzer(detector, ip_to_user)
    analyzer.tail(args.log, follow=not args.no_follow)


if __name__ == "__main__":
    main()
