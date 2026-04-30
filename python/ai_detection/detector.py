"""corpsec-ops-platform — AI exfiltration detector.

Multi-vector correlation:
  - DNS queries to AI service domains (sliding window)
  - Proxy/firewall log POST/PUT to AI APIs (with byte volume)
  - Clipboard events near AI tab focus (simulated via log events)
  - Temporal correlation: multiple low-severity events from same user → escalate

Generates Wazuh-compatible JSON events and TheHive cases for confirmed exfil.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from collections import defaultdict, deque
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ai_detection.policies import AIServiceRegistry, AIService

logger = logging.getLogger(__name__)


# ── Result dataclass ───────────────────────────────────────────────────────────
@dataclass
class AIExfilAlert:
    """Single AI exfiltration alert."""
    timestamp: str
    user: str
    detection_type: str  # dns_query | proxy_upload | clipboard | correlated
    ai_service: str
    ai_service_classification: str  # AUTHORIZED_CORPORATE | UNAUTHORIZED_PERSONAL | UNKNOWN
    ai_service_authorized: bool
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    details: dict
    after_hours: bool = False
    correlated_events: int = 0
    window_minutes: int = 0

    def as_dict(self) -> dict:
        d = asdict(self)
        d["source"] = "corpsec-ai-detection"
        return d


# ── Detector ───────────────────────────────────────────────────────────────────
class AIExfilDetector:
    """Detects AI service exfiltration via DNS + proxy + clipboard correlation."""

    # Thresholds (tunable via constructor)
    DNS_MEDIUM_COUNT = 5     # 5+ queries in 10min = MEDIUM
    DNS_MEDIUM_WINDOW = 600
    DNS_HIGH_COUNT = 20      # 20+ queries in 1h = HIGH
    DNS_HIGH_WINDOW = 3600
    UPLOAD_HIGH_BYTES = 10 * 1024        # >10KB = real content (not just a prompt)
    UPLOAD_CRITICAL_BYTES = 1024 * 1024  # >1MB = bulk exfil
    CORRELATION_WINDOW_SECONDS = 300     # 5 min — multi-vector correlation
    CORRELATION_MIN_EVENTS = 3
    BUSINESS_HOURS_START = 8   # 8am local
    BUSINESS_HOURS_END = 18    # 6pm local

    def __init__(self, registry: Optional[AIServiceRegistry] = None):
        self.registry = registry or AIServiceRegistry()
        # Per-user rolling windows for correlation
        self._dns_window: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._event_window: dict[str, deque[tuple[float, str, dict]]] = defaultdict(deque)

    # ── Single-event analysis ───────────────────────────────────────────────────
    def analyze_dns_query(self, user: str, host: str, ts: Optional[datetime] = None) -> Optional[AIExfilAlert]:
        """Analyze one DNS query event."""
        ts = ts or datetime.now(timezone.utc)
        category, service = self.registry.classify(host)
        if not service:
            # Unknown AI domain — only alert if it looks AI-ish
            if not any(kw in host.lower() for kw in ("ai", "gpt", "llm", "chat", "copilot", "gemini", "perplexity")):
                return None
            return AIExfilAlert(
                timestamp=ts.isoformat(),
                user=user,
                detection_type="dns_query",
                ai_service=host,
                ai_service_classification="UNKNOWN",
                ai_service_authorized=False,
                severity="LOW",
                details={"reason": "unknown AI-ish domain", "host": host},
                after_hours=self._is_after_hours(ts),
            )

        if category == "AUTHORIZED_CORPORATE":
            return None  # Allowed — no alert

        # Track in sliding window for escalation
        self._record_dns(user, ts.timestamp(), host)
        recent_count = self._count_recent_dns(user, host, self.DNS_HIGH_WINDOW)
        recent_short = self._count_recent_dns(user, host, self.DNS_MEDIUM_WINDOW)

        severity = "LOW"
        if recent_count >= self.DNS_HIGH_COUNT:
            severity = "HIGH"
        elif recent_short >= self.DNS_MEDIUM_COUNT:
            severity = "MEDIUM"

        after_hours = self._is_after_hours(ts)
        if after_hours and severity in ("MEDIUM", "HIGH"):
            severity = self._bump_severity(severity)

        alert = AIExfilAlert(
            timestamp=ts.isoformat(),
            user=user,
            detection_type="dns_query",
            ai_service=service.name,
            ai_service_classification=category,
            ai_service_authorized=False,
            severity=severity,
            details={
                "host": host,
                "service_key": service.name,
                "queries_in_10min": recent_short,
                "queries_in_1h": recent_count,
            },
            after_hours=after_hours,
        )
        self._record_event(user, ts.timestamp(), "dns_query", alert.details)
        return alert

    def analyze_proxy_log(
        self,
        user: str,
        url: str,
        method: str,
        upload_bytes: int,
        ts: Optional[datetime] = None,
    ) -> Optional[AIExfilAlert]:
        """Analyze one proxy log entry (HTTP request)."""
        ts = ts or datetime.now(timezone.utc)
        host = url.split("/")[2] if "://" in url else url.split("/")[0]
        category, service = self.registry.classify(host, url)
        if not service or category == "AUTHORIZED_CORPORATE":
            return None
        if method.upper() not in ("POST", "PUT", "PATCH"):
            return None

        # Below 10KB = likely just a prompt, not data exfil
        if upload_bytes < self.UPLOAD_HIGH_BYTES:
            severity = "LOW"
        elif upload_bytes < self.UPLOAD_CRITICAL_BYTES:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        after_hours = self._is_after_hours(ts)
        if after_hours and severity in ("MEDIUM", "HIGH"):
            severity = self._bump_severity(severity)

        alert = AIExfilAlert(
            timestamp=ts.isoformat(),
            user=user,
            detection_type="proxy_upload",
            ai_service=service.name,
            ai_service_classification=category,
            ai_service_authorized=False,
            severity=severity,
            details={
                "url": url,
                "method": method,
                "upload_bytes": upload_bytes,
                "upload_mb": round(upload_bytes / 1024 / 1024, 2),
            },
            after_hours=after_hours,
        )
        self._record_event(user, ts.timestamp(), "proxy_upload", alert.details)

        # Check for cross-vector correlation
        correlated = self.correlate_user_events(user, ts.timestamp())
        if correlated:
            return correlated  # Returns an upgraded correlated alert
        return alert

    def correlate_user_events(self, user: str, now_ts: float) -> Optional[AIExfilAlert]:
        """Detect multi-vector exfiltration within the correlation window.

        E.g.: DNS query to chat.openai.com + POST to api.openai.com + clipboard
              event from same user within 5 min = CRITICAL correlated alert.
        """
        events = self._event_window.get(user, deque())
        recent = [(ts, kind, det) for ts, kind, det in events
                  if now_ts - ts <= self.CORRELATION_WINDOW_SECONDS]
        if len(recent) < self.CORRELATION_MIN_EVENTS:
            return None

        kinds = {kind for _, kind, _ in recent}
        if len(kinds) < 2:
            return None  # Need cross-vector, not just multiple of same kind

        return AIExfilAlert(
            timestamp=datetime.fromtimestamp(now_ts, timezone.utc).isoformat(),
            user=user,
            detection_type="correlated",
            ai_service="multi-service",
            ai_service_classification="UNAUTHORIZED_PERSONAL",
            ai_service_authorized=False,
            severity="CRITICAL",
            details={
                "vectors": list(kinds),
                "events_in_window": [
                    {"kind": k, "details": d} for _, k, d in recent
                ],
            },
            correlated_events=len(recent),
            window_minutes=int(self.CORRELATION_WINDOW_SECONDS / 60),
        )

    # ── Reporting ──────────────────────────────────────────────────────────────
    def emit(self, alert: AIExfilAlert, output_path: Path | str = "/var/log/corpsec/ai-detection.jsonl") -> None:
        """Append alert to Wazuh-monitored JSONL file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(alert.as_dict()) + "\n")

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _record_dns(self, user: str, ts: float, host: str) -> None:
        window = self._dns_window[user]
        window.append((ts, host))
        cutoff = ts - self.DNS_HIGH_WINDOW
        while window and window[0][0] < cutoff:
            window.popleft()

    def _count_recent_dns(self, user: str, host: str, window_seconds: int) -> int:
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - window_seconds
        return sum(1 for ts, h in self._dns_window.get(user, ()) if ts >= cutoff and h == host)

    def _record_event(self, user: str, ts: float, kind: str, details: dict) -> None:
        window = self._event_window[user]
        window.append((ts, kind, details))
        cutoff = ts - self.CORRELATION_WINDOW_SECONDS
        while window and window[0][0] < cutoff:
            window.popleft()

    @staticmethod
    def _is_after_hours(ts: datetime) -> bool:
        return ts.hour < AIExfilDetector.BUSINESS_HOURS_START or ts.hour >= AIExfilDetector.BUSINESS_HOURS_END

    @staticmethod
    def _bump_severity(sev: str) -> str:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            i = order.index(sev)
            return order[min(i + 1, len(order) - 1)]
        except ValueError:
            return sev


# ── CLI ────────────────────────────────────────────────────────────────────────
def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="corpsec-ops AI exfiltration detector")
    parser.add_argument("--user", default="testuser@corpsec.local")
    parser.add_argument("--host", help="Test DNS query")
    parser.add_argument("--url", help="Test proxy log entry URL")
    parser.add_argument("--method", default="POST", help="HTTP method")
    parser.add_argument("--bytes", type=int, default=50000, help="Upload bytes")
    parser.add_argument("--sample", action="store_true", help="Run sample correlation scenario")
    parser.add_argument("--output", default="/var/log/corpsec/ai-detection.jsonl")
    args = parser.parse_args()

    detector = AIExfilDetector()

    if args.sample:
        # Simulate a correlated exfiltration scenario
        scenarios = [
            ("user_alice@corpsec.local", "chat.openai.com", None, None, None),
            ("user_alice@corpsec.local", "api.openai.com", "https://api.openai.com/v1/chat/completions", "POST", 250000),
            ("user_alice@corpsec.local", "chat.openai.com", None, None, None),
            ("user_bob@corpsec.local", "perplexity.ai", None, None, None),
        ]
        for user, host, url, method, byts in scenarios:
            if url:
                alert = detector.analyze_proxy_log(user, url, method, byts)
            else:
                alert = detector.analyze_dns_query(user, host)
            if alert:
                detector.emit(alert, args.output)
                print(f"[{alert.severity}] {alert.detection_type} {alert.user} → {alert.ai_service}")
    elif args.url:
        alert = detector.analyze_proxy_log(args.user, args.url, args.method, args.bytes)
        if alert:
            detector.emit(alert, args.output)
            print(json.dumps(alert.as_dict(), indent=2))
    elif args.host:
        alert = detector.analyze_dns_query(args.user, args.host)
        if alert:
            detector.emit(alert, args.output)
            print(json.dumps(alert.as_dict(), indent=2))
    else:
        parser.error("Provide --host, --url, or --sample")


if __name__ == "__main__":
    main()
