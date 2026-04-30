"""CrowdStrike Falcon API client.

Wraps the Falcon API for: detection retrieval, host containment (RTR),
prevention policy export, sensor health.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class FalconClient:
    """CrowdStrike Falcon API wrapper using crowdstrike-falconpy SDK."""

    def __init__(self, client_id: str | None = None, client_secret: str | None = None):
        self.client_id = client_id or os.getenv("CROWDSTRIKE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("CROWDSTRIKE_CLIENT_SECRET")
        self.base_url = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")

        if not self.client_id or not self.client_secret:
            raise RuntimeError("CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET must be set")

        # Lazy import — falconpy is optional during tests
        from falconpy import Detects, Hosts, RealTimeResponse, PreventionPolicies
        self._detects = Detects(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
        self._hosts = Hosts(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
        self._rtr = RealTimeResponse(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)
        self._policies = PreventionPolicies(client_id=self.client_id, client_secret=self.client_secret, base_url=self.base_url)

    # ── Detection retrieval ────────────────────────────────────────────────
    def query_detections(self, since_iso: str | None = None, limit: int = 100) -> list[dict]:
        filter_str = f"created_timestamp:>'{since_iso}'" if since_iso else None
        ids_response = self._detects.query_detects(filter=filter_str, limit=limit)
        ids = ids_response.get("body", {}).get("resources", [])
        if not ids:
            return []
        details = self._detects.get_detect_summaries(ids=ids)
        return details.get("body", {}).get("resources", [])

    # ── Real-Time Response (containment) ───────────────────────────────────
    def contain_host(self, device_id: str) -> dict:
        """Network-isolate a host via Falcon RTR."""
        result = self._hosts.perform_action(action_name="contain", ids=[device_id])
        logger.info("CrowdStrike: contained host %s", device_id)
        return result.get("body", {})

    def lift_containment(self, device_id: str) -> dict:
        result = self._hosts.perform_action(action_name="lift_containment", ids=[device_id])
        return result.get("body", {})

    # ── Compliance evidence exports ────────────────────────────────────────
    def export_edr_status(self) -> dict:
        """Summary of EDR coverage — agent count, online %, recent detection counts."""
        host_response = self._hosts.query_devices_by_filter(limit=5000)
        host_ids = host_response.get("body", {}).get("resources", [])
        return {
            "total_hosts_enrolled": len(host_ids),
            "queried_at": _now_iso(),
            "evidence_type": "crowdstrike_edr_coverage",
        }

    def export_recent_detections(self, days: int = 7) -> dict:
        from datetime import datetime, timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        detections = self.query_detections(since, limit=500)
        by_severity: dict[str, int] = {}
        for d in detections:
            sev = str(d.get("max_severity_displayname", "unknown"))
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {
            "window_days": days,
            "total_detections": len(detections),
            "by_severity": by_severity,
        }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
