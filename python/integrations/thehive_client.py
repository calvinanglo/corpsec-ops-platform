"""TheHive 5 API client.

Used by remediation engine and DLP reporter to create incident response cases
linked to Wazuh alerts.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class TheHiveClient:
    """TheHive 5 API wrapper."""

    def __init__(self):
        self.base_url = os.getenv("THEHIVE_URL", "http://thehive:9000").rstrip("/")
        self.api_key = os.getenv("THEHIVE_API_KEY", "")
        if not self.api_key:
            logger.warning("THEHIVE_API_KEY not set — case creation will fail until configured post-bootstrap")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def create_case(
        self,
        title: str,
        description: str,
        severity: int = 2,
        tags: list[str] | None = None,
        tlp: int = 2,
        pap: int = 2,
    ) -> dict:
        body = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
            "tags": tags or [],
        }
        r = self.session.post(f"{self.base_url}/api/v1/case", json=body, timeout=30)
        r.raise_for_status()
        return r.json()

    def create_case_from_remediation(self, alert: dict, result: Any, playbook: Any) -> str:
        """Create a TheHive case linked to a remediation result."""
        rule = alert.get("rule", {})
        title = f"[{playbook.playbook_id}] {rule.get('description', 'Remediation triggered')}"
        description_lines = [
            f"## Auto-remediation triggered",
            f"- **Playbook**: `{playbook.playbook_id}` — {playbook.name}",
            f"- **Rule**: {rule.get('id')} - {rule.get('description', '')}",
            f"- **Severity**: {result.severity}",
            f"- **User**: {result.user or 'unknown'}",
            f"- **Final status**: `{result.final_status}`",
            "",
            "## Actions executed",
        ]
        for action in result.actions_executed:
            mark = "✓" if action.success else "✗"
            description_lines.append(
                f"- {mark} `{action.action_name}` at {action.timestamp} — {action.error or 'OK'}"
            )
        case = self.create_case(
            title=title[:200],
            description="\n".join(description_lines),
            severity=_severity_to_thehive(result.severity),
            tags=["auto-remediation", playbook.playbook_id, f"rule-{rule.get('id', 'unknown')}"],
        )
        return case.get("_id", case.get("id", ""))

    # ── Compliance evidence exports ────────────────────────────────────────
    def export_case_metrics(self) -> dict:
        try:
            r = self.session.post(
                f"{self.base_url}/api/v1/query",
                json={"query": [{"_name": "listCase"}, {"_name": "limit", "limit": 100}]},
                timeout=30,
            )
            r.raise_for_status()
            cases = r.json()
        except Exception as exc:
            return {"error": str(exc)}
        return {
            "total_cases": len(cases),
            "open": sum(1 for c in cases if c.get("status") == "Open"),
            "closed": sum(1 for c in cases if c.get("status") == "Closed"),
            "by_severity": _count_by(cases, "severity"),
        }

    def export_response_metrics(self) -> dict:
        return self.export_case_metrics()

    def export_closed_cases_with_rca(self) -> dict:
        return {"placeholder": "queries_closed_cases_with_rca_field"}


def _severity_to_thehive(sev: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 2)


def _count_by(items: list[dict], key: str) -> dict:
    counts: dict[Any, int] = {}
    for it in items:
        v = it.get(key, "unknown")
        counts[v] = counts.get(v, 0) + 1
    return counts
