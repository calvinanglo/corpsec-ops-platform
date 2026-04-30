"""Wazuh Manager API client.

Used by compliance evidence collector to export agent inventory, vulnerability
status, alert metrics.
"""
from __future__ import annotations

import logging
import os

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class WazuhClient:
    """Wazuh Manager REST API wrapper."""

    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL", "https://wazuh-manager:55000").rstrip("/")
        self.user = os.getenv("WAZUH_API_USER", "wazuh-wui")
        self.password = os.getenv("WAZUH_API_PASSWORD", "")
        if not self.password:
            raise RuntimeError("WAZUH_API_PASSWORD must be set")
        self._token: str | None = None

    def _auth(self) -> str:
        if self._token:
            return self._token
        r = requests.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.user, self.password),
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        self._token = r.json()["data"]["token"]
        return self._token

    def _get(self, path: str, params: dict | None = None) -> dict:
        token = self._auth()
        r = requests.get(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            verify=False,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    # ── Compliance evidence exports ────────────────────────────────────────
    def export_agent_inventory(self) -> dict:
        resp = self._get("/agents", params={"limit": 1000})
        agents = resp.get("data", {}).get("affected_items", [])
        return {
            "total_agents": len(agents),
            "active_agents": sum(1 for a in agents if a.get("status") == "active"),
            "agents": [
                {"id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"), "os": a.get("os", {}).get("platform"), "status": a.get("status")}
                for a in agents
            ],
        }

    def export_vulnerability_summary(self) -> dict:
        try:
            resp = self._get("/vulnerability", params={"limit": 100})
        except Exception as exc:
            return {"error": str(exc)}
        return {"vulnerability_data": resp.get("data", {})}

    def export_alert_summary(self) -> dict:
        # Alert summary is typically queried from the indexer (OpenSearch); the manager API exposes manager status only
        resp = self._get("/manager/info")
        return {"manager_info": resp.get("data", {})}

    def export_log_retention_status(self) -> dict:
        return {"placeholder": "log_retention_check_via_indexer", "manager_url": self.base_url}
