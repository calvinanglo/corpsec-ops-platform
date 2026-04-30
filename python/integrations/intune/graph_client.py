"""Microsoft Graph API client for Intune.

Authenticates with client credentials (App Registration) and queries Intune
device, compliance policy, and conditional access endpoints.
"""
from __future__ import annotations

import logging
import os
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class GraphClient:
    """Microsoft Graph API wrapper (Intune-focused)."""

    def __init__(
        self,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
    ):
        self.tenant_id = tenant_id or os.getenv("INTUNE_TENANT_ID")
        self.client_id = client_id or os.getenv("INTUNE_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("INTUNE_CLIENT_SECRET")
        self.base_url = os.getenv("GRAPH_API_BASE_URL", "https://graph.microsoft.com/v1.0")

        if not all([self.tenant_id, self.client_id, self.client_secret]):
            raise RuntimeError("INTUNE_TENANT_ID, INTUNE_CLIENT_ID, INTUNE_CLIENT_SECRET must be set")

        self._token: str | None = None
        self._token_expires: float = 0.0
        self.session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        r = requests.post(url, data=data, timeout=30)
        r.raise_for_status()
        body = r.json()
        self._token = body["access_token"]
        self._token_expires = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def _request(self, method: str, path: str, **kwargs) -> dict:
        token = self._get_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/json"
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        r = self.session.request(method, url, headers=headers, timeout=30, **kwargs)
        r.raise_for_status()
        return r.json() if r.content else {}

    # ── Device queries ─────────────────────────────────────────────────────
    def get_managed_devices(self) -> list[dict]:
        """List all Intune-managed devices."""
        items: list[dict] = []
        url = "/deviceManagement/managedDevices"
        while url:
            resp = self._request("GET", url)
            items.extend(resp.get("value", []))
            url = resp.get("@odata.nextLink")
        return items

    def get_device_compliance_policies(self) -> list[dict]:
        return self._request("GET", "/deviceManagement/deviceCompliancePolicies").get("value", [])

    def get_device_configurations(self) -> list[dict]:
        return self._request("GET", "/deviceManagement/deviceConfigurations").get("value", [])

    def get_conditional_access_policies(self) -> list[dict]:
        return self._request("GET", "/identity/conditionalAccess/policies").get("value", [])

    # ── Compliance evidence exports ────────────────────────────────────────
    def export_encryption_compliance(self) -> dict:
        devices = self.get_managed_devices()
        encrypted = sum(1 for d in devices if d.get("isEncrypted"))
        return {
            "total_devices": len(devices),
            "encrypted_devices": encrypted,
            "encryption_percentage": round(100.0 * encrypted / max(len(devices), 1), 2),
            "non_compliant_devices": [
                {"deviceName": d.get("deviceName"), "userPrincipalName": d.get("userPrincipalName")}
                for d in devices if not d.get("isEncrypted")
            ],
        }

    def export_compliance_summary(self) -> dict:
        devices = self.get_managed_devices()
        by_state: dict[str, int] = {}
        for d in devices:
            state = d.get("complianceState", "unknown")
            by_state[state] = by_state.get(state, 0) + 1
        return {
            "total_devices": len(devices),
            "compliance_state_counts": by_state,
        }

    def export_conditional_access_policies_json(self) -> dict:
        policies = self.get_conditional_access_policies()
        return {
            "policy_count": len(policies),
            "policies": [
                {
                    "id": p.get("id"),
                    "displayName": p.get("displayName"),
                    "state": p.get("state"),
                    "conditions": p.get("conditions"),
                    "grantControls": p.get("grantControls"),
                }
                for p in policies
            ],
        }
