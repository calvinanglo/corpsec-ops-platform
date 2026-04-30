"""Okta Management API client.

Wraps the Okta API for: user lifecycle (suspend/clear sessions), user/role
exports for compliance, MFA policy exports.
Uses the Okta Developer Free org as the SSO/IdP foundation.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class OktaClient:
    """Okta Management API wrapper."""

    def __init__(self, org_url: str | None = None, api_token: str | None = None):
        self.org_url = (org_url or os.getenv("OKTA_ORG_URL", "")).rstrip("/")
        self.api_token = api_token or os.getenv("OKTA_API_TOKEN", "")
        if not self.org_url or not self.api_token:
            raise RuntimeError("OKTA_ORG_URL and OKTA_API_TOKEN must be set")

        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    # ── User lifecycle (used by remediation actions) ───────────────────────
    def suspend_user(self, user_email: str) -> dict:
        user_id = self._lookup_user_id(user_email)
        r = self.session.post(f"{self.org_url}/api/v1/users/{user_id}/lifecycle/suspend")
        r.raise_for_status()
        logger.info("Okta: suspended %s (id=%s)", user_email, user_id)
        return {"user_id": user_id, "status": "suspended"}

    def unsuspend_user(self, user_email: str) -> dict:
        user_id = self._lookup_user_id(user_email)
        r = self.session.post(f"{self.org_url}/api/v1/users/{user_id}/lifecycle/unsuspend")
        r.raise_for_status()
        return {"user_id": user_id, "status": "active"}

    def clear_user_sessions(self, user_email: str) -> dict:
        user_id = self._lookup_user_id(user_email)
        r = self.session.delete(f"{self.org_url}/api/v1/users/{user_id}/sessions?oauthTokens=true")
        r.raise_for_status()
        logger.info("Okta: cleared sessions for %s", user_email)
        return {"user_id": user_id, "sessions_cleared": True}

    # ── System log streaming (used by log_streamer) ────────────────────────
    def get_system_logs(self, since_iso: str, limit: int = 1000) -> list[dict]:
        url = f"{self.org_url}/api/v1/logs"
        params = {"since": since_iso, "limit": limit}
        r = self.session.get(url, params=params)
        r.raise_for_status()
        return r.json()

    # ── Compliance evidence export methods ─────────────────────────────────
    def export_users_and_roles(self) -> dict:
        users = self._paged("/api/v1/users")
        return {
            "user_count": len(users),
            "users": [
                {"email": u["profile"].get("email"), "status": u.get("status"), "created": u.get("created")}
                for u in users
            ],
        }

    def export_mfa_policies(self) -> dict:
        policies = self._paged("/api/v1/policies?type=MFA_ENROLL")
        return {"mfa_policy_count": len(policies), "policies": [{"id": p["id"], "name": p["name"], "status": p["status"]} for p in policies]}

    def export_access_policies(self) -> dict:
        policies = self._paged("/api/v1/policies?type=ACCESS_POLICY")
        return {"access_policy_count": len(policies), "policies": [{"id": p["id"], "name": p["name"]} for p in policies]}

    def export_roles(self) -> dict:
        # Custom roles
        try:
            r = self.session.get(f"{self.org_url}/api/v1/iam/roles")
            r.raise_for_status()
            return {"roles": r.json().get("roles", [])}
        except Exception as exc:
            return {"error": str(exc)}

    def export_jml_audit(self) -> dict:
        # Past 30 days of lifecycle events
        from datetime import datetime, timedelta, timezone
        since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        logs = self.get_system_logs(since, limit=200)
        lifecycle_events = [
            log for log in logs
            if log.get("eventType", "").startswith("user.lifecycle.")
        ]
        return {"event_count": len(lifecycle_events), "events": lifecycle_events[:50]}

    # ── Helpers ───────────────────────────────────────────────────────────
    def _lookup_user_id(self, user_email: str) -> str:
        r = self.session.get(f"{self.org_url}/api/v1/users/{user_email}")
        r.raise_for_status()
        return r.json()["id"]

    def _paged(self, path: str, max_pages: int = 10) -> list[dict]:
        url = f"{self.org_url}{path}"
        results: list[dict] = []
        for _ in range(max_pages):
            r = self.session.get(url)
            r.raise_for_status()
            results.extend(r.json())
            link = r.headers.get("Link", "")
            next_url = None
            for part in link.split(","):
                if 'rel="next"' in part:
                    next_url = part.split(";")[0].strip().lstrip("<").rstrip(">")
                    break
            if not next_url:
                break
            url = next_url
        return results
