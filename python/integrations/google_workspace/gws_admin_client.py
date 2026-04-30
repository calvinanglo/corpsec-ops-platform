"""Google Workspace Admin SDK client.

Pulls audit logs from the Reports API, manages DLP rules, queries Alert Center.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


class GWSAdminClient:
    """Google Workspace Admin SDK wrapper."""

    SCOPES = [
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/admin.reports.usage.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/apps.alerts",
    ]

    def __init__(self, service_account_file: str | None = None, delegated_user: str | None = None):
        self.service_account_file = service_account_file or os.getenv("GWS_SERVICE_ACCOUNT_FILE")
        self.delegated_user = delegated_user or os.getenv("GWS_DELEGATED_USER")
        self.domain = os.getenv("GWS_DOMAIN")
        self._service = None

    def _build_service(self, service_name: str, version: str):
        from google.oauth2 import service_account
        from googleapiclient.discovery import build

        if not self.service_account_file or not os.path.exists(self.service_account_file):
            raise RuntimeError(f"GWS service account file not found: {self.service_account_file}")
        creds = service_account.Credentials.from_service_account_file(
            self.service_account_file, scopes=self.SCOPES
        )
        if self.delegated_user:
            creds = creds.with_subject(self.delegated_user)
        return build(service_name, version, credentials=creds, cache_discovery=False)

    # ── Audit log streaming ────────────────────────────────────────────────
    def get_audit_activities(self, application: str = "login", since_minutes: int = 60) -> list[dict]:
        """Pull audit events for an application (login, admin, drive, gmail, etc)."""
        reports = self._build_service("admin", "reports_v1")
        start_time = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        all_items: list[dict] = []
        page_token = None
        while True:
            req = reports.activities().list(
                userKey="all",
                applicationName=application,
                startTime=start_time,
                maxResults=1000,
                pageToken=page_token,
            )
            resp = req.execute()
            all_items.extend(resp.get("items", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return all_items

    # ── Compliance evidence exports ────────────────────────────────────────
    def export_user_directory(self) -> dict:
        directory = self._build_service("admin", "directory_v1")
        users: list[dict] = []
        page_token = None
        while True:
            resp = directory.users().list(
                customer="my_customer", maxResults=500, pageToken=page_token
            ).execute()
            users.extend(resp.get("users", []))
            page_token = resp.get("nextPageToken")
            if not page_token:
                break
        return {
            "user_count": len(users),
            "users": [
                {
                    "primaryEmail": u.get("primaryEmail"),
                    "isAdmin": u.get("isAdmin", False),
                    "isEnforcedIn2Sv": u.get("isEnforcedIn2Sv", False),
                    "isEnrolledIn2Sv": u.get("isEnrolledIn2Sv", False),
                    "suspended": u.get("suspended", False),
                    "creationTime": u.get("creationTime"),
                }
                for u in users
            ],
        }

    def export_dlp_summary(self) -> dict:
        # DLP events from past 7 days
        dlp_events = self.get_audit_activities("drive", since_minutes=7 * 24 * 60)
        dlp_only = [e for e in dlp_events if any("dlp" in str(p).lower() for p in e.get("events", []))]
        return {"window_days": 7, "dlp_event_count": len(dlp_only), "events": dlp_only[:50]}
