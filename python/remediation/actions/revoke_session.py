"""Revoke all SSO sessions for a user — kicks them out of all SSO-protected apps."""
from __future__ import annotations

import logging
from typing import Tuple

logger = logging.getLogger(__name__)


def execute(alert: dict) -> Tuple[bool, dict]:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    user = (
        data.get("user")
        or data.get("user_email")
        or (data.get("actor") or {}).get("email")
        or (data.get("actor") or {}).get("alternateId")
    )
    if not user:
        return False, {"error": "no_user_in_alert"}

    try:
        from integrations.okta.okta_client import OktaClient
        client = OktaClient()
        result = client.clear_user_sessions(user)
        logger.info("Revoked all sessions for %s", user)
        return True, {"user": user, "sessions_cleared": result}
    except Exception as exc:
        logger.exception("revoke_session failed for %s", user)
        return False, {"user": user, "error": str(exc)}
