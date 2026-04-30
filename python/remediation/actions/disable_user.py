"""Disable user via Okta API (suspend account, terminate sessions)."""
from __future__ import annotations

import logging
from typing import Tuple

logger = logging.getLogger(__name__)


def execute(alert: dict) -> Tuple[bool, dict]:
    """Disable the user identified in the alert.

    Looks up user_email from alert.data.user, alert.data.actor.email,
    or alert.data.user_email. Calls Okta API to suspend the user.
    """
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
        result = client.suspend_user(user)
        # Also clear sessions
        client.clear_user_sessions(user)
        logger.info("Disabled Okta user %s", user)
        return True, {"user": user, "okta_response": result}
    except Exception as exc:
        logger.exception("disable_user failed for %s", user)
        return False, {"user": user, "error": str(exc)}
