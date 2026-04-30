"""Isolate endpoint via CrowdStrike Real-Time Response (RTR) network containment."""
from __future__ import annotations

import logging
from typing import Tuple

logger = logging.getLogger(__name__)


def execute(alert: dict) -> Tuple[bool, dict]:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    device_id = (
        data.get("device_id")
        or (data.get("device") or {}).get("device_id")
        or (data.get("device") or {}).get("hostname")
        or data.get("hostname")
    )
    if not device_id:
        return False, {"error": "no_device_in_alert"}

    try:
        from integrations.crowdstrike.falcon_client import FalconClient
        client = FalconClient()
        result = client.contain_host(device_id)
        logger.info("Isolated endpoint %s via CrowdStrike RTR", device_id)
        return True, {"device_id": device_id, "containment": result}
    except Exception as exc:
        logger.exception("isolate_endpoint failed for %s", device_id)
        return False, {"device_id": device_id, "error": str(exc)}
