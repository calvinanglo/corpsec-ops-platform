"""Block domain via DNS sinkhole + proxy block list.

Writes domain to a sinkhole list file that is loaded by the corporate DNS
resolver (Pi-hole, Bind RPZ, or similar).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)

SINKHOLE_FILE = Path(os.getenv("DNS_SINKHOLE_FILE", "/var/log/corpsec/dns-sinkhole.txt"))


def execute(alert: dict) -> Tuple[bool, dict]:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    domain = (
        data.get("ai_service")
        or data.get("destination")
        or data.get("domain")
        or data.get("host")
    )
    if not domain:
        return False, {"error": "no_domain_in_alert"}

    duration = int(data.get("duration_seconds", 3600))

    try:
        SINKHOLE_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = f"{datetime.now(timezone.utc).isoformat()}\t{domain}\t{duration}\t{alert.get('id', 'unknown')}\n"
        with SINKHOLE_FILE.open("a", encoding="utf-8") as f:
            f.write(entry)
        logger.info("Sinkholed domain %s for %ds", domain, duration)
        return True, {
            "domain": domain,
            "duration_seconds": duration,
            "sinkhole_file": str(SINKHOLE_FILE),
        }
    except Exception as exc:
        logger.exception("block_domain failed for %s", domain)
        return False, {"domain": domain, "error": str(exc)}
