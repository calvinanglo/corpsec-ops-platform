"""Quarantine a flagged file — move to quarantine directory with metadata."""
from __future__ import annotations

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

logger = logging.getLogger(__name__)

QUARANTINE_DIR = Path(os.getenv("QUARANTINE_DIR", "/var/log/corpsec/quarantine"))


def execute(alert: dict) -> Tuple[bool, dict]:
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}
    file_path = data.get("file_path") or data.get("path") or data.get("resource")
    if not file_path:
        return False, {"error": "no_file_path_in_alert"}

    src = Path(file_path)
    if not src.exists():
        return False, {"file_path": file_path, "error": "source_file_missing"}

    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        # Preserve original path in quarantined filename
        safe_name = str(src).replace("/", "_").replace("\\", "_").lstrip("_")
        dest = QUARANTINE_DIR / f"{ts}_{safe_name}"
        shutil.move(str(src), str(dest))

        # Write metadata sidecar
        meta = {
            "original_path": str(src),
            "quarantined_path": str(dest),
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert.get("id", "unknown"),
            "rule_id": alert.get("rule", {}).get("id"),
            "user": data.get("user"),
        }
        meta_path = dest.with_suffix(dest.suffix + ".meta.json")
        meta_path.write_text(json.dumps(meta, indent=2))

        logger.info("Quarantined %s -> %s", src, dest)
        return True, meta
    except Exception as exc:
        logger.exception("quarantine_file failed for %s", file_path)
        return False, {"file_path": file_path, "error": str(exc)}
