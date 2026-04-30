"""corpsec-ops-platform — DLP alert reporter.

Emits two channels:
  1. JSONL file monitored by Wazuh agent (becomes a Wazuh alert via custom rule)
  2. Direct TheHive case for HIGH/CRITICAL matches
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dlp.engine import DLPScanResult

logger = logging.getLogger(__name__)


class DLPReporter:
    """Routes DLP scan results to Wazuh (via JSONL) and TheHive (via API)."""

    def __init__(
        self,
        jsonl_path: Path | str = "/var/log/corpsec/dlp-alerts.jsonl",
        thehive_client=None,
        case_severity_threshold: str = "HIGH",
    ):
        self.jsonl_path = Path(jsonl_path)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self.thehive = thehive_client
        self.case_severity_threshold = case_severity_threshold

    def report(self, result: DLPScanResult, user: Optional[str] = None) -> None:
        """Report a scan result."""
        if not result.matches:
            return

        for match in result.matches:
            event = self._build_event(result, match, user)
            self._write_jsonl(event)

        if self._should_create_case(result):
            self._create_thehive_case(result, user)

    def _build_event(self, result: DLPScanResult, match, user: Optional[str]) -> dict:
        """Wazuh-compatible JSON event."""
        return {
            "source": "corpsec-dlp",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_id": match.policy_id,
            "policy_name": match.policy_name,
            "pattern_name": match.pattern_name,
            "severity": match.severity,
            "confidence": match.confidence,
            "user": user or os.getenv("USER", "unknown"),
            "file_path": result.resource,
            "matched_text_redacted": match.matched_text_redacted,
            "context_window": match.context_window,
            "match_count": result.match_count,
            "scan_id": f"dlp-{int(datetime.now().timestamp())}-{match.position}",
        }

    def _write_jsonl(self, event: dict) -> None:
        """Append event to JSONL file (Wazuh consumes via localfile)."""
        try:
            with self.jsonl_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            logger.exception("Failed to write DLP event to %s", self.jsonl_path)

    def _should_create_case(self, result: DLPScanResult) -> bool:
        """Auto-create TheHive case for HIGH+ severity."""
        if not self.thehive:
            return False
        order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get(result.severity, 0) >= order.get(self.case_severity_threshold, 3)

    def _create_thehive_case(self, result: DLPScanResult, user: Optional[str]) -> None:
        """Create incident response case for high-severity DLP."""
        if not self.thehive:
            return
        try:
            self.thehive.create_case(
                title=f"[DLP-{result.severity}] {result.match_count} matches in {result.resource}",
                description=self._format_case_description(result, user),
                severity=self._severity_to_thehive(result.severity),
                tags=["dlp", "automated"] + [m.policy_id for m in result.matches],
            )
            logger.info("TheHive case created for DLP scan: %s", result.resource)
        except Exception:
            logger.exception("Failed to create TheHive case")

    def _format_case_description(self, result: DLPScanResult, user: Optional[str]) -> str:
        lines = [
            f"## DLP scan result — auto-created case",
            f"- **Resource**: `{result.resource}`",
            f"- **User**: {user or 'unknown'}",
            f"- **Scan time**: {result.scanned_at}",
            f"- **Severity**: {result.severity}",
            f"- **Match count**: {result.match_count}",
            "",
            "## Matches",
        ]
        for m in result.matches:
            lines.append(
                f"- `{m.policy_id}` / `{m.pattern_name}` (severity={m.severity}, "
                f"confidence={m.confidence}): `{m.matched_text_redacted}` — context: `{m.context_window[:80]}...`"
            )
        lines.extend([
            "",
            "## Triage Checklist",
            "1. Verify match is true positive (open file, check content)",
            "2. Identify intent (accidental vs intentional)",
            "3. Check destination (internal share / external email / cloud upload)",
            "4. Check user RBAC (authorized for this data classification?)",
            "5. Document outcome and apply tuning if false positive",
        ])
        return "\n".join(lines)

    @staticmethod
    def _severity_to_thehive(sev: str) -> int:
        """Map DLP severity to TheHive 1-4 scale."""
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 2)
