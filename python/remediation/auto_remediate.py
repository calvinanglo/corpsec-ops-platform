"""corpsec-ops-platform — Auto-remediation dispatcher.

Receives alerts (from n8n webhook or active-response), matches them to
playbooks, executes ordered actions, creates TheHive case with timeline.
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from remediation.playbooks import RemediationPlaybook, find_playbook_for_rule, PLAYBOOKS

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class ActionResult:
    success: bool
    action_name: str
    timestamp: str
    details: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class RemediationResult:
    playbook_id: str
    triggered_at: str
    alert_id: str
    rule_id: int
    severity: str
    user: Optional[str]
    actions_executed: list[ActionResult] = field(default_factory=list)
    actions_skipped: list[str] = field(default_factory=list)
    case_id: Optional[str] = None
    notification_channels: list[str] = field(default_factory=list)
    final_status: str = "pending"  # pending | success | partial | failed | no_match

    def as_dict(self) -> dict:
        return {
            "playbook_id": self.playbook_id,
            "triggered_at": self.triggered_at,
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "user": self.user,
            "case_id": self.case_id,
            "final_status": self.final_status,
            "actions_executed": [asdict(a) for a in self.actions_executed],
            "actions_skipped": self.actions_skipped,
            "notification_channels": self.notification_channels,
        }


class AutoRemediate:
    """SOAR dispatcher — matches alerts to playbooks, executes actions."""

    def __init__(self, audit_log: str = "/var/log/corpsec/audit.jsonl"):
        self.audit_log = audit_log

    def receive_alert(self, alert: dict) -> RemediationResult:
        """Entry point — classify alert and execute matching playbook."""
        rule_id = int(alert.get("rule", {}).get("id", 0))
        severity = (alert.get("data", {}).get("severity") or "MEDIUM").upper()
        alert_id = alert.get("id", f"alert-{datetime.now().timestamp()}")
        user = alert.get("data", {}).get("user") or alert.get("data", {}).get("actor", {}).get("email")

        result = RemediationResult(
            playbook_id="",
            triggered_at=datetime.now(timezone.utc).isoformat(),
            alert_id=alert_id,
            rule_id=rule_id,
            severity=severity,
            user=user,
        )

        playbook = find_playbook_for_rule(rule_id)
        if not playbook:
            result.final_status = "no_match"
            logger.info("No playbook matches rule %s", rule_id)
            self._audit(result)
            return result

        result.playbook_id = playbook.playbook_id
        result.notification_channels = playbook.notify_channels

        if SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(playbook.severity_threshold, 0):
            result.final_status = "below_threshold"
            result.actions_skipped = playbook.actions[:]
            logger.info(
                "Severity %s below threshold %s for playbook %s",
                severity, playbook.severity_threshold, playbook.playbook_id,
            )
            self._audit(result)
            return result

        # Execute actions in order — stop on first failure
        for action_name in playbook.actions:
            action_result = self._execute_action(action_name, alert)
            result.actions_executed.append(action_result)
            if not action_result.success:
                logger.error(
                    "Action %s failed — skipping remaining actions in playbook %s",
                    action_name, playbook.playbook_id,
                )
                # Skip remaining actions
                idx = playbook.actions.index(action_name)
                result.actions_skipped = playbook.actions[idx + 1:]
                result.final_status = "partial"
                break
        else:
            result.final_status = "success" if result.actions_executed else "success"

        # Create case (always, for audit)
        if playbook.create_case:
            try:
                from integrations.thehive_client import TheHiveClient
                client = TheHiveClient()
                case_id = client.create_case_from_remediation(alert, result, playbook)
                result.case_id = case_id
            except Exception as exc:
                logger.exception("Failed to create TheHive case: %s", exc)

        self._audit(result)
        return result

    def _execute_action(self, action_name: str, alert: dict) -> ActionResult:
        """Dynamically dispatch to remediation.actions.<action_name>."""
        ts = datetime.now(timezone.utc).isoformat()
        try:
            module = importlib.import_module(f"remediation.actions.{action_name}")
            success, details = module.execute(alert)
            return ActionResult(
                success=bool(success),
                action_name=action_name,
                timestamp=ts,
                details=details if isinstance(details, dict) else {"output": str(details)},
            )
        except Exception as exc:
            logger.exception("Action %s raised exception", action_name)
            return ActionResult(
                success=False,
                action_name=action_name,
                timestamp=ts,
                error=str(exc),
            )

    def _audit(self, result: RemediationResult) -> None:
        """Append remediation result to audit log."""
        try:
            os.makedirs(os.path.dirname(self.audit_log), exist_ok=True)
            with open(self.audit_log, "a", encoding="utf-8") as f:
                f.write(json.dumps(result.as_dict()) + "\n")
        except Exception:
            logger.exception("Failed to write audit log")


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="corpsec-ops auto-remediation")
    parser.add_argument("--alert-json", help="Path to alert JSON file")
    parser.add_argument("--list-playbooks", action="store_true")
    args = parser.parse_args()

    if args.list_playbooks:
        for pb in PLAYBOOKS.values():
            print(f"  {pb.playbook_id:15} {pb.name}")
            print(f"      threshold={pb.severity_threshold}, actions={pb.actions}, rules={pb.trigger_rule_ids}")
        return

    if not args.alert_json:
        parser.error("Provide --alert-json or --list-playbooks")

    alert = json.loads(open(args.alert_json).read())
    engine = AutoRemediate()
    result = engine.receive_alert(alert)
    print(json.dumps(result.as_dict(), indent=2))


if __name__ == "__main__":
    main()
