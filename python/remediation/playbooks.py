"""corpsec-ops-platform — Remediation playbook definitions.

7 playbooks covering DLP, AI exfiltration, EDR detections, phishing,
account compromise. Each playbook = ordered list of action module names
plus thresholds and rollback steps.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RemediationPlaybook:
    """A single auto-remediation playbook."""
    playbook_id: str
    name: str
    description: str
    trigger_rule_ids: list[int]                 # Wazuh rule IDs that fire this playbook
    severity_threshold: str                      # Min severity (LOW < MEDIUM < HIGH < CRITICAL)
    actions: list[str]                           # Ordered action module names
    requires_approval: bool = False              # True = create case + wait for human
    create_case: bool = True                     # Always create a TheHive case for audit
    rollback_actions: list[str] = field(default_factory=list)
    notify_channels: list[str] = field(default_factory=lambda: ["soc-alerts"])


# ── DLP Playbooks ─────────────────────────────────────────────────────────────
PB_DLP_001 = RemediationPlaybook(
    playbook_id="PB-DLP-001",
    name="DLP HIGH/CRITICAL — Quarantine + Disable + Investigate",
    description="Auto-quarantine flagged file, disable user pending review, create case",
    trigger_rule_ids=[100102, 100103, 100120, 100150, 100151, 100152],
    severity_threshold="HIGH",
    actions=[
        "quarantine_file",
        "disable_user",
    ],
    rollback_actions=["restore_file", "enable_user"],
    notify_channels=["soc-alerts", "soc-lead"],
)

PB_DLP_002 = RemediationPlaybook(
    playbook_id="PB-DLP-002",
    name="DLP MEDIUM — Case only (human triage)",
    description="Create case for analyst review without auto-action",
    trigger_rule_ids=[100101, 100110, 100111, 100130, 100140],
    severity_threshold="MEDIUM",
    actions=[],  # No automated action — case only
    create_case=True,
    notify_channels=["soc-alerts"],
)

# ── AI Exfiltration Playbooks ─────────────────────────────────────────────────
PB_AI_001 = RemediationPlaybook(
    playbook_id="PB-AI-001",
    name="AI Exfil CRITICAL — Block + Revoke + Manager Notify",
    description="Block AI service, revoke session, notify manager — protects client data",
    trigger_rule_ids=[100202, 100203],
    severity_threshold="CRITICAL",
    actions=[
        "block_domain",
        "revoke_session",
    ],
    rollback_actions=["unblock_domain"],
    notify_channels=["soc-alerts", "soc-lead", "manager"],
)

PB_AI_002 = RemediationPlaybook(
    playbook_id="PB-AI-002",
    name="AI Exfil MEDIUM/HIGH — Case + Investigation",
    description="Create case for analyst investigation, no auto-block",
    trigger_rule_ids=[100201, 100211, 100212, 100220, 100221, 100222, 100223],
    severity_threshold="MEDIUM",
    actions=[],
    create_case=True,
    notify_channels=["soc-alerts"],
)

# ── EDR Playbooks ─────────────────────────────────────────────────────────────
PB_EDR_001 = RemediationPlaybook(
    playbook_id="PB-EDR-001",
    name="Malware/Ransomware Detection — Isolate + Forensic",
    description="Auto-isolate endpoint via CrowdStrike RTR, trigger forensic snapshot",
    trigger_rule_ids=[100304, 100319, 100320, 100321],
    severity_threshold="HIGH",
    actions=[
        "isolate_endpoint",
    ],
    rollback_actions=["unisolate_endpoint"],
    notify_channels=["soc-alerts", "soc-lead"],
)

# ── Phishing Playbook ─────────────────────────────────────────────────────────
PB_PHISH_001 = RemediationPlaybook(
    playbook_id="PB-PHISH-001",
    name="User Clicked Phishing Link — Force Reset + Train",
    description="Revoke session, force password reset, enroll in training module",
    trigger_rule_ids=[],  # Triggered by GoPhish webhook, not Wazuh rule
    severity_threshold="MEDIUM",
    actions=[
        "revoke_session",
        # Real password reset trigger would go here
    ],
    notify_channels=["soc-alerts"],
)

# ── Account Compromise Playbook ───────────────────────────────────────────────
PB_ACCT_001 = RemediationPlaybook(
    playbook_id="PB-ACCT-001",
    name="Account Compromise Indicators — Disable + Revoke",
    description="Impossible travel, MFA fatigue, password spray → disable + revoke",
    trigger_rule_ids=[100002, 100003, 100011, 100020, 100021, 100502, 100503],
    severity_threshold="HIGH",
    actions=[
        "disable_user",
        "revoke_session",
    ],
    rollback_actions=["enable_user"],
    notify_channels=["soc-alerts", "soc-lead"],
)


PLAYBOOKS: dict[str, RemediationPlaybook] = {
    pb.playbook_id: pb
    for pb in [
        PB_DLP_001, PB_DLP_002,
        PB_AI_001, PB_AI_002,
        PB_EDR_001,
        PB_PHISH_001,
        PB_ACCT_001,
    ]
}


def find_playbook_for_rule(rule_id: int) -> RemediationPlaybook | None:
    """Return the first playbook whose trigger_rule_ids contains rule_id."""
    for pb in PLAYBOOKS.values():
        if rule_id in pb.trigger_rule_ids:
            return pb
    return None
