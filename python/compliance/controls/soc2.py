"""SOC 2 Trust Services Criteria — control-to-evidence mapping.

Each control specifies:
  - source: which integration/system to query
  - method: function name to invoke
  - description: human-readable control statement
  - freshness_days: max age before evidence is stale
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ControlSpec:
    control_id: str
    name: str
    description: str
    source: str  # okta | crowdstrike | gws | onepassword | intune | wazuh | thehive | ansible
    method: str  # name of method on the source's collector
    freshness_days: int = 30


SOC2_CONTROLS: list[ControlSpec] = [
    # ── CC1: Control Environment ────────────────────────────────────────────
    ControlSpec(
        control_id="CC1.1",
        name="Control Environment - Integrity and Ethical Values",
        description="Demonstrate commitment to integrity through code of conduct and policies",
        source="docs",
        method="export_policies",
        freshness_days=365,
    ),

    # ── CC2: Communication & Information ────────────────────────────────────
    ControlSpec(
        control_id="CC2.1",
        name="Communication and Information",
        description="Internal information needs identified and addressed",
        source="docs",
        method="export_runbooks",
        freshness_days=180,
    ),

    # ── CC6: Logical and Physical Access Controls ───────────────────────────
    ControlSpec(
        control_id="CC6.1",
        name="Logical Access - Identity and Access Management",
        description="The entity implements logical access security software and infrastructure to protect information assets",
        source="okta",
        method="export_users_and_roles",
        freshness_days=30,
    ),
    ControlSpec(
        control_id="CC6.2",
        name="Authentication - Multi-Factor",
        description="MFA is enforced for privileged accounts and remote access",
        source="okta",
        method="export_mfa_policies",
        freshness_days=30,
    ),
    ControlSpec(
        control_id="CC6.3",
        name="Threat Management - Vulnerability Detection",
        description="Continuous vulnerability scanning identifies and addresses threats",
        source="wazuh",
        method="export_vulnerability_summary",
        freshness_days=7,
    ),
    ControlSpec(
        control_id="CC6.6",
        name="Data Flow Controls - DLP",
        description="The entity restricts the transmission, movement, and removal of information",
        source="dlp",
        method="export_dlp_policies",
        freshness_days=30,
    ),
    ControlSpec(
        control_id="CC6.7",
        name="Data Encryption at Rest",
        description="Data is protected by encryption at rest",
        source="intune",
        method="export_encryption_compliance",
        freshness_days=14,
    ),
    ControlSpec(
        control_id="CC6.8",
        name="Malware Prevention - EDR",
        description="The entity implements controls to prevent or detect and act upon malicious software",
        source="crowdstrike",
        method="export_edr_status",
        freshness_days=7,
    ),

    # ── CC7: System Operations ──────────────────────────────────────────────
    ControlSpec(
        control_id="CC7.1",
        name="Configuration Management",
        description="Detection of changes that could affect security",
        source="ansible",
        method="export_compliance_audit",
        freshness_days=30,
    ),
    ControlSpec(
        control_id="CC7.2",
        name="Security Monitoring - SIEM",
        description="The entity monitors system components and the operation of those components",
        source="wazuh",
        method="export_alert_summary",
        freshness_days=7,
    ),
    ControlSpec(
        control_id="CC7.3",
        name="Incident Evaluation",
        description="The entity evaluates security events to determine whether they could or have resulted in a failure",
        source="thehive",
        method="export_case_metrics",
        freshness_days=14,
    ),
    ControlSpec(
        control_id="CC7.4",
        name="Incident Response",
        description="The entity responds to identified security incidents",
        source="thehive",
        method="export_response_metrics",
        freshness_days=14,
    ),
    ControlSpec(
        control_id="CC7.5",
        name="Recovery and Root Cause Analysis",
        description="The entity identifies, develops, and implements activities to recover from identified security incidents",
        source="thehive",
        method="export_closed_cases_with_rca",
        freshness_days=30,
    ),

    # ── CC8: Change Management ──────────────────────────────────────────────
    ControlSpec(
        control_id="CC8.1",
        name="Change Management",
        description="Changes to infrastructure are authorized, designed, developed, configured, documented, tested, approved, and implemented",
        source="git",
        method="export_recent_commits",
        freshness_days=7,
    ),
]
