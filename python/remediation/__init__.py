"""corpsec-ops-platform — Auto-remediation SOAR engine.

Maps Wazuh alerts to playbooks, executes ordered action steps, creates
TheHive cases. Maps to JD requirement: "develop scripts to drive
auto-remediation."
"""

from remediation.auto_remediate import AutoRemediate, RemediationResult
from remediation.playbooks import PLAYBOOKS, RemediationPlaybook

__all__ = ["AutoRemediate", "RemediationResult", "PLAYBOOKS", "RemediationPlaybook"]
