"""corpsec-ops-platform — Real production tool API integrations.

Wrappers for Okta, CrowdStrike Falcon, Google Workspace, 1Password, Intune.
Each integration provides:
  - Client class with authenticated session
  - Log streamer (pulls events → writes Wazuh-monitored JSONL)
  - Compliance export methods (used by evidence_collector)
"""
