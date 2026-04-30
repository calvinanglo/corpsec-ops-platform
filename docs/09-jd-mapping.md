# Job Description → Evidence Mapping

This document maps every requirement in the Clio Corporate Security Analyst job
description to the specific artifact in this repository that demonstrates the
capability.

**Purpose**: Recruiters and hiring managers can verify each JD bullet point
against actual code, configuration, runbook, or screenshot in the portfolio.

---

## "Build & Run: Monitor and triage DLP alerts to surface real signals from noise and operate EDR day-to-day"

### DLP Monitoring & Triage

| Evidence | Location |
|----------|----------|
| Custom DLP engine with 8 policies | [`python/dlp/engine.py`](../python/dlp/engine.py) |
| False-positive tuning (signal-vs-noise) | [`python/dlp/policies.py`](../python/dlp/policies.py) — `false_positive_patterns` per policy |
| Luhn checksum validation for credit cards | [`engine.py:luhn_check`](../python/dlp/engine.py) |
| Confidence scoring for triage prioritization | [`engine.py:_compute_confidence`](../python/dlp/engine.py) |
| Triage workflow runbook | [`runbooks/DLP-001-triage-workflow.md`](../runbooks/DLP-001-triage-workflow.md) |
| Detection rules in SIEM | [`wazuh/custom-rules/dlp-rules.xml`](../wazuh/custom-rules/dlp-rules.xml) |
| Google Workspace DLP integration | [`screenshots/google-workspace/04-dlp-rules.png`](../screenshots/google-workspace/) |

### EDR Operations

| Evidence | Location |
|----------|----------|
| CrowdStrike Falcon API integration | [`integrations/crowdstrike/falcon_client.py`](../python/integrations/crowdstrike/falcon_client.py) |
| Detection streaming pipeline | [`integrations/crowdstrike/detection_streamer.py`](../python/integrations/crowdstrike/detection_streamer.py) |
| Real-Time Response (host containment) | [`falcon_client.py:contain_host`](../python/integrations/crowdstrike/falcon_client.py) |
| EDR detection rules in Wazuh | [`wazuh/custom-rules/crowdstrike-rules.xml`](../wazuh/custom-rules/crowdstrike-rules.xml), [`edr-rules.xml`](../wazuh/custom-rules/edr-rules.xml) |
| EDR response runbook | [`runbooks/IR-007-crowdstrike-detection.md`](../runbooks/IR-007-crowdstrike-detection.md) |
| Real CrowdStrike screenshots | [`screenshots/crowdstrike/`](../screenshots/crowdstrike/) |

---

## "Drive Education: Run phishing simulation campaigns end-to-end"

| Evidence | Location |
|----------|----------|
| GoPhish self-hosted phishing platform | [`docker-compose.phishing.yml`](../docker-compose.phishing.yml) |
| 3 campaign templates (cred harvest, attachment, BEC) | [`gophish/templates/campaigns/`](../gophish/templates/campaigns/) |
| Email templates (Okta password, invoice, IT helpdesk) | [`gophish/templates/email-templates/`](../gophish/templates/email-templates/) |
| Fake Okta landing page (pixel-perfect) | [`gophish/templates/landing-pages/fake-okta-login.html`](../gophish/templates/landing-pages/fake-okta-login.html) |
| Education flow with quiz | [`gophish/templates/landing-pages/training-page.html`](../gophish/templates/landing-pages/training-page.html) |
| Campaign automation client | [`integrations/gophish_client.py`](../python/integrations/gophish_client.py) |
| Campaign execution runbook | [`runbooks/PHISH-001-campaign-execution.md`](../runbooks/PHISH-001-campaign-execution.md) |
| Real campaign screenshots | [`screenshots/gophish/`](../screenshots/gophish/) |

---

## "Incident Response: Handle L1/L2 security incidents (phishing, device compromise, data loss)"

| Incident type | Runbook | Auto-remediation playbook |
|---------------|---------|---------------------------|
| Phishing | [`IR-001`](../runbooks/IR-001-phishing-response.md) | `PB-PHISH-001` |
| Device compromise | [`IR-002`](../runbooks/IR-002-device-compromise.md) | `PB-EDR-001` |
| Data loss (DLP) | [`IR-003`](../runbooks/IR-003-data-loss-triage.md) | `PB-DLP-001`, `PB-DLP-002` |
| AI exfiltration | [`IR-004`](../runbooks/IR-004-ai-exfiltration.md) | `PB-AI-001`, `PB-AI-002` |
| Account compromise | [`IR-005`](../runbooks/IR-005-account-compromise.md) | `PB-ACCT-001` |
| Okta suspicious sign-in | [`IR-006`](../runbooks/IR-006-okta-suspicious-signin.md) | `PB-ACCT-001` |
| CrowdStrike detection | [`IR-007`](../runbooks/IR-007-crowdstrike-detection.md) | `PB-EDR-001` |
| GWS alert triage | [`IR-008`](../runbooks/IR-008-gws-alert-triage.md) | n/a |

| Supporting evidence | Location |
|---------------------|----------|
| TheHive case management | [`thehive/application.conf`](../thehive/application.conf) |
| Cortex automated analysis | [`thehive/cortex/application.conf`](../thehive/cortex/application.conf) |
| Custom Wazuh analyzer | [`thehive/cortex/analyzers/WazuhAnalyzer/`](../thehive/cortex/analyzers/WazuhAnalyzer/) |
| Alert-to-case automation | [`n8n/workflows/wazuh-to-thehive.json`](../n8n/workflows/wazuh-to-thehive.json) |

---

## "Optimize Systems: Maintain runbooks and support compliance evidence collection (SOC 2, ISO 27001)"

### Runbooks
12 runbooks total in [`runbooks/`](../runbooks/) directory:
- IR-001 through IR-008 (incident response)
- DLP-001 (DLP triage workflow)
- COMP-001 (SOC 2 evidence collection)
- COMP-002 (ISO 27001 audit)
- PHISH-001 (phishing campaign execution)

### Compliance Evidence Collection

| Evidence | Location |
|----------|----------|
| Automated evidence collector | [`python/compliance/evidence_collector.py`](../python/compliance/evidence_collector.py) |
| SOC 2 control specs (12 controls mapped) | [`python/compliance/controls/soc2.py`](../python/compliance/controls/soc2.py) |
| ISO 27001 control specs (14 controls mapped) | [`python/compliance/controls/iso27001.py`](../python/compliance/controls/iso27001.py) |
| YAML control mapping for auditors | [`compliance/control-mapping/`](../compliance/control-mapping/) |
| SOC 2 evidence runbook | [`runbooks/COMP-001-soc2-evidence.md`](../runbooks/COMP-001-soc2-evidence.md) |
| ISO 27001 audit runbook | [`runbooks/COMP-002-iso27001-audit.md`](../runbooks/COMP-002-iso27001-audit.md) |
| Daily evidence collection workflow | [`n8n/workflows/compliance-evidence.json`](../n8n/workflows/compliance-evidence.json) |
| SHA-256 integrity hashing | [`evidence_collector.py:_collect_one`](../python/compliance/evidence_collector.py) |

---

## "Technical Growth: Develop scripts to drive auto-remediation and tune security tooling for AI detection"

### Auto-Remediation

| Evidence | Location |
|----------|----------|
| SOAR dispatcher | [`python/remediation/auto_remediate.py`](../python/remediation/auto_remediate.py) |
| 7 remediation playbooks | [`python/remediation/playbooks.py`](../python/remediation/playbooks.py) |
| Disable user action (Okta) | [`actions/disable_user.py`](../python/remediation/actions/disable_user.py) |
| Revoke session action (Okta) | [`actions/revoke_session.py`](../python/remediation/actions/revoke_session.py) |
| Isolate endpoint action (CrowdStrike RTR) | [`actions/isolate_endpoint.py`](../python/remediation/actions/isolate_endpoint.py) |
| Block domain action (DNS sinkhole) | [`actions/block_domain.py`](../python/remediation/actions/block_domain.py) |
| Quarantine file action | [`actions/quarantine_file.py`](../python/remediation/actions/quarantine_file.py) |
| Wazuh active-response shell scripts | [`wazuh/active-response/`](../wazuh/active-response/) |
| HTTP API for remediation calls | [`python/remediation/api_server.py`](../python/remediation/api_server.py) |

### AI Detection (Unauthorized Data Moves)

| Evidence | Location |
|----------|----------|
| Multi-vector AI exfil detector | [`python/ai_detection/detector.py`](../python/ai_detection/detector.py) |
| AI service registry (10 services categorized) | [`python/ai_detection/policies.py`](../python/ai_detection/policies.py) |
| DNS query monitor | [`python/ai_detection/dns_monitor.py`](../python/ai_detection/dns_monitor.py) |
| Proxy log analyzer | [`python/ai_detection/proxy_log_analyzer.py`](../python/ai_detection/proxy_log_analyzer.py) |
| Wazuh detection rules | [`wazuh/custom-rules/ai-exfil-rules.xml`](../wazuh/custom-rules/ai-exfil-rules.xml) |
| AI exfil response runbook | [`runbooks/IR-004-ai-exfiltration.md`](../runbooks/IR-004-ai-exfiltration.md) |
| Endpoint-level AI blocking (Ansible) | [`ansible/playbooks/endpoint-hardening.yml`](../ansible/playbooks/endpoint-hardening.yml) — `ai-block` tag |

---

## "Collaborate: Engage with security culture across Clio's security stack (Okta, 1Password, Google Workspace, MDM)"

| Tool | API integration | Compliance export | Screenshots |
|------|----------------|-------------------|-------------|
| **Okta** | [`integrations/okta/okta_client.py`](../python/integrations/okta/okta_client.py) | 5 export methods | [`screenshots/okta/`](../screenshots/okta/) |
| **1Password** | [`integrations/onepassword/`](../python/integrations/onepassword/) | Audit log streaming | [`screenshots/1password/`](../screenshots/1password/) |
| **Google Workspace** | [`integrations/google_workspace/gws_admin_client.py`](../python/integrations/google_workspace/gws_admin_client.py) | 3 export methods | [`screenshots/google-workspace/`](../screenshots/google-workspace/) |
| **MDM (Intune)** | [`integrations/intune/graph_client.py`](../python/integrations/intune/graph_client.py) | 3 export methods | [`screenshots/intune/`](../screenshots/intune/) |

---

## "Bonus: SIEM in incident context"

| Evidence | Location |
|----------|----------|
| Wazuh SIEM (full deployment) | [`docker-compose.yml`](../docker-compose.yml) — services 2-4 |
| 9 custom rule files | [`wazuh/custom-rules/`](../wazuh/custom-rules/) |
| FIM, rootcheck, vuln detector configured | [`wazuh/ossec.conf`](../wazuh/ossec.conf) |
| SIEM screenshots | [`screenshots/wazuh/`](../screenshots/wazuh/) |

---

## "Bonus: Scripting (Python, Bash) for automating investigation or remediation"

### Python
- DLP engine: 4 modules in [`python/dlp/`](../python/dlp/)
- AI detection: 4 modules in [`python/ai_detection/`](../python/ai_detection/)
- SOAR remediation: dispatcher + 5 actions + API server in [`python/remediation/`](../python/remediation/)
- Compliance: collector + 26 control specs in [`python/compliance/`](../python/compliance/)
- 5 production tool integrations in [`python/integrations/`](../python/integrations/)
- Tests: [`python/tests/`](../python/tests/)

### Bash
- Active response scripts: [`wazuh/active-response/`](../wazuh/active-response/)
- Operational scripts: [`scripts/`](../scripts/)

---

## Architecture Doc

For the full system overview, see [`docs/00-architecture.md`](00-architecture.md).
