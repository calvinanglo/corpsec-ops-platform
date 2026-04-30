# Screenshot Capture Checklist

**The screenshots are the proof artifact.** This document is the master checklist
for capturing them — when, what, where to save, and quality standards.

## Master Checklist (~58 screenshots total)

### Okta (6) — capture immediately, no expiry
- [ ] `screenshots/okta/01-admin-console.png` — Admin Console home
- [ ] `screenshots/okta/02-sso-applications.png` — Applications list with SAML/OIDC apps
- [ ] `screenshots/okta/03-mfa-policy.png` — MFA enrollment policy
- [ ] `screenshots/okta/04-system-log-events.png` — System Log with real events
- [ ] `screenshots/okta/05-scim-provisioning.png` — SCIM provisioning to 1Password
- [ ] `screenshots/okta/06-conditional-access.png` — Sign-on policies

### CrowdStrike Falcon (6) — capture within 14-day trial
- [ ] `screenshots/crowdstrike/01-falcon-dashboard.png`
- [ ] `screenshots/crowdstrike/02-detections.png` — Real eicar detection visible
- [ ] `screenshots/crowdstrike/03-host-management.png` — Enrolled endpoint
- [ ] `screenshots/crowdstrike/04-mitre-coverage.png`
- [ ] `screenshots/crowdstrike/05-response-actions.png`
- [ ] `screenshots/crowdstrike/06-real-time-response.png`

### Google Workspace (6) — capture within 14-day trial
- [ ] `screenshots/google-workspace/01-admin-console.png`
- [ ] `screenshots/google-workspace/02-security-center.png`
- [ ] `screenshots/google-workspace/03-alert-center.png` — at least 1 alert visible
- [ ] `screenshots/google-workspace/04-dlp-rules.png`
- [ ] `screenshots/google-workspace/05-audit-logs.png`
- [ ] `screenshots/google-workspace/06-context-aware-access.png`

### 1Password Business (6) — capture within 14-day trial
- [ ] `screenshots/1password/01-business-console.png`
- [ ] `screenshots/1password/02-vault-structure.png` — 4 vaults visible
- [ ] `screenshots/1password/03-okta-sso-integration.png`
- [ ] `screenshots/1password/04-watchtower.png`
- [ ] `screenshots/1password/05-audit-events.png`
- [ ] `screenshots/1password/06-secret-automation.png`

### Microsoft Intune (7) — capture within 30-day trial
- [ ] `screenshots/intune/01-admin-center.png`
- [ ] `screenshots/intune/02-device-enrollment.png` — enrolled device visible
- [ ] `screenshots/intune/03-compliance-policies.png`
- [ ] `screenshots/intune/04-conditional-access.png`
- [ ] `screenshots/intune/05-app-deployment.png`
- [ ] `screenshots/intune/06-configuration-profiles.png`
- [ ] `screenshots/intune/07-endpoint-security.png`

### Self-hosted (after `make up-all`)

#### Wazuh (6)
- [ ] `screenshots/wazuh/01-dashboard.png` — main dashboard with real data
- [ ] `screenshots/wazuh/02-alerts.png` — alerts forwarded from CrowdStrike
- [ ] `screenshots/wazuh/03-mitre-att&ck.png`
- [ ] `screenshots/wazuh/04-fim-changes.png`
- [ ] `screenshots/wazuh/05-vulnerability-detector.png`
- [ ] `screenshots/wazuh/06-active-response.png`

#### GoPhish (5)
- [ ] `screenshots/gophish/01-campaign-list.png`
- [ ] `screenshots/gophish/02-email-template.png`
- [ ] `screenshots/gophish/03-landing-page.png` — fake Okta login
- [ ] `screenshots/gophish/04-results-dashboard.png`
- [ ] `screenshots/gophish/05-training-page.png`

#### TheHive (5)
- [ ] `screenshots/thehive/01-case-list.png` — real cases auto-created
- [ ] `screenshots/thehive/02-case-detail.png` — full task workflow
- [ ] `screenshots/thehive/03-task-workflow.png`
- [ ] `screenshots/thehive/04-cortex-analysis.png`
- [ ] `screenshots/thehive/05-mitre-tagging.png`

#### Grafana (7)
- [ ] `screenshots/grafana/01-soc-overview.png`
- [ ] `screenshots/grafana/02-dlp-alerts.png`
- [ ] `screenshots/grafana/03-edr-status.png`
- [ ] `screenshots/grafana/04-phishing-campaigns.png`
- [ ] `screenshots/grafana/05-compliance-posture.png`
- [ ] `screenshots/grafana/06-incident-metrics.png`
- [ ] `screenshots/grafana/07-ai-exfil-monitor.png`

### Architecture
- [ ] `screenshots/architecture/arch-diagram.png` — exported from Mermaid in `00-architecture.md`

## Quality Standards

1. **Browser address bar visible** — proves real URL (not a mockup)
2. **Real data visible** — no empty/synthetic dashboards
3. **No personal info** — blur user emails, phone numbers, real names
4. **Annotated** — use Greenshot, ShareX, or browser extension to add arrows highlighting key features
5. **Naming**: `NN-feature-name.png` (zero-padded for sort order)
6. **Format**: PNG (no JPEG artifacts on text)
7. **Resolution**: At least 1920x1080 for clarity in portfolio README

## Annotation Tools

Free, recommended:
- **Greenshot** (Windows) — `greenshot.org`
- **ShareX** (Windows) — `getsharex.com`
- **Shottr** (macOS) — `shottr.cc`
- Built-in Snip & Sketch (Windows) + browser screenshot extension

## Capture Workflow

For each tool:
1. Sign in to the admin console
2. Open the relevant page
3. Wait for data to load
4. Snip with annotation tool
5. Add arrows to key features (e.g., "MFA enforced", "Real detection")
6. Save with the canonical filename
7. Tick the checkbox above
8. Commit screenshots to repo: `git add screenshots/<tool>/`

## Pre-Push Review

Before pushing screenshots:
- [ ] No personal email addresses or phone numbers
- [ ] No real customer/client names
- [ ] No API keys, tokens, or credentials visible
- [ ] No employee photos
- [ ] Browser address bar visible
- [ ] Annotations clear and correct
