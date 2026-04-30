# corpsec-ops-platform

Production-grade Corporate Security Operations Center built on real production tools.
Demonstrates hands-on capability across SSO, EDR, DLP, MDM, password management,
phishing simulation, incident response, compliance automation (SOC 2 / ISO 27001),
and AI exfiltration detection.

## Real Production Stack

| Tool | Role | Status |
|------|------|--------|
| **Okta Developer** | SSO/IdP | Permanent (free, 10 users) |
| **Microsoft Intune** | MDM | 30-day trial |
| **CrowdStrike Falcon** | EDR | 14-day trial |
| **Google Workspace** | Email security | 14-day trial |
| **1Password Business** | Password management | 14-day trial |
| **Wazuh** | SIEM (aggregates all above) | Self-hosted permanent |
| **TheHive + Cortex** | Incident response case mgmt | Self-hosted permanent |
| **GoPhish** | Phishing simulation | Self-hosted permanent |
| **Grafana + Prometheus + Loki** | SOC dashboards | Self-hosted permanent |
| **n8n** | SOAR automation | Self-hosted permanent |
| **Custom Python** | DLP + AI detection + remediation + compliance | This repo |

## Quick Start

```bash
# 1. First-time setup
make setup              # Generates self-signed certs + .env from template
# ... edit .env with your trial credentials ...

# 2. Start the stack
make up-all             # All 17 containers
make health             # Verify all healthy

# 3. Pull live logs from real production tools
make sync-all           # Okta + CrowdStrike + GWS + 1Password + Intune → Wazuh

# 4. Run demo scenario
make demo               # End-to-end alert → case → remediation
```

## Architecture

```
                    [Real Okta Developer] ──┐
                              │             │
[Real CrowdStrike Falcon] ────┼──── (API) ──┼──> [Self-hosted Wazuh SIEM]
                              │             │           │
[Real Google Workspace] ──────┼──── (API) ──┤           │
                              │             │           v
[Real 1Password Business] ────┼──── (API) ──┤    [TheHive Cases]
                              │             │           │
[Real Microsoft Intune] ──────┼──── (Graph)─┘           │
                              │                          v
                              └──── (SCIM/SAML) ──> [Grafana SOC Dashboards]
```

## Repository Layout

```
corpsec-ops-platform/
├── docker-compose*.yml           # Self-hosted stack
├── integrations/                 # Real production API integrations
│   ├── okta/                    # Okta Management API + system log streaming
│   ├── crowdstrike/             # Falcon API + RTR + detection forwarding
│   ├── google_workspace/        # Admin SDK + audit log streaming
│   ├── onepassword/             # 1Password CLI + Events API
│   └── intune/                  # Microsoft Graph API for Intune
├── python/
│   ├── dlp/                     # Data Loss Prevention engine (8 policies)
│   ├── ai_detection/            # AI exfiltration detection
│   ├── remediation/             # SOAR auto-remediation (7 playbooks)
│   └── compliance/              # SOC 2 + ISO 27001 evidence collection
├── wazuh/                        # SIEM rules, decoders, active response
├── grafana/dashboards/           # 7 SOC dashboards
├── n8n/workflows/                # SOAR workflows
├── gophish/templates/            # Phishing campaign templates
├── ansible/                      # Endpoint hardening playbooks
├── runbooks/                     # IR procedures (12 runbooks)
├── compliance/control-mapping/   # SOC 2 + ISO 27001 control catalog
├── screenshots/                  # PROOF — admin console captures per tool
├── scripts/                      # Setup + demo + health-check scripts
└── docs/                         # Architecture + setup guides + JD mapping
```

## Documentation

- [`docs/00-architecture.md`](docs/00-architecture.md) — Full architecture
- [`docs/01-trial-signup-guide.md`](docs/01-trial-signup-guide.md) — Trial sign-up walkthrough
- [`docs/02-okta-setup.md`](docs/02-okta-setup.md) — Okta configuration
- [`docs/03-crowdstrike-setup.md`](docs/03-crowdstrike-setup.md) — CrowdStrike trial setup
- [`docs/04-gws-setup.md`](docs/04-gws-setup.md) — Google Workspace setup
- [`docs/05-1password-setup.md`](docs/05-1password-setup.md) — 1Password Business setup
- [`docs/06-intune-setup.md`](docs/06-intune-setup.md) — Microsoft Intune setup
- [`docs/07-integration-architecture.md`](docs/07-integration-architecture.md) — How everything wires together
- [`docs/08-screenshot-checklist.md`](docs/08-screenshot-checklist.md) — Screenshot capture protocol
- [`docs/09-jd-mapping.md`](docs/09-jd-mapping.md) — Capability-to-evidence index

## Capability Matrix

| Capability | Implementation |
|------------|---------------|
| **DLP monitoring & triage** | `python/dlp/` engine + Google Workspace DLP rules |
| **EDR operations** | CrowdStrike Falcon (real) + Wazuh EDR rules |
| **Phishing simulation** | GoPhish campaigns + training education flow |
| **L1/L2 incident response** | TheHive case management + 12 runbooks |
| **SOC 2 / ISO 27001 evidence** | `python/compliance/` automated collection |
| **Auto-remediation scripting** | `python/remediation/` SOAR with 7 playbooks |
| **AI exfiltration detection** | `python/ai_detection/` DNS + proxy correlation |
| **Okta + 1Password + GWS + MDM** | Real API integrations in `integrations/` |
| **Python + Bash automation** | All `python/` modules + `wazuh/active-response/` |

## License

MIT for original code in this repository. Refer to upstream tool licenses for
Wazuh (GPLv2), TheHive/Cortex (AGPL), Grafana (AGPL), GoPhish (MIT), n8n (Sustainable Use).
