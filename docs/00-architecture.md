# Architecture

## Overview

`corpsec-ops-platform` is a hybrid corporate security operations stack combining
**real production SaaS tools** (Okta, CrowdStrike, Google Workspace, 1Password,
Microsoft Intune) with **self-hosted open-source security infrastructure**
(Wazuh, TheHive, Grafana, GoPhish, n8n).

## High-Level Diagram

```
                        ┌─────────────────────────────────┐
                        │   Real Production SaaS Tools    │
                        │                                 │
  ┌──── Okta Developer ─┤  SSO/IdP — permanent (free)    │
  │                     │                                 │
  │  ┌─ CrowdStrike ────┤  EDR — 14-day trial            │
  │  │  Falcon          │                                 │
  │  │                  │                                 │
  │  │  ┌─ Google ──────┤  Email security — 14-day trial │
  │  │  │  Workspace    │                                 │
  │  │  │               │                                 │
  │  │  │  ┌─ 1Password ┤  Password mgmt — 14-day trial  │
  │  │  │  │  Business  │                                 │
  │  │  │  │            │                                 │
  │  │  │  │  ┌─ Intune ┤  MDM — 30-day trial            │
  │  │  │  │  │         │                                 │
  └──┴──┴──┴──┴─────────┘
     │  │  │  │
     │  │  │  └────── Microsoft Graph API
     │  │  └────── 1Password Events API
     │  └────── Google Admin SDK
     │  └────── CrowdStrike Falcon API
     └────── Okta System Log API
                  │
                  ▼
        ┌─────────────────────────────────┐
        │   Python Integration Layer       │
        │   integrations/{okta,crowd...}/  │
        │   - log_streamer.py per tool     │
        │   - API client per tool          │
        │   - Compliance export methods    │
        └─────────────────────────────────┘
                  │
                  │ JSONL files (per source)
                  ▼
        ┌─────────────────────────────────┐
        │   Wazuh SIEM (self-hosted)      │
        │                                 │
        │  ┌── wazuh-manager (rules)     │
        │  ├── wazuh-indexer (storage)   │
        │  └── wazuh-dashboard (UI)      │
        │                                 │
        │   Custom rules (100000+):       │
        │   - okta-rules.xml             │
        │   - crowdstrike-rules.xml      │
        │   - gws-rules.xml              │
        │   - onepassword-rules.xml      │
        │   - intune-rules.xml           │
        │   - dlp-rules.xml              │
        │   - ai-exfil-rules.xml         │
        │   - edr-rules.xml              │
        │   - compliance-rules.xml       │
        └─────────────────────────────────┘
                  │
                  │ Webhook (level >= 7)
                  ▼
        ┌─────────────────────────────────┐
        │   n8n SOAR Workflows            │
        │                                 │
        │   - wazuh-to-thehive            │
        │   - sync-production-tools       │
        │   - dlp-auto-remediate          │
        │   - phishing-report-triage      │
        │   - compliance-evidence         │
        └─────────────────────────────────┘
                  │
                  │ HTTP /remediate/execute
                  ▼
        ┌─────────────────────────────────┐
        │   corpsec-python (Flask API)    │
        │                                 │
        │   /remediate/disable-user       │  ◄── Active Response
        │   /remediate/revoke-session     │      from Wazuh
        │   /remediate/isolate-endpoint   │      (disable-user.sh,
        │   /remediate/block-domain       │       block-exfil.sh)
        │   /remediate/quarantine-file    │
        │   /remediate/execute (playbook) │
        │   /dlp/scan                     │
        │   /ai/detect                    │
        │   /compliance/collect           │
        └─────────────────────────────────┘
                  │
                  │ Case creation
                  ▼
        ┌─────────────────────────────────┐
        │   TheHive 5 + Cortex 3          │
        │   - Case management             │
        │   - Cortex analyzers (Wazuh,    │
        │     VirusTotal, AbuseIPDB)      │
        └─────────────────────────────────┘

        ┌─────────────────────────────────┐
        │   Observability Layer           │
        │                                 │
        │   - Prometheus (metrics)        │
        │   - Loki (logs)                 │
        │   - Grafana (7 SOC dashboards)  │
        │   - Alertmanager (Slack route)  │
        └─────────────────────────────────┘

        ┌─────────────────────────────────┐
        │   Phishing Simulation           │
        │                                 │
        │   - GoPhish (campaigns)         │
        │   - MailHog (safe email sink)   │
        │                                 │
        │   3 campaign templates:         │
        │   - Credential harvest          │
        │   - Malicious attachment        │
        │   - CEO fraud / BEC             │
        └─────────────────────────────────┘
```

## Container List (17 total)

| # | Container | Network | Purpose |
|---|-----------|---------|---------|
| 1 | nginx | frontend | TLS reverse proxy |
| 2 | wazuh-manager | frontend, wazuh | SIEM + active response |
| 3 | wazuh-indexer | wazuh | Log indexing (OpenSearch fork) |
| 4 | wazuh-dashboard | frontend, wazuh | Wazuh UI |
| 5 | thehive | frontend, backend | IR case management |
| 6 | cortex | backend | Observable analysis |
| 7 | thehive-db | backend | Cassandra (TheHive case storage) |
| 8 | thehive-index | backend | Elasticsearch (TheHive search) |
| 9 | grafana | frontend, backend | SOC dashboards |
| 10 | prometheus | backend | Metrics |
| 11 | loki | backend | Log aggregation |
| 12 | promtail | backend | Log shipping |
| 13 | alertmanager | backend | Alert routing |
| 14 | n8n | frontend, backend | SOAR workflows |
| 15 | corpsec-python | frontend, backend | DLP + AI det + remediation + compliance |
| 16 | gophish | frontend, backend | Phishing simulation |
| 17 | mailhog | backend | Safe email capture |

## Network Segmentation

- **corpsec-frontend** (bridge): UI-facing services accessible via nginx proxy
- **corpsec-backend** (bridge, internal): Inter-service only, no external access
- **corpsec-wazuh** (bridge, internal): Wazuh cluster internal traffic

## Data Flow

1. **Production tools generate events** (real APIs)
2. **Python integrations pull events every 5 min** (n8n schedule)
3. **Events written as JSONL** to `/var/log/corpsec/*.jsonl`
4. **Wazuh ingests JSONL** via `<localfile>` config
5. **Custom Wazuh rules fire** based on event content
6. **Webhook to n8n** for level >= 7 alerts
7. **n8n triggers Python remediation** via HTTP API
8. **TheHive case created** with full timeline
9. **Grafana dashboards** show real-time SOC view
10. **Alertmanager** routes critical alerts to Slack/PagerDuty

## Compliance Path

1. **Daily** at 02:00 — n8n triggers `compliance-evidence` workflow
2. **Python collector** queries each control's source (Okta API, Wazuh API, etc.)
3. **Evidence written** to `compliance/evidence/{framework}/{control}/{date}/`
4. **SHA-256 hash** computed for integrity verification
5. **Pre-audit** — `make evidence-collect` generates full package
