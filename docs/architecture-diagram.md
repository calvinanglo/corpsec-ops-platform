# Architecture Diagram — Mermaid Source

Render this diagram with any Mermaid-compatible tool:
- GitHub renders it automatically in `.md` files
- VS Code: Mermaid Markdown preview extension
- mermaid.live: paste the source into the live editor for PNG export → save to `screenshots/architecture/arch-diagram.png`

## Full Stack Diagram

```mermaid
flowchart LR
    subgraph CLOUD["Real Production SaaS Tools"]
        OKTA["Okta Developer Free<br/>(SSO, IdP)"]
        CS["CrowdStrike Falcon<br/>(EDR, RTR)"]
        GWS["Google Workspace<br/>(Email, Drive, DLP)"]
        OP["1Password Business<br/>(Password mgmt)"]
        INTUNE["Microsoft Intune<br/>(MDM)"]
    end

    subgraph PYTHON["Python Integration Layer"]
        OKTA_INT["okta/log_streamer<br/>+ user_lifecycle<br/>+ conditional_access"]
        CS_INT["crowdstrike/<br/>detection_streamer<br/>+ rtr_response<br/>+ policy_export"]
        GWS_INT["google_workspace/<br/>audit_log_streamer<br/>+ alert_center_poller<br/>+ dlp_rule_manager"]
        OP_INT["onepassword/<br/>audit_log_streamer<br/>+ service_account_manager"]
        INTUNE_INT["intune/<br/>device_streamer<br/>+ graph_client"]
    end

    subgraph WAZUH["Wazuh SIEM (self-hosted)"]
        WAZUH_MGR["wazuh-manager<br/>(rule engine + 9 custom rule files)"]
        WAZUH_IDX["wazuh-indexer<br/>(OpenSearch)"]
        WAZUH_DASH["wazuh-dashboard<br/>(UI + alerts)"]
    end

    subgraph SOAR["SOAR Layer (self-hosted)"]
        N8N["n8n<br/>(8 workflows)"]
        CORPSEC["corpsec-python<br/>(DLP + AI det + remediation API)"]
    end

    subgraph IR["Incident Response (self-hosted)"]
        THEHIVE["TheHive 5<br/>(case mgmt)"]
        CORTEX["Cortex 3<br/>(Wazuh + DLP analyzers)"]
    end

    subgraph OBS["Observability (self-hosted)"]
        GRAFANA["Grafana<br/>(8 SOC dashboards)"]
        PROM["Prometheus<br/>(metrics + alert rules)"]
        LOKI["Loki<br/>(log aggregation)"]
        AM["Alertmanager<br/>(Slack routing)"]
    end

    subgraph PHISH["Phishing Simulation (self-hosted)"]
        GOPHISH["GoPhish<br/>(3 campaigns)"]
        MAILHOG["MailHog<br/>(safe email sink)"]
    end

    OKTA -->|"System Log API"| OKTA_INT
    CS -->|"Detections + RTR API"| CS_INT
    GWS -->|"Reports + Alert Center API"| GWS_INT
    OP -->|"Events Reporting API"| OP_INT
    INTUNE -->|"Microsoft Graph"| INTUNE_INT

    OKTA_INT -->|"JSONL"| WAZUH_MGR
    CS_INT -->|"JSONL"| WAZUH_MGR
    GWS_INT -->|"JSONL"| WAZUH_MGR
    OP_INT -->|"JSONL"| WAZUH_MGR
    INTUNE_INT -->|"JSONL"| WAZUH_MGR

    WAZUH_MGR --> WAZUH_IDX
    WAZUH_IDX --> WAZUH_DASH
    WAZUH_MGR -->|"webhook level>=7"| N8N
    WAZUH_MGR -->|"active-response<br/>disable-user.sh<br/>block-exfil.sh"| CORPSEC

    N8N -->|"POST /remediate/execute"| CORPSEC
    N8N -->|"POST /api/v1/case"| THEHIVE
    CORPSEC -->|"Case w/ remediation timeline"| THEHIVE
    THEHIVE --> CORTEX
    CORTEX -->|"WazuhAnalyzer + DLPAnalyzer"| WAZUH_MGR

    WAZUH_IDX --> GRAFANA
    PROM --> GRAFANA
    LOKI --> GRAFANA
    PROM --> AM
    AM -->|"Slack #soc-alerts"| SLACK[("Slack")]

    GOPHISH --> MAILHOG
    GOPHISH -->|"campaign results"| CORPSEC

    OKTA -.->|"SSO/SAML/OIDC"| GRAFANA
    OKTA -.->|"SSO"| THEHIVE
    OKTA -.->|"SSO"| WAZUH_DASH
    OKTA -.->|"SCIM"| OP
    OKTA -.->|"SAML"| GWS
```

## Simplified Data Flow

```mermaid
sequenceDiagram
    participant T as Real Tool (e.g., CrowdStrike)
    participant P as Python Integration
    participant W as Wazuh Manager
    participant N as n8n
    participant R as corpsec-python /remediate
    participant H as TheHive

    T->>P: API: get detections (since 5m)
    P->>P: write JSONL to /var/log/corpsec/
    Note over P,W: Wazuh agent <localfile> ingests
    W->>W: rule fires (level >= 7)
    W->>N: webhook POST /webhook/wazuh-alert
    N->>N: parse, classify, dedupe
    N->>R: POST /remediate/execute
    R->>R: match playbook by rule_id
    R->>T: action (e.g., contain host via RTR)
    R->>H: create case w/ remediation timeline
    N->>H: also create case in parallel
    H->>H: enrich via Cortex analyzers
    Note over H: SOC analyst reviews and closes
```

## How to Export to PNG

```bash
# Option 1: mermaid-cli
npm install -g @mermaid-js/mermaid-cli
mmdc -i docs/architecture-diagram.md -o screenshots/architecture/arch-diagram.png

# Option 2: paste each diagram block into mermaid.live and download PNG
# Option 3: GitHub-rendered diagram → screenshot the rendered page
```
