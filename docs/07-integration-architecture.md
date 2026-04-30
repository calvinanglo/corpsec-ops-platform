# Integration Architecture

How real production tools connect to the self-hosted SIEM and IR pipeline.

## End-to-End Flow

```
[Real production tool] ──API──> [Python integration]
                                       │
                                       │ writes JSONL
                                       ▼
                              [/var/log/corpsec/*.jsonl]
                                       │
                                       │ Wazuh agent <localfile>
                                       ▼
                              [Wazuh manager rule engine]
                                       │
                                       │ rule fires (level >= 7)
                                       ▼
                              [Wazuh integration → n8n webhook]
                                       │
                                       ▼
                              [n8n workflow: wazuh-to-thehive]
                                       │
                                       ├──> POST /remediate/execute
                                       │     (corpsec-python API)
                                       │           │
                                       │           ▼
                                       │     [Auto-remediation playbook
                                       │      runs ordered actions]
                                       │
                                       └──> POST /api/v1/case
                                             (TheHive API)
                                                   │
                                                   ▼
                                             [Case created with
                                              full alert + remediation
                                              timeline]
```

## Per-Tool Integration

### Okta → Wazuh
- **Trigger**: `make sync-okta` (or n8n schedule every 5 min)
- **Module**: `python/integrations/okta/log_streamer.py`
- **Path**: Okta System Log API → JSONL → `/var/log/corpsec/okta-events.jsonl`
- **Wazuh config**: `<localfile>` in `ossec.conf`
- **Decoder**: `wazuh/decoders/production-tools-decoder.xml`
- **Rules**: `wazuh/custom-rules/okta-rules.xml` (range 100000-100099)

### CrowdStrike Falcon → Wazuh
- **Trigger**: `make sync-crowdstrike`
- **Module**: `python/integrations/crowdstrike/detection_streamer.py`
- **Path**: Falcon Detections API → JSONL → `/var/log/corpsec/crowdstrike-detections.jsonl`
- **Rules**: `wazuh/custom-rules/crowdstrike-rules.xml` (range 100300-100399)

### Google Workspace → Wazuh
- **Trigger**: `make sync-gws`
- **Module**: `python/integrations/google_workspace/audit_log_streamer.py`
- **Path**: Admin SDK Reports API → JSONL → `/var/log/corpsec/gws-audit.jsonl`
- **Rules**: `wazuh/custom-rules/gws-rules.xml` (range 100400-100499)

### 1Password → Wazuh
- **Trigger**: `make sync-1password`
- **Module**: `python/integrations/onepassword/audit_log_streamer.py`
- **Path**: 1Password Events Reporting API → JSONL → `/var/log/corpsec/onepassword-audit.jsonl`
- **Rules**: `wazuh/custom-rules/onepassword-rules.xml` (range 100500-100599)

### Microsoft Intune → Wazuh
- **Trigger**: `make sync-intune`
- **Module**: `python/integrations/intune/device_streamer.py`
- **Path**: Microsoft Graph API → JSONL → `/var/log/corpsec/intune-events.jsonl`
- **Rules**: `wazuh/custom-rules/intune-rules.xml` (range 100600-100699)

## Why JSONL + Wazuh `<localfile>` (and not direct API push)

1. **Reliability** — if Wazuh is down, JSONL files persist; events are not lost
2. **Replay** — can re-process historical JSONL by truncating Wazuh's read offset
3. **Decoupling** — Python pullers and Wazuh ingestion run on independent schedules
4. **Auditability** — JSONL files are human-readable forensic artifacts on their own

## Authentication Summary

| Tool | Auth method | Where stored |
|------|-------------|--------------|
| Okta | API Token (SSWS) | `OKTA_API_TOKEN` in `.env` |
| CrowdStrike | OAuth client credentials | `CROWDSTRIKE_CLIENT_ID/SECRET` in `.env` |
| Google Workspace | Service Account JSON + domain-wide delegation | `gws-service-account.json` mounted as Docker secret |
| 1Password | Service Account token + Events API token | `OP_*` in `.env` |
| Intune | App Registration client credentials (Microsoft Graph) | `INTUNE_*` in `.env` |
| Wazuh API | Basic Auth | `WAZUH_API_USER/PASSWORD` in `.env` |
| TheHive | Bearer token | `THEHIVE_API_KEY` in `.env` |
| Cortex | Bearer token | `CORTEX_API_KEY` in `.env` |

## Failure Modes & Graceful Degradation

| Failure | Impact | Mitigation |
|---------|--------|-----------|
| Trial expires (CrowdStrike, GWS, 1Password, Intune) | sync command returns auth error | Compliance collector logs `source_unavailable: true` for affected controls; rest of platform continues |
| Wazuh manager down | New events buffered as JSONL but not indexed | Restart manager; agent re-reads from offset |
| TheHive down | Cases not created from new alerts | n8n retries with backoff; manual queue review |
| Python container down | Active response calls fail | Wazuh logs failure; manual remediation via runbook |
| Network partition | All trial tool sync fails | Retries via `urllib3.Retry(total=3, backoff_factor=1)` |
