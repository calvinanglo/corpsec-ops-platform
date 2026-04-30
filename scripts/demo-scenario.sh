#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — End-to-end incident lifecycle demo
# Walks through: alert → triage → containment → remediation → case closure
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

PYTHON_API="${PYTHON_API:-http://localhost:8080}"

echo "═════════════════════════════════════════════════════════════════"
echo "  corpsec-ops-platform — Demo Scenario"
echo "  Simulating: 'CFO uploaded client matter PDF to ChatGPT personal'"
echo "═════════════════════════════════════════════════════════════════"

step() { echo ""; echo "─── $1 ───"; }

step "1. Simulate user attempt to upload corporate document to ChatGPT"
docker exec corpsec-python python -m ai_detection.detector \
    --user "cfo@corpsec.local" \
    --url "https://api.openai.com/v1/chat/completions" \
    --method POST \
    --bytes 250000

sleep 2

step "2. Wazuh ingests the AI exfil event (rule 100201)"
docker exec corpsec-wazuh-manager tail -n 5 /var/log/corpsec/ai-detection.jsonl
sleep 2

step "3. n8n webhook fires → POST /remediate/execute"
echo "  (n8n workflow 'wazuh-to-thehive' will create TheHive case + invoke remediation)"
sleep 2

step "4. Auto-remediation: PB-AI-001 playbook triggers"
echo "  Action 1: block_domain (api.openai.com → DNS sinkhole)"
echo "  Action 2: revoke_session (Okta clears all SSO sessions for cfo@corpsec.local)"

# Trigger explicitly for the demo
docker exec corpsec-python python -c "
from remediation.actions.block_domain import execute as block
from remediation.actions.revoke_session import execute as revoke

alert = {'data': {'domain': 'api.openai.com', 'user': 'cfo@corpsec.local'}, 'id': 'demo-1'}
print('  block_domain:', block(alert))

# revoke_session would call real Okta API — skip in demo unless creds present
print('  revoke_session: skipped (would call Okta in production)')
" || true

sleep 2

step "5. TheHive case created (visible at https://corpsec.local:9443)"
echo "  Title: '[PB-AI-001] AI exfil CRITICAL — cfo@corpsec.local'"
echo "  Tags: ai-exfil, critical, auto-remediation"
echo "  Tasks: review the runbook IR-004-ai-exfiltration.md"

step "6. Grafana dashboards updated"
echo "  - SOC Overview: AI Exfil Alerts counter +1"
echo "  - AI Exfil Monitor: cfo@corpsec.local appears in upload-volume chart"
echo "  - Incident Metrics: case count +1"

step "7. Compliance evidence updated"
echo "  - SOC 2 CC6.6 (Data Flow Controls) evidence captured"
echo "  - SOC 2 CC7.4 (Incident Response) case linked"

echo ""
echo "═════════════════════════════════════════════════════════════════"
echo "  Demo complete. Verify in:"
echo "    https://corpsec.local:5443  (Wazuh alerts)"
echo "    https://corpsec.local:9443  (TheHive cases)"
echo "    https://corpsec.local:3443  (Grafana dashboards)"
echo "═════════════════════════════════════════════════════════════════"
