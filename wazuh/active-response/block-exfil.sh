#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Active Response: block exfiltration destination
# Triggered by: AI exfil rules (100201, 100202, 100203)
# Adds destination domain/IP to DNS sinkhole + proxy block list
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
PYTHON_API="${CORPSEC_PYTHON_API:-http://corpsec-python:8080}"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') corpsec-block-exfil: $*" >> "$LOG_FILE"
}

ALERT_JSON=$(cat)
DESTINATION=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.data.ai_service // .parameters.alert.data.destination // empty')
USER=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.data.user // empty')
RULE_ID=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.rule.id // "unknown"')

log "Triggered by rule $RULE_ID, destination=$DESTINATION, user=$USER"

if [[ -z "$DESTINATION" || "$DESTINATION" == "null" ]]; then
    log "ERROR: No destination identified - cannot block"
    exit 1
fi

RESPONSE=$(curl -sf -X POST "${PYTHON_API}/remediate/block-domain" \
    -H "Content-Type: application/json" \
    -d "{\"domain\":\"${DESTINATION}\",\"user\":\"${USER}\",\"reason\":\"Wazuh rule ${RULE_ID}\",\"duration_seconds\":3600}" \
    2>&1) || {
    log "ERROR: Block API failed - $RESPONSE"
    exit 1
}

log "SUCCESS: Blocked $DESTINATION for 3600s - $RESPONSE"
exit 0
