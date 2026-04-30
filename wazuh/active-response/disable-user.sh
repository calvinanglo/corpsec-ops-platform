#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Active Response: disable Okta user
# Triggered by: DLP HIGH/CRITICAL (100102, 100103), AI exfil CRITICAL (100201, 100202)
# Receives JSON alert on stdin from Wazuh manager
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
PYTHON_API="${CORPSEC_PYTHON_API:-http://corpsec-python:8080}"

log() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') corpsec-disable-user: $*" >> "$LOG_FILE"
}

# Parse alert from stdin (JSON from Wazuh)
ALERT_JSON=$(cat)
USER_EMAIL=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.data.user // .parameters.alert.data.actor.email // empty')
RULE_ID=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.rule.id // "unknown"')
ALERT_ID=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.id // "unknown"')

log "Triggered by rule $RULE_ID, alert $ALERT_ID, user=$USER_EMAIL"

if [[ -z "$USER_EMAIL" || "$USER_EMAIL" == "null" ]]; then
    log "ERROR: No user identified in alert - cannot disable"
    exit 1
fi

# Call Python remediation API to disable Okta user
RESPONSE=$(curl -sf -X POST "${PYTHON_API}/remediate/disable-user" \
    -H "Content-Type: application/json" \
    -d "{\"user_email\":\"${USER_EMAIL}\",\"reason\":\"Wazuh rule ${RULE_ID}\",\"alert_id\":\"${ALERT_ID}\"}" \
    2>&1) || {
    log "ERROR: API call failed - $RESPONSE"
    exit 1
}

log "SUCCESS: Disabled user $USER_EMAIL - $RESPONSE"
exit 0
