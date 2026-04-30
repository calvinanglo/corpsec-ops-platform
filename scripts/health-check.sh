#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Health check for all services
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

PROJECT_NAME="corpsec"
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'

failed=0; passed=0; skipped=0

check() {
    local name="$1"; local container="$2"; local cmd="$3"
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        printf "  [%bSKIP%b] %-30s container not running\n" "$YELLOW" "$NC" "$name"
        ((skipped++)); return
    fi
    if docker exec "$container" sh -c "$cmd" >/dev/null 2>&1; then
        printf "  [ %bOK%b ] %-30s healthy\n" "$GREEN" "$NC" "$name"
        ((passed++))
    else
        printf "  [%bFAIL%b] %-30s health check failed\n" "$RED" "$NC" "$name"
        ((failed++))
    fi
}

echo "═════════════════════════════════════════════════════════════════"
echo "  corpsec-ops-platform — Health Check"
echo "═════════════════════════════════════════════════════════════════"
echo ""
echo "  Core stack:"
check "nginx"            "corpsec-nginx"           "nginx -t"
check "wazuh-manager"    "corpsec-wazuh-manager"   "curl -sk https://localhost:55000 -u wazuh-wui:\$API_PASSWORD || true"
check "wazuh-indexer"    "corpsec-wazuh-indexer"   "curl -sk https://localhost:9200 -u admin:admin > /dev/null"
check "wazuh-dashboard"  "corpsec-wazuh-dashboard" "curl -sk https://localhost:5601/api/status > /dev/null"
check "thehive"          "corpsec-thehive"         "curl -sf http://localhost:9000/api/v1/status > /dev/null"
check "cortex"           "corpsec-cortex"          "curl -sf http://localhost:9001/api/status > /dev/null"
check "thehive-db"       "corpsec-thehive-db"      "nodetool status | grep -q '^UN'"
check "thehive-index"    "corpsec-thehive-index"   "curl -sf http://localhost:9200/_cluster/health > /dev/null"
check "grafana"          "corpsec-grafana"         "wget -q --spider http://localhost:3000/api/health"
check "prometheus"       "corpsec-prometheus"      "wget -q --spider http://localhost:9090/-/healthy"
check "loki"             "corpsec-loki"            "wget -q --spider http://localhost:3100/ready"
check "alertmanager"     "corpsec-alertmanager"    "wget -q --spider http://localhost:9093/-/healthy"

echo ""
echo "  SOAR overlay:"
check "n8n"              "corpsec-n8n"             "wget -q --spider http://localhost:5678/healthz"
check "corpsec-python"   "corpsec-python"          "curl -sf http://localhost:8080/health > /dev/null"

echo ""
echo "  Phishing overlay:"
check "gophish"          "corpsec-gophish"         "wget -q --spider http://localhost:3333/api/util/ping"
check "mailhog"          "corpsec-mailhog"         "wget -q --spider http://localhost:8025"

echo ""
echo "═════════════════════════════════════════════════════════════════"
printf "  Passed: %b%d%b   Failed: %b%d%b   Skipped: %b%d%b\n" "$GREEN" $passed "$NC" "$RED" $failed "$NC" "$YELLOW" $skipped "$NC"
echo "═════════════════════════════════════════════════════════════════"

exit $failed
