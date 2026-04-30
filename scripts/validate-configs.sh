#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Validate config files (YAML, JSON, XML)
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

errors=0

check() {
    local file="$1"; local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        printf "  [ OK ] %s\n" "$file"
    else
        printf "  [FAIL] %s\n" "$file"
        ((errors++))
    fi
}

echo "═════════════════════════════════════════════════════════════════"
echo "  Validating config files..."
echo "═════════════════════════════════════════════════════════════════"

echo ""
echo "  Docker Compose files:"
for f in docker-compose*.yml; do
    [[ -f "$f" ]] && check "$f" "docker compose -f $f config -q"
done

echo ""
echo "  YAML files:"
for f in $(find . -name "*.yml" -o -name "*.yaml" \
    | grep -vE "(node_modules|\.git|venv|compliance/evidence)"); do
    check "$f" "python3 -c 'import yaml,sys; yaml.safe_load(open(\"$f\"))'"
done

echo ""
echo "  JSON files:"
for f in $(find n8n grafana gophish thehive -name "*.json" 2>/dev/null); do
    check "$f" "python3 -m json.tool < $f > /dev/null"
done

echo ""
echo "  XML files (Wazuh rules + decoders):"
for f in $(find wazuh -name "*.xml" 2>/dev/null); do
    check "$f" "python3 -c 'import xml.etree.ElementTree as ET; ET.parse(\"$f\")'"
done

echo ""
echo "  Python syntax (compile check):"
for f in $(find python -name "*.py" 2>/dev/null); do
    check "$f" "python3 -m py_compile $f"
done

echo ""
echo "═════════════════════════════════════════════════════════════════"
if (( errors == 0 )); then
    echo "  All config files valid"
else
    echo "  $errors errors found"
fi
echo "═════════════════════════════════════════════════════════════════"

exit $errors
