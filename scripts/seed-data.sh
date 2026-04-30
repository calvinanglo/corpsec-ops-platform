#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Seed demo data for Grafana dashboards
# Generates synthetic alerts to validate the full pipeline without waiting
# for real production tool events
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

PYTHON_API="${PYTHON_API:-http://localhost:8080}"

echo "═════════════════════════════════════════════════════════════════"
echo "  Seeding demo data..."
echo "═════════════════════════════════════════════════════════════════"

# DLP scan against test data
echo ""
echo "[+] Triggering DLP scans..."
docker exec corpsec-python python -c "
from dlp.engine import DLPEngine
from dlp.reporter import DLPReporter
from pathlib import Path

engine = DLPEngine()
reporter = DLPReporter()

# Scan synthetic content
test_cases = [
    ('user_alice@corpsec.local', 'Client Doe SSN: 123-45-6789, see matter file'),
    ('user_bob@corpsec.local', 'Credit card on file: 4532 1488 0343 6467'),
    ('user_carol@corpsec.local', 'AKIAIOSFODNN7EXAMPLE was the demo key'),
]
for user, text in test_cases:
    matches = engine.scan_text(text, {'file_path': '/demo/sample.txt'})
    if matches:
        from dlp.engine import DLPScanResult
        from datetime import datetime, timezone
        result = DLPScanResult(resource='/demo/sample.txt', scanned_at=datetime.now(timezone.utc).isoformat(), matches=matches)
        reporter.report(result, user=user)
        print(f'  {user}: {len(matches)} matches → {result.severity}')
"

# AI exfiltration detection scenarios
echo ""
echo "[+] Triggering AI exfiltration detection..."
docker exec corpsec-python python -m ai_detection.detector --sample

# Synthetic Wazuh alerts (would normally come from real tool sync)
echo ""
echo "[+] Generating synthetic alerts..."
for i in 1 2 3; do
    docker exec corpsec-wazuh-manager bash -c "
        echo '{\"source\":\"crowdstrike\",\"timestamp\":\"$(date -Iseconds)\",\"detection\":{\"tactic\":\"Execution\",\"technique\":\"Suspicious PowerShell\"},\"severity_int\":75,\"severity_label\":\"High\",\"device\":{\"hostname\":\"demo-host-$i\"}}' >> /var/log/corpsec/crowdstrike-detections.jsonl
    " 2>/dev/null || true
done

echo ""
echo "[+] Seeding complete. Check:"
echo "    Wazuh dashboard:  https://corpsec.local:5443  (alerts in last 5 min)"
echo "    TheHive:          https://corpsec.local:9443  (auto-created cases)"
echo "    Grafana SOC:      https://corpsec.local:3443  (DLP + AI panels populated)"
