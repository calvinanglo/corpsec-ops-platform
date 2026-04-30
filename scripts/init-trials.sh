#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Trial sign-up tracker
# Records start dates for parallel trials and computes expiry deadlines
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

TRACK_FILE="${TRACK_FILE:-trial-tracking.txt}"
TODAY=$(date +%Y-%m-%d)

cat > "$TRACK_FILE" <<EOF
═════════════════════════════════════════════════════════════════
  corpsec-ops-platform — Trial Tracking
  Generated: $TODAY
═════════════════════════════════════════════════════════════════

| Tool                  | Sign-up date | Expires      | Days left |
|-----------------------|--------------|--------------|-----------|
| Okta Developer Free   | $TODAY       | NEVER        | ∞         |
| Microsoft Intune      | $TODAY       | $(date -d "+30 days" +%Y-%m-%d) | 30       |
| CrowdStrike Falcon    | $TODAY       | $(date -d "+14 days" +%Y-%m-%d) | 14       |
| Google Workspace      | $TODAY       | $(date -d "+14 days" +%Y-%m-%d) | 14       |
| 1Password Business    | $TODAY       | $(date -d "+14 days" +%Y-%m-%d) | 14       |

═════════════════════════════════════════════════════════════════
  Screenshot deadlines (be done 2 days before expiry):
    14-day trials:  $(date -d "+12 days" +%Y-%m-%d)
    30-day trial:   $(date -d "+28 days" +%Y-%m-%d)

  Daily reminder schedule:
    Day  3:  Verify all .env credentials work, sync events
    Day  7:  Verify Wazuh ingestion of all 5 sources
    Day 12:  Capture remaining 14-day-trial screenshots
    Day 28:  Capture Intune screenshots, decide on conversion
═════════════════════════════════════════════════════════════════
EOF

cat "$TRACK_FILE"
echo ""
echo "[+] Tracking written to $TRACK_FILE"
echo "[+] Next: edit .env with credentials from each trial console"
echo "[+] Then: make up-all && make sync-all && make health"
