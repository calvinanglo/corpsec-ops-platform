#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# corpsec-ops-platform — Screenshot capture progress tracker
# Counts collected screenshots vs target, computes trial-deadline urgency
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCREENSHOTS_DIR="${SCREENSHOTS_DIR:-screenshots}"
TRACK_FILE="${TRACK_FILE:-trial-tracking.txt}"
GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'

# ── Required counts per tool (from docs/08-screenshot-checklist.md) ──
declare -A REQUIRED=(
    [okta]=6
    [crowdstrike]=6
    [google-workspace]=6
    [1password]=6
    [intune]=7
    [wazuh]=6
    [gophish]=5
    [thehive]=5
    [grafana]=7
    [architecture]=1
)

# ── Trial expiry awareness ──
days_remaining() {
    local tool="$1"
    if [[ ! -f "$TRACK_FILE" ]]; then echo "?"; return; fi
    case "$tool" in
        okta)               echo "∞" ;;
        intune)             echo "30 from start" ;;
        crowdstrike|google-workspace|1password)
                            echo "14 from start" ;;
        *)                  echo "n/a" ;;
    esac
}

color_for_progress() {
    local pct=$1
    if (( pct >= 100 )); then echo "$GREEN"
    elif (( pct >= 50 )); then echo "$YELLOW"
    else echo "$RED"
    fi
}

total_required=0
total_collected=0

echo "═════════════════════════════════════════════════════════════════"
echo "  Screenshot Capture Progress"
echo "═════════════════════════════════════════════════════════════════"
echo ""
printf "  %-20s %-12s %-15s %s\n" "Tool" "Collected" "Trial" "Progress"
printf "  %-20s %-12s %-15s %s\n" "----" "---------" "-----" "--------"

for tool in "${!REQUIRED[@]}"; do
    target=${REQUIRED[$tool]}
    dir="$SCREENSHOTS_DIR/$tool"
    if [[ -d "$dir" ]]; then
        count=$(find "$dir" -maxdepth 1 -type f \( -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" \) | wc -l | tr -d ' ')
    else
        count=0
    fi
    pct=$(( count * 100 / target ))
    color=$(color_for_progress $pct)
    days=$(days_remaining "$tool")

    printf "  %-20s %b%d/%d%b      %-15s %d%%\n" "$tool" "$color" "$count" "$target" "$NC" "$days" "$pct"

    total_required=$(( total_required + target ))
    total_collected=$(( total_collected + count ))
done

echo ""
total_pct=$(( total_collected * 100 / total_required ))
total_color=$(color_for_progress $total_pct)
printf "  %-20s %b%d/%d%b      Overall:        %d%%\n" "TOTAL" "$total_color" "$total_collected" "$total_required" "$NC" "$total_pct"

echo ""
echo "═════════════════════════════════════════════════════════════════"

if (( total_pct < 100 )); then
    echo ""
    echo "  Next steps:"
    echo "    1. Sign in to the tool consoles"
    echo "    2. Capture missing screenshots per docs/08-screenshot-checklist.md"
    echo "    3. Save as PNG at NN-feature-name.png in the right subdirectory"
    echo "    4. Re-run this script to confirm"
    echo ""
    echo "  Trial deadline reminders:"
    [[ -f "$TRACK_FILE" ]] && grep -E "Expires" "$TRACK_FILE" || echo "    Run 'bash scripts/init-trials.sh' first"
else
    echo ""
    echo "  ${GREEN}All screenshots captured! Push to GitHub for portfolio review.${NC}"
fi
