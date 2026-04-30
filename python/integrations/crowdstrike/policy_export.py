"""Export CrowdStrike prevention policies to JSON for git-based version control.

Run periodically (e.g., monthly via n8n). Diff the export to detect drift
between current Falcon config and the version-controlled baseline.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from integrations.crowdstrike.falcon_client import FalconClient

logger = logging.getLogger(__name__)


def export_policies(output_dir: str = "integrations/crowdstrike/policies") -> int:
    """Export all CrowdStrike prevention policies to JSON files."""
    client = FalconClient()
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Falcon SDK exposes prevention policies via PreventionPolicies module
    try:
        result = client._policies.query_combined_prevention_policies(limit=100)
    except Exception as exc:
        logger.error("Failed to query Falcon policies: %s", exc)
        return 0

    policies = result.get("body", {}).get("resources", [])
    written = 0
    for p in policies:
        name = p.get("name", "unnamed").replace(" ", "_").lower()
        platform = p.get("platform_name", "unknown").lower()
        out_file = output_path / f"{platform}-{name}.json"
        out_file.write_text(json.dumps(p, indent=2, sort_keys=True))
        written += 1
        logger.info("Exported policy %s → %s", p.get("name"), out_file.name)

    # Write a manifest with timestamp + count for compliance evidence
    manifest = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "policy_count": written,
        "policies": [{"name": p.get("name"), "platform": p.get("platform_name"), "id": p.get("id")} for p in policies],
    }
    (output_path / "_manifest.json").write_text(json.dumps(manifest, indent=2))
    return written


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Export CrowdStrike policies for git version control")
    parser.add_argument("--output-dir", default="integrations/crowdstrike/policies")
    args = parser.parse_args()
    count = export_policies(args.output_dir)
    print(f"Exported {count} prevention policies to {args.output_dir}/")


if __name__ == "__main__":
    main()
