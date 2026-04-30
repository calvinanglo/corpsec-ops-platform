"""Google Workspace DLP rule manager.

Lists and exports GWS DLP rules for version control + compliance evidence.
GWS DLP API is part of the Drive API and Admin SDK.

Note: Creating/modifying rules requires `dlp:rules` admin scope (not commonly
exposed in service-account-only setups). This module focuses on read operations.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from integrations.google_workspace.gws_admin_client import GWSAdminClient

logger = logging.getLogger(__name__)


class DLPRuleManager:
    """Read GWS DLP rules + export for git versioning."""

    def __init__(self, client: GWSAdminClient | None = None):
        self.client = client or GWSAdminClient()

    def list_rules(self) -> list[dict]:
        """Get all DLP rules from GWS DLP API.

        Implementation note: full DLP rule retrieval requires the Workspace
        DLP API which has limited Python client support. This stub queries
        recent DLP-tagged audit events as a proxy for active rules.
        """
        events = self.client.get_audit_activities("drive", since_minutes=7 * 24 * 60)
        # Filter to DLP rule triggers — each unique RULE_NAME = an active rule
        rule_names: set[str] = set()
        for event in events:
            for e in event.get("events", []):
                if e.get("name") == "RULE_TRIGGERED":
                    for p in e.get("parameters", []):
                        if p.get("name") == "RULE_NAME":
                            rule_names.add(p.get("value", "unknown"))
        return [{"rule_name": rn, "discovered_via": "audit_log"} for rn in rule_names]

    def export_rules(self, output_dir: str = "integrations/google_workspace/dlp-rules") -> int:
        """Export all DLP rules to JSON for git diff-based change tracking."""
        rules = self.list_rules()
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        manifest = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "rule_count": len(rules),
            "rules": rules,
        }
        (out_path / "_manifest.json").write_text(json.dumps(manifest, indent=2))
        logger.info("Exported %d DLP rule(s) to %s/", len(rules), output_dir)
        return len(rules)


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("list", help="List active DLP rules")
    export_p = sub.add_parser("export", help="Export rules to JSON")
    export_p.add_argument("--output-dir", default="integrations/google_workspace/dlp-rules")
    args = parser.parse_args()

    mgr = DLPRuleManager()
    if args.cmd == "list":
        for r in mgr.list_rules():
            print(f"  - {r['rule_name']}")
    elif args.cmd == "export":
        n = mgr.export_rules(args.output_dir)
        print(f"Exported {n} rule(s)")


if __name__ == "__main__":
    main()
