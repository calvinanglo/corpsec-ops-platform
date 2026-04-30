"""Okta Conditional Access (sign-on policies) — policy-as-code.

Export current sign-on policies and rules to JSON for git versioning.
Detect drift by comparing exports across runs.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from integrations.okta.okta_client import OktaClient

logger = logging.getLogger(__name__)


class ConditionalAccessManager:
    def __init__(self, client: OktaClient | None = None):
        self.client = client or OktaClient()

    # ── Read operations ────────────────────────────────────────────────────
    def list_sign_on_policies(self) -> list[dict]:
        """All sign-on policies (Okta calls these access policies)."""
        return self.client._paged("/api/v1/policies?type=ACCESS_POLICY")

    def list_mfa_policies(self) -> list[dict]:
        return self.client._paged("/api/v1/policies?type=MFA_ENROLL")

    def list_password_policies(self) -> list[dict]:
        return self.client._paged("/api/v1/policies?type=PASSWORD")

    def get_policy_rules(self, policy_id: str) -> list[dict]:
        url = f"/api/v1/policies/{policy_id}/rules"
        return self.client._paged(url)

    # ── Export for compliance + version control ────────────────────────────
    def export_all(self, output_dir: str = "integrations/okta/policies") -> int:
        """Export all sign-on, MFA, and password policies to JSON files."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        total = 0

        for policy_type, fetcher in (
            ("sign-on", self.list_sign_on_policies),
            ("mfa-enroll", self.list_mfa_policies),
            ("password", self.list_password_policies),
        ):
            try:
                policies = fetcher()
            except Exception as exc:
                logger.warning("Failed to fetch %s policies: %s", policy_type, exc)
                continue
            for p in policies:
                # Hydrate with rules
                rules = self.get_policy_rules(p["id"])
                p["_rules"] = rules
                # Write
                safe_name = p.get("name", "unnamed").replace(" ", "_").replace("/", "_").lower()
                out_file = out / f"{policy_type}-{safe_name}.json"
                out_file.write_text(json.dumps(p, indent=2, sort_keys=True))
                total += 1

        # Manifest
        manifest = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "policy_count": total,
        }
        (out / "_manifest.json").write_text(json.dumps(manifest, indent=2))
        logger.info("Exported %d Okta policies to %s/", total, output_dir)
        return total


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Okta conditional access / policy-as-code")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("list", help="List all policies")
    export_p = sub.add_parser("export", help="Export policies to JSON")
    export_p.add_argument("--output-dir", default="integrations/okta/policies")
    args = parser.parse_args()

    mgr = ConditionalAccessManager()
    if args.cmd == "list":
        for p in mgr.list_sign_on_policies():
            print(f"  - {p['name']} ({p['status']})")
    elif args.cmd == "export":
        count = mgr.export_all(args.output_dir)
        print(f"Exported {count} policies")


if __name__ == "__main__":
    main()
