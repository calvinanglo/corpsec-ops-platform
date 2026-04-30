"""1Password Service Account management.

Manage service accounts via the `op` CLI (admin operations) and the
1Password Connect server (programmatic vault access).

Common operations:
  - List service accounts
  - Rotate service account tokens (manual via UI; CLI doesn't support this yet)
  - List items in a vault accessible to a service account
  - Audit recent access patterns
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from typing import Any

logger = logging.getLogger(__name__)


class ServiceAccountManager:
    """Wraps `op` CLI for service account operations."""

    def __init__(self):
        if not os.getenv("OP_SERVICE_ACCOUNT_TOKEN"):
            raise RuntimeError("OP_SERVICE_ACCOUNT_TOKEN must be set")

    def _run(self, args: list[str]) -> dict | list:
        cmd = ["op"] + args + ["--format=json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout) if result.stdout.strip() else []

    # ── Service account operations ─────────────────────────────────────────
    def list_service_accounts(self) -> list[dict]:
        return self._run(["service-account", "list"])

    def get_service_account(self, name_or_id: str) -> dict:
        return self._run(["service-account", "get", name_or_id])

    def list_accessible_vaults(self) -> list[dict]:
        """Vaults the current service account can access."""
        return self._run(["vault", "list"])

    def list_items(self, vault: str) -> list[dict]:
        """Items in a specific vault."""
        return self._run(["item", "list", f"--vault={vault}"])

    # ── Audit + rotation reminders ─────────────────────────────────────────
    def audit_summary(self) -> dict:
        """Quick health summary for compliance evidence."""
        accounts = self.list_service_accounts()
        return {
            "service_account_count": len(accounts),
            "accounts": [
                {
                    "name": a.get("name"),
                    "id": a.get("id"),
                    "created_at": a.get("created_at"),
                }
                for a in accounts
            ],
        }


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="1Password service account manager")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("list-accounts", help="List all service accounts")
    sub.add_parser("list-vaults", help="List vaults accessible to current service account")
    items_p = sub.add_parser("list-items", help="List items in a vault")
    items_p.add_argument("--vault", required=True)
    sub.add_parser("audit", help="Audit summary for compliance evidence")
    args = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        sys.exit(0)

    mgr = ServiceAccountManager()
    if args.cmd == "list-accounts":
        print(json.dumps(mgr.list_service_accounts(), indent=2))
    elif args.cmd == "list-vaults":
        print(json.dumps(mgr.list_accessible_vaults(), indent=2))
    elif args.cmd == "list-items":
        print(json.dumps(mgr.list_items(args.vault), indent=2))
    elif args.cmd == "audit":
        print(json.dumps(mgr.audit_summary(), indent=2))


if __name__ == "__main__":
    main()
