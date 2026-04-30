"""Okta User Lifecycle Management — JML automation.

Joiner / Mover / Leaver workflows for the SOC team. Wraps the Okta Management
API with audit logging.

Operations:
  - joiner: create user + assign to default groups + enrollment email
  - mover: change group memberships (department transfer)
  - leaver: deactivate + clear sessions + transfer file ownership (manual)
  - certify: quarterly access review report (CSV export of user-role matrix)
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from integrations.okta.okta_client import OktaClient

logger = logging.getLogger(__name__)
AUDIT_LOG = Path(os.getenv("AUDIT_LOG_PATH", "/var/log/corpsec/audit.jsonl"))


def _audit(action: str, user: str, details: dict | None = None) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "okta-lifecycle",
        "action": action,
        "user": user,
        "details": details or {},
        "operator": os.getenv("USER", "unknown"),
    }
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


class UserLifecycle:
    def __init__(self, client: OktaClient | None = None):
        self.client = client or OktaClient()

    # ── Joiner ─────────────────────────────────────────────────────────────
    def joiner(self, email: str, first_name: str, last_name: str, groups: list[str] | None = None) -> dict:
        body = {
            "profile": {
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "login": email,
            },
            "credentials": {
                "password": {"value": _generate_temp_password()},
            },
        }
        r = self.client.session.post(f"{self.client.org_url}/api/v1/users?activate=true", json=body)
        r.raise_for_status()
        user = r.json()
        user_id = user["id"]

        for group_name in (groups or []):
            self._add_to_group(user_id, group_name)

        _audit("joiner", email, {"user_id": user_id, "groups": groups or []})
        logger.info("Joiner: created %s with groups=%s", email, groups)
        return {"user_id": user_id, "email": email}

    # ── Mover ──────────────────────────────────────────────────────────────
    def mover(self, email: str, add_groups: list[str] | None = None, remove_groups: list[str] | None = None) -> dict:
        user_id = self.client._lookup_user_id(email)
        for g in (add_groups or []):
            self._add_to_group(user_id, g)
        for g in (remove_groups or []):
            self._remove_from_group(user_id, g)
        _audit("mover", email, {"user_id": user_id, "added": add_groups or [], "removed": remove_groups or []})
        return {"user_id": user_id, "added": add_groups, "removed": remove_groups}

    # ── Leaver ─────────────────────────────────────────────────────────────
    def leaver(self, email: str) -> dict:
        user_id = self.client._lookup_user_id(email)
        self.client.session.post(f"{self.client.org_url}/api/v1/users/{user_id}/lifecycle/deactivate")
        self.client.clear_user_sessions(email)
        _audit("leaver", email, {"user_id": user_id})
        logger.info("Leaver: deactivated %s + cleared sessions", email)
        return {"user_id": user_id, "status": "deactivated"}

    # ── Certify (access review export for SOC 2 CC6.1) ─────────────────────
    def certify(self, output_csv: str = "compliance/evidence/access-review.csv") -> int:
        users = self.client._paged("/api/v1/users")
        out_path = Path(output_csv)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["email", "status", "created", "lastLogin", "groups"])
            for u in users:
                groups = self._user_groups(u["id"])
                writer.writerow([
                    u["profile"].get("email"),
                    u.get("status"),
                    u.get("created"),
                    u.get("lastLogin", "never"),
                    ";".join(g.get("profile", {}).get("name", "") for g in groups),
                ])
        _audit("certify_export", "all", {"user_count": len(users), "output": str(out_path)})
        logger.info("Certified access review for %d users → %s", len(users), output_csv)
        return len(users)

    # ── Helpers ────────────────────────────────────────────────────────────
    def _add_to_group(self, user_id: str, group_name: str) -> None:
        group_id = self._group_id(group_name)
        self.client.session.put(f"{self.client.org_url}/api/v1/groups/{group_id}/users/{user_id}")

    def _remove_from_group(self, user_id: str, group_name: str) -> None:
        group_id = self._group_id(group_name)
        self.client.session.delete(f"{self.client.org_url}/api/v1/groups/{group_id}/users/{user_id}")

    def _group_id(self, group_name: str) -> str:
        r = self.client.session.get(f"{self.client.org_url}/api/v1/groups?q={group_name}")
        r.raise_for_status()
        groups = r.json()
        if not groups:
            raise RuntimeError(f"Group '{group_name}' not found")
        return groups[0]["id"]

    def _user_groups(self, user_id: str) -> list[dict]:
        r = self.client.session.get(f"{self.client.org_url}/api/v1/users/{user_id}/groups")
        r.raise_for_status()
        return r.json()


def _generate_temp_password(length: int = 16) -> str:
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Okta JML lifecycle automation")
    sub = parser.add_subparsers(dest="cmd")

    j = sub.add_parser("joiner")
    j.add_argument("--email", required=True)
    j.add_argument("--first-name", required=True)
    j.add_argument("--last-name", required=True)
    j.add_argument("--groups", default="", help="Comma-separated group names")

    m = sub.add_parser("mover")
    m.add_argument("--email", required=True)
    m.add_argument("--add-groups", default="")
    m.add_argument("--remove-groups", default="")

    l = sub.add_parser("leaver")
    l.add_argument("--email", required=True)

    c = sub.add_parser("certify")
    c.add_argument("--output", default="compliance/evidence/access-review.csv")

    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        sys.exit(0)

    lifecycle = UserLifecycle()
    if args.cmd == "joiner":
        groups = [g.strip() for g in args.groups.split(",") if g.strip()]
        result = lifecycle.joiner(args.email, args.first_name, args.last_name, groups)
        print(json.dumps(result, indent=2))
    elif args.cmd == "mover":
        add = [g.strip() for g in args.add_groups.split(",") if g.strip()]
        remove = [g.strip() for g in args.remove_groups.split(",") if g.strip()]
        result = lifecycle.mover(args.email, add, remove)
        print(json.dumps(result, indent=2))
    elif args.cmd == "leaver":
        result = lifecycle.leaver(args.email)
        print(json.dumps(result, indent=2))
    elif args.cmd == "certify":
        count = lifecycle.certify(args.output)
        print(f"Certified {count} users → {args.output}")


if __name__ == "__main__":
    main()
