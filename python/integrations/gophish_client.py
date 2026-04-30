"""GoPhish API client for phishing campaign automation."""
from __future__ import annotations

import argparse
import logging
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class GoPhishClient:
    def __init__(self):
        self.base_url = os.getenv("GOPHISH_URL", "https://gophish:3333").rstrip("/")
        self.api_key = os.getenv("GOPHISH_API_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": self.api_key})
        self.session.verify = False

    def list_campaigns(self) -> list[dict]:
        r = self.session.get(f"{self.base_url}/api/campaigns/")
        r.raise_for_status()
        return r.json()

    def get_campaign_results(self, campaign_id: int) -> dict:
        r = self.session.get(f"{self.base_url}/api/campaigns/{campaign_id}/results")
        r.raise_for_status()
        return r.json()

    def launch_campaign(self, name: str, template_name: str, page_name: str, group_name: str, smtp_name: str, url: str) -> dict:
        body = {
            "name": name,
            "template": {"name": template_name},
            "page": {"name": page_name},
            "url": url,
            "smtp": {"name": smtp_name},
            "groups": [{"name": group_name}],
        }
        r = self.session.post(f"{self.base_url}/api/campaigns/", json=body)
        r.raise_for_status()
        return r.json()


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    launch = sub.add_parser("launch")
    launch.add_argument("--campaign", default="credential-harvest")

    sub.add_parser("results")
    sub.add_parser("list")

    args = parser.parse_args()
    if args.cmd is None:
        parser.print_help()
        sys.exit(0)

    client = GoPhishClient()
    if args.cmd == "list":
        for c in client.list_campaigns():
            print(f"  [{c['id']}] {c['name']} — status: {c['status']}")
    elif args.cmd == "results":
        for c in client.list_campaigns():
            results = client.get_campaign_results(c["id"])
            stats = results.get("stats", {})
            print(f"  [{c['id']}] {c['name']}: sent={stats.get('sent', 0)} clicked={stats.get('clicked', 0)} submitted={stats.get('submitted_data', 0)}")
    elif args.cmd == "launch":
        result = client.launch_campaign(
            name=f"corpsec-{args.campaign}",
            template_name="Password Reset Urgent",
            page_name="Fake Okta Login",
            group_name="All Employees",
            smtp_name="MailHog",
            url="http://gophish:8080",
        )
        print(f"Campaign launched: {result.get('id', result)}")


if __name__ == "__main__":
    main()
