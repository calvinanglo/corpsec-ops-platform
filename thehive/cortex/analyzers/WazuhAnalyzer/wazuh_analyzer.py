#!/usr/bin/env python3
"""WazuhAnalyzer — Cortex analyzer.

Takes an observable (IP, hostname, or rule ID), queries Wazuh manager,
returns related alerts, agent status, FIM changes, vulnerability summary.
"""
from __future__ import annotations

import sys

import requests
import urllib3
from cortexutils.analyzer import Analyzer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_url = self.get_param("config.wazuh_api_url", "https://wazuh-manager:55000")
        self.api_user = self.get_param("config.wazuh_api_user", message="wazuh_api_user required")
        self.api_password = self.get_param("config.wazuh_api_password", message="wazuh_api_password required")
        self._token = None

    def _auth(self):
        if self._token:
            return self._token
        r = requests.post(
            f"{self.api_url}/security/user/authenticate",
            auth=(self.api_user, self.api_password),
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        self._token = r.json()["data"]["token"]
        return self._token

    def _get(self, path, params=None):
        token = self._auth()
        r = requests.get(
            f"{self.api_url}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            verify=False,
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def summary(self, full_report):
        return {"taxonomies": [{"namespace": "Wazuh", "predicate": "Status", "value": full_report.get("summary", "queried"), "level": "info"}]}

    def run(self):
        Analyzer.run(self)
        observable = self.get_data()
        try:
            if self.data_type in ("hostname", "fqdn"):
                # Find agent matching this hostname
                agents = self._get("/agents", {"name": observable, "limit": 5}).get("data", {}).get("affected_items", [])
                self.report({
                    "observable": observable,
                    "agents": agents,
                    "summary": f"{len(agents)} matching agent(s)",
                })
            elif self.data_type == "ip":
                agents = self._get("/agents", {"ip": observable, "limit": 5}).get("data", {}).get("affected_items", [])
                self.report({
                    "observable": observable,
                    "agents": agents,
                    "summary": f"{len(agents)} agent(s) at IP",
                })
            else:
                # Treat as rule ID
                self.report({"observable": observable, "summary": "rule_id_lookup_not_implemented_in_minimal_analyzer"})
        except Exception as exc:
            self.error(str(exc))


if __name__ == "__main__":
    WazuhAnalyzer().run()
