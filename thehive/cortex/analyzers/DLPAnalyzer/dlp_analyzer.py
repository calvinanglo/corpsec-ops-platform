#!/usr/bin/env python3
"""DLPAnalyzer — Cortex analyzer.

Sends an observable to the corpsec-python /dlp/scan endpoint, returns
matched policies, confidence scores, and recommended containment.
"""
from __future__ import annotations

import requests
from cortexutils.analyzer import Analyzer


class DLPAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_url = self.get_param(
            "config.corpsec_python_url",
            "http://corpsec-python:8080",
        ).rstrip("/")

    def summary(self, full_report):
        match_count = full_report.get("match_count", 0)
        severity = full_report.get("severity", "NONE")
        level = "info" if match_count == 0 else (
            "suspicious" if severity in ("LOW", "MEDIUM") else "malicious"
        )
        return {
            "taxonomies": [{
                "namespace": "DLP",
                "predicate": severity,
                "value": str(match_count),
                "level": level,
            }]
        }

    def run(self):
        Analyzer.run(self)
        observable = self.get_data()

        try:
            if self.data_type == "file" or self.data_type == "filename":
                payload = {"file_path": observable}
            else:
                payload = {"text": observable}

            r = requests.post(f"{self.api_url}/dlp/scan", json=payload, timeout=30)
            r.raise_for_status()
            result = r.json()

            recommended_action = self._recommend(result)
            result["recommended_action"] = recommended_action
            self.report(result)
        except Exception as exc:
            self.error(str(exc))

    def _recommend(self, result: dict) -> str:
        sev = result.get("severity", "NONE")
        if sev == "CRITICAL":
            return "Auto-quarantine + disable user (PB-DLP-001)"
        if sev == "HIGH":
            return "Auto-quarantine + open case for L2 (PB-DLP-001)"
        if sev == "MEDIUM":
            return "Open case for L1 triage (PB-DLP-002)"
        if sev == "LOW":
            return "Log to Wazuh; tune if recurring false positive"
        return "No action required"


if __name__ == "__main__":
    DLPAnalyzer().run()
