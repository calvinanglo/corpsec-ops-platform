"""corpsec-ops-platform — Compliance evidence collector.

Iterates control mappings, queries the right source, hashes artifacts, writes
to compliance/evidence/{framework}/{control_id}/{date}/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from compliance.controls.soc2 import SOC2_CONTROLS, ControlSpec
from compliance.controls.iso27001 import ISO27001_CONTROLS

logger = logging.getLogger(__name__)

EVIDENCE_ROOT = Path(os.getenv("COMPLIANCE_EVIDENCE_ROOT", "/compliance/evidence"))


@dataclass
class EvidencePackage:
    framework: str
    control_id: str
    collected_at: str
    artifacts: list[dict] = field(default_factory=list)
    sha256: str = ""
    error: Optional[str] = None
    collector_version: str = "1.0.0"

    def as_dict(self) -> dict:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "collected_at": self.collected_at,
            "sha256": self.sha256,
            "error": self.error,
            "artifacts": self.artifacts,
            "collector_version": self.collector_version,
        }


class EvidenceCollector:
    """Orchestrates evidence collection for SOC 2 + ISO 27001."""

    def __init__(self, evidence_root: Path | str = EVIDENCE_ROOT):
        self.evidence_root = Path(evidence_root)

    def collect_all(self, framework: str = "all") -> list[EvidencePackage]:
        """Collect evidence for an entire framework (or both)."""
        packages: list[EvidencePackage] = []
        if framework in ("all", "soc2"):
            packages.extend(self._collect_framework("soc2", SOC2_CONTROLS))
        if framework in ("all", "iso27001"):
            packages.extend(self._collect_framework("iso27001", ISO27001_CONTROLS))
        return packages

    def collect_control(self, framework: str, control_id: str) -> Optional[EvidencePackage]:
        controls = SOC2_CONTROLS if framework == "soc2" else ISO27001_CONTROLS
        for ctrl in controls:
            if ctrl.control_id == control_id:
                return self._collect_one(framework, ctrl)
        return None

    # ── Internal ───────────────────────────────────────────────────────────
    def _collect_framework(self, framework: str, controls: list[ControlSpec]) -> list[EvidencePackage]:
        results = []
        for ctrl in controls:
            try:
                pkg = self._collect_one(framework, ctrl)
                results.append(pkg)
            except Exception as exc:
                logger.exception("Failed to collect %s/%s", framework, ctrl.control_id)
                results.append(EvidencePackage(
                    framework=framework,
                    control_id=ctrl.control_id,
                    collected_at=datetime.now(timezone.utc).isoformat(),
                    error=str(exc),
                ))
        return results

    def _collect_one(self, framework: str, ctrl: ControlSpec) -> EvidencePackage:
        pkg = EvidencePackage(
            framework=framework,
            control_id=ctrl.control_id,
            collected_at=datetime.now(timezone.utc).isoformat(),
        )
        artifact = self._dispatch_collection(ctrl)
        if artifact:
            pkg.artifacts.append(artifact)

        # Compute sha256 over canonical JSON
        canonical = json.dumps(pkg.artifacts, sort_keys=True).encode("utf-8")
        pkg.sha256 = hashlib.sha256(canonical).hexdigest()

        # Persist to disk
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        out_dir = self.evidence_root / framework / ctrl.control_id / date
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"evidence-{int(datetime.now().timestamp())}.json"
        out_file.write_text(json.dumps(pkg.as_dict(), indent=2))
        logger.info("Wrote evidence %s/%s/%s", framework, ctrl.control_id, out_file.name)
        return pkg

    def _dispatch_collection(self, ctrl: ControlSpec) -> Optional[dict]:
        """Route collection to the right source — best-effort with graceful degradation.

        If a source is unavailable (e.g., trial expired), record placeholder
        instead of failing the whole framework collection.
        """
        try:
            if ctrl.source == "okta":
                from integrations.okta.okta_client import OktaClient
                client = OktaClient()
                return getattr(client, ctrl.method, lambda: {"placeholder": "method_not_implemented"})()
            if ctrl.source == "crowdstrike":
                from integrations.crowdstrike.falcon_client import FalconClient
                client = FalconClient()
                return getattr(client, ctrl.method, lambda: {"placeholder": "method_not_implemented"})()
            if ctrl.source == "intune":
                from integrations.intune.graph_client import GraphClient
                client = GraphClient()
                return getattr(client, ctrl.method, lambda: {"placeholder": "method_not_implemented"})()
            if ctrl.source == "gws":
                from integrations.google_workspace.gws_admin_client import GWSAdminClient
                client = GWSAdminClient()
                return getattr(client, ctrl.method, lambda: {"placeholder": "method_not_implemented"})()
            if ctrl.source == "wazuh":
                from integrations.wazuh_client import WazuhClient
                client = WazuhClient()
                return getattr(client, ctrl.method, lambda: {"placeholder": "method_not_implemented"})()
            if ctrl.source == "thehive":
                from integrations.thehive_client import TheHiveClient
                client = TheHiveClient()
                return getattr(client, ctrl.method, lambda: {"placeholder": "method_not_implemented"})()
            if ctrl.source == "dlp":
                from dlp.policies import ALL_POLICIES
                return {
                    "policy_count": len(ALL_POLICIES),
                    "policies": [{"id": p.policy_id, "name": p.name, "severity": p.base_severity} for p in ALL_POLICIES],
                }
            if ctrl.source == "git":
                import subprocess
                output = subprocess.run(
                    ["git", "log", "--oneline", "-50"],
                    capture_output=True, text=True, cwd="/app",
                )
                return {"recent_commits": output.stdout.strip().split("\n")}
            if ctrl.source == "docs":
                docs_dir = Path("/app/runbooks")
                return {"available_documents": [str(p.name) for p in docs_dir.glob("*.md")] if docs_dir.exists() else []}
            if ctrl.source == "ansible":
                return {"placeholder": "ansible_audit_runs_outside_python_container"}

            return {"warning": f"unknown_source: {ctrl.source}"}
        except Exception as exc:
            logger.warning("Source %s unavailable for %s: %s", ctrl.source, ctrl.control_id, exc)
            return {"error": str(exc), "source_unavailable": True}


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="corpsec-ops compliance evidence collector")
    parser.add_argument("--framework", choices=["all", "soc2", "iso27001"], default="all")
    parser.add_argument("--control", help="Collect a single control by ID")
    args = parser.parse_args()

    collector = EvidenceCollector()
    if args.control:
        framework = "soc2" if args.control.startswith("CC") else "iso27001"
        pkg = collector.collect_control(framework, args.control)
        print(json.dumps(pkg.as_dict() if pkg else {"error": "not_found"}, indent=2))
    else:
        results = collector.collect_all(args.framework)
        print(f"Collected {len(results)} evidence packages")
        for r in results:
            status = "OK" if not r.error else "ERR"
            print(f"  [{status}] {r.framework} / {r.control_id} sha256={r.sha256[:16]}...")


if __name__ == "__main__":
    main()
