"""Compliance evidence collector tests."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from compliance.controls.soc2 import SOC2_CONTROLS
from compliance.controls.iso27001 import ISO27001_CONTROLS
from compliance.evidence_collector import EvidenceCollector


class TestControlInventory:
    def test_soc2_has_required_controls(self):
        ids = {c.control_id for c in SOC2_CONTROLS}
        # JD-relevant controls must be present
        required = {"CC6.1", "CC6.2", "CC6.6", "CC6.7", "CC6.8", "CC7.2", "CC7.4"}
        assert required.issubset(ids)

    def test_iso27001_has_required_controls(self):
        ids = {c.control_id for c in ISO27001_CONTROLS}
        required = {"A.9.1", "A.9.4", "A.12.4", "A.12.6", "A.16.1"}
        assert required.issubset(ids)

    def test_all_soc2_controls_have_freshness(self):
        for c in SOC2_CONTROLS:
            assert c.freshness_days > 0


class TestEvidenceCollection:
    def test_collect_writes_evidence_file(self, tmp_path):
        collector = EvidenceCollector(evidence_root=tmp_path)
        # Force "git" source which doesn't need API access
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "abc1234 Initial commit"
            packages = collector.collect_all("soc2")
        assert len(packages) > 0
        # Verify at least one evidence file exists on disk
        evidence_files = list(tmp_path.rglob("evidence-*.json"))
        assert len(evidence_files) > 0

    def test_evidence_has_sha256(self, tmp_path):
        collector = EvidenceCollector(evidence_root=tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "abc1234"
            packages = collector.collect_all("soc2")
        for pkg in packages:
            if pkg.error is None:
                assert len(pkg.sha256) == 64  # SHA-256 hex length

    def test_unknown_source_records_warning(self, tmp_path):
        from compliance.controls.soc2 import ControlSpec
        collector = EvidenceCollector(evidence_root=tmp_path)
        ctrl = ControlSpec(
            control_id="TEST.1",
            name="test",
            description="test",
            source="nonexistent_source",
            method="any",
        )
        artifact = collector._dispatch_collection(ctrl)
        assert artifact is not None
        assert "warning" in artifact or "error" in artifact
