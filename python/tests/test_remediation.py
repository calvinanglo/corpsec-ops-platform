"""Auto-remediation engine tests."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from remediation.auto_remediate import AutoRemediate, ActionResult
from remediation.playbooks import PLAYBOOKS, find_playbook_for_rule


class TestPlaybookLookup:
    def test_dlp_critical_rule_finds_playbook(self):
        pb = find_playbook_for_rule(100103)  # DLP CRITICAL
        assert pb is not None
        assert pb.playbook_id == "PB-DLP-001"

    def test_ai_critical_rule_finds_playbook(self):
        pb = find_playbook_for_rule(100202)
        assert pb is not None
        assert pb.playbook_id == "PB-AI-001"

    def test_unknown_rule_returns_none(self):
        assert find_playbook_for_rule(999999) is None

    def test_all_playbooks_have_unique_ids(self):
        ids = [pb.playbook_id for pb in PLAYBOOKS.values()]
        assert len(ids) == len(set(ids))

    def test_playbook_count(self):
        assert len(PLAYBOOKS) == 7  # PB-DLP-001/002, PB-AI-001/002, PB-EDR-001, PB-PHISH-001, PB-ACCT-001


class TestSeverityThreshold:
    def test_low_severity_skips_high_threshold_playbook(self):
        engine = AutoRemediate(audit_log="/tmp/test_audit.jsonl")
        alert = {
            "id": "test-1",
            "rule": {"id": 100103},  # DLP CRITICAL
            "data": {"severity": "LOW", "user": "user@test.local"},
        }
        result = engine.receive_alert(alert)
        assert result.final_status == "below_threshold"
        assert len(result.actions_executed) == 0

    def test_critical_severity_executes_playbook(self):
        engine = AutoRemediate(audit_log="/tmp/test_audit.jsonl")
        alert = {
            "id": "test-2",
            "rule": {"id": 100103},
            "data": {"severity": "CRITICAL", "user": "user@test.local", "file_path": "/nonexistent"},
        }
        # Mock all action modules — they'll fail gracefully without real APIs
        with patch("remediation.actions.quarantine_file.execute", return_value=(True, {"ok": True})):
            with patch("remediation.actions.disable_user.execute", return_value=(True, {"ok": True})):
                result = engine.receive_alert(alert)
        assert result.final_status in ("success", "partial")
        assert result.playbook_id == "PB-DLP-001"


class TestNoMatchHandling:
    def test_unknown_rule_returns_no_match(self):
        engine = AutoRemediate(audit_log="/tmp/test_audit.jsonl")
        alert = {"id": "test-3", "rule": {"id": 999999}, "data": {"severity": "HIGH"}}
        result = engine.receive_alert(alert)
        assert result.final_status == "no_match"
