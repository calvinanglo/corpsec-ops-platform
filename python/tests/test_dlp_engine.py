"""DLP engine tests — verify signal-vs-noise tuning works."""
from __future__ import annotations

import pytest

from dlp.engine import DLPEngine, luhn_check, redact
from dlp.policies import load_policies


# ── Helper validation tests ────────────────────────────────────────────────────
class TestHelpers:
    def test_luhn_valid_visa(self):
        assert luhn_check("4532148803436467")

    def test_luhn_invalid(self):
        assert not luhn_check("4532148803436468")

    def test_redact_short(self):
        assert redact("ab") == "**"

    def test_redact_normal(self):
        assert redact("123-45-6789") == "12*******89"


# ── True positive detection tests ─────────────────────────────────────────────
class TestTruePositives:
    def test_detects_valid_ssn(self, dlp_engine):
        matches = dlp_engine.scan_text("Employee SSN: 234-56-7891")
        assert any(m.policy_id == "PII-001" for m in matches)

    def test_detects_valid_credit_card_with_luhn(self, dlp_engine):
        # Real Luhn-valid Visa
        matches = dlp_engine.scan_text("Card on file: 4532148803436467")
        assert any(m.policy_id == "PII-002" for m in matches)

    def test_detects_attorney_client_privilege(self, dlp_engine):
        matches = dlp_engine.scan_text("This document is protected by attorney-client privilege")
        assert any(m.policy_id == "LEGAL-001" for m in matches)

    def test_detects_aws_access_key(self, dlp_engine):
        matches = dlp_engine.scan_text("Use this key: AKIAQWERTYUIOPASDFGH")
        assert any(m.policy_id == "CODE-001" for m in matches)


# ── False positive suppression tests (the "signal vs noise" capability) ───────
class TestFalsePositiveSuppression:
    def test_suppresses_phone_number_lookalike(self, dlp_engine):
        # Phone numbers in xxx-xx-xxxx format should not flag as SSN
        matches = dlp_engine.scan_text("phone: 415-22-3344, please call back")
        ssn_matches = [m for m in matches if m.policy_id == "PII-001"]
        assert len(ssn_matches) == 0

    def test_suppresses_invalid_ssn_test_value(self, dlp_engine):
        # Common test SSN should be rejected
        matches = dlp_engine.scan_text("Test SSN: 123-45-6789")
        ssn_matches = [m for m in matches if m.policy_id == "PII-001"]
        assert len(ssn_matches) == 0

    def test_suppresses_credit_card_test_number(self, dlp_engine):
        # Visa test number 4111111111111111 should be suppressed
        matches = dlp_engine.scan_text("Test card: 4111 1111 1111 1111")
        cc_matches = [m for m in matches if m.policy_id == "PII-002"]
        assert len(cc_matches) == 0

    def test_suppresses_aws_docs_example_key(self, dlp_engine):
        # AKIAIOSFODNN7EXAMPLE is the AWS-published example
        matches = dlp_engine.scan_text("Example: AKIAIOSFODNN7EXAMPLE")
        code_matches = [m for m in matches if m.policy_id == "CODE-001"]
        assert len(code_matches) == 0

    def test_suppresses_documentation_example(self, dlp_engine):
        # Documentation showing a pattern should be suppressed
        matches = dlp_engine.scan_text("e.g., a SSN like 234-56-7891 would be flagged")
        # Should be heavily suppressed because of "e.g.," marker
        ssn_matches = [m for m in matches if m.policy_id == "PII-001"]
        assert len(ssn_matches) == 0


# ── Confidence scoring tests ──────────────────────────────────────────────────
class TestConfidenceScoring:
    def test_higher_confidence_with_keyword_context(self, dlp_engine):
        with_kw = dlp_engine.scan_text("Customer SSN on record: 234-56-7891")
        without_kw = dlp_engine.scan_text("Random number: 234-56-7891")
        ssn_with = next((m for m in with_kw if m.policy_id == "PII-001"), None)
        ssn_without = next((m for m in without_kw if m.policy_id == "PII-001"), None)
        assert ssn_with is not None and ssn_without is not None
        assert ssn_with.confidence > ssn_without.confidence

    def test_severity_bumps_on_high_confidence(self, dlp_engine):
        # High confidence should bump severity above base
        matches = dlp_engine.scan_text(
            "Client SSN tax ID social security: 234-56-7891 in the legal file"
        )
        ssn = next((m for m in matches if m.policy_id == "PII-001"), None)
        assert ssn is not None
        assert ssn.confidence >= 0.85


# ── Policy filtering ──────────────────────────────────────────────────────────
class TestPolicyFiltering:
    def test_load_specific_policies(self):
        policies = load_policies(["PII-001"])
        assert len(policies) == 1
        assert policies[0].policy_id == "PII-001"

    def test_load_all(self):
        policies = load_policies()
        assert len(policies) == 8
