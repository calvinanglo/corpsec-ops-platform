"""AI exfiltration detector tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ai_detection.detector import AIExfilDetector
from ai_detection.policies import AIServiceRegistry


class TestServiceClassification:
    def test_classifies_chatgpt_personal(self):
        registry = AIServiceRegistry()
        category, service = registry.classify("chat.openai.com")
        assert category == "UNAUTHORIZED_PERSONAL"
        assert service is not None

    def test_classifies_unknown(self):
        registry = AIServiceRegistry()
        category, service = registry.classify("not-an-ai-service.example.com")
        assert category == "UNKNOWN"
        assert service is None

    def test_classifies_endpoint_match(self):
        registry = AIServiceRegistry()
        category, service = registry.classify("api.openai.com", "https://api.openai.com/v1/chat/completions")
        assert category == "UNAUTHORIZED_PERSONAL"


class TestDNSDetection:
    def test_dns_query_to_unauthorized_creates_alert(self):
        detector = AIExfilDetector()
        alert = detector.analyze_dns_query("user@corpsec.local", "chat.openai.com")
        assert alert is not None
        assert alert.detection_type == "dns_query"
        assert alert.severity == "LOW"

    def test_dns_burst_escalates_severity(self):
        detector = AIExfilDetector()
        for _ in range(5):
            detector.analyze_dns_query("user@corpsec.local", "chat.openai.com")
        # Next query should be MEDIUM (5+ in 10 min)
        alert = detector.analyze_dns_query("user@corpsec.local", "chat.openai.com")
        assert alert.severity in ("MEDIUM", "HIGH")


class TestProxyUploadDetection:
    def test_small_upload_is_low_severity(self):
        detector = AIExfilDetector()
        alert = detector.analyze_proxy_log(
            "user@corpsec.local",
            "https://api.openai.com/v1/chat/completions",
            "POST",
            500,  # tiny prompt
        )
        assert alert is not None
        assert alert.severity == "LOW"

    def test_large_upload_is_critical(self):
        detector = AIExfilDetector()
        alert = detector.analyze_proxy_log(
            "user@corpsec.local",
            "https://api.openai.com/v1/chat/completions",
            "POST",
            2_000_000,  # 2MB — bulk content
        )
        assert alert is not None
        assert alert.severity == "CRITICAL"

    def test_authorized_corporate_no_alert(self):
        registry = AIServiceRegistry()
        detector = AIExfilDetector(registry=registry)
        # The default registry has a placeholder for chat.company.openai.com
        alert = detector.analyze_proxy_log(
            "user@corpsec.local",
            "https://chat.company.openai.com/v1/chat/completions",
            "POST",
            500_000,
        )
        assert alert is None
