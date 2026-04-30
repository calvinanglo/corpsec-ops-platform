"""Shared test fixtures."""
from __future__ import annotations

import pytest

from dlp.engine import DLPEngine
from dlp.policies import load_policies


@pytest.fixture
def dlp_engine():
    """Default DLP engine with all policies loaded."""
    return DLPEngine(policies=load_policies())


@pytest.fixture
def dlp_engine_pii_only():
    """DLP engine with only PII policies."""
    return DLPEngine(policies=load_policies(["PII-001", "PII-002", "PII-003", "PII-004"]))
