"""corpsec-ops-platform — DLP policy definitions.

8 policies covering PII, legal/client privilege, code secrets, and financial.
Each policy has tuning rules (false_positive_patterns, boost_keywords) so the
SOC analyst can tune the engine without code changes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern


@dataclass
class DLPPolicy:
    """A single DLP detection policy."""
    policy_id: str
    name: str
    description: str
    base_severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    base_confidence: float  # 0.0 - 1.0 default confidence

    # Compiled patterns: pattern_name -> regex
    patterns: dict[str, Pattern]

    # Tuning rules
    false_positive_patterns: list[Pattern] = field(default_factory=list)
    boost_keywords: list[str] = field(default_factory=list)
    applies_to_extensions: list[str] = field(default_factory=list)


def _re(pattern: str, flags: int = re.IGNORECASE) -> Pattern:
    return re.compile(pattern, flags)


# ── PII Policies ──────────────────────────────────────────────────────────────
PII_001_SSN = DLPPolicy(
    policy_id="PII-001",
    name="US Social Security Number",
    description="Detects US SSN with area-number/group-number/serial validation",
    base_severity="HIGH",
    base_confidence=0.7,
    patterns={
        "ssn_dashed": _re(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        "ssn_spaced": _re(r"\b(?!000|666|9\d{2})\d{3} (?!00)\d{2} (?!0000)\d{4}\b"),
    },
    false_positive_patterns=[
        _re(r"phone[:\s]*\d{3}[-\s]\d{2}[-\s]\d{4}"),
        _re(r"fax[:\s]*\d{3}[-\s]\d{2}[-\s]\d{4}"),
        _re(r"order[#:\s]*\d{3}[-\s]\d{2}[-\s]\d{4}"),
        _re(r"invoice[#:\s]*\d{3}[-\s]\d{2}[-\s]\d{4}"),
        _re(r"isbn[:\s]*\d{3}[-\s]\d{2}[-\s]\d{4}"),
    ],
    boost_keywords=["ssn", "social security", "social-security", "tax id", "tax-id", "tin"],
)

PII_002_CC = DLPPolicy(
    policy_id="PII-002",
    name="Credit Card Number",
    description="Major card brands with Luhn validation",
    base_severity="HIGH",
    base_confidence=0.7,  # Engine boosts after Luhn passes
    patterns={
        "visa": _re(r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "mastercard": _re(r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "amex": _re(r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b"),
        "discover": _re(r"\b6011[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
    },
    false_positive_patterns=[
        _re(r"4111[\s-]?1111[\s-]?1111[\s-]?1111"),  # Visa test
        _re(r"5555[\s-]?5555[\s-]?5555[\s-]?4444"),  # Mastercard test
        _re(r"3782[\s-]?822463[\s-]?10005"),  # Amex test
    ],
    boost_keywords=["credit card", "credit-card", "cc#", "card number", "cardnumber", "cvv", "expir"],
)

PII_003_BULK_EMAIL = DLPPolicy(
    policy_id="PII-003",
    name="Bulk Email Harvest",
    description="Multiple unique email addresses in one document (exfiltration signal)",
    base_severity="MEDIUM",
    base_confidence=0.6,
    patterns={
        "email": _re(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"),
    },
    false_positive_patterns=[
        _re(r"@(example|test|localhost|sample)\."),
        _re(r"noreply@"),
        _re(r"do[-_]?not[-_]?reply@"),
    ],
    boost_keywords=["mailing list", "contacts", "subscribers", "members"],
)

PII_004_SIN = DLPPolicy(
    policy_id="PII-004",
    name="Canadian Social Insurance Number",
    description="Canadian SIN — relevant for Vancouver-based companies",
    base_severity="HIGH",
    base_confidence=0.7,
    patterns={
        "sin_dashed": _re(r"\b\d{3}-\d{3}-\d{3}\b"),
        "sin_spaced": _re(r"\b\d{3} \d{3} \d{3}\b"),
    },
    false_positive_patterns=[
        _re(r"phone[:\s]*\d{3}[-\s]\d{3}[-\s]\d{3}"),
        _re(r"part[-#:\s]*\d{3}[-\s]\d{3}[-\s]\d{3}"),
    ],
    boost_keywords=["sin", "social insurance", "social-insurance"],
)


# ── Legal Practice Management ─────────────────────────────────────────────────
LEGAL_001_PRIVILEGE = DLPPolicy(
    policy_id="LEGAL-001",
    name="Attorney-Client Privilege Markers",
    description="Documents marked as legally privileged",
    base_severity="CRITICAL",
    base_confidence=0.85,
    patterns={
        "privilege_marker": _re(
            r"\b(attorney[\s-]client privileg|privileged.{0,20}confidential|"
            r"work[\s-]product|attorney work[\s-]product|"
            r"protected by attorney[\s-]client)\b"
        ),
        "court_caption": _re(r"\bcase\s+(no\.|number)\s*:?\s*[A-Z0-9-]+\b"),
        "court_filing": _re(r"\bdocket\s+(no\.|number|#)\s*:?\s*\d{2,}-[A-Z0-9-]+\b"),
    },
    false_positive_patterns=[
        _re(r"sample privilege"),
        _re(r"definition of privileg"),
    ],
    boost_keywords=["confidential", "do not distribute", "internal only", "trial prep"],
)

LEGAL_002_MATTER = DLPPolicy(
    policy_id="LEGAL-002",
    name="Client Matter and Trust Account IDs",
    description="Client matter numbers, trust account references (Clio practice management context)",
    base_severity="HIGH",
    base_confidence=0.7,
    patterns={
        "matter_id": _re(r"\bmatter[#\s]*:?\s*([A-Z]{2,4}-)?\d{4,}-?\d{0,4}\b"),
        "trust_account": _re(r"\btrust[\s-]?(?:account|acct)[#\s]*:?\s*[A-Z0-9-]{6,}\b"),
        "client_id": _re(r"\bclient[#\s]*(?:id|number|no)?\s*:?\s*[A-Z]{0,3}\d{4,}\b"),
    },
    boost_keywords=["billable", "retainer", "matter", "client file", "iolta"],
)


# ── Code Secrets ──────────────────────────────────────────────────────────────
CODE_001_SECRETS = DLPPolicy(
    policy_id="CODE-001",
    name="API Keys and Secrets in Non-Code Files",
    description="Detects keys/tokens that should be in vaults, not in docs/sheets/emails",
    base_severity="HIGH",
    base_confidence=0.8,
    patterns={
        "aws_access_key": _re(r"\bAKIA[0-9A-Z]{16}\b"),
        "aws_secret": _re(r"\b[A-Za-z0-9/+=]{40}\b(?=.*aws|.*secret)", re.IGNORECASE),
        "github_pat": _re(r"\bghp_[A-Za-z0-9]{36}\b"),
        "github_oauth": _re(r"\bgho_[A-Za-z0-9]{36}\b"),
        "openai_key": _re(r"\bsk-[A-Za-z0-9]{32,}\b"),
        "slack_token": _re(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "jwt_token": _re(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "private_key_header": _re(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    },
    false_positive_patterns=[
        _re(r"AKIAIOSFODNN7EXAMPLE"),  # AWS docs example
        _re(r"YOUR_API_KEY"),
        _re(r"<your.*key.*here>"),
        _re(r"REPLACE_WITH_"),
        _re(r"CHANGE_ME"),
        _re(r"xxx{3,}"),
    ],
    boost_keywords=["api key", "secret", "credential", "token", "private key"],
    # Don't flag keys in actual code/config files — those should be caught by git-secrets pre-commit
    applies_to_extensions=[".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt", ".md", ".eml", ".html", ""],
)


# ── Financial ─────────────────────────────────────────────────────────────────
FIN_001_BANKING = DLPPolicy(
    policy_id="FIN-001",
    name="Bank Routing and Account Numbers",
    description="US/Canadian banking identifiers",
    base_severity="HIGH",
    base_confidence=0.6,
    patterns={
        # US ABA routing: 9 digits, often with leading zeros
        "aba_routing": _re(r"\b(?:0[1-9]|1[0-2]|2[1-9]|3[0-2])\d{7}\b"),
        # Account numbers near "account" keyword (avoid false positives)
        "account_number": _re(r"\baccount[#\s]*(?:no|number|#)?\s*:?\s*\d{8,17}\b"),
        # IBAN (international)
        "iban": _re(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    },
    false_positive_patterns=[
        _re(r"order[#:\s]*\d{8,}"),
        _re(r"tracking[#:\s]*\d{8,}"),
    ],
    boost_keywords=["routing", "aba", "swift", "iban", "wire transfer", "ach"],
)


# ── Registry ──────────────────────────────────────────────────────────────────
ALL_POLICIES = [
    PII_001_SSN,
    PII_002_CC,
    PII_003_BULK_EMAIL,
    PII_004_SIN,
    LEGAL_001_PRIVILEGE,
    LEGAL_002_MATTER,
    CODE_001_SECRETS,
    FIN_001_BANKING,
]


def load_policies(policy_ids: list[str] | None = None) -> list[DLPPolicy]:
    """Load all policies, or filter by ID."""
    if policy_ids is None:
        return ALL_POLICIES
    by_id = {p.policy_id: p for p in ALL_POLICIES}
    return [by_id[pid] for pid in policy_ids if pid in by_id]
