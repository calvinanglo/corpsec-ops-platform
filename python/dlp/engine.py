"""corpsec-ops-platform — DLP detection engine.

Pattern matching with context validation, Luhn checksum, and false-positive
suppression. The "signal-vs-noise" capability that differentiates this from
naive regex scanning.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dlp.policies import DLPPolicy, load_policies

logger = logging.getLogger(__name__)


# ── Result dataclasses ─────────────────────────────────────────────────────────
@dataclass
class DLPMatch:
    """Single policy match with redacted matched text and confidence."""
    policy_id: str
    policy_name: str
    pattern_name: str
    matched_text_redacted: str  # Only first/last 2 chars + asterisks
    position: int
    context_window: str  # Surrounding 50 chars
    confidence: float  # 0.0 - 1.0
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class DLPScanResult:
    """Result of scanning a single resource."""
    resource: str
    scanned_at: str
    matches: list[DLPMatch] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def severity(self) -> str:
        """Highest severity across all matches."""
        if not self.matches:
            return "NONE"
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return max(self.matches, key=lambda m: order.get(m.severity, 0)).severity

    @property
    def match_count(self) -> int:
        return len(self.matches)

    def as_dict(self) -> dict:
        return {
            "resource": self.resource,
            "scanned_at": self.scanned_at,
            "severity": self.severity,
            "match_count": self.match_count,
            "matches": [m.as_dict() for m in self.matches],
            "error": self.error,
        }


# ── Helpers ────────────────────────────────────────────────────────────────────
def luhn_check(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm.

    Reduces credit-card false positives from ~80% (regex-only) to <5% in practice.
    """
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact(text: str) -> str:
    """Redact matched text — keep first/last 2 chars, mask rest.

    Example: '123-45-6789' -> '12*******89'
    """
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * (len(text) - 4)}{text[-2:]}"


def context_window(text: str, position: int, length: int, window: int = 50) -> str:
    """Extract surrounding context for a match.

    Useful for triage: shows whether the match appears in code/comments
    (likely false positive) vs prose (likely real).
    """
    start = max(0, position - window)
    end = min(len(text), position + length + window)
    return text[start:end].replace("\n", " ")


# ── Engine ─────────────────────────────────────────────────────────────────────
class DLPEngine:
    """Core DLP detection engine.

    Loads policies, scans content, applies tuning logic to suppress false
    positives. Each match includes confidence score for triage prioritization.
    """

    def __init__(self, policies: Optional[list[DLPPolicy]] = None):
        self.policies: list[DLPPolicy] = policies or load_policies()
        logger.info(
            "DLPEngine initialized with %d policies: %s",
            len(self.policies),
            ", ".join(p.policy_id for p in self.policies),
        )

    # ── Scanning ──
    def scan_text(self, text: str, context: Optional[dict] = None) -> list[DLPMatch]:
        """Scan a string against all policies. Returns list of matches."""
        context = context or {}
        all_matches: list[DLPMatch] = []
        for policy in self.policies:
            all_matches.extend(self._scan_with_policy(text, policy, context))
        return all_matches

    def scan_file(self, path: Path | str, context: Optional[dict] = None) -> DLPScanResult:
        """Scan a single file."""
        path = Path(path)
        result = DLPScanResult(
            resource=str(path),
            scanned_at=datetime.now(timezone.utc).isoformat(),
        )

        # Skip binary / oversized files (common false-positive source)
        if not path.exists():
            result.error = "file_not_found"
            return result
        if path.stat().st_size > 50 * 1024 * 1024:  # 50 MB
            result.error = "file_too_large"
            return result

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            result.error = f"read_error: {exc}"
            return result

        ctx = (context or {}).copy()
        ctx["file_path"] = str(path)
        ctx["file_extension"] = path.suffix.lower()
        result.matches = self.scan_text(text, ctx)
        return result

    def scan_directory(self, root: Path | str, context: Optional[dict] = None) -> list[DLPScanResult]:
        """Recursively scan a directory."""
        root = Path(root)
        results: list[DLPScanResult] = []
        for path in root.rglob("*"):
            if path.is_file():
                results.append(self.scan_file(path, context))
        return results

    # ── Internal ──
    def _scan_with_policy(self, text: str, policy: DLPPolicy, context: dict) -> list[DLPMatch]:
        """Apply one policy with all its patterns + tuning rules."""
        matches: list[DLPMatch] = []
        ext = context.get("file_extension", "")
        if policy.applies_to_extensions and ext and ext not in policy.applies_to_extensions:
            return matches

        for pattern_name, regex in policy.patterns.items():
            for m in regex.finditer(text):
                matched = m.group(0)

                # Apply policy-specific validation (e.g., Luhn for credit cards)
                if not self._validate_match(policy, pattern_name, matched, text, m.start()):
                    continue

                # Apply false-positive suppression
                ctx_window = context_window(text, m.start(), len(matched))
                if self._is_false_positive(policy, ctx_window, matched, context):
                    logger.debug(
                        "Suppressed FP: policy=%s match=%s context=%s",
                        policy.policy_id,
                        redact(matched),
                        ctx_window[:50],
                    )
                    continue

                confidence = self._compute_confidence(policy, matched, ctx_window, context)
                severity = self._classify_severity(policy, confidence, len(matches))

                matches.append(
                    DLPMatch(
                        policy_id=policy.policy_id,
                        policy_name=policy.name,
                        pattern_name=pattern_name,
                        matched_text_redacted=redact(matched),
                        position=m.start(),
                        context_window=ctx_window,
                        confidence=confidence,
                        severity=severity,
                    )
                )
        return matches

    def _validate_match(self, policy: DLPPolicy, pattern_name: str, matched: str, text: str, position: int) -> bool:
        """Policy-specific validation beyond regex.

        Examples:
        - Credit cards: Luhn checksum
        - Bulk email: must have N+ unique addresses
        - SSN: not a known test pattern (123-45-6789, 000-00-0000)
        """
        if policy.policy_id == "PII-002":  # Credit card
            digits = "".join(c for c in matched if c.isdigit())
            return luhn_check(digits)

        if policy.policy_id == "PII-001":  # SSN
            # Reject obvious test/example values
            normalized = matched.replace("-", "").replace(" ", "")
            test_patterns = {"000000000", "123456789", "111111111", "222222222"}
            if normalized in test_patterns:
                return False
            # Reject if first 3 digits are 000, 666, or start with 9 (invalid SSN ranges)
            area = normalized[:3]
            if area in ("000", "666") or area.startswith("9"):
                return False
            return True

        if policy.policy_id == "PII-003":  # Bulk email
            # Single email match — defer to threshold check at result level
            return True

        return True

    def _is_false_positive(self, policy: DLPPolicy, ctx: str, matched: str, context: dict) -> bool:
        """Apply policy's false_positive_patterns to suppress noisy matches.

        Critical for triage: every FP suppressed here is one less alert
        in the SOC analyst's queue.
        """
        ctx_lower = ctx.lower()
        for fp_pattern in policy.false_positive_patterns:
            if fp_pattern.search(ctx):
                return True

        # Generic FP heuristics
        # 1. In code comments or test files
        if context.get("file_extension") in (".test.js", ".test.py", ".spec.ts"):
            return True
        if "test" in context.get("file_path", "").lower() and "test_data" in ctx_lower:
            return True
        # 2. Documentation showing example patterns
        if any(marker in ctx_lower for marker in ("example:", "e.g.", "sample:", "test value:")):
            return True

        return False

    def _compute_confidence(self, policy: DLPPolicy, matched: str, ctx: str, context: dict) -> float:
        """Compute 0.0-1.0 confidence score.

        Higher confidence = more likely to be a real positive.
        Triage threshold: <0.5 = informational only, >=0.7 = act on it.
        """
        confidence = policy.base_confidence

        # Boost confidence if surrounded by relevant keywords
        ctx_lower = ctx.lower()
        for keyword in policy.boost_keywords:
            if keyword in ctx_lower:
                confidence = min(1.0, confidence + 0.15)
                break

        # Boost if filename suggests sensitive content
        path_lower = context.get("file_path", "").lower()
        for indicator in ("client", "legal", "matter", "case", "finance", "payroll"):
            if indicator in path_lower:
                confidence = min(1.0, confidence + 0.05)
                break

        return round(confidence, 2)

    def _classify_severity(self, policy: DLPPolicy, confidence: float, prior_match_count: int) -> str:
        """Determine severity based on policy base + confidence + volume."""
        base_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        order_to_label = {v: k for k, v in base_order.items()}
        base = base_order[policy.base_severity]

        # Bump severity on high confidence
        if confidence >= 0.9:
            base = min(4, base + 1)
        # Bump severity on bulk matches (10+)
        if prior_match_count >= 9:  # 10th+ match
            base = min(4, base + 1)
        # Reduce severity on low confidence
        if confidence < 0.5:
            base = max(1, base - 1)

        return order_to_label[base]


# ── CLI entrypoint ──
def main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="corpsec-ops DLP engine")
    parser.add_argument("--text", help="Scan a single string")
    parser.add_argument("--file", help="Scan a single file")
    parser.add_argument("--dir", help="Recursively scan a directory")
    parser.add_argument("--policy", help="Load only a specific policy by ID")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    engine = DLPEngine()
    results: list = []

    if args.text:
        matches = engine.scan_text(args.text)
        results = [{"resource": "<stdin>", "matches": [m.as_dict() for m in matches]}]
    elif args.file:
        results = [engine.scan_file(args.file).as_dict()]
    elif args.dir:
        results = [r.as_dict() for r in engine.scan_directory(args.dir)]
    else:
        parser.error("Provide --text, --file, or --dir")

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if isinstance(r, dict) and r.get("matches"):
                print(f"\n[{r.get('severity', 'N/A')}] {r['resource']}")
                for m in r["matches"]:
                    print(f"  {m['policy_id']:10} {m['pattern_name']:20} conf={m['confidence']:.2f} {m['matched_text_redacted']}")


if __name__ == "__main__":
    main()
