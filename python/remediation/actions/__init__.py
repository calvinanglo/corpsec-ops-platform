"""corpsec-ops-platform — Remediation action modules.

Each module exports `execute(alert: dict) -> tuple[bool, dict]` that performs
a single remediation step against a real production tool API.
"""
