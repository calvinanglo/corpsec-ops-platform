"""corpsec-ops-platform — Data Loss Prevention engine.

Detects sensitive data in files, text, and event streams using regex pattern
matching with context validation, Luhn checksum verification, and false-positive
suppression. Maps to JD requirement: "Monitor and triage DLP alerts to surface
real signals from noise."
"""

from dlp.engine import DLPEngine, DLPMatch
from dlp.policies import DLPPolicy, load_policies

__all__ = ["DLPEngine", "DLPMatch", "DLPPolicy", "load_policies"]
