"""corpsec-ops-platform — Compliance evidence collection.

Automated SOC 2 and ISO 27001 evidence collection. Each control mapped to a
queryable platform artifact with SHA-256 integrity hashing.
Maps to JD requirement: "support compliance evidence collection (SOC 2,
ISO 27001)."
"""

from compliance.evidence_collector import EvidenceCollector, EvidencePackage

__all__ = ["EvidenceCollector", "EvidencePackage"]
