"""corpsec-ops-platform — AI service registry.

Categorizes AI services as authorized (corporate-sanctioned) vs unauthorized
(personal accounts) vs unknown. YAML-configurable so security teams can add
new AI services without code changes.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class AIService:
    """Single AI service definition."""
    name: str
    category: str  # AUTHORIZED_CORPORATE | UNAUTHORIZED_PERSONAL | UNKNOWN
    domains: list[str]
    api_endpoints: list[str] = field(default_factory=list)
    description: str = ""

    def matches_domain(self, host: str) -> bool:
        host_lower = host.lower().rstrip(".")
        return any(host_lower == d.lower() or host_lower.endswith("." + d.lower()) for d in self.domains)

    def matches_endpoint(self, url: str) -> bool:
        url_lower = url.lower()
        return any(ep.lower() in url_lower for ep in self.api_endpoints)


# Default registry — can be overridden via YAML at /etc/corpsec/ai-services.yml
DEFAULT_REGISTRY: dict[str, AIService] = {
    # ── Authorized corporate (placeholder examples) ─────────────────────────
    "chatgpt-enterprise-corp": AIService(
        name="ChatGPT Enterprise (corporate)",
        category="AUTHORIZED_CORPORATE",
        domains=["chat.company.openai.com"],  # Replace with actual corp endpoint
        description="Corporate ChatGPT Enterprise instance",
    ),
    # ── Unauthorized personal AI services ───────────────────────────────────
    "chatgpt-personal": AIService(
        name="ChatGPT (personal)",
        category="UNAUTHORIZED_PERSONAL",
        domains=["chat.openai.com", "chatgpt.com"],
        api_endpoints=["api.openai.com/v1/chat/completions", "api.openai.com/v1/completions"],
        description="Personal ChatGPT consumer endpoints",
    ),
    "gemini-personal": AIService(
        name="Gemini (personal)",
        category="UNAUTHORIZED_PERSONAL",
        domains=["gemini.google.com", "bard.google.com", "aistudio.google.com"],
        api_endpoints=["generativelanguage.googleapis.com"],
        description="Personal Gemini / Google AI Studio",
    ),
    "copilot-personal": AIService(
        name="Microsoft Copilot (personal)",
        category="UNAUTHORIZED_PERSONAL",
        domains=["copilot.microsoft.com"],
        description="Personal Copilot — note corp Copilot has different domain",
    ),
    "perplexity-personal": AIService(
        name="Perplexity AI",
        category="UNAUTHORIZED_PERSONAL",
        domains=["perplexity.ai", "www.perplexity.ai"],
        api_endpoints=["api.perplexity.ai"],
        description="Perplexity AI search/chat",
    ),
    "deepseek-personal": AIService(
        name="DeepSeek",
        category="UNAUTHORIZED_PERSONAL",
        domains=["chat.deepseek.com", "deepseek.com"],
        api_endpoints=["api.deepseek.com"],
        description="DeepSeek consumer/API",
    ),
    "mistral-personal": AIService(
        name="Mistral Le Chat",
        category="UNAUTHORIZED_PERSONAL",
        domains=["chat.mistral.ai"],
        api_endpoints=["api.mistral.ai"],
        description="Mistral Le Chat consumer",
    ),
    "you-personal": AIService(
        name="You.com",
        category="UNAUTHORIZED_PERSONAL",
        domains=["you.com", "chat.you.com"],
        description="You.com chat",
    ),
    "character-personal": AIService(
        name="Character.AI",
        category="UNAUTHORIZED_PERSONAL",
        domains=["character.ai", "beta.character.ai"],
        description="Character.AI",
    ),
}


class AIServiceRegistry:
    """Registry of AI services with classification logic."""

    def __init__(self, services: dict[str, AIService] | None = None):
        self.services = services or DEFAULT_REGISTRY.copy()

    @classmethod
    def from_yaml(cls, path: Path | str) -> "AIServiceRegistry":
        """Load registry from YAML file. Falls back to default if not found."""
        path = Path(path)
        if not path.exists():
            logger.info("AI registry YAML not found at %s — using defaults", path)
            return cls()

        with path.open() as f:
            data = yaml.safe_load(f) or {}

        services = {}
        for key, spec in data.get("services", {}).items():
            services[key] = AIService(
                name=spec["name"],
                category=spec["category"],
                domains=spec.get("domains", []),
                api_endpoints=spec.get("api_endpoints", []),
                description=spec.get("description", ""),
            )
        return cls(services)

    def classify(self, host: str, url: str | None = None) -> tuple[str, AIService | None]:
        """Classify a host/URL.

        Returns (category, matching_service) or ("UNKNOWN", None).
        """
        for service in self.services.values():
            if service.matches_domain(host):
                return service.category, service
            if url and service.matches_endpoint(url):
                return service.category, service
        return "UNKNOWN", None

    def is_authorized(self, host: str, url: str | None = None) -> bool:
        category, _ = self.classify(host, url)
        return category == "AUTHORIZED_CORPORATE"

    def all_unauthorized_domains(self) -> set[str]:
        """All domains classified as unauthorized — for blocklist generation."""
        domains = set()
        for s in self.services.values():
            if s.category == "UNAUTHORIZED_PERSONAL":
                domains.update(s.domains)
        return domains
