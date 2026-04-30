"""corpsec-ops-platform — AI exfiltration detection.

Detects unauthorized corporate data movement to consumer LLM services
(ChatGPT, Gemini, Copilot, Perplexity, DeepSeek, Mistral, etc.). Maps to JD
requirement: "tune security tooling for AI detection to address unauthorized
data moves."
"""

from ai_detection.detector import AIExfilDetector, AIExfilAlert
from ai_detection.policies import AIServiceRegistry

__all__ = ["AIExfilDetector", "AIExfilAlert", "AIServiceRegistry"]
