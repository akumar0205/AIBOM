from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata

KNOWN_MODEL_TYPES = {
    "OpenAI",
    "ChatOpenAI",
    "ChatAnthropic",
    "Anthropic",
    "HuggingFaceHub",
    "Ollama",
    "ConfigModelHint",
}


class UnsupportedProviderRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="unsupported-provider-use",
        category="unsupported provider",
        owasp_llm="LLM05 Supply-Chain Vulnerabilities",
        default_severity="medium",
        rationale="Model surface uses a provider or wrapper outside the assessed inventory.",
        evidence_requirements=(
            "model identity from static analysis",
            "provider or wrapper classification",
        ),
        control_mappings=("OWASP-LLM-05", "NIST-AI-RMF-GOVERN"),
        default_confidence=0.6,
        default_exposure=0.6,
        control_objective="Inventory and approve every model provider, including wrappers.",
        remediation="Register the provider in the approved-vendor list or migrate to an assessed provider.",
    )

    def evaluate(self, entities: dict[str, list]) -> list[RuleMatch]:
        return [
            RuleMatch(
                metadata=self.metadata,
                entity=entity,
                confidence=self.metadata.default_confidence,
                exposure=self.metadata.default_exposure,
                provenance_completeness=0.4,
            )
            for entity in entities.get("models", [])
            if entity.name not in KNOWN_MODEL_TYPES or entity.name.startswith("Factory:")
        ]
