from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata

EXTERNAL_PROVIDER_MODELS = {"OpenAI", "ChatOpenAI", "ChatAnthropic"}


class ThirdPartyProviderRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="third-party-provider",
        category="third-party dependency",
        owasp_llm="LLM07 Insecure Plugin Design",
        default_severity="medium",
        rationale="External model provider detected.",
        evidence_requirements=(
            "model type from static analysis",
            "source file path where provider is referenced",
        ),
        control_mappings=("OWASP-LLM-07", "NIST-AI-RMF-GOVERN"),
        default_confidence=0.8,
        default_exposure=0.7,
    )

    def evaluate(self, entities: dict[str, list]) -> list[RuleMatch]:
        return [
            RuleMatch(
                metadata=self.metadata,
                entity=entity,
                confidence=self.metadata.default_confidence,
                exposure=self.metadata.default_exposure,
                provenance_completeness=1.0 if entity.source_file else 0.4,
            )
            for entity in entities["models"]
            if entity.name in EXTERNAL_PROVIDER_MODELS
        ]
