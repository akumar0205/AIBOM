from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata


class PromptInjectionSurfaceRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="prompt-injection-surface",
        category="prompt injection surface",
        owasp_llm="LLM01 Prompt Injection",
        default_severity="medium",
        rationale="Prompt templates detected; review source trust boundaries.",
        evidence_requirements=(
            "prompt template presence",
            "originating file or unresolved source marker",
        ),
        control_mappings=("OWASP-LLM-01", "NIST-AI-RMF-MAP"),
        default_confidence=0.65,
        default_exposure=0.6,
    )

    def evaluate(self, entities: dict[str, list]) -> list[RuleMatch]:
        return [
            RuleMatch(
                metadata=self.metadata,
                entity=entity,
                confidence=self.metadata.default_confidence,
                exposure=self.metadata.default_exposure,
                provenance_completeness=0.5,
            )
            for entity in entities["prompts"]
        ]
