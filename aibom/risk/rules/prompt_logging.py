from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata


class PromptLoggingRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="prompt-logging",
        category="prompt logging",
        owasp_llm="LLM02 Insecure Output Handling",
        default_severity="medium",
        rationale="Prompt templates detected; template content and completions may be logged without redaction.",
        evidence_requirements=(
            "prompt template presence",
            "originating file or unresolved source marker",
        ),
        control_mappings=("OWASP-LLM-02", "SOC2-CC6.1"),
        default_confidence=0.6,
        default_exposure=0.6,
        control_objective="Ensure prompts and completions are logged safely or not at all.",
        remediation="Disable prompt logging by default, redact PII/secrets in logged templates, and set retention limits.",
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
            for entity in entities.get("prompts", [])
        ]
