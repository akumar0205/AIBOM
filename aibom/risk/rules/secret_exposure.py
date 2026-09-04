from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata


class SecretExposureRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="secret-exposure",
        category="secret exposure",
        owasp_llm="LLM06 Sensitive Information Disclosure",
        default_severity="high",
        rationale="Provider credential material detected in scanned configuration.",
        evidence_requirements=(
            "redacted credential finding from config scan",
            "source file path containing the credential reference",
        ),
        control_mappings=("OWASP-LLM-06", "SOC2-CC6.1"),
        default_confidence=0.85,
        default_exposure=0.9,
        control_objective="Prevent AI provider credentials from living in source or config.",
        remediation="Move the credential to a managed secret store, rotate the exposed value, and block commits containing secrets.",
    )

    def evaluate(self, entities: dict[str, list]) -> list[RuleMatch]:
        return [
            RuleMatch(
                metadata=self.metadata,
                entity=entity,
                confidence=self.metadata.default_confidence,
                exposure=self.metadata.default_exposure,
                provenance_completeness=0.6,
            )
            for entity in entities.get("secrets", [])
        ]
