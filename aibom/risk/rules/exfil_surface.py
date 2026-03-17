from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata

EXFIL_TOOLS = {"Requests", "ReadFileTool", "WriteFileTool", "SerpAPI"}


class ExfilSurfaceRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="exfil-surface",
        category="exfil surface",
        owasp_llm="LLM06 Sensitive Information Disclosure",
        default_severity="high",
        rationale="Tool may read/write data or access web.",
        evidence_requirements=(
            "tool invocation or import evidence",
            "source file path with exfil-capable tool",
        ),
        control_mappings=("OWASP-LLM-06", "SOC2-CC6.1"),
        default_confidence=0.75,
        default_exposure=0.85,
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
            for entity in entities["tools"]
            if entity.name in EXFIL_TOOLS
        ]
