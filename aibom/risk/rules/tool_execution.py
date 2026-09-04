from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata


class ToolExecutionRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="tool-execution",
        category="tool execution",
        owasp_llm="LLM08 Excessive Agency",
        default_severity="high",
        rationale="Agentic tool surface detected; the model can trigger side effects.",
        evidence_requirements=(
            "tool invocation evidence",
            "source file path with tool wiring",
        ),
        control_mappings=("OWASP-LLM-08", "NIST-AI-RMF-GOVERN"),
        default_confidence=0.7,
        default_exposure=0.85,
        control_objective="Bound what agentic tools can do on the model's behalf.",
        remediation="Require human approval for high-impact tools, sandbox execution, and audit every tool call.",
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
            for entity in entities.get("tools", [])
            if not entity.name.startswith("dynamic-import:")
        ]
