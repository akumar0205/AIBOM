from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata


class RetrievalAugmentationRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="retrieval-augmentation",
        category="retrieval augmentation",
        owasp_llm="LLM03 Training Data Poisoning",
        default_severity="medium",
        rationale="Vector store / retrieval usage detected; poisoned or stale passages can steer outputs.",
        evidence_requirements=(
            "vector store invocation evidence",
            "source file path with retrieval usage",
        ),
        control_mappings=("OWASP-LLM-03", "NIST-AI-RMF-MEASURE"),
        default_confidence=0.75,
        default_exposure=0.65,
        control_objective="Govern retrieval corpora that ground model outputs.",
        remediation="Version and sign retrieval snapshots, scan ingested content, and monitor for poisoning or staleness.",
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
            for entity in entities.get("datasets", [])
        ]
