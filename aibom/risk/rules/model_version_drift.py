from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata

UNPINNED_MODEL_MARKERS = {"unknown", "", "latest"}


class ModelVersionDriftRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="model-version-drift",
        category="model version drift",
        owasp_llm="LLM05 Supply-Chain Vulnerabilities",
        default_severity="medium",
        rationale="Model reference is unpinned; provider-side updates can change behavior silently.",
        evidence_requirements=(
            "model identity from static analysis",
            "missing or floating version pin",
        ),
        control_mappings=("OWASP-LLM-05", "NIST-AI-RMF-MANAGE"),
        default_confidence=0.8,
        default_exposure=0.5,
        control_objective="Pin every model reference to an immutable version or digest.",
        remediation="Pin model versions or digests, subscribe to provider change notices, and re-validate on drift.",
    )

    def evaluate(self, entities: dict[str, list]) -> list[RuleMatch]:
        return [
            RuleMatch(
                metadata=self.metadata,
                entity=entity,
                confidence=self.metadata.default_confidence,
                exposure=self.metadata.default_exposure,
                provenance_completeness=0.3,
            )
            for entity in entities.get("models", [])
            if entity.detail.strip().lower() in UNPINNED_MODEL_MARKERS
        ]
