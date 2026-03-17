from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NormalizedEntity:
    entity_type: str
    name: str
    source_file: str


@dataclass(frozen=True)
class RuleMetadata:
    base_rule_id: str
    category: str
    owasp_llm: str
    default_severity: str
    rationale: str
    evidence_requirements: tuple[str, ...]
    control_mappings: tuple[str, ...]
    default_confidence: float
    default_exposure: float


@dataclass(frozen=True)
class RuleMatch:
    metadata: RuleMetadata
    entity: NormalizedEntity
    confidence: float
    exposure: float
    provenance_completeness: float


class RiskRule:
    metadata: RuleMetadata

    def evaluate(self, entities: dict[str, list[NormalizedEntity]]) -> list[RuleMatch]:
        raise NotImplementedError
