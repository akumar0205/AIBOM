from __future__ import annotations

from aibom.risk.rules.base import RiskRule, RuleMatch, RuleMetadata

NETWORK_TOOL_HINTS = {
    "requests",
    "httpx",
    "urllib",
    "fetch",
    "axios",
    "serpapi",
    "webbrowser",
    "websearch",
    "browser",
}


class InternetEgressRule(RiskRule):
    metadata = RuleMetadata(
        base_rule_id="internet-egress",
        category="internet egress",
        owasp_llm="LLM06 Sensitive Information Disclosure",
        default_severity="medium",
        rationale="Network-capable tool detected; prompts or data may leave the boundary.",
        evidence_requirements=(
            "tool invocation or import evidence",
            "source file path with network-capable tool",
        ),
        control_mappings=("OWASP-LLM-06", "SOC2-CC6.1"),
        default_confidence=0.7,
        default_exposure=0.8,
        control_objective="Constrain which AI tools can initiate outbound network calls.",
        remediation="Allowlist egress destinations, enforce egress proxying, and log outbound calls.",
    )

    def evaluate(self, entities: dict[str, list]) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for entity in entities.get("tools", []):
            lowered = entity.name.lower()
            if any(hint in lowered for hint in NETWORK_TOOL_HINTS):
                matches.append(
                    RuleMatch(
                        metadata=self.metadata,
                        entity=entity,
                        confidence=self.metadata.default_confidence,
                        exposure=self.metadata.default_exposure,
                        provenance_completeness=1.0 if entity.source_file else 0.4,
                    )
                )
        return matches
