from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from aibom.risk.rules import load_builtin_rulepack
from aibom.risk.rules.base import NormalizedEntity, RuleMatch

DEFAULT_SCORING_WEIGHTS = {
    "confidence": 0.35,
    "exposure": 0.4,
    "provenance": 0.25,
}

SEVERITY_BANDS = (
    (0.8, "critical"),
    (0.6, "high"),
    (0.4, "medium"),
    (0.0, "low"),
)


def _stable_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _normalize_weights(policy_weights: dict[str, Any] | None) -> dict[str, float]:
    merged = dict(DEFAULT_SCORING_WEIGHTS)
    if isinstance(policy_weights, dict):
        for key in merged:
            value = policy_weights.get(key)
            if isinstance(value, (int, float)) and value >= 0:
                merged[key] = float(value)
    total = sum(merged.values())
    if total <= 0:
        return dict(DEFAULT_SCORING_WEIGHTS)
    return {key: value / total for key, value in merged.items()}


def _load_policy_file(policy_path: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if policy_path is None:
        default_policy = {
            "policy_id": "builtin-default",
            "version": "1",
            "rule_overrides": {},
            "scoring": {"weights": DEFAULT_SCORING_WEIGHTS},
        }
        provenance = {
            "policy_id": default_policy["policy_id"],
            "version": default_policy["version"],
            "source": "builtin",
            "sha256": sha256(_stable_json(default_policy).encode("utf-8")).hexdigest(),
        }
        return default_policy, provenance

    text = policy_path.read_text(encoding="utf-8")
    suffix = policy_path.suffix.lower()
    if suffix == ".json":
        data = json.loads(text)
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ModuleNotFoundError as exc:
            msg = "YAML risk policy requires PyYAML; use JSON or install pyyaml."
            raise ValueError(msg) from exc
        data = yaml.safe_load(text)
    else:
        msg = "Unsupported policy format. Use .json, .yaml, or .yml"
        raise ValueError(msg)

    if not isinstance(data, dict):
        raise ValueError("Risk policy must be a JSON/YAML object")

    policy = {
        "policy_id": str(data.get("policy_id", "custom-policy")),
        "version": str(data.get("version", "1")),
        "rule_overrides": data.get("rule_overrides", {}),
        "scoring": data.get("scoring", {"weights": DEFAULT_SCORING_WEIGHTS}),
    }
    provenance = {
        "policy_id": policy["policy_id"],
        "version": policy["version"],
        "source": str(policy_path),
        "sha256": sha256(text.encode("utf-8")).hexdigest(),
    }
    return policy, provenance


def _normalize_entities(aibom: dict[str, Any]) -> dict[str, list[NormalizedEntity]]:
    return {
        "models": [
            NormalizedEntity(
                entity_type="model",
                name=str(model.get("type", "unknown")),
                source_file=str(model.get("source_file", "")),
            )
            for model in aibom.get("models", [])
        ],
        "tools": [
            NormalizedEntity(
                entity_type="tool",
                name=str(tool.get("name", "unknown")),
                source_file=str(tool.get("source_file", "")),
            )
            for tool in aibom.get("tools", [])
        ],
        "prompts": (
            [
                NormalizedEntity(
                    entity_type="prompt_surface", name="prompt_templates", source_file=""
                )
            ]
            if aibom.get("prompts")
            else []
        ),
    }


def _match_allowlist(
    entity: NormalizedEntity, allowlist: list[dict[str, Any]]
) -> dict[str, Any] | None:
    for exception in allowlist:
        entity_type = str(exception.get("entity_type", "")).strip()
        name = str(exception.get("name", "")).strip()
        source_file = str(exception.get("source_file", "")).strip()
        if entity_type and entity.entity_type != entity_type:
            continue
        if name and entity.name != name:
            continue
        if source_file and entity.source_file != source_file:
            continue
        return exception
    return None


def _score_to_severity(weighted_score: float) -> str:
    for threshold, severity in SEVERITY_BANDS:
        if weighted_score >= threshold:
            return severity
    return "low"


def _weighted_score(match: RuleMatch, weights: dict[str, float]) -> float:
    return (
        (match.confidence * weights["confidence"])
        + (match.exposure * weights["exposure"])
        + (match.provenance_completeness * weights["provenance"])
    )


def evaluate_risk(
    aibom: dict[str, Any], policy_path: Path | None = None
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    policy, provenance = _load_policy_file(policy_path)
    overrides = policy.get("rule_overrides", {})
    scoring = policy.get("scoring", {}) if isinstance(policy, dict) else {}
    global_weights = _normalize_weights(scoring.get("weights", {}))

    entities = _normalize_entities(aibom)
    rules = load_builtin_rulepack()

    grouped: dict[str, list[RuleMatch]] = {}
    for rule in rules.values():
        grouped[rule.metadata.base_rule_id] = rule.evaluate(entities)

    findings: list[dict[str, str]] = []
    suppressed: list[dict[str, str]] = []
    applied_rules: list[dict[str, Any]] = []

    for base_rule_id, rule_matches in sorted(grouped.items()):
        override = overrides.get(base_rule_id, {}) if isinstance(overrides, dict) else {}
        if isinstance(override, dict) and override.get("enabled") is False:
            suppressed.append(
                {
                    "base_rule_id": base_rule_id,
                    "rule_id": str(override.get("rule_id", base_rule_id)),
                    "entity_type": "rule",
                    "name": base_rule_id,
                    "source_file": "",
                    "reason": "disabled-by-policy",
                }
            )
            continue

        threshold = int(override.get("threshold", 1)) if isinstance(override, dict) else 1
        allowlist = override.get("allowlist", []) if isinstance(override, dict) else []
        if not isinstance(allowlist, list):
            allowlist = []

        rule_weights = _normalize_weights(
            override.get("weights", {}) if isinstance(override, dict) else {}
        )
        effective_weights = {
            key: rule_weights.get(key, global_weights[key]) for key in DEFAULT_SCORING_WEIGHTS
        }

        kept_matches: list[RuleMatch] = []
        for match in rule_matches:
            exception = _match_allowlist(match.entity, allowlist)
            if exception:
                suppressed.append(
                    {
                        "base_rule_id": base_rule_id,
                        "rule_id": str(override.get("rule_id", base_rule_id)),
                        "entity_type": match.entity.entity_type,
                        "name": match.entity.name,
                        "source_file": match.entity.source_file,
                        "reason": str(exception.get("reason", "allowlisted")),
                    }
                )
                continue
            kept_matches.append(match)

        metadata = rules[base_rule_id].metadata
        applied_rules.append(
            {
                "base_rule_id": base_rule_id,
                "rule_id": str(override.get("rule_id", base_rule_id)),
                "severity": str(override.get("severity", metadata.default_severity)),
                "threshold": threshold,
                "candidate_count": len(rule_matches),
                "post_allowlist_count": len(kept_matches),
                "enabled": True,
                "category": metadata.category,
                "rationale": metadata.rationale,
                "evidence_requirements": list(metadata.evidence_requirements),
                "control_mappings": list(metadata.control_mappings),
                "effective_weights": effective_weights,
            }
        )

        if len(kept_matches) < threshold:
            suppressed.append(
                {
                    "base_rule_id": base_rule_id,
                    "rule_id": str(override.get("rule_id", base_rule_id)),
                    "entity_type": "rule",
                    "name": base_rule_id,
                    "source_file": "",
                    "reason": (f"threshold-not-met: {len(kept_matches)} < {threshold}"),
                }
            )
            continue

        rule_id = str(override.get("rule_id", base_rule_id))
        control_mapping_tags = override.get("control_mapping_tags", [])
        if not isinstance(control_mapping_tags, list):
            control_mapping_tags = []

        for match in kept_matches:
            weighted_score = _weighted_score(match, effective_weights)
            severity = str(override.get("severity", _score_to_severity(weighted_score)))
            findings.append(
                {
                    "id": f"{rule_id}:{match.entity.name}:{match.entity.source_file}",
                    "rule_id": rule_id,
                    "base_rule_id": base_rule_id,
                    "category": match.metadata.category,
                    "owasp_llm": match.metadata.owasp_llm,
                    "severity": severity,
                    "rationale": match.metadata.rationale,
                    "heuristic": "true",
                    "confidence": f"{match.confidence:.2f}",
                    "exposure": f"{match.exposure:.2f}",
                    "provenance_completeness": f"{match.provenance_completeness:.2f}",
                    "weighted_score": f"{weighted_score:.3f}",
                    "control_mappings": list(match.metadata.control_mappings),
                    "control_mapping_tags": [str(tag) for tag in control_mapping_tags],
                    "evidence_requirements": list(match.metadata.evidence_requirements),
                }
            )

    audit = {
        "policy": provenance,
        "applied_rules": sorted(applied_rules, key=lambda item: item["base_rule_id"]),
        "suppressed": sorted(
            suppressed,
            key=lambda item: (
                item["base_rule_id"],
                item["entity_type"],
                item["name"],
                item["source_file"],
            ),
        ),
        "scoring": {"weights": global_weights},
    }
    return sorted(findings, key=lambda item: item["id"]), audit


def generate_risk_findings(
    aibom: dict[str, Any], policy_path: Path | None = None
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    return evaluate_risk(aibom, policy_path=policy_path)
