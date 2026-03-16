from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

EXTERNAL_PROVIDER_MODELS = {"OpenAI", "ChatOpenAI", "ChatAnthropic"}
EXFIL_TOOLS = {"Requests", "ReadFileTool", "WriteFileTool", "SerpAPI"}


@dataclass(frozen=True)
class NormalizedEntity:
    entity_type: str
    name: str
    source_file: str


@dataclass(frozen=True)
class RuleMatch:
    base_rule_id: str
    category: str
    owasp_llm: str
    default_severity: str
    rationale: str
    entity: NormalizedEntity


def _stable_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _load_policy_file(policy_path: Path | None) -> tuple[dict[str, Any], dict[str, Any]]:
    if policy_path is None:
        default_policy = {"policy_id": "builtin-default", "version": "1", "rule_overrides": {}}
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


def _evaluate_external_provider_rule(
    entities: dict[str, list[NormalizedEntity]]
) -> list[RuleMatch]:
    return [
        RuleMatch(
            base_rule_id="third-party-provider",
            category="third-party dependency",
            owasp_llm="LLM07 Insecure Plugin Design",
            default_severity="medium",
            rationale="External model provider detected.",
            entity=entity,
        )
        for entity in entities["models"]
        if entity.name in EXTERNAL_PROVIDER_MODELS
    ]


def _evaluate_exfil_rule(entities: dict[str, list[NormalizedEntity]]) -> list[RuleMatch]:
    return [
        RuleMatch(
            base_rule_id="exfil-surface",
            category="exfil surface",
            owasp_llm="LLM06 Sensitive Information Disclosure",
            default_severity="high",
            rationale="Tool may read/write data or access web.",
            entity=entity,
        )
        for entity in entities["tools"]
        if entity.name in EXFIL_TOOLS
    ]


def _evaluate_prompt_surface_rule(entities: dict[str, list[NormalizedEntity]]) -> list[RuleMatch]:
    return [
        RuleMatch(
            base_rule_id="prompt-injection-surface",
            category="prompt injection surface",
            owasp_llm="LLM01 Prompt Injection",
            default_severity="medium",
            rationale="Prompt templates detected; review source trust boundaries.",
            entity=entity,
        )
        for entity in entities["prompts"]
    ]


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


def evaluate_risk(
    aibom: dict[str, Any], policy_path: Path | None = None
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    policy, provenance = _load_policy_file(policy_path)
    overrides = policy.get("rule_overrides", {})

    entities = _normalize_entities(aibom)
    matches = [
        *_evaluate_external_provider_rule(entities),
        *_evaluate_exfil_rule(entities),
        *_evaluate_prompt_surface_rule(entities),
    ]

    grouped: dict[str, list[RuleMatch]] = {}
    for match in matches:
        grouped.setdefault(match.base_rule_id, []).append(match)

    findings: list[dict[str, str]] = []
    suppressed: list[dict[str, str]] = []
    applied_rules: list[dict[str, Any]] = []

    for base_rule_id, rule_matches in sorted(grouped.items()):
        override = overrides.get(base_rule_id, {}) if isinstance(overrides, dict) else {}
        threshold = int(override.get("threshold", 1))
        allowlist = override.get("allowlist", [])
        if not isinstance(allowlist, list):
            allowlist = []

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

        applied_rules.append(
            {
                "base_rule_id": base_rule_id,
                "rule_id": str(override.get("rule_id", base_rule_id)),
                "severity": str(override.get("severity", rule_matches[0].default_severity)),
                "threshold": threshold,
                "candidate_count": len(rule_matches),
                "post_allowlist_count": len(kept_matches),
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
        severity = str(override.get("severity", kept_matches[0].default_severity))
        for match in kept_matches:
            findings.append(
                {
                    "id": f"{rule_id}:{match.entity.name}:{match.entity.source_file}",
                    "rule_id": rule_id,
                    "base_rule_id": base_rule_id,
                    "category": match.category,
                    "owasp_llm": match.owasp_llm,
                    "severity": severity,
                    "rationale": match.rationale,
                    "heuristic": "true",
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
    }
    return sorted(findings, key=lambda item: item["id"]), audit


def generate_risk_findings(
    aibom: dict[str, Any], policy_path: Path | None = None
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    return evaluate_risk(aibom, policy_path=policy_path)
