from __future__ import annotations

import json
from pathlib import Path

from aibom.analyzer import generate_aibom
from aibom.risk.rules import load_builtin_rulepack


def _fixture_project() -> Path:
    return Path(__file__).parent / "fixtures" / "sample_project"


def test_builtin_rulepack_registry_exposes_rule_metadata() -> None:
    rulepack = load_builtin_rulepack()
    assert {"third-party-provider", "exfil-surface", "prompt-injection-surface"} <= set(rulepack)
    provider_rule = rulepack["third-party-provider"]
    assert provider_rule.metadata.category == "third-party dependency"
    assert provider_rule.metadata.evidence_requirements
    assert provider_rule.metadata.control_mappings


def test_policy_override_can_disable_rule_and_add_control_tags(tmp_path: Path) -> None:
    policy = {
        "policy_id": "org-risk-rules",
        "version": "2026.04",
        "scoring": {"weights": {"confidence": 0.2, "exposure": 0.6, "provenance": 0.2}},
        "rule_overrides": {
            "prompt-injection-surface": {"enabled": False},
            "third-party-provider": {"control_mapping_tags": ["tier-1-vendor"]},
        },
    }
    policy_path = tmp_path / "risk-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    doc = generate_aibom(_fixture_project(), risk_policy_path=policy_path)
    assert not any(f["base_rule_id"] == "prompt-injection-surface" for f in doc["risk_findings"])
    assert any(s["reason"] == "disabled-by-policy" for s in doc["risk_policy"]["suppressed"])

    provider_findings = [
        f for f in doc["risk_findings"] if f["base_rule_id"] == "third-party-provider"
    ]
    assert provider_findings
    assert all("weighted_score" in finding for finding in provider_findings)
    assert all(
        finding["control_mapping_tags"] == ["tier-1-vendor"] for finding in provider_findings
    )


def test_legacy_policy_format_remains_supported(tmp_path: Path) -> None:
    legacy_policy = {
        "policy_id": "legacy",
        "version": "1",
        "rule_overrides": {"third-party-provider": {"rule_id": "LEG-01", "severity": "high"}},
    }
    policy_path = tmp_path / "legacy-risk-policy.json"
    policy_path.write_text(json.dumps(legacy_policy), encoding="utf-8")

    doc = generate_aibom(_fixture_project(), risk_policy_path=policy_path)
    provider_findings = [
        f for f in doc["risk_findings"] if f["base_rule_id"] == "third-party-provider"
    ]
    assert provider_findings
    assert all(f["severity"] == "high" and f["rule_id"] == "LEG-01" for f in provider_findings)
