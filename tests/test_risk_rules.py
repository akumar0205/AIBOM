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


def _synthetic_aibom(**overrides: object) -> dict:
    doc: dict = {
        "models": [],
        "tools": [],
        "prompts": [],
        "datasets": [],
        "scan_findings": [],
    }
    doc.update(overrides)
    return doc


def test_soc_control_pack_has_ten_rules_with_objectives() -> None:
    from aibom.risk.heuristics import evaluate_risk

    rulepack = load_builtin_rulepack()
    assert len(rulepack) >= 10
    for rule_id, rule in rulepack.items():
        assert rule.metadata.control_objective, rule_id
        assert rule.metadata.remediation, rule_id
        assert rule.metadata.owasp_llm, rule_id

    findings, audit = evaluate_risk(_synthetic_aibom())
    assert findings == []
    assert len(audit["applied_rules"]) >= 10


def test_secret_exposure_rule_fires_on_credential_findings() -> None:
    from aibom.risk.heuristics import evaluate_risk

    doc = _synthetic_aibom(
        scan_findings=[
            {
                "id": "config:openai_api_key:.env",
                "category": "provider credential",
                "source_type": "config",
                "source_file": ".env",
                "severity": "high",
                "confidence": "medium",
                "evidence": "OPENAI_API_KEY=[masked]",
            }
        ]
    )
    findings, _ = evaluate_risk(doc)
    secrets = [f for f in findings if f["base_rule_id"] == "secret-exposure"]
    assert secrets
    assert all(f["control_objective"] and f["remediation"] for f in secrets)
    assert all(f["finding_kind"] == "risk" for f in secrets)


def test_internet_egress_rule_fires_on_network_tools() -> None:
    from aibom.risk.heuristics import evaluate_risk

    doc = _synthetic_aibom(tools=[{"name": "Requests", "source_file": "app.py"}])
    findings, _ = evaluate_risk(doc)
    assert any(f["base_rule_id"] == "internet-egress" for f in findings)
    quiet, _ = evaluate_risk(
        _synthetic_aibom(tools=[{"name": "PromptTemplate", "source_file": "app.py"}])
    )
    assert not any(f["base_rule_id"] == "internet-egress" for f in quiet)


def test_retrieval_augmentation_rule_fires_on_vectorstores() -> None:
    from aibom.risk.heuristics import evaluate_risk

    doc = _synthetic_aibom(
        datasets=[{"type": "langchain.vectorstores.FAISS", "source_file": "app.py"}]
    )
    findings, _ = evaluate_risk(doc)
    assert any(f["base_rule_id"] == "retrieval-augmentation" for f in findings)


def test_tool_execution_rule_fires_on_tools() -> None:
    from aibom.risk.heuristics import evaluate_risk

    doc = _synthetic_aibom(tools=[{"name": "initialize_agent", "source_file": "app.py"}])
    findings, _ = evaluate_risk(doc)
    assert any(f["base_rule_id"] == "tool-execution" for f in findings)


def test_prompt_logging_rule_fires_on_prompts() -> None:
    from aibom.risk.heuristics import evaluate_risk

    doc = _synthetic_aibom(prompts=[{"id": "app.py:9", "source_file": "app.py"}])
    findings, _ = evaluate_risk(doc)
    assert any(f["base_rule_id"] == "prompt-logging" for f in findings)


def test_model_version_drift_rule_fires_on_unpinned_models() -> None:
    from aibom.risk.heuristics import evaluate_risk

    doc = _synthetic_aibom(
        models=[
            {"type": "ChatOpenAI", "model": "unknown", "source_file": "app.py"},
            {"type": "ChatOpenAI", "model": "gpt-4o-mini", "source_file": "app.py"},
        ]
    )
    findings, _ = evaluate_risk(doc)
    drift = [f for f in findings if f["base_rule_id"] == "model-version-drift"]
    assert len(drift) == 1


def test_unsupported_provider_rule_fires_on_wrappers() -> None:
    from aibom.risk.heuristics import evaluate_risk

    doc = _synthetic_aibom(
        models=[
            {"type": "Factory:build_llm", "model": "unknown", "source_file": "app.py"},
            {"type": "ChatOpenAI", "model": "gpt-4o-mini", "source_file": "app.py"},
        ]
    )
    findings, _ = evaluate_risk(doc)
    unsupported = [f for f in findings if f["base_rule_id"] == "unsupported-provider-use"]
    assert len(unsupported) == 1
