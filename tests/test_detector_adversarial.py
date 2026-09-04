from __future__ import annotations

from pathlib import Path

from aibom.analyzer import generate_aibom


def _adversarial_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "adversarial"


def _models_for(doc: dict, source_file: str) -> list[dict]:
    return [m for m in doc["models"] if m.get("source_file") == source_file]


def test_wrapper_factory_models_are_inferred_not_observed() -> None:
    doc = generate_aibom(_adversarial_dir())
    factory_models = _models_for(doc, "wrapper_factory.py")
    assert any(m["type"] == "ChatOpenAI" for m in factory_models)
    assert all(m.get("evidence_class") == "inferred_dependency" for m in factory_models)
    assert any(
        str(m.get("detection_method", "")).startswith("factory:") for m in factory_models
    )
    assert any(
        str(m.get("type", "")).startswith("Factory:") for m in factory_models
    )


def test_env_driven_model_selection_resolves_default() -> None:
    doc = generate_aibom(_adversarial_dir())
    env_models = _models_for(doc, "env_driven.py")
    assert env_models
    resolved = [m for m in env_models if m.get("model") == "gpt-4o-mini"]
    assert resolved
    assert all(m.get("evidence_class") == "inferred_dependency" for m in resolved)
    assert any("config-dataflow" in str(m.get("detection_method", "")) for m in resolved)


def test_dynamic_import_is_suspected_usage() -> None:
    doc = generate_aibom(_adversarial_dir())
    tools = [t for t in doc["tools"] if t.get("source_file") == "dynamic_imports.py"]
    assert any(
        t.get("evidence_class") == "suspected_usage"
        and t.get("detection_method") == "dynamic-import-hook"
        for t in tools
    )
    findings = [
        f
        for f in doc["scan_findings"]
        if f.get("category") == "dynamic import"
        and f.get("source_file") == "dynamic_imports.py"
    ]
    assert findings
    assert all(f["confidence"] == "low" for f in findings)


def test_js_factory_and_config_indirection_are_inferred() -> None:
    doc = generate_aibom(_adversarial_dir())
    ts_models = [
        m
        for m in doc["models"]
        if str(m.get("source_file", "")).startswith("wrapper_factory.ts")
    ]
    assert any(
        m["type"] == "OpenAI"
        and str(m.get("detection_method", "")).startswith("factory:")
        for m in ts_models
    )
    pinned = [m for m in ts_models if m.get("model") == "gpt-4o-mini"]
    assert pinned
    assert all(m.get("evidence_class") == "inferred_dependency" for m in pinned)
    assert any(
        str(m.get("type", "")).startswith("Factory:") for m in ts_models
    )


def test_misleading_config_keys_produce_no_models() -> None:
    doc = generate_aibom(_adversarial_dir())
    assert not _models_for(doc, "misleading_config.yaml")


def test_known_blind_spot_raw_http_documents_gap() -> None:
    """Raw HTTP provider calls are a tracked detection gap (no SDK surface)."""
    doc = generate_aibom(_adversarial_dir())
    assert not _models_for(doc, "blind_spots.py")


def test_detector_benchmark_recall_on_adversarial_corpus() -> None:
    """Benchmark: every expected adversarial finding must be present (recall 1.0)."""
    import json

    cases = json.loads(
        (Path(__file__).parent / "fixtures" / "benchmark" / "cases.json").read_text(
            encoding="utf-8"
        )
    )
    doc = generate_aibom(_adversarial_dir())
    total_expected = 0
    total_found = 0
    for case in cases:
        source = case["source_file"]
        models = _models_for(doc, source)
        for expected in case.get("expect_models", []):
            total_expected += 1
            hit = any(
                m.get("type") == expected["type"]
                and m.get("evidence_class") == expected["evidence_class"]
                for m in models
            )
            assert hit, f"missing expected model {expected} in {source}"
            total_found += 1
        for forbidden in case.get("expect_no_models", []):
            assert not any(m.get("type") == forbidden for m in models), (
                f"unexpected model {forbidden} in {source}"
            )
    recall = total_found / total_expected if total_expected else 1.0
    assert recall == 1.0
