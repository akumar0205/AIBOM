from __future__ import annotations

import argparse
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from aibom.analyzer import generate_aibom
from aibom.bundle import create_bundle, verify_bundle_signature
from aibom.diffing import diff_aibom, trend_diff_aibom
from aibom.exporters import export_spdx
from aibom.validation import AIBOMValidationException, validate_aibom


def _fixture_project() -> Path:
    return Path(__file__).parent / "fixtures" / "sample_project"


def _runtime_fixture_project() -> Path:
    return Path(__file__).parent / "fixtures" / "runtime_project"


def test_generate_matches_golden_structure() -> None:
    doc = generate_aibom(_fixture_project(), include_runtime_manifests=True)
    validate_aibom(doc)
    golden = json.loads((Path(__file__).parent / "fixtures" / "golden_aibom.json").read_text())
    for k in ["generated_at", "git_sha", "artifact_sha256"]:
        doc["metadata"][k] = "DYNAMIC"
    assert doc == golden


def test_generated_aibom_validates_against_schema() -> None:
    doc = generate_aibom(_fixture_project())
    validate_aibom(doc)


def test_config_detector_finds_model_provider_and_keys() -> None:
    doc = generate_aibom(_fixture_project())

    assert any(
        model["type"] == "ConfigModelHint" and model["source_file"] == "settings.yaml"
        for model in doc["models"]
    )
    assert {f["source_type"] for f in doc["scan_findings"]} >= {"python", "config"}
    assert any(
        f["category"] == "provider credential" and f["source_file"] == ".env"
        for f in doc["scan_findings"]
    )


def test_secret_evidence_is_redacted_for_all_policies() -> None:
    for policy in ("strict", "default", "off"):
        doc = generate_aibom(_fixture_project(), redaction_policy=policy)
        evidence = "\n".join(
            f["evidence"] for f in doc["scan_findings"] if f["source_type"] == "config"
        )
        assert "sk-test-value" not in evidence
        assert "anth-test" not in evidence
        assert "[masked:" in evidence
        assert "hash:" in evidence


def test_strict_redaction_masks_non_secret_config_values() -> None:
    strict = generate_aibom(_fixture_project(), redaction_policy="strict")
    default = generate_aibom(_fixture_project(), redaction_policy="default")

    strict_evidence = {
        f["id"]: f["evidence"] for f in strict["scan_findings"] if f["source_type"] == "config"
    }
    default_evidence = {
        f["id"]: f["evidence"] for f in default["scan_findings"] if f["source_type"] == "config"
    }

    assert "[masked:" in strict_evidence["config:model:settings.yaml"]
    assert default_evidence["config:model:settings.yaml"] == "model=gpt-4.1-mini"


def test_runtime_manifest_ingestion_is_opt_in() -> None:
    base = generate_aibom(_fixture_project())
    runtime = generate_aibom(_fixture_project(), include_runtime_manifests=True)

    assert not any(f["source_type"] == "runtime_manifest" for f in base["scan_findings"])
    assert any(f["source_type"] == "runtime_manifest" for f in runtime["scan_findings"])


def test_provenance_fields_present_for_models_and_runtime_context() -> None:
    doc = generate_aibom(_fixture_project(), include_runtime_manifests=True)

    required_fields = {
        "provider_endpoint",
        "registry_uri",
        "immutable_version",
        "environment",
        "region",
    }
    assert required_fields <= set(doc["runtime_context"])
    assert required_fields <= set(doc["models"][0]["provenance"])


def test_config_and_runtime_detectors_populate_provenance_when_observable() -> None:
    doc = generate_aibom(_fixture_project(), include_runtime_manifests=True)
    config_model = next(
        m
        for m in doc["models"]
        if m["type"] == "ConfigModelHint" and m["source_file"] == "settings.yaml"
    )

    assert config_model["provenance"]["provider_endpoint"] == "unknown"
    assert doc["runtime_context"]["immutable_version"] == "python:3.11-slim"


def test_runtime_manifest_detector_extracts_lineage_context(tmp_path: Path) -> None:
    deployment = tmp_path / "k8s" / "deployment.yaml"
    deployment.parent.mkdir(parents=True, exist_ok=True)
    deployment.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inference-prod-v2
  labels:
    app: model-serving
  annotations:
    deployment_id: inference-prod-v2
spec:
  template:
    spec:
      serviceAccountName: inference-sa
      model_artifact_digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      containers:
        - name: api
          image: ghcr.io/acme/serving@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""".strip(),
        encoding="utf-8",
    )

    doc = generate_aibom(tmp_path, include_runtime_manifests=True)
    lineage = doc["runtime_context"]["lineage"]

    assert lineage["deployment_id"] == "inference-prod-v2"
    assert lineage["service_account_identity"] == "inference-sa"
    assert lineage["owning_system"] == "model-serving"
    assert (
        lineage["model_artifact_digest"]
        == "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )


def test_coverage_summary_and_unsupported_artifacts_present() -> None:
    doc = generate_aibom(_fixture_project(), include_runtime_manifests=True)
    detector_types = {d["source_type"] for d in doc["coverage_summary"]["detectors"]}
    assert {
        "python",
        "jupyter_notebook",
        "config",
        "runtime_manifest",
        "js_ts_manifest",
        "js_ts_ast",
        "java_ast",
        "go_ast",
        "dotnet_ast",
    } <= detector_types
    assert not any(
        item["artifact_type"] in {".ts", ".tsx", ".js", ".jsx"}
        for item in doc["unsupported_artifacts"]
    )


def test_js_ts_ast_detector_finds_models_tools_prompts_and_frameworks() -> None:
    doc = generate_aibom(_fixture_project(), include_prompts=True)

    assert any(
        model["type"] == "OpenAI" and model["source_file"].startswith("script.ts:")
        for model in doc["models"]
    )
    assert any(tool["source_file"].startswith("script.ts:") for tool in doc["tools"])
    assert any(prompt["source_file"].startswith("script.ts:") for prompt in doc["prompts"])
    assert any(framework["name"] == "openai" for framework in doc["frameworks"])
    assert any(framework["name"] == "langchain" for framework in doc["frameworks"])
    assert any(
        f["source_type"] == "js_ts_ast" and f["source_file"].startswith("script.ts:")
        for f in doc["scan_findings"]
    )


def test_python_alias_binding_detection_for_models_and_tools() -> None:
    doc = generate_aibom(_fixture_project())

    assert any(
        model["source_file"] == "alias_wrappers.py" and model["type"] == "ChatOpenAI"
        for model in doc["models"]
    )
    assert any(
        tool["source_file"] == "alias_wrappers.py" and tool["name"] == "initialize_agent"
        for tool in doc["tools"]
    )
    python_findings = [
        finding
        for finding in doc["scan_findings"]
        if finding["source_type"] == "python" and finding["source_file"] == "alias_wrappers.py"
    ]
    assert python_findings
    assert all(finding["confidence"] in {"medium", "high"} for finding in python_findings)


def test_js_ts_ast_alias_and_factory_detection_uses_ast_context() -> None:
    doc = generate_aibom(_fixture_project(), include_prompts=True)

    assert any(
        model["source_file"].startswith("edge_cases.ts:") and model["type"] == "ChatOpenAI"
        for model in doc["models"]
    )
    assert any(
        tool["source_file"].startswith("edge_cases.ts:") and tool["name"] == "tool"
        for tool in doc["tools"]
    )
    assert any(prompt["source_file"].startswith("edge_cases.ts:") for prompt in doc["prompts"])

    edge_findings = [
        finding
        for finding in doc["scan_findings"]
        if finding["source_type"] == "js_ts_ast"
        and finding["source_file"].startswith("edge_cases.ts:")
    ]
    assert edge_findings
    assert any("context=" in finding["evidence"] for finding in edge_findings)


def test_java_go_dotnet_detectors_find_expected_surfaces() -> None:
    doc = generate_aibom(_fixture_project(), include_prompts=True)

    expected_source_types = {"java_ast", "go_ast", "dotnet_ast"}
    assert expected_source_types <= {item["name"] for item in doc["source_types"]}

    for source_type in expected_source_types:
        assert any(f["source_type"] == source_type for f in doc["scan_findings"])

    assert any(model["source_file"].startswith("assistant.java:") for model in doc["models"])
    assert any(model["source_file"].startswith("assistant.go:") for model in doc["models"])
    assert any(model["source_file"].startswith("Assistant.cs:") for model in doc["models"])

    assert any(tool["source_file"].startswith("assistant.java:") for tool in doc["tools"])
    assert any(tool["source_file"].startswith("assistant.go:") for tool in doc["tools"])
    assert any(tool["source_file"].startswith("Assistant.cs:") for tool in doc["tools"])

    assert any(prompt["source_file"].startswith("assistant.java:") for prompt in doc["prompts"])
    assert any(prompt["source_file"].startswith("assistant.go:") for prompt in doc["prompts"])
    assert any(prompt["source_file"].startswith("Assistant.cs:") for prompt in doc["prompts"])


def test_cli_generate_fails_on_unsupported_threshold(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    for src in _fixture_project().iterdir():
        if src.is_file():
            (project / src.name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (project / "scanner.toml").write_text("[tool.aibom]\nstrict=true\n", encoding="utf-8")

    output_path = tmp_path / "aibom.json"
    cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "generate",
            str(project),
            "-o",
            str(output_path),
            "--fail-on-unsupported-threshold",
            "0",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cmd.returncode == 2
    assert "Unsupported artifact threshold exceeded" in cmd.stderr


def test_cli_generate_passes_when_unsupported_threshold_allows(tmp_path: Path) -> None:
    output_path = tmp_path / "aibom.json"
    cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "generate",
            str(_fixture_project()),
            "-o",
            str(output_path),
            "--fail-on-unsupported-threshold",
            "10",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cmd.returncode == 0
    assert output_path.exists()


def test_validation_fails_for_missing_required_field() -> None:
    doc = generate_aibom(_fixture_project())
    del doc["metadata"]["artifact_sha256"]
    with pytest.raises(AIBOMValidationException) as exc:
        validate_aibom(doc)
    assert "/metadata/artifact_sha256" in str(exc.value)


def test_golden_fixture_validates_against_schema() -> None:
    golden = json.loads((Path(__file__).parent / "fixtures" / "golden_aibom.json").read_text())
    golden["metadata"]["artifact_sha256"] = "0" * 64
    validate_aibom(golden)


def test_validation_fixtures_cover_valid_and_invalid_cases() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures"
    validation_dir = fixtures_dir / "validation"
    valid_doc = json.loads((fixtures_dir / "valid_aibom.json").read_text(encoding="utf-8"))
    minimal_provenance_doc = json.loads(
        (validation_dir / "valid_minimal_provenance_aibom.json").read_text(encoding="utf-8")
    )
    enriched_provenance_doc = json.loads(
        (validation_dir / "valid_enriched_provenance_aibom.json").read_text(encoding="utf-8")
    )
    invalid_doc = json.loads(
        (fixtures_dir / "invalid_aibom_missing_field.json").read_text(encoding="utf-8")
    )

    validate_aibom(valid_doc)
    validate_aibom(minimal_provenance_doc)
    validate_aibom(enriched_provenance_doc)
    with pytest.raises(AIBOMValidationException) as exc:
        validate_aibom(invalid_doc)

    assert "/" in str(exc.value)


def test_cli_prompt_inclusion_requires_acknowledgement(tmp_path: Path) -> None:
    output_path = tmp_path / "aibom.json"
    cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "generate",
            str(_fixture_project()),
            "-o",
            str(output_path),
            "--include-prompts",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cmd.returncode == 2
    assert "requires --acknowledge-prompt-exposure-risk" in cmd.stderr


def test_cli_prompt_inclusion_warns_with_acknowledgement(tmp_path: Path) -> None:
    output_path = tmp_path / "aibom.json"
    cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "generate",
            str(_fixture_project()),
            "-o",
            str(output_path),
            "--include-prompts",
            "--acknowledge-prompt-exposure-risk",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cmd.returncode == 0
    assert "WARNING: Including prompts may expose sensitive" in cmd.stderr


def test_cli_validate_command_success_and_failure(tmp_path: Path) -> None:
    valid_doc = generate_aibom(_fixture_project())
    valid_path = tmp_path / "valid.json"
    valid_path.write_text(json.dumps(valid_doc), encoding="utf-8")

    ok = subprocess.run(
        [sys.executable, "-m", "aibom.cli", "validate", str(valid_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0
    assert "OK: AIBOM validates against schema" in ok.stdout

    invalid_doc = dict(valid_doc)
    invalid_doc.pop("models", None)
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text(json.dumps(invalid_doc), encoding="utf-8")
    bad = subprocess.run(
        [sys.executable, "-m", "aibom.cli", "validate", str(invalid_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 2
    assert "/" in bad.stderr


def test_generate_fails_closed_before_writing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aibom import cli as cli_module

    invalid_doc = generate_aibom(_fixture_project())
    invalid_doc["metadata"].pop("generated_at", None)

    def _fake_generate(*_args: object, **_kwargs: object) -> dict:
        return invalid_doc

    monkeypatch.setattr(cli_module, "generate_aibom", _fake_generate)

    output_path = tmp_path / "should_not_exist.json"
    rc = cli_module.cmd_generate(
        argparse.Namespace(
            target=str(_fixture_project()),
            output=str(output_path),
            include_prompts=False,
            acknowledge_prompt_exposure_risk=False,
            include_runtime_manifests=False,
            redaction_policy="strict",
            audit_mode=False,
            bundle_out=None,
            fail_on_unsupported_threshold=None,
            risk_policy=None,
        )
    )

    assert rc == 2
    assert not output_path.exists()


def test_export_spdx_deterministic() -> None:
    doc = generate_aibom(_fixture_project())
    spdx = export_spdx(doc)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert [p["SPDXID"] for p in spdx["packages"]] == sorted(
        [p["SPDXID"] for p in spdx["packages"]]
    )


def test_runtime_manifest_supports_lockfiles_k8s_and_oci_findings() -> None:
    doc = generate_aibom(_runtime_fixture_project(), include_runtime_manifests=True)

    runtime_findings = [f for f in doc["scan_findings"] if f["source_type"] == "runtime_manifest"]
    assert any(f["category"] == "immutable image digest" for f in runtime_findings)
    assert any(f["category"] == "runtime ai service config" for f in runtime_findings)
    assert any(f["source_file"].endswith("k8s/deployment.yaml") for f in runtime_findings)
    assert any(framework["name"] == "langchain" for framework in doc["frameworks"])
    assert "@sha256:" in doc["runtime_context"]["immutable_version"]


def test_trend_diff_tracks_novel_components() -> None:
    history = [
        {"models": [{"type": "ChatOpenAI"}], "tools": [{"name": "Tool"}], "datasets": []},
        {"models": [{"type": "ChatOpenAI"}], "tools": [{"name": "Tool"}], "datasets": []},
    ]
    current = {
        "models": [{"type": "ChatOpenAI"}, {"type": "ChatAnthropic"}],
        "tools": [{"name": "Tool"}, {"name": "initialize_agent"}],
        "datasets": [{"type": "Chroma"}],
    }

    drift = trend_diff_aibom(history, current)
    assert drift["trend"]["history_window"] == 2
    assert any(
        item["type"] == "ChatAnthropic" for item in drift["trend"]["novel_since_window"]["models"]
    )
    assert any(
        item["name"] == "initialize_agent" for item in drift["trend"]["novel_since_window"]["tools"]
    )


def test_cli_periodic_scan_persists_history_and_trend_output(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "from langchain_openai import ChatOpenAI\nChatOpenAI(model='gpt-4o-mini')\n",
        encoding="utf-8",
    )

    output_path = tmp_path / "periodic.json"
    first = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "periodic-scan",
            str(project),
            "-o",
            str(output_path),
            "--include-runtime-manifests",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0

    (project / "tool.py").write_text(
        "from langchain.agents import initialize_agent\n", encoding="utf-8"
    )
    second = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "periodic-scan",
            str(project),
            "-o",
            str(output_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert second.returncode == 0

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["history_window"] >= 1
    assert "trend" in payload["drift"]

    history_file = project / ".aibom" / "periodic" / "history.json"
    assert history_file.exists()
    history_data = json.loads(history_file.read_text(encoding="utf-8"))
    assert len(history_data["snapshots"]) >= 2


def test_diff_detects_additions() -> None:
    old = {"models": [], "tools": [], "datasets": []}
    new = {
        "models": [{"type": "ChatOpenAI"}],
        "tools": [{"name": "initialize_agent"}],
        "datasets": [],
    }
    d = diff_aibom(old, new)
    assert len(d["added"]["models"]) == 1
    assert len(d["added"]["tools"]) == 1


def test_bundle_contains_manifest(tmp_path: Path) -> None:
    doc = generate_aibom(_fixture_project())
    aibom_path = tmp_path / "aibom.json"
    aibom_path.write_text(json.dumps(doc), encoding="utf-8")
    bundle_path = tmp_path / "evidence.zip"
    create_bundle(aibom_path, bundle_path, compliance_md="# map")
    assert bundle_path.exists()


def test_cli_version() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "aibom.cli", "--version"], capture_output=True, text=True, check=True
    )
    assert "aibom" in proc.stdout


def _create_signing_material(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "signing.key"
    cert = tmp_path / "signing.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=aibom-test",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return key, cert


def _create_ca_and_leaf(tmp_path: Path) -> tuple[Path, Path, Path]:
    ca_key = tmp_path / "ca.key"
    ca_cert = tmp_path / "ca.crt"
    leaf_key = tmp_path / "leaf.key"
    leaf_csr = tmp_path / "leaf.csr"
    leaf_cert = tmp_path / "leaf.crt"
    ext_file = tmp_path / "leaf.ext"

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=Test Root CA",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(leaf_key),
            "-out",
            str(leaf_csr),
            "-nodes",
            "-subj",
            "/CN=aibom-leaf",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    ext_file.write_text("subjectAltName=DNS:aibom.example\n")
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(leaf_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(leaf_cert),
            "-days",
            "1",
            "-extfile",
            str(ext_file),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return leaf_key, leaf_cert, ca_cert


def test_bundle_sign_and_attest_verify(tmp_path: Path) -> None:
    doc = generate_aibom(_fixture_project())
    aibom_path = tmp_path / "aibom.json"
    aibom_path.write_text(json.dumps(doc), encoding="utf-8")
    bundle_path = tmp_path / "evidence.zip"
    key, cert = _create_signing_material(tmp_path)

    bundle_cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "bundle",
            "--input",
            str(aibom_path),
            "--out",
            str(bundle_path),
            "--sign",
            "--signing-key",
            str(key),
            "--signing-cert",
            str(cert),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bundle_cmd.returncode == 0

    sig = tmp_path / "evidence.zip.sig"
    provenance = tmp_path / "provenance.json"
    assert sig.exists()
    assert provenance.exists()

    verify_cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "attest",
            "--bundle",
            str(bundle_path),
            "--signature",
            str(sig),
            "--provenance",
            str(provenance),
            "--signing-cert",
            str(cert),
            "--verify",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify_cmd.returncode == 0


def test_attest_writes_adjacent_artifacts(tmp_path: Path) -> None:
    doc = generate_aibom(_fixture_project())
    aibom_path = tmp_path / "aibom.json"
    aibom_path.write_text(json.dumps(doc), encoding="utf-8")
    bundle_path = tmp_path / "evidence.zip"
    create_bundle(aibom_path, bundle_path, compliance_md="# map")
    key, cert = _create_signing_material(tmp_path)

    sign_cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "attest",
            "--bundle",
            str(bundle_path),
            "--signing-key",
            str(key),
            "--signing-cert",
            str(cert),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert sign_cmd.returncode == 0

    sig = tmp_path / "evidence.zip.sig"
    provenance = tmp_path / "provenance.json"
    verify_bundle_signature(bundle_path, sig, cert, provenance)
    with zipfile.ZipFile(bundle_path) as zf:
        assert "MANIFEST.json" in zf.namelist()


def test_attest_verify_policy_checks_and_provenance(tmp_path: Path) -> None:
    doc = generate_aibom(_fixture_project())
    aibom_path = tmp_path / "aibom.json"
    aibom_path.write_text(json.dumps(doc), encoding="utf-8")
    bundle_path = tmp_path / "evidence.zip"
    create_bundle(aibom_path, bundle_path, compliance_md="# map")
    key, cert, ca_cert = _create_ca_and_leaf(tmp_path)
    provenance = tmp_path / "provenance.json"

    sign_cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "attest",
            "--bundle",
            str(bundle_path),
            "--signing-key",
            str(key),
            "--signing-cert",
            str(cert),
            "--provenance",
            str(provenance),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert sign_cmd.returncode == 0

    sig = tmp_path / "evidence.zip.sig"
    verify_cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "attest",
            "--bundle",
            str(bundle_path),
            "--signature",
            str(sig),
            "--provenance",
            str(provenance),
            "--signing-cert",
            str(cert),
            "--verify",
            "--ca-bundle",
            str(ca_cert),
            "--allow-subject",
            "CN = aibom-leaf",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify_cmd.returncode == 0

    prov = json.loads(provenance.read_text(encoding="utf-8"))
    assert prov["policy_evaluation"]["status"] == "passed"
    assert prov["policy_evaluation"]["checks"]["certificate_validity"]["status"] == "passed"
    assert prov["policy_evaluation"]["checks"]["certificate_chain"]["status"] == "passed"
    assert prov["policy_evaluation"]["checks"]["signer_allowlist"]["status"] == "passed"


def test_attest_verify_rejects_unauthorized_signer(tmp_path: Path) -> None:
    doc = generate_aibom(_fixture_project())
    aibom_path = tmp_path / "aibom.json"
    aibom_path.write_text(json.dumps(doc), encoding="utf-8")
    bundle_path = tmp_path / "evidence.zip"
    create_bundle(aibom_path, bundle_path, compliance_md="# map")
    key, cert = _create_signing_material(tmp_path)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "attest",
            "--bundle",
            str(bundle_path),
            "--signing-key",
            str(key),
            "--signing-cert",
            str(cert),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    sig = tmp_path / "evidence.zip.sig"
    verify_cmd = subprocess.run(
        [
            sys.executable,
            "-m",
            "aibom.cli",
            "attest",
            "--bundle",
            str(bundle_path),
            "--signature",
            str(sig),
            "--signing-cert",
            str(cert),
            "--verify",
            "--allow-subject",
            "subject=CN=does-not-match",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert verify_cmd.returncode != 0
    assert "not authorized" in verify_cmd.stderr


def test_risk_policy_default_provenance_present() -> None:
    doc = generate_aibom(_fixture_project())
    assert doc["risk_policy"]["policy"]["policy_id"] == "builtin-default"
    assert doc["risk_policy"]["policy"]["source"] == "builtin"


def test_risk_policy_custom_severity_override(tmp_path: Path) -> None:
    policy = {
        "policy_id": "org-risk-rules",
        "version": "2026.03",
        "rule_overrides": {"third-party-provider": {"rule_id": "ORG-TP-01", "severity": "high"}},
    }
    policy_path = tmp_path / "risk-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    doc = generate_aibom(_fixture_project(), risk_policy_path=policy_path)
    provider_findings = [
        f for f in doc["risk_findings"] if f["base_rule_id"] == "third-party-provider"
    ]
    assert provider_findings
    assert all(f["severity"] == "high" for f in provider_findings)
    assert all(f["rule_id"] == "ORG-TP-01" for f in provider_findings)
    assert doc["risk_policy"]["policy"]["policy_id"] == "org-risk-rules"


def test_risk_policy_allowlist_suppression_with_audit_trace(tmp_path: Path) -> None:
    policy = {
        "policy_id": "org-risk-rules",
        "version": "2026.03",
        "rule_overrides": {
            "third-party-provider": {
                "rule_id": "ORG-TP-01",
                "allowlist": [
                    {
                        "entity_type": "model",
                        "name": "ChatOpenAI",
                        "source_file": "app.py",
                        "reason": "approved-external-provider",
                    }
                ],
            }
        },
    }
    policy_path = tmp_path / "risk-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    doc = generate_aibom(_fixture_project(), risk_policy_path=policy_path)
    assert not any(
        f["base_rule_id"] == "third-party-provider" and f["id"].endswith(":app.py")
        for f in doc["risk_findings"]
    )
    assert any(
        s["base_rule_id"] == "third-party-provider"
        and s["name"] == "ChatOpenAI"
        and s["reason"] == "approved-external-provider"
        for s in doc["risk_policy"]["suppressed"]
    )
