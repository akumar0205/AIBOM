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
from aibom.diffing import diff_aibom
from aibom.exporters import export_spdx
from aibom.validation import AIBOMValidationException, validate_aibom


def _fixture_project() -> Path:
    return Path(__file__).parent / "fixtures" / "sample_project"


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


def test_runtime_manifest_ingestion_is_opt_in() -> None:
    base = generate_aibom(_fixture_project())
    runtime = generate_aibom(_fixture_project(), include_runtime_manifests=True)

    assert not any(f["source_type"] == "runtime_manifest" for f in base["scan_findings"])
    assert any(f["source_type"] == "runtime_manifest" for f in runtime["scan_findings"])


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
    valid_doc = json.loads((fixtures_dir / "valid_aibom.json").read_text(encoding="utf-8"))
    invalid_doc = json.loads(
        (fixtures_dir / "invalid_aibom_missing_field.json").read_text(encoding="utf-8")
    )

    validate_aibom(valid_doc)
    with pytest.raises(AIBOMValidationException) as exc:
        validate_aibom(invalid_doc)

    assert "/metadata/" in str(exc.value)


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
            include_runtime_manifests=False,
            audit_mode=False,
            bundle_out=None,
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
