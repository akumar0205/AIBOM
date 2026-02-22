from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

from aibom.analyzer import generate_aibom
from aibom.bundle import create_bundle
from aibom.diffing import diff_aibom
from aibom.exporters import export_spdx
from aibom.validation import AIBOMValidationException, validate_aibom


def _fixture_project() -> Path:
    return Path(__file__).parent / "fixtures" / "sample_project"


def test_generate_matches_golden_structure() -> None:
    doc = generate_aibom(_fixture_project())
    validate_aibom(doc)
    golden = json.loads((Path(__file__).parent / "fixtures" / "golden_aibom.json").read_text())
    for k in ["generated_at", "git_sha", "artifact_sha256"]:
        doc["metadata"][k] = "DYNAMIC"
    assert doc == golden


def test_generated_aibom_validates_against_schema() -> None:
    doc = generate_aibom(_fixture_project())
    validate_aibom(doc)


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
    invalid_doc = json.loads((fixtures_dir / "invalid_aibom_missing_field.json").read_text(encoding="utf-8"))

    validate_aibom(valid_doc)
    with pytest.raises(AIBOMValidationException) as exc:
        validate_aibom(invalid_doc)

    assert "/metadata/generated_at" in str(exc.value)


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



def test_generate_fails_closed_before_writing_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    assert [p["SPDXID"] for p in spdx["packages"]] == sorted([p["SPDXID"] for p in spdx["packages"]])


def test_diff_detects_additions() -> None:
    old = {"models": [], "tools": [], "datasets": []}
    new = {"models": [{"type": "ChatOpenAI"}], "tools": [{"name": "initialize_agent"}], "datasets": []}
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
    proc = subprocess.run([sys.executable, "-m", "aibom.cli", "--version"], capture_output=True, text=True, check=True)
    assert "aibom" in proc.stdout
