from __future__ import annotations

import json
import subprocess
from pathlib import Path

from aibom.analyzer import generate_aibom
from aibom.bundle import create_bundle
from aibom.diffing import diff_aibom
from aibom.exporters import export_spdx
from aibom.validation import validate_aibom


def _fixture_project() -> Path:
    return Path(__file__).parent / "fixtures" / "sample_project"


def test_generate_matches_golden_structure() -> None:
    doc = generate_aibom(_fixture_project())
    validate_aibom(doc)
    golden = json.loads((Path(__file__).parent / "fixtures" / "golden_aibom.json").read_text())
    for k in ["generated_at", "git_sha", "artifact_sha256"]:
        doc["metadata"][k] = "DYNAMIC"
    assert doc == golden


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
    proc = subprocess.run(["aibom", "--version"], capture_output=True, text=True, check=True)
    assert "aibom" in proc.stdout
