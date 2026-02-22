from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from aibom.diffing import diff_aibom
from aibom.exporters import export_spdx
from aibom.storage import load_json
from aibom.utils import environment_capture, sha256_bytes, stable_json


def build_manifest(files: dict[str, bytes]) -> dict[str, str]:
    return {name: sha256_bytes(content) for name, content in sorted(files.items())}


def create_bundle(aibom_path: Path, out_zip: Path, baseline_path: Path | None = None, compliance_md: str = "") -> Path:
    aibom = load_json(aibom_path)
    files: dict[str, bytes] = {}
    files["AIBOM.json"] = stable_json(aibom).encode("utf-8")
    files["SPDX.json"] = stable_json(export_spdx(aibom)).encode("utf-8")
    if baseline_path and baseline_path.exists():
        baseline = load_json(baseline_path)
        files["DIFF.json"] = stable_json(diff_aibom(baseline, aibom)).encode("utf-8")
    files["ENVIRONMENT.json"] = stable_json(environment_capture()).encode("utf-8")
    files["COMPLIANCE_MAPPING.md"] = compliance_md.encode("utf-8")
    manifest = build_manifest(files)
    files["MANIFEST.json"] = stable_json(manifest).encode("utf-8")

    with ZipFile(out_zip, "w", compression=ZIP_DEFLATED) as zf:
        for name in sorted(files):
            zf.writestr(name, files[name])
    return out_zip
