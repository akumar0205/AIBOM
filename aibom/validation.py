from __future__ import annotations

from typing import Any


REQUIRED_KEYS = ["schema_version", "metadata", "models", "datasets", "tools", "frameworks", "risk_findings"]


def validate_aibom(doc: dict[str, Any], schema_path: object | None = None) -> None:
    del schema_path
    missing = [k for k in REQUIRED_KEYS if k not in doc]
    if missing:
        raise ValueError(f"AIBOM missing required keys: {', '.join(missing)}")
    meta = doc.get("metadata", {})
    for key in ["generated_at", "git_sha", "artifact_sha256"]:
        if key not in meta:
            raise ValueError(f"AIBOM metadata missing '{key}'")
