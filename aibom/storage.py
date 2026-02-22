from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aibom.utils import git_sha, stable_json, utc_now


def persist_run(target_dir: Path, aibom: dict[str, Any]) -> Path:
    run_dir = target_dir / ".aibom" / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{utc_now()}_{git_sha(target_dir)[:12]}.json"
    out = run_dir / filename
    out.write_text(stable_json(aibom), encoding="utf-8")
    latest = target_dir / ".aibom" / "latest.json"
    latest.write_text(stable_json(aibom), encoding="utf-8")
    return out


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
