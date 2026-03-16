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


def list_run_history(target_dir: Path, limit: int | None = None) -> list[Path]:
    run_dir = target_dir / ".aibom" / "runs"
    if not run_dir.exists():
        return []
    runs = sorted(run_dir.glob("*.json"))
    if limit is not None:
        return runs[-limit:]
    return runs


def persist_periodic_snapshot(
    target_dir: Path,
    aibom: dict[str, Any],
    interval: str,
    drift: dict[str, Any],
) -> Path:
    snapshots_dir = target_dir / ".aibom" / "periodic"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now()
    payload = {
        "snapshot_id": f"{timestamp}_{git_sha(target_dir)[:12]}",
        "timestamp": timestamp,
        "interval": interval,
        "git_sha": git_sha(target_dir),
        "aibom_metadata": aibom.get("metadata", {}),
        "runtime_context": aibom.get("runtime_context", {}),
        "drift": drift,
    }
    out = snapshots_dir / f"{timestamp}.json"
    out.write_text(stable_json(payload), encoding="utf-8")

    history_index = snapshots_dir / "history.json"
    history: dict[str, Any] = {"snapshots": []}
    if history_index.exists():
        history = json.loads(history_index.read_text(encoding="utf-8"))
    history.setdefault("snapshots", []).append(
        {
            "snapshot": out.name,
            "timestamp": timestamp,
            "interval": interval,
            "artifact_sha256": aibom.get("metadata", {}).get("artifact_sha256", ""),
            "trend": drift.get("trend", {}),
        }
    )
    history["snapshots"] = history["snapshots"][-200:]
    history_index.write_text(stable_json(history), encoding="utf-8")
    return out


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
