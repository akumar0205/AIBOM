from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from aibom.analyzer import generate_aibom
from aibom.diffing import diff_aibom, gate_failures
from aibom.presentation import (
    build_ai_bom_like_profile,
    profile_json_dumps,
    render_markdown_summary,
)
from aibom.storage import load_json
from aibom.utils import stable_json, validate_safe_path
from aibom.validation import validate_aibom


@dataclass
class RepoScanRecord:
    repo: str
    status: str
    output_json: str
    output_profile_json: str | None
    counts: dict[str, int]
    gate_verdict: str
    gate_failures: list[str]
    error: str | None = None


def _repo_slug(repo: str) -> str:
    return repo.replace("/", "__")


def _clone_repo(
    repo: str,
    dest: Path,
    branch: str | None,
    depth: int,
    token: str | None,
    timeout_sec: int,
) -> None:
    url = f"https://github.com/{repo}.git"
    if token:
        url = f"https://x-access-token:{token}@github.com/{repo}.git"

    cmd = ["git", "clone", "--depth", str(depth)]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([url, str(dest)])

    subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout_sec)


def _count_summary(aibom: dict[str, Any]) -> dict[str, int]:
    return {
        "models": len(aibom.get("models", [])),
        "tools": len(aibom.get("tools", [])),
        "datasets": len(aibom.get("datasets", [])),
        "frameworks": len(aibom.get("frameworks", [])),
        "prompts": len(aibom.get("prompts", [])),
        "unsupported_artifacts": len(aibom.get("unsupported_artifacts", [])),
        "high_or_critical_risks": sum(
            1
            for item in aibom.get("risk_findings", [])
            if str(item.get("severity", "")).lower() in {"high", "critical"}
        ),
    }


def _load_repos(args_repos: list[str], repos_file: str | None) -> list[str]:
    repos = list(args_repos)
    if repos_file:
        file_path = validate_safe_path(Path(repos_file), must_exist=True, must_be_file=True)
        for line in file_path.read_text(encoding="utf-8").splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            repos.append(candidate)
    seen: set[str] = set()
    unique: list[str] = []
    for repo in repos:
        if repo not in seen:
            seen.add(repo)
            unique.append(repo)
    return unique


def scan_github_repos(
    repos: list[str],
    output_dir: Path,
    branch: str | None = None,
    depth: int = 1,
    token_env: str = "GITHUB_TOKEN",
    max_repos: int | None = None,
    timeout_sec: int = 180,
    include_prompts: bool = False,
    include_runtime_manifests: bool = False,
    redaction_policy: str = "strict",
    risk_policy_path: Path | None = None,
    profile: str = "canonical",
    fail_on: str | None = None,
    max_high_risk: int | None = None,
    max_unsupported: int | None = None,
    baseline_file: Path | None = None,
) -> tuple[list[RepoScanRecord], int]:
    output_dir = validate_safe_path(output_dir, must_exist=False)
    output_dir.mkdir(parents=True, exist_ok=True)

    token = os.getenv(token_env)
    selected_repos = repos[:max_repos] if max_repos is not None else repos
    records: list[RepoScanRecord] = []
    global_failures = 0

    baseline_doc = load_json(baseline_file) if baseline_file and baseline_file.exists() else None
    fail_on_set = set(filter(None, (fail_on or "").split(",")))

    for repo in selected_repos:
        repo_dir = output_dir / _repo_slug(repo)
        repo_dir.mkdir(parents=True, exist_ok=True)
        canonical_output = repo_dir / "AI_BOM.json"
        profile_output = repo_dir / "AI_BOM_ai_profile.json"

        try:
            with tempfile.TemporaryDirectory(prefix="aibom-gh-") as temp_dir:
                clone_dest = Path(temp_dir) / "repo"
                _clone_repo(
                    repo=repo,
                    dest=clone_dest,
                    branch=branch,
                    depth=depth,
                    token=token,
                    timeout_sec=timeout_sec,
                )
                aibom = generate_aibom(
                    clone_dest,
                    include_prompts=include_prompts,
                    include_runtime_manifests=include_runtime_manifests,
                    redaction_policy=redaction_policy,
                    risk_policy_path=risk_policy_path,
                )
                validate_aibom(aibom)
                canonical_output.write_text(stable_json(aibom), encoding="utf-8")

                profile_path_str: str | None = None
                if profile == "ai-bom-like":
                    ai_profile = build_ai_bom_like_profile(aibom)
                    profile_output.write_text(profile_json_dumps(ai_profile), encoding="utf-8")
                    profile_path_str = str(profile_output.relative_to(output_dir))

                failures: list[str] = []
                if baseline_doc is not None:
                    failures.extend(gate_failures(diff_aibom(baseline_doc, aibom), fail_on_set))
                if (
                    max_high_risk is not None
                    and _count_summary(aibom)["high_or_critical_risks"] > max_high_risk
                ):
                    failures.append("max-high-risk")
                if (
                    max_unsupported is not None
                    and _count_summary(aibom)["unsupported_artifacts"] > max_unsupported
                ):
                    failures.append("max-unsupported")

                gate_verdict = "pass" if not failures else "fail"
                if failures:
                    global_failures += 1

                records.append(
                    RepoScanRecord(
                        repo=repo,
                        status="ok",
                        output_json=str(canonical_output.relative_to(output_dir)),
                        output_profile_json=profile_path_str,
                        counts=_count_summary(aibom),
                        gate_verdict=gate_verdict,
                        gate_failures=sorted(set(failures)),
                    )
                )
        except Exception as exc:
            global_failures += 1
            if repo_dir.exists() and not any(repo_dir.iterdir()):
                shutil.rmtree(repo_dir)
            records.append(
                RepoScanRecord(
                    repo=repo,
                    status="error",
                    output_json="",
                    output_profile_json=None,
                    counts={
                        "models": 0,
                        "tools": 0,
                        "datasets": 0,
                        "frameworks": 0,
                        "prompts": 0,
                        "unsupported_artifacts": 0,
                        "high_or_critical_risks": 0,
                    },
                    gate_verdict="fail",
                    gate_failures=["scan-error"],
                    error=str(exc),
                )
            )

    summary = {
        "profile": profile,
        "total_repositories": len(selected_repos),
        "failed_repositories": global_failures,
        "records": [asdict(record) for record in records],
    }
    (output_dir / "summary.json").write_text(stable_json(summary), encoding="utf-8")
    (output_dir / "SUMMARY.md").write_text(
        render_markdown_summary(summary["records"]),
        encoding="utf-8",
    )

    exit_code = 2 if global_failures else 0
    return records, exit_code


__all__ = ["scan_github_repos", "_load_repos"]
