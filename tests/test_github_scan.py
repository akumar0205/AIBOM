from __future__ import annotations

import json
from pathlib import Path

import pytest

from aibom.github_scan import _load_repos, scan_github_repos


FIXTURE = Path(__file__).parent / "fixtures" / "sample_project"


def test_load_repos_dedupes_and_reads_file(tmp_path: Path) -> None:
    repos_file = tmp_path / "repos.txt"
    repos_file.write_text("owner/a\n# comment\nowner/b\nowner/a\n", encoding="utf-8")

    repos = _load_repos(["owner/c", "owner/b"], str(repos_file))

    assert repos == ["owner/c", "owner/b", "owner/a"]


def test_scan_github_repos_generates_summary_with_partial_failures(
    tmp_path: Path, monkeypatch
) -> None:
    from aibom import github_scan as mod

    def fake_clone(repo: str, dest: Path, **_kwargs: object) -> None:
        if repo == "bad/repo":
            raise RuntimeError("clone failed")
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "app.py").write_text(
            FIXTURE.joinpath("app.py").read_text(encoding="utf-8"), encoding="utf-8"
        )

    monkeypatch.setattr(mod, "_clone_repo", fake_clone)

    records, exit_code = scan_github_repos(
        repos=["good/repo", "bad/repo"],
        output_dir=tmp_path / "out",
        profile="ai-bom-like",
        max_high_risk=0,
    )

    assert exit_code == 2
    assert len(records) == 2
    assert any(record.status == "ok" for record in records)
    assert any(record.status == "error" for record in records)

    summary_json = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    assert summary_json["total_repositories"] == 2
    assert (tmp_path / "out" / "SUMMARY.md").exists()
    assert (tmp_path / "out" / "good__repo" / "AI_BOM.json").exists()
    assert (tmp_path / "out" / "good__repo" / "AI_BOM_ai_profile.json").exists()


def test_scan_records_origin_commit_and_branch(tmp_path: Path, monkeypatch) -> None:
    from aibom import github_scan as mod

    def fake_clone(repo: str, dest: Path, **_kwargs: object) -> str:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "app.py").write_text(
            FIXTURE.joinpath("app.py").read_text(encoding="utf-8"), encoding="utf-8"
        )
        return "abc123"

    monkeypatch.setattr(mod, "_clone_repo", fake_clone)

    records, exit_code = scan_github_repos(
        repos=["good/repo"],
        output_dir=tmp_path / "out",
        branch="main",
    )
    assert exit_code == 0
    assert records[0].status == "ok"
    assert records[0].repo_origin == "https://github.com/good/repo.git"
    assert records[0].resolved_commit == "abc123"
    assert records[0].branch == "main"
    assert records[0].scanned_at.endswith("Z")

    summary_json = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    record_json = summary_json["records"][0]
    assert record_json["repo_origin"] == "https://github.com/good/repo.git"
    assert record_json["resolved_commit"] == "abc123"


def test_scan_prefers_local_mirrors_and_is_deterministic(tmp_path: Path) -> None:
    mirrors = tmp_path / "mirrors"
    mirror_repo = mirrors / "good__repo"
    mirror_repo.mkdir(parents=True)
    (mirror_repo / "app.py").write_text(
        FIXTURE.joinpath("app.py").read_text(encoding="utf-8"), encoding="utf-8"
    )

    first, _ = scan_github_repos(
        repos=["good/repo"],
        output_dir=tmp_path / "out1",
        local_mirrors_dir=mirrors,
    )
    second, _ = scan_github_repos(
        repos=["good/repo"],
        output_dir=tmp_path / "out2",
        local_mirrors_dir=mirrors,
    )
    assert first[0].status == "ok" and second[0].status == "ok"
    first_doc = json.loads((tmp_path / "out1" / "good__repo" / "AI_BOM.json").read_text())
    second_doc = json.loads((tmp_path / "out2" / "good__repo" / "AI_BOM.json").read_text())
    for key in ("generated_at", "artifact_sha256"):
        first_doc["metadata"][key] = "DYNAMIC"
        second_doc["metadata"][key] = "DYNAMIC"
    assert first_doc == second_doc


def test_clone_requires_token_opt_in_and_valid_commit(tmp_path: Path, monkeypatch) -> None:
    from aibom.github_scan import _clone_repo

    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    with pytest.raises(ValueError, match="opt-in"):
        _clone_repo(
            repo="owner/repo",
            dest=tmp_path / "dest",
            branch=None,
            depth=1,
            token="secret-token",
            timeout_sec=10,
        )
    with pytest.raises(ValueError, match="[Cc]ommit"):
        _clone_repo(
            repo="owner/repo",
            dest=tmp_path / "dest",
            branch=None,
            depth=1,
            token=None,
            timeout_sec=10,
            commit="not-a-sha!!",
        )
