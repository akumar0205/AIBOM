from __future__ import annotations

import json
from pathlib import Path

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
