from __future__ import annotations

import json
from pathlib import Path

from aibom.presentation import (
    build_ai_bom_like_profile,
    render_markdown_summary,
    render_text_summary,
)


FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_ai_bom_like_profile_matches_snapshot() -> None:
    aibom_doc = _load_fixture("export_input_aibom.json")
    expected = _load_fixture("golden_ai_profile.json")

    assert build_ai_bom_like_profile(aibom_doc) == expected


def test_text_summary_contains_core_sections() -> None:
    aibom_doc = _load_fixture("export_input_aibom.json")
    summary = render_text_summary(aibom_doc)

    assert "AIBOM scan summary" in summary
    assert "Top risks" in summary
    assert "Coverage" in summary
    assert "Drift/gate verdict: pass" in summary


def test_markdown_summary_table_rendering() -> None:
    markdown = render_markdown_summary(
        [
            {
                "repo": "octo/demo",
                "status": "ok",
                "counts": {
                    "models": 2,
                    "tools": 1,
                    "high_or_critical_risks": 1,
                    "unsupported_artifacts": 0,
                },
                "gate_verdict": "pass",
            },
            {
                "repo": "octo/bad",
                "status": "error",
                "counts": {
                    "models": 0,
                    "tools": 0,
                    "high_or_critical_risks": 0,
                    "unsupported_artifacts": 0,
                },
                "gate_verdict": "fail",
            },
        ]
    )

    assert "| Repository | Status |" in markdown
    assert "octo/demo" in markdown
    assert "failed: 1" in markdown
