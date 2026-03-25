from __future__ import annotations

import json
from typing import Any


DEFAULT_TOP_RISKS = 3


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(str(severity).lower(), 4)


def build_ai_bom_like_profile(aibom: dict[str, Any]) -> dict[str, Any]:
    """Build a companion presentation profile without changing canonical schema output."""
    risk_findings = list(aibom.get("risk_findings", []))
    sorted_risks = sorted(
        risk_findings,
        key=lambda item: (
            _severity_rank(str(item.get("severity", ""))),
            -float(item.get("score", 0.0) or 0.0),
            str(item.get("title", item.get("id", ""))),
        ),
    )

    coverage = aibom.get("coverage_summary", {})
    detectors = list(coverage.get("detectors", []))
    detectors_sorted = sorted(detectors, key=lambda item: item.get("source_type", ""))

    return {
        "profile": "ai-bom-like",
        "schema_version": aibom.get("schema_version", "1.0"),
        "metadata": {
            "generated_at": aibom.get("metadata", {}).get("generated_at", ""),
            "git_sha": aibom.get("metadata", {}).get("git_sha", "unknown"),
            "artifact_sha256": aibom.get("metadata", {}).get("artifact_sha256", ""),
        },
        "executive_summary": {
            "models": len(aibom.get("models", [])),
            "tools": len(aibom.get("tools", [])),
            "datasets": len(aibom.get("datasets", [])),
            "frameworks": len(aibom.get("frameworks", [])),
            "prompts": len(aibom.get("prompts", [])),
            "risk_findings": len(risk_findings),
            "high_or_critical_risks": sum(
                1
                for item in risk_findings
                if str(item.get("severity", "")).lower() in {"high", "critical"}
            ),
            "unsupported_artifacts": len(aibom.get("unsupported_artifacts", [])),
        },
        "ai_assets": {
            "models": sorted(
                [
                    {
                        "type": item.get("type", "unknown"),
                        "model": item.get("model", "unknown"),
                        "source_file": item.get("source_file", "unknown"),
                        "provider": item.get("provenance", {}).get("provider_endpoint", "unknown"),
                    }
                    for item in aibom.get("models", [])
                ],
                key=lambda item: (item["type"], item["model"], item["source_file"]),
            ),
            "tools": sorted(
                [
                    {
                        "name": item.get("name", "unknown"),
                        "source_file": item.get("source_file", "unknown"),
                    }
                    for item in aibom.get("tools", [])
                ],
                key=lambda item: (item["name"], item["source_file"]),
            ),
            "datasets": sorted(
                [
                    {
                        "type": item.get("type", "unknown"),
                        "source_file": item.get("source_file", "unknown"),
                    }
                    for item in aibom.get("datasets", [])
                ],
                key=lambda item: (item["type"], item["source_file"]),
            ),
            "frameworks": sorted(item.get("name", "") for item in aibom.get("frameworks", [])),
        },
        "risk_highlights": [
            {
                "id": item.get("id", ""),
                "title": item.get("title", ""),
                "severity": item.get("severity", ""),
                "score": item.get("score", 0.0),
                "rule_id": item.get("rule_id", ""),
            }
            for item in sorted_risks[:DEFAULT_TOP_RISKS]
        ],
        "provenance_and_compliance": {
            "runtime_context": aibom.get("runtime_context", {}),
            "risk_policy": aibom.get("risk_policy", {}),
            "source_types": aibom.get("source_types", []),
        },
        "detector_coverage": {
            "unsupported_total": int(coverage.get("unsupported_total", 0) or 0),
            "detectors": [
                {
                    "source_type": item.get("source_type", "unknown"),
                    "files_scanned": int(item.get("files_scanned", 0) or 0),
                    "findings": int(item.get("findings", 0) or 0),
                }
                for item in detectors_sorted
            ],
        },
    }


def render_text_summary(
    aibom: dict[str, Any],
    drift_failures: list[str] | None = None,
    max_risks: int = DEFAULT_TOP_RISKS,
) -> str:
    risk_findings = list(aibom.get("risk_findings", []))
    high_or_critical = [
        item
        for item in risk_findings
        if str(item.get("severity", "")).lower() in {"high", "critical"}
    ]
    top_risks = sorted(
        risk_findings,
        key=lambda item: (
            _severity_rank(str(item.get("severity", ""))),
            -float(item.get("score", 0.0) or 0.0),
        ),
    )[:max_risks]

    coverage = aibom.get("coverage_summary", {})
    detectors = sorted(
        list(coverage.get("detectors", [])),
        key=lambda item: item.get("source_type", ""),
    )

    lines = [
        "AIBOM scan summary",
        "-" * 60,
        "Counts",
        "  category     count",
        f"  models       {len(aibom.get('models', []))}",
        f"  tools        {len(aibom.get('tools', []))}",
        f"  datasets     {len(aibom.get('datasets', []))}",
        f"  frameworks   {len(aibom.get('frameworks', []))}",
        f"  prompts      {len(aibom.get('prompts', []))}",
        f"  unsupported  {len(aibom.get('unsupported_artifacts', []))}",
        f"  risks(high+) {len(high_or_critical)}",
        "",
        "Top risks",
    ]

    if not top_risks:
        lines.append("  - none")
    else:
        for item in top_risks:
            lines.append(
                f"  - [{item.get('severity', 'unknown')}] {item.get('title', item.get('id', 'finding'))}"
            )

    lines.extend(["", "Coverage"])
    if not detectors:
        lines.append("  - no detector coverage metadata")
    else:
        for item in detectors:
            lines.append(
                f"  - {item.get('source_type', 'unknown')}: files={item.get('files_scanned', 0)} findings={item.get('findings', 0)}"
            )

    verdict = "pass"
    if drift_failures:
        verdict = f"fail ({', '.join(sorted(set(drift_failures)))})"
    lines.extend(["", f"Drift/gate verdict: {verdict}"])
    return "\n".join(lines)


def render_markdown_summary(records: list[dict[str, Any]]) -> str:
    lines = [
        "# AIBOM GitHub Scan Summary",
        "",
        "| Repository | Status | Models | Tools | High+ Risks | Unsupported | Gate Verdict |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for record in records:
        lines.append(
            "| {repo} | {status} | {models} | {tools} | {risks} | {unsupported} | {verdict} |".format(
                repo=record.get("repo", "unknown"),
                status=record.get("status", "error"),
                models=record.get("counts", {}).get("models", 0),
                tools=record.get("counts", {}).get("tools", 0),
                risks=record.get("counts", {}).get("high_or_critical_risks", 0),
                unsupported=record.get("counts", {}).get("unsupported_artifacts", 0),
                verdict=record.get("gate_verdict", "fail"),
            )
        )

    failed = [item["repo"] for item in records if item.get("status") != "ok"]
    lines.extend(["", "## Aggregate"])
    lines.append(f"- scanned: {len(records)}")
    lines.append(f"- failed: {len(failed)}")
    if failed:
        lines.append(f"- failed_repositories: {', '.join(sorted(failed))}")
    return "\n".join(lines) + "\n"


def profile_json_dumps(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)
