from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from aibom.analyzer import ScanContext

IGNORED_DIRS = {".venv", "venv", "__pycache__", ".git", ".aibom"}
PROVENANCE_UNKNOWN = "unknown"

FRAMEWORK_IMPORTS = {
    "github.com/openai/openai-go": "openai",
    "github.com/anthropics/anthropic-sdk-go": "anthropic",
    "github.com/tmc/langchaingo": "langchain",
}
MODEL_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bopenai\.NewClient\b"), "OpenAI", "https://api.openai.com"),
    (re.compile(r"\banthropic\.NewClient\b"), "Anthropic", "https://api.anthropic.com"),
]
TOOL_PATTERNS = [re.compile(r"\btools?\.[A-Za-z_]+"), re.compile(r"\bAgent\b")]
PROMPT_PATTERNS = [
    re.compile(r"\bPromptTemplate\b"),
    re.compile(r"\bSystemPrompt\b"),
    re.compile(r"\btemplate\.New\b"),
]


@dataclass
class GoScanResult:
    models: list[dict[str, Any]] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    scan_findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    runtime_context: dict[str, str] = field(default_factory=dict)


class GoAstDetector:
    source_type = "go_ast"

    def scan(self, context: ScanContext) -> GoScanResult:
        result = GoScanResult()
        candidates = _find_go_files(context.target_dir)
        scanned = 0

        for source_file in candidates:
            text = _safe_read_text(source_file)
            if not text:
                continue
            scanned += 1
            rel = source_file.relative_to(context.target_dir)
            for line_number, line in enumerate(text.splitlines(), start=1):
                import_match = re.search(r'"([^"]+)"', line)
                if import_match:
                    imported = import_match.group(1).lower()
                    framework = FRAMEWORK_IMPORTS.get(imported)
                    if framework:
                        result.frameworks.add(framework)

                for model_pattern, model_type, provider_endpoint in MODEL_PATTERNS:
                    if model_pattern.search(line):
                        source_ref = f"{rel}:{line_number}"
                        result.models.append(
                            {
                                "type": model_type,
                                "model": _extract_string_literal(line),
                                "source_file": source_ref,
                                "provenance": _provenance(provider_endpoint=provider_endpoint),
                            }
                        )
                        result.scan_findings.append(
                            _finding(
                                finding_id=f"go-model:{model_type}:{source_ref}",
                                category="model invocation",
                                source_type=self.source_type,
                                source_file=source_ref,
                                severity="medium",
                                confidence="medium",
                                evidence=f"Go model usage detected: {model_type}.",
                            )
                        )

                if any(pattern.search(line) for pattern in TOOL_PATTERNS):
                    source_ref = f"{rel}:{line_number}"
                    result.tools.append({"name": _extract_symbol(line), "source_file": source_ref})

                if any(pattern.search(line) for pattern in PROMPT_PATTERNS):
                    source_ref = f"{rel}:{line_number}"
                    prompt = {"id": source_ref, "source_file": source_ref}
                    if context.include_prompts:
                        prompt["template"] = _extract_string_literal(line, minimum=4)
                    result.prompts.append(prompt)

        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "medium",
        }
        return result


def _find_go_files(target: Path) -> list[Path]:
    return sorted(
        [
            p
            for p in target.rglob("*.go")
            if p.is_file() and not any(part in IGNORED_DIRS for part in p.parts)
        ],
        key=lambda p: str(p),
    )


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _extract_string_literal(line: str, minimum: int = 1) -> str:
    match = re.search(r'"([^"]+)"', line)
    if match and len(match.group(1)) >= minimum:
        return match.group(1)
    return "unknown" if minimum == 1 else "redacted"


def _extract_symbol(line: str) -> str:
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", line)
    return match.group(1) if match else "go_tool"


def _finding(
    finding_id: str,
    category: str,
    source_type: str,
    source_file: str,
    severity: str,
    confidence: str,
    evidence: str,
) -> dict[str, str]:
    return {
        "id": finding_id,
        "category": category,
        "source_type": source_type,
        "source_file": source_file,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
    }


def _provenance(
    provider_endpoint: str = PROVENANCE_UNKNOWN,
    registry_uri: str = PROVENANCE_UNKNOWN,
    immutable_version: str = PROVENANCE_UNKNOWN,
    environment: str = PROVENANCE_UNKNOWN,
    region: str = PROVENANCE_UNKNOWN,
) -> dict[str, str]:
    return {
        "provider_endpoint": provider_endpoint,
        "registry_uri": registry_uri,
        "immutable_version": immutable_version,
        "environment": environment,
        "region": region,
    }
