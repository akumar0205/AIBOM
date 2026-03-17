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
    "dev.langchain4j": "langchain",
    "org.springframework.ai": "langchain",
    "com.openai": "openai",
    "com.anthropic": "anthropic",
}

MODEL_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bOpenAi(Chat)?Model\b"), "OpenAI", "https://api.openai.com"),
    (re.compile(r"\bAnthropic(Chat)?Model\b"), "Anthropic", "https://api.anthropic.com"),
]
TOOL_PATTERNS = [
    re.compile(r"\bToolSpecification\b"),
    re.compile(r"\bAgent\b"),
    re.compile(r"\btool\s*\("),
]
PROMPT_PATTERNS = [
    re.compile(r"\bPromptTemplate\b"),
    re.compile(r"\bPrompt\.from\s*\("),
    re.compile(r"\bSystemMessage\b"),
]


@dataclass
class JavaScanResult:
    models: list[dict[str, Any]] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    scan_findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    runtime_context: dict[str, str] = field(default_factory=dict)


class JavaAstDetector:
    source_type = "java_ast"

    def scan(self, context: ScanContext) -> JavaScanResult:
        result = JavaScanResult()
        candidates = _find_java_files(context.target_dir)
        scanned = 0

        for source_file in candidates:
            text = _safe_read_text(source_file)
            if not text:
                continue
            scanned += 1
            rel = source_file.relative_to(context.target_dir)
            for line_number, line in enumerate(text.splitlines(), start=1):
                import_match = re.match(r"^\s*import\s+([^;]+);", line)
                if import_match:
                    imported = import_match.group(1).lower()
                    for import_key, framework_name in FRAMEWORK_IMPORTS.items():
                        if import_key in imported:
                            result.frameworks.add(framework_name)

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
                                finding_id=f"java-model:{model_type}:{source_ref}",
                                category="model invocation",
                                source_type=self.source_type,
                                source_file=source_ref,
                                severity="medium",
                                confidence="medium",
                                evidence=f"Java model usage detected: {model_type}.",
                            )
                        )

                if any(pattern.search(line) for pattern in TOOL_PATTERNS):
                    source_ref = f"{rel}:{line_number}"
                    tool_name = _extract_call_name(line, default="java_tool")
                    result.tools.append({"name": tool_name, "source_file": source_ref})

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


def _find_java_files(target: Path) -> list[Path]:
    return sorted(
        [
            p
            for p in target.rglob("*.java")
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


def _extract_call_name(line: str, default: str) -> str:
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
    return match.group(1) if match else default


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
