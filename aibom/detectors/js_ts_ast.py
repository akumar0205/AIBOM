from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROVENANCE_UNKNOWN = "unknown"

JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
IGNORED_DIRS = {".venv", "venv", "__pycache__", ".git", ".aibom"}

FRAMEWORK_IMPORTS = {
    "openai": "openai",
    "@anthropic-ai/sdk": "anthropic",
    "langchain": "langchain",
    "@langchain/core": "langchain",
    "@langchain/openai": "langchain",
    "@langchain/anthropic": "langchain",
}

MODEL_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bnew\s+OpenAI\s*\("), "OpenAI", "https://api.openai.com"),
    (re.compile(r"\bnew\s+Anthropic\s*\("), "Anthropic", "https://api.anthropic.com"),
    (re.compile(r"\bnew\s+ChatOpenAI\s*\("), "ChatOpenAI", "https://api.openai.com"),
    (
        re.compile(r"\bnew\s+ChatAnthropic\s*\("),
        "ChatAnthropic",
        "https://api.anthropic.com",
    ),
]

TOOL_PATTERNS = [
    re.compile(r"\btool\s*\("),
    re.compile(r"\bDynamicTool\b"),
    re.compile(r"\binitializeAgentExecutorWithOptions\s*\("),
    re.compile(r"\bloadTools\s*\("),
]

PROMPT_PATTERNS = [
    re.compile(r"\bPromptTemplate\b"),
    re.compile(r"\bChatPromptTemplate\b"),
    re.compile(r"\.fromTemplate\s*\("),
]


@dataclass
class JSTSScanResult:
    models: list[dict[str, Any]] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    scan_findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    runtime_context: dict[str, str] = field(default_factory=dict)


class JSTSAstDetector:
    source_type = "js_ts_ast"

    def scan(self, context: Any) -> JSTSScanResult:
        result = JSTSScanResult()
        candidates = _find_js_ts_source_files(context.target_dir)
        scanned = 0

        for source_file in candidates:
            text = _safe_read_text(source_file)
            if not text:
                continue
            scanned += 1
            rel = source_file.relative_to(context.target_dir)
            for line_number, line in enumerate(text.splitlines(), start=1):
                import_match = re.search(r"\b(?:from|require\()\s*[\"']([^\"']+)[\"']", line)
                if import_match:
                    maybe_framework = FRAMEWORK_IMPORTS.get(import_match.group(1).lower())
                    if maybe_framework:
                        result.frameworks.add(maybe_framework)

                for model_pattern, model_type, provider_endpoint in MODEL_PATTERNS:
                    if not model_pattern.search(line):
                        continue
                    model_name = _extract_model_name(line)
                    source_ref = f"{rel}:{line_number}"
                    result.models.append(
                        {
                            "type": model_type,
                            "model": model_name,
                            "source_file": source_ref,
                            "provenance": _provenance(provider_endpoint=provider_endpoint),
                        }
                    )
                    result.scan_findings.append(
                        _finding(
                            finding_id=f"js-ts-model:{model_type}:{source_ref}",
                            category="model invocation",
                            source_type=self.source_type,
                            source_file=source_ref,
                            severity="medium",
                            confidence="medium",
                            evidence=f"JS/TS model usage detected: {model_type}.",
                        )
                    )

                if any(pattern.search(line) for pattern in TOOL_PATTERNS):
                    tool_name = _extract_tool_name(line)
                    source_ref = f"{rel}:{line_number}"
                    result.tools.append({"name": tool_name, "source_file": source_ref})
                    result.scan_findings.append(
                        _finding(
                            finding_id=f"js-ts-tool:{tool_name}:{source_ref}",
                            category="tool invocation",
                            source_type=self.source_type,
                            source_file=source_ref,
                            severity="low",
                            confidence="medium",
                            evidence=f"JS/TS tool usage detected: {tool_name}.",
                        )
                    )

                if any(pattern.search(line) for pattern in PROMPT_PATTERNS):
                    source_ref = f"{rel}:{line_number}"
                    prompt_entry = {"id": source_ref, "source_file": source_ref}
                    if context.include_prompts:
                        prompt_entry["template"] = _extract_prompt_template(line)
                    result.prompts.append(prompt_entry)
                    result.scan_findings.append(
                        _finding(
                            finding_id=f"js-ts-prompt:{source_ref}",
                            category="prompt template",
                            source_type=self.source_type,
                            source_file=source_ref,
                            severity="medium",
                            confidence="medium",
                            evidence="JS/TS prompt template usage detected.",
                        )
                    )

        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "medium",
        }
        return result


def _find_js_ts_source_files(target: Path) -> list[Path]:
    return sorted(
        [
            path
            for path in target.rglob("*")
            if path.is_file()
            and path.suffix.lower() in JS_TS_EXTENSIONS
            and not any(part in IGNORED_DIRS for part in path.parts)
        ],
        key=lambda p: str(p),
    )


def _extract_model_name(line: str) -> str:
    match = re.search(r"\bmodel\s*:\s*[\"']([^\"']+)[\"']", line)
    return match.group(1) if match else "unknown"


def _extract_tool_name(line: str) -> str:
    call_match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
    if call_match:
        return call_match.group(1)
    token_match = re.search(r"\bDynamicTool\b", line)
    if token_match:
        return token_match.group(0)
    return "unknown_tool"


def _extract_prompt_template(line: str) -> str:
    match = re.search(r"[\"']([^\"']{4,})[\"']", line)
    return match.group(1) if match else "redacted"


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


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
