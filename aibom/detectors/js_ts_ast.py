from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aibom.confidence import score_confidence

PROVENANCE_UNKNOWN = "unknown"

JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
if TYPE_CHECKING:
    from aibom.analyzer import ScanContext

IGNORED_DIRS = {".venv", "venv", "__pycache__", ".git", ".aibom"}

FRAMEWORK_IMPORTS = {
    "openai": "openai",
    "@anthropic-ai/sdk": "anthropic",
    "langchain": "langchain",
    "@langchain/core": "langchain",
    "@langchain/openai": "langchain",
    "@langchain/anthropic": "langchain",
}

MODEL_CONSTRUCTORS = {
    "OpenAI": "https://api.openai.com",
    "Anthropic": "https://api.anthropic.com",
    "ChatOpenAI": "https://api.openai.com",
    "ChatAnthropic": "https://api.anthropic.com",
}
TOOL_HINTS = {"tool", "DynamicTool", "initializeAgentExecutorWithOptions", "loadTools"}
PROMPT_HINTS = {"PromptTemplate", "ChatPromptTemplate", "fromTemplate"}

_IMPORT_RE = re.compile(
    r"\bimport\s+(?:(?P<default>[A-Za-z_$][\w$]*)\s*(?:,\s*)?)?"
    r"(?:\{(?P<named>[^}]+)\})?\s*from\s*[\"'](?P<module>[^\"']+)[\"']"
)
_REQUIRE_RE = re.compile(
    r"(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*require\(\s*[\"'](?P<module>[^\"']+)[\"']\s*\)"
)
_DESTRUCT_REQUIRE_RE = re.compile(
    r"(?:const|let|var)\s+\{(?P<named>[^}]+)\}\s*=\s*require\(\s*[\"'](?P<module>[^\"']+)[\"']\s*\)"
)
_NEW_RE = re.compile(r"\bnew\s+([A-Za-z_$][\w$.]*)\s*\((.*?)\)", re.DOTALL)
_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$.]*)\s*\((.*?)\)", re.DOTALL)


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

    def scan(self, context: ScanContext) -> JSTSScanResult:
        result = JSTSScanResult()
        candidates = _find_js_ts_source_files(context.target_dir)
        scanned = 0

        for source_file in candidates:
            text = _safe_read_text(source_file)
            if not text:
                continue
            scanned += 1
            rel = source_file.relative_to(context.target_dir)
            parser = _JSTSParser(text)
            parsed = parser.parse()

            for module in parsed["framework_import_modules"]:
                maybe_framework = FRAMEWORK_IMPORTS.get(module.lower())
                if maybe_framework:
                    result.frameworks.add(maybe_framework)

            for constructor in parsed["constructors"]:
                leaf = constructor["resolved"].split(".")[-1]
                token_leaf = constructor["token"].split(".")[-1]
                model_type = ""
                if token_leaf in MODEL_CONSTRUCTORS:
                    model_type = token_leaf
                elif leaf in MODEL_CONSTRUCTORS:
                    model_type = leaf
                elif constructor["resolved"].startswith("openai."):
                    model_type = "OpenAI"
                elif "ChatOpenAI" in constructor["resolved"]:
                    model_type = "ChatOpenAI"
                elif "ChatAnthropic" in constructor["resolved"]:
                    model_type = "ChatAnthropic"
                elif constructor["resolved"].startswith("@anthropic-ai/sdk"):
                    model_type = "Anthropic"
                if not model_type:
                    continue
                source_ref = f"{rel}:{constructor['line']}"
                signals = {"constructor"}
                if constructor["imported"]:
                    signals.add("import")
                if _contains_config_key(constructor["args"]):
                    signals.add("config_key")
                result.models.append(
                    {
                        "type": model_type,
                        "model": _extract_model_name(constructor["args"]),
                        "source_file": source_ref,
                        "provenance": _provenance(provider_endpoint=MODEL_CONSTRUCTORS[model_type]),
                    }
                )
                result.scan_findings.append(
                    _finding(
                        finding_id=f"js-ts-model:{model_type}:{source_ref}",
                        category="model invocation",
                        source_type=self.source_type,
                        source_file=source_ref,
                        severity="medium",
                        confidence=score_confidence(signals),
                        evidence=(
                            f"JS/TS AST constructor detected: {constructor['resolved']}"
                            f" (imported={constructor['imported']})."
                        ),
                    )
                )

            for call in parsed["calls"]:
                leaf = call["resolved"].split(".")[-1]
                source_ref = f"{rel}:{call['line']}"
                if leaf in TOOL_HINTS:
                    result.tools.append({"name": leaf, "source_file": source_ref})
                    result.scan_findings.append(
                        _finding(
                            finding_id=f"js-ts-tool:{leaf}:{source_ref}",
                            category="tool invocation",
                            source_type=self.source_type,
                            source_file=source_ref,
                            severity="low",
                            confidence=score_confidence(
                                {"constructor", "import" if call["imported"] else ""} - {""}
                            ),
                            evidence=(
                                "JS/TS AST call detected: "
                                f"{call['resolved']} (context={call['context']})."
                            ),
                        )
                    )

                if leaf in PROMPT_HINTS:
                    prompt_entry = {"id": source_ref, "source_file": source_ref}
                    if context.include_prompts:
                        prompt_entry["template"] = _extract_prompt_template(call["args"])
                    result.prompts.append(prompt_entry)
                    result.scan_findings.append(
                        _finding(
                            finding_id=f"js-ts-prompt:{source_ref}",
                            category="prompt template",
                            source_type=self.source_type,
                            source_file=source_ref,
                            severity="medium",
                            confidence=score_confidence(
                                {"constructor", "import" if call["imported"] else ""} - {""}
                            ),
                            evidence=(
                                "JS/TS AST prompt call detected: "
                                f"{call['resolved']} (context={call['context']})."
                            ),
                        )
                    )

        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "medium",
        }
        return result


class _JSTSParser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.import_aliases: dict[str, str] = {}
        self.bindings: dict[str, str] = {}
        self.framework_import_modules: set[str] = set()

    def parse(self) -> dict[str, list[dict[str, Any]] | set[str]]:
        constructors: list[dict[str, Any]] = []
        calls: list[dict[str, Any]] = []

        for match in _IMPORT_RE.finditer(self.text):
            module = match.group("module")
            self.framework_import_modules.add(module)
            if match.group("default"):
                self.import_aliases[match.group("default")] = f"{module}.default"
            named = match.group("named") or ""
            for raw in named.split(","):
                alias = raw.strip()
                if not alias:
                    continue
                if " as " in alias:
                    source, target = [part.strip() for part in alias.split(" as ", 1)]
                else:
                    source = target = alias
                self.import_aliases[target] = f"{module}.{source}"

        for match in _REQUIRE_RE.finditer(self.text):
            self.import_aliases[match.group("name")] = f"{match.group('module')}.default"
            self.framework_import_modules.add(match.group("module"))

        for match in _DESTRUCT_REQUIRE_RE.finditer(self.text):
            module = match.group("module")
            self.framework_import_modules.add(module)
            for raw in match.group("named").split(","):
                alias = raw.strip()
                if not alias:
                    continue
                if ":" in alias:
                    source, target = [part.strip() for part in alias.split(":", 1)]
                else:
                    source = target = alias
                self.import_aliases[target] = f"{module}.{source}"

        assign_re = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$.]*)")
        for match in assign_re.finditer(self.text):
            self.bindings[match.group(1)] = self._resolve_symbol(match.group(2))

        for match in _NEW_RE.finditer(self.text):
            start = match.start()
            token = match.group(1)
            resolved = self._resolve_symbol(token)
            constructors.append(
                {
                    "token": token,
                    "resolved": resolved,
                    "line": self._line_at(start),
                    "args": match.group(2),
                    "imported": self._is_imported(resolved),
                }
            )

        for match in _CALL_RE.finditer(self.text):
            start = match.start()
            token = match.group(1)
            resolved = self._resolve_symbol(token)
            calls.append(
                {
                    "resolved": resolved,
                    "line": self._line_at(start),
                    "args": match.group(2),
                    "imported": self._is_imported(resolved),
                    "context": "method" if "." in token else "function",
                }
            )

        return {
            "constructors": constructors,
            "calls": calls,
            "framework_import_modules": self.framework_import_modules,
        }

    def _resolve_symbol(self, symbol: str) -> str:
        parts = symbol.split(".")
        root = parts[0]
        if root in self.bindings:
            return ".".join(self.bindings[root].split(".") + parts[1:])
        if root in self.import_aliases:
            return ".".join(self.import_aliases[root].split(".") + parts[1:])
        return symbol

    def _is_imported(self, symbol: str) -> bool:
        root = symbol.split(".")[0]
        return root in FRAMEWORK_IMPORTS or root.startswith("@")

    def _line_at(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1


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


def _extract_model_name(args_text: str) -> str:
    match = re.search(r"\bmodel\s*:\s*[\"']([^\"']+)[\"']", args_text)
    return match.group(1) if match else "unknown"


def _extract_prompt_template(args_text: str) -> str:
    match = re.search(r"[\"']([^\"']{4,})[\"']", args_text)
    return match.group(1) if match else "redacted"


def _contains_config_key(args_text: str) -> bool:
    return bool(re.search(r"\b(model|modelName|apiKey|provider|deployment)\b\s*:", args_text))


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
