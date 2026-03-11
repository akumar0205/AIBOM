from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aibom.risk.heuristics import generate_risk_findings
from aibom.utils import git_sha, sha256_bytes, stable_json, utc_now

FRAMEWORK_ALIASES: dict[str, set[str]] = {
    "langchain": {"langchain", "langchain_openai", "langchain_community", "langchain_core"},
    "transformers": {"transformers"},
    "torch": {"torch", "pytorch"},
    "openai": {"openai"},
    "anthropic": {"anthropic"},
}
MODEL_CLASS_HINTS = {"OpenAI", "ChatOpenAI", "HuggingFaceHub", "Ollama", "ChatAnthropic"}
TOOL_HINTS = {"initialize_agent", "load_tools", "Tool", "AgentExecutor"}
VECTORSTORE_HINTS = {"FAISS", "Chroma", "Pinecone"}
PROMPT_HINTS = {"PromptTemplate", "ChatPromptTemplate"}
CONFIG_GLOBS = ("*.yaml", "*.yml", "*.json", ".env")
CONFIG_KEY_HINTS = {
    "model": "model configuration",
    "model_name": "model configuration",
    "provider": "provider configuration",
    "openai_api_key": "provider credential",
    "anthropic_api_key": "provider credential",
    "huggingfacehub_api_token": "provider credential",
    "azure_openai_api_key": "provider credential",
}
REDUCTION_POLICIES = {"strict", "default", "off"}
SENSITIVE_CONFIG_KEYS = {
    "openai_api_key",
    "anthropic_api_key",
    "huggingfacehub_api_token",
    "azure_openai_api_key",
}
RUNTIME_MANIFEST_FILES = {
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}


@dataclass
class ScanResult:
    models: list[dict[str, Any]] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    scan_findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanContext:
    target_dir: Path
    include_prompts: bool
    include_runtime_manifests: bool
    redaction_policy: str = "strict"


class Detector(Protocol):
    source_type: str

    def scan(self, context: ScanContext) -> ScanResult:
        ...


class AIBOMVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, include_prompts: bool = False) -> None:
        self.file_path = file_path
        self.include_prompts = include_prompts
        self.models: list[dict[str, Any]] = []
        self.datasets: list[dict[str, Any]] = []
        self.tools: list[dict[str, Any]] = []
        self.prompts: list[dict[str, Any]] = []
        self.imported_frameworks: set[str] = set()

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self._track_framework(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if not node.module:
            return
        self._track_framework(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        name = self._name_of(node.func)
        leaf = name.split(".")[-1]
        if leaf in MODEL_CLASS_HINTS:
            self.models.append({"type": leaf, "model": self._arg_or_kw(node, "model", "model_name"), "source_file": str(self.file_path)})
        if leaf in TOOL_HINTS or "agent" in leaf.lower():
            self.tools.append({"name": leaf, "source_file": str(self.file_path)})
        if any(part in VECTORSTORE_HINTS for part in name.split(".")):
            self.datasets.append({"type": name, "source_file": str(self.file_path)})
        if leaf in PROMPT_HINTS:
            prompt_id = f"{self.file_path}:{getattr(node, 'lineno', 0)}"
            entry = {"id": prompt_id, "source_file": str(self.file_path)}
            if self.include_prompts:
                entry["template"] = self._arg_or_kw(node, "template", default="redacted")
            self.prompts.append(entry)
        self.generic_visit(node)

    def _name_of(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._name_of(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _arg_or_kw(self, node: ast.Call, *keys: str, default: str = "unknown") -> str:
        for kw in node.keywords:
            if kw.arg in keys and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value
        return default

    def _track_framework(self, root: str) -> None:
        for fw, aliases in FRAMEWORK_ALIASES.items():
            if root in aliases:
                self.imported_frameworks.add(fw)


class PythonAstDetector:
    source_type = "python"

    def scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        for py_file in find_python_files(context.target_dir):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            rel = py_file.relative_to(context.target_dir)
            visitor = AIBOMVisitor(rel, include_prompts=context.include_prompts)
            visitor.visit(tree)
            result.models.extend(visitor.models)
            result.datasets.extend(visitor.datasets)
            result.tools.extend(visitor.tools)
            result.prompts.extend(visitor.prompts)
            result.frameworks.update(visitor.imported_frameworks)

            for model in visitor.models:
                result.scan_findings.append(
                    _finding(
                        finding_id=f"python-model:{model['type']}:{model['source_file']}",
                        category="model invocation",
                        source_type=self.source_type,
                        source_file=model["source_file"],
                        severity="medium",
                        confidence="high",
                        evidence=f"Model class {model['type']} detected in Python source.",
                    )
                )
        return result


class ConfigFileDetector:
    source_type = "config"

    def scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        candidates = _config_candidates(context.target_dir)
        for file_path in candidates:
            rel = file_path.relative_to(context.target_dir)
            text = _safe_read_text(file_path)
            if not text:
                continue

            kv_pairs = _extract_key_values(file_path, text)
            for key, value in kv_pairs:
                normalized = key.lower()
                if normalized not in CONFIG_KEY_HINTS:
                    continue

                descriptor = CONFIG_KEY_HINTS[normalized]
                severity = "high" if "credential" in descriptor else "medium"
                confidence = "high" if normalized in {"model", "model_name", "provider"} else "medium"
                result.scan_findings.append(
                    _finding(
                        finding_id=f"config:{normalized}:{rel}",
                        category=descriptor,
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity=severity,
                        confidence=confidence,
                        evidence=_config_evidence(key, value, normalized, context.redaction_policy),
                    )
                )

                if normalized in {"model", "model_name"} and value:
                    result.models.append(
                        {
                            "type": "ConfigModelHint",
                            "model": value,
                            "source_file": str(rel),
                            "source_type": self.source_type,
                            "confidence": "medium",
                        }
                    )
                if normalized == "provider" and value:
                    result.frameworks.add(value.lower())
        return result


class RuntimeManifestDetector:
    source_type = "runtime_manifest"

    def scan(self, context: ScanContext) -> ScanResult:
        if not context.include_runtime_manifests:
            return ScanResult()

        result = ScanResult()
        for file_path in _runtime_manifest_candidates(context.target_dir):
            rel = file_path.relative_to(context.target_dir)
            text = _safe_read_text(file_path)
            if not text:
                continue

            deps = _extract_dependencies(file_path.name, text)
            if deps:
                result.scan_findings.append(
                    _finding(
                        finding_id=f"runtime-deps:{rel}",
                        category="dependency graph",
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity="medium",
                        confidence="medium",
                        evidence=f"Detected dependencies: {', '.join(sorted(deps)[:10])}",
                    )
                )
                for dep in deps:
                    for fw, aliases in FRAMEWORK_ALIASES.items():
                        if dep.lower() in aliases:
                            result.frameworks.add(fw)

            if file_path.name.lower().startswith("docker") or "compose" in file_path.name.lower():
                result.scan_findings.append(
                    _finding(
                        finding_id=f"runtime-container:{rel}",
                        category="container metadata",
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity="low",
                        confidence="high",
                        evidence="Container runtime metadata discovered.",
                    )
                )
        return result


def _dedupe(items: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        marker = tuple(str(item.get(k, "")) for k in keys)
        if marker not in seen:
            seen.add(marker)
            out.append(item)
    return sorted(out, key=lambda x: stable_json(x))


def find_python_files(target: Path) -> list[Path]:
    ignored = {".venv", "venv", "__pycache__", ".git"}
    return sorted(
        [p for p in target.rglob("*.py") if not any(part in ignored for part in p.parts)],
        key=lambda p: str(p),
    )


def generate_aibom(
    target_dir: Path,
    include_prompts: bool = False,
    include_runtime_manifests: bool = False,
    redaction_policy: str = "strict",
) -> dict[str, Any]:
    normalized_policy = redaction_policy.lower()
    if normalized_policy not in REDUCTION_POLICIES:
        msg = f"Unsupported redaction policy: {redaction_policy}"
        raise ValueError(msg)

    context = ScanContext(
        target_dir=target_dir,
        include_prompts=include_prompts,
        include_runtime_manifests=include_runtime_manifests,
        redaction_policy=normalized_policy,
    )
    detectors: list[Detector] = [PythonAstDetector(), ConfigFileDetector(), RuntimeManifestDetector()]

    models: list[dict[str, Any]] = []
    datasets: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    frameworks: set[str] = set()
    scan_findings: list[dict[str, Any]] = []

    for detector in detectors:
        partial = detector.scan(context)
        models.extend(partial.models)
        datasets.extend(partial.datasets)
        tools.extend(partial.tools)
        prompts.extend(partial.prompts)
        frameworks.update(partial.frameworks)
        scan_findings.extend(partial.scan_findings)

    doc: dict[str, Any] = {
        "schema_version": "1.0",
        "metadata": {
            "generated_at": utc_now(),
            "git_sha": git_sha(target_dir),
        },
        "models": _dedupe(models, ["type", "model", "source_file"]),
        "datasets": _dedupe(datasets, ["type", "source_file"]),
        "tools": _dedupe(tools, ["name", "source_file"]),
        "frameworks": [{"name": f} for f in sorted(frameworks)],
        "prompts": _dedupe(prompts, ["id"]),
        "scan_findings": _dedupe(scan_findings, ["id"]),
        "source_types": [
            {"name": "python", "default_severity": "medium", "default_confidence": "high"},
            {"name": "config", "default_severity": "medium", "default_confidence": "medium"},
            {
                "name": "runtime_manifest",
                "default_severity": "medium",
                "default_confidence": "medium",
            },
        ],
    }
    doc["risk_findings"] = generate_risk_findings(doc)
    artifact_hash = sha256_bytes(stable_json(doc).encode("utf-8"))
    doc["metadata"]["artifact_sha256"] = artifact_hash
    return doc


def _config_candidates(target: Path) -> list[Path]:
    ignored = {".venv", "venv", "__pycache__", ".git"}
    out: set[Path] = set()
    for pattern in CONFIG_GLOBS:
        out.update(p for p in target.rglob(pattern) if not any(part in ignored for part in p.parts))
    return sorted(out)


def _runtime_manifest_candidates(target: Path) -> list[Path]:
    ignored = {".venv", "venv", "__pycache__", ".git"}
    out: list[Path] = []
    for p in target.rglob("*"):
        if not p.is_file() or any(part in ignored for part in p.parts):
            continue
        if p.name in RUNTIME_MANIFEST_FILES:
            out.append(p)
    return sorted(out)


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _extract_key_values(path: Path, text: str) -> list[tuple[str, str]]:
    suffix = path.suffix.lower()
    if path.name == ".env":
        pairs: list[tuple[str, str]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            pairs.append((k.strip(), v.strip().strip('"').strip("'")))
        return pairs

    if suffix == ".json":
        try:
            data = json.loads(text)
        except Exception:
            return []
        return [(k, str(v)) for k, v in _flatten_dict(data)]

    # yaml/yml naive line parser avoids requiring PyYAML
    pairs = []
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_\-]+)\s*:\s*(.+?)\s*$", line)
        if m:
            pairs.append((m.group(1), m.group(2).strip().strip('"').strip("'")))
    return pairs


def _flatten_dict(data: Any, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(data, dict):
        out: list[tuple[str, Any]] = []
        for key, value in data.items():
            out.extend(_flatten_dict(value, f"{prefix}.{key}" if prefix else str(key)))
        return out
    return [(prefix.split(".")[-1], data)]


def _extract_dependencies(filename: str, text: str) -> set[str]:
    deps: set[str] = set()
    if filename == "requirements.txt":
        for line in text.splitlines():
            pkg = line.strip().split("==")[0].split(">=")[0]
            if pkg and not pkg.startswith("#"):
                deps.add(pkg.lower())
    elif filename == "poetry.lock":
        deps.update(m.group(1).lower() for m in re.finditer(r'name = "([^"]+)"', text))
    elif filename in {"Pipfile.lock", "package-lock.json"}:
        try:
            data = json.loads(text)
        except Exception:
            return deps
        if filename == "Pipfile.lock":
            deps.update((data.get("default") or {}).keys())
        else:
            deps.update((data.get("dependencies") or {}).keys())
    return deps


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


def _config_evidence(key: str, value: str, normalized_key: str, redaction_policy: str) -> str:
    if not value:
        return key

    if normalized_key in SENSITIVE_CONFIG_KEYS:
        return _masked_and_hashed_value(key, value)

    if redaction_policy == "strict":
        return _masked_and_hashed_value(key, value)

    return f"{key}={value[:80]}"


def _masked_and_hashed_value(key: str, value: str) -> str:
    digest = sha256_bytes(value.encode("utf-8"))[:12]
    if len(value) <= 4:
        masked = "*" * len(value)
    else:
        masked = f"{value[:2]}{'*' * max(len(value) - 4, 1)}{value[-2:]}"
    return f"{key}=[masked:{masked} hash:{digest}]"
