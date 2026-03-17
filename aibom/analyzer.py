from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aibom.confidence import score_confidence
from aibom.detectors import DotNetAstDetector, GoAstDetector, JSTSAstDetector, JavaAstDetector
from aibom.detectors.protocol import SourceDetector
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
PROVENANCE_UNKNOWN = "unknown"
PROVENANCE_FIELDS = (
    "provider_endpoint",
    "registry_uri",
    "immutable_version",
    "environment",
    "region",
)
LINEAGE_FIELDS = (
    "model_artifact_digest",
    "deployment_id",
    "service_account_identity",
    "owning_system",
)
PROVIDER_ENDPOINT_KEYS = {
    "provider_endpoint",
    "endpoint",
    "api_base",
    "base_url",
    "openai_api_base",
    "azure_endpoint",
}
REGISTRY_URI_KEYS = {
    "registry_uri",
    "model_registry_uri",
    "model_repo_uri",
    "repository",
    "repository_uri",
}
IMMUTABLE_VERSION_KEYS = {
    "model_version",
    "model_digest",
    "digest",
    "image",
    "image_digest",
    "image_uri",
}
ENVIRONMENT_KEYS = {"environment", "env", "stage", "deployment_stage"}
REGION_KEYS = {"region", "aws_region", "azure_region", "gcp_region"}
DEPLOYMENT_ID_KEYS = {
    "deployment",
    "deployment_id",
    "deployment_name",
    "release",
    "release_name",
}
SERVICE_ACCOUNT_IDENTITY_KEYS = {
    "serviceaccount",
    "serviceaccountname",
    "service_account",
    "service_account_email",
    "service_account_name",
    "workload_identity",
}
OWNING_SYSTEM_KEYS = {
    "app",
    "application",
    "managed_by",
    "owner",
    "owning_system",
    "system",
    "team",
}
MODEL_ARTIFACT_DIGEST_KEYS = {
    "artifact_digest",
    "digest",
    "image_digest",
    "model_artifact_digest",
    "model_digest",
}
MODEL_PROVIDER_ENDPOINTS = {
    "ChatOpenAI": "https://api.openai.com",
    "OpenAI": "https://api.openai.com",
    "ChatAnthropic": "https://api.anthropic.com",
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
    "requirements-dev.txt",
    "constraints.txt",
    "poetry.lock",
    "pyproject.toml",
    "uv.lock",
    "pdm.lock",
    "pdm.toml",
    "Pipfile.lock",
    "package-lock.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Chart.yaml",
    "values.yaml",
}
RUNTIME_MANIFEST_SUFFIXES = {".yaml", ".yml", ".json", ".toml"}
RUNTIME_MANIFEST_PATH_HINTS = {"k8s", "kubernetes", "helm", "charts", "manifests"}
AI_RUNTIME_CONFIG_KEY_PATTERN = re.compile(
    r"(openai|anthropic|azure_openai|huggingface|ollama|vertexai|bedrock|llm|model).*"
    r"(endpoint|base|url|api|key|token|model|deployment|version)?",
    re.IGNORECASE,
)


@dataclass
class ScanResult:
    models: list[dict[str, Any]] = field(default_factory=list)
    datasets: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    scan_findings: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    runtime_context: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanContext:
    target_dir: Path
    include_prompts: bool
    include_runtime_manifests: bool
    redaction_policy: str = "strict"


class AIBOMVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, include_prompts: bool = False) -> None:
        self.file_path = file_path
        self.include_prompts = include_prompts
        self.models: list[dict[str, Any]] = []
        self.datasets: list[dict[str, Any]] = []
        self.tools: list[dict[str, Any]] = []
        self.prompts: list[dict[str, Any]] = []
        self.imported_frameworks: set[str] = set()
        self.import_aliases: dict[str, str] = {}
        self.bindings: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            root = alias.name.split(".")[0]
            self._track_framework(root)
            self.import_aliases[alias.asname or root] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if not node.module:
            return
        self._track_framework(node.module.split(".")[0])
        for alias in node.names:
            if alias.name == "*":
                continue
            self.import_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        bound = self._bound_symbol(node.value)
        if bound:
            for target in node.targets:
                for target_name in self._target_names(target):
                    self.bindings[target_name] = bound
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        bound = self._bound_symbol(node.value)
        if bound:
            for target_name in self._target_names(node.target):
                self.bindings[target_name] = bound
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        resolved_name = self._resolve_symbol(self._name_of(node.func))
        leaf = resolved_name.split(".")[-1]
        source_ref = f"{self.file_path}:{getattr(node, 'lineno', 0)}"
        file_ref = str(self.file_path)
        if leaf in MODEL_CLASS_HINTS:
            provider_endpoint = MODEL_PROVIDER_ENDPOINTS.get(leaf, PROVENANCE_UNKNOWN)
            self.models.append(
                {
                    "type": leaf,
                    "model": self._arg_or_kw(node, "model", "model_name"),
                    "source_file": file_ref,
                    "signals": sorted(self._classification_signals(resolved_name, node)),
                    "provenance": _provenance(provider_endpoint=provider_endpoint),
                }
            )
        if leaf in TOOL_HINTS or "agent" in leaf.lower():
            self.tools.append({"name": leaf, "source_file": file_ref})
        if any(part in VECTORSTORE_HINTS for part in resolved_name.split(".")):
            self.datasets.append({"type": resolved_name, "source_file": file_ref})
        if leaf in PROMPT_HINTS:
            entry = {"id": source_ref, "source_file": file_ref}
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

    def _resolve_symbol(self, name: str) -> str:
        if not name:
            return ""
        parts = name.split(".")
        root = parts[0]
        if root in self.bindings:
            return ".".join(self.bindings[root].split(".") + parts[1:])
        if root in self.import_aliases:
            return ".".join(self.import_aliases[root].split(".") + parts[1:])
        return name

    def _bound_symbol(self, value: ast.AST | None) -> str:
        if value is None:
            return ""
        if isinstance(value, ast.Name):
            return self._resolve_symbol(value.id)
        if isinstance(value, ast.Attribute):
            return self._resolve_symbol(self._name_of(value))
        if isinstance(value, ast.Call):
            return self._resolve_symbol(self._name_of(value.func))
        return ""

    def _target_names(self, target: ast.AST) -> list[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            out: list[str] = []
            for elt in target.elts:
                out.extend(self._target_names(elt))
            return out
        return []

    def _classification_signals(self, resolved_name: str, node: ast.Call) -> set[str]:
        signals: set[str] = {"constructor"}
        root = resolved_name.split(".")[0]
        if root in {"openai", "anthropic", "langchain", "langchain_openai", "transformers"}:
            signals.add("import")
        if any(
            kw.arg in {"model", "model_name", "api_key", "provider", "openai_api_key"}
            for kw in node.keywords
            if kw.arg
        ):
            signals.add("config_key")
        return signals

    def _arg_or_kw(self, node: ast.Call, *keys: str, default: str = "unknown") -> str:
        for kw in node.keywords:
            if (
                kw.arg in keys
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                return kw.value.value
        if (
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
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
        candidates = find_python_files(context.target_dir)
        scanned = 0
        for py_file in candidates:
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            scanned += 1
            rel = py_file.relative_to(context.target_dir)
            visitor = AIBOMVisitor(rel, include_prompts=context.include_prompts)
            visitor.visit(tree)
            for model in visitor.models:
                model_signals = set(model.get("signals", []))
                clean_model = {k: v for k, v in model.items() if k != "signals"}
                result.models.append(clean_model)
                result.scan_findings.append(
                    _finding(
                        finding_id=f"python-model:{model['type']}:{model['source_file']}",
                        category="model invocation",
                        source_type=self.source_type,
                        source_file=model["source_file"],
                        severity="medium",
                        confidence=score_confidence(model_signals),
                        evidence=f"Model class {model['type']} detected in Python source.",
                    )
                )
            result.datasets.extend(visitor.datasets)
            result.tools.extend(visitor.tools)
            result.prompts.extend(visitor.prompts)
            result.frameworks.update(visitor.imported_frameworks)
        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "high",
        }
        return result


class NotebookDetector:
    source_type = "jupyter_notebook"

    def scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        candidates = sorted(context.target_dir.rglob("*.ipynb"))
        scanned = 0
        for notebook in candidates:
            try:
                payload = json.loads(notebook.read_text(encoding="utf-8"))
            except Exception:
                continue
            scanned += 1
            rel = notebook.relative_to(context.target_dir)
            cells = payload.get("cells", [])
            for idx, cell in enumerate(cells):
                if cell.get("cell_type") != "code":
                    continue
                src = "".join(cell.get("source", []))
                if not src.strip():
                    continue
                try:
                    tree = ast.parse(src)
                except Exception:
                    continue
                visitor = AIBOMVisitor(
                    Path(f"{rel}#cell-{idx}"), include_prompts=context.include_prompts
                )
                visitor.visit(tree)
                result.models.extend(
                    {k: v for k, v in model.items() if k != "signals"} for model in visitor.models
                )
                result.datasets.extend(visitor.datasets)
                result.tools.extend(visitor.tools)
                result.prompts.extend(visitor.prompts)
                result.frameworks.update(visitor.imported_frameworks)
        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "medium",
        }
        return result


class ConfigFileDetector:
    source_type = "config"

    def scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        candidates = _config_candidates(context.target_dir)
        scanned = 0
        for file_path in candidates:
            rel = file_path.relative_to(context.target_dir)
            text = _safe_read_text(file_path)
            if not text:
                continue
            scanned += 1

            kv_pairs = _extract_key_values(file_path, text)
            detector_runtime_context = _provenance()
            model_provenance = _provenance()
            for key, value in kv_pairs:
                normalized = key.lower()

                if normalized in PROVIDER_ENDPOINT_KEYS and value:
                    detector_runtime_context["provider_endpoint"] = value
                    model_provenance["provider_endpoint"] = value
                if normalized in REGISTRY_URI_KEYS and value:
                    detector_runtime_context["registry_uri"] = value
                    model_provenance["registry_uri"] = value
                if normalized in IMMUTABLE_VERSION_KEYS and value:
                    detector_runtime_context["immutable_version"] = value
                    model_provenance["immutable_version"] = value
                if normalized in ENVIRONMENT_KEYS and value:
                    detector_runtime_context["environment"] = value
                    model_provenance["environment"] = value
                if normalized in REGION_KEYS and value:
                    detector_runtime_context["region"] = value
                    model_provenance["region"] = value

                if normalized in DEPLOYMENT_ID_KEYS and value:
                    detector_runtime_context.setdefault("lineage", _lineage())
                    model_provenance.setdefault("lineage", _lineage())
                    detector_runtime_context["lineage"]["deployment_id"] = value
                    model_provenance["lineage"]["deployment_id"] = value
                if normalized in SERVICE_ACCOUNT_IDENTITY_KEYS and value:
                    detector_runtime_context.setdefault("lineage", _lineage())
                    model_provenance.setdefault("lineage", _lineage())
                    detector_runtime_context["lineage"]["service_account_identity"] = value
                    model_provenance["lineage"]["service_account_identity"] = value
                if normalized in OWNING_SYSTEM_KEYS and value:
                    detector_runtime_context.setdefault("lineage", _lineage())
                    model_provenance.setdefault("lineage", _lineage())
                    detector_runtime_context["lineage"]["owning_system"] = value
                    model_provenance["lineage"]["owning_system"] = value
                if normalized in MODEL_ARTIFACT_DIGEST_KEYS and value and "sha256:" in value:
                    detector_runtime_context.setdefault("lineage", _lineage())
                    model_provenance.setdefault("lineage", _lineage())
                    detector_runtime_context["lineage"]["model_artifact_digest"] = value
                    model_provenance["lineage"]["model_artifact_digest"] = value

                if normalized not in CONFIG_KEY_HINTS:
                    continue

                descriptor = CONFIG_KEY_HINTS[normalized]
                severity = "high" if "credential" in descriptor else "medium"
                signals = {"config_key"}
                if normalized in {"model", "model_name", "provider"}:
                    signals.add("import")
                confidence = score_confidence(signals)
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
                            "confidence": score_confidence({"config_key"}),
                            "provenance": model_provenance,
                        }
                    )
                if normalized == "provider" and value:
                    result.frameworks.add(value.lower())
            result.runtime_context = _merge_provenance(
                result.runtime_context, detector_runtime_context
            )
        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "medium",
        }
        return result


class RuntimeManifestDetector:
    source_type = "runtime_manifest"

    def scan(self, context: ScanContext) -> ScanResult:
        if not context.include_runtime_manifests:
            result = ScanResult()
            result.coverage = {
                "source_type": self.source_type,
                "artifacts_seen": 0,
                "artifacts_scanned": 0,
                "default_confidence": "medium",
            }
            return result

        result = ScanResult()
        candidates = _runtime_manifest_candidates(context.target_dir)
        scanned = 0
        for file_path in candidates:
            rel = file_path.relative_to(context.target_dir)
            text = _safe_read_text(file_path)
            if not text:
                continue
            scanned += 1

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

            runtime_context = _runtime_context_from_manifest(file_path.name, text)
            result.runtime_context = _merge_provenance(result.runtime_context, runtime_context)

            lineage_pairs = _extract_lineage_key_values(file_path.name, text)
            for key, value in lineage_pairs:
                result.scan_findings.append(
                    _finding(
                        finding_id=f"runtime-lineage:{rel}:{key}",
                        category="deployment lineage",
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity="low",
                        confidence="medium",
                        evidence=_config_evidence(key, value, key, context.redaction_policy),
                    )
                )

            immutable_refs = _extract_immutable_image_refs(file_path.name, text)
            for ref in immutable_refs:
                result.scan_findings.append(
                    _finding(
                        finding_id=f"runtime-image-digest:{rel}:{ref}",
                        category="immutable image digest",
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity="low",
                        confidence=score_confidence({"constructor"}),
                        evidence=f"Immutable OCI image reference detected: {ref}",
                    )
                )

            ai_runtime_keys = _extract_runtime_ai_service_config(file_path.name, text)
            for key, value in ai_runtime_keys:
                result.scan_findings.append(
                    _finding(
                        finding_id=f"runtime-ai-config:{rel}:{key}",
                        category="runtime ai service config",
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity="medium",
                        confidence="medium",
                        evidence=_config_evidence(key, value, key, context.redaction_policy),
                    )
                )

            if (
                immutable_refs
                or ai_runtime_keys
                or lineage_pairs
                or file_path.name.lower().startswith("docker")
            ):
                result.scan_findings.append(
                    _finding(
                        finding_id=f"runtime-container:{rel}",
                        category="container metadata",
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity="low",
                        confidence=score_confidence({"constructor"}),
                        evidence="Container/runtime metadata discovered.",
                    )
                )
        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "medium",
        }
        return result


class JSTSPackageManifestDetector:
    source_type = "js_ts_manifest"

    def scan(self, context: ScanContext) -> ScanResult:
        result = ScanResult()
        candidates = _js_ts_manifest_candidates(context.target_dir)
        scanned = 0
        for manifest in candidates:
            rel = manifest.relative_to(context.target_dir)
            text = _safe_read_text(manifest)
            if not text:
                continue
            scanned += 1
            deps = _extract_js_ts_dependencies(manifest.name, text)
            if deps:
                result.scan_findings.append(
                    _finding(
                        finding_id=f"js-ts-deps:{rel}",
                        category="dependency graph",
                        source_type=self.source_type,
                        source_file=str(rel),
                        severity="medium",
                        confidence="medium",
                        evidence=f"Detected JS/TS dependencies: {', '.join(sorted(deps)[:10])}",
                    )
                )
                for dep in deps:
                    for fw, aliases in FRAMEWORK_ALIASES.items():
                        if dep.lower() in aliases:
                            result.frameworks.add(fw)
        result.coverage = {
            "source_type": self.source_type,
            "artifacts_seen": len(candidates),
            "artifacts_scanned": scanned,
            "default_confidence": "medium",
        }
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
    ignored = {".venv", "venv", "__pycache__", ".git", ".aibom"}
    return sorted(
        [p for p in target.rglob("*.py") if not any(part in ignored for part in p.parts)],
        key=lambda p: str(p),
    )


def generate_aibom(
    target_dir: Path,
    include_prompts: bool = False,
    include_runtime_manifests: bool = False,
    redaction_policy: str = "strict",
    risk_policy_path: Path | None = None,
    extra_detectors: list[SourceDetector] | None = None,
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
    detectors: list[SourceDetector] = [
        PythonAstDetector(),
        NotebookDetector(),
        ConfigFileDetector(),
        RuntimeManifestDetector(),
        JSTSPackageManifestDetector(),
        JSTSAstDetector(),
        JavaAstDetector(),
        GoAstDetector(),
        DotNetAstDetector(),
    ]
    detectors.extend(extra_detectors or [])

    models: list[dict[str, Any]] = []
    datasets: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    frameworks: set[str] = set()
    scan_findings: list[dict[str, Any]] = []
    coverage_summary: list[dict[str, Any]] = []
    runtime_context = _provenance()

    for detector in detectors:
        partial = detector.scan(context)
        models.extend(partial.models)
        datasets.extend(partial.datasets)
        tools.extend(partial.tools)
        prompts.extend(partial.prompts)
        frameworks.update(partial.frameworks)
        scan_findings.extend(partial.scan_findings)
        if partial.coverage:
            coverage_summary.append(partial.coverage)
        runtime_context = _merge_provenance(runtime_context, partial.runtime_context)

    unsupported_artifacts = _unsupported_artifacts(context.target_dir)

    model_entries = _dedupe(models, ["type", "model", "source_file"])
    model_entries = [
        _with_model_provenance(model_entry, runtime_context=runtime_context)
        for model_entry in model_entries
    ]

    doc: dict[str, Any] = {
        "schema_version": "1.0",
        "metadata": {
            "generated_at": utc_now(),
            "git_sha": git_sha(target_dir),
        },
        "models": model_entries,
        "datasets": _dedupe(datasets, ["type", "source_file"]),
        "tools": _dedupe(tools, ["name", "source_file"]),
        "frameworks": [{"name": f} for f in sorted(frameworks)],
        "prompts": _dedupe(prompts, ["id"]),
        "scan_findings": _dedupe(scan_findings, ["id"]),
        "coverage_summary": {
            "detectors": sorted(coverage_summary, key=lambda x: x.get("source_type", "")),
            "unsupported_total": len(unsupported_artifacts),
        },
        "unsupported_artifacts": unsupported_artifacts,
        "source_types": [
            {"name": "python", "default_severity": "medium", "default_confidence": "high"},
            {
                "name": "jupyter_notebook",
                "default_severity": "medium",
                "default_confidence": "medium",
            },
            {"name": "config", "default_severity": "medium", "default_confidence": "medium"},
            {
                "name": "runtime_manifest",
                "default_severity": "medium",
                "default_confidence": "medium",
            },
            {
                "name": "js_ts_manifest",
                "default_severity": "medium",
                "default_confidence": "medium",
            },
            {
                "name": "js_ts_ast",
                "default_severity": "medium",
                "default_confidence": "medium",
            },
            {"name": "java_ast", "default_severity": "medium", "default_confidence": "medium"},
            {"name": "go_ast", "default_severity": "medium", "default_confidence": "medium"},
            {"name": "dotnet_ast", "default_severity": "medium", "default_confidence": "medium"},
        ],
        "runtime_context": runtime_context,
    }
    risk_findings, risk_policy = generate_risk_findings(doc, policy_path=risk_policy_path)
    doc["risk_findings"] = risk_findings
    doc["risk_policy"] = risk_policy
    artifact_hash = sha256_bytes(stable_json(doc).encode("utf-8"))
    doc["metadata"]["artifact_sha256"] = artifact_hash
    return doc


def _config_candidates(target: Path) -> list[Path]:
    ignored = {".venv", "venv", "__pycache__", ".git", ".aibom"}
    out: set[Path] = set()
    for pattern in CONFIG_GLOBS:
        out.update(p for p in target.rglob(pattern) if not any(part in ignored for part in p.parts))
    return sorted(out)


def _runtime_manifest_candidates(target: Path) -> list[Path]:
    ignored = {".venv", "venv", "__pycache__", ".git", ".aibom"}
    out: set[Path] = set()
    for p in target.rglob("*"):
        if not p.is_file() or any(part in ignored for part in p.parts):
            continue
        lowered = p.name.lower()
        parent_parts = {part.lower() for part in p.parts}
        if p.name in RUNTIME_MANIFEST_FILES:
            out.add(p)
            continue
        if lowered in {"deployment.yaml", "service.yaml", "statefulset.yaml", "job.yaml"}:
            out.add(p)
            continue
        if (
            p.suffix.lower() in RUNTIME_MANIFEST_SUFFIXES
            and parent_parts & RUNTIME_MANIFEST_PATH_HINTS
        ):
            out.add(p)
    return sorted(out)


def _js_ts_manifest_candidates(target: Path) -> list[Path]:
    ignored = {".venv", "venv", "__pycache__", ".git", ".aibom"}
    names = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    out: list[Path] = []
    for p in target.rglob("*"):
        if not p.is_file() or any(part in ignored for part in p.parts):
            continue
        if p.name in names:
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
    lowered = filename.lower()

    if lowered in {"requirements.txt", "requirements-dev.txt", "constraints.txt"}:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            pkg = re.split(r"==|>=|<=|~=|!=|<|>", line, maxsplit=1)[0].strip()
            if pkg:
                deps.add(pkg.lower())
    elif lowered == "poetry.lock":
        deps.update(m.group(1).lower() for m in re.finditer(r'name = "([^"]+)"', text))
    elif lowered == "uv.lock":
        deps.update(m.group(1).lower() for m in re.finditer(r'name\s*=\s*"([^"]+)"', text))
    elif lowered == "pdm.lock":
        deps.update(m.group(1).lower() for m in re.finditer(r'name\s*=\s*"([^"]+)"', text))
    elif lowered == "pyproject.toml":
        deps.update(
            m.group(1).lower()
            for m in re.finditer(r'"([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|\^|<|>)', text)
        )
    elif lowered in {"pdm.toml", "chart.yaml", "values.yaml"}:
        deps.update(
            m.group(1).lower()
            for m in re.finditer(r"^\s*name\s*:\s*([A-Za-z0-9_.-]+)", text, flags=re.MULTILINE)
        )
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


def _extract_js_ts_dependencies(filename: str, text: str) -> set[str]:
    deps: set[str] = set()
    if filename in {"package.json", "package-lock.json"}:
        try:
            data = json.loads(text)
        except Exception:
            return deps
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            deps.update((data.get(key) or {}).keys())
    if filename == "yarn.lock":
        deps.update(
            m.group(1).split("@")[0] for m in re.finditer(r"^([^\s:@][^:\n]*?)@", text, re.M)
        )
    if filename == "pnpm-lock.yaml":
        deps.update(m.group(1).split("/")[-1] for m in re.finditer(r"^\s*/([^:@]+)", text, re.M))
    return {d.lower() for d in deps if d}


def _unsupported_artifacts(target: Path) -> list[dict[str, str]]:
    ignored = {".venv", "venv", "__pycache__", ".git", ".aibom"}
    unsupported_ext = {".toml"}
    out: list[dict[str, str]] = []
    for p in sorted(target.rglob("*")):
        if not p.is_file() or any(part in ignored for part in p.parts):
            continue
        if p.suffix.lower() in unsupported_ext:
            out.append(
                {
                    "path": str(p.relative_to(target)),
                    "artifact_type": p.suffix.lower(),
                    "reason": "No enabled detector covers this source artifact type.",
                }
            )
    return out


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


def _lineage(
    model_artifact_digest: str = PROVENANCE_UNKNOWN,
    deployment_id: str = PROVENANCE_UNKNOWN,
    service_account_identity: str = PROVENANCE_UNKNOWN,
    owning_system: str = PROVENANCE_UNKNOWN,
) -> dict[str, str]:
    return {
        "model_artifact_digest": model_artifact_digest,
        "deployment_id": deployment_id,
        "service_account_identity": service_account_identity,
        "owning_system": owning_system,
    }


def _merge_lineage(
    base: dict[str, str] | None, overlay: dict[str, str] | None
) -> dict[str, str] | None:
    merged = dict(base) if isinstance(base, dict) else _lineage()
    has_known = False
    for lineage_field in LINEAGE_FIELDS:
        value = PROVENANCE_UNKNOWN
        if isinstance(overlay, dict):
            value = overlay.get(lineage_field, PROVENANCE_UNKNOWN)
        if value and value != PROVENANCE_UNKNOWN:
            merged[lineage_field] = value
        elif lineage_field not in merged:
            merged[lineage_field] = PROVENANCE_UNKNOWN
        if merged.get(lineage_field) != PROVENANCE_UNKNOWN:
            has_known = True
    return merged if has_known else None


def _merge_provenance(base: dict[str, str], overlay: dict[str, str]) -> dict[str, str]:
    merged = dict(base) if base else _provenance()
    for provenance_field in PROVENANCE_FIELDS:
        value = overlay.get(provenance_field, PROVENANCE_UNKNOWN)
        if value and value != PROVENANCE_UNKNOWN:
            merged[provenance_field] = value
        elif provenance_field not in merged:
            merged[provenance_field] = PROVENANCE_UNKNOWN
    merged_lineage = _merge_lineage(
        base.get("lineage") if isinstance(base.get("lineage"), dict) else None,
        overlay.get("lineage") if isinstance(overlay.get("lineage"), dict) else None,
    )
    if merged_lineage:
        merged["lineage"] = merged_lineage
    return merged


def _with_model_provenance(
    model: dict[str, Any], runtime_context: dict[str, str]
) -> dict[str, Any]:
    model_copy = dict(model)
    model_provenance = model_copy.get("provenance")
    model_copy["provenance"] = _merge_provenance(
        runtime_context,
        model_provenance if isinstance(model_provenance, dict) else _provenance(),
    )
    return model_copy


def _runtime_context_from_manifest(filename: str, text: str) -> dict[str, str]:
    runtime_context = _provenance()
    if filename.lower().startswith("docker"):
        from_match = re.search(r"^\s*FROM\s+([^\s]+)", text, re.MULTILINE | re.IGNORECASE)
        if from_match:
            image = from_match.group(1).strip()
            runtime_context["immutable_version"] = image
            if "/" in image:
                runtime_context["registry_uri"] = image.rsplit(":", 1)[0]

    immutable_refs = _extract_immutable_image_refs(filename, text)
    if immutable_refs:
        runtime_context["immutable_version"] = immutable_refs[0]
        runtime_context["registry_uri"] = immutable_refs[0].split("@", 1)[0]

    for key, value in _extract_runtime_ai_service_config(filename, text):
        if key in PROVIDER_ENDPOINT_KEYS and value:
            runtime_context["provider_endpoint"] = value
        elif key in IMMUTABLE_VERSION_KEYS and value:
            runtime_context["immutable_version"] = value
        elif key in REGISTRY_URI_KEYS and value:
            runtime_context["registry_uri"] = value
        elif key in ENVIRONMENT_KEYS and value:
            runtime_context["environment"] = value
        elif key in REGION_KEYS and value:
            runtime_context["region"] = value

    lineage = _lineage()
    for key, value in _extract_lineage_key_values(filename, text):
        if key in DEPLOYMENT_ID_KEYS and value:
            lineage["deployment_id"] = value
        elif key in SERVICE_ACCOUNT_IDENTITY_KEYS and value:
            lineage["service_account_identity"] = value
        elif key in OWNING_SYSTEM_KEYS and value:
            lineage["owning_system"] = value
        elif key in MODEL_ARTIFACT_DIGEST_KEYS and value and "sha256:" in value:
            lineage["model_artifact_digest"] = value
    merged_lineage = _merge_lineage(None, lineage)
    if merged_lineage:
        runtime_context["lineage"] = merged_lineage
    return runtime_context


def _extract_immutable_image_refs(filename: str, text: str) -> list[str]:
    if not text:
        return []
    refs: set[str] = set()
    if filename.lower().startswith("docker"):
        refs.update(
            m.group(1).strip()
            for m in re.finditer(
                r"^\s*FROM\s+([^\s]+@sha256:[a-fA-F0-9]{64})",
                text,
                re.MULTILINE | re.IGNORECASE,
            )
        )
    refs.update(
        m.group(1).strip() for m in re.finditer(r"([\w./:-]+@sha256:[a-fA-F0-9]{64})", text)
    )
    return sorted(refs)


def _extract_runtime_ai_service_config(filename: str, text: str) -> list[tuple[str, str]]:
    pairs = _extract_key_values(Path(filename), text)
    findings: list[tuple[str, str]] = []
    for key, value in pairs:
        normalized = key.lower()
        if AI_RUNTIME_CONFIG_KEY_PATTERN.match(normalized):
            findings.append((normalized, value))
        elif normalized in PROVIDER_ENDPOINT_KEYS | IMMUTABLE_VERSION_KEYS | REGISTRY_URI_KEYS:
            findings.append((normalized, value))
    return findings


def _extract_lineage_key_values(filename: str, text: str) -> list[tuple[str, str]]:
    pairs = _extract_key_values(Path(filename), text)
    findings: list[tuple[str, str]] = []
    lineage_keys = (
        DEPLOYMENT_ID_KEYS
        | SERVICE_ACCOUNT_IDENTITY_KEYS
        | OWNING_SYSTEM_KEYS
        | MODEL_ARTIFACT_DIGEST_KEYS
    )
    for key, value in pairs:
        normalized = key.lower()
        if normalized in lineage_keys:
            findings.append((normalized, value))
    return findings


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
