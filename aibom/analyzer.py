from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

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


def generate_aibom(target_dir: Path, include_prompts: bool = False) -> dict[str, Any]:
    models: list[dict[str, Any]] = []
    datasets: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    prompts: list[dict[str, Any]] = []
    frameworks: set[str] = set()

    for py_file in find_python_files(target_dir):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        visitor = AIBOMVisitor(py_file.relative_to(target_dir), include_prompts=include_prompts)
        visitor.visit(tree)
        models.extend(visitor.models)
        datasets.extend(visitor.datasets)
        tools.extend(visitor.tools)
        prompts.extend(visitor.prompts)
        frameworks.update(visitor.imported_frameworks)

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
    }
    doc["risk_findings"] = generate_risk_findings(doc)
    artifact_hash = sha256_bytes(stable_json(doc).encode("utf-8"))
    doc["metadata"]["artifact_sha256"] = artifact_hash
    return doc
