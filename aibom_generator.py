#!/usr/bin/env python3
"""Generate an AI Bill of Materials (AIBOM) for a Python codebase.

The script statically analyzes Python files to identify AI-related components,
with a focus on LangChain usage.
"""

from __future__ import annotations

import argparse
import ast
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

try:
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    import importlib_metadata  # type: ignore


FRAMEWORK_ALIASES: Dict[str, Set[str]] = {
    "langchain": {"langchain", "langchain_openai", "langchain_community", "langchain_core"},
    "transformers": {"transformers"},
    "torch": {"torch", "pytorch"},
    "tensorflow": {"tensorflow", "tf"},
    "faiss": {"faiss", "faiss_cpu", "faiss_gpu"},
    "sentence_transformers": {"sentence_transformers"},
    "openai": {"openai"},
    "chromadb": {"chromadb"},
    "llama_index": {"llama_index"},
    "scikit-learn": {"sklearn", "scikit_learn"},
}

MODEL_CLASS_HINTS = {
    "OpenAI",
    "ChatOpenAI",
    "AzureChatOpenAI",
    "AzureOpenAI",
    "HuggingFaceHub",
    "HuggingFacePipeline",
    "HuggingFaceEndpoint",
    "Cohere",
    "Bedrock",
    "Ollama",
    "VertexAI",
    "ChatAnthropic",
    "Anthropic",
}

VECTORSTORE_HINTS = {
    "FAISS",
    "Chroma",
    "Pinecone",
    "Weaviate",
    "Milvus",
    "Qdrant",
    "PGVector",
}

TOOL_HINTS = {
    "initialize_agent",
    "create_react_agent",
    "AgentExecutor",
    "load_tools",
    "Tool",
    "StructuredTool",
    "SerpAPIWrapper",
}

MODEL_KEYWORDS = {
    "model",
    "model_name",
    "model_id",
    "repo_id",
    "checkpoint",
    "deployment_name",
    "engine",
}

DATASET_KEYWORDS = {
    "file_path",
    "path",
    "persist_directory",
    "collection_name",
    "index_name",
    "index_path",
    "directory",
    "source",
}


class AIBOMVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.imported_frameworks: Set[str] = set()
        self.import_map: Dict[str, str] = {}
        self.models: List[Dict[str, Any]] = []
        self.datasets: List[Dict[str, Any]] = []
        self.tools: List[Dict[str, Any]] = []

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            name = alias.name
            root = name.split(".")[0]
            asname = alias.asname or root
            self.import_map[asname] = name
            self._track_framework(root)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        if not node.module:
            return
        root = node.module.split(".")[0]
        self._track_framework(root)
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.import_map[local_name] = f"{node.module}.{alias.name}"

            if root == "langchain":
                if alias.name in MODEL_CLASS_HINTS:
                    self.models.append(
                        {
                            "type": alias.name,
                            "model": "unknown",
                            "source_file": str(self.file_path),
                            "details": "Imported LangChain model class",
                        }
                    )
                if alias.name in TOOL_HINTS or "agent" in alias.name.lower():
                    self.tools.append(
                        {
                            "name": alias.name,
                            "purpose": "LangChain agent/tool import",
                            "source_file": str(self.file_path),
                        }
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        fn_name = self._name_of(node.func)
        fn_root = fn_name.split(".")[-1] if fn_name else ""

        if fn_root in MODEL_CLASS_HINTS:
            self.models.append(self._build_model_entry(fn_name, node))

        if fn_root in TOOL_HINTS or "agent" in fn_name.lower():
            self.tools.append(self._build_tool_entry(fn_name, node))

        if self._is_vectorstore_call(fn_name):
            self.datasets.append(self._build_dataset_entry(fn_name, node))

        self.generic_visit(node)

    def _track_framework(self, import_root: str) -> None:
        for framework, aliases in FRAMEWORK_ALIASES.items():
            if import_root in aliases:
                self.imported_frameworks.add(framework)

    def _name_of(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._name_of(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _extract_literal(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                else:
                    parts.append("{expr}")
            return "".join(parts)
        return None

    def _collect_kwargs(self, node: ast.Call) -> Dict[str, str]:
        collected: Dict[str, str] = {}
        for kw in node.keywords:
            if kw.arg is None:
                continue
            literal = self._extract_literal(kw.value)
            if literal is not None:
                collected[kw.arg] = literal
        return collected

    def _build_model_entry(self, fn_name: str, node: ast.Call) -> Dict[str, Any]:
        kwargs = self._collect_kwargs(node)
        model_value = "unknown"
        for key in MODEL_KEYWORDS:
            if key in kwargs:
                model_value = kwargs[key]
                break

        if model_value == "unknown" and node.args:
            first_literal = self._extract_literal(node.args[0])
            if first_literal:
                model_value = first_literal

        return {
            "type": fn_name.split(".")[-1],
            "model": model_value,
            "source_file": str(self.file_path),
            "details": {"call": fn_name, "params": kwargs},
        }

    def _build_tool_entry(self, fn_name: str, node: ast.Call) -> Dict[str, Any]:
        kwargs = self._collect_kwargs(node)
        purpose = kwargs.get("description") or kwargs.get("purpose") or "Agent/tool usage detected"
        return {
            "name": fn_name.split(".")[-1],
            "purpose": purpose,
            "source_file": str(self.file_path),
            "details": {"call": fn_name, "params": kwargs},
        }

    def _is_vectorstore_call(self, fn_name: str) -> bool:
        if not fn_name:
            return False
        parts = fn_name.split(".")
        return any(part in VECTORSTORE_HINTS for part in parts)

    def _build_dataset_entry(self, fn_name: str, node: ast.Call) -> Dict[str, Any]:
        kwargs = self._collect_kwargs(node)
        dataset_refs: Dict[str, str] = {}
        for key in DATASET_KEYWORDS:
            if key in kwargs:
                dataset_refs[key] = kwargs[key]

        if node.args:
            literal_args = [self._extract_literal(arg) for arg in node.args]
            detected_paths = [arg for arg in literal_args if arg and ("/" in arg or "." in arg)]
            if detected_paths:
                dataset_refs["positional_refs"] = ", ".join(detected_paths)

        return {
            "name": fn_name.split(".")[0],
            "type": fn_name,
            "used_for": "Vector store / dataset ingestion",
            "source_file": str(self.file_path),
            "details": dataset_refs or {"note": "No explicit dataset path found"},
        }


def find_python_files(target: Path) -> Iterable[Path]:
    ignored_dirs = {".venv", "venv", "env", "__pycache__"}
    for py_file in target.rglob("*.py"):
        if any(part in ignored_dirs for part in py_file.parts):
            continue
        yield py_file


def get_framework_versions(frameworks: Iterable[str]) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    for fw in sorted(set(frameworks)):
        version = "not installed"
        possible_pkgs = sorted(FRAMEWORK_ALIASES.get(fw, {fw}))
        for pkg_name in possible_pkgs:
            try:
                version = importlib_metadata.version(pkg_name.replace("_", "-"))
                break
            except importlib_metadata.PackageNotFoundError:
                continue
        result.append({"name": fw, "version": version})
    return result


def dedupe_dict_entries(entries: List[Dict[str, Any]], keys: List[str]) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    unique: List[Dict[str, Any]] = []
    for entry in entries:
        marker = "|".join(str(entry.get(key, "")) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(entry)
    return unique


def generate_aibom(target_dir: Path) -> Dict[str, Any]:
    all_models: List[Dict[str, Any]] = []
    all_datasets: List[Dict[str, Any]] = []
    all_tools: List[Dict[str, Any]] = []
    framework_hits: Set[str] = set()

    file_errors: Dict[str, str] = {}

    for py_file in find_python_files(target_dir):
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except Exception as exc:
            file_errors[str(py_file)] = str(exc)
            continue

        visitor = AIBOMVisitor(py_file)
        visitor.visit(tree)

        all_models.extend(visitor.models)
        all_datasets.extend(visitor.datasets)
        all_tools.extend(visitor.tools)
        framework_hits.update(visitor.imported_frameworks)

    aibom = {
        "models": dedupe_dict_entries(all_models, ["type", "model", "source_file"]),
        "datasets": dedupe_dict_entries(all_datasets, ["type", "source_file"]),
        "tools": dedupe_dict_entries(all_tools, ["name", "source_file"]),
        "frameworks": get_framework_versions(framework_hits),
    }

    if file_errors:
        aibom["analysis_warnings"] = file_errors

    return aibom


def print_summary(aibom: Dict[str, Any]) -> None:
    print("=== AI Bill of Materials Summary ===")
    print(f"Models found    : {len(aibom.get('models', []))}")
    print(f"Datasets found  : {len(aibom.get('datasets', []))}")
    print(f"Tools found     : {len(aibom.get('tools', []))}")
    print(f"Frameworks found: {len(aibom.get('frameworks', []))}")

    if aibom.get("frameworks"):
        print("Framework versions:")
        for fw in aibom["frameworks"]:
            print(f"  - {fw['name']}: {fw['version']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an AI BOM for a Python codebase.")
    parser.add_argument("target", nargs="?", default=".", help="Target project directory to scan")
    parser.add_argument(
        "-o",
        "--output",
        default="AI_BOM.json",
        help="Output JSON file path (default: AI_BOM.json)",
    )
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    output_path = Path(args.output).resolve()

    aibom = generate_aibom(target_dir)
    output_path.write_text(json.dumps(aibom, indent=2), encoding="utf-8")

    print_summary(aibom)
    print(f"\nFull AI BOM written to: {output_path}")


if __name__ == "__main__":
    main()
