from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

try:
    from jsonschema import Draft202012Validator
except ModuleNotFoundError:  # pragma: no cover
    Draft202012Validator = None


AIBOM_SCHEMA_VERSION = "1.0"
ALLOWED_SCHEMA_VERSIONS = {AIBOM_SCHEMA_VERSION}
DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schema" / "aibom_v1.json"


class AIBOMValidationError(ValueError):
    """Raised when an AIBOM document fails validation."""


@dataclass
class _SimpleValidationIssue:
    absolute_path: list[Any]
    message: str


def _json_pointer(path: list[Any]) -> str:
    if not path:
        return "/"
    escaped = [str(p).replace("~", "~0").replace("/", "~1") for p in path]
    return "/" + "/".join(escaped)


@lru_cache(maxsize=4)
def _load_schema(schema_path: str) -> dict[str, Any]:
    return json.loads(Path(schema_path).read_text(encoding="utf-8"))


def _type_matches(value: Any, expected: str) -> bool:
    mapping = {
        "object": dict,
        "array": list,
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
    }
    py_type = mapping.get(expected)
    return isinstance(value, py_type) if py_type else True


def _iter_simple_schema_errors(value: Any, schema: dict[str, Any], path: list[Any]) -> Iterable[_SimpleValidationIssue]:
    expected_type = schema.get("type")
    if expected_type and not _type_matches(value, expected_type):
        yield _SimpleValidationIssue(path, f"{value!r} is not of type '{expected_type}'")
        return

    if "enum" in schema and value not in schema["enum"]:
        yield _SimpleValidationIssue(path, f"{value!r} is not one of {schema['enum']}")

    if isinstance(value, str) and "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
        yield _SimpleValidationIssue(path, f"{value!r} does not match pattern {schema['pattern']!r}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                yield _SimpleValidationIssue(path, f"{key!r} is a required property")

        properties = schema.get("properties", {})
        for key, prop_schema in properties.items():
            if key in value and isinstance(prop_schema, dict):
                yield from _iter_simple_schema_errors(value[key], prop_schema, [*path, key])

    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for idx, item in enumerate(value):
            yield from _iter_simple_schema_errors(item, schema["items"], [*path, idx])


def _iter_schema_errors(doc: dict[str, Any], schema: dict[str, Any]) -> Iterable[Any]:
    if Draft202012Validator is not None:
        validator = Draft202012Validator(schema)
        yield from validator.iter_errors(doc)
    else:
        yield from _iter_simple_schema_errors(doc, schema, [])


def validate_aibom(doc: dict[str, Any], schema_path: object | None = None) -> None:
    resolved = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH

    schema_version = doc.get("schema_version")
    if schema_version not in ALLOWED_SCHEMA_VERSIONS:
        allowed = ", ".join(sorted(ALLOWED_SCHEMA_VERSIONS))
        raise AIBOMValidationError(
            f"Invalid schema_version at /schema_version: {schema_version!r}. Allowed versions: {allowed}"
        )

    schema = _load_schema(str(resolved))
    errors = sorted(_iter_schema_errors(doc, schema), key=lambda e: (list(e.absolute_path), e.message))

    if errors:
        lines: list[str] = []
        for err in errors:
            pointer = _json_pointer(list(err.absolute_path))
            lines.append(f"- {pointer}: {err.message}")
        raise AIBOMValidationError("AIBOM schema validation failed:\n" + "\n".join(lines))
