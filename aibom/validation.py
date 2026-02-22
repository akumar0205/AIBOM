from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

AIBOM_SCHEMA_VERSION = "1.0"
ALLOWED_SCHEMA_VERSIONS = {AIBOM_SCHEMA_VERSION}
DEFAULT_SCHEMA_PATH = Path(__file__).parent / "schema" / "aibom_v1.json"


class AIBOMValidationException(ValueError):
    """Raised when an AIBOM document fails schema validation."""

    def __init__(self, pointer: str, message: str):
        self.pointer = pointer
        self.message = message
        super().__init__(f"Schema validation failed at {pointer}: {message}")


AIBOMValidationError = AIBOMValidationException


def _json_pointer(path: list[Any]) -> str:
    if not path:
        return "/"
    escaped = [str(p).replace("~", "~0").replace("/", "~1") for p in path]
    return "/" + "/".join(escaped)


def _error_pointer(err: Any) -> str:
    base_path = list(err.absolute_path)
    if err.validator == "required":
        missing_match = re.search(r"'([^']+)' is a required property", err.message)
        if missing_match:
            base_path.append(missing_match.group(1))
    return _json_pointer(base_path)


@lru_cache(maxsize=4)
def _load_schema(schema_path: str) -> dict[str, Any]:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


@lru_cache(maxsize=4)
def _build_validator(schema_path: str) -> Draft202012Validator:
    schema = _load_schema(schema_path)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def validate_aibom(doc: dict[str, Any], schema_path: object | None = None) -> None:
    resolved = Path(schema_path) if schema_path else DEFAULT_SCHEMA_PATH

    schema_version = doc.get("schema_version")
    if schema_version not in ALLOWED_SCHEMA_VERSIONS:
        allowed = ", ".join(sorted(ALLOWED_SCHEMA_VERSIONS))
        raise AIBOMValidationException(
            "/schema_version", f"Invalid value {schema_version!r}. Allowed versions: {allowed}"
        )

    validator = _build_validator(str(resolved))
    errors = sorted(validator.iter_errors(doc), key=lambda e: (_error_pointer(e), e.message))

    if errors:
        first = errors[0]
        raise AIBOMValidationException(_error_pointer(first), first.message)
