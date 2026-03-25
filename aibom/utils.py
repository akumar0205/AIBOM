from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Characters dangerous in shell contexts that should be rejected
_SHELL_METACHARACTERS = frozenset(";&|`$(){}[]!\"'\\<>\n\r")


class PathSecurityError(ValueError):
    """Raised when a path fails security validation."""

    pass


def validate_safe_path(
    path: Path,
    must_exist: bool = True,
    must_be_file: bool = False,
    must_be_dir: bool = False,
    allow_symlinks: bool = False,
    base_dir: Path | None = None,
) -> Path:
    """
    Validate that a path is safe to use in subprocess calls.

    Args:
        path: The path to validate
        must_exist: Whether the path must exist
        must_be_file: Whether the path must be a file
        must_be_dir: Whether the path must be a directory
        allow_symlinks: Whether symlinks are allowed
        base_dir: If provided, path must resolve to be within this directory

    Returns:
        The resolved, absolute path

    Raises:
        PathSecurityError: If the path fails security validation
    """
    # Convert to Path if string
    path_obj = Path(path)

    # Check for shell metacharacters in the path string
    path_str = str(path_obj)
    if any(c in _SHELL_METACHARACTERS for c in path_str):
        bad_chars = [c for c in path_str if c in _SHELL_METACHARACTERS]
        raise PathSecurityError(f"Path contains shell metacharacters: {bad_chars[:5]}")

    # Convert to absolute path and resolve symlinks
    try:
        abs_path = path_obj.resolve(strict=False)
    except (OSError, ValueError) as e:
        raise PathSecurityError(f"Cannot resolve path: {e}")

    # Check if path is within base_dir (path traversal protection)
    if base_dir is not None:
        base_resolved = base_dir.resolve()
        try:
            abs_path.relative_to(base_resolved)
        except ValueError:
            raise PathSecurityError(
                f"Path {abs_path} is outside allowed base directory {base_resolved}"
            )

    # Check existence
    if must_exist and not abs_path.exists():
        raise PathSecurityError(f"Path does not exist: {abs_path}")

    # Check if it's a symlink
    if not allow_symlinks and abs_path.is_symlink():
        raise PathSecurityError(f"Symlinks are not allowed: {abs_path}")

    # Check file type
    if must_be_file and must_exist and not abs_path.is_file():
        raise PathSecurityError(f"Path is not a file: {abs_path}")

    if must_be_dir and must_exist and not abs_path.is_dir():
        raise PathSecurityError(f"Path is not a directory: {abs_path}")

    # Additional check: ensure the path doesn't contain null bytes
    if b"\x00" in os.fsencode(abs_path):
        raise PathSecurityError("Path contains null bytes")

    return abs_path


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def git_sha(cwd: Path) -> str:
    """Get git SHA with path validation."""
    try:
        # Validate the working directory path
        safe_cwd = validate_safe_path(cwd, must_exist=True, must_be_dir=True)

        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(safe_cwd),
            text=True,
            stderr=subprocess.PIPE,
        ).strip()
        return out
    except PathSecurityError as e:
        logger.warning("Path security error for git SHA: %s", e)
        return "unknown"
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("Failed to get git SHA in %s: %s", cwd, e)
        return "unknown"


def environment_capture() -> dict[str, Any]:
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
    }
