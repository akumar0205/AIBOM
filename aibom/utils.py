from __future__ import annotations

import hashlib
import json
import logging
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def git_sha(cwd: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(cwd),
            text=True,
            stderr=subprocess.PIPE,
        ).strip()
        return out
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("Failed to get git SHA in %s: %s", cwd, e)
        return "unknown"


def environment_capture() -> dict[str, Any]:
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
    }
