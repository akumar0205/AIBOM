from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(cwd), text=True).strip()
        return out
    except Exception:
        return "unknown"


def environment_capture() -> dict[str, Any]:
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
    }
