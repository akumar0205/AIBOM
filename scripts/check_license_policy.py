#!/usr/bin/env python3
"""Fail CI when disallowed or unknown licenses are present."""

from __future__ import annotations

import json
import sys
from pathlib import Path

DISALLOWED_LICENSE_TOKENS = ("GPL", "LGPL", "AGPL")
ALLOWED_LICENSES = {
    "MIT",
    "MIT License",
    "BSD",
    "BSD License",
    "Apache-2.0",
    "Apache Software License",
    "Python Software Foundation License",
    "ISC",
    "ISC License",
    "MPL-2.0",
    "Mozilla Public License 2.0 (MPL 2.0)",
}


def normalize(license_name: str) -> str:
    return " ".join(license_name.strip().split())


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check_license_policy.py <pip-licenses-json>")
        return 2

    report_path = Path(sys.argv[1])
    report = json.loads(report_path.read_text(encoding="utf-8"))

    violations: list[str] = []

    for entry in report:
        package = entry.get("Name", "<unknown-package>")
        license_name = normalize(str(entry.get("License", "UNKNOWN")))

        if not license_name or license_name.upper() == "UNKNOWN":
            violations.append(f"{package}: unknown license")
            continue

        if any(token in license_name for token in DISALLOWED_LICENSE_TOKENS):
            violations.append(f"{package}: disallowed copyleft license '{license_name}'")
            continue

        if license_name not in ALLOWED_LICENSES:
            violations.append(f"{package}: not in allowlist '{license_name}'")

    if violations:
        print("License policy violations detected:")
        for violation in violations:
            print(f" - {violation}")
        return 1

    print("License policy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
