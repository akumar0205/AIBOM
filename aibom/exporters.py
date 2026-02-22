from __future__ import annotations

from typing import Any


def export_spdx(aibom: dict[str, Any]) -> dict[str, Any]:
    packages: list[dict[str, Any]] = []
    for model in aibom.get("models", []):
        packages.append({"SPDXID": f"SPDXRef-Model-{model['type']}", "name": model["type"], "versionInfo": model.get("model", "unknown")})
    for tool in aibom.get("tools", []):
        packages.append({"SPDXID": f"SPDXRef-Tool-{tool['name']}", "name": tool["name"], "versionInfo": "unknown"})
    for ds in aibom.get("datasets", []):
        packages.append({"SPDXID": f"SPDXRef-Dataset-{ds['type'].replace('.', '-')}", "name": ds["type"], "versionInfo": "unknown"})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "AIBOM Export",
        "documentNamespace": "https://example.com/spdx/aibom",
        "packages": sorted(packages, key=lambda x: x["SPDXID"]),
    }


def export_cyclonedx(aibom: dict[str, Any]) -> dict[str, Any]:
    components: list[dict[str, str]] = []
    for model in aibom.get("models", []):
        components.append({"type": "machine-learning-model", "name": model["type"], "version": model.get("model", "unknown")})
    for fw in aibom.get("frameworks", []):
        components.append({"type": "library", "name": fw["name"], "version": "unknown"})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": sorted(components, key=lambda x: x["name"])}
