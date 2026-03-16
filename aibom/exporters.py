from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from aibom import __version__


def _stable_seed(aibom: dict[str, Any]) -> str:
    metadata = aibom.get("metadata", {})
    preferred = metadata.get("artifact_sha256") or metadata.get("git_sha")
    if preferred and preferred != "DYNAMIC":
        return str(preferred)
    canonical = json.dumps(aibom, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-") or "unknown"


def _spdx_safe_id(prefix: str, *parts: str) -> str:
    joined = "-".join(_slug(part) for part in parts if part)
    digest = hashlib.sha256("::".join(parts).encode("utf-8")).hexdigest()[:10]
    return f"SPDXRef-{prefix}-{joined}-{digest}"


def _normalize_timestamp(aibom: dict[str, Any]) -> str:
    raw = str(aibom.get("metadata", {}).get("generated_at", "")).strip()
    if raw and raw != "DYNAMIC":
        for fmt in ("%Y%m%dT%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                parsed = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                continue
    return "1970-01-01T00:00:00Z"


def _component_evidence(source_file: str | None) -> dict[str, str] | None:
    if not source_file:
        return None
    return {
        "referenceCategory": "OTHER",
        "referenceType": "aibom-evidence-source",
        "referenceLocator": f"file:{source_file}",
    }


def _parse_dependency_names(scan_findings: list[dict[str, Any]]) -> list[str]:
    deps: set[str] = set()
    for finding in scan_findings:
        if finding.get("category") != "dependency graph":
            continue
        evidence = str(finding.get("evidence", ""))
        if ":" not in evidence:
            continue
        dep_fragment = evidence.split(":", maxsplit=1)[1]
        for candidate in dep_fragment.split(","):
            name = candidate.strip().strip(".")
            if name:
                deps.add(name)
    return sorted(deps)


def export_spdx(aibom: dict[str, Any]) -> dict[str, Any]:
    seed = _stable_seed(aibom)
    created = _normalize_timestamp(aibom)
    doc_namespace = f"https://aibom.dev/spdx/{seed}"

    packages: list[dict[str, Any]] = []
    package_ids_by_name: dict[str, str] = {}

    def add_package(kind: str, name: str, version: str, source_file: str | None = None) -> None:
        spdx_id = _spdx_safe_id(kind, name, version, source_file or "")
        package: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "supplier": "NOASSERTION",
        }
        evidence_ref = _component_evidence(source_file)
        if evidence_ref:
            package["externalRefs"] = [evidence_ref]
        packages.append(package)
        package_ids_by_name.setdefault(name.lower(), spdx_id)

    for model in aibom.get("models", []):
        add_package(
            "Model",
            str(model.get("type", "unknown-model")),
            str(model.get("model", "unknown")),
            model.get("source_file"),
        )
    for tool in aibom.get("tools", []):
        add_package(
            "Tool",
            str(tool.get("name", "unknown-tool")),
            str(tool.get("version", "unknown")),
            tool.get("source_file"),
        )
    for dataset in aibom.get("datasets", []):
        add_package(
            "Dataset",
            str(dataset.get("type", "unknown-dataset")),
            str(dataset.get("version", "unknown")),
            dataset.get("source_file"),
        )
    for framework in aibom.get("frameworks", []):
        add_package(
            "Framework",
            str(framework.get("name", "unknown-framework")),
            str(framework.get("version", "unknown")),
            framework.get("source_file"),
        )

    packages = sorted(packages, key=lambda x: x["SPDXID"])
    document_describes = [pkg["SPDXID"] for pkg in packages]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package_id,
        }
        for package_id in document_describes
    ]

    dep_names = _parse_dependency_names(aibom.get("scan_findings", []))
    for dep_name in dep_names:
        target_id = package_ids_by_name.get(dep_name.lower())
        if not target_id:
            continue
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": target_id,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"AIBOM SPDX Export {seed[:12]}",
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: aibom/{__version__}", "Organization: AIBOM Project"],
        },
        "documentDescribes": document_describes,
        "packages": packages,
        "relationships": relationships,
    }


def export_cyclonedx(aibom: dict[str, Any]) -> dict[str, Any]:
    seed = _stable_seed(aibom)
    timestamp = _normalize_timestamp(aibom)
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"aibom:{seed}")

    components: list[dict[str, Any]] = []
    refs_by_name: dict[str, str] = {}

    finding_by_source: dict[str, dict[str, str]] = {}
    for finding in aibom.get("scan_findings", []):
        source = str(finding.get("source_file", ""))
        if source and source not in finding_by_source:
            finding_by_source[source] = {
                "confidence": str(finding.get("confidence", "unknown")),
                "severity": str(finding.get("severity", "unknown")),
                "source_type": str(finding.get("source_type", "unknown")),
            }

    def add_component(
        component_type: str, name: str, version: str, source_file: str | None = None
    ) -> None:
        ref_seed = f"{component_type}:{name}:{version}:{source_file or ''}"
        bom_ref = f"aibom-{hashlib.sha256(ref_seed.encode('utf-8')).hexdigest()[:16]}"
        props = [{"name": "aibom:source_file", "value": source_file or "unknown"}]
        if source_file and source_file in finding_by_source:
            source_meta = finding_by_source[source_file]
            props.extend(
                [
                    {"name": "aibom:confidence", "value": source_meta["confidence"]},
                    {"name": "aibom:severity", "value": source_meta["severity"]},
                    {"name": "aibom:source_type", "value": source_meta["source_type"]},
                ]
            )
        component = {
            "type": component_type,
            "name": name,
            "version": version,
            "bom-ref": bom_ref,
            "properties": props,
        }
        components.append(component)
        refs_by_name.setdefault(name.lower(), bom_ref)

    for model in aibom.get("models", []):
        add_component(
            "application",
            str(model.get("type", "unknown-model")),
            str(model.get("model", "unknown")),
            model.get("source_file"),
        )
    for tool in aibom.get("tools", []):
        add_component(
            "application",
            str(tool.get("name", "unknown-tool")),
            str(tool.get("version", "unknown")),
            tool.get("source_file"),
        )
    for dataset in aibom.get("datasets", []):
        add_component(
            "data",
            str(dataset.get("type", "unknown-dataset")),
            str(dataset.get("version", "unknown")),
            dataset.get("source_file"),
        )
    for framework in aibom.get("frameworks", []):
        add_component(
            "library",
            str(framework.get("name", "unknown-framework")),
            str(framework.get("version", "unknown")),
            framework.get("source_file"),
        )

    components = sorted(components, key=lambda x: x["bom-ref"])
    dependency_names = _parse_dependency_names(aibom.get("scan_findings", []))
    depends_on = [
        refs_by_name[name.lower()] for name in dependency_names if name.lower() in refs_by_name
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "AIBOM", "name": "aibom", "version": __version__}],
        },
        "components": components,
        "dependencies": [
            {
                "ref": "aibom-root-document",
                "dependsOn": sorted(set(depends_on)),
            }
        ],
    }
