from __future__ import annotations

import json
from pathlib import Path

from aibom.exporters import (
    export_cyclonedx,
    export_sarif,
    export_spdx,
    export_vex,
)


def _input_doc() -> dict:
    return json.loads(
        (Path(__file__).parent / "fixtures" / "export_input_aibom.json").read_text(
            encoding="utf-8"
        )
    )


def _evidence_doc() -> dict:
    """Synthetic doc carrying evidence-graded provenance."""
    return {
        "schema_version": "1.0",
        "metadata": {
            "generated_at": "2026-01-02T03:04:05Z",
            "git_sha": "a" * 40,
            "artifact_sha256": "b" * 64,
        },
        "models": [
            {
                "type": "ChatOpenAI",
                "model": "gpt-4o-mini",
                "source_file": "app.py",
                "evidence_class": "observed_call",
                "detection_method": "direct-constructor",
                "provenance": {
                    "provider_endpoint": "https://api.openai.com",
                    "registry_uri": None,
                    "immutable_version": None,
                    "environment": "prod",
                    "region": None,
                    "evidence": {
                        "provider_endpoint": {
                            "status": "inferred",
                            "method": "inferred:model-class-default",
                        },
                        "registry_uri": {"status": "missing", "method": "not-observed"},
                        "immutable_version": {
                            "status": "missing",
                            "method": "not-observed",
                        },
                        "environment": {
                            "status": "observed",
                            "method": "observed:config-file",
                        },
                        "region": {"status": "missing", "method": "not-observed"},
                    },
                },
            }
        ],
        "tools": [],
        "datasets": [],
        "frameworks": [{"name": "openai"}],
        "prompts": [],
        "scan_findings": [],
        "risk_findings": [
            {
                "id": "third-party-provider:ChatOpenAI:app.py",
                "rule_id": "third-party-provider",
                "base_rule_id": "third-party-provider",
                "finding_kind": "risk",
                "category": "third-party dependency",
                "owasp_llm": "LLM07 Insecure Plugin Design",
                "severity": "medium",
                "rationale": "External model provider detected.",
                "heuristic": "true",
                "control_objective": "Approve providers.",
                "remediation": "Review vendor.",
            }
        ],
    }


def test_spdx_conforms_to_native_shape() -> None:
    spdx = export_spdx(_input_doc())
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert spdx["documentNamespace"].startswith("https://")
    assert spdx["creationInfo"]["created"].endswith("Z")
    assert spdx["documentDescribes"]
    for package in spdx["packages"]:
        assert package["SPDXID"].startswith("SPDXRef-")
        for field in (
            "name",
            "versionInfo",
            "downloadLocation",
            "filesAnalyzed",
            "licenseConcluded",
            "licenseDeclared",
            "supplier",
        ):
            assert field in package, f"missing SPDX package field {field}"
    assert {"DESCRIBES"} <= {r["relationshipType"] for r in spdx["relationships"]}


def test_cyclonedx_conforms_to_native_shape() -> None:
    cdx = export_cyclonedx(_input_doc())
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert cdx["serialNumber"].startswith("urn:uuid:")
    assert cdx["version"] == 1
    assert cdx["metadata"]["timestamp"].endswith("Z")
    for component in cdx["components"]:
        assert component["bom-ref"]
        for field in ("type", "name", "version"):
            assert field in component, f"missing CycloneDX field {field}"
    assert cdx["dependencies"]


def test_sarif_conforms_to_native_shape() -> None:
    sarif = export_sarif(_input_doc())
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].startswith("https://")
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "aibom"
    assert run["results"]
    for result in run["results"]:
        assert result["ruleId"]
        assert result["message"]["text"] is not None
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_vex_conforms_to_native_shape() -> None:
    vex = export_vex(_input_doc())
    assert vex["@context"].startswith("https://openvex.dev")
    assert vex["@id"].startswith("urn:uuid:")
    assert vex["timestamp"].endswith("Z")
    assert vex["version"] == 1
    for statement in vex["statements"]:
        assert statement["vulnerability"]["name"]
        assert statement["products"]
        assert statement["status"] in {
            "affected",
            "under_investigation",
            "not_affected",
        }


def test_exports_carry_evidence_grades_with_namespaced_extensions() -> None:
    doc = _evidence_doc()
    spdx = export_spdx(doc)
    ref_types = {
        ref["referenceType"]
        for package in spdx["packages"]
        for ref in package.get("externalRefs", [])
    }
    assert "aibom:provenance:evidence:environment" in ref_types
    assert "aibom:provenance:environment" in ref_types
    # Missing provenance must not emit bare value refs.
    assert "aibom:provenance:registry_uri" not in ref_types

    cdx = export_cyclonedx(doc)
    prop_names = {
        prop["name"] for component in cdx["components"] for prop in component["properties"]
    }
    assert "aibom:provenance:evidence:environment" in prop_names
    # Every custom property is aibom:-namespaced; native fields stay native.
    assert all(
        name.startswith("aibom:") for name in prop_names if ":" in name or name.startswith("aibom")
    )
    for component in cdx["components"]:
        assert set(component) >= {"type", "name", "version", "bom-ref", "properties"}
