from __future__ import annotations

import json
from pathlib import Path

from aibom.exporters import export_cyclonedx, export_spdx


FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_export_spdx_matches_golden_fixture() -> None:
    aibom_doc = _load_fixture("export_input_aibom.json")
    expected = _load_fixture("golden_spdx_export.json")

    actual = export_spdx(aibom_doc)

    assert actual == expected
    assert actual["documentNamespace"].startswith("https://aibom.dev/spdx/")
    assert actual["creationInfo"]["creators"]
    assert actual["creationInfo"]["created"].endswith("Z")
    assert any(r["relationshipType"] == "DESCRIBES" for r in actual["relationships"])
    assert any(r["relationshipType"] == "DEPENDS_ON" for r in actual["relationships"])
    for package in actual["packages"]:
        assert package["externalRefs"][0]["referenceLocator"].startswith("file:")


def test_export_cyclonedx_matches_golden_fixture() -> None:
    aibom_doc = _load_fixture("export_input_aibom.json")
    expected = _load_fixture("golden_cyclonedx_export.json")

    actual = export_cyclonedx(aibom_doc)

    assert actual == expected
    assert actual["serialNumber"].startswith("urn:uuid:")
    assert actual["metadata"]["timestamp"].endswith("Z")
    assert actual["metadata"]["tools"][0]["name"] == "aibom"
    assert actual["dependencies"][0]["dependsOn"]
    for component in actual["components"]:
        assert component["bom-ref"].startswith("aibom-")
        prop_names = {prop["name"] for prop in component["properties"]}
        assert "aibom:source_file" in prop_names
