"""Evidence-graded provenance model (SOC-003).

Missing provenance is represented as ``None`` plus an explicit evidence entry
``{"status": "missing", "method": "not-observed"}`` instead of placeholder
strings such as ``"unknown"``, so auditors can distinguish observed,
inferred, and missing collection states.
"""

from __future__ import annotations

from typing import Any

EVIDENCE_STATUSES = ("observed", "inferred", "missing")
PROVENANCE_FIELDS = (
    "provider_endpoint",
    "registry_uri",
    "immutable_version",
    "environment",
    "region",
)
LINEAGE_FIELDS = (
    "model_artifact_digest",
    "deployment_id",
    "service_account_identity",
    "owning_system",
)


def _missing_evidence() -> dict[str, str]:
    return {"status": "missing", "method": "not-observed"}


def _observed_or_inferred_evidence(method: str) -> dict[str, str]:
    status = "observed" if method.startswith("observed") else "inferred"
    return {"status": status, "method": method}


def _provenance(
    provider_endpoint: str | None = None,
    registry_uri: str | None = None,
    immutable_version: str | None = None,
    environment: str | None = None,
    region: str | None = None,
    _methods: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build evidence-graded provenance.

    Missing fields are ``None`` with ``{"status": "missing", ...}`` evidence
    instead of placeholder strings, so downstream consumers can distinguish
    observed, inferred, and missing collection states.
    """
    methods = _methods or {}
    values = {
        "provider_endpoint": provider_endpoint,
        "registry_uri": registry_uri,
        "immutable_version": immutable_version,
        "environment": environment,
        "region": region,
    }
    evidence: dict[str, dict[str, str]] = {}
    for field, value in values.items():
        if value is None:
            evidence[field] = _missing_evidence()
        else:
            evidence[field] = _observed_or_inferred_evidence(
                methods.get(field, "inferred:static-analysis-default")
            )
    return {**values, "evidence": evidence}


def _lineage(
    model_artifact_digest: str | None = None,
    deployment_id: str | None = None,
    service_account_identity: str | None = None,
    owning_system: str | None = None,
    _methods: dict[str, str] | None = None,
) -> dict[str, Any]:
    methods = _methods or {}
    values = {
        "model_artifact_digest": model_artifact_digest,
        "deployment_id": deployment_id,
        "service_account_identity": service_account_identity,
        "owning_system": owning_system,
    }
    evidence: dict[str, dict[str, str]] = {}
    for field, value in values.items():
        if value is None:
            evidence[field] = _missing_evidence()
        else:
            evidence[field] = _observed_or_inferred_evidence(
                methods.get(field, "inferred:static-analysis-default")
            )
    return {**values, "evidence": evidence}


def _set_provenance_field(prov: dict[str, Any], field: str, value: str, method: str) -> None:
    prov[field] = value
    prov.setdefault("evidence", {})[field] = _observed_or_inferred_evidence(method)


def _set_lineage_field(prov: dict[str, Any], field: str, value: str, method: str) -> None:
    lineage = prov.get("lineage")
    if not isinstance(lineage, dict):
        lineage = _lineage()
        prov["lineage"] = lineage
    lineage[field] = value
    lineage.setdefault("evidence", {})[field] = _observed_or_inferred_evidence(method)


def _merge_evidence_dicts(
    base_ev: dict[str, Any] | None,
    overlay_ev: dict[str, Any] | None,
    fields: tuple[str, ...],
    overlay_wins: set[str],
) -> dict[str, dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}
    for field in fields:
        candidate = None
        if field in overlay_wins and isinstance(overlay_ev, dict) and field in overlay_ev:
            candidate = overlay_ev[field]
        elif isinstance(base_ev, dict) and field in base_ev:
            candidate = base_ev[field]
        elif isinstance(overlay_ev, dict) and field in overlay_ev:
            candidate = overlay_ev[field]
        if isinstance(candidate, dict) and candidate.get("status") in EVIDENCE_STATUSES:
            merged[field] = {
                "status": str(candidate["status"]),
                "method": str(candidate.get("method", "not-observed")),
            }
        else:
            merged[field] = _missing_evidence()
    return merged


def _merge_lineage(
    base: dict[str, Any] | None, overlay: dict[str, Any] | None
) -> dict[str, Any] | None:
    base = dict(base) if isinstance(base, dict) else _lineage()
    overlay = overlay if isinstance(overlay, dict) else {}
    merged: dict[str, Any] = {}
    overlay_wins: set[str] = set()
    has_observed = False
    for lineage_field in LINEAGE_FIELDS:
        value = overlay.get(lineage_field)
        if value is not None:
            merged[lineage_field] = value
            overlay_wins.add(lineage_field)
            has_observed = True
        elif base.get(lineage_field) is not None:
            merged[lineage_field] = base.get(lineage_field)
            has_observed = True
        else:
            merged[lineage_field] = None
    merged["evidence"] = _merge_evidence_dicts(
        base.get("evidence") if isinstance(base.get("evidence"), dict) else None,
        overlay.get("evidence") if isinstance(overlay.get("evidence"), dict) else None,
        LINEAGE_FIELDS,
        overlay_wins,
    )
    return merged if has_observed else None


def _merge_provenance(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    base = dict(base) if base else _provenance()
    overlay = overlay if isinstance(overlay, dict) else {}
    merged: dict[str, Any] = {}
    overlay_wins: set[str] = set()
    for provenance_field in PROVENANCE_FIELDS:
        value = overlay.get(provenance_field)
        if value is not None:
            merged[provenance_field] = value
            overlay_wins.add(provenance_field)
        else:
            merged[provenance_field] = base.get(provenance_field)
    merged["evidence"] = _merge_evidence_dicts(
        base.get("evidence") if isinstance(base.get("evidence"), dict) else None,
        overlay.get("evidence") if isinstance(overlay.get("evidence"), dict) else None,
        PROVENANCE_FIELDS,
        overlay_wins,
    )
    merged_lineage = _merge_lineage(
        base.get("lineage") if isinstance(base.get("lineage"), dict) else None,
        overlay.get("lineage") if isinstance(overlay.get("lineage"), dict) else None,
    )
    if merged_lineage:
        merged["lineage"] = merged_lineage
    elif isinstance(base.get("lineage"), dict):
        merged["lineage"] = base["lineage"]
    return merged
