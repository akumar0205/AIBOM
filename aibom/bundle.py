from __future__ import annotations

import json
import re
import subprocess
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile

from aibom.diffing import diff_aibom
from aibom.exporters import export_spdx
from aibom.storage import load_json
from aibom.utils import (
    environment_capture,
    sha256_bytes,
    stable_json,
    validate_safe_path,
)


def build_manifest(files: dict[str, bytes]) -> dict[str, str]:
    return {name: sha256_bytes(content) for name, content in sorted(files.items())}


def create_bundle(
    aibom_path: Path, out_zip: Path, baseline_path: Path | None = None, compliance_md: str = ""
) -> Path:
    aibom = load_json(aibom_path)
    files: dict[str, bytes] = {}
    files["AIBOM.json"] = stable_json(aibom).encode("utf-8")
    files["SPDX.json"] = stable_json(export_spdx(aibom)).encode("utf-8")
    if baseline_path and baseline_path.exists():
        baseline = load_json(baseline_path)
        files["DIFF.json"] = stable_json(diff_aibom(baseline, aibom)).encode("utf-8")
    files["ENVIRONMENT.json"] = stable_json(environment_capture()).encode("utf-8")
    files["COMPLIANCE_MAPPING.md"] = compliance_md.encode("utf-8")
    manifest = build_manifest(files)
    files["MANIFEST.json"] = stable_json(manifest).encode("utf-8")

    with ZipFile(out_zip, "w", compression=ZIP_DEFLATED) as zf:
        for name in sorted(files):
            zf.writestr(name, files[name])
    return out_zip


def _openssl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openssl", *args], check=True, text=True, capture_output=True)


def _cert_metadata(cert_path: Path) -> dict[str, str]:
    # Validate certificate path before passing to openssl
    safe_cert_path = validate_safe_path(cert_path, must_exist=True, must_be_file=True)
    lines = _openssl(
        [
            "x509",
            "-in",
            str(safe_cert_path),
            "-noout",
            "-subject",
            "-issuer",
            "-serial",
            "-dates",
            "-fingerprint",
            "-sha256",
        ]
    ).stdout.splitlines()
    cert_data: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        cert_data[key.strip()] = value.strip()
    return {
        "subject": cert_data.get("subject", ""),
        "issuer": cert_data.get("issuer", ""),
        "serial": cert_data.get("serial", ""),
        "not_before": cert_data.get("notBefore", ""),
        "not_after": cert_data.get("notAfter", ""),
        "sha256_fingerprint": cert_data.get("sha256 Fingerprint", ""),
    }


def _parse_openssl_time(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _certificate_sans(cert_path: Path) -> list[str]:
    # Validate certificate path before passing to openssl
    safe_cert_path = validate_safe_path(cert_path, must_exist=True, must_be_file=True)
    ext = _openssl(["x509", "-in", str(safe_cert_path), "-noout", "-ext", "subjectAltName"]).stdout
    return re.findall(r"DNS:([^,\n]+)", ext)


def _verify_chain(
    signing_cert: Path,
    ca_bundle: Path | None,
    trusted_roots: list[Path] | None,
    crl_file: Path | None,
    revocation_policy: str,
) -> None:
    # Validate signing certificate path
    safe_signing_cert = validate_safe_path(signing_cert, must_exist=True, must_be_file=True)

    if not ca_bundle and not trusted_roots:
        return

    args = ["verify"]
    if ca_bundle:
        safe_ca_bundle = validate_safe_path(ca_bundle, must_exist=True, must_be_file=True)
        args += ["-CAfile", str(safe_ca_bundle)]
    if trusted_roots:
        # Validate all trusted root paths before writing to temp file
        safe_roots = []
        for root in trusted_roots:
            safe_roots.append(validate_safe_path(root, must_exist=True, must_be_file=True))
        roots = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".pem", delete=False)
        with roots:
            for root in safe_roots:
                roots.write(root.read_text(encoding="utf-8"))
                roots.write("\n")
        args += ["-CAfile", roots.name]
    if revocation_policy == "crl":
        if not crl_file:
            raise ValueError("CRL revocation policy requires a CRL file")
        safe_crl_file = validate_safe_path(crl_file, must_exist=True, must_be_file=True)
        args += ["-crl_check", "-CRLfile", str(safe_crl_file)]

    args.append(str(safe_signing_cert))
    try:
        _openssl(args)
    finally:
        if trusted_roots:
            Path(roots.name).unlink(missing_ok=True)


def _enforce_validity_window(signing_cert: Path) -> None:
    metadata = _cert_metadata(signing_cert)
    not_before = _parse_openssl_time(metadata["not_before"])
    not_after = _parse_openssl_time(metadata["not_after"])
    now = datetime.now(timezone.utc)
    if now < not_before or now > not_after:
        raise ValueError("Signing certificate is outside its validity window")


def _match_allowlist(signing_cert: Path, allowlist_policy: dict[str, Any] | None) -> dict[str, Any]:
    cert = _cert_metadata(signing_cert)
    cert_fingerprint = cert.get("sha256_fingerprint", "")
    cert_subject = cert.get("subject", "")
    cert_sans = _certificate_sans(signing_cert)

    if not allowlist_policy:
        return {"status": "skipped", "reason": "no allowlist policy provided"}

    fingerprints = set(allowlist_policy.get("sha256_fingerprints") or [])
    subjects = set(allowlist_policy.get("subjects") or [])
    san_dns = set(allowlist_policy.get("san_dns") or [])

    matches = {
        "sha256_fingerprint": bool(fingerprints and cert_fingerprint in fingerprints),
        "subject": bool(subjects and cert_subject in subjects),
        "san_dns": bool(san_dns and any(name in san_dns for name in cert_sans)),
    }

    if any(matches.values()):
        return {
            "status": "passed",
            "matches": matches,
            "certificate": {
                "subject": cert_subject,
                "sha256_fingerprint": cert_fingerprint,
                "san_dns": cert_sans,
            },
        }

    raise ValueError("Signer certificate is not authorized by allowlist policy")


def _evaluate_revocation(
    signing_cert: Path,
    revocation_policy: str,
    revocation_hook: Callable[[Path], tuple[bool, str] | bool] | None = None,
) -> dict[str, Any]:
    if revocation_policy == "none":
        return {"status": "skipped", "reason": "revocation policy disabled"}
    if revocation_policy == "crl":
        return {"status": "passed", "mechanism": "crl"}
    if revocation_policy == "ocsp":
        if revocation_hook:
            hook_result = revocation_hook(signing_cert)
            if isinstance(hook_result, tuple):
                allowed, detail = hook_result
            else:
                allowed, detail = bool(hook_result), "hook returned boolean"
            if not allowed:
                raise ValueError(f"Revocation hook rejected certificate: {detail}")
            return {"status": "passed", "mechanism": "ocsp", "detail": detail}
        return {"status": "skipped", "reason": "ocsp policy selected without hook"}
    return {"status": "skipped", "reason": "unknown revocation policy"}


def sign_bundle(
    bundle_path: Path,
    signing_key: Path,
    signing_cert: Path,
    signature_path: Path | None = None,
    provenance_path: Path | None = None,
) -> tuple[Path, Path]:
    # Validate all input paths before use
    safe_bundle_path = validate_safe_path(bundle_path, must_exist=True, must_be_file=True)
    safe_signing_key = validate_safe_path(signing_key, must_exist=True, must_be_file=True)
    safe_signing_cert = validate_safe_path(signing_cert, must_exist=True, must_be_file=True)

    signature_path = signature_path or bundle_path.with_suffix(bundle_path.suffix + ".sig")
    provenance_path = provenance_path or bundle_path.with_name("provenance.json")

    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(safe_signing_key),
            "-out",
            str(signature_path),
            str(safe_bundle_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    provenance = {
        "attestation_type": "aibom-bundle-signature/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "bundle": {
            "path": safe_bundle_path.name,
            "sha256": sha256_bytes(safe_bundle_path.read_bytes()),
        },
        "signature": {
            "path": signature_path.name,
            "sha256": sha256_bytes(signature_path.read_bytes()),
            "algorithm": "RSA-SHA256",
        },
        "certificate": _cert_metadata(safe_signing_cert),
        "policy_evaluation": {
            "status": "not_evaluated",
            "checks": {},
        },
    }
    provenance_path.write_text(stable_json(provenance), encoding="utf-8")
    return signature_path, provenance_path


def verify_bundle_signature(
    bundle_path: Path,
    signature_path: Path,
    signing_cert: Path,
    provenance_path: Path | None = None,
    ca_bundle: Path | None = None,
    trusted_roots: list[Path] | None = None,
    revocation_policy: str = "none",
    crl_file: Path | None = None,
    allowlist_policy: dict[str, Any] | None = None,
    revocation_hook: Callable[[Path], tuple[bool, str] | bool] | None = None,
) -> None:
    # Validate all input paths before use
    safe_bundle_path = validate_safe_path(bundle_path, must_exist=True, must_be_file=True)
    safe_signature_path = validate_safe_path(signature_path, must_exist=True, must_be_file=True)
    safe_signing_cert = validate_safe_path(signing_cert, must_exist=True, must_be_file=True)

    # Validate optional paths
    safe_ca_bundle: Path | None = None
    safe_crl_file: Path | None = None
    safe_trusted_roots: list[Path] | None = None
    safe_provenance_path: Path | None = None

    if ca_bundle is not None:
        safe_ca_bundle = validate_safe_path(ca_bundle, must_exist=True, must_be_file=True)
    if crl_file is not None:
        safe_crl_file = validate_safe_path(crl_file, must_exist=True, must_be_file=True)
    if trusted_roots is not None:
        safe_trusted_roots = [
            validate_safe_path(p, must_exist=True, must_be_file=True) for p in trusted_roots
        ]
    if provenance_path is not None and provenance_path.exists():
        safe_provenance_path = validate_safe_path(
            provenance_path, must_exist=True, must_be_file=True
        )

    _enforce_validity_window(safe_signing_cert)
    _verify_chain(
        safe_signing_cert, safe_ca_bundle, safe_trusted_roots, safe_crl_file, revocation_policy
    )

    policy_checks: dict[str, Any] = {
        "certificate_validity": {"status": "passed"},
        "certificate_chain": {
            "status": "passed" if (safe_ca_bundle or safe_trusted_roots) else "skipped",
            "reason": (
                "no trust anchors provided" if not (safe_ca_bundle or safe_trusted_roots) else None
            ),
        },
    }

    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".pem", delete=False
    ) as pubkey_file:
        pubkey_file.write(
            _openssl(["x509", "-in", str(safe_signing_cert), "-pubkey", "-noout"]).stdout
        )
        pubkey_path = Path(pubkey_file.name)
    try:
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(pubkey_path),
                "-signature",
                str(safe_signature_path),
                str(safe_bundle_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        pubkey_path.unlink(missing_ok=True)

    if safe_provenance_path:
        provenance = json.loads(safe_provenance_path.read_text(encoding="utf-8"))
        expected_bundle = provenance.get("bundle", {}).get("sha256")
        expected_sig = provenance.get("signature", {}).get("sha256")
        expected_fp = provenance.get("certificate", {}).get("sha256_fingerprint")
        actual_fp = _cert_metadata(safe_signing_cert).get("sha256_fingerprint")

        if expected_bundle and expected_bundle != sha256_bytes(safe_bundle_path.read_bytes()):
            raise ValueError("Provenance bundle SHA256 does not match input bundle")
        if expected_sig and expected_sig != sha256_bytes(safe_signature_path.read_bytes()):
            raise ValueError("Provenance signature SHA256 does not match signature file")
        if expected_fp and expected_fp != actual_fp:
            raise ValueError(
                "Provenance certificate fingerprint does not match provided certificate"
            )

    policy_checks["signer_allowlist"] = _match_allowlist(safe_signing_cert, allowlist_policy)
    policy_checks["revocation"] = _evaluate_revocation(
        safe_signing_cert,
        revocation_policy,
        revocation_hook=revocation_hook,
    )

    if provenance_path:
        if safe_provenance_path:
            provenance = json.loads(safe_provenance_path.read_text(encoding="utf-8"))
        else:
            provenance = {
                "attestation_type": "aibom-bundle-signature/v1",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        provenance["policy_evaluation"] = {
            "status": "passed",
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "checks": policy_checks,
        }
        if safe_provenance_path:
            safe_provenance_path.write_text(stable_json(provenance), encoding="utf-8")
