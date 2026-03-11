from __future__ import annotations

import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from aibom.diffing import diff_aibom
from aibom.exporters import export_spdx
from aibom.storage import load_json
from aibom.utils import environment_capture, sha256_bytes, stable_json


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
    lines = _openssl(
        [
            "x509",
            "-in",
            str(cert_path),
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


def sign_bundle(
    bundle_path: Path,
    signing_key: Path,
    signing_cert: Path,
    signature_path: Path | None = None,
    provenance_path: Path | None = None,
) -> tuple[Path, Path]:
    signature_path = signature_path or bundle_path.with_suffix(bundle_path.suffix + ".sig")
    provenance_path = provenance_path or bundle_path.with_name("provenance.json")

    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            str(signing_key),
            "-out",
            str(signature_path),
            str(bundle_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    provenance = {
        "attestation_type": "aibom-bundle-signature/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "bundle": {
            "path": bundle_path.name,
            "sha256": sha256_bytes(bundle_path.read_bytes()),
        },
        "signature": {
            "path": signature_path.name,
            "sha256": sha256_bytes(signature_path.read_bytes()),
            "algorithm": "RSA-SHA256",
        },
        "certificate": _cert_metadata(signing_cert),
    }
    provenance_path.write_text(stable_json(provenance), encoding="utf-8")
    return signature_path, provenance_path


def verify_bundle_signature(
    bundle_path: Path,
    signature_path: Path,
    signing_cert: Path,
    provenance_path: Path | None = None,
) -> None:
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".pem", delete=False
    ) as pubkey_file:
        pubkey_file.write(_openssl(["x509", "-in", str(signing_cert), "-pubkey", "-noout"]).stdout)
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
                str(signature_path),
                str(bundle_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        pubkey_path.unlink(missing_ok=True)

    if provenance_path and provenance_path.exists():
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        expected_bundle = provenance.get("bundle", {}).get("sha256")
        expected_sig = provenance.get("signature", {}).get("sha256")
        expected_fp = provenance.get("certificate", {}).get("sha256_fingerprint")
        actual_fp = _cert_metadata(signing_cert).get("sha256_fingerprint")

        if expected_bundle and expected_bundle != sha256_bytes(bundle_path.read_bytes()):
            raise ValueError("Provenance bundle SHA256 does not match input bundle")
        if expected_sig and expected_sig != sha256_bytes(signature_path.read_bytes()):
            raise ValueError("Provenance signature SHA256 does not match signature file")
        if expected_fp and expected_fp != actual_fp:
            raise ValueError(
                "Provenance certificate fingerprint does not match provided certificate"
            )
