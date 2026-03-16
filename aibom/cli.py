from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aibom import __version__
from aibom.analyzer import generate_aibom
from aibom.bundle import create_bundle, sign_bundle, verify_bundle_signature
from aibom.diffing import diff_aibom, gate_failures
from aibom.exporters import export_cyclonedx, export_spdx
from aibom.risk.heuristics import generate_risk_findings
from aibom.storage import load_json, persist_run
from aibom.validation import AIBOMValidationException, validate_aibom


COMPLIANCE_STARTER = """# Starter Compliance Mapping\n\nThis mapping is a starter reference only and not legal advice.\n"""


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def _parse_allowlist(args: argparse.Namespace) -> dict[str, list[str]] | None:
    policy: dict[str, list[str]] = {}
    if args.allow_subject:
        policy["subjects"] = list(args.allow_subject)
    if args.allow_san_dns:
        policy["san_dns"] = list(args.allow_san_dns)
    if args.allow_fingerprint:
        policy["sha256_fingerprints"] = list(args.allow_fingerprint)
    return policy or None


def cmd_generate(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    out = Path(args.output).resolve()
    if args.include_prompts and not args.acknowledge_prompt_exposure_risk:
        print(
            "ERROR: --include-prompts is high risk and requires --acknowledge-prompt-exposure-risk.",
            file=sys.stderr,
        )
        return 2

    if args.include_prompts:
        print(
            "WARNING: Including prompts may expose sensitive business logic or secrets in templates.",
            file=sys.stderr,
        )

    risk_policy_path = Path(args.risk_policy).resolve() if args.risk_policy else None

    aibom = generate_aibom(
        target,
        include_prompts=args.include_prompts,
        include_runtime_manifests=args.include_runtime_manifests,
        redaction_policy=args.redaction_policy,
        risk_policy_path=risk_policy_path,
    )
    try:
        validate_aibom(aibom)
    except AIBOMValidationException as exc:
        print(f"ERROR: Schema validation failed at {exc.pointer}: {exc.message}", file=sys.stderr)
        return 2

    if args.fail_on_unsupported_threshold is not None:
        unsupported = len(aibom.get("unsupported_artifacts", []))
        if unsupported > args.fail_on_unsupported_threshold:
            print(
                "ERROR: Unsupported artifact threshold exceeded "
                f"({unsupported} > {args.fail_on_unsupported_threshold}).",
                file=sys.stderr,
            )
            return 2

    _write_json(out, aibom)
    persist_run(target, aibom)

    if args.audit_mode:
        spdx_out = out.with_name("SPDX.json")
        _write_json(spdx_out, export_spdx(aibom))
        if args.bundle_out:
            baseline = target / ".aibom" / "baseline.json"
            create_bundle(
                out,
                Path(args.bundle_out).resolve(),
                baseline if baseline.exists() else None,
                COMPLIANCE_STARTER,
            )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    src = load_json(Path(args.input))
    try:
        validate_aibom(src)
    except AIBOMValidationException as exc:
        print(f"ERROR: Schema validation failed at {exc.pointer}: {exc.message}", file=sys.stderr)
        return 2
    print("OK: AIBOM validates against schema")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    src = load_json(Path(args.input))
    if args.format == "spdx-json":
        data = export_spdx(src)
    else:
        data = export_cyclonedx(src)
    _write_json(Path(args.output), data)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    old, new = load_json(Path(args.old)), load_json(Path(args.new))
    d = diff_aibom(old, new)
    if args.output:
        _write_json(Path(args.output), d)
    print(json.dumps(d, indent=2, sort_keys=True))
    failures = gate_failures(d, set(filter(None, (args.fail_on or "").split(","))))
    if failures:
        print(f"Drift gates failed: {', '.join(sorted(set(failures)))}", file=sys.stderr)
        return 2
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    baseline = Path(args.baseline) if args.baseline else None
    bundle_path = create_bundle(Path(args.input), Path(args.out), baseline, COMPLIANCE_STARTER)
    if args.sign:
        if not args.signing_key or not args.signing_cert:
            print("ERROR: --sign requires --signing-key and --signing-cert", file=sys.stderr)
            return 2
        sign_bundle(
            bundle_path,
            Path(args.signing_key),
            Path(args.signing_cert),
            Path(args.signature_out) if args.signature_out else None,
            Path(args.provenance_out) if args.provenance_out else None,
        )
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle)
    cert = Path(args.signing_cert)

    if args.verify:
        if not args.signature:
            print("ERROR: attest --verify requires --signature", file=sys.stderr)
            return 2
        trusted_roots = [Path(root) for root in (args.trusted_root or [])]
        verify_bundle_signature(
            bundle,
            Path(args.signature),
            cert,
            Path(args.provenance) if args.provenance else None,
            ca_bundle=Path(args.ca_bundle) if args.ca_bundle else None,
            trusted_roots=trusted_roots,
            revocation_policy=args.revocation_policy,
            crl_file=Path(args.crl_file) if args.crl_file else None,
            allowlist_policy=_parse_allowlist(args),
        )
        return 0

    if not args.signing_key:
        print("ERROR: attest signing requires --signing-key", file=sys.stderr)
        return 2

    sign_bundle(
        bundle,
        Path(args.signing_key),
        cert,
        Path(args.signature) if args.signature else None,
        Path(args.provenance) if args.provenance else None,
    )
    return 0


def cmd_risk(args: argparse.Namespace) -> int:
    src = load_json(Path(args.input))
    risk_policy_path = Path(args.risk_policy).resolve() if args.risk_policy else None

    if args.risk_policy:
        findings, risk_policy = generate_risk_findings(src, policy_path=risk_policy_path)
    else:
        findings = src.get("risk_findings", [])
        risk_policy = src.get("risk_policy", {})

    print(
        json.dumps(
            {"count": len(findings), "findings": findings, "risk_policy": risk_policy},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aibom", description="Living AIBOM generator")
    parser.add_argument("--version", action="version", version=f"aibom {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate")
    gen.add_argument("target", nargs="?", default=".")
    gen.add_argument("-o", "--output", default="AI_BOM.json")
    gen.add_argument("--include-prompts", action="store_true")
    gen.add_argument(
        "--acknowledge-prompt-exposure-risk",
        action="store_true",
        help="Required acknowledgement for --include-prompts high-risk data exposure.",
    )
    gen.add_argument("--include-runtime-manifests", action="store_true")
    gen.add_argument(
        "--redaction-policy",
        choices=["strict", "default", "off"],
        default="strict",
        help="Evidence redaction policy for scan findings (SOC default: strict).",
    )
    gen.add_argument("--audit-mode", action="store_true")
    gen.add_argument("--risk-policy", help="Optional JSON/YAML risk rules policy file.")
    gen.add_argument("--bundle-out")
    gen.add_argument(
        "--fail-on-unsupported-threshold",
        type=int,
        help="Fail generation if unsupported artifact count is greater than this threshold.",
    )
    gen.set_defaults(func=cmd_generate)

    v = sub.add_parser("validate")
    v.add_argument("input")
    v.set_defaults(func=cmd_validate)

    ex = sub.add_parser("export")
    ex.add_argument("--input", required=True)
    ex.add_argument("--format", choices=["spdx-json", "cyclonedx-json"], default="spdx-json")
    ex.add_argument("-o", "--output", required=True)
    ex.set_defaults(func=cmd_export)

    d = sub.add_parser("diff")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--output")
    d.add_argument("--fail-on")
    d.set_defaults(func=cmd_diff)

    b = sub.add_parser("bundle")
    b.add_argument("--input", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--baseline")
    b.add_argument("--sign", action="store_true")
    b.add_argument("--signing-key")
    b.add_argument("--signing-cert")
    b.add_argument("--signature-out")
    b.add_argument("--provenance-out")
    b.set_defaults(func=cmd_bundle)

    a = sub.add_parser("attest")
    a.add_argument("--bundle", required=True)
    a.add_argument("--signing-cert", required=True)
    a.add_argument("--signing-key")
    a.add_argument("--signature")
    a.add_argument("--provenance")
    a.add_argument("--verify", action="store_true")
    a.add_argument("--ca-bundle")
    a.add_argument("--trusted-root", action="append")
    a.add_argument("--revocation-policy", choices=["none", "crl", "ocsp"], default="none")
    a.add_argument("--crl-file")
    a.add_argument("--allow-subject", action="append")
    a.add_argument("--allow-san-dns", action="append")
    a.add_argument("--allow-fingerprint", action="append")
    a.set_defaults(func=cmd_attest)

    r = sub.add_parser("risk")
    r.add_argument("--input", required=True)
    r.add_argument("--risk-policy", help="Optional JSON/YAML risk rules policy file.")
    r.set_defaults(func=cmd_risk)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except AIBOMValidationException as exc:
        print(f"ERROR: Schema validation failed at {exc.pointer}: {exc.message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
