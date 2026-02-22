from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aibom import __version__
from aibom.analyzer import generate_aibom
from aibom.bundle import create_bundle
from aibom.diffing import diff_aibom, gate_failures
from aibom.exporters import export_cyclonedx, export_spdx
from aibom.storage import load_json, persist_run
from aibom.validation import AIBOMValidationError, validate_aibom


COMPLIANCE_STARTER = """# Starter Compliance Mapping\n\nThis mapping is a starter reference only and not legal advice.\n"""


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def cmd_generate(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    out = Path(args.output).resolve()
    aibom = generate_aibom(target, include_prompts=args.include_prompts)
    validate_aibom(aibom)
    _write_json(out, aibom)
    persist_run(target, aibom)

    if args.audit_mode:
        spdx_out = out.with_name("SPDX.json")
        _write_json(spdx_out, export_spdx(aibom))
        if args.bundle_out:
            baseline = target / ".aibom" / "baseline.json"
            create_bundle(out, Path(args.bundle_out).resolve(), baseline if baseline.exists() else None, COMPLIANCE_STARTER)
    return 0




def cmd_validate(args: argparse.Namespace) -> int:
    src = load_json(Path(args.input))
    validate_aibom(src)
    print(f"Validation passed: {args.input}")
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
    create_bundle(Path(args.input), Path(args.out), baseline, COMPLIANCE_STARTER)
    return 0


def cmd_risk(args: argparse.Namespace) -> int:
    src = load_json(Path(args.input))
    findings = src.get("risk_findings", [])
    print(json.dumps({"count": len(findings), "findings": findings}, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aibom", description="Living AIBOM generator")
    parser.add_argument("--version", action="version", version=f"aibom {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate")
    gen.add_argument("target", nargs="?", default=".")
    gen.add_argument("-o", "--output", default="AI_BOM.json")
    gen.add_argument("--include-prompts", action="store_true")
    gen.add_argument("--audit-mode", action="store_true")
    gen.add_argument("--bundle-out")
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
    b.set_defaults(func=cmd_bundle)

    r = sub.add_parser("risk")
    r.add_argument("--input", required=True)
    r.set_defaults(func=cmd_risk)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except AIBOMValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
