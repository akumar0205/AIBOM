# AIBOM (Living AI Bill of Materials)

Standards-first, CI-native AIBOM generator for Python/LangChain/JS-TS/Java/Go/.NET projects with SPDX/CycloneDX/SARIF/VEX exports, drift gates, and attestation workflows.

## Install

```bash
pip install -e .
pip install -r requirements.txt
```

## CLI quickstart

```bash
aibom generate . -o AI_BOM.json
aibom summarize --input AI_BOM.json
```

## ai-bom-like compatibility profile

AIBOM keeps the canonical `AI_BOM.json` schema stable by default. For ai-bom-style ergonomics, use `--profile ai-bom-like`.

```bash
aibom generate . -o AI_BOM.json --profile ai-bom-like
# writes AI_BOM.json + AI_BOM_ai_profile.json and prints a concise terminal summary
```

This profile adds a companion presentation JSON with:
- executive summary counts
- grouped AI assets
- risk highlights
- provenance/compliance rollup
- detector coverage stats

## GitHub scanner quickstart

```bash
aibom scan-github \
  --repo openai/openai-quickstart-python \
  --output-dir out \
  --profile ai-bom-like
```

Multi-repo scan:

```bash
aibom scan-github \
  --repos-file repos.txt \
  --output-dir out \
  --max-repos 20 \
  --timeout-sec 240 \
  --fail-on new-model,new-tool,new-external-provider \
  --max-high-risk 0 \
  --max-unsupported 0
```

Output layout:
- `out/<owner__repo>/AI_BOM.json`
- `out/<owner__repo>/AI_BOM_ai_profile.json` (when `--profile ai-bom-like`)
- `out/SUMMARY.md`
- `out/summary.json`

## Core commands

- `aibom generate`
- `aibom scan-github`
- `aibom summarize`
- `aibom validate`
- `aibom export`
- `aibom diff`
- `aibom bundle`
- `aibom attest`
- `aibom risk`

## SOC-grade assurance hardening

Evidence-graded, fail-closed defaults for auditor-facing use:

- **Fail-closed attestation**: `attest --verify` requires `--ca-bundle` or
  `--trusted-root`; OCSP revocation without a responder integration errors
  instead of silently skipping.
- **Evidence-graded provenance**: missing provenance is `null` with
  `{status: observed|inferred|missing, method}` evidence — never `"unknown"`
  placeholders (rejected by the schema).
- **Semantic detectors**: Python/JS-TS resolve aliases, factory wrappers, and
  config/env dataflow into model constructors; dynamic imports are flagged
  `suspected_usage`. Every model/finding carries `evidence_class`
  (`observed_call`/`inferred_dependency`/`suspected_usage`) and
  `detection_method`, with confidence calibrated to evidence class.
- **10-rule control pack**: `third-party-provider`, `exfil-surface`,
  `prompt-injection-surface`, `secret-exposure`, `internet-egress`,
  `retrieval-augmentation`, `tool-execution`, `prompt-logging`,
  `model-version-drift`, `unsupported-provider-use`. Findings carry
  `finding_kind`, `control_objective`, and `remediation`.
- **Reproducible evidence bundles**: `COLLECTION.json` records tool version,
  CLI args, detector versions, git SHA plus dirty state, lockfile hashes,
  scan statistics, and classified manifest entries.
- **Reproducible GitHub scans**: `--commit` pinning, per-record
  `repo_origin`/`resolved_commit`/`branch`/`scanned_at`,
  `--allow-tokenized-clone` opt-in, and `--local-mirrors-dir` mode.
- **Hardened schema**: stable `$id`, `date-time`/enum/format constraints, and
  `additionalProperties: false` on core entities.
- **Adversarial coverage**: `tests/fixtures/adversarial/` plus a recall-gated
  benchmark (`tests/fixtures/benchmark/cases.json`), and export conformance
  tests for SPDX/CycloneDX/SARIF/VEX shapes with namespaced `aibom:`
  extensions.

## Compatibility and migration notes

- `generate`, `validate`, `export`, `diff`, `bundle`, `attest`, and `risk` remain functional and backward compatible.
- New `scan-github` and `summarize` commands are additive.
- ai-bom-like output is opt-in (`--profile ai-bom-like`) to avoid schema-breaking changes to canonical AIBOM consumers.
- `scan-github` returns nonzero when any repo scan errors or configured gates fail, while still producing aggregate summary files for partial failures.

## Documentation

- [GitHub scanner guide](docs/GITHUB_SCANNER_GUIDE.md)
- [For auditors](docs/FOR_AUDITORS.md)
- [SOC deployment guide](docs/SOC_DEPLOYMENT_GUIDE.md)
- [Compliance mapping](docs/COMPLIANCE_MAPPING.md)
- [Risk policy format](docs/RISK_POLICY_FORMAT.md)

## Examples

- [`examples/github_repo_samples/`](examples/github_repo_samples/)
- [`examples/langchain_demo/`](examples/langchain_demo/)
