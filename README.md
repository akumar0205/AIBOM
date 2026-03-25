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

## Examples

- [`examples/github_repo_samples/`](examples/github_repo_samples/)
- [`examples/langchain_demo/`](examples/langchain_demo/)
