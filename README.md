# AIBOM (Living AI Bill of Materials)

Standards-first, CI-native AIBOM generator for Python/LangChain projects with audit evidence bundling, drift detection, and heuristic risk overlay.

## Install

```bash
pip install -e .
pip install -r requirements.txt
```

## CLI

```bash
aibom --version
aibom --help
```

Commands:
- `aibom generate`
- `aibom validate`
- `aibom export`
- `aibom diff`
- `aibom bundle`
- `aibom risk`

## Usage

### Generate AIBOM

```bash
aibom generate . -o AI_BOM.json
# generation fails fast if JSON Schema validation fails
```

Optional prompt-content collection (default is metadata-only):

```bash
aibom generate . -o AI_BOM.json --include-prompts
```

### Audit mode (end-to-end)

```bash
aibom generate . -o AI_BOM.json --audit-mode --bundle-out evidence.zip
```


Validate an existing AIBOM JSON against the bundled schema:

```bash
aibom validate AI_BOM.json
```

### Standards Output

```bash
aibom export --input AI_BOM.json --format spdx-json -o SPDX.json
aibom export --input AI_BOM.json --format cyclonedx-json -o CYCLONEDX.json
```

Internal → SPDX mapping (MVP):
- `models[].type` -> `packages[].name`
- `models[].model` -> `packages[].versionInfo`
- `tools[].name` -> `packages[].name`
- `datasets[].type` -> `packages[].name`

### Drift detection

```bash
aibom diff .aibom/baseline.json AI_BOM.json --fail-on new-model,new-tool,new-external-provider
```

### Evidence bundle

```bash
aibom bundle --input AI_BOM.json --out evidence.zip --baseline .aibom/baseline.json
```

Bundle contains:
- `AIBOM.json`
- `SPDX.json`
- `DIFF.json` (if baseline exists)
- `MANIFEST.json` (SHA256s)
- `ENVIRONMENT.json`
- `COMPLIANCE_MAPPING.md`

### Risk summary

```bash
aibom risk --input AI_BOM.json
```

## For Auditors

See [`docs/FOR_AUDITORS.md`](docs/FOR_AUDITORS.md) for verification procedure, manifest validation, and reproducibility notes.

## SOC Deployment Guide

See [`docs/SOC_DEPLOYMENT_GUIDE.md`](docs/SOC_DEPLOYMENT_GUIDE.md) for CI/CD integration and drift gate rollout.

## Compliance Mapping

See [`docs/COMPLIANCE_MAPPING.md`](docs/COMPLIANCE_MAPPING.md). This is a starter mapping only, not legal advice.

## LangChain demo

See [`examples/langchain_demo/README.md`](examples/langchain_demo/README.md).
