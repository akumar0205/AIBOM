# AIBOM - AI Bill of Materials Generator

## Project Overview

AIBOM is a standards-first, CI-native AI Bill of Materials (AIBOM) generator for Python/LangChain projects. It performs static analysis to detect AI/ML components (models, frameworks, tools, datasets, prompts) and produces structured inventory documents with audit evidence bundling, drift detection, and heuristic risk overlays aligned with OWASP LLM Top 10.

## Technology Stack

- **Language**: Python 3.9+
- **Build System**: setuptools (via `pyproject.toml`)
- **Core Dependencies**: jsonschema 4.23.0
- **Development Tools**:
  - Linting: ruff 0.8.4
  - Formatting: black 24.10.0 (line-length: 100)
  - Testing: pytest 8.3.4
  - Security: pip-audit 2.7.3, pip-licenses 4.4.0
- **Dependency Management**: pip-tools with hash-locked `requirements.lock`
- **Container**: Docker (python:3.12.8-alpine3.20)
- **Orchestration**: Kubernetes Jobs/CronJobs

## Project Structure

```
├── aibom/                    # Main package source code
│   ├── __init__.py           # Package version
│   ├── cli.py                # CLI entry point and command handlers
│   ├── analyzer.py           # Multi-detector static analysis engine
│   ├── validation.py         # JSON Schema validation
│   ├── exporters.py          # SPDX/CycloneDX format export
│   ├── bundle.py             # Evidence bundle creation and signing
│   ├── diffing.py            # Drift detection between AIBOM versions
│   ├── storage.py            # Persistence utilities
│   ├── utils.py              # Utility functions with security validations
│   ├── risk/                 # Risk analysis module
│   │   ├── __init__.py
│   │   └── heuristics.py     # OWASP LLM-aligned risk heuristics
│   └── schema/
│       └── aibom_v1.json     # JSON Schema for AIBOM validation
├── tests/                    # Test suite
│   ├── test_cli.py           # Comprehensive CLI and integration tests
│   └── fixtures/             # Test fixtures
│       ├── sample_project/   # Representative AI project for testing
│       ├── golden_aibom.json # Expected output for regression tests
│       ├── valid_aibom.json  # Valid AIBOM fixture
│       └── validation/       # Additional validation test fixtures
├── deploy/                   # Deployment assets
│   ├── Dockerfile            # Production container image
│   └── k8s/
│       └── aibom-generate.yaml  # Kubernetes Job/CronJob manifests
├── scripts/
│   └── check_license_policy.py  # License compliance checker
├── docs/                     # Documentation
│   ├── FOR_AUDITORS.md       # Auditor verification procedures
│   ├── SOC_DEPLOYMENT_GUIDE.md  # SOC compliance deployment guide
│   └── COMPLIANCE_MAPPING.md    # Regulatory compliance mappings
├── examples/                 # Usage examples
│   ├── langchain_demo/       # LangChain integration demo
│   └── github_repo_samples/  # Sample scans of public repos
└── .github/workflows/        # CI/CD workflows
    ├── ci.yml                # Main CI pipeline
    ├── security-ci.yml       # Security-focused CI with attestations
    └── aibom.yml             # AIBOM drift gate for PRs
```

## Build and Test Commands

### Installation
```bash
# Development install
pip install -e .
pip install -r requirements.txt

# Production install (hash-locked)
pip install --require-hashes -r requirements.lock
pip install --no-deps -e .
```

### Testing
```bash
# Run all tests
pytest -q

# Run with coverage (if configured)
pytest --cov=aibom
```

### Code Quality
```bash
# Linting
ruff check .

# Format check
black --check .

# Auto-format
black .

# Pre-commit hooks (if configured)
pre-commit run --all-files
```

### Security Audits
```bash
# Vulnerability scan
pip-audit -r requirements.lock --strict

# License compliance
pip-licenses --format=json --output-file licenses.json
python scripts/check_license_policy.py licenses.json
```

### Dependency Management
```bash
# Update lockfile after changing pyproject.toml or requirements-dev.in
pip-compile --generate-hashes --output-file=requirements.lock pyproject.toml requirements-dev.in
```

## Code Style Guidelines

- **Line Length**: 100 characters (enforced by black and ruff)
- **Import Style**: `from __future__ import annotations` at top of each file
- **Type Hints**: Used throughout; prefer modern syntax (PEP 585+)
- **String Formatting**: f-strings preferred
- **Error Handling**: Custom exceptions with descriptive messages
- **Security**: Path validation via `validate_safe_path()` before subprocess calls
- **Documentation**: Docstrings for public functions following Google style

## CLI Commands

The `aibom` CLI provides these subcommands:

### Generate
```bash
# Basic generation
aibom generate . -o AI_BOM.json

# Audit mode with evidence bundle
aibom generate . --audit-mode --bundle-out evidence.zip

# Include prompts (requires acknowledgment)
aibom generate . -o AI_BOM.json --include-prompts --acknowledge-prompt-exposure-risk

# Include runtime manifests
aibom generate . --include-runtime-manifests

# Redaction policy (strict/default/off)
aibom generate . --redaction-policy strict

# Fail on unsupported artifact threshold
aibom generate . --fail-on-unsupported-threshold 0
```

### Validate
```bash
aibom validate AI_BOM.json
```

### Export
```bash
# SPDX format
aibom export --input AI_BOM.json --format spdx-json -o SPDX.json

# CycloneDX format
aibom export --input AI_BOM.json --format cyclonedx-json -o CYCLONEDX.json
```

### Diff (Drift Detection)
```bash
# Compare two AIBOMs
aibom diff old.json new.json --output diff.json

# Fail on specific changes
aibom diff baseline.json new.json --fail-on new-model,new-tool,new-external-provider
```

### Bundle
```bash
# Create evidence bundle
aibom bundle --input AI_BOM.json --out evidence.zip --baseline baseline.json

# Create and sign
aibom bundle --input AI_BOM.json --out evidence.zip --sign --signing-key key.pem --signing-cert cert.pem
```

### Attest (Signing/Verification)
```bash
# Sign bundle
aibom attest --bundle evidence.zip --signing-key key.pem --signing-cert cert.pem

# Verify signature
aibom attest --bundle evidence.zip --signature evidence.zip.sig --signing-cert cert.pem --verify

# Full verification with CA and allowlist
aibom attest --bundle evidence.zip --signature evidence.zip.sig --provenance provenance.json \
  --signing-cert cert.pem --verify --ca-bundle ca.pem --allow-subject "CN=signer"
```

### Risk
```bash
aibom risk --input AI_BOM.json
```

## Architecture

### Detector System
The analyzer uses a pluggable detector architecture:

1. **PythonAstDetector**: Parses `.py` files using AST to detect:
   - Model classes (OpenAI, ChatOpenAI, ChatAnthropic, etc.)
   - Tool usage (initialize_agent, load_tools, etc.)
   - Vector stores (FAISS, Chroma, Pinecone)
   - Prompt templates
   - Framework imports

2. **NotebookDetector**: Extracts code cells from `.ipynb` files and applies Python AST detection

3. **ConfigFileDetector**: Scans YAML, JSON, and `.env` files for:
   - Model configuration keys
   - Provider settings
   - API credentials (with redaction)

4. **RuntimeManifestDetector**: Analyzes dependency files (requirements.txt, poetry.lock, etc.) and Dockerfiles when `--include-runtime-manifests` is enabled

5. **JSTSPackageManifestDetector**: Extracts dependencies from package.json, yarn.lock, pnpm-lock.yaml

### AIBOM Document Structure
```json
{
  "schema_version": "1.0",
  "metadata": {
    "generated_at": "ISO8601 timestamp",
    "git_sha": "commit hash",
    "artifact_sha256": "SHA256 of document"
  },
  "models": [...],
  "datasets": [...],
  "tools": [...],
  "frameworks": [...],
  "prompts": [...],
  "scan_findings": [...],
  "risk_findings": [...],
  "coverage_summary": {...},
  "unsupported_artifacts": [...],
  "source_types": [...]
}
```

### Security Features
- **Path Validation**: All paths passed to subprocess are validated via `validate_safe_path()` to prevent path traversal and shell injection
- **Evidence Redaction**: Configurable policies (strict/default/off) for masking sensitive values in config files
- **Credential Protection**: API keys always masked regardless of redaction policy
- **Prompt Exposure Control**: Requires explicit `--acknowledge-prompt-exposure-risk` flag to include prompt content

## Testing Strategy

- **Unit Tests**: `tests/test_cli.py` covers all major CLI commands and edge cases
- **Golden File Testing**: Compare generated AIBOM against `tests/fixtures/golden_aibom.json`
- **Schema Validation Tests**: Verify valid/invalid AIBOM documents
- **Integration Tests**: Full CLI subprocess invocations
- **Security Tests**: Signature creation and verification with ephemeral certificates
- **Fixtures**: `tests/fixtures/sample_project/` provides realistic test data

## CI/CD Workflows

### ci.yml
- Runs on all PRs and pushes
- Lockfile freshness guard
- Lint, format check, unit tests
- Vulnerability audit (pip-audit)
- License policy check
- Evidence bundle generation and signing

### security-ci.yml
- Runs on PRs and main branch pushes
- Comprehensive security pipeline
- Drift gate enforcement
- Artifact upload with 90-day retention
- All reports captured as artifacts

### aibom.yml
- Dedicated drift gate for PRs
- Fails on new-model, new-tool, new-external-provider

## Deployment

### Docker
```bash
docker build -f deploy/Dockerfile -t aibom-cli:latest .
docker run --rm -v $(pwd):/workspace aibom-cli:latest generate /workspace -o /out/aibom.json
```

### Kubernetes
- Job for one-time generation
- CronJob for scheduled scans
- Security-hardened pod spec (non-root, read-only root FS, dropped capabilities)
- ConfigMap/Secret for environment variables

## Security Considerations

1. **Dependency Security**:
   - Hash-locked requirements.lock
   - pip-audit vulnerability scanning
   - License policy enforcement (no GPL/LGPL/AGPL)

2. **Supply Chain**:
   - Evidence bundles with SHA256 manifests
   - Cryptographic signing with X.509 certificates
   - Provenance attestation with policy evaluation

3. **Data Protection**:
   - Config value redaction
   - Prompt template exposure controls
   - Path traversal prevention

4. **SOC Compliance**:
   - Three-tier data handling policies
   - Two-person approval for dependency changes
   - 30-day dependency refresh cadence
   - Emergency CVE response runbook

## Development Conventions

- Use `from __future__ import annotations` for forward compatibility
- Prefer dataclasses for structured data
- Use Protocol for interface definitions (Detector)
- Sort JSON output keys for reproducibility (`stable_json()`)
- All file paths resolved via `Path.resolve()`
- Ignored directories: `.venv`, `venv`, `__pycache__`, `.git`, `.aibom`

## Contributing

1. Create feature branch
2. Install deps: `pip install -e . && pip install -r requirements.txt`
3. Run checks: `ruff check . && black --check . && pytest -q`
4. Open PR with tests and docs updates

## License

MIT License (see LICENSE file)
