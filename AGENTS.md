# AIBOM - AI Bill of Materials Generator

## Project Overview

AIBOM is a standards-first, CI-native AI Bill of Materials (AIBOM) generator for Python/LangChain/JS-TS/Java/Go/.NET projects. It performs static analysis to detect AI/ML components (models, frameworks, tools, datasets, prompts) and produces structured inventory documents with audit evidence bundling, drift detection, and heuristic risk overlays aligned with OWASP LLM Top 10.

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
│   ├── confidence.py         # Confidence scoring for detector signals
│   ├── validation.py         # JSON Schema validation
│   ├── exporters.py          # SPDX/CycloneDX/SARIF/VEX format export
│   ├── bundle.py             # Evidence bundle creation and signing
│   ├── diffing.py            # Drift detection between AIBOM versions
│   ├── storage.py            # Persistence utilities (runs, snapshots, history)
│   ├── utils.py              # Utility functions with security validations
│   ├── github_scan.py        # GitHub repository scanning
│   ├── presentation.py       # AI BOM-like profile generation and summaries
│   ├── detectors/            # Detector plugins package
│   │   ├── __init__.py       # Detector exports
│   │   ├── protocol.py       # SourceDetector Protocol interface
│   │   ├── js_ts_ast.py      # JavaScript/TypeScript AST detector
│   │   ├── java_ast.py       # Java AST detector
│   │   ├── go_ast.py         # Go AST detector
│   │   └── dotnet_ast.py     # .NET/C# AST detector
│   ├── risk/                 # Risk analysis module
│   │   ├── __init__.py
│   │   ├── heuristics.py     # Risk evaluation engine with policy support
│   │   └── rules/            # Risk rule implementations
│   │       ├── __init__.py   # Rule pack loader
│   │       ├── base.py       # Base rule classes and types
│   │       ├── third_party_provider.py
│   │       ├── prompt_injection_surface.py
│   │       └── exfil_surface.py
│   └── schema/
│       └── aibom_v1.json     # JSON Schema for AIBOM validation
├── tests/                    # Test suite
│   ├── test_cli.py           # Comprehensive CLI and integration tests
│   ├── test_exporters.py     # SPDX/CycloneDX/SARIF/VEX export tests
│   ├── test_risk_rules.py    # Risk rule and policy tests
│   ├── test_github_scan.py   # GitHub scanning tests
│   ├── test_presentation.py  # Profile and summary tests
│   └── fixtures/             # Test fixtures
│       ├── sample_project/   # Representative AI project for testing
│       ├── runtime_project/  # Project with runtime manifests for testing
│       ├── golden_aibom.json # Expected output for regression tests
│       ├── valid_aibom.json  # Valid AIBOM fixture
│       ├── export_input_aibom.json
│       ├── golden_spdx_export.json
│       ├── golden_cyclonedx_export.json
│       ├── golden_sarif_export.json
│       ├── golden_vex_export.json
│       └── validation/       # Additional validation test fixtures
├── deploy/                   # Deployment assets
│   ├── Dockerfile            # Production container image
│   └── k8s/                  # Kubernetes manifests
│       └── aibom-generate.yaml
├── scripts/
│   └── check_license_policy.py  # License compliance checker
├── docs/                     # Documentation
│   ├── FOR_AUDITORS.md       # Auditor verification procedures
│   ├── SOC_DEPLOYMENT_GUIDE.md  # SOC compliance deployment guide
│   ├── COMPLIANCE_MAPPING.md    # Regulatory compliance mappings
│   ├── GITHUB_SCANNER_GUIDE.md  # GitHub scanning usage guide
│   └── RISK_POLICY_FORMAT.md    # Risk policy format documentation
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

# Custom risk policy
aibom generate . --risk-policy risk-policy.json

# AI BOM-like profile output
aibom generate . --profile ai-bom-like -o AI_BOM.json
```

### Scan GitHub
```bash
# Scan a single repository
aibom scan-github --repo openai/openai-quickstart-python --output-dir out

# Scan multiple repositories
aibom scan-github --repo owner/repo1 --repo owner/repo2 --output-dir out

# Scan from file
aibom scan-github --repos-file repos.txt --output-dir out

# With risk gates
aibom scan-github --repo owner/repo --max-high-risk 5 --max-unsupported 10

# With drift detection
aibom scan-github --repo owner/repo --baseline baseline.json --fail-on new-model,new-tool
```

### Periodic Scan
```bash
# Periodic scan with trend analysis
aibom periodic-scan . -o periodic_scan.json

# With history window and interval
aibom periodic-scan . --history-window 10 --interval daily
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

# SARIF format
aibom export --input AI_BOM.json --format sarif-json -o FINDINGS.sarif.json

# VEX format
aibom export --input AI_BOM.json --format vex-json -o ADVISORIES.vex.json
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

# With revocation checking
aibom attest --bundle evidence.zip --signature evidence.zip.sig --signing-cert cert.pem --verify \
  --revocation-policy crl --crl-file crl.pem

# With trusted roots and SAN DNS allowlist
aibom attest --bundle evidence.zip --signature evidence.zip.sig --signing-cert cert.pem --verify \
  --trusted-root root.pem --allow-san-dns "aibom.example"
```

### Risk
```bash
# Show risk findings
aibom risk --input AI_BOM.json

# With custom risk policy
aibom risk --input AI_BOM.json --risk-policy risk-policy.json
```

### Summarize
```bash
# Print text summary
aibom summarize --input AI_BOM.json

# JSON output
aibom summarize --input AI_BOM.json --json
```

## Architecture

### Detector System
The analyzer uses a pluggable detector architecture with a `SourceDetector` Protocol:

```python
class SourceDetector(Protocol):
    source_type: str
    def scan(self, context: ScanContext) -> ScanResult: ...
```

Available detectors:

1. **PythonAstDetector** (`analyzer.py`): Parses `.py` files using AST to detect:
   - Model classes (OpenAI, ChatOpenAI, ChatAnthropic, etc.)
   - Tool usage (initialize_agent, load_tools, etc.)
   - Vector stores (FAISS, Chroma, Pinecone)
   - Prompt templates
   - Framework imports

2. **NotebookDetector** (`analyzer.py`): Extracts code cells from `.ipynb` files and applies Python AST detection

3. **ConfigFileDetector** (`analyzer.py`): Scans YAML, JSON, and `.env` files for:
   - Model configuration keys
   - Provider settings
   - API credentials (with redaction)
   - Provenance and lineage metadata

4. **RuntimeManifestDetector** (`analyzer.py`): Analyzes dependency files (requirements.txt, poetry.lock, etc.) and Dockerfiles when `--include-runtime-manifests` is enabled

5. **JSTSPackageManifestDetector** (`analyzer.py`): Extracts dependencies from package.json, yarn.lock, pnpm-lock.yaml

6. **JSTSAstDetector** (`detectors/js_ts_ast.py`): Pattern-based detection for JavaScript/TypeScript files:
   - Model instantiations (new OpenAI(), new Anthropic(), etc.)
   - Tool patterns
   - Prompt templates
   - Framework imports

7. **JavaAstDetector** (`detectors/java_ast.py`): Pattern-based detection for Java files

8. **GoAstDetector** (`detectors/go_ast.py`): Pattern-based detection for Go files

9. **DotNetAstDetector** (`detectors/dotnet_ast.py`): Pattern-based detection for C#/.NET files

### Confidence Scoring
The `confidence.py` module provides signal-based confidence scoring:
- `import` signal: +1 point
- `constructor` signal: +1 point  
- `config_key` signal: +1 point
- Score >= 2: "high" confidence
- Score == 1: "medium" confidence
- Score == 0: "low" confidence

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
  "risk_policy": {
    "policy": {...},
    "applied_rules": [...],
    "suppressed": [...],
    "scoring": {"weights": {...}}
  },
  "coverage_summary": {
    "detectors": [...],
    "unsupported_total": 0
  },
  "unsupported_artifacts": [...],
  "source_types": [...],
  "runtime_context": {
    "provider_endpoint": "...",
    "registry_uri": "...",
    "immutable_version": "...",
    "environment": "...",
    "region": "...",
    "lineage": {
      "model_artifact_digest": "...",
      "deployment_id": "...",
      "service_account_identity": "...",
      "owning_system": "..."
    }
  }
}
```

### AI BOM-Like Profile
The `presentation.py` module provides an alternative profile format:

```json
{
  "profile": "ai-bom-like",
  "schema_version": "1.0",
  "metadata": {...},
  "executive_summary": {
    "models": 3,
    "tools": 2,
    "datasets": 1,
    "frameworks": 2,
    "prompts": 0,
    "risk_findings": 5,
    "high_or_critical_risks": 2,
    "unsupported_artifacts": 0
  },
  "ai_assets": {...},
  "risk_highlights": [...],
  "provenance_and_compliance": {...},
  "detector_coverage": {...}
}
```

### Risk Analysis System
The risk analysis engine (`risk/heuristics.py`) provides:

1. **Built-in Risk Rules**:
   - `third-party-provider`: Detects external model providers (OWASP LLM-07)
   - `exfil-surface`: Detects data exfiltration-capable tools (OWASP LLM-06)
   - `prompt-injection-surface`: Detects prompt template surfaces (OWASP LLM-01)

2. **Risk Scoring**:
   - Weighted scoring based on confidence, exposure, and provenance completeness
   - Configurable weights via policy
   - Severity bands: critical (0.8+), high (0.6+), medium (0.4+), low (<0.4)

3. **Policy Controls**:
   - Rule enable/disable
   - Severity overrides
   - Threshold-based suppression
   - Allowlist-based suppression with audit trail
   - Control mapping tags

### GitHub Scanning
The `github_scan.py` module provides bulk repository scanning:

```python
@dataclass
class RepoScanRecord:
    repo: str
    status: str  # "ok" or "error"
    output_json: str
    output_profile_json: str | None
    counts: dict[str, int]
    gate_verdict: str  # "pass" or "fail"
    gate_failures: list[str]
    error: str | None
```

Features:
- Clone repos to temp workspace
- Parallel-ready architecture
- Aggregate summary output (JSON + Markdown)
- Drift gate evaluation per repo
- Risk threshold enforcement

### Security Features
- **Path Validation**: All paths passed to subprocess are validated via `validate_safe_path()` to prevent path traversal and shell injection
- **Evidence Redaction**: Configurable policies (strict/default/off) for masking sensitive values in config files
- **Credential Protection**: API keys always masked regardless of redaction policy
- **Prompt Exposure Control**: Requires explicit `--acknowledge-prompt-exposure-risk` flag to include prompt content

### Storage and Persistence
The `storage.py` module provides:
- **Run Persistence**: Each scan is saved to `.aibom/runs/` with timestamp and git SHA
- **Latest Tracking**: `.aibom/latest.json` always points to the most recent scan
- **Periodic Snapshots**: History tracking with drift analysis for scheduled scans
- **History Index**: `.aibom/periodic/history.json` maintains rolling window of snapshots

## Testing Strategy

- **Unit Tests**: `tests/test_cli.py` covers all major CLI commands and edge cases
- **Export Tests**: `tests/test_exporters.py` validates SPDX/CycloneDX/SARIF/VEX output
- **Risk Rule Tests**: `tests/test_risk_rules.py` validates risk policy and rule evaluation
- **GitHub Scan Tests**: `tests/test_github_scan.py` validates repository scanning
- **Presentation Tests**: `tests/test_presentation.py` validates profile generation
- **Golden File Testing**: Compare generated AIBOM against `tests/fixtures/golden_aibom.json`
- **Schema Validation Tests**: Verify valid/invalid AIBOM documents
- **Integration Tests**: Full CLI subprocess invocations
- **Security Tests**: Signature creation and verification with ephemeral certificates
- **Fixtures**: `tests/fixtures/sample_project/` and `tests/fixtures/runtime_project/` provide realistic test data

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
   - Certificate chain verification
   - Signer allowlist enforcement (subject, SAN DNS, fingerprint)
   - Revocation checking (CRL/OCSP with hooks)
   - Validity window enforcement

3. **Data Protection**:
   - Config value redaction (strict/default/off policies)
   - Prompt template exposure controls
   - Path traversal prevention via `validate_safe_path()`
   - Shell metacharacter rejection
   - Symlink control

4. **SOC Compliance**:
   - Three-tier data handling policies
   - Two-person approval for dependency changes
   - 30-day dependency refresh cadence
   - Emergency CVE response runbook

## Development Conventions

- Use `from __future__ import annotations` for forward compatibility
- Prefer dataclasses for structured data
- Use Protocol for interface definitions (SourceDetector)
- Sort JSON output keys for reproducibility (`stable_json()`)
- All file paths resolved via `Path.resolve()`
- Ignored directories: `.venv`, `venv`, `__pycache__`, `.git`, `.aibom`

## Risk Policy Format

Custom risk policies can be provided as JSON or YAML:

```json
{
  "policy_id": "org-risk-rules",
  "version": "2026.03",
  "scoring": {
    "weights": {
      "confidence": 0.35,
      "exposure": 0.4,
      "provenance": 0.25
    }
  },
  "rule_overrides": {
    "third-party-provider": {
      "rule_id": "ORG-TP-01",
      "severity": "high",
      "threshold": 1,
      "enabled": true,
      "weights": {
        "confidence": 0.5,
        "exposure": 0.3,
        "provenance": 0.2
      },
      "allowlist": [
        {
          "entity_type": "model",
          "name": "ChatOpenAI",
          "source_file": "app.py",
          "reason": "approved-external-provider"
        }
      ],
      "control_mapping_tags": ["tier-1-vendor"]
    },
    "prompt-injection-surface": {
      "enabled": false
    }
  }
}
```

## Contributing

1. Create feature branch
2. Install deps: `pip install -e . && pip install -r requirements.txt`
3. Run checks: `ruff check . && black --check . && pytest -q`
4. Open PR with tests and docs updates

## License

MIT License (see LICENSE file)
