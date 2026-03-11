# SOC Deployment Guide

- Run `aibom generate --audit-mode --bundle-out evidence.zip` on each PR.
- Store `evidence.zip` as immutable build artifact.
- Maintain `.aibom/baseline.json` on protected branch.
- Enforce drift gates: `new-model,new-tool,new-external-provider`.

## Dependency governance for SOC controls

- **Update cadence:** refresh pinned dependencies every 30 days (or within 48 hours of a critical CVE announcement) by re-running:
  - `pip-compile --generate-hashes --output-file=requirements.lock pyproject.toml requirements-dev.in`
- **Two-person approval:** dependency lockfile changes require:
  1. One change author from Engineering.
  2. One approver from Security or Compliance.
- **Evidence retention:** include `requirements.lock` diff, vulnerability scan output, and license scan output in the PR artifacts.

## CI failure policy

The CI pipeline must fail the build when any of the following occur:

1. `pip install --require-hashes -r requirements.lock` fails (tampered or unhashed dependencies).
2. `pip-audit -r requirements.lock --strict` reports any unresolved vulnerability.
3. `pip-licenses` detects disallowed licenses (`GPL`, `LGPL`, `AGPL`) or any package outside the allowlist.
4. Standard quality/supply-chain checks (lint, tests, attestation signing/verification) fail.


## Emergency CVE response runbook

When a CVE affecting a direct or transitive dependency is rated **critical** (CVSS >= 9.0), execute this emergency process:

1. **Trigger window:** start remediation within 24 hours of advisory publication and complete lockfile refresh within 48 hours.
2. **Hotfix branch:** create a dedicated branch that changes only dependency inputs (`pyproject.toml`, `requirements-dev.in`) and `requirements.lock`.
3. **Regenerate lockfile with hashes:**
   - `pip-compile --generate-hashes --output-file=requirements.lock pyproject.toml requirements-dev.in`
4. **Validation gates:** run `pip install --require-hashes -r requirements.lock`, `pip-audit -r requirements.lock --strict`, unit tests, and license policy checks.
5. **Approvals and deployment:** require Security approval, merge with priority, and deploy at the next emergency window.
6. **Post-incident evidence:** attach CVE reference, lockfile diff, CI artifacts, and deployment timestamp to the change record.


## Data handling tiers for scan evidence

Use `aibom generate` redaction controls to match your SOC data handling policy:

- **Tier 1 (Strict, SOC default):** `--redaction-policy strict`
  - All config evidence values are masked+hashed in `scan_findings.evidence`.
  - Raw credentials and non-secret config values are never persisted in evidence output.
- **Tier 2 (Default):** `--redaction-policy default`
  - Credential-like values (API keys/tokens) are always masked+hashed.
  - Non-secret config values (for example `provider` or `model`) may appear in plain text for triage.
- **Tier 3 (Off):** `--redaction-policy off`
  - Credential-like values remain masked+hashed (hard safety floor).
  - Other config values are unredacted to maximize debugging detail.

### Prompt extraction risk controls

`--include-prompts` is high risk because prompt templates can include proprietary logic, PII, or secrets.

- You must explicitly pass `--acknowledge-prompt-exposure-risk` to enable prompt collection.
- The CLI emits a warning on stderr when prompt collection is enabled.
- Recommended SOC posture: do not enable prompt collection in shared CI artifacts unless required by an approved exception.
