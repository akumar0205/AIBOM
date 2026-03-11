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
