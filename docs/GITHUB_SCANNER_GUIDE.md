# GitHub Scanner Guide

## Overview

`aibom scan-github` clones one or many GitHub repositories into a temporary workspace, runs the normal AIBOM generation pipeline, and writes per-repository outputs plus aggregate summaries.

## Authentication

By default the scanner reads `GITHUB_TOKEN` from the environment. A set token
is **never** embedded into clone URLs unless you explicitly opt in with
`--allow-tokenized-clone` (fail-closed default avoids credential leakage into
logs or process tables).

```bash
export GITHUB_TOKEN=ghp_xxx
aibom scan-github --repo owner/name --output-dir out --allow-tokenized-clone
```

Use a custom env var with `--token-env`:

```bash
aibom scan-github --repo owner/name --token-env AIBOM_GH_TOKEN --output-dir out --allow-tokenized-clone
```

## Reproducible scans

Every scan record captures `repo_origin`, the exact `resolved_commit`,
`branch`, and `scanned_at` timestamp in `summary.json`.

```bash
# Pin every repo to the same commit SHA.
aibom scan-github --repo owner/name --commit abc123def456 --output-dir out

# Preferred mode: scan already-checked-out local mirrors (no clone, no network).
aibom scan-github --repo owner/name --local-mirrors-dir ./mirrors --output-dir out
```

## Rate limits and reliability

- Prefer authenticated requests for larger scans.
- Use `--max-repos` to cap scope.
- Use `--timeout-sec` to avoid hanging clones.
- Partial failures are aggregated: failed repositories do not stop subsequent scans.

## Drift/risk gates

```bash
aibom scan-github \
  --repos-file repos.txt \
  --output-dir out \
  --fail-on new-model,new-tool,new-external-provider \
  --max-high-risk 0 \
  --max-unsupported 0
```

A nonzero exit code is returned when any repository fails scan or fails a configured gate.

## Output files

- Per repo: `AI_BOM.json`
- Optional profile: `AI_BOM_ai_profile.json` (with `--profile ai-bom-like`)
- Aggregate machine output: `summary.json`
- Aggregate human output: `SUMMARY.md`

## CI example

See `.github/workflows/aibom.yml` for:
- pull request drift gate
- scheduled multi-repo scans
- artifact upload for scan outputs and summaries
