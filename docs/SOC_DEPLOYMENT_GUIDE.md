# SOC Deployment Guide

- Run `aibom generate --audit-mode --bundle-out evidence.zip` on each PR.
- Store `evidence.zip` as immutable build artifact.
- Maintain `.aibom/baseline.json` on protected branch.
- Enforce drift gates: `new-model,new-tool,new-external-provider`.
