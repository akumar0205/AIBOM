# For Auditors

1. Verify `AIBOM.json` matches schema `aibom/schema/aibom_v1.json`.
2. Recompute SHA256 hashes for each file in evidence zip and compare to `MANIFEST.json`.
3. Confirm `ENVIRONMENT.json` and `metadata.git_sha` align with CI run.
4. Review `DIFF.json` for inventory drift and gate failures.
