# For Auditors

1. Verify `AIBOM.json` matches schema `aibom/schema/aibom_v1.json`.
2. Recompute SHA256 hashes for each file in evidence zip and compare to `MANIFEST.json`.
3. Confirm `ENVIRONMENT.json` and `metadata.git_sha` align with CI run.
4. Review `DIFF.json` for inventory drift and gate failures.
5. Review AIBOM detector coverage metadata:
   - `coverage_summary.detectors[*].artifacts_seen` vs `artifacts_scanned` indicates parsing/coverage success.
   - `coverage_summary.detectors[*].default_confidence` provides baseline confidence semantics per detector.
   - `unsupported_artifacts` lists files with no active detector support, and `coverage_summary.unsupported_total` summarizes count.
   - If CI policy enforces unsupported thresholds, confirm generation failed/passed according to configured limit.
6. Validate detached signature and provenance chain:
   - Verify detached signature:
     - `openssl x509 -in signing.crt -pubkey -noout > signing.pub`
     - `openssl dgst -sha256 -verify signing.pub -signature evidence.zip.sig evidence.zip`
   - Verify provenance metadata hashes + policy checks:
     - `python -m aibom.cli attest --bundle evidence.zip --signature evidence.zip.sig --provenance provenance.json --signing-cert signing.crt --verify --ca-bundle ca.pem --allow-fingerprint "SHA256 Fingerprint=..." --revocation-policy none`
   - If your policy requires CRL validation, use `--revocation-policy crl --crl-file issuer.crl`.
   - Confirm `provenance.json` contains `policy_evaluation.checks` with passed chain/validity/allowlist checks.

7. Review provenance metadata for model and runtime traceability:
   - Each `models[*].provenance` object SHOULD contain:
     - `provider_endpoint`: API endpoint/base URL used to resolve the model provider.
     - `registry_uri`: model registry/repository URI (e.g., OCI/HF/private registry), when known.
     - `immutable_version`: immutable model identifier (version pin, digest, or immutable image ref).
     - `environment`: deployment stage context (`dev`, `staging`, `prod`, etc.).
     - `region`: cloud/geo region context for model invocation or hosting.
   - `runtime_context` captures the same fields at document scope from runtime manifests and deployment metadata.
   - Values may be `"unknown"` when not observable from scanned artifacts; treat unknowns as evidence gaps requiring compensating controls or runtime attestation.
