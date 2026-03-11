# For Auditors

1. Verify `AIBOM.json` matches schema `aibom/schema/aibom_v1.json`.
2. Recompute SHA256 hashes for each file in evidence zip and compare to `MANIFEST.json`.
3. Confirm `ENVIRONMENT.json` and `metadata.git_sha` align with CI run.
4. Review `DIFF.json` for inventory drift and gate failures.
5. Validate detached signature and provenance chain:
   - Verify detached signature:
     - `openssl x509 -in signing.crt -pubkey -noout > signing.pub`
     - `openssl dgst -sha256 -verify signing.pub -signature evidence.zip.sig evidence.zip`
   - Verify provenance metadata hashes:
     - `python -m aibom.cli attest --bundle evidence.zip --signature evidence.zip.sig --provenance provenance.json --signing-cert signing.crt --verify`
   - Confirm provenance certificate fingerprint matches approved signer policy.
