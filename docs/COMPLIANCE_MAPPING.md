# Compliance Mapping (Starter, Not Legal Advice)

## EU AI Act (starter)
- Technical documentation obligations -> `AIBOM.json` inventory sections.
- Change tracking -> `DIFF.json`.
- Traceability/integrity -> `MANIFEST.json`, `metadata.artifact_sha256`.

## NIST AI RMF (starter)
- Govern -> documented controls and CI policy.
- Map -> inventory (`models`, `datasets`, `tools`, `frameworks`).
- Measure -> `risk_findings` heuristic overlay.
- Manage -> drift gates and release evidence bundle.

## Provenance and Runtime Context Mapping
- Provider endpoint and region context (`models[*].provenance.provider_endpoint`, `.region`, `runtime_context.*`) support jurisdictional and third-party service traceability expectations.
- Registry/repository URI and immutable version/digest (`registry_uri`, `immutable_version`) support reproducibility, supply-chain integrity, and model version accountability.
- Environment/stage tagging (`environment`) supports segregation-of-duties and SDLC control evidence across dev/staging/prod lanes.
- Explicit `"unknown"` markers preserve schema-valid output while signaling audit evidence gaps for follow-up controls.

