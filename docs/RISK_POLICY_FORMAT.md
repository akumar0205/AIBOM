# Risk Policy Configuration Format

AIBOM supports organization-defined risk rule overrides via optional policy files.

## Supported formats

- JSON (`.json`)
- YAML (`.yaml`, `.yml`) when `pyyaml` is installed

## Policy structure

```json
{
  "policy_id": "org-risk-rules",
  "version": "2026.03",
  "scoring": {
    "weights": {
      "confidence": 0.35,
      "exposure": 0.40,
      "provenance": 0.25
    }
  },
  "rule_overrides": {
    "third-party-provider": {
      "enabled": true,
      "rule_id": "ORG-TP-01",
      "severity": "high",
      "threshold": 1,
      "weights": {
        "confidence": 0.2,
        "exposure": 0.5,
        "provenance": 0.3
      },
      "control_mapping_tags": ["pci", "critical-vendor"],
      "allowlist": [
        {
          "entity_type": "model",
          "name": "ChatOpenAI",
          "source_file": "app.py",
          "reason": "approved-external-provider"
        }
      ]
    },
    "prompt-injection-surface": {
      "enabled": false
    }
  }
}
```

## Fields

- `policy_id`: Human-readable identifier for the rule set.
- `version`: Rule set version.
- `scoring.weights`: Global weighted-severity inputs.
  - `confidence`: detector confidence contribution.
  - `exposure`: runtime blast-radius/context contribution.
  - `provenance`: source/provenance completeness contribution.
- `rule_overrides`: Per-rule override map keyed by built-in rule IDs:
  - `third-party-provider`
  - `exfil-surface`
  - `prompt-injection-surface`
- `enabled`: Optional boolean to disable/enable a rule.
- `rule_id`: Organization-defined rule ID emitted into findings.
- `severity`: Optional fixed severity override. If omitted, AIBOM uses weighted severity bands.
- `threshold`: Minimum post-allowlist matches required to emit findings.
- `weights`: Optional rule-specific weighting override.
- `control_mapping_tags`: Optional tags added to findings for downstream governance mapping.
- `allowlist`: Optional exception list to suppress specific entity matches.

## Backward compatibility

Legacy policy files that only define `rule_overrides` with `rule_id`, `severity`, `threshold`, and
`allowlist` continue to work with no changes.

## CLI usage

```bash
aibom generate . -o AI_BOM.json --risk-policy risk-policy.json
aibom risk --input AI_BOM.json --risk-policy risk-policy.json
```
