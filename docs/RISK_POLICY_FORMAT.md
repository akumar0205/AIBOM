# Risk Policy Configuration Format

AIBOM supports organization-defined risk rule overrides via optional policy files.

## Supported formats

- JSON (`.json`)
- YAML (`.yaml`, `.yml`) when `pyyaml` is installed

## Schema

```json
{
  "policy_id": "org-risk-rules",
  "version": "2026.03",
  "rule_overrides": {
    "third-party-provider": {
      "rule_id": "ORG-TP-01",
      "severity": "high",
      "threshold": 1,
      "allowlist": [
        {
          "entity_type": "model",
          "name": "ChatOpenAI",
          "source_file": "app.py",
          "reason": "approved-external-provider"
        }
      ]
    }
  }
}
```

## Fields

- `policy_id`: Human-readable identifier for the rule set.
- `version`: Rule set version.
- `rule_overrides`: Per-rule override map keyed by built-in rule IDs:
  - `third-party-provider`
  - `exfil-surface`
  - `prompt-injection-surface`
- `rule_id`: Organization-defined rule ID emitted into findings.
- `severity`: Severity override for matching findings.
- `threshold`: Minimum post-allowlist matches required to emit findings.
- `allowlist`: Optional exception list to suppress specific entity matches.

## CLI usage

```bash
aibom generate . -o AI_BOM.json --risk-policy risk-policy.json
aibom risk --input AI_BOM.json --risk-policy risk-policy.json
```
