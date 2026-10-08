# Findings, diffs and CI

Every audit writes a `*-findings-*.json` in the vault-ops skill's schema
([`schemas/findings.schema.json`](../schemas/findings.schema.json)). Each finding
has a stable fingerprint, a rule ID, a severity and structured evidence, and
the document records coverage: what was denied or errored.

```bash
# What changed between two runs (no Vault connection needed)
python main.py diff outputs/old-namespace-findings.json outputs/new-namespace-findings.json

# No arguments: the two newest *-full-findings-*.json for the newest file's cluster
python main.py diff

# Gate CI on the results
python main.py namespace-audit --fail-on medium --fail-on-gaps
```

| Exit code | Meaning |
| --- | --- |
| 0 | Completed |
| 1 | Fatal: connection, token or configuration error, or the audit failed |
| 2 | `--fail-on-gaps` and coverage was incomplete |
| 3 | `--fail-on <severity>` and a finding was at or above it (wins over 2) |

`--fail-on` and `--fail-on-gaps` work on every command that writes findings.
