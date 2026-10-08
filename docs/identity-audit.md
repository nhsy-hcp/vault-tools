# Identity audit

```bash
python main.py identity-audit
python main.py identity-audit --list   # also write names, metadata and aliases
```

Reads every identity entity in every namespace and checks for:

- `VT-ID-001`: entities with no aliases.
- `VT-ID-002`: policies attached directly to an entity.
- `VT-ID-003`: disabled entities.
- `VT-ID-004`: a namespace with at least 100 entities and more than three times
  its active entity clients. Only judged when the activity log records something.
- `VT-ID-005`: the same alias name on several entities.

Entity names, metadata and alias names can hold emails, usernames and AppRole
role_ids. The findings, the per-namespace CSV and the report therefore identify
entities by ID only. `--list` writes everything to a separate
`{cluster-name}-identity-entities-{YYYYMMDD}.json`; treat that file as
confidential.
