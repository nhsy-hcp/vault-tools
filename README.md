# Vault Tools

[![Test Vault Tools](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml/badge.svg)](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

A read-only CLI for auditing HashiCorp Vault: namespaces, cluster health,
policies, identity and client usage, in one run or one area at a time. It only
sends GET and LIST requests, and the token's policies decide what it can see.

## Features

- **Full audit**: every check in one run, with a combined review report like the vault-ops skill's: executive summary, ranked findings and drafted operator commands
- **Namespace audit**: mounts, ACL and Sentinel policies across the whole namespace tree, including what each policy grants when the token can read it
- **Cluster audit**: seal, HA, replication, raft, audit devices, snapshots and node metrics; works on sealed and DR-secondary nodes too
- **Identity audit**: orphaned, disabled and directly-granted entities, duplicate aliases, entity sprawl
- **Activity and entity exports**: client usage exports with usage anti-pattern checks
- **Machine-readable findings**: a `findings.json` per audit, a `diff` subcommand and CI exit codes

## Quick start

Prerequisites: Python 3.12+, [uv](https://docs.astral.sh/uv/), the `vault` CLI,
and an admin able to write policies in the cluster.

```bash
git clone https://github.com/nhsy-hcp/vault-tools.git && cd vault-tools
uv sync
export VAULT_ADDR=https://vault.example.com:8200
vault policy write vault-tools-audit policies/audit-policy.hcl   # once, by an admin
export VAULT_TOKEN="$(vault token create -policy=vault-tools-audit -no-default-policy -orphan -ttl=1h -field=token)"
uv run vault-tools full-audit
# → outputs/{cluster-name}-{cluster-id-8}-full-audit-{YYYYMMDD}.md
```

Or keep the address and token in `.env` (copy [`.env.example`](.env.example))
and run `source .env` first. To also assess what each ACL and Sentinel policy
grants, attach the optional add-on policies: see
[Audit token and policies](docs/token-and-policies.md).

## Subcommands

Run with `uv run vault-tools <subcommand>` (or `python main.py`, or
`task run -- <subcommand>`); `--help` on any of them lists every option.

| Subcommand | What it does | Docs |
| --- | --- | --- |
| `full-audit` | Every audit and export, plus a combined report | [Full audit](docs/full-audit.md) |
| `namespace-audit` | Mounts, ACL and Sentinel policies in every namespace, plus cluster health | [Namespace audit](docs/namespace-audit.md) |
| `cluster-audit` | Cluster health only; also works on sealed and DR-secondary nodes | [Cluster audit](docs/cluster-audit.md) |
| `identity-audit` | Identity entities and aliases in every namespace | [Identity audit](docs/identity-audit.md) |
| `activity-export` | Activity log export plus client-usage checks | [Exports](docs/exports.md) |
| `entity-export` | Client entity export | [Exports](docs/exports.md) |
| `diff` | Compare two `findings.json` files; no Vault connection needed | [Findings and CI](docs/findings-and-ci.md) |
| `all` | Legacy: namespace-audit and both exports | [Exports](docs/exports.md#all-legacy) |

## Documentation

| Topic | |
| --- | --- |
| [Audit token and policies](docs/token-and-policies.md) | Creating a read-only token, the add-on policies, what each rule grants, `sudo` |
| [Full audit](docs/full-audit.md) | What the combined report contains and how to run it |
| [Namespace audit](docs/namespace-audit.md) | Output files, report sections, lease and Sentinel checks |
| [Cluster audit](docs/cluster-audit.md) | Health, replication, raft, audit device and snapshot checks |
| [Identity audit](docs/identity-audit.md) | Entity checks and how entity names are kept private |
| [Exports](docs/exports.md) | Activity and entity exports, client-usage checks |
| [Findings, diffs and CI](docs/findings-and-ci.md) | `findings.json`, `diff` and exit codes |
| [Configuration](docs/configuration.md) | Environment variables, flags and output file names |
| [Development](docs/development.md) | Pre-commit, tests, CI, architecture and contributing |

## License

This project is intended for defensive security purposes only. Use responsibly and in accordance with your organization's security policies.

## Support

For issues, questions, or contributions, please use the project's issue tracker.
