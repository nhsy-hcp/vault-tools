#!/bin/bash
#
# Seed (or remove) no-op Sentinel EGP/RGP policies for testing namespace-audit.
#
# Every policy written here passes unconditionally, so nothing is ever blocked
# -- the point is to give the audit's Sentinel collection, findings and report
# section something real to read. Between them the five policies cover every
# branch: one per enforcement level, a wildcard EGP path, an always-true rule,
# and a hard-mandatory control that must produce no finding.
#
# Only that one policy uses the literal `main = rule { true }`; the rest use a
# condition that cannot be false. Vault rejects a policy with no main rule at
# all ("every policy must have a main rule"), so a comments-only body is not a
# state a real cluster can reach.
#
# Requires Vault Enterprise with the Governance & Policy module. Anywhere else
# these endpoints 404 and the script says so rather than failing obscurely.
#
# Usage:
#   scripts/seed-sentinel-policies.sh [namespace ...]
#   scripts/seed-sentinel-policies.sh --delete [namespace ...]
#
# With no namespace argument the policies go into the root namespace. VAULT_ADDR
# and VAULT_TOKEN must already be set.

set -euo pipefail

POLICY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../examples/sentinel" && pwd)"

# name|kind|enforcement_level|paths|file
# paths is EGP-only and ignored for RGP.
POLICIES=(
  "vault-tools-noop-advisory|egp|advisory|secret/data/*|egp-noop-advisory.sentinel"
  "vault-tools-noop-wildcard|egp|hard-mandatory|*|egp-noop-wildcard.sentinel"
  "vault-tools-always-true|egp|soft-mandatory|sys/mounts|egp-always-true.sentinel"
  "vault-tools-noop-hard|rgp|hard-mandatory||rgp-noop-hard.sentinel"
  "vault-tools-noop-soft|rgp|soft-mandatory||rgp-noop-soft.sentinel"
)

DELETE=false
if [[ "${1:-}" == "--delete" ]]; then
  DELETE=true
  shift
fi

NAMESPACES=("$@")
if [[ ${#NAMESPACES[@]} -eq 0 ]]; then
  NAMESPACES=("")
fi

command -v vault >/dev/null 2>&1 || {
  echo "❌ vault binary not found. Install from https://developer.hashicorp.com/vault/downloads" >&2
  exit 1
}
: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"

# Probe once before writing anything: on Community the whole run is pointless,
# and one clear message beats five identical 404s.
#
# Vault exits non-zero for an empty list as well as for a missing endpoint, so
# the exit status alone proves nothing -- only the message separates "no
# Sentinel here" from "no policies yet", which is the same ambiguity the audit
# tool itself has to work around.
probe="$(vault list sys/policies/egp 2>&1 || true)"
if [[ "$probe" == *"unsupported path"* ]]; then
  echo "❌ Sentinel EGP/RGP is not available on this cluster." >&2
  echo "   It requires Vault Enterprise with the Governance & Policy module." >&2
  exit 1
fi

for namespace in "${NAMESPACES[@]}"; do
  export VAULT_NAMESPACE="$namespace"
  label="${namespace:-root}"

  for entry in "${POLICIES[@]}"; do
    IFS='|' read -r name kind level paths file <<<"$entry"

    if [[ "$DELETE" == true ]]; then
      echo "  - deleting ${kind}/${name} in ${label}"
      vault delete "sys/policies/${kind}/${name}" >/dev/null
      continue
    fi

    echo "  - writing ${kind}/${name} (${level}) in ${label}"
    if [[ "$kind" == "egp" ]]; then
      vault write "sys/policies/${kind}/${name}" \
        "policy=@${POLICY_DIR}/${file}" \
        "enforcement_level=${level}" \
        "paths=${paths}" >/dev/null
    else
      vault write "sys/policies/${kind}/${name}" \
        "policy=@${POLICY_DIR}/${file}" \
        "enforcement_level=${level}" >/dev/null
    fi
  done
done

unset VAULT_NAMESPACE

if [[ "$DELETE" == true ]]; then
  echo "✅ Removed ${#POLICIES[@]} Sentinel policies from ${#NAMESPACES[@]} namespace(s)"
else
  echo "✅ Seeded ${#POLICIES[@]} no-op Sentinel policies into ${#NAMESPACES[@]} namespace(s)"
  echo "   Run the audit and check the '## Sentinel policies' report section:"
  echo "     python main.py namespace-audit --output-dir .tmp/audit"
fi
