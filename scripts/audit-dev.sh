#!/bin/bash
# Run vault-tools against the dev stack: full-audit on the primary with .tmp/audit-token,
# then cluster-audit on each secondary that is running (the DR node answers only
# unauthenticated reads; the performance secondary uses .tmp/audit-token-pr). Output goes
# to .tmp/audit/<node>. TLS is verified against the stack's own CA.
set -euo pipefail

VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
CA=".tmp/vault/tls/vault-ca.pem"
export VAULT_CACERT="$CA"
unset VAULT_NAMESPACE VAULT_SKIP_VERIFY

[[ -s .tmp/audit-token ]] || { echo "No audit token; run: task token:policies" >&2; exit 1; }

up() { curl -s -o /dev/null --cacert "$CA" "https://${VAULT_HOST_IP}:$1/v1/sys/health?drsecondarycode=200&perfstandbyok=true"; }

run() {
  local node="$1" port="$2" token_file="$3"
  shift 3
  echo "==> vault-tools $1 on ${node} (port ${port})"
  VAULT_ADDR="https://${VAULT_HOST_IP}:${port}" VAULT_TOKEN="$(cat "$token_file")" \
    uv run vault-tools "$@" --output-dir ".tmp/audit/${node}"
}

run primary "${VAULT_HOST_PORT:-8310}" .tmp/audit-token full-audit

dr_port="${VAULT_DR_HOST_PORT:-8320}"
if up "$dr_port"; then
  # Tokens do not reach a DR secondary; cluster-audit falls back to unauthenticated reads.
  run dr "$dr_port" .tmp/audit-token cluster-audit
else
  echo "==> DR secondary not running; skipped"
fi

pr_port="${VAULT_PR_HOST_PORT:-8340}"
if up "$pr_port" && [[ -s .tmp/audit-token-pr ]]; then
  run pr "$pr_port" .tmp/audit-token-pr cluster-audit
else
  echo "==> performance secondary not running or no .tmp/audit-token-pr (task token:pr); skipped"
fi
