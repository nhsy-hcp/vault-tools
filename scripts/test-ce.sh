#!/bin/bash
# Run the CE smoke tests (tests/test_ce.py) against a throwaway Community `vault server -dev`
# from compose.ce.yaml. Community edition: no namespaces, Sentinel, licence, Raft or
# snapshots. In memory, no licence needed; the container is removed on exit. Root is used
# only for setup and, after the first pass, to seal the server for the sealed-node pass.
# Extra arguments go to pytest (e.g. `task test:ce -- -k cluster`).
set -euo pipefail

PORT="${CE_PORT:-8330}"
ROOT_TOKEN="${CE_ROOT_TOKEN:-vault-tools-ce-root}"
CONTAINER_CLI="${CONTAINER_CLI:-docker}"
COMPOSE=("$CONTAINER_CLI" compose -f compose.ce.yaml)
export CE_PORT="$PORT" CE_ROOT_TOKEN="$ROOT_TOKEN"

if curl -s -o /dev/null "http://127.0.0.1:${PORT}/v1/sys/health"; then
  echo "error: port ${PORT} is already in use (set CE_PORT, or run task down:ce)" >&2
  exit 1
fi

TOKEN_FILE=".tmp/ce-audit-token"
trap 'rm -f "$TOKEN_FILE"; "${COMPOSE[@]}" down >/dev/null 2>&1 || true' EXIT
"${COMPOSE[@]}" up -d --wait vault-ce
if curl -s "http://127.0.0.1:${PORT}/v1/sys/health" | jq -r .version | grep -q "+ent"; then
  echo "error: ${VAULT_CE_IMAGE:-the CE image} is Enterprise; test:ce needs a Community image" >&2
  exit 1
fi

export VAULT_ADDR="http://127.0.0.1:${PORT}"
unset VAULT_CACERT VAULT_NAMESPACE VAULT_SKIP_VERIFY
(
  export VAULT_TOKEN="$ROOT_TOKEN"
  # Just enough configuration to trip a few rules (VT-MOUNT-006, VT-POL-001).
  vault secrets enable -path=kv1 -version=1 kv >/dev/null
  vault policy write admin - >/dev/null <<<'path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }'
  POLICY_READER=1 TOKEN_FILE="$TOKEN_FILE" scripts/audit-token.sh >/dev/null
)
audit_token="$(cat "$TOKEN_FILE")"

VAULT_TOKEN="$audit_token" VAULT_TOOLS_CE=1 uv run pytest -q -m ce tests/test_ce.py "$@"
# Then seal the throwaway server: cluster-audit must still report it, everything else must refuse.
VAULT_TOKEN="$ROOT_TOKEN" vault operator seal >/dev/null
VAULT_TOKEN="$audit_token" VAULT_TOOLS_CE=sealed uv run pytest -q -m ce tests/test_ce.py "$@"
