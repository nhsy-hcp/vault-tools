#!/bin/bash
# Start one Vault Enterprise node (compose.yaml service: raft storage, TLS); init, unseal and
# create a token with id "root" on first start. Idempotent.
#   usage: scripts/vault-up.sh [vault-primary|vault-dr|vault-pr] [host-port]
set -euo pipefail

NAME="${1:-vault-primary}"
HOST_PORT="${2:-${VAULT_HOST_PORT:-8310}}"
PRIMARY_NAME="vault-primary"
CONTAINER_CLI="${CONTAINER_CLI:-docker}"
VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
ROOT_DIR="$(pwd)/.tmp/vault"
NODE_DIR="${ROOT_DIR}/${NAME}"
TLS_DIR="${ROOT_DIR}/tls"
: "${VAULT_IMAGE:?VAULT_IMAGE must be set in .env}"
: "${VAULT_LICENSE:?VAULT_LICENSE must be set in .env}"

export VAULT_ADDR="https://${VAULT_HOST_IP}:${HOST_PORT}"
export VAULT_CACERT="${TLS_DIR}/vault-ca.pem"
unset VAULT_SKIP_VERIFY VAULT_NAMESPACE

scripts/gen-tls.sh "$TLS_DIR"
mkdir -p "$NODE_DIR"  # init.json (unseal key, initial root token); Raft data is in a named volume

# The service's profile is enabled because it is named explicitly; --wait blocks until the
# API answers (compose.yaml healthcheck), whatever the seal/init state.
"$CONTAINER_CLI" compose up -d --wait "$NAME"
echo "${NAME}: running (${VAULT_IMAGE}) on ${VAULT_ADDR}"

health() {
  curl -s --cacert "$VAULT_CACERT" \
    "${VAULT_ADDR}/v1/sys/health?uninitcode=200&sealedcode=200&standbycode=200&drsecondarycode=200&perfstandbyok=true"
}

echo -n "${NAME}: waiting for API"
for _ in $(seq 1 30); do
  if health | jq -e '.initialized != null' >/dev/null 2>&1; then break; fi
  echo -n "."
  sleep 1
done
echo

if [[ "$(health | jq -r .initialized)" == "false" ]]; then
  echo "${NAME}: initialising (1 key share)"
  (umask 077 && vault operator init -key-shares=1 -key-threshold=1 -format=json >"${NODE_DIR}/init.json")
fi

if [[ "$(health | jq -r .sealed)" == "true" ]]; then
  # A DR or performance secondary takes over the primary's unseal keys once activated, so try both.
  for keyfile in "${NODE_DIR}/init.json" "${ROOT_DIR}/${PRIMARY_NAME}/init.json"; do
    [[ -s "$keyfile" ]] || continue
    vault operator unseal "$(jq -r '.unseal_keys_b64[0]' "$keyfile")" >/dev/null 2>&1 || true
    [[ "$(health | jq -r .sealed)" == "false" ]] && break
  done
fi

echo -n "${NAME}: waiting for active node"
for _ in $(seq 1 30); do
  state="$(health)"
  if jq -e '(.sealed | not) and ((.standby | not) or .replication_dr_mode == "secondary")' >/dev/null 2>&1 <<<"$state"; then
    break
  fi
  echo -n "."
  sleep 1
done
echo

dr_mode="$(health | jq -r .replication_dr_mode)"
pr_mode="$(health | jq -r .replication_performance_mode)"
if [[ "$pr_mode" == "secondary" ]] && ! VAULT_TOKEN=root vault token lookup >/dev/null 2>&1; then
  # Tokens don't replicate and activation wiped this node's own: pr-enable.sh restores `root`.
  echo "${NAME}: performance secondary without a 'root' token (run: task pr:enable)"
elif [[ "$dr_mode" != "secondary" ]]; then
  # Keep VAULT_TOKEN=root working like dev mode: create a root-policy token with id "root".
  if ! VAULT_TOKEN=root vault token lookup >/dev/null 2>&1; then
    VAULT_TOKEN="$(jq -r .root_token "${NODE_DIR}/init.json")" \
      vault token create -id=root -policy=root -orphan -display-name=dev-root >/dev/null 2>&1  # custom-id SHA1 warning is expected in dev
    echo "${NAME}: created token id 'root'"
  fi
fi

health | jq -c '{node: "'"${NAME}"'", version, sealed, standby, replication_dr_mode, replication_performance_mode, cluster_name}'
