#!/bin/bash
# Enable DR replication: vault-primary -> vault-dr (idempotent). Both nodes must be up.
set -euo pipefail

PRIMARY_NAME="vault-primary"
DR_NAME="vault-dr"
VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
PRIMARY_ADDR="https://${VAULT_HOST_IP}:${VAULT_HOST_PORT:-8310}"
DR_ADDR="https://${VAULT_HOST_IP}:${VAULT_DR_HOST_PORT:-8320}"
ROOT_DIR="$(pwd)/.tmp/vault"
export VAULT_CACERT="${ROOT_DIR}/tls/vault-ca.pem"
unset VAULT_SKIP_VERIFY VAULT_NAMESPACE

dr_status() { curl -s --cacert "$VAULT_CACERT" "$1/v1/sys/replication/dr/status" | jq -c '.data // .'; }

primary_mode="$(dr_status "$PRIMARY_ADDR" | jq -r .mode)"
if [[ "$primary_mode" != "primary" ]]; then
  echo "Enabling DR primary on ${PRIMARY_NAME}"
  VAULT_ADDR="$PRIMARY_ADDR" VAULT_TOKEN=root vault write -f sys/replication/dr/primary/enable \
    primary_cluster_addr="https://${PRIMARY_NAME}:8201" >/dev/null
  sleep 3
fi

dr_mode="$(dr_status "$DR_ADDR" | jq -r .mode)"
if [[ "$dr_mode" == "secondary" ]]; then
  echo "${DR_NAME} is already a DR secondary"
else
  echo "Generating secondary activation token (id ${DR_NAME})"
  # Revoke a stale token for this id from an earlier attempt; ignore if none.
  VAULT_ADDR="$PRIMARY_ADDR" VAULT_TOKEN=root vault write sys/replication/dr/primary/revoke-secondary id="$DR_NAME" >/dev/null 2>&1 || true
  activation="$(VAULT_ADDR="$PRIMARY_ADDR" VAULT_TOKEN=root vault write -format=json \
    sys/replication/dr/primary/secondary-token id="$DR_NAME" ttl=10m | jq -r .wrap_info.token)"
  echo "Enabling DR secondary on ${DR_NAME} (its storage is replaced by the primary's)"
  # The secondary reaches the primary by container name; the shared CA is mounted at /vault/tls.
  VAULT_ADDR="$DR_ADDR" VAULT_TOKEN=root vault write sys/replication/dr/secondary/enable \
    token="$activation" primary_api_addr="https://${PRIMARY_NAME}:8200" ca_file=/vault/tls/vault-ca.pem >/dev/null
fi

echo -n "Waiting for ${DR_NAME} to stream WALs"
for _ in $(seq 1 60); do
  state="$(dr_status "$DR_ADDR" | jq -r .state)"
  if [[ "$state" == "stream-wals" ]]; then
    echo " ok"
    break
  fi
  echo -n "."
  sleep 2
done

echo "primary:   $(dr_status "$PRIMARY_ADDR" | jq -c '{mode, state, known_secondaries, connection: [.secondaries[]?.connection_status]}')"
echo "secondary: $(dr_status "$DR_ADDR" | jq -c '{mode, state, connection_state, last_remote_wal}')"
[[ "$state" == "stream-wals" ]] || { echo "DR secondary did not reach stream-wals (state=${state})" >&2; exit 1; }
