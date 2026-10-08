#!/bin/bash
# Enable performance replication: vault-primary -> vault-pr (idempotent). Both nodes must be up.
# Activation replaces vault-pr's storage with the primary's (minus local mounts) and its
# unseal key with the primary's. Tokens don't replicate, so token `root` is restored on
# vault-pr with generate-root using the primary's unseal key.
set -euo pipefail

PRIMARY_NAME="vault-primary"
PR_NAME="vault-pr"
VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
PRIMARY_ADDR="https://${VAULT_HOST_IP}:${VAULT_HOST_PORT:-8310}"
PR_ADDR="https://${VAULT_HOST_IP}:${VAULT_PR_HOST_PORT:-8340}"
ROOT_DIR="$(pwd)/.tmp/vault"
export VAULT_CACERT="${ROOT_DIR}/tls/vault-ca.pem"
unset VAULT_SKIP_VERIFY VAULT_NAMESPACE

pr_status() { curl -s --cacert "$VAULT_CACERT" "$1/v1/sys/replication/performance/status" | jq -c '.data // .'; }

if [[ "$(pr_status "$PRIMARY_ADDR" | jq -r .mode)" != "primary" ]]; then
  echo "Enabling performance primary on ${PRIMARY_NAME}"
  VAULT_ADDR="$PRIMARY_ADDR" VAULT_TOKEN=root vault write -f sys/replication/performance/primary/enable \
    primary_cluster_addr="https://${PRIMARY_NAME}:8201" >/dev/null
  sleep 3
fi

if [[ "$(pr_status "$PR_ADDR" | jq -r .mode)" == "secondary" ]]; then
  echo "${PR_NAME} is already a performance secondary"
else
  echo "Generating secondary activation token (id ${PR_NAME})"
  VAULT_ADDR="$PRIMARY_ADDR" VAULT_TOKEN=root vault write sys/replication/performance/primary/revoke-secondary id="$PR_NAME" >/dev/null 2>&1 || true
  activation="$(VAULT_ADDR="$PRIMARY_ADDR" VAULT_TOKEN=root vault write -format=json \
    sys/replication/performance/primary/secondary-token id="$PR_NAME" ttl=10m | jq -r .wrap_info.token)"
  echo "Enabling performance secondary on ${PR_NAME} (its storage is replaced by the primary's)"
  VAULT_ADDR="$PR_ADDR" VAULT_TOKEN=root vault write sys/replication/performance/secondary/enable \
    token="$activation" primary_api_addr="https://${PRIMARY_NAME}:8200" ca_file=/vault/tls/vault-ca.pem >/dev/null
fi

echo -n "Waiting for ${PR_NAME} to stream WALs"
state=""
for _ in $(seq 1 60); do
  state="$(pr_status "$PR_ADDR" | jq -r .state)"
  if [[ "$state" == "stream-wals" ]]; then
    echo " ok"
    break
  fi
  echo -n "."
  sleep 2
done
[[ "$state" == "stream-wals" ]] || { echo "performance secondary did not reach stream-wals (state=${state})" >&2; exit 1; }

export VAULT_ADDR="$PR_ADDR"
if VAULT_TOKEN=root vault token lookup >/dev/null 2>&1; then
  echo "${PR_NAME}: token 'root' present"
else
  echo "${PR_NAME}: restoring token 'root' (generate-root with the primary's unseal key)"
  unset VAULT_TOKEN  # generate-root is unauthenticated; an invalid token gets a 403
  vault operator generate-root -cancel >/dev/null 2>&1 || true
  init="$(vault operator generate-root -init -format=json)"
  key="$(jq -r '.unseal_keys_b64[0]' "${ROOT_DIR}/${PRIMARY_NAME}/init.json")"
  encoded="$(vault operator generate-root -nonce="$(jq -r .nonce <<<"$init")" -format=json "$key" | jq -r .encoded_token)"
  generated="$(vault operator generate-root -decode="$encoded" -otp="$(jq -r .otp <<<"$init")" -format=json | jq -r .token)"
  # The custom-id SHA1 warning is expected in dev; any real failure keeps the generated token so nothing is lost.
  if ! out="$(VAULT_TOKEN="$generated" vault token create -id=root -policy=root -orphan -display-name=dev-root 2>&1)" \
    || ! VAULT_TOKEN=root vault token lookup >/dev/null 2>&1; then
    echo "$out" >&2
    echo "error: could not create token 'root' on ${PR_NAME}; the generated root token was kept (not revoked)" >&2
    exit 1
  fi
  VAULT_TOKEN="$generated" vault token revoke -self >/dev/null
fi

echo "primary:   $(pr_status "$PRIMARY_ADDR" | jq -c '{mode, state, known_secondaries, connection: [.secondaries[]?.connection_status]}')"
echo "secondary: $(pr_status "$PR_ADDR" | jq -c '{mode, state, connection_state, last_remote_wal}')"
