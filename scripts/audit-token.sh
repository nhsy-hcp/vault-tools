#!/bin/bash
# Write the vault-tools audit policy and mint a 1h orphan token into .tmp/audit-token (0600).
# TOKEN_FILE overrides the output file (token:pr mints on the performance secondary: tokens are
# per cluster, policy writes there are forwarded to the primary).
# POLICY_READER=1 also writes and attaches the read-only add-ons vault-tools-acl-reader
# (ACL policy bodies) and vault-tools-sentinel-reader (Sentinel EGP/RGP bodies).
# Needs a token that can write policies (the dev stack's `root`).
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
TOKEN_FILE="${TOKEN_FILE:-.tmp/audit-token}"
# name|file
POLICIES=("vault-tools-audit|policies/audit-policy.hcl")
if [[ "${POLICY_READER:-0}" == "1" ]]; then
  POLICIES+=(
    "vault-tools-acl-reader|policies/audit-policy-acl-reader.hcl"
    "vault-tools-sentinel-reader|policies/audit-policy-sentinel-reader.hcl"
  )
fi

mkdir -p "$(dirname "$TOKEN_FILE")"
policy_flags=()
names=()
for entry in "${POLICIES[@]}"; do
  IFS='|' read -r name file <<<"$entry"
  vault policy write "$name" "$file" >/dev/null
  policy_flags+=("-policy=${name}")
  names+=("$name")
done
umask 077
vault token create "${policy_flags[@]}" -no-default-policy -orphan \
  -ttl=1h -explicit-max-ttl=1h -display-name=vault-tools-audit -field=token >"$TOKEN_FILE"
echo "Wrote ${TOKEN_FILE} (policies ${names[*]}, ttl 1h)"
echo "Use it with: export VAULT_TOKEN=\"\$(cat ${TOKEN_FILE})\""
