#!/bin/bash
# Seed configuration that trips the vault-tools audit rules (run after seed-vault.py (task seed)).
# Idempotent: existing mounts/policies are left as they are. Needs a root token.
set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"
NS="${FINDINGS_NAMESPACE:-tn009/soc2/dev}"
SENTINEL_NS="${SENTINEL_NAMESPACE:-tn009}"
SENTINEL_DRIFT_NS="${SENTINEL_DRIFT_NAMESPACE:-tn009/gdpr}"
EMPTY_PARENT="${EMPTY_PARENT:-tn010/prototypes}"
SENTINEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../examples/sentinel" && pwd)"

step() { printf '  [+] %s\n' "$1"; }

# vault CLI exits non-zero when a path is already in use; treat that as success.
try() {
  local out
  if ! out="$("$@" 2>&1)"; then
    if [[ "$out" == *"already in use"* || "$out" == *"existing mount"* || "$out" == *"already exists"* ]]; then
      return 0
    fi
    echo "$out" >&2
    return 1
  fi
}

echo "Seeding audit findings in ${NS}"
step "VT-AUTH-001 userpass-public (listing_visibility=unauth)"
try vault auth enable -namespace="$NS" -path=userpass-public -listing-visibility=unauth userpass

step "VT-MOUNT-002 kv-long-ttl (max-lease-ttl above the cluster ceiling)"
try vault secrets enable -namespace="$NS" -path=kv-long-ttl kv-v2
vault secrets tune -namespace="$NS" -max-lease-ttl=87600h kv-long-ttl >/dev/null

step "VT-MOUNT-004 kv-long-default (default-lease-ttl above 768h)"
try vault secrets enable -namespace="$NS" -path=kv-long-default kv-v2
vault secrets tune -namespace="$NS" -max-lease-ttl=87600h -default-lease-ttl=1000h kv-long-default >/dev/null

step "VT-MOUNT-003 kv-local (local mount)"
try vault secrets enable -namespace="$NS" -path=kv-local -local kv-v2

step "VT-MOUNT-006 kv-v1 (KV version 1)"
try vault secrets enable -namespace="$NS" -path=kv-v1 -version=1 kv

step "VT-MOUNT-005 sprawl-01..21 (more than 20 kv mounts in one namespace)"
for i in $(seq -w 1 21); do
  try vault secrets enable -namespace="$NS" -path="sprawl-${i}" kv-v2
done

step "VT-NS-002 ${EMPTY_PARENT}/empty-leaf (unused leaf namespace)"
try vault namespace create -namespace="$EMPTY_PARENT" empty-leaf

# Entities are upserted by name, so rerunning these is harmless.
step "VT-ID-001 entity vault-tools-orphan (no aliases)"
vault write -namespace="$NS" identity/entity name=vault-tools-orphan metadata=team=platform >/dev/null
step "VT-ID-002 entity vault-tools-direct (policy attached directly)"
vault write -namespace="$NS" identity/entity name=vault-tools-direct policies=default metadata=owner=vault-tools >/dev/null
step "VT-ID-003 entity vault-tools-disabled (disabled)"
vault write -namespace="$NS" identity/entity name=vault-tools-disabled disabled=true >/dev/null

step "VT-ID-005 entities vault-tools-dup-a/-b (same alias name on two userpass mounts)"
try vault auth enable -namespace="$NS" -path=userpass-dup userpass
for pair in "a:userpass-public" "b:userpass-dup"; do
  entity="vault-tools-dup-${pair%%:*}"
  vault write -namespace="$NS" identity/entity name="$entity" >/dev/null
  entity_id="$(vault read -namespace="$NS" -field=id "identity/entity/name/${entity}")"
  accessor="$(vault auth list -namespace="$NS" -format=json | jq -r --arg m "${pair#*:}/" '.[$m].accessor')"
  try vault write -namespace="$NS" identity/entity-alias name=vault-tools-dup canonical_id="$entity_id" mount_accessor="$accessor"
done

# ACL policies (namespace-audit, with the ACL reader add-on). The base seed's admin, rbac-policy-manager,
# oauth2-token-manager and service-account-creator already trip VT-POL-001/002/003.
step "VT-POL-004 drifted read-only policy (differs from every other copy)"
vault policy write -namespace="$NS" read-only - >/dev/null <<'HCL'
path "secret/data/*" { capabilities = ["read", "list"] }
path "secret/metadata/*" { capabilities = ["list"] }
HCL

# Audit devices and snapshots are cluster-wide: root namespace only.
echo "Seeding audit devices and automated snapshots (root namespace)"
step "audit device vault-tools-file (dummy file in the node's logs dir)"
try vault audit enable -path=vault-tools-file file file_path=/vault/logs/vault-tools-audit.log
step "VT-AUD-003 audit device vault-tools-stdout (stdout, hmac_accessor=false)"
try vault audit enable -path=vault-tools-stdout file file_path=stdout hmac_accessor=false

if vault list sys/storage/raft/snapshot-auto/config 2>&1 | grep -qE "unsupported path|enterprise-only feature"; then
  echo "  [skip] automated snapshots not available on this cluster"
else
  # The first snapshot runs one interval after the config is written, and the status is
  # empty until then: start at 30s, wait for a completed run, then settle on 24h.
  step "VT-SNAP-003 snapshot config vault-tools-local (local storage, 24h)"
  snap_config() {
    vault write sys/storage/raft/snapshot-auto/config/vault-tools-local \
      storage_type=local interval="$1" retain=2 \
      path_prefix=/vault/file/snapshots local_max_space=104857600 >/dev/null
  }
  if ! vault read -format=json sys/storage/raft/snapshot-auto/status/vault-tools-local 2>/dev/null | jq -e '.data.last_snapshot_end' >/dev/null; then
    snap_config 30s
    for _ in $(seq 1 18); do
      vault read -format=json sys/storage/raft/snapshot-auto/status/vault-tools-local 2>/dev/null | jq -e '.data.last_snapshot_end' >/dev/null && break
      sleep 5
    done
  fi
  snap_config 24h
fi

if vault list -namespace="$SENTINEL_NS" sys/policies/egp 2>&1 | grep -qE "unsupported path|enterprise-only feature"; then
  echo "  [skip] Sentinel not available on this cluster"
  exit 0
fi

echo "Seeding Sentinel policies in ${SENTINEL_NS}"
step "VT-SNT-001 egp vault-tools-advisory"
vault write -namespace="$SENTINEL_NS" sys/policies/egp/vault-tools-advisory \
  enforcement_level=advisory paths="secret/data/*" policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-002 rgp vault-tools-soft"
vault write -namespace="$SENTINEL_NS" sys/policies/rgp/vault-tools-soft \
  enforcement_level=soft-mandatory policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-003 egp vault-tools-wildcard (hard-mandatory, paths=*)"
vault write -namespace="$SENTINEL_NS" sys/policies/egp/vault-tools-wildcard \
  enforcement_level=hard-mandatory paths="*" policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-004 rgp vault-tools-always-true"
vault write -namespace="$SENTINEL_NS" sys/policies/rgp/vault-tools-always-true \
  enforcement_level=hard-mandatory policy=@"${SENTINEL_DIR}/always-true.sentinel" >/dev/null
step "control: rgp vault-tools-hard (must produce no audit finding)"
vault write -namespace="$SENTINEL_NS" sys/policies/rgp/vault-tools-hard \
  enforcement_level=hard-mandatory policy=@"${SENTINEL_DIR}/noop.sentinel" >/dev/null
step "VT-SNT-005 rgp vault-tools-hard drifted copy in ${SENTINEL_DRIFT_NS}"
vault write -namespace="$SENTINEL_DRIFT_NS" sys/policies/rgp/vault-tools-hard \
  enforcement_level=hard-mandatory policy=@"${SENTINEL_DIR}/noop-drift.sentinel" >/dev/null
step "VT-SNT-007 egp vault-tools-http (advisory, narrow path)"
vault write -namespace="$SENTINEL_NS" sys/policies/egp/vault-tools-http \
  enforcement_level=advisory paths="secret/data/vault-tools-http/*" policy=@"${SENTINEL_DIR}/http-import.sentinel" >/dev/null
# VT-SNT-006 (hard-mandatory, always false) is not seeded: it would lock out the dev cluster. Unit-tested only.

if [[ "$(vault read -field=mode sys/replication/performance/status 2>/dev/null || true)" == "primary" ]]; then
  echo "Seeding performance replication findings (primary is a performance primary)"
  step "VT-REPL-005 paths filter on vault-pr (deny ${PR_FILTER_PATH:-tn009/})"
  vault write sys/replication/performance/primary/paths-filter/vault-pr mode=deny paths="${PR_FILTER_PATH:-tn009/}" >/dev/null
  step "VT-REPL-002 unused activation token for secondary id vault-pr-stale"
  if ! vault read -format=json sys/replication/performance/status | jq -e '.data.known_secondaries | index("vault-pr-stale")' >/dev/null; then
    vault write sys/replication/performance/primary/secondary-token id=vault-pr-stale ttl=24h >/dev/null
  fi
  # VT-REPL-001/003/004 (lag, clock skew, merkle corruption) can't be produced on demand. Unit-tested only.
else
  echo "Skipping performance replication findings (run task pr:enable first)"
fi
echo "Done."
