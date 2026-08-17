# Vault ACL policy for the vault-tools audit CLI.
#
# Read-only: the tool never writes to Vault. Every path corresponds to an
# endpoint the tool actually calls, so nothing here is speculative.
#
# NAMESPACE SCOPING (Vault Enterprise)
# ------------------------------------
# ACL policies are namespace-local, and a token does not pick up a same-named
# policy defined in a child namespace. To audit a namespace tree with a single
# token created in the root namespace, each child namespace must be addressed
# by a namespace-prefixed path from the root.
#
# "+" matches exactly one path segment, and Vault has no variable-depth
# wildcard, so one rule is needed per level of nesting:
#
#     sys/mounts              root namespace
#     +/sys/mounts            one level down    (team-a/)
#     +/+/sys/mounts          two levels down   (team-a/ci-cd/)
#     +/+/+/sys/mounts        three levels down (team-a/ci-cd/prod/)
#     +/+/+/+/sys/mounts      four levels down
#     +/+/+/+/+/sys/mounts    five levels down
#
# Every rule below covers the root namespace plus five levels of nesting. A
# deeper hierarchy needs a further "+/" rule per extra level; levels deeper
# than the tree in use are harmless. Assign this policy to a token created in
# the root namespace.

# --- Connection validation ---------------------------------------------------
# read_health_status() supplies the cluster name used in every output filename;
# is_sealed() and is_initialized() gate the run. These are checked once, in the
# namespace the tool starts from -- the root namespace unless VAULT_NAMESPACE
# or --namespace says otherwise, hence the nested variants.
path "sys/health" {
  capabilities = ["read"]
}

path "+/sys/health" {
  capabilities = ["read"]
}

path "+/+/sys/health" {
  capabilities = ["read"]
}

path "+/+/+/sys/health" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/health" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/health" {
  capabilities = ["read"]
}

path "sys/seal-status" {
  capabilities = ["read"]
}

path "+/sys/seal-status" {
  capabilities = ["read"]
}

path "+/+/sys/seal-status" {
  capabilities = ["read"]
}

path "+/+/+/sys/seal-status" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/seal-status" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/seal-status" {
  capabilities = ["read"]
}

path "sys/init" {
  capabilities = ["read"]
}

path "+/sys/init" {
  capabilities = ["read"]
}

path "+/+/sys/init" {
  capabilities = ["read"]
}

path "+/+/+/sys/init" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/init" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/init" {
  capabilities = ["read"]
}

# --- namespace-audit: auth methods -------------------------------------------
# list_auth_methods() -> GET sys/auth, once per namespace visited.
path "sys/auth" {
  capabilities = ["read"]
}

path "+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/auth" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/auth" {
  capabilities = ["read"]
}

# --- namespace-audit: secret engines -----------------------------------------
# list_mounted_secrets_engines() -> GET sys/mounts, once per namespace visited.
path "sys/mounts" {
  capabilities = ["read"]
}

path "+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/mounts" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/mounts" {
  capabilities = ["read"]
}

# --- namespace-audit: child namespace discovery ------------------------------
# list_namespaces() -> LIST sys/namespaces. This is what drives the recursive
# walk: without it at a given level, the audit stops there. Enterprise only; on
# Community the tool treats the InvalidPath response as "no children" and
# carries on.
path "sys/namespaces" {
  capabilities = ["list"]
}

path "+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

path "+/+/+/+/+/sys/namespaces" {
  capabilities = ["list"]
}

# --- activity-export ---------------------------------------------------------
# A single call already reports every namespace beneath the one queried; the
# nested variants only matter when the tool is pointed at a child namespace.
path "sys/internal/counters/activity" {
  capabilities = ["read"]
}

path "+/sys/internal/counters/activity" {
  capabilities = ["read"]
}

path "+/+/sys/internal/counters/activity" {
  capabilities = ["read"]
}

path "+/+/+/sys/internal/counters/activity" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/internal/counters/activity" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/internal/counters/activity" {
  capabilities = ["read"]
}

# --- entity-export -----------------------------------------------------------
# This is the one endpoint the tool uses that Vault root-protects: "read" alone
# returns 403, so "sudo" is required as well. It is also the only rule here that
# needs it -- every other path above works with plain read/list.
path "sys/internal/counters/activity/export" {
  capabilities = ["read", "sudo"]
}

path "+/sys/internal/counters/activity/export" {
  capabilities = ["read", "sudo"]
}

path "+/+/sys/internal/counters/activity/export" {
  capabilities = ["read", "sudo"]
}

path "+/+/+/sys/internal/counters/activity/export" {
  capabilities = ["read", "sudo"]
}

path "+/+/+/+/sys/internal/counters/activity/export" {
  capabilities = ["read", "sudo"]
}

path "+/+/+/+/+/sys/internal/counters/activity/export" {
  capabilities = ["read", "sudo"]
}
