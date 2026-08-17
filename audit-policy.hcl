# Vault ACL policy for the vault-tools audit CLI.
#
# Read-only: the tool never writes to Vault. Every rule below corresponds to a
# request the tool actually issues on some code path -- nothing is speculative,
# and nothing is granted "just in case".
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
# Only the three namespace-audit rules need this treatment; see the comments on
# each section for why the rest are root-only. They cover the root namespace
# plus five levels of nesting. A deeper hierarchy needs a further "+/" rule per
# extra level; levels deeper than the tree in use are harmless.
#
# Assign this policy to a token created in the ROOT namespace.

# --- Token self-inspection ---------------------------------------------------
# validate_connection() calls hvac's is_authenticated(), which is a
# GET auth/token/lookup-self. hvac swallows a 403 there and returns False, so
# without this rule the tool aborts with "Vault client is not authenticated ...
# check your VAULT_TOKEN", which points at entirely the wrong cause.
#
# Vault's built-in "default" policy already grants this, so a token created the
# usual way inherits it. It is stated explicitly here so the policy is
# self-sufficient and still works with -no-default-policy.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# --- Connection validation ---------------------------------------------------
# Deliberately absent: sys/health, sys/seal-status and sys/init.
#
# read_health_status(), is_sealed() and is_initialized() are the three checks
# validate_connection() runs, and all three are UNAUTHENTICATED Vault endpoints
# -- an ACL rule for them grants nothing. They are also always issued against
# the root namespace, because validate_connection() uses the default
# namespace="" client, so nested variants would be doubly dead.

# --- namespace-audit: auth methods -------------------------------------------
# list_auth_methods() -> GET sys/auth, once per namespace visited. The traversal
# scopes each request with get_client(namespace_path), so every nesting level is
# genuinely reached.
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
# Root-only, deliberately. get_activity_data() issues this without a namespace,
# and a root-namespace query already reports every namespace beneath it, so
# nested variants would grant access to client-count data across the tree
# without the tool ever using it.
path "sys/internal/counters/activity" {
  capabilities = ["read"]
}

# --- entity-export -----------------------------------------------------------
# Root-only for the same reason as activity-export above -- which matters more
# here, because this is the one endpoint the tool uses that Vault root-protects:
# "read" alone returns 403, so "sudo" is required as well. It is the only rule
# in this policy that needs it. Granting sudo on this path across five levels of
# namespaces would be real attack surface for no functional benefit.
path "sys/internal/counters/activity/export" {
  capabilities = ["read", "sudo"]
}
