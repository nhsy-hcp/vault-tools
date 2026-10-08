# Add-on policy: read Sentinel EGP/RGP policy bodies (VT-SNT-001..007).
#
# Grants READ on Sentinel policy bodies and nothing else: no list, no sudo, no
# write. policies/audit-policy.hcl already lists the names; with this attached too, the
# tool reads each body to judge its enforcement level, paths and rule. The token
# is the source of truth: attach this and Sentinel is assessed; leave it off and
# the report says Sentinel was listed but not assessed.
#
# Bodies are reduced in memory: only names, enforcement levels, EGP paths, a
# body hash, import names and the flagged rule IDs are written out. Policy source
# never reaches an output file.
#
# Attach it alongside policies/audit-policy.hcl, in the ROOT namespace:
#   vault policy write vault-tools-sentinel-reader policies/audit-policy-sentinel-reader.hcl
#
# Namespace-local rules repeat per nesting level ("+" = exactly one segment);
# root plus five levels are covered, matching policies/audit-policy.hcl.

path "sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/policies/egp/*" {
  capabilities = ["read"]
}

path "sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/policies/rgp/*" {
  capabilities = ["read"]
}
