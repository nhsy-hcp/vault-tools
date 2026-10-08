# Add-on policy for `namespace-audit --acl-bodies` (VT-POL-001..005).
#
# Grants READ on ACL policy bodies and nothing else: no list, no sudo, no write.
# audit-policy.hcl already lists policy names; this lets the tool read each
# body to assess its permissions. Bodies are parsed in memory: only policy
# names, a body hash and the flagged rules' paths and capabilities are written
# out. Bodies and allowed/denied parameter values never reach an output file.
#
# Reading bodies lets the token reconstruct the cluster's access model, which is
# why this is separate from audit-policy.hcl. Attach it only for a policy review,
# alongside audit-policy.hcl, in the ROOT namespace, and drop it afterwards.
#
# Namespace-local rules repeat per nesting level ("+" = exactly one segment);
# root plus five levels are covered, matching audit-policy.hcl.

path "sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}

path "+/+/+/+/+/sys/policies/acl/*" {
  capabilities = ["read"]
}
