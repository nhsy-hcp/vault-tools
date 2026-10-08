# Add-on policy: read ACL policy bodies (VT-POL-001..005).
#
# Grants READ on ACL policy bodies and nothing else: no list, no sudo, no write.
# policies/audit-policy.hcl already lists policy names; with this attached too, the tool
# reads each body to assess its permissions. The token is the source of truth:
# attach this and ACL permissions are assessed; leave it off and they are not. Bodies are parsed in memory: only policy
# names, a body hash and the flagged rules' paths and capabilities are written
# out. Bodies and allowed/denied parameter values never reach an output file.
#
# Reading bodies lets the token reconstruct the cluster's access model, which is
# why this is separate from policies/audit-policy.hcl. Attach it only for a policy review,
# alongside policies/audit-policy.hcl, in the ROOT namespace, and drop it afterwards:
#   vault policy write vault-tools-acl-reader policies/audit-policy-acl-reader.hcl
#
# Namespace-local rules repeat per nesting level ("+" = exactly one segment);
# root plus five levels are covered, matching policies/audit-policy.hcl.

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
