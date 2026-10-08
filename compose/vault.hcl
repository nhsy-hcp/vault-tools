# Shared by every node in compose.yaml. Per-node values come from the environment:
# VAULT_API_ADDR, VAULT_CLUSTER_ADDR and VAULT_RAFT_NODE_ID.
ui            = true
disable_mlock = true

# Vault 2.0 authenticates sys/generate-root by default (CVE-2026-5807). Dev only: a
# performance secondary loses every token on activation, so scripts/pr-enable.sh needs the
# unauthenticated ceremony (with the primary's unseal key) to restore token `root`.
enable_unauthenticated_access = ["generate-root"]

storage "raft" {
  path = "/vault/file"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/vault/tls/vault-cert.pem"
  tls_key_file    = "/vault/tls/vault-key.pem"
}
