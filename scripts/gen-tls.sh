#!/bin/bash
# Generate a local CA and one server cert shared by all Vault nodes (idempotent).
# The leaf carries Authority/Subject Key Identifiers: Python 3.13+ verifies with
# VERIFY_X509_STRICT and rejects certs without them. An existing leaf lacking them is
# reissued from the same CA, so trust (including the secondaries' ca_file) is kept.
set -euo pipefail

TLS_DIR="${1:-.tmp/vault/tls}"
NODES="${VAULT_NODE_NAMES:-vault-primary vault-dr vault-pr}"
CA_KEY="${TLS_DIR}/vault-ca-key.pem"
CA_CERT="${TLS_DIR}/vault-ca.pem"
LEAF_KEY="${TLS_DIR}/vault-key.pem"
LEAF_CERT="${TLS_DIR}/vault-cert.pem"

mkdir -p "$TLS_DIR"
umask 077

if [[ ! -s "$CA_CERT" || ! -s "$CA_KEY" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CA_KEY" -out "$CA_CERT" \
    -subj "/CN=vault-tools local CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null
  rm -f "$LEAF_CERT"
  echo "Generated CA in ${TLS_DIR}"
fi

# Reuse the leaf only if it has the key identifiers and a SAN for every node (a new node,
# e.g. vault-pr, reissues it from the same CA so existing trust is kept).
leaf_ok() {
  [[ -s "$LEAF_CERT" ]] || return 1
  openssl x509 -in "$LEAF_CERT" -noout -ext authorityKeyIdentifier 2>/dev/null | grep -qE "keyid|[0-9A-F]{2}:" || return 1
  local sans node
  sans="$(openssl x509 -in "$LEAF_CERT" -noout -ext subjectAltName 2>/dev/null)"
  for node in $NODES; do
    grep -qE "DNS:${node}(,|$)" <<<"$sans" || return 1
  done
}
if leaf_ok; then
  echo "TLS material already present in ${TLS_DIR}"
  exit 0
fi

san="DNS:localhost,IP:127.0.0.1"
for node in $NODES; do
  san="${san},DNS:${node}"
done

[[ -s "$LEAF_KEY" ]] || openssl genrsa -out "$LEAF_KEY" 2048 2>/dev/null
openssl req -new -key "$LEAF_KEY" -out "${TLS_DIR}/vault.csr" -subj "/CN=vault" 2>/dev/null
openssl x509 -req -in "${TLS_DIR}/vault.csr" -days 365 \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$LEAF_CERT" \
  -extfile <(printf '%s\n' \
    "subjectAltName=${san}" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth,clientAuth" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid,issuer") 2>/dev/null

rm -f "${TLS_DIR}/vault.csr" "${TLS_DIR}/vault-ca.srl"
# Readable by the container's vault user; the key stays inside .tmp (gitignored).
chmod 644 "$CA_CERT" "$LEAF_CERT" "$LEAF_KEY"
echo "Issued server cert (${san}) in ${TLS_DIR}"
