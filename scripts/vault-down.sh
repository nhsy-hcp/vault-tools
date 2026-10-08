#!/bin/bash
# Stop and remove Vault node containers (idempotent). Named volumes (Raft data) are kept;
# VOLUMES=1 removes them too (task clean).
#   usage: scripts/vault_down.sh [node ...]   (default: every node and the network)
set -euo pipefail

CONTAINER_CLI="${CONTAINER_CLI:-docker}"
if [[ $# -eq 0 ]]; then
  if [[ "${VOLUMES:-0}" == "1" ]]; then
    "$CONTAINER_CLI" compose --profile '*' down --volumes
  else
    "$CONTAINER_CLI" compose --profile '*' down
  fi
else
  "$CONTAINER_CLI" compose rm -sf "$@"
fi
