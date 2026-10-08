#!/bin/bash
# Full end-to-end check from scratch: wipes .tmp/vault (all node data, unseal keys, TLS),
# rebuilds primary + DR + performance secondary, enables replication, seeds, mints the
# audit tokens, runs full-audit and cluster-audit against every node, then the unit tests,
# the CE smoke tests and lint. Local only (needs a licence with replication and a container
# runtime).
set -euo pipefail

steps=(
  down clean up:all
  dr:enable pr:enable # before seed: enabling replication restarts the primary and drops unsaved client activity
  seed seed:findings
  token:policies token:pr
  audit:dev
  test test:ce lint
)

start=$SECONDS
for step in "${steps[@]}"; do
  echo "==> task ${step}"
  task "$step"
done
echo "e2e passed in $((SECONDS - start))s"
