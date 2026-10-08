#!/bin/bash
# Validate the local toolchain and environment for the vault-tools dev stack
# (compose.yaml, compose.ce.yaml). Exits 1 if anything required is missing;
# warnings (an empty licence, say) do not fail, since `task test:ce` needs neither.
set -euo pipefail

CONTAINER_CLI="${CONTAINER_CLI:-docker}"
VAULT_HOST_IP="${VAULT_HOST_IP:-127.0.0.1}"
VAULT_HOST_PORT="${VAULT_HOST_PORT:-8310}"
VAULT_DR_HOST_PORT="${VAULT_DR_HOST_PORT:-8320}"
VAULT_PR_HOST_PORT="${VAULT_PR_HOST_PORT:-8340}"
CE_PORT="${CE_PORT:-8330}"
fail=0

ok() { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1" >&2; fail=1; }
warn() { printf '  WARN  %s\n' "$1" >&2; }

echo "Tools:"
for tool in task uv vault jq curl openssl lsof "$CONTAINER_CLI"; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool"; else bad "$tool not found"; fi
done
# gitleaks, ruff and markdownlint run inside pre-commit; shellcheck is run by hand.
if command -v shellcheck >/dev/null 2>&1; then ok "shellcheck"; else warn "shellcheck not found (needed to lint scripts/)"; fi
if [[ -d .venv ]]; then ok ".venv present"; else bad ".venv missing (run: task init)"; fi

echo "Container runtime:"
if "$CONTAINER_CLI" info >/dev/null 2>&1; then
  ok "$CONTAINER_CLI engine reachable"
else
  bad "$CONTAINER_CLI engine not reachable (podman: run 'podman machine start')"
fi
if "$CONTAINER_CLI" compose version >/dev/null 2>&1; then
  ok "$CONTAINER_CLI compose"
else
  bad "$CONTAINER_CLI compose not available (podman: install docker-compose)"
fi

echo "Network:"
if [[ "$(uname -s)" == "Darwin" && "$VAULT_HOST_IP" != "127.0.0.1" ]] && ! ifconfig lo0 | grep -q "inet ${VAULT_HOST_IP} "; then
  bad "${VAULT_HOST_IP} is not on lo0; run once per boot: sudo ifconfig lo0 alias ${VAULT_HOST_IP}"
else
  ok "${VAULT_HOST_IP} available"
fi
for port in "$VAULT_HOST_PORT" "$VAULT_DR_HOST_PORT" "$VAULT_PR_HOST_PORT" "$CE_PORT"; do
  if lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null | grep -qv -e COMMAND -e gvproxy; then
    bad "port ${port} already in use by another process"
  else
    ok "port ${port} free (or held by a vault container)"
  fi
done

echo "Environment:"
if [[ -f .env ]]; then ok ".env present"; else bad ".env missing (cp .env.example .env)"; fi
if [[ -n "${VAULT_LICENSE:-}" ]]; then ok "VAULT_LICENSE set"; else warn "VAULT_LICENSE empty in .env (needed by task up, not by task test:ce)"; fi
if [[ -n "${VAULT_ADDR:-}" ]]; then ok "VAULT_ADDR=${VAULT_ADDR}"; else bad "VAULT_ADDR not set"; fi

exit "$fail"
