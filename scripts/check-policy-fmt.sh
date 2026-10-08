#!/bin/bash
#
# Check (or fix) that Vault policy files are `vault policy fmt`-clean.
#
# Check mode never touches the real file: each policy is copied to .tmp/,
# formatted there, and compared. A difference fails with the diff, so the
# fix is visible before it is applied. A policy that does not parse fails too.
#
# `vault policy fmt` works offline -- no server, address or token is used.
# Without a vault binary on PATH the check is skipped with a message rather
# than failed, so environments without one (CI runners) still lint cleanly.
#
# Usage:
#   scripts/check-policy-fmt.sh [--fix] [file.hcl ...]
#
# With no files, every policies/*.hcl is checked. pre-commit passes the staged
# .hcl files explicitly; any outside policies/ are ignored.

set -euo pipefail

fix=false
if [[ "${1:-}" == "--fix" ]]; then
  fix=true
  shift
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v vault >/dev/null 2>&1; then
  echo "⚠️  vault binary not found; skipping the policy format check (install from https://developer.hashicorp.com/vault/install)"
  exit 0
fi

# Only policies/ holds policies. Other .hcl files (compose/vault.hcl, a server
# config) are passed by the hook too, but `vault policy fmt` cannot parse them.
files=()
for file in "$@"; do
  [[ "$file" == policies/* ]] && files+=("$file")
done
if [[ $# -eq 0 ]]; then
  shopt -s nullglob
  files=(policies/*.hcl)
  shopt -u nullglob
fi
if [[ ${#files[@]} -eq 0 ]]; then
  echo "No policy files to check."
  exit 0
fi

mkdir -p .tmp
work_dir="$(mktemp -d .tmp/policy-fmt.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

status=0
for file in "${files[@]}"; do
  copy="$work_dir/$(basename "$file")"
  cp "$file" "$copy"
  if ! vault policy fmt "$copy" >/dev/null 2>"$work_dir/error"; then
    echo "❌ $file does not parse: $(cat "$work_dir/error")"
    status=1
    continue
  fi
  if cmp -s "$file" "$copy"; then
    continue
  fi
  if [[ "$fix" == true ]]; then
    cp "$copy" "$file"
    echo "✏️  Formatted $file"
  else
    echo "❌ $file is not vault policy fmt-clean:"
    diff -u "$file" "$copy" | sed "1,2s|$copy|$file (formatted)|" || true
    status=1
  fi
done

if [[ $status -ne 0 && "$fix" == false ]]; then
  echo "Run 'task fmt:policy' to apply the formatting."
fi
exit "$status"
