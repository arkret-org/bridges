#!/usr/bin/env bash
# Exercise the real deletion gate against isolated source trees.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/bridge-deletion-gate.XXXXXXXX")"
cleanup() {
  rm -f -- "$scratch/crates/fixture.rs" "$scratch/scripts/deletion_gate.sh" "$scratch/result.log"
  rmdir -- "$scratch/crates" "$scratch/scripts" "$scratch"
}
trap cleanup EXIT
mkdir "$scratch/crates" "$scratch/scripts"
cp "$ROOT/scripts/deletion_gate.sh" "$scratch/scripts/deletion_gate.sh"

check_case() {
  local expected="$1"
  local source="$2"
  printf '%s\n' "$source" > "$scratch/crates/fixture.rs"
  local status=0
  bash "$scratch/scripts/deletion_gate.sh" > "$scratch/result.log" 2>&1 || status=$?
  if [ "$expected" = "accept" ]; then
    [ "$status" -eq 0 ] || { cat "$scratch/result.log" >&2; return 1; }
  else
    [ "$status" -eq 1 ] || { cat "$scratch/result.log" >&2; return 1; }
    grep -Fq "FAIL [$expected]" "$scratch/result.log"
  fi
}

check_case accept 'use sdk::RealmActorContentBackupSealedHandover;'
check_case accept 'struct SealCarrier;'
check_case accept 'struct Unsealed;'
check_case Seal 'struct Seal;'
check_case Seal 'use retired::Seal;'
check_case Seal 'type Retired = r#Seal;'
check_case CellId 'struct CellId;'
printf '%s\n' 'deletion_gate regressions: ok'
