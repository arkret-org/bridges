#!/usr/bin/env bash
# ARC-0002 deletion gate (arkret 大架构重构计划 2026-07-10, W0).
#
# All bridges patterns are already at zero — this gate prevents regressions:
#   - `cokret` (any case): brand rename closed 2026-07-09 (F-04 renamed
#     crates/runtime/src/cokret_edge.rs); must never reappear.
#   - `ck_ops`: legacy identifier, closed.
#   - `mock` outside tests/ dirs: platform write paths must be real API
#     adapters or explicit structured rejections (BR-001/BR-002); mock
#     helpers belong under a tests/ directory.
#
# Usage: scripts/deletion_gate.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

# check <name> <plan-ref> <grep args...>
# grep exit codes: 0 = matches found, 1 = clean, >=2 = grep itself failed
# (which must fail the gate loudly, never pass as "no matches").
check() {
  local name="$1" planref="$2"
  shift 2
  local matches rc
  set +e
  matches=$(grep -rn --include='*.rs' "$@" crates/)
  rc=$?
  set -e
  if [ "$rc" -ge 2 ]; then
    echo "ERROR [$name] grep failed with exit $rc — gate result unreliable." >&2
    fail=1
    return
  fi
  if [ "$rc" -eq 0 ]; then
    echo "FAIL [$name] pattern must stay at zero ($planref). Offending lines:" >&2
    echo "$matches" | head -20 >&2
    fail=1
  else
    echo "ok   [$name] 0/0 ($planref)"
  fi
}

# NOTE: no `-i` — grep -i -r aborts on some UTF-8 sources; use case classes.
check cokret "brand rename (closed)" -E -- '[Cc]okret|COKRET'
check ck_ops "brand rename (closed)" -F -- ck_ops
check mock-write-path "BR-001/BR-002 real platform adapters" --exclude-dir=tests -E -- '\b[Mm]ock|\bMOCK'

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "deletion_gate: FAILED — see _code_review/重构计划-2026-07-10.md (ARC-0002)." >&2
  exit 1
fi

echo "deletion_gate: ok"
