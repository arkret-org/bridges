#!/usr/bin/env bash
# ARC-0002 deletion gate (arkret 大架构重构计划 2026-07-10, W0).
#
# Legacy patterns slated for deletion must ratchet monotonically to zero:
#   - count above baseline  -> FAIL (new debt introduced)
#   - count below baseline  -> FAIL (progress! tighten the baseline below)
#   - zero-baseline pattern -> any occurrence fails outright
#
# When a migration wave lands, update the baseline in the BASELINES table
# to the new (lower) count in the same commit. The gate reaches its final
# form when every baseline is 0.
#
# Usage: scripts/deletion_gate.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# name|baseline|plan-ref|fixed-string pattern (searched in crates/**/*.rs)
BASELINES=$(cat <<'EOF'
Cokret|0|brand rename (closed)|Cokret
ck_ops|0|brand rename (closed)|ck_ops
TypedTrustDomainId|0|SDK alias deleted, renamed to TrustDomainId here (closed)|TypedTrustDomainId
EOF
)

fail=0

while IFS='|' read -r name baseline planref pattern; do
  [ -z "$name" ] && continue
  # grep exit codes: 0 = matches, 1 = clean, >=2 = grep itself failed
  # (which must fail the gate loudly, never pass as "no matches").
  set +e
  matches=$(grep -rn --include='*.rs' -F -- "$pattern" crates/)
  rc=$?
  set -e
  if [ "$rc" -ge 2 ]; then
    echo "ERROR [$name] grep failed with exit $rc — gate result unreliable." >&2
    fail=1
    continue
  fi
  if [ "$rc" -eq 1 ]; then
    count=0
  else
    count=$(printf '%s\n' "$matches" | wc -l | tr -d '[:space:]')
  fi
  if [ "$count" -gt "$baseline" ]; then
    echo "FAIL [$name] $count occurrence(s) of '$pattern', baseline is $baseline ($planref)." >&2
    echo "     New uses of a to-be-deleted pattern are not allowed. Offending lines:" >&2
    printf '%s\n' "$matches" | head -20 >&2
    fail=1
  elif [ "$count" -lt "$baseline" ]; then
    echo "FAIL [$name] count dropped to $count but baseline is still $baseline ($planref)." >&2
    echo "     Tighten the baseline in scripts/deletion_gate.sh in this same commit." >&2
    fail=1
  else
    echo "ok   [$name] $count/$baseline ($planref)"
  fi
done <<< "$BASELINES"

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "deletion_gate: FAILED." >&2
  exit 1
fi

echo "deletion_gate: ok"
