#!/usr/bin/env bash
# Forbidden-identifier gate.
#
# Every pattern below names a protocol object the authority-commit ruling
# removed, or a brand/type rename that is already closed. A pattern must ratchet
# monotonically to zero:
#   - count above baseline  -> FAIL (new debt introduced)
#   - count below baseline  -> FAIL (progress! tighten the baseline below)
#   - zero-baseline pattern -> any occurrence fails outright
#
# When a migration wave lands, update the baseline in the BASELINES table
# to the new (lower) count in the same commit. Every baseline here is already 0,
# so any occurrence fails outright.
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
Seal|0|authority-commit: Station admission replaces Seal|Seal
CellId|0|authority-commit: protocol-level Cell removed|CellId
cas_cell|0|authority-commit: protocol-level Cell removed|cas_cell
CBS|0|authority-commit: CBS effect planes removed|CBS
ControlProposal|0|authority-commit: ControlProposal removed|ControlProposal
control_proposal|0|authority-commit: ControlProposal removed|control_proposal
Frontier|0|authority-commit: a Realm has one current write authority|Frontier
security_frontier|0|authority-commit: security_frontier removed|security_frontier
Lattice|0|authority-commit: Lattice removed|Lattice
sequenced_state|0|authority-commit: state-model removed|sequenced_state
causal_register|0|authority-commit: state-model removed|causal_register
or_set|0|authority-commit: state-model removed|or_set
ordered_log|0|authority-commit: state-model removed|ordered_log
dot_observed_remove|0|authority-commit: dot-observed-remove removed|dot_observed_remove
authority_revision|0|authority-commit: authority_revision removed|authority_revision
policy_root|0|authority-commit: policy_root removed|policy_root
encryption_floor|0|authority-commit: create-locked encryption floors removed|encryption_floor
RHRK|0|authority-commit: RHRK acquisition removed|RHRK
WelcomeEvent|0|MLS Welcome is a delivery object, never an Event|WelcomeEvent
ak.mls.welcome|0|MLS Welcome is a delivery object, never an Event|ak.mls.welcome
EventInitialSubmission|0|EventCommitSubmission is the only submission DTO|EventInitialSubmission
history_exporter|0|authority-commit: history exporter removed|history_exporter
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
