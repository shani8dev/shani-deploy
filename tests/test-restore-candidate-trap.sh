#!/bin/bash
# After a deploy has flipped the slot markers, an ERR/EXIT trap must NOT fire.
#
# WHY THIS EXISTS. `finalize_update()` arms two traps early and clears them at
# the very end:
#
#     trap 'restore_candidate' ERR
#     trap '[[ $? -ne 0 ]] && restore_candidate' EXIT
#
# Between arming and clearing, the deploy flips the slot markers
# (`current-slot` -> the candidate) and then does a dozen more small things
# (mkdir /run/shanios, chmod, touch user-setup-needed, write the reboot-needed
# marker). If a trap fires in that window, restore_candidate runs against a
# deployment that has ALREADY committed its state: it restores the candidate
# subvolume from its backup, and the markers still claim that candidate is
# current. The machine is then on the old system with markers pointing at the
# new one, which is a state no later step can reason about.
#
# The code's own comment says this is why the traps are cleared — and it names
# one specific offender. So the hazard is understood; what is not tested is
# whether a bare failing command in that window actually fires the trap, and
# whether the traps are cleared early enough.
#
# This tests the MECHANISM in isolation with the real arm/clear code lifted from
# the script, and a stubbed restore_candidate that records being called.
#
#   shani-deploy/tests/test-restore-candidate-trap.sh     (host-only, no root, no disks)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(dirname "$HERE")/.."
DEPLOY="$HERE/../scripts/shani-deploy.sh"
pass=0 fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; fail=$((fail + 1)); }

[[ -f $DEPLOY ]] || { echo "shani-deploy.sh not found at $DEPLOY" >&2; exit 2; }

# Leading whitespace is not fixed: one arm site is nested inside an if (8
# spaces), the other at function level (4). Anchoring on exactly four spaces
# found one of the two and called it a defect.
ARM_ERR=$(grep -cE "^[[:space:]]+trap 'restore_candidate' ERR$" "$DEPLOY")
CLEAR_ERR=$(grep -c '^    trap - ERR$' "$DEPLOY")
CLEAR_EXIT=$(grep -c '^    trap - EXIT$' "$DEPLOY")

echo "== both traps are armed, and both are cleared"
# Two arm sites (deploy_update's and finalize_update's), and the pair of clears
# in finalize_update. An EXIT trap armed but never cleared is the dangerous one:
# it fires on any later nonzero exit, long after the deploy is over.
[[ $ARM_ERR -ge 2 ]] \
  && ok "the ERR trap is armed at both sites (${ARM_ERR})" \
  || no "the ERR trap is armed at both sites" "found ${ARM_ERR}"
[[ $CLEAR_ERR -ge 1 && $CLEAR_EXIT -ge 1 ]] \
  && ok "both ERR and EXIT are explicitly cleared" \
  || no "both ERR and EXIT are cleared" "ERR=${CLEAR_ERR} EXIT=${CLEAR_EXIT}"

echo
echo "== the clear happens AFTER the markers flip, not before"
# If the traps were cleared before the flip, a failure during the flip itself
# would leave nothing armed. The hazard is the opposite, but the ordering has to
# be asserted because it is what the comment relies on.
# Take the LAST `trap - ERR`, not the first: rollback_system() clears the trap at
# 2426, long before finalize_update even runs, so head -1 compared the wrong
# pair and reported correct ordering as broken.
clear_line=$(grep -n '^    trap - ERR$' "$DEPLOY" | tail -1 | cut -d: -f1)
marker_line=$(grep -n 'echo "\$CANDIDATE_SLOT" > /data/current-slot' "$DEPLOY" | head -1 | cut -d: -f1)
if [[ -n $clear_line && -n $marker_line ]]; then
  (( clear_line > marker_line )) \
    && ok "the traps are cleared after the markers flip (markers at line ${marker_line}, clear at ${clear_line})" \
    || no "the traps are cleared after the markers flip" \
         "traps cleared at line ${clear_line}, BEFORE the flip at ${marker_line}: a failure during the flip would leave nothing armed"
else
  no "the ordering could be determined" "clear=${clear_line:-?} marker=${marker_line:-?}"
fi

echo
echo "== a bare failing command in the committed window does fire the trap"
# Establishes that the hazard is REAL rather than theoretical: with the traps
# armed, a failing command in that window invokes restore_candidate. If this
# ever stops firing, the mechanism has changed and the clearing comment is
# describing something that no longer holds.
out=$( (
  set -uo pipefail
  trap 'echo FIRED:ERR' ERR
  trap '[[ $? -ne 0 ]] && echo FIRED:EXIT' EXIT
  echo "  (armed)"
  false            # a bare failing command, as in the committed window
  true
) 2>&1 )
grep -q 'FIRED' <<<"$out" \
  && ok "with the traps armed, a bare failure in the window does invoke the handler" \
  || no "a bare failure in the window invokes the handler" "got [$(printf '%s' "$out" | tr '\n' ';')]"

echo
echo "== but it does NOT fire once they are cleared"
out2=$( (
  set -uo pipefail
  trap 'echo FIRED:ERR' ERR
  trap '[[ $? -ne 0 ]] && echo FIRED:EXIT' EXIT
  trap - ERR
  trap - EXIT
  false
  true
) 2>&1 )
grep -q 'FIRED' <<<"$out2" \
  && no "cleared traps stay quiet" "still fired: $(printf '%s' "$out2" | tr '\n' ';')" \
  || ok "cleared traps stay quiet, so the post-deploy window cannot roll back"

echo
echo "== restore_candidate restores the BOOT CONFIGURATION, not just the subvolume"
# The whole failure mode is a restored subvolume with an ESP still naming the
# candidate. One finalize_boot_entries call in restore_candidate is what closes
# it; without it the markers and the bootloader disagree.
# awk's /start/,/end/ range, not a python slice cut at the first "# ---" inside
# the body: that comment appears mid-function and truncated the block before the
# finalize_boot_entries call, so a correct restore looked absent.
rc_block=$(awk '/^restore_candidate\(\)/,/^}$/' "$DEPLOY")
if printf '%s' "$rc_block" | grep -q 'finalize_boot_entries'; then
  ok "restore_candidate calls finalize_boot_entries, so the ESP follows the subvolume"
else
  no "restore_candidate calls finalize_boot_entries" \
       "a restored subvolume with an ESP still naming the candidate is the failure this exists to prevent"
fi

echo
echo "== it does not recurse: the trap is disarmed on entry"
grep -qE '^    trap - ERR EXIT$' "$DEPLOY" \
  && ok "restore_candidate disarms ERR and EXIT on entry, so a failure inside it cannot recurse" \
  || no "restore_candidate disarms the traps on entry" \
       "an error inside restore_candidate would re-enter it"

echo
echo "== rollback_system also disarms, for the same reason"
# awk's range ends at the first `^}$`, and rollback_system has a nested closing
# brace early, so the slice stopped before the disarm. The disarm is a bare
# `trap - ERR` at line 2426 - the same shape restore_candidate uses in one
# statement (`trap - ERR EXIT`), so both spellings are accepted.
awk '/^rollback_system\(\)/,/^    safe_mount /' "$DEPLOY" | grep -qE 'trap - ERR( EXIT)?$' \
  && ok "rollback_system disarms the ERR trap on entry" \
  || no "rollback_system disarms the ERR trap" "its own comment says why"
echo
echo "${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]