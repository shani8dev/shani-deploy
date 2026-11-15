#!/bin/bash
# Which slot does `shani-deploy --rollback` end up defaulting to, and why?
#
# WHY THIS EXISTS. `rollback_system()` picks between four outcomes from the
# state it finds:
#
#   go-back        switch the default to the sibling, touch nothing
#   repair         restore the failed slot FROM its backup
#   repair-copy    the failed slot has no backup, so snapshot the BOOTED slot
#                  into it
#   same-slot      the booted slot itself failed -> switch the default only
#
# Getting one wrong is destructive in a way nothing catches today:
# `rollback_system` and `restore_candidate` are the two functions that decide
# which system a machine comes up in after a failure, and between them they had
# NO test coverage at all. Both have already produced real damage:
#
#   - a rollback that overwrote the previous system with a copy of the new one
#     (found by shani-testbed's gate, 2026-09-24). It exited 0.
#   - the version comparison that was added for it then destroyed the previous
#     system on a SAME-DAY build, where the two versions tie (found by
#     `rollback:restored`, 2026-10-01). Also exited 0.
#
# Both bugs were "the branch was taken that should not have been", and both were
# invisible to every assertion, because the assertions looked at the resulting
# versions and not at which branch ran.
#
# This drives the DECISION BLOCK verbatim out of the real script - it lifts the
# text rather than restating it, so the branch cannot drift from what ships. A
# hand-copy is how the dracut hook's own test came to carry the same bug it was
# written to catch.
#
#   shani-deploy/tests/test-rollback-decision.sh        (host-only, no root, no disks)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(dirname "$HERE")/.."
DEPLOY="$HERE/../scripts/shani-deploy.sh"
TMPROOT=$(mktemp -d /tmp/rollback-decision.XXXXXX)
trap 'rm -rf "$TMPROOT"' EXIT
pass=0 fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; fail=$((fail + 1)); }

[[ -f $DEPLOY ]] || { echo "shani-deploy.sh not found at $DEPLOY" >&2; exit 2; }

# Lift the decision block: from the first `local _bv _ov` through the end of the
# "no backup" branch. Everything before it derives `booted`/`failed_slot` from
# simple inputs this harness supplies directly.
DECIDE=$(python3 - "$DEPLOY" <<'PY'
import sys
src = open(sys.argv[1]).read()
start = src.find("    local _bv _ov")
if start < 0:
    raise SystemExit("the version-comparison block is gone - has rollback_system moved?")
end = src.find('    log "Restoring @${failed_slot} from @${BACKUP_NAME}"', start)
if end < 0:
    raise SystemExit("the repair branch is gone")
print(src[start:end])
PY
) || { echo "could not lift the decision block" >&2; exit 2; }

DECIDE_OK=1
[[ -n $DECIDE ]] || { no "the decision block was located" "empty"; DECIDE_OK=0; }
[[ $DECIDE_OK -eq 1 ]] && ok "the decision block was located in shani-deploy.sh"

# Run it against a described state. Echoes which branch was taken.
run() { # <booted> <recorded_fail|none> <booted-version> <sibling-version> <sibling-has-backup:yes|no>
  local booted="$1" recfail="$2" bv="$3" ov="$4" hasbackup="$5"
  # The sentinel is `none` so the call sites read clearly, but the code under
  # test uses `-z "$recorded_fail"`, so the sentinel has to become EMPTY here.
  # Passing `none` straight through made every "no recorded failure" branch test
  # false, and the harness silently exercised only the failure paths - five of
  # its cases passing for a reason that had nothing to do with the branches.
  [[ "$recfail" == none ]] && recfail=""
  local M="$TMPROOT/mnt" out=""
  rm -rf "$M"; mkdir -p "$M/@data" "$M/@${booted}/etc" "$M/@$([ "$booted" = blue ] && echo green || echo blue)/etc"
  printf '%s' "$bv" > "$M/@${booted}/etc/shani-version"
  sib=$([ "$booted" = blue ] && echo green || echo blue)
  printf '%s' "$ov" > "$M/@$sib/etc/shani-version"
  [[ -n "$recfail" ]] && printf '%s' "$recfail" > "$M/@data/boot_failure"
  [[ "$hasbackup" == yes ]] && printf '  @%s_backup_20260101010101\n' "$sib" > "$M/subvol-list"
  : > "$M/subvol-list-empty"
  out=$( (
    set -uo pipefail
    _HAY_BACKUP="$hasbackup"
    MOUNT_DIR="$M"
    recorded_fail="${recfail:-}"
    # The lifted block references booted and failed_slot, which rollback_system
    # derives before the block starts. They must be set HERE: as locals of
    # run() they are not visible to this subshell, and the block died on
    # `booted: unbound variable` under set -u - before reaching either branch,
    # which reported as "took the repair path" for every case.
    booted="$booted"
    sib=$([ "$booted" = blue ] && echo green || echo blue)
    failed_slot="$sib"
    _bv="$bv"; _ov="$ov"
    _HAY_BACKUP="$hasbackup"
    # The branch under test calls switch_to_sibling_slot, which needs btrfs and
    # a real ESP. Stub it: the question is WHICH branch runs, and stubbing it
    # means the branch cannot half-execute and look like another one.
    switch_to_sibling_slot() { echo "BRANCH:go-back"; }
    log()      { :; }
    log_warn() { :; }
    log_success() { :; }
    # $hasbackup is a local of run(), so the subshell does not have it unless
    # it is passed in explicitly. The first version relied on bash's dynamic
    # scoping reaching into the function, which it does not - so the stub
    # always reported "no backups" and every no-backup case silently behaved
    # like a backup case.
    btrfs() { if [[ "${1:-}" == subvolume && "${2:-}" == list ]]; then
                if [[ "${_HAY_BACKUP:-no}" == yes ]]; then cat "$M/subvol-list"; else cat "$M/subvol-list-empty"; fi
              fi; }
    eval "$DECIDE"
  ) 2>/dev/null )
  if grep -q BRANCH:go-back <<<"$out"; then echo "go-back"; else echo "repair"; fi
}

echo
echo "== a newer booted slot with no recorded failure goes BACK, not forward"
# This is the 2026-09-24 damage: the repair path would snapshot the booted slot
# over the previous system, destroying it.
[[ $(run blue none 20261010 20260925 yes) == "go-back" ]] \
  && ok "booted v20261010 > sibling v20260925 -> go-back, previous system preserved" \
  || no "a newer booted slot goes back" "took the repair path, which overwrites the previous system"

echo
echo "== a TIE is decided by the BACKUP, not by the comparison"
# The 2026-10-01 damage: the version comparison was strict `>`, so a tie fell
# through to repair and destroyed the previous system. It is now caught by the
# separate no-backup branch below - a deploy backs up the slot it WRITES INTO, so
# a sibling with no backup was never deployed onto and is the intact previous
# system. So the rule is: a tie with a backup is a real deploy and repairs; a
# tie with NO backup is the previous system and goes back.
[[ $(run blue none 20261001 20261001 no) == "go-back" ]] \
  && ok "tie + no backup -> go-back (the 2026-10-01 case)" \
  || no "tie with no backup goes back" "took the repair path and overwrites the previous system"
[[ $(run blue none 20261001 20261001 yes) == "repair" ]] \
  && ok "tie + a backup present -> repair (a real deploy onto that slot)" \
  || no "tie with a backup repairs" "went back past a genuine deploy"

echo
echo "== a recorded failure DOES repair (the case the branches exist for)"
# The whole point of the two go-back branches is that they only fire when there
# is NO evidence of failure. With a marker recorded, repair is correct - and a
# check that cannot fail would be one that never distinguishes these.
[[ $(run blue blue 20261010 20260925 yes) == "repair" ]] \
  && ok "recorded failure -> repair, even though versions favour go-back" \
  || no "a recorded failure repairs" "went back and left the failed slot alone"
[[ $(run green green 20260925 20261010 yes) == "repair" ]] \
  && ok "recorded failure on the other slot -> repair" \
  || no "a recorded failure on the other slot repairs" "went back"

echo
echo "== an OLDER booted slot is already the rollback target"
[[ $(run blue none 20260925 20261010 yes) == "repair" ]] \
  && ok "booted older than sibling with no marker -> repair (nothing to roll back to)" \
  || no "an older booted slot repairs" "went back to a NEWER system"

echo
echo "== the tie rule is a SEPARATE branch, not an accident of the comparison"
# Both damage reports came from the boundary of `_bv > _ov`. The tie is now
# handled by its own branch keyed on the absence of a backup, so re-tightening
# or loosening the comparison cannot silently change tie behaviour. Assert the
# STRUCTURE, because the outcome tests above pass either way if someone merges
# the two branches.
grep -qE '_bv +>+ +_ov' <<<"$DECIDE" \
  && ok "the version comparison is still strict >" \
  || no "the version comparison is still >" "the comparison changed; see the two damage reports"
if grep -qE 'failed_slot}_backup_' <<<"$DECIDE" && grep -q 'BRANCH\|switch_to_sibling_slot "$booted" go-back' <<<"$DECIDE"; then
  ok "a no-backup sibling is decided by a branch of its own, which is what makes a tie safe"
else
  no "the no-backup branch exists" "the tie now depends on the comparison alone"
fi

echo
echo "${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]