#!/bin/bash
# finalize_boot_entries must clear the EFI variables that OUTRANK the one it sets.
#
# WHY THIS EXISTS. `bootctl set-default` writes only LoaderEntryDefault, and
# systemd-boot's config_select_default_entry() (boot.c) tries, returning on the
# FIRST match:
#
#   1 LoaderEntrySysFail   2 LoaderEntryOneShot   3 LoaderEntryPreferred
#   4 the saved entry       5 LoaderEntryDefault   6 loader.conf's `default`
#
# LoaderEntryDefault is FIFTH. So on a machine where an earlier boot failed,
# LoaderEntrySysFail is still set and still names the dead candidate:
# finalize_boot_entries writes the correct new default, the correct new default
# LOSES, and the machine boots the slot that just failed.
#
# This is the same defect the dracut hook had, one layer up. The hook cleared
# these four variables by writing zero bytes to them - measured on real efivarfs
# to be a silent no-op that exits 0 (shani-testbed/boot-probes/efivar-proof.sh). The
# hook now unlinks and verifies. Nothing had ever checked that shani-deploy does
# the same, and finalize-boot-entries-test.sh contains no assertion about EFI
# variables at all.
#
# It matters most for ROLLBACK. switch_to_sibling_slot() - which both `deploy -r`
# and same-slot failure recovery go through - calls finalize_boot_entries, so a
# rollback on a machine with a stale LoaderEntrySysFail wrote the right default
# and then booted the failed slot anyway.
#
#   shani-deploy/tests/test-finalize-boot-efivars.sh      (host-only, no root, no disks)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(dirname "$HERE")/.."
DEPLOY="$HERE/../scripts/shani-deploy.sh"
pass=0 fail=0
# LoaderEntryPreferred is NOT cleared any more: `bootctl set-preferred` writes it
# right after this block (shani-deploy.sh says why), so it must survive
HIGH="LoaderEntrySysFail LoaderEntryOneShot"
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; fail=$((fail + 1)); }

[[ -f $DEPLOY ]] || { echo "shani-deploy.sh not found at $DEPLOY" >&2; exit 2; }

# Lift finalize_boot_entries' real EFI-clearing block out of the real script,
# rather than hand-copying it. A hand-copy is how the dracut hook's own test
# came to carry the same bug it was written to catch.
extract_block() {
  python3 - "$DEPLOY" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
start = src.find('local _efivarfs="${SHANIOS_EFIVARS_DIR')
if start < 0:
    raise SystemExit("no _efivarfs assignment found - has the fix moved?")
# up to the first bootctl CALL - not a comment that names one (the block's own
# comments do, and cutting there dropped the rm)
pos = start
for line in src[start:].splitlines(keepends=True):
    if 'bootctl ' in line and not line.lstrip().startswith('#'):
        break
    pos += len(line)
else:
    raise SystemExit("no bootctl call after the block")
print(src[start:pos])
PY
}

if ! BLOCK=$(extract_block 2>"${TMPDIR:-/tmp}/fbe.err"); then
  no "the EFI-clearing block is present in shani-deploy.sh" "$(cat "${TMPDIR:-/tmp}/fbe.err")"
  echo; echo "${pass} passed, ${fail} failed"; exit 1
fi
ok "the EFI-clearing block is present in shani-deploy.sh"

# Mutation (a) - restoring the literal pre-fix form, in which the block exists
# but clears nothing - was GREEN, because every other assertion is about effect
# and with no clearing there is simply nothing to observe. An effect-only test
# of a fix that adds a mechanism cannot fail when the mechanism is removed; it
# needs one assertion on the mechanism itself.
for n in $HIGH; do
  grep -q "$n" <<<"$BLOCK" \
    && ok "$n is named in the clearing code, not merely handled" \
    || no "$n is named in the clearing code" "absent from the block"
done
grep -qE 'rm -f "\$_f"' <<<"$BLOCK" \
  && ok "the block unlinks - a zero-byte write does NOT delete on efivarfs" \
  || no "the block unlinks" "no rm -f: a write is a silent no-op on efivarfs"

mkfake() { # <dir> [names...]
  local d="$1"; shift; mkdir -p "$d"
  local n
  for n in "$@"; do printf 'x' > "$d/${n}-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"; done
}

run_block() { # <efivars-dir> -> prints the names it cleared
  # A function wrapper, because the lifted block uses `local` and `local`
  # outside a function is an error - which, under `set -u`, reads as the block
  # not having run rather than as a harness mistake.
  ( set -uo pipefail
    _drive() {
      SHANIOS_EFIVARS_DIR="$1"
      log_verbose() { :; }
      eval "$BLOCK"
      printf 'CLEARED:%s\n' "${_cleared_efv[*]-}"
    }
    _drive "$1"
  ) 2>/dev/null
}

echo
echo "== the two higher-precedence variables are removed"
E=$(mktemp -d); mkfake "$E" $HIGH LoaderEntryPreferred LoaderEntryDefault
OUT=$(run_block "$E")
for n in $HIGH; do
  if ls "$E/${n}-"* >/dev/null 2>&1; then
    no "$n is removed" "node still present - it outranks the default being set"
  else
    ok "$n is removed"
  fi
done

echo
echo "== LoaderEntryPreferred is NOT cleared (set-preferred writes it next)"
if ls "$E/LoaderEntryPreferred-"* >/dev/null 2>&1; then
  ok "LoaderEntryPreferred survives"
else
  no "LoaderEntryPreferred survives" "cleared, then set-preferred would race over it"
fi

echo
echo "== LoaderEntryDefault is NOT cleared (that is the one being set)"
# `[[ -e DIR/pattern ]]` is a glob that [[ never expands, so the first version
# of this assertion tested a literal filename that does not exist and reported
# the variable as deleted when nothing had touched it. compgen -G does expand,
# and an empty result is the honest "not there".
if compgen -G "$E/LoaderEntryDefault-*" >/dev/null 2>&1; then
  ok "LoaderEntryDefault survives - finalize_boot_entries is about to set it"
else
  no "LoaderEntryDefault survives" "the block deleted the variable it sets"
fi

echo
echo "== it reports what it cleared, and only what it really cleared"
echo "$OUT" | grep -q 'LoaderEntrySysFail' \
  && ok "it reports LoaderEntrySysFail as cleared" \
  || no "it reports what it cleared" "got [$(echo "$OUT" | tail -1)]"
echo "$OUT" | grep -q 'LoaderEntryDefault' \
  && no "it does not claim to have cleared the variable it sets" "reported LoaderEntryDefault" \
  || ok "it does not claim to have cleared the variable it sets"

echo
echo "== a machine with none of them set is left alone and claims nothing"
E2=$(mktemp -d); mkfake "$E2" LoaderDevicePartUUID LoaderInfo
OUT2=$(run_block "$E2")
[[ -e "$E2/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f" ]] \
  && ok "a GRUB host's variables survive untouched" \
  || no "a GRUB host's variables survive" "LoaderDevicePartUUID was deleted"
echo "$OUT2" | tail -1 | grep -qE 'CLEARED:$' \
  && ok "nothing is claimed when there was nothing to clear" \
  || no "nothing is claimed when there was nothing to clear" "got [$(echo "$OUT2" | tail -1)]"

echo
echo "== an absent efivarfs directory is not an error"
# A BIOS machine has no efivarfs at all. The block must be a no-op there, and -
# this bit me writing the test - the last line is `[[ ... ]] && log_verbose`,
# whose exit status is 1 when nothing was cleared. That is CORRECT shell, but it
# made the whole block "fail" under a harness that judges the exit status. So
# the assertion is on the behaviour (nothing cleared, nothing deleted), and the
# exit status is normalised rather than treated as the verdict: a deploy must
# not die here, and `set -e` is not in force in shani-deploy's function.
# `local` is only legal inside a function, so the lifted block has to be driven
# from one - `eval` at top level makes every `local` in it an error and, under
# `set -u`, the failure looks like the block "not running" rather than like a
# harness bug. run_block below wraps it for the same reason.
out=$(run_block "$E/does-not-exist")
if [[ $out == "CLEARED:" ]]; then
  ok "a machine with no efivarfs (BIOS) clears nothing"
else
  no "a machine with no efivarfs clears nothing" "got [$out]"
fi
# A fresh directory, not $E: the earlier scenarios deliberately populated that
# one, so "leaves the scratch dir alone" was asserting against a directory this
# test had itself filled and had nothing to do with the block.
E3=$(mktemp -d); mkfake "$E3" LoaderEntrySysFail
run_block "$E3/does-not-exist" >/dev/null
if compgen -G "$E3/LoaderEntrySysFail-*" >/dev/null 2>&1; then
  ok "a BIOS run creates nothing and deletes nothing"
else
  no "a BIOS run creates nothing and deletes nothing" "the node was removed with no efivarfs"
fi
rm -rf "$E3"

rm -rf "$E" "$E2"
echo
echo "${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]