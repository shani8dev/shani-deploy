#!/usr/bin/env bash
# The `smb_share` target in scripts/shani-cassini-save.sh.
#
# WHY THIS FILE EXISTS. `tabs/smb.py` calls
# `pkexec shani-cassini-save --target smb_share` to write
# /etc/samba/smb.conf.d/50-shani-cassini.conf. That target has to exist in the
# helper's allowlist for any of it to work, and the failure when it does not is
# a refusal whose message ("unknown target") reads like a plausible answer -
# exactly what `modules-load-target.sh` exists for.
#
# WHAT IS PROVEN HERE, and what is not:
#
#   * PROVEN: the target resolves to the drop-in, with mode 0644, and its
#     validators are `testparm -s` - Samba's own parser, before and after.
#   * NOT PROVEN: that Samba accepts a real stanza. That needs `testparm`, and
#     `samba-libs` is not on a development host, so the whole privileged
#     container route in modules-load-target.sh has no Samba counterpart to
#     copy. **This file cannot run the validator, so nothing here is evidence
#     that a share saves.**
#
# Run it:
#   tests/smb-share-target.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SAVE_SRC="$REPO_ROOT/scripts/shani-cassini-save.sh"
SETTINGS="${SHANI_SETTINGS_DIR:-$REPO_ROOT/../shani-settings}"

[[ -f "$SAVE_SRC" ]] || { echo "no helper at $SAVE_SRC" >&2; exit 1; }

pass=0
fail=0
check() {
    if [[ "$2" == "$3" ]]; then
        printf '  ✓ %s\n' "$1"
        pass=$(( pass + 1 ))
    else
        printf '  ✗ %s (expected %s, got %s)\n' "$1" "$2" "$3" >&2
        fail=$(( fail + 1 ))
    fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Sourced, never `bash file arg` - that only DEFINES the function and exits 0,
# which makes any assertion about it pass while checking nothing.
extract() { sed -n "/^$1()/,/^}/p" "$2" > "$work/$1.sh"; printf '%s' "$work/$1.sh"; }
call() { bash -c 'source "$1"; shift; "$@"' _ "$(extract "$1" "$2")" "$1" "$3" 2>/dev/null; }

echo "smb_share target: $SAVE_SRC"

check "target_path resolves to the drop-in" \
    "/etc/samba/smb.conf.d/50-shani-cassini.conf" \
    "$(call target_path "$SAVE_SRC" smb_share)"
check "target_mode is 0644" "0644" "$(call target_mode "$SAVE_SRC" smb_share)"
check "CONTROL: an unknown target resolves to nothing" "" \
    "$(call target_path "$SAVE_SRC" definitely-not-a-target)"

tv="$(bash -c 'source "$1"; target_validators smb_share; printf "[%s][%s]" \
         "${PRE_VALIDATOR_CMD[*]}" "${POST_VALIDATOR_CMD[*]}"' \
      _ "$(extract target_validators "$SAVE_SRC")" 2>/dev/null)"
check "both validators are testparm -s (Samba's own parser)" \
    "[testparm -s][testparm -s]" "$tv"

# The directory must exist on a real machine, because the helper refuses to
# create a target's parent. This checks the thing that actually makes the
# target reachable: shani-settings shipping the drop-in directory.
check "shani-settings ships the smb.conf.d directory" "yes" \
    "$([[ -d "$SETTINGS/etc/samba/smb.conf.d" ]] && echo yes || echo no)"

smb_conf="$SETTINGS/etc/samba/smb.conf"
if [[ -f "$smb_conf" ]]; then
    check "smb.conf includes the drop-in directory" "1" \
        "$(grep -c '^[[:space:]]*include = /etc/samba/smb.conf.d/\*.conf' "$smb_conf")"
    # The reader must be a different file from the writer, or `pacman -u
    # shani-settings` would replace the file the GUI wrote.
    readme="$SETTINGS/etc/samba/smb.conf.d/00-shani-readme.conf"
    if [[ -f "$readme" ]] && grep -q '^[[:space:]]*[^#[:space:]]' "$readme"; then
        printf '  ✗ the shipped drop-in has a directive in it; it must be comments only\n' >&2
        fail=$(( fail + 1 ))
    else
        printf '  ✓ the shipped drop-in is comment-only, so an update cannot clobber shares\n'
        pass=$(( pass + 1 ))
    fi
else
    printf '  ? no shani-settings checkout at %s - include line not checked\n' "$SETTINGS"
fi

echo
if (( fail == 0 )); then
    printf '✓ %d passed, 0 failed\n' "$pass"
    echo "NOTE: testparm was not run (no samba-libs here). This file proves the"
    echo "      target is wired, not that Samba accepts a real stanza."
    exit 0
fi
printf '✗ %d passed, %d failed\n' "$pass" "$fail" >&2
exit 1