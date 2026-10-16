#!/usr/bin/env bash
# The `modprobe_blacklist` target in scripts/shani-cassini-save.sh.
#
# WHY THIS FILE EXISTS. It is the companion of `modules-load-target.sh`, which
# proves the `modules_load` target against a real kmod in a privileged
# container. That container route is deliberately not repeated here for the
# blacklist, because **almost everything that can be wrong about this target is
# checkable without root**. The part that needs root (the atomic install, the
# read-back, the rollback) is generic helper machinery modules-load-target.sh
# already covers. What is target-specific is exactly what this file drives.
#
# The three real defects this target is shaped around, each asserted below
# rather than merely described:
#
#   1. **An empty file must be accepted.** `check_modules_load_file` refuses a
#      file that "names no modules at all", and copying that rule here would
#      break the one save that always has to work - removing the last
#      blacklisted module. The result of that removal IS an empty file.
#
#   2. **`modprobe -R` must NOT be used as the validator.** A blacklist names
#      modules that must NOT load, and the entries a user most wants are
#      routinely ones the running kernel does not carry. modules_load's
#      validator refuses a name modprobe cannot resolve; doing the same here
#      would refuse exactly the entries the page exists to offer.
#
#   3. **`(( lineno++ ))` aborts under this file's `set -e`.** Found by running
#      this file, not by writing it. A bare post-increment evaluates to the
#      PRE-increment value and 0 is falsy, so the validator aborted on the first
#      line of every non-empty file and printed nothing at all - while an EMPTY
#      file passed, which made it look correct. The same defect is already
#      recorded and fixed in this file for `((issues++))` and
#      `((format_count++))`; NEGATIVE CONTROL 1 re-introduces it.
#
# Run it:
#   tests/modprobe-blacklist-target.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SAVE_SRC="$REPO_ROOT/scripts/shani-cassini-save.sh"

[[ -f "$SAVE_SRC" ]] || { echo "no helper at $SAVE_SRC" >&2; exit 1; }

pass=0
fail=0
check() { # check <name> <expected> <actual>
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

echo "modprobe_blacklist target: $SAVE_SRC"

# ── 1. the allowlist knows the target ─────────────────────────────────────────
# `target_path()` is extracted and **sourced**, then called. It has to be done
# that way for two reasons, and the second is the worse.
#
#   * The helper checks for root BEFORE it resolves a target, so as an ordinary
#     user every target - known or not - refuses with "must run as root" and the
#     allowlist cannot be observed at all. An earlier version of this file
#     asserted on that refusal and so proved nothing: it passed for a target the
#     helper had never heard of, which is the exact failure this section exists
#     to prevent.
#   * Running the extracted copy with `bash file arg` **defines** the function
#     and never calls it, so it prints nothing and exits 0. That is what made
#     the `target_validators` assertion below pass for a function that was never
#     invoked - a control reporting a pass while checking nothing. So the copy is
#     sourced and the call is made explicitly.
extract_fn() { # extract_fn <fn-name> <source-file> -> extracted copy path
    local name="$1" src="$2" out="$work/fn-$1.sh"
    sed -n "/^${name}()/,/^}/p" "$src" > "$out"
    printf '%s' "$out"
}

call_fn() { # call_fn <fn-name> <source-file> <arg> -> the function's stdout
    local copy
    copy="$(extract_fn "$1" "$2")"
    bash -c 'source "$1"; shift; "$@"' _ "$copy" "$1" "$3" 2>/dev/null
}

check "target_path resolves modprobe_blacklist to its drop-in" \
    "/etc/modprobe.d/50-shani-blacklist.conf" \
    "$(call_fn target_path "$SAVE_SRC" modprobe_blacklist)"

check "target_mode is 0644" "0644" \
    "$(call_fn target_mode "$SAVE_SRC" modprobe_blacklist)"

# An unknown target must resolve to nothing, or the two checks above cannot
# discriminate. This is the control for the controls.
check "CONTROL: an unknown target resolves to nothing" "" \
    "$(call_fn target_path "$SAVE_SRC" definitely-not-a-target)"

# target_validators assigns three globals rather than printing, so it is run in
# a subshell that reports what it left behind - an exit status alone says
# nothing about which validator was wired.
tv_out="$(bash -c 'source "$1"; target_validators modprobe_blacklist; rc=$?;
                    printf "rc=%s pre=[%s] post=[%s]" "$rc" \
                        "${PRE_VALIDATOR_CMD[*]}" "${POST_VALIDATOR_CMD[*]}"' \
                 _ "$(extract_fn target_validators "$SAVE_SRC")" 2>/dev/null)"
if [[ "$tv_out" == *"check-modprobe-blacklist"* ]]; then
    printf '  ✓ target_validators wires modprobe_blacklist to the structural checker\n'
    pass=$(( pass + 1 ))
else
    printf '  ✗ no validator wired for modprobe_blacklist (got: %s)\n' "$tv_out" >&2
    fail=$(( fail + 1 ))
fi

# ── 2. the structural validator ───────────────────────────────────────────────
printf '# Managed by Shani Cassini\nblacklist kvm_intel\nblacklist floppy\n' \
    > "$work/good.conf"
bash "$SAVE_SRC" --check-modprobe-blacklist "$work/good.conf" >/dev/null 2>&1
check "a well-formed fragment is accepted" 0 "$?"

# defect 1: empty is the legitimate "clear the blacklist" state
: > "$work/empty.conf"
bash "$SAVE_SRC" --check-modprobe-blacklist "$work/empty.conf" >/dev/null 2>&1
check "an EMPTY fragment is accepted (that is how a blacklist is cleared)" 0 "$?"

printf '   \n\t\n# comments only\n' > "$work/comments.conf"
bash "$SAVE_SRC" --check-modprobe-blacklist "$work/comments.conf" >/dev/null 2>&1
check "comments and blank lines only is accepted" 0 "$?"

printf 'options floppy\n' > "$work/bad-directive.conf"
bash "$SAVE_SRC" --check-modprobe-blacklist "$work/bad-directive.conf" >/dev/null 2>&1
check "REFUSED: a directive that is not a blacklist line" 1 "$?"

printf 'blacklist ../escape\n' > "$work/bad-path.conf"
bash "$SAVE_SRC" --check-modprobe-blacklist "$work/bad-path.conf" >/dev/null 2>&1
check "REFUSED: a module name containing a path" 1 "$?"

printf 'blacklist two words\n' > "$work/bad-two.conf"
bash "$SAVE_SRC" --check-modprobe-blacklist "$work/bad-two.conf" >/dev/null 2>&1
check "REFUSED: two tokens after blacklist" 1 "$?"

bash "$SAVE_SRC" --check-modprobe-blacklist "$work/does-not-exist.conf" >/dev/null 2>&1
check "REFUSED: a path that does not exist" 1 "$?"

# defect 2, asserted as a property of the source: modprobe must not be this
# target's authority.
if sed -n '/^check_modprobe_blacklist_file/,/^}/p' "$SAVE_SRC" | grep -q 'modprobe '; then
    printf '  ✗ the blacklist validator runs modprobe (it must not)\n' >&2
    fail=$(( fail + 1 ))
else
    printf '  ✓ the blacklist validator does not ask modprobe (an unloadable name stays storable)\n'
    pass=$(( pass + 1 ))
fi

# ── 3. NEGATIVE CONTROL 1: the (( lineno++ )) abort ───────────────────────────
sed 's/lineno=$(( lineno + 1 ))/(( lineno++ ))/' "$SAVE_SRC" > "$work/buggy.sh"
bash "$work/buggy.sh" --check-modprobe-blacklist "$work/good.conf" >/dev/null 2>&1
check "NEGATIVE CONTROL: the (( lineno++ )) bug is caught" 1 "$?"

# ── 4. NEGATIVE CONTROL 2: the target removed from the allowlist ──────────────
sed '/modprobe_blacklist) printf/d' "$SAVE_SRC" > "$work/no-target.sh"
check "NEGATIVE CONTROL: dropping the target makes it resolve to nothing" "" \
    "$(call_fn target_path "$work/no-target.sh" modprobe_blacklist)"

# ── 5. NEGATIVE CONTROL 3: the empty-is-valid rule removed ────────────────────
# If someone copies modules_load's "names no modules at all" refusal into this
# target, removing the last blacklisted module becomes impossible.
if python3 - "$SAVE_SRC" "$work/no-empty-rule.sh" <<'PY'
import sys, pathlib
src = pathlib.Path(sys.argv[1]).read_text()
start = src.index("check_modprobe_blacklist_file()")
end = src.index("\n}", start)
body = src[start:end]
mutated = body.replace(
    "    return 0",
    '    if [[ ! -s "$file" ]]; then return 1; fi\n    return 0',
)
if mutated == body:
    # Refusing to write an unmutated copy: a control built from a mutation that
    # did not apply passes vacuously, which is the failure this whole file is
    # shaped around.
    sys.stderr.write("MUTATION DID NOT APPLY\n")
    sys.exit(1)
pathlib.Path(sys.argv[2]).write_text(src[:start] + mutated + src[end:])
PY
then
    bash "$work/no-empty-rule.sh" --check-modprobe-blacklist "$work/empty.conf" >/dev/null 2>&1
    check "NEGATIVE CONTROL: a copied 'names nothing' refusal is caught" 1 "$?"
else
    printf '  ✗ NEGATIVE CONTROL 3 could not be built (refusing to report a pass)\n' >&2
    fail=$(( fail + 1 ))
fi

echo
if (( fail == 0 )); then
    printf '✓ %d passed, 0 failed\n' "$pass"
    exit 0
fi
printf '✗ %d passed, %d failed\n' "$pass" "$fail" >&2
exit 1