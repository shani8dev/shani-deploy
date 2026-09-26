#!/bin/bash
# tests/test-list-backups-json.sh — contract tests for
# `shani-deploy --list-backups --json`, the machine-readable backup listing
# (Shani Cassini's Updates & Rollback page consumes it).
#
# Same technique as tests/test-status-json.sh, deliberately: the real
# functions are EXTRACTED from scripts/shani-deploy.sh with sed and `eval`ed
# verbatim (never reimplemented here), run in a subshell carrying the real
# script's `set -Eeuo pipefail`, against a mktemp -d sandbox. Only the
# privileged/environment bits are stubbed — `mount`, `btrfs`, `du`,
# `check_root`, `safe_umount`, `force_umount_all` — because this suite must
# run on an ordinary unprivileged host with no Btrfs and no /data.
#
# The second half drives the REAL main() (arg parsing + dispatch + the
# --check/--json guard) by sourcing the script with its final `main "$@"`
# line removed, so the guard tests are not a re-implementation either.
#
# B1: --list-backups --json additionally reports each slot's OS version,
# read from the slot's own /etc/shani-version — the same file
# rollback_system() already reads, so the two can never disagree. The
# version deliberately does NOT appear in --status --json: that function is
# dispatched before check_root, and mounting there would break its
# unprivileged, lock-free contract (20 tests in test-status-json.sh).

set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ok    $1"; }
fail(){ FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }
summary() {
    echo ""
    if (( FAIL > 0 )); then echo "✗ $PASS passed, $FAIL failed"; exit 1; fi
    echo "✓ $PASS passed, 0 failed"
}

DEPLOY=../scripts/shani-deploy.sh
[[ -f "$DEPLOY" ]] || { echo "missing $DEPLOY"; exit 1; }

################################################################################
# Extract the real functions
################################################################################
LIST_JSON_FN=$(sed -n '/^list_backups_json() {/,/^}/p' "$DEPLOY")
if [[ -z "$LIST_JSON_FN" ]]; then
    fail "list_backups_json() exists in $DEPLOY" "could not extract list_backups_json() from $DEPLOY"
    echo ""
    echo "✗ $PASS passed, $FAIL failed"
    exit 1
fi
ok "list_backups_json() exists in $DEPLOY"

# The helper that actually walks the subvolumes is optional at this point so
# that a missing implementation reports as a data failure (not an extraction
# failure); the abort/RETURN-trap test below fails loudly if it is absent.
COLLECT_FN=$(sed -n '/^_list_backups_json_collect() {/,/^}/p' "$DEPLOY")

################################################################################
# Sandbox: a fake subvolid=5 tree
################################################################################
SB=$(mktemp -d)
trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/mnt/@blue/etc" "$SB/mnt/@green/etc" \
         "$SB/mnt/@blue_backup_20260915120000" \
         "$SB/mnt/@blue_backup_20260910093000"
printf 'v20260915\n'  > "$SB/mnt/@blue/etc/shani-version"
printf '20260914\n'   > "$SB/mnt/@green/etc/shani-version"
# @green deliberately has NO backup subvolume: it must still be reported, with
# its version and an empty backup list.
cat > "$SB/svol_list" <<'EOF'
ID 257 gen 42 top level 5 path @blue
ID 258 gen 43 top level 5 path @green
ID 259 gen 44 top level 5 path @blue_backup_20260915120000
ID 260 gen 45 top level 5 path @blue_backup_20260910093000
ID 261 gen 46 top level 5 path @data
ID 262 gen 47 top level 5 path @blue_backup_2026091
ID 263 gen 48 top level 5 path @home
EOF

# A `jq` that always fails, used for the abort/RETURN-trap test.
mkdir -p "$SB/badbin"
printf '#!/bin/sh\nexit 1\n' > "$SB/badbin/jq"
chmod +x "$SB/badbin/jq"

# --- stubs -------------------------------------------------------------------
_btrfs_stub() {
    case "${1:-} ${2:-}" in
        "subvolume list")
            cat "$SB/svol_list"
            ;;
        "subvolume show")
            local n created tabs
            n=$(basename "${3:-}")
            if [[ -n "${STUB_CREATED:-}" ]]; then
                created="$STUB_CREATED"
            else
                case "$n" in
                    *20260915120000) created="2026-09-15 12:00:00 +0000" ;;
                    *20260910093000) created="2026-09-10 09:30:00 +0000" ;;
                    *)               created="unknown" ;;
                esac
            fi
            # btrfs pads this label with a VARIABLE number of tabs depending
            # on the field; deliberately differ between the two subvolumes so
            # the test fails for any fixed-field parse ($2/$NF) rather than
            # only for a broken one.
            case "$n" in
                *20260915120000) tabs=$'\t\t\t' ;;
                *)               tabs=$'\t\t' ;;
            esac
            printf 'Name: \t\t\t%s\n'                 "$n"
            printf 'UUID: \t\t\tdeadbeef-0000-0000-0000-000000000000\n'
            printf 'Creation time: %s%s\n'           "$tabs" "$created"
            printf 'Subvolume ID: \t\t256\n'
            ;;
        *) return 1 ;;
    esac
}
_du_stub() { printf '%s\t%s\n' "${STUB_SIZE:-1.2G}" "${*: -1}"; }

# emit <fn-source> [VAR=VALUE ...] — runs the real function in a subshell
# with the real script's strict mode, in the fake tree. The VAR=VALUE pairs
# are exported *inside* the subshell (a prefix assignment on a function call
# is bash-magic we don't want a contract test to depend on).
emit() {
    local list_json_src="$1"; shift
    (
        set -Eeuo pipefail
        local _kv
        for _kv in "$@"; do export "${_kv?}"; done
        MOUNT_DIR="$SB/mnt"
        ROOT_DEV="$SB/fake-root"
        LOG_FILE="$SB/deploy.log"
        check_root()       { :; }
        die()              { echo "DIE: $*" >&2; exit 1; }
        mount()            { echo "mount" >> "$SB/calls"; return 0; }
        safe_umount()      { echo "umount" >> "$SB/calls"; return 0; }
        force_umount_all() { echo "force_umount" >> "$SB/calls"; return 0; }
        btrfs()            { _btrfs_stub "$@"; }
        du()               { _du_stub "$@"; }
        # shellcheck disable=SC2086
        eval "$COLLECT_FN"
        eval "$list_json_src"
        list_backups_json
    ) 2>/dev/null
}

jqf() { printf '%s' "$1" | jq -r "$2" 2>/dev/null; }
# Concatenated side-effect log; absent file reads as "" instead of erroring.
calls_str() { [[ -f "$1" ]] && tr '\n' ',' < "$1" || echo ""; }

echo "────────────────── list-backups --json contract tests ──────────────────"

################################################################################
# 1. The data actually has to be there. A bare `{}` stub — or anything that
#    is not the real implementation — fails here.
################################################################################
out=$(emit "$LIST_JSON_FN")
if printf '%s' "$out" | jq -e '.slots' >/dev/null 2>&1; then
    ok "emits a top-level .slots array"
else
    fail "emits a top-level .slots array" \
         "jq -e '.slots' -> $(printf '%s' "$out" | jq -e '.slots' 2>&1 | head -1)  full output: ${out:-<empty>}"
fi

if printf '%s' "$out" | jq -e 'type == "object"' >/dev/null 2>&1; then
    ok "output is a single JSON object (not a stream/lines)"
else
    fail "output is a single JSON object (not a stream/lines)" "${out:-<empty>}"
fi

if [[ $(jqf "$out" '.slots | length') == 2 ]]; then
    ok "both slots are reported"
else
    fail "both slots are reported" "got $(jqf "$out" '[.slots[].slot] | join(",")')  raw: ${out:-<empty>}"
fi

# 2. Per-slot version (the B1 payload) — read from the slot's own
#    /etc/shani-version, digits only, exactly like rollback_system().
if [[ $(jqf "$out" '.slots[] | select(.slot=="blue")  | .version') == 20260915 \
   && $(jqf "$out" '.slots[] | select(.slot=="green") | .version') == 20260914 ]]; then
    ok "each slot reports its own OS version"
else
    fail "each slot reports its own OS version" \
         "blue=$(jqf "$out" '.slots[]|select(.slot=="blue")|.version') green=$(jqf "$out" '.slots[]|select(.slot=="green")|.version')  raw: ${out:-<empty>}"
fi

# 3. A slot with no backups at all still appears, with its version and an
#    empty (not null, not missing) backup list.
if [[ $(jqf "$out" '.slots[] | select(.slot=="green") | .backups | length') == 0 \
   && $(jqf "$out" '.slots[] | select(.slot=="green") | .backups | type') == array ]]; then
    ok "slot with no backups still reported with a version and empty backups[]"
else
    fail "slot with no backups still reported with a version and empty backups[]" \
         "green=$(jqf "$out" '.slots[]|select(.slot=="green")')  raw: ${out:-<empty>}"
fi

# 4. The backups themselves: name / created / size, only real
#    @<slot>_backup_<10-14 digits> subvolumes, sorted.
if [[ $(jqf "$out" '.slots[] | select(.slot=="blue") | .backups | length') == 2 ]]; then
    ok "blue reports its two backups"
else
    fail "blue reports its two backups" \
         "$(jqf "$out" '.slots[]|select(.slot=="blue")|.backups')  raw: ${out:-<empty>}"
fi
if [[ $(jqf "$out" '.slots[]|select(.slot=="blue")|.backups|map(.name)|join(",")') \
   == "@blue_backup_20260910093000,@blue_backup_20260915120000" ]]; then
    ok "backups are named exactly and sorted ascending (malformed @blue_backup_2026091 ignored)"
else
    fail "backups are named exactly and sorted ascending (malformed @blue_backup_2026091 ignored)" \
         "got: $(jqf "$out" '.slots[]|select(.slot=="blue")|.backups|map(.name)|join(",")')"
fi
if [[ $(jqf "$out" '.slots[]|select(.slot=="blue")|.backups[0].created') == "2026-09-10 09:30:00 +0000" \
   && $(jqf "$out" '.slots[]|select(.slot=="blue")|.backups[0].size')  == "1.2G" ]]; then
    ok "each backup carries its creation time and size"
else
    fail "each backup carries its creation time and size" \
         "$(jqf "$out" '.slots[]|select(.slot=="blue")|.backups[0]')"
fi
# A backup subvolume only ever belongs to its own slot.
if [[ $(jqf "$out" '[.slots[].backups[].name] | length') == 2 \
   && $(jqf "$out" '[.slots[].backups[].name] | all(startswith("@blue_backup_"))') == true ]]; then
    ok "backups are attributed to the right slot"
else
    fail "backups are attributed to the right slot" "$(jqf "$out" '[.slots[].backups[].name]')"
fi

# 5. NEGATIVE CONTROL — the printf-vs-jq hazard. `btrfs subvolume show`'s
#    "Creation time:" value is free-form: it can contain spaces, colons,
#    quotes and backslashes. A printf-built JSON document breaks on the
#    quote/backslash; jq -nc --arg cannot. If this implementation ever
#    regresses to string concatenation, this is the test that catches it.
GARBAGE='weird "quoted" \ backslash : with : colons and spaces'
out=$(emit "$LIST_JSON_FN" "STUB_CREATED=$GARBAGE")
# Both halves matter: `jq -e .` alone would pass vacuously on a `{}` stub, so
# the value must also be present in a backup entry. --arg (not interpolation
# into the jq program — the value contains quotes and a backslash).
if printf '%s' "$out" | jq -e --arg g "$GARBAGE" '[.slots[].backups[].created] | index($g) != null' >/dev/null 2>&1; then
    ok "garbage Creation time (quotes/backslashes/colons) still yields valid JSON"
else
    fail "garbage Creation time (quotes/backslashes/colons) still yields valid JSON" \
         "jq rejected it or lost the value: ${out:-<empty>}"
fi
if [[ $(jqf "$out" '.slots[]|select(.slot=="blue")|.backups[0].created') == "$GARBAGE" ]]; then
    ok "garbage Creation time survives round-trip verbatim (escaped, not mangled)"
else
    fail "garbage Creation time survives round-trip verbatim (escaped, not mangled)" \
         "got: $(jqf "$out" '.slots[]|select(.slot=="blue")|.backups[0].created')"
fi
# Proof the hazard is real rather than hypothetical: the SAME value dropped
# into a printf-built template — the style this function must not use, and the
# style status_json() uses for its already-sanitized fields — produces a
# document jq cannot parse. If this ever stops being true, the jq choice in
# list_backups_json() is no longer load-bearing and can be revisited.
if printf '{"created":"%s"}\n' "$GARBAGE" | jq -e . >/dev/null 2>&1; then
    fail "printf-concatenation control: garbage value breaks a printf-built document" \
         "printf output was parseable — the control is no longer meaningful"
else
    ok "printf-concatenation control: garbage value breaks a printf-built document"
fi

# 6. An unreadable / absent shani-version is reported as "" — never guessed,
#    never fatal (same contract as status_json's version field).
mv "$SB/mnt/@green/etc/shani-version" "$SB/green-version.bak"
out=$(emit "$LIST_JSON_FN")
if printf '%s' "$out" | jq -e '[.slots[] | select(.slot=="green")] | length == 1' >/dev/null 2>&1 \
   && [[ $(jqf "$out" '.slots[]|select(.slot=="green")|.version') == "" ]]; then
    ok "slot with no readable shani-version reports version \"\" and still emits JSON"
else
    fail "slot with no readable shani-version reports version \"\" and still emits JSON" \
         "green version=$(jqf "$out" '.slots[]|select(.slot=="green")|.version')  raw: ${out:-<empty>}"
fi
mv "$SB/green-version.bak" "$SB/mnt/@green/etc/shani-version"

# 7. The subvolid=5 mount must be released on the abort path too.
#    list_backups() has no trap at all, so any die() leaks the mount; a
#    RETURN trap alone is NOT enough (bash does not run a RETURN trap on
#    `exit` — verified: f(){ trap 'echo T' RETURN; exit 1; } prints nothing),
#    so the failure path has to unmount explicitly before dying.
if [[ -z "$COLLECT_FN" ]]; then
    fail "abort mid-function still unmounts subvolid=5" "_list_backups_json_collect() not found in $DEPLOY"
elif ! command -v jq >/dev/null 2>&1; then
    fail "abort mid-function still unmounts subvolid=5" "jq not installed — cannot run this test"
else
    rm -f "$SB/calls"
    rc=0; out=$(emit "$LIST_JSON_FN" "PATH=$SB/badbin:$PATH") || rc=$?
    if [[ $rc -ne 0 && -f "$SB/calls" && $(grep -c 'umount' "$SB/calls") -ge 1 ]]; then
        ok "abort mid-function (jq fails) still unmounts subvolid=5 (rc=$rc)"
    else
        fail "abort mid-function (jq fails) still unmounts subvolid=5" \
             "rc=$rc calls=$(tr '\n' ',' < "$SB/calls" 2>/dev/null) output=${out:-<empty>}"
    fi

    # MUTATION GUARD for that test (same pattern as test-status-json.sh #12):
    # drop the explicit unmount + RETURN trap and confirm the check above
    # would then FAIL, so it is not passing vacuously. If the substitution
    # stops matching we fail loudly instead.
    MUT_FROM='    trap '"'"'safe_umount "$MOUNT_DIR" 2>/dev/null || force_umount_all "$MOUNT_DIR" || true; trap - RETURN'"'"' RETURN'
    MUT_TO='# mutation: cleanup removed'
    if [[ "$LIST_JSON_FN" != *"$MUT_FROM"* ]]; then
        fail "mutation guard: removed-cleanup variant still detectable" "trap line not found — update this test"
    else
        ok "mutation guard: removed-cleanup variant still detectable"
        MUTATED="${LIST_JSON_FN//"$MUT_FROM"/"$MUT_TO"}"
        MUTATED="${MUTATED//safe_umount \"\$MOUNT_DIR\" 2>\/dev\/null || force_umount_all \"\$MOUNT_DIR\" || true/true}"
        rm -f "$SB/calls"
        rc=0; emit "$MUTATED" "PATH=$SB/badbin:$PATH" >/dev/null || rc=$?
        if [[ $rc -ne 0 ]] && ! grep -q umount "$SB/calls" 2>/dev/null; then
            ok "mutation guard: without the cleanup the same test fails (mount leaks)"
        else
            fail "mutation guard: without the cleanup the same test fails (mount leaks)" \
                 "rc=$rc calls=$(calls_str "$SB/calls")"
        fi
    fi
fi

################################################################################
# Second half: the real main() — arg parsing, dispatch, and the
# --check/--json guard. `--list-backups --json` used to die here.
################################################################################
E2E="$SB/e2e"
mkdir -p "$E2E/cfg/shani" "$E2E/bin" "$E2E/mnt/@blue/etc" "$E2E/mnt/@green/etc" \
         "$E2E/mnt/@blue_backup_20260915120000"
# Every path the real script resolves is redirected into the sandbox: this
# must never touch a real /data, /run/shanios, /mnt or /var/log.
cat > "$E2E/cfg/shani/shani.conf" <<EOF
[deploy]
channel = stable
download_dir = $E2E/downloads
mount_dir = $E2E/mnt
esp_path = $E2E/esp
log_file = $E2E/deploy.log
lock_file = $E2E/deploy.lock
reboot_needed = $E2E/reboot-needed
boot_failure = $E2E/boot_failure
boot_hard_failure = $E2E/boot_hard_failure
auto_rollback_done = $E2E/auto_rollback_done
current_slot = $E2E/current-slot
prev_slot = $E2E/previous-slot
channel_file = $E2E/shani-channel
rootlabel = test-root
EOF
printf 'stable' > "$E2E/shani-channel"
printf 'blue'   > "$E2E/current-slot"
printf 'green'  > "$E2E/previous-slot"
printf 'v20260915\n' > "$E2E/mnt/@blue/etc/shani-version"
printf 'v20260914\n' > "$E2E/mnt/@green/etc/shani-version"
cat > "$E2E/svol_list" <<'EOF'
ID 257 gen 42 top level 5 path @blue
ID 258 gen 43 top level 5 path @green
ID 259 gen 44 top level 5 path @blue_backup_20260915120000
EOF
# PATH shims: the real mount(8)/btrfs(8) are privileged/absent here. The
# deploy lock, awk, sort, head, tr, du's real pipeline and the real jq are
# left alone.
cat > "$E2E/bin/mount" <<EOF
#!/bin/sh
echo "mount \$*" >> "$E2E/calls"
exit 0
EOF
cat > "$E2E/bin/btrfs" <<EOF
#!/bin/sh
case "\$1 \$2" in
  "subvolume list") cat "$E2E/svol_list" ;;
  "subvolume show")
      printf 'Name: \t\t\t%s\n' "\$(basename "\${3:-}")"
      printf 'Creation time: \t\t2026-09-15 12:00:00 +0000\n' ;;
  *) exit 1 ;;
esac
EOF
cat > "$E2E/bin/du" <<EOF
#!/bin/sh
printf '1.2G\t%s\n' "\${*: -1}"
EOF
chmod +x "$E2E/bin/mount" "$E2E/bin/btrfs" "$E2E/bin/du"

# Body of the real script with its final `main "$@"` invocation removed, so
# we can call main() ourselves with only the privileged bits stubbed.
sed '/^main "\$@"$/d' "$DEPLOY" > "$E2E/body.sh"

# run_main <args...> — stdout only; stderr goes to $E2E/stderr.
run_main() {
    rm -f "$E2E/calls"
    XDG_CONFIG_HOME="$E2E/cfg" PATH="$E2E/bin:$PATH" bash -c '
        set -Eeuo pipefail
        E2E="$1"; shift
        # shellcheck disable=SC1090
        source "$E2E/body.sh"
        # Only the root escalation and the booted-subvolume probe are stubbed
        # — both need real privileges/a real /proc/cmdline. Everything the
        # tests actually assert on (arg parsing, the guard, the dispatch, the
        # real list_backups_json) is the shipped code.
        check_root()       { echo check_root >> "$E2E/calls"; STATE_DIR="$E2E/state"; export STATE_DIR; }
        get_booted_subvol() { echo blue; }
        main "$@"
    ' _ "$E2E" "$@" 2>"$E2E/stderr"
}

echo "------------------------- dispatch / guard tests -------------------------"

# 8. --status --json must be byte-for-byte what it was before the guard was
#    relaxed. This literal was captured from the UNMODIFIED script
#    (shani-deploy --status --json against exactly this sandbox) before any
#    change was made. It also pins the unprivileged contract: no check_root.
out=$(run_main --status --json)
GOLDEN='{"version":"","profile":"","channel":"stable","booted_slot":"blue","current_slot":"blue","previous_slot":"green","boot_failure":"","boot_hard_failure":"","auto_rollback_done":false,"candidate_boot":false,"reboot_needed":"","remote":{"stable":"","latest":""},"update_available":null}'
if [[ "$out" == "$GOLDEN" ]]; then
    ok "--status --json output is byte-identical to the pre-change baseline"
else
    fail "--status --json output is byte-identical to the pre-change baseline" \
         "got:  $out  want: $GOLDEN"
fi
if ! grep -q check_root "$E2E/calls" 2>/dev/null; then
    ok "--status --json still runs unprivileged (check_root not reached)"
else
    fail "--status --json still runs unprivileged (check_root not reached)" \
         "check_root was called: $(calls_str "$E2E/calls")"
fi

# 9. Bare --json without --status must still be rejected. The guard was
#    relaxed for --list-backups only; widening it any further is the bug
#    this pins shut.
rc=0; out=$(run_main --json) || rc=$?
if [[ $rc -ne 0 && -z "$out" && $(grep -c 'go with --status' "$E2E/stderr" 2>/dev/null || echo 0) -ge 1 ]]; then
    ok "bare --json without --status still dies (rc=$rc, nothing on stdout)"
else
    fail "bare --json without --status still dies" "rc=$rc stdout=${out:-<empty>} stderr=$(cat "$E2E/stderr")"
fi

# 10. --check is not part of the relaxation: it still requires --status.
rc=0; out=$(run_main --check) || rc=$?
if [[ $rc -ne 0 && -z "$out" ]]; then
    ok "bare --check without --status still dies (rc=$rc)"
else
    fail "bare --check without --status still dies" "rc=$rc stdout=${out:-<empty>}"
fi
rc=0; out=$(run_main --check --list-backups) || rc=$?
if [[ $rc -ne 0 && -z "$out" ]]; then
    ok "--check --list-backups (no --json) still dies (rc=$rc)"
else
    fail "--check --list-backups (no --json) still dies" "rc=$rc stdout=${out:-<empty>}"
fi

# 11. The feature itself: --list-backups --json goes through the real
#     dispatch and the real list_backups_json, and prints JSON alone.
rc=0; out=$(run_main --list-backups --json) || rc=$?
if [[ $rc -eq 0 ]] && printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
    ok "--list-backups --json exits 0 and prints a single valid JSON object"
else
    fail "--list-backups --json exits 0 and prints a single valid JSON object" \
         "rc=$rc stdout=${out:-<empty>} stderr=$(cat "$E2E/stderr")"
fi
if [[ $(jqf "$out" '.slots[]|select(.slot=="blue")|.version') == 20260915 \
   && $(jqf "$out" '.slots[]|select(.slot=="green")|.version') == 20260914 \
   && $(jqf "$out" '.slots[]|select(.slot=="blue")|.backups[0].name') == "@blue_backup_20260915120000" ]]; then
    ok "--list-backups --json end-to-end reports versions and backups"
else
    fail "--list-backups --json end-to-end reports versions and backups" "raw: ${out:-<empty>}"
fi
if [[ $(jqf "$out" '[.slots[]|select(.slot=="green")|.backups|length]|add') == 0 ]]; then
    ok "--list-backups --json end-to-end: backup-less slot present with empty list"
else
    fail "--list-backups --json end-to-end: backup-less slot present with empty list" "raw: ${out:-<empty>}"
fi
if grep -q check_root "$E2E/calls" 2>/dev/null; then
    ok "--list-backups --json still escalates (check_root reached before mounting)"
else
    fail "--list-backups --json still escalates (check_root reached before mounting)" \
         "calls=$(calls_str "$E2E/calls")"
fi
# The human mode must be untouched: no --json, plain text, no JSON document.
rc=0; out=$(run_main --list-backups) || rc=$?
if [[ $rc -eq 0 ]] && [[ -n "$out" ]] && ! printf '%s' "$out" | jq -e . >/dev/null 2>&1 \
   && [[ "$out" == *"blue_backup_20260915120000"* ]]; then
    ok "--list-backups (human mode) still prints the plain listing, not JSON"
else
    fail "--list-backups (human mode) still prints the plain listing, not JSON" \
         "rc=$rc stdout=$(printf '%s' "$out" | tr '\n' '|')"
fi

summary
