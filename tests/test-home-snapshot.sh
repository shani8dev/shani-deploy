#!/bin/bash
# tests/test-home-snapshot.sh — contract tests for the pre-deploy /home snapshot
#
# `shani-deploy` takes a snapshot of /home before it writes anything to the
# standby slot. This suite exercises both halves of that:
#
#   * `take_predeploy_home_snapshot()` is EXTRACTED from scripts/shani-deploy.sh
#     and run verbatim (only the four log functions are stubbed), so the
#     shipped branching - disabled, dry-run, missing helper, taken, skipped,
#     failed - is what runs here. The most important property is the one that
#     says a failure changes nothing: a snapshot is insurance, and refusing to
#     update because the insurance could not be issued would be worse than the
#     risk it covers.
#   * `scripts/shani-snapshot-home.sh` is executed for real with a fake
#     `shani-backup` on PATH. Only the privilege probe (`id -u`) and the disk
#     percentage (`df`) are replaced, because the runner is neither root nor
#     guaranteed to have a nearly-full /home; every other line is the shipped
#     one, including the KEEP it passes and the exit codes the deploy reads.
#
# The negative control that matters: the "skipped" and "failed" cases assert
# the helper's non-zero status is NOT propagated, so deleting the `return 0`
# at the end of the function makes this suite fail.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }
summary() {
    echo ""
    if (( FAIL > 0 )); then echo "✗ $PASS passed, $FAIL failed"; exit 1; fi
    echo "✓ $PASS passed, 0 failed"
}

DEPLOY=scripts/shani-deploy.sh
HELPER=scripts/shani-snapshot-home.sh
for f in "$DEPLOY" "$HELPER"; do
    [[ -f "$f" ]] || { echo "missing $f" >&2; exit 1; }
    bash -n "$f" || { echo "FATAL: $f does not parse" >&2; exit 1; }
done
[[ -x "$HELPER" ]] || { echo "FATAL: $HELPER is not executable" >&2; exit 1; }

eval "$(sed -n '/^take_predeploy_home_snapshot() {/,/^}/p' "$DEPLOY")"
declare -F take_predeploy_home_snapshot >/dev/null || {
    echo "FATAL: could not extract take_predeploy_home_snapshot()" >&2
    exit 1
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
LOG="$TMP/log"

# The only stubs on the deploy side. The real functions append to $LOG_FILE;
# these only need to be observable.
log()         { echo "INFO $*"    >> "$LOG"; }
log_warn()    { echo "WARN $*"    >> "$LOG"; }
log_success() { echo "SUCCESS $*" >> "$LOG"; }
log_verbose() { echo "DEBUG $*"   >> "$LOG"; }

echo ""
echo "take_predeploy_home_snapshot() — the deploy side"

# A helper that records how it was called, then exits with a chosen status.
cat > "$TMP/helper" <<'EOF'
#!/bin/bash
echo "helper keep=${SHANI_SNAPSHOT_KEEP} argv=$*" > "$FAKE_LOG"
echo "${FAKE_OUT-alice: ok /home/.snapshots/@home/predeploy-2026-10-31_10-00-00}"
exit "${FAKE_HELPER_RC:-0}"
EOF
chmod +x "$TMP/helper"

# Run the real function in a subshell. `export` puts the case's variables in
# the environment the helper inherits; locals inside the function are not
# affected.
deploy_case() { # VAR=value...
    ( set -a; export "$@"; take_predeploy_home_snapshot ) >/dev/null 2>&1
}

# 1. disabled
: > "$LOG"; rm -f "$TMP/called"
deploy_case HOME_SNAPSHOT=no DRY_RUN=no SNAPSHOT_HOME_SCRIPT="$TMP/helper" \
           HOME_SNAPSHOT_KEEP=2 FAKE_LOG="$TMP/called"
rc=$?
if [[ $rc -eq 0 && ! -e "$TMP/called" ]] && grep -q 'disabled' "$LOG"; then
    ok "HOME_SNAPSHOT=no neither runs the helper nor fails"
else
    fail "HOME_SNAPSHOT=no neither runs the helper nor fails" "rc=$rc called=$(ls "$TMP/called" 2>/dev/null) log=$(cat "$LOG")"
fi

# 2. dry run
: > "$LOG"; rm -f "$TMP/called"
deploy_case HOME_SNAPSHOT=yes DRY_RUN=yes SNAPSHOT_HOME_SCRIPT="$TMP/helper" \
           HOME_SNAPSHOT_KEEP=2 FAKE_LOG="$TMP/called"
rc=$?
if [[ $rc -eq 0 && ! -e "$TMP/called" ]] && grep -q 'DRY-RUN' "$LOG"; then
    ok "a dry run does not touch /home and still returns 0"
else
    fail "a dry run does not touch /home and still returns 0" "rc=$rc called=$(ls "$TMP/called" 2>/dev/null) log=$(cat "$LOG")"
fi

# 3. helper not installed
: > "$LOG"
deploy_case HOME_SNAPSHOT=yes DRY_RUN=no SNAPSHOT_HOME_SCRIPT="$TMP/not-installed" \
           HOME_SNAPSHOT_KEEP=2
rc=$?
if [[ $rc -eq 0 ]] && grep -q 'not installed' "$LOG"; then
    ok "a missing helper is a warning, not a failed deploy"
else
    fail "a missing helper is a warning, not a failed deploy" "rc=$rc log=$(cat "$LOG")"
fi

# 4. taken (and --keep is forwarded)
: > "$LOG"; rm -f "$TMP/called"
deploy_case HOME_SNAPSHOT=yes DRY_RUN=no SNAPSHOT_HOME_SCRIPT="$TMP/helper" \
           HOME_SNAPSHOT_KEEP=7 FAKE_LOG="$TMP/called" FAKE_HELPER_RC=0
rc=$?
if [[ $rc -eq 0 ]] && grep -q 'SUCCESS.*taken' "$LOG" && grep -q 'keep=7' "$TMP/called"; then
    ok "a taken snapshot is reported, and HOME_SNAPSHOT_KEEP reaches the helper"
else
    fail "a taken snapshot is reported, and HOME_SNAPSHOT_KEEP reaches the helper" "rc=$rc called=$(cat "$TMP/called" 2>/dev/null) log=$(cat "$LOG")"
fi

# 5. skipped by the helper (10) — must not fail the deploy
: > "$LOG"
deploy_case HOME_SNAPSHOT=yes DRY_RUN=no SNAPSHOT_HOME_SCRIPT="$TMP/helper" \
           HOME_SNAPSHOT_KEEP=2 FAKE_LOG="$TMP/called" \
           FAKE_HELPER_RC=10 FAKE_OUT="not enough free space"
rc=$?
if [[ $rc -eq 0 ]] && grep -q 'WARN.*skipped' "$LOG" && grep -q 'not enough free space' "$LOG"; then
    ok "exit 10 is a skip with its reason, and the deploy continues"
else
    fail "exit 10 is a skip with its reason, and the deploy continues" "rc=$rc log=$(cat "$LOG")"
fi

# 6. helper failed (11) — must not fail the deploy
: > "$LOG"
deploy_case HOME_SNAPSHOT=yes DRY_RUN=no SNAPSHOT_HOME_SCRIPT="$TMP/helper" \
           HOME_SNAPSHOT_KEEP=2 FAKE_LOG="$TMP/called" \
           FAKE_HELPER_RC=11 FAKE_OUT="btrfs said no"
rc=$?
if [[ $rc -eq 0 ]] && grep -q 'WARN.*FAILED' "$LOG"; then
    ok "a failed snapshot is a warning, not a blocked update"
else
    fail "a failed snapshot is a warning, not a blocked update" "rc=$rc log=$(cat "$LOG")"
fi

# 7. the call is inside deploy_update(), before the mount
BODY=$(sed -n '/^deploy_update() {/,/^}/p' "$DEPLOY")
CALL_LINE=$(grep -n 'take_predeploy_home_snapshot' <<< "$BODY" | head -1 | cut -d: -f1)
MOUNT_LINE=$(grep -n 'safe_mount "\$ROOT_DEV"' <<< "$BODY" | head -1 | cut -d: -f1)
if [[ -n "$CALL_LINE" && -n "$MOUNT_LINE" ]] && (( CALL_LINE < MOUNT_LINE )); then
    ok "deploy_update() calls it before mounting or writing"
else
    fail "deploy_update() calls it before mounting or writing" "call=$CALL_LINE mount=$MOUNT_LINE"
fi

echo ""
echo "shani-snapshot-home — the helper"

BIN="$TMP/bin"
mkdir -p "$BIN"
REAL_TAIL=$(command -v tail)
REAL_TR=$(command -v tr)

# The only two probes replaced: "are we root" and "how full is /home".
cat > "$BIN/id" <<'EOF'
#!/bin/sh
echo "${FAKE_UID:-0}"
EOF

cat > "$BIN/df" <<'EOF'
#!/bin/sh
printf 'Use%%\n%3s%%\n' "${FAKE_FREE_PCT:-42}"
EOF

cat > "$BIN/shani-backup" <<'EOF'
#!/bin/bash
echo "argv=$*" > "$FAKE_LOG"
echo "${FAKE_OUT-alice: ok /home/.snapshots/@home/predeploy-2026-10-31_10-00-00}"
exit "${FAKE_RC:-0}"
EOF
ln -s "$REAL_TAIL" "$BIN/tail"
ln -s "$REAL_TR" "$BIN/tr"

# For the "not installed" case: everything the helper legitimately shells out
# to, except shani-backup.
NOPATH="$TMP/nopath"
mkdir -p "$NOPATH"
ln -s "$BIN/id" "$NOPATH/id"
ln -s "$BIN/df" "$NOPATH/df"
ln -s "$REAL_TAIL" "$NOPATH/tail"
ln -s "$REAL_TR" "$NOPATH/tr"

chmod +x "$BIN/id" "$BIN/df" "$BIN/shani-backup"

helper_run() { # <PATH> <VAR=value>... [-- helper args...]
    local path="$1"; shift
    local -a envs=() args=()
    while [[ $# -gt 0 && "$1" != "--" ]]; do envs+=("$1"); shift; done
    [[ "${1:-}" == "--" ]] && shift
    args=("$@")
    env PATH="$path" ${envs[@]+"${envs[@]}"} "$HELPER" ${args[@]+"${args[@]}"} \
        > "$TMP/out" 2>&1
}

# 8. not root
rm -f "$TMP/called"
helper_run "$BIN" FAKE_UID=1000 FAKE_LOG="$TMP/called"
rc=$?
if [[ $rc -eq 10 ]] && grep -q 'needs root' "$TMP/out" && [[ ! -e "$TMP/called" ]]; then
    ok "a non-root call skips (10) without touching btrfs"
else
    fail "a non-root call skips (10) without touching btrfs" "rc=$rc out=$(cat "$TMP/out")"
fi

# 9. shani-backup not installed
helper_run "$NOPATH" FAKE_UID=0
rc=$?
if [[ $rc -eq 10 ]] && grep -q 'shani-backup is not installed' "$TMP/out"; then
    ok "a machine without shani-backup skips (10)"
else
    fail "a machine without shani-backup skips (10)" "rc=$rc out=$(cat "$TMP/out")"
fi

# 10. low free space: skip before running shani-backup
rm -f "$TMP/called"
helper_run "$BIN" FAKE_UID=0 FAKE_FREE_PCT=2 FAKE_LOG="$TMP/called"
rc=$?
if [[ $rc -eq 10 ]] && grep -q '2% free' "$TMP/out" && [[ ! -e "$TMP/called" ]]; then
    ok "a nearly-full /home skips (10) before taking a snapshot"
else
    fail "a nearly-full /home skips (10) before taking a snapshot" "rc=$rc called=$(ls "$TMP/called" 2>/dev/null) out=$(cat "$TMP/out")"
fi

# 11. success, default keep, argv shape
helper_run "$BIN" FAKE_UID=0 FAKE_FREE_PCT=42 FAKE_LOG="$TMP/called" FAKE_RC=0
rc=$?
if [[ $rc -eq 0 ]] && grep -qx 'argv=home predeploy --keep 2' "$TMP/called"; then
    ok "a normal update takes a predeploy snapshot and reports it (0)"
else
    fail "a normal update takes a predeploy snapshot and reports it (0)" "rc=$rc called=$(cat "$TMP/called" 2>/dev/null) out=$(cat "$TMP/out")"
fi

# 12. --keep is passed through to shani-backup
helper_run "$BIN" FAKE_UID=0 FAKE_FREE_PCT=42 FAKE_LOG="$TMP/called" FAKE_RC=0 -- --keep 5
rc=$?
if [[ $rc -eq 0 ]] && grep -qx 'argv=home predeploy --keep 5' "$TMP/called"; then
    ok "--keep reaches shani-backup"
else
    fail "--keep reaches shani-backup" "rc=$rc called=$(cat "$TMP/called" 2>/dev/null) out=$(cat "$TMP/out")"
fi

# 13. shani-backup failed
helper_run "$BIN" FAKE_UID=0 FAKE_FREE_PCT=42 FAKE_LOG="$TMP/called" \
           FAKE_RC=1 FAKE_OUT="alice: FAILED no space"
rc=$?
if [[ $rc -eq 11 ]] && grep -q 'FAILED no space' "$TMP/out"; then
    ok "shani-backup's failure becomes exit 11 with its reason"
else
    fail "shani-backup's failure becomes exit 11 with its reason" "rc=$rc out=$(cat "$TMP/out")"
fi

# 14. success with nothing to snapshot is a skip, not a snapshot
helper_run "$BIN" FAKE_UID=0 FAKE_FREE_PCT=42 FAKE_LOG="$TMP/called" FAKE_RC=0 FAKE_OUT=""
rc=$?
if [[ $rc -eq 10 ]] && grep -q 'no home folders' "$TMP/out"; then
    ok "an empty answer is a skip (10), not a claimed snapshot"
else
    fail "an empty answer is a skip (10), not a claimed snapshot" "rc=$rc out=$(cat "$TMP/out")"
fi

echo ""
echo "shani.conf — the snapshot keys are validated, not trusted"

eval "$(sed -n '/^DEFAULT_deploy_/p' "$DEPLOY")"
eval "$(sed -n '/^_vc_bad_path() {/,/^}/p;/^_vc_num() {/,/^}/p;/^_vc_bool() {/,/^}/p;/^_validate_config() {/,/^}/p' "$DEPLOY")"
declare -F _validate_config >/dev/null || {
    echo "FATAL: could not extract _validate_config()" >&2
    exit 1
}

config_case() { # $1=home_snapshot $2=keep -> "bool|keep|warnings"
    # The function must run in a subshell anyway; its warnings go to a file so
    # they survive, since `var=$(f)` would discard every assignment f made.
    ( set +u
      ESP=/boot/efi MOUNT_DIR=/mnt GENEFI_SCRIPT=/usr/local/bin/gen-efi
      SNAPSHOT_HOME_SCRIPT=/usr/local/bin/shani-snapshot-home ROOTLABEL=shani_root
      MAX_INHIBIT_DEPTH=2 MAX_DOWNLOAD_ATTEMPTS=5 EXTRACTION_TIMEOUT=1800
      MIN_FREE_SPACE_MB=10240 MIN_FILE_SIZE=10485760
      HOME_SNAPSHOT="$1" HOME_SNAPSHOT_KEEP="$2"
      _validate_config 2> "$TMP/warn"
      printf '%s|%s|' "$HOME_SNAPSHOT" "$HOME_SNAPSHOT_KEEP" )
    cat "$TMP/warn"
}

got=$(config_case yes 2)
[[ "$got" == "yes|2|" ]] && ok "a valid home_snapshot/keep pair is kept" \
    || fail "a valid home_snapshot/keep pair is kept" "$got"

got=$(config_case no 0)
[[ "$got" == "no|0|" ]] && ok "home_snapshot=no and keep=0 (keep all) are kept" \
    || fail "home_snapshot=no and keep=0 (keep all) are kept" "$got"

got=$(config_case maybe 2)
[[ "$got" == yes\|2\|* && "$got" == *home_snapshot* ]] && ok "home_snapshot=maybe falls back to yes and says so" \
    || fail "home_snapshot=maybe falls back to yes and says so" "$got"

got=$(config_case yes abc)
[[ "$got" == yes\|2\|* && "$got" == *home_snapshot_keep* ]] && ok "a non-numeric keep falls back to 2 and says so" \
    || fail "a non-numeric keep falls back to 2 and says so" "$got"

got=$(config_case yes -1)
[[ "$got" == yes\|2\|* ]] && ok "a negative keep is a typo, not a policy: falls back to 2" \
    || fail "a negative keep is a typo, not a policy: falls back to 2" "$got"

summary
