#!/bin/bash
# tests/test-sysctl-verify.sh — contract tests for the "Sysctl verify" row in
# shani-health.sh's --boot section.
#
# The block is EXTRACTED from scripts/shani-health.sh and run verbatim, so what
# is exercised is the shipped control flow. The two hardcoded binary paths are
# the only thing rewritten (pointed at a fixture), because systemd-sysctl lives
# at a fixed absolute path and cannot be shadowed without root or a mount
# namespace (`unshare` is denied in this environment, confirmed). The real paths
# are pinned separately by static assertions, so redirecting them here does not
# let the production path regress unnoticed.
#
# Why this exists. The row shipped with two defects that made it a check which
# could never fail on any real system:
#
#   1. It was gated on `command -v systemd-sysctl`. systemd-sysctl is a private
#      helper at /usr/lib/systemd/systemd-sysctl and is NOT on PATH (confirmed
#      on this host: `command -v` finds nothing), so the gate was always false
#      and the row never rendered at all. Dead code.
#   2. It counted findings with `grep -c '^not applied'`. Upstream systemd's
#      verify path (src/sysctl/sysctl.c) never emits that string: a failure
#      goes through log_error_errno on stderr, and a healthy run prints
#      NOTHING. So the count was always 0 and every mismatch reported "OK".
#      The host's real systemd 255 proves the shape — it prints
#      "unrecognized option '--verify'", which that grep would never match.
#
# A test asserting only "the row appears" would have passed against both
# defects. Each case below therefore asserts the row's STATUS PREFIX, which is
# what consumers (including shani-fleet's collect_verify) actually read, and the
# mismatch fixtures use the real diagnostic text. If the output handling is
# deleted or narrowed back to a string match, these go red rather than passing
# quietly.

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

# Overridable only so the negative control can run this same suite against a
# restored copy of the pre-fix block; unset, it is always the shipped script.
HEALTH="${SHANI_HEALTH_UNDER_TEST:-scripts/shani-health.sh}"
[[ -f "$HEALTH" ]] || { echo "missing $HEALTH"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- extraction --
# Anchored on the block's own comments, NOT on `^    fi$` — there are two bare
# 4-space `fi` lines in this region and the first one closes the binary-
# discovery conditional, so a `fi` anchor silently extracts a block with no
# _row calls in it at all (which is what this test did on its first run, and
# reported as "no row emitted" on every behavioural case).
# Both anchors are asserted unique below, so a future edit that duplicates
# either one fails loudly instead of quietly changing what is under test.
SV_START='^    # systemd-sysctl --verify is a 262 feature'
SV_END='^    # Written by shani-boot-safety-failed'

for _a in "$SV_START" "$SV_END"; do
    _n="$(grep -c "$_a" "$HEALTH" || true)"
    if [[ "$_n" != "1" ]]; then
        echo "FATAL: anchor '$_a' matched $_n times, expected exactly 1"
        exit 1
    fi
done

# Take everything from the start anchor up to (but not including) the end anchor.
SV_BLOCK="$(sed -n "/$SV_START/,/$SV_END/p" "$HEALTH" | head -n -1)"
if [[ -z "$SV_BLOCK" ]]; then
    echo "FATAL: could not extract the sysctl-verify block from $HEALTH"
    exit 1
fi
# The extraction must contain the rows it is supposed to test, and must not
# over-run into the pstore/boot-safety code that follows.
if ! printf '%s\n' "$SV_BLOCK" | grep -q '_row "Sysctl verify"'; then
    echo "FATAL: extracted block contains no 'Sysctl verify' row — anchors are wrong"
    exit 1
fi
if printf '%s\n' "$SV_BLOCK" | grep -q 'boot_safety_failed\|_row "Kernel crash"'; then
    echo "FATAL: extraction over-ran past the sysctl block"
    exit 1
fi

# ------------------------------------------------------- static assertions ---
# These pin the production facts the behavioural cases cannot observe, because
# the behavioural cases run against redirected paths.
if printf '%s\n' "$SV_BLOCK" | grep -q '/usr/lib/systemd/systemd-sysctl'; then
    ok "production block probes /usr/lib/systemd/systemd-sysctl"
else
    fail "production block probes /usr/lib/systemd/systemd-sysctl" "path not found in $HEALTH"
fi
if printf '%s\n' "$SV_BLOCK" | grep -q '/lib/systemd/systemd-sysctl'; then
    ok "production block falls back to /lib/systemd/systemd-sysctl"
else
    fail "production block falls back to /lib/systemd/systemd-sysctl" "path not found in $HEALTH"
fi
# The false-green regression: no guessed diagnostic string may drive the count.
if printf '%s\n' "$SV_BLOCK" | grep -q "not applied"; then
    fail "no guessed diagnostic string drives the finding count" \
         "'not applied' present — upstream never emits it, so this false-greens"
else
    ok "no guessed diagnostic string drives the finding count"
fi
# --strict must be on the INVOCATION, and this has to grep comment-stripped code:
# the block's own comments deliberately name --strict (they document why it is
# load-bearing), so grepping the raw block would match that documentation and go
# green even if the flag were dropped from the command. Same trap, same fix as
# the runtime-only suite's static assertions.
_sv_code="$(printf '%s\n' "$SV_BLOCK" | sed 's/^[[:space:]]*#.*$//')"
if printf '%s\n' "$_sv_code" | grep -q -- '--verify --strict'; then
    ok "shipped invocation passes --verify --strict"
else
    fail "shipped invocation passes --verify --strict" \
         "no '--verify --strict' on the command line — write-refused faults stay invisible"
fi

# ------------------------------------------------------------------ harness --
SV_OUT=""

# Point the block's two absolute paths at fixture locations.
# The two paths cannot be substituted in sequence: "/lib/systemd/systemd-sysctl"
# is a SUBSTRING of "/usr/lib/systemd/systemd-sysctl", so after rewriting the
# /usr/ path the rewritten string still contains the /lib/ pattern, and the
# second pass mangles the middle of the path it just produced. So the /usr/
# path is parked behind a placeholder token first, which is expanded only after
# the /lib/ pass has run.
_repoint() { # $1=fake usr-dir (empty => leave the /usr/ path pointing nowhere)
    local usr_dir="$1"
    local out="$SV_BLOCK"
    out="${out//\/usr\/lib\/systemd\/systemd-sysctl/__SV_USR__}"
    out="${out//\/lib\/systemd\/systemd-sysctl/$TMP/absent/systemd-sysctl}"
    if [[ -n "$usr_dir" ]]; then
        out="${out//__SV_USR__/$usr_dir/usr/lib/systemd/systemd-sysctl}"
    else
        out="${out//__SV_USR__/$TMP/absent/systemd-sysctl}"
    fi
    printf '%s\n' "$out"
}

_run() { # $1=fake usr-dir (empty => no binary anywhere)
    local usr_dir="$1"
    local block; block="$(_repoint "$usr_dir")"
    # The block uses `local`, so it must be evaluated inside a function. Its
    # stdout is captured: both _row and _rec write there.
    _sv_harness() {
        local _sv_bin="" _sv_out="" _sv_n=0
        _row() { local v="$2"; printf 'ROW|%s|%s|%s\n' "$1" "${v%%  *}" "${v#*  }"; }
        _rec() { printf 'REC|%s\n' "$1"; }
        eval "$block"
    }
    SV_OUT="$(
        set -u
        # Stripped PATH: no systemd-sysctl reachable by name, so the block can
        # only find it by absolute path. This is the real-world condition.
        PATH=/usr/bin:/bin
        export PATH
        _sv_harness
    2>"$TMP/stderr")"
}

_prefix() { printf '%s\n' "$SV_OUT" | sed -n 's/^ROW|Sysctl verify|\([^|]*\)|.*/\1/p'; }

_assert_prefix() { # $1=label  $2=expected
    local got; got="$(_prefix)"
    if [[ -z "$got" ]]; then
        fail "$1" "no 'Sysctl verify' row emitted at all (output: ${SV_OUT:-<empty>})"
    elif [[ "$got" == "$2" ]]; then
        ok "$1"
    else
        fail "$1" "expected '$2', got '$got' (row: ${SV_OUT})"
    fi
}

_assert_rec() { # $1=label  $2=yes|no
    local have=no
    printf '%s\n' "$SV_OUT" | grep -q '^REC|' && have=yes
    if [[ "$have" == "$2" ]]; then
        ok "$1"
    else
        fail "$1" "expected recommendation=$2, got $have"
    fi
}

_mkfake() { # $1=dir  $2=body
    mkdir -p "$1/usr/lib/systemd"
    printf '%s\n' "$2" > "$1/usr/lib/systemd/systemd-sysctl"
    chmod +x "$1/usr/lib/systemd/systemd-sysctl"
}

# --------------------------------------------------------- 1. healthy path --
# Upstream prints nothing on success. Empty output is the success signal.
_mkfake "$TMP/healthy" "#!/bin/bash
[[ \"\$1\" == \"--verify\" && \"\$2\" == \"--strict\" ]] || exit 64
exit 0"
_run "$TMP/healthy"
_assert_prefix "healthy run (silent) reports OK" "OK"
_assert_rec   "healthy run raises no recommendation" "no"

# --------------------------------------------------------- 2. real mismatch --
# Verbatim diagnostic shape from src/sysctl/sysctl.c. The old '^not applied'
# grep matched nothing here and would have reported OK.
_mkfake "$TMP/bad" "#!/bin/bash
[[ \"\$1\" == \"--verify\" && \"\$2\" == \"--strict\" ]] || exit 64
printf \"Couldn't write '4096' to 'vm.max_map_count': Read-only file system\n\" >&2
exit 1"
_run "$TMP/bad"
_assert_prefix "real Couldn't write diagnostic reports !!" "!!"
_assert_rec   "real mismatch raises a recommendation" "yes"

# ------------------------------------------------------- 3. multi-line count --
_mkfake "$TMP/multi" "#!/bin/bash
[[ \"\$1\" == \"--verify\" && \"\$2\" == \"--strict\" ]] || exit 64
{
  printf \"Couldn't write '4096' to 'vm.max_map_count': Read-only file system\n\"
  printf \"Couldn't write '1' to 'vm.swappiness': Permission denied\n\"
} >&2
exit 1"
_run "$TMP/multi"
if printf '%s\n' "$SV_OUT" | grep -qE 'REC\|.*2 line'; then
    ok "multi-line output is counted as 2, not truncated"
else
    fail "multi-line output is counted as 2, not truncated" \
         "recommendation was: $(printf '%s' "$SV_OUT" | tr '\n' ' ')"
fi

# --------------------------------------------- 4. unknown diagnostic = fault --
# Guards against re-narrowing the check to specific known strings.
_mkfake "$TMP/odd" "#!/bin/bash
[[ \"\$1\" == \"--verify\" && \"\$2\" == \"--strict\" ]] || exit 64
printf \"sysctl: some entirely new diagnostic nobody predicted\n\" >&2
exit 1"
_run "$TMP/odd"
_assert_prefix "unrecognised diagnostic is still a finding" "!!"

# ------------------------------------------------ 5. pre-262 = unavailable --
# Otherwise every 261.2 image would raise this recommendation permanently.
# Text below is verbatim from the host's real systemd 255.
_mkfake "$TMP/old" "#!/bin/bash
printf \"/usr/lib/systemd/systemd-sysctl: unrecognized option '--verify'\n\" >&2
exit 1"
_run "$TMP/old"
_assert_prefix "unsupported --verify reports unavailable" "--"
_assert_rec   "unsupported --verify raises no recommendation" "no"

# --------------------------------------------------- 6. binary absent: skip --
_run ""
if [[ -z "$(printf '%s\n' "$SV_OUT" | grep '^ROW|')" ]]; then
    ok "absent binary emits no row (no false green, no crash)"
else
    fail "absent binary emits no row (no false green, no crash)" "emitted: $SV_OUT"
fi

# ----------------------------------- 7. non-zero exit with no output is OK --
# The contract is "healthy is silent". Keying on the exit code instead would
# invent a fault here.
_mkfake "$TMP/quietfail" "#!/bin/bash
[[ \"\$1\" == \"--verify\" && \"\$2\" == \"--strict\" ]] || exit 64
exit 1"
_run "$TMP/quietfail"
_assert_prefix "non-zero exit with no output is not a fault" "OK"

# -------------------------------------- 8. stderr, not just stdout, is read --
# Upstream logs failures to stderr; a check reading only stdout would pass.
_mkfake "$TMP/stderronly" "#!/bin/bash
[[ \"\$1\" == \"--verify\" && \"\$2\" == \"--strict\" ]] || exit 64
printf \"permission denied\n\" >&2
exit 1"
_run "$TMP/stderronly"
_assert_prefix "diagnostics on stderr are captured" "!!"

# ---------------------------- 9. --strict is what makes a refusal visible --
# Emulates upstream sysctl_write_or_warn(): a write-REFUSED errno (EROFS/EACCES)
# is swallowed via log_debug_errno and returns 0 unless arg_strict is set. So one
# and the same real fault — a read-only or hardened sysctl — is SILENT without
# --strict and REPORTED with it, and silent is what this row reads as "OK all
# shipped sysctl.d values are live". That includes 90-security-hardening.conf.
# This is the false-green the flag closes, exercised through the real block.
_mkfake "$TMP/refused" "#!/bin/bash
strict=0
for a in \"\$@\"; do
  [[ \"\$a\" == \"--strict\" ]] && strict=1
done
if (( strict == 0 )); then
  exit 0
fi
printf \"Couldn't write '1' to 'kernel.dmesg_restrict': Read-only file system\\n\" >&2
exit 1"
_run "$TMP/refused"
_assert_prefix "write-refused (EROFS) is reported because --strict is passed" "!!"
_assert_rec   "write-refused fault raises a recommendation" "yes"

summary
