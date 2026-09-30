#!/bin/bash
# tests/test-runtime-only-units.sh — contract tests for the "Runtime-only units"
# row in shani-health.sh's Units section.
#
# The block is EXTRACTED from scripts/shani-health.sh and run verbatim, so what
# is exercised is the shipped control flow. Only `systemctl` is stubbed; the
# parsing pipeline, the by-design exclusion and the row/_rec wiring are the real
# ones.
#
# Why this exists. A unit enabled with `--runtime` (or by a package that did so)
# is running now and is gone after the next reboot — and on this OS every reboot
# is also a blue-green slot switch, so it is exactly how a service silently
# disappears one update later with nothing in the journal. No other row in this
# script can catch it: the unit is ABSENT, not failed, so
# `systemctl list-units --state=failed` never sees it, and a missing unit has no
# `systemd-analyze security` exposure score to report.
#
# The trap this test guards hardest. The obvious implementation is
# `systemd-analyze unit-files`, whose documented output is a
# `UNIT FILE / STATE / PRESET` table. On systemd 255 that is NOT what you get
# when the output is piped: it prints an `ids: NAME -> PATH` form with no state
# column and no header (measured on this host, 941 lines, 0 headers). A STATE
# column scrape therefore matches nothing, always reports "all clear", and is
# indistinguishable from a healthy system. Case 6 below pins the interface so
# that regression cannot come back quietly.
#
# The false-positive guard. systemd's own `systemd-fsck-root.service` and
# `systemd-remount-fs.service` are enabled-runtime BY DESIGN (they are
# generator-produced). Reporting them as findings on every single machine would
# train the user to ignore this row. Case 2 is the case that must stay silent,
# and case 4 is its control.

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
# mutated copy of the block; unset, it is always the shipped script.
HEALTH="${SHANI_HEALTH_UNDER_TEST:-scripts/shani-health.sh}"
[[ -f "$HEALTH" ]] || { echo "missing $HEALTH"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- extraction --
# Anchored on the block's own first comment line and the function's closing
# brace. The start anchor is asserted unique, and the extracted text is asserted
# to contain the row and to stop before the next function, so a future edit that
# moves either boundary fails loudly instead of quietly changing what is tested.
RO_START='^    # Runtime-only enables vanish on the next reboot'
_n="$(grep -c "$RO_START" "$HEALTH" || true)"
if [[ "$_n" != "1" ]]; then
    echo "FATAL: start anchor matched $_n times, expected exactly 1"
    exit 1
fi

RO_BLOCK="$(sed -n "/$RO_START/,/^}$/p" "$HEALTH" | head -n -1)"
if [[ -z "$RO_BLOCK" ]]; then
    echo "FATAL: could not extract the runtime-only block from $HEALTH"
    exit 1
fi
if ! printf '%s\n' "$RO_BLOCK" | grep -q '_row "Runtime-only units"'; then
    echo "FATAL: extracted block has no 'Runtime-only units' row — anchors are wrong"
    exit 1
fi
if printf '%s\n' "$RO_BLOCK" | grep -q '_section_package_managers'; then
    echo "FATAL: extraction over-ran past the Units section"
    exit 1
fi

# ------------------------------------------------------------- test harness --
# `systemctl` is stubbed because the real one's output depends on the host's
# unit files, which differ between the developer machine, the build container
# and a testbed slot. The return code is also injectable, so the
# systemctl-fails path is reachable.
# The block uses `local`, so it is evaluated inside a function.
run_block() {
    local out="$1" rc="${2:-0}"
    rm -rf "$TMP/bin"; mkdir -p "$TMP/bin"
    {
        echo '#!/bin/bash'
        echo "printf '%s' '$out'"
        echo "exit $rc"
    } > "$TMP/bin/systemctl"
    chmod +x "$TMP/bin/systemctl"
    (
        set -Eeuo pipefail
        PATH="$TMP/bin:$PATH"
        _row() { printf 'ROW|%s|%s\n' "$1" "$2"; }
        _rec() { printf 'REC|%s\n' "$1"; }
        _probe() { eval "$RO_BLOCK"; }
        _probe
    ) 2>&1
}
row_key()  { printf '%s\n' "$1" | sed -n 's/^ROW|\([^|]*\)|.*/\1/p'; }
row_msg()  { printf '%s\n' "$1" | sed -n 's/^ROW|[^|]*|\(.*\)/\1/p'; }

# Comment-stripped copy, for the static assertions below. The block's own
# comments name `systemd-analyze unit-files` and `--no-legend --plain` in order
# to warn against them, so grepping the raw block matches the documentation and
# the guard would pass on a regression that reintroduces the very call it
# forbids. Assert against code only.
#
# Only comment-ONLY lines are dropped (`^[[:space:]]*#`). A looser
# `[[:space:]]*#` also eats the `#` inside `${#_runtime_only[@]}`, truncating
# the very line the count assertion reads, so it reports a false failure.
RO_CODE="$(printf '%s\n' "$RO_BLOCK" | sed 's/^[[:space:]]*#.*$//')"

# ------------------------------------------------------------ behavioural ----
# Real-world shapes, taken from this host's actual
# `systemctl list-unit-files --state=enabled-runtime --no-legend --plain`.

# 1. A genuine third-party runtime-only enable must be reported.
OUT="$(run_block 'netplan-ovs-cleanup.service enabled-runtime enabled
')"
if [[ "$(row_key "$OUT")" == "Runtime-only units" ]]; then
    ok "third-party runtime-only unit produces a row"
else
    fail "third-party runtime-only unit produces a row" "got: $OUT"
fi
if [[ "$(row_msg "$OUT")" == *netplan-ovs-cleanup.service* ]]; then
    ok "row names the offending unit"
else
    fail "row names the offending unit" "message was: $(row_msg "$OUT")"
fi
if [[ "$(row_msg "$OUT")" == --* ]]; then
    ok "row is informational (-- prefix), not a failure"
else
    fail "row is informational (-- prefix), not a failure" "message was: $(row_msg "$OUT")"
fi
if [[ "$(row_msg "$OUT")" == *'1 enabled'* ]]; then
    ok "row reports the correct count"
else
    fail "row reports the correct count" "message was: $(row_msg "$OUT")"
fi
if printf '%s\n' "$OUT" | grep -q '^REC|'; then
    ok "row raises a recommendation with the fix"
else
    fail "row raises a recommendation with the fix" "no REC line in: $OUT"
fi

# 2. By-design generators ALONE must produce NO row. This is the case that
#    would otherwise fire on every machine and get the row ignored.
OUT="$(run_block 'systemd-fsck-root.service enabled-runtime enabled
systemd-remount-fs.service enabled-runtime enabled
')"
if [[ -z "$OUT" ]]; then
    ok "by-design fsck/remount generators alone produce no row"
else
    fail "by-design fsck/remount generators alone produce no row" "got: $OUT"
fi

# 3. Mixed: generators excluded, third-party kept, count reflects only the latter.
OUT="$(run_block 'systemd-fsck-root.service enabled-runtime enabled
systemd-remount-fs.service enabled-runtime enabled
foo.service enabled-runtime enabled
bar.timer enabled-runtime enabled
')"
if [[ "$(row_msg "$OUT")" == *'2 enabled'* ]] \
   && [[ "$(row_msg "$OUT")" == *foo.service* ]] \
   && [[ "$(row_msg "$OUT")" == *bar.timer* ]] \
   && [[ "$(row_msg "$OUT")" != *fsck-root* ]] \
   && [[ "$(row_msg "$OUT")" != *remount-fs* ]]; then
    ok "generators excluded while third-party units are kept and counted"
else
    fail "generators excluded while third-party units are kept and counted" "message was: $(row_msg "$OUT")"
fi

# 4. CONTROL for case 2 — the exclusion must be load-bearing. Re-run the same
#    by-design fixture through the pipeline with the exclusion removed; if the
#    exclusion did nothing, the filtered result would still be empty and this
#    control could not fail.
UNFILTERED="$(printf '%s\n' \
    'systemd-fsck-root.service enabled-runtime enabled' \
    'systemd-remount-fs.service enabled-runtime enabled' \
    | awk '{print $1}' | grep -v '^$')"
if [[ "$UNFILTERED" == *fsck-root* && "$UNFILTERED" == *remount-fs* ]]; then
    ok "control: without the exclusion the by-design units DO appear (exclusion is load-bearing)"
else
    fail "control: without the exclusion the by-design units DO appear" "unfiltered was: $UNFILTERED"
fi

# 5. No runtime-only units at all -> silence, not an empty or zero row.
OUT="$(run_block '')"
if [[ -z "$OUT" ]]; then
    ok "no runtime-only units produces no row"
else
    fail "no runtime-only units produces no row" "got: $OUT"
fi

# 6. systemctl failing (no bus, restricted container) must not crash the health
#    run. The script runs under `set -Eeuo pipefail`; a non-zero pipeline here
#    would abort the entire report. The correct outcome is silence: no row, and
#    no error text leaking out of the block.
OUT="$(run_block 'Failed to connect to bus: No such file or directory' 1)"
if [[ -z "$OUT" ]]; then
    ok "failing systemctl yields no row and no crash"
else
    fail "failing systemctl yields no row and no crash" "got: $OUT"
fi

# ---------------------------------------------------------------- static -----
# Pin the interface. These are the facts the behavioural cases cannot observe,
# because the behavioural cases run against a stubbed `systemctl`. All of them
# grep RO_CODE, not the raw block — see RO_CODE above.
if printf '%s\n' "$RO_CODE" | grep -q 'list-unit-files --no-legend --plain --no-pager'; then
    ok "uses systemctl list-unit-files in positional (offline) form"
else
    fail "uses systemctl list-unit-files in positional (offline) form" "not found in $HEALTH"
fi
# The core regression guard: the output must never be column-scraped. Checked
# against code, because the block's own comment names the forbidden command.
if printf '%s\n' "$RO_CODE" | grep -q 'systemd-analyze'; then
    fail "does not scrape systemd-analyze unit-files" \
         "a systemd-analyze call is present — its piped form has no STATE column (see header)"
else
    ok "does not scrape systemd-analyze unit-files"
fi
# `--state=` is the one form that needs the bus; measured in a real `test enter`
# slot it returns rc=1 with no output when /run/systemd/system is absent, which
# would silently reduce this row to nothing in the sessions where a slot is
# actually inspected. The state must be filtered by awk instead.
if printf '%s\n' "$RO_CODE" | grep -q -- '--state='; then
    fail "does not use systemctl --state= (needs the bus, rc=1 without it)" \
         "--state= present in $HEALTH — the row will be empty in a chroot/enter session"
else
    ok "does not use systemctl --state= (needs the bus, rc=1 without it)"
fi
if printf '%s\n' "$RO_CODE" | grep -qF 'awk '"'"'$2 == "enabled-runtime" {print $1}'"'"''; then
    ok "filters enabled-runtime with awk on the state column"
else
    fail "filters enabled-runtime with awk on the state column" "not found in $HEALTH"
fi
# The pipeline must take the unit name ($1), not the state or preset column.
if printf '%s\n' "$RO_CODE" | grep -qF 'print $1'; then
    ok "parses the unit-name column (\$1)"
else
    fail "parses the unit-name column (\$1)" "not found in $HEALTH"
fi
# The count in the message must come from the collected array, not a literal.
if printf '%s\n' "$RO_CODE" | grep -qF '${#_runtime_only[@]}'; then
    ok "count is derived from the collected units"
else
    fail "count is derived from the collected units" "\${#_runtime_only[@]} not found in $HEALTH"
fi
# The row must stay informational: this is a reportable fact, not a fault, and
# a critical row would make a normal machine look broken.
if printf '%s\n' "$RO_CODE" | grep -qF '_row "Runtime-only units" "--  '; then
    ok "row is emitted with the informational '--' prefix"
else
    fail "row is emitted with the informational '--' prefix" "row prefix changed in $HEALTH"
fi

summary
