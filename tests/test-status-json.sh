#!/bin/bash
# tests/test-status-json.sh — contract tests for `shani-deploy --status --json`,
# the machine-readable interface Shani Cassini's agent consumes.
#
# The real status_json() is EXTRACTED from scripts/shani-deploy.sh and run
# verbatim (never reimplemented here) against a sandbox of marker files, with
# only the two environment-derived inputs stubbed: get_booted_subvol() (needs a
# real /proc/cmdline + btrfs) and read_channel_from_file() (needs /etc).
# The marker paths come from the same config-overridable variables the script
# itself uses, which is what makes this runnable without a container.

set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }
summary() {
    echo ""
    if (( FAIL > 0 )); then echo "✗ $PASS passed, $FAIL failed"; exit 1; fi
    echo "✓ $PASS passed, $FAIL failed"
}

DEPLOY=../scripts/shani-deploy.sh
[[ -f "$DEPLOY" ]] || { echo "missing $DEPLOY"; exit 1; }
STATUS_FN=$(sed -n '/^status_json() {/,/^}/p' "$DEPLOY")
[[ -n "$STATUS_FN" ]] || { echo "could not extract status_json() from $DEPLOY"; exit 1; }

SB=$(mktemp -d)
trap 'rm -rf "$SB"' EXIT

# Run the real status_json() in a subshell with `set -Eeuo pipefail` (as the
# real script has) over a clean sandbox. $1 = booted slot, or "!" to make
# get_booted_subvol fail exactly the way the real one does (die() -> exit 1
# from inside the command substitution).
emit() {
    STUB_BOOTED="$1"; STUB_CHECK="${2:-no}"
    (
        set -Eeuo pipefail
        BOOT_FAILURE_FILE="$SB/boot_failure"
        BOOT_HARD_FAILURE_FILE="$SB/boot_hard_failure"
        AUTO_ROLLBACK_DONE_FILE="$SB/auto_rollback_done"
        CURRENT_SLOT_FILE="$SB/current-slot"
        PREV_SLOT_FILE="$SB/previous-slot"
        REBOOT_NEEDED_FILE="$SB/reboot-needed"
        # STUB_BOOTED, not a local: bash locals are dynamically scoped, and
        # status_json declares its own `local booted`, which this callee would
        # otherwise see (empty) instead of the value passed to emit().
        get_booted_subvol() {
            if [[ "$STUB_BOOTED" == "!" ]]; then
                echo "Cannot detect booted subvolume" >&2
                exit 1
            fi
            echo "$STUB_BOOTED"
        }
        read_channel_from_file() { echo "stable"; }
        eval "$STATUS_FN"
        status_json "$STUB_CHECK"
    ) 2>/dev/null
}

# markers current=<x> previous=<x> [name=content]... — wipes the sandbox first.
markers() {
    rm -f "$SB"/* 2>/dev/null || true
    local kv
    for kv in "$@"; do
        case "$kv" in
            current=*)  printf '%s' "${kv#current=}"  > "$SB/current-slot" ;;
            previous=*) printf '%s' "${kv#previous=}" > "$SB/previous-slot" ;;
            *=*)        printf '%s' "${kv#*=}" > "$SB/${kv%%=*}" ;;
        esac
    done
}

# jq field read; empty string when absent so callers can compare literally.
jqf() { printf '%s' "$1" | jq -r "$2" 2>/dev/null; }

echo "────────────────── status --json contract tests ──────────────────"

# Guard: every marker must be read through a config-overridable variable. A
# literal /data/... or /run/shanios/... here would mean the reporter and the
# component that writes the marker can silently disagree, and would make this
# whole suite untestable without a real system.
if printf '%s' "$STATUS_FN" | grep -qE '/data/|/run/shanios'; then
    fail "no hardcoded marker paths in status_json()" \
         "$(printf '%s' "$STATUS_FN" | grep -nE '/data/|/run/shanios' | tr '\n' ' ')"
else
    ok "no hardcoded marker paths in status_json()"
fi

# 1. Steady state: booted == current-slot, nothing pending, no markers.
markers current=blue previous=green
out=$(emit blue)
if printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
    ok "steady state emits valid JSON"
else
    fail "steady state emits valid JSON" "rc/output: $out"
fi
if [[ $(jqf "$out" .booted_slot) == blue && $(jqf "$out" .current_slot) == blue \
   && $(jqf "$out" .previous_slot) == green ]]; then
    ok "steady state reports the real slot markers"
else
    fail "steady state reports the real slot markers" "$out"
fi
if [[ $(jqf "$out" .boot_failure) == "" && $(jqf "$out" .boot_hard_failure) == "" \
   && $(jqf "$out" .reboot_needed) == "" ]]; then
    ok "steady state: no failure/reboot markers reported as empty"
else
    fail "steady state: no failure/reboot markers reported as empty" "$out"
fi
if [[ $(jqf "$out" .auto_rollback_done) == false && $(jqf "$out" .candidate_boot) == false ]]; then
    ok "steady state: auto_rollback_done and candidate_boot false"
else
    fail "steady state: auto_rollback_done and candidate_boot false" "$out"
fi

# 2. Deploy finalized, reboot still pending: current-slot moved to the new
#    slot, we keep running the old one, reboot marker holds the new version.
markers current=green previous=blue reboot-needed=20260925
out=$(emit blue)
if [[ $(jqf "$out" .reboot_needed) == "20260925" && $(jqf "$out" .candidate_boot) == true ]]; then
    ok "pending deploy: candidate_boot true with the deployed version"
else
    fail "pending deploy: candidate_boot true with the deployed version" "$out"
fi

# 3. NEGATIVE CONTROL — bootloader fallback. check-boot-failure.sh recorded the
#    failure; the reboot that triggered the fallback wiped /run, so the reboot
#    marker is gone while current-slot still names the candidate that failed.
#    Nothing is pending: rebooting again would land on the same broken slot.
markers current=green previous=blue boot_failure=green
out=$(emit blue)
if [[ $(jqf "$out" .boot_failure) == green && $(jqf "$out" .candidate_boot) == false ]]; then
    ok "fallback boot: failure reported, candidate_boot NOT claimed"
else
    fail "fallback boot: failure reported, candidate_boot NOT claimed" "$out"
fi

# 4. Rollback already switched the default back and cleared the marker; we are
#    still running the newer slot until the next reboot. Same `booted !=
#    current` shape as a pending deploy, opposite meaning.
markers current=blue previous=green
out=$(emit green)
if [[ $(jqf "$out" .current_slot) == blue && $(jqf "$out" .candidate_boot) == false ]]; then
    ok "rolled-back default: candidate_boot NOT claimed"
else
    fail "rolled-back default: candidate_boot NOT claimed" "$out"
fi

# 5. Negative control: a leftover reboot marker alone must not fabricate a
#    candidate when the slot markers show no flip (booted == current-slot).
markers current=blue previous=green reboot-needed=20260925
out=$(emit blue)
if [[ $(jqf "$out" .reboot_needed) == "20260925" && $(jqf "$out" .candidate_boot) == false ]]; then
    ok "stale reboot marker with no slot flip: candidate_boot false"
else
    fail "stale reboot marker with no slot flip: candidate_boot false" "$out"
fi

# 6. Negative control: garbage slot-marker content must fail closed, not be
#    turned into a candidate by defaulting one side of the comparison.
markers current=@@@ previous=blue reboot-needed=20260925
out=$(emit blue)
if [[ $(jqf "$out" .candidate_boot) == false ]]; then
    ok "invalid current-slot content: candidate_boot false (fails closed)"
else
    fail "invalid current-slot content: candidate_boot false (fails closed)" "$out"
fi

# 7. The booted subvolume is undetectable (no subvol= on /proc/cmdline, no
#    btrfs default). get_booted_subvol's die() runs inside $( ) and used to
#    abort the whole script under `set -e` — empty output, rc=1, no JSON at
#    all, which is the worst possible answer for a machine-readable contract.
markers current=green previous=blue reboot-needed=20260925
if out=$(emit "!" 2>/dev/null); then rc=0; else rc=$?; fi
if [[ -n "$out" ]] && printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
    ok "undetectable booted slot still emits valid JSON (rc=$rc)"
else
    fail "undetectable booted slot still emits valid JSON" "rc=$rc output: ${out:-<empty>}"
fi
if [[ $(jqf "$out" .booted_slot) == "" && $(jqf "$out" .candidate_boot) == false ]]; then
    ok "undetectable booted slot: reported as unknown, no candidate guessed"
else
    fail "undetectable booted slot: reported as unknown, no candidate guessed" "$out"
fi

# 8. auto_rollback_done maps 1:1 to the marker, which shani-auto-rollback.sh
#    writes on success AND on failure and mark-boot-in-progress.service clears
#    at the start of every boot.
markers current=blue previous=green auto_rollback_done=
if [[ $(jqf "$(emit blue)" .auto_rollback_done) == true ]]; then
    ok "auto_rollback_done marker present -> true"
else
    fail "auto_rollback_done marker present -> true" "marker not honoured"
fi

# 9. boot_failure precedence must match rollback_system()'s: the plain marker
#    wins, the acknowledged copy is the fallback. A --status that reported ""
#    while --rollback acts on a recorded failure would be lying to the UI.
markers current=green previous=blue boot_failure=green
if [[ $(jqf "$(emit blue)" .boot_failure) == green ]]; then
    ok "boot_failure read from the plain marker"
else
    fail "boot_failure read from the plain marker" "not reported"
fi
markers current=green previous=blue boot_failure.acked=green
if [[ $(jqf "$(emit blue)" .boot_failure) == green ]]; then
    ok "boot_failure falls back to the acknowledged marker"
else
    fail "boot_failure falls back to the acknowledged marker" "not reported"
fi
markers current=green previous=blue boot_failure=blue boot_failure.acked=green
if [[ $(jqf "$(emit blue)" .boot_failure) == blue ]]; then
    ok "boot_failure: plain marker takes precedence over acknowledged"
else
    fail "boot_failure: plain marker takes precedence over acknowledged" "wrong precedence"
fi

# 10. A hard failure (dracut hook, before the root mount is attempted) is
#     reported in its own field and never leaks into the soft one.
markers current=green previous=blue boot_hard_failure=green
out=$(emit blue)
if [[ $(jqf "$out" .boot_hard_failure) == green && $(jqf "$out" .boot_failure) == "" ]]; then
    ok "boot_hard_failure reported separately from boot_failure"
else
    fail "boot_hard_failure reported separately from boot_failure" "$out"
fi

# 11. --check must not change the shape of the recovery fields, and must still
#     emit valid JSON when the remote pointers are unreachable.
markers current=blue previous=green
out=$(emit blue yes)
if printf '%s' "$out" | jq -e . >/dev/null 2>&1 \
   && [[ $(jqf "$out" .update_available) == "null" ]] \
   && [[ $(jqf "$out" .candidate_boot) == false ]]; then
    ok "--check --json stays valid and non-guessing"
else
    fail "--check --json stays valid and non-guessing" "$out"
fi

# 12. MUTATION GUARD (the negative control for the negative controls): swap the
#     real conjunction back to the retired `booted == sibling(current)`
#     heuristic and confirm test 3 and 4 would then FAIL. If the substitution
#     below ever stops matching, the guard fails loudly rather than passing
#     vacuously.
OLD_COND='    if [[ -n "$reboot" && "$cur" =~ ^(blue|green)$ && "$booted" =~ ^(blue|green)$ && "$booted" != "$cur" ]]; then'
OLD_HEURISTIC='    local other; if [[ "$cur" == blue ]]; then other=green; else other=blue; fi
    if [[ "$cur" =~ ^(blue|green)$ && "$booted" == "$other" ]]; then'
if [[ "$STATUS_FN" != *"${OLD_COND}"* ]]; then
    fail "mutation guard: retired heuristic still detectable" "condition line not found — update this test"
else
    ok "mutation guard: retired heuristic still detectable"
    STATUS_FN_ORIG="$STATUS_FN"
    STATUS_FN="${STATUS_FN_ORIG/"$OLD_COND"/"$OLD_HEURISTIC"}"
    markers current=green previous=blue boot_failure=green
    if [[ $(jqf "$(emit blue)" .candidate_boot) == true ]]; then
        ok "mutation guard: retired heuristic wrongly claims a candidate on fallback"
    else
        fail "mutation guard: retired heuristic wrongly claims a candidate on fallback" \
             "heuristic produced the same answer — tests 3/4 would be vacuous"
    fi
    STATUS_FN="$STATUS_FN_ORIG"
fi

summary
