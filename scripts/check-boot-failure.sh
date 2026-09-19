#!/bin/bash
# check-boot-failure.sh – Record boot failure if boot-success marker is missing.
#
# Deliberately NO `set -Eeuo pipefail` here, unlike its sibling scripts —
# tried adding it and reverted after live-testing found a real regression:
# `[ -z "$BOOTED_SLOT" ] && BOOTED_SLOT=$(btrfs subvolume get-default / ...)`
# is a bare `cmd1 && cmd2` statement (not inside an `if`), so under `set -e`
# a failing `btrfs` call here (missing binary, not-a-btrfs-root, run inside
# a container without a real subvolume, etc.) aborts the whole script
# instead of falling through to the graceful "cannot detect booted
# subvolume — skip" exit this script's own logic already handles a few
# lines later. Confirmed live: a sandboxed run with no `btrfs` on `$PATH`
# exits 127 immediately with strict mode on, vs. correctly reaching the
# graceful skip path without it. Don't re-add strict mode without also
# auditing every risky line for an explicit `|| true`-style guard first —
# that's a bigger change than "add set -e", not a drop-in one-liner.

_load_ini_config() {
    local conf_file="$1" section="" line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        if [[ "$line" =~ ^\[([a-zA-Z0-9_]+)\][[:space:]]*$ ]]; then
            section="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*([a-zA-Z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            value="${value%"${value##*[![:space:]]}"}"
            value="${value#"${value%%[![:space:]]*}"}"
            [[ -z "$section" ]] && continue
            printf -v "${section}_${key}" '%s' "$value"
        fi
    done < "$conf_file"
}

DEFAULT_deploy_current_slot="/data/current-slot"
DEFAULT_deploy_boot_failure="/data/boot_failure"
DEFAULT_deploy_boot_failure_acked="/data/boot_failure.acked"
DEFAULT_deploy_boot_hard_failure="/data/boot_hard_failure"
DEFAULT_deploy_boot_ok="/data/boot-ok"
DEFAULT_deploy_boot_in_progress="/data/boot_in_progress"

if [[ -f /etc/shani/shani.conf ]]; then
    _load_ini_config /etc/shani/shani.conf
fi
if [[ -f "${XDG_CONFIG_HOME:-${HOME:-}/.config}/shani/shani.conf" ]]; then
    _load_ini_config "${XDG_CONFIG_HOME:-${HOME:-}/.config}/shani/shani.conf"
fi

CURRENT_SLOT_FILE="${deploy_current_slot:-${DEFAULT_deploy_current_slot}}"
BOOT_FAILURE_FILE="${deploy_boot_failure:-${DEFAULT_deploy_boot_failure}}"
BOOT_FAILURE_ACKED="${deploy_boot_failure_acked:-${DEFAULT_deploy_boot_failure_acked}}"
BOOT_HARD_FAILURE_FILE="${deploy_boot_hard_failure:-${DEFAULT_deploy_boot_hard_failure}}"
BOOT_OK_FILE="${deploy_boot_ok:-${DEFAULT_deploy_boot_ok}}"
BOOT_IN_PROGRESS_FILE="${deploy_boot_in_progress:-${DEFAULT_deploy_boot_in_progress}}"

# Serialize marker read+write with flock — same pattern used for the
# subid-allocation lock in shani-user-setup.sh. This script reads then
# conditionally writes/removes /data/boot_failure, /data/boot_failure.acked,
# /data/boot_hard_failure, /data/boot-ok and /data/boot_in_progress; without a
# lock, two concurrent invocations (e.g. a manual run racing the 15-minute
# timer, or a re-triggered check-boot-failure.service) could interleave their
# read-then-write sequences and produce a lost update or a corrupted marker
# state. Held for the remainder of this script.
BOOT_MARKER_LOCK="/run/shani-boot-failure.lock"
exec 9>"$BOOT_MARKER_LOCK"
if ! flock -w 30 9; then
    logger -t check-boot-failure "Could not acquire boot-marker lock within 30s — skipping this run to avoid racing a concurrent invocation."
    exit 0
fi

# The slot that actually booted (the fallback, working slot).
# Uses the same rootflags= parsing as shani-deploy and shani-update for
# consistency — a 5th, previously-unaudited copy of this detection logic
# (the "duplicated 4×" finding in AGENTS.md missed this one since it's
# inline, not a named get_booted_subvol()/_get_booted_subvol() function).
# Keep in sync with those 4 too.
_rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2- 2>/dev/null || echo "")
BOOTED_SLOT=$(awk -F'subvol=' '{print $2}' <<< "$_rootflags" | cut -d, -f1)
BOOTED_SLOT="${BOOTED_SLOT#@}"
# Fallback: a bare subvol=@name directly on cmdline, no rootflags= wrapper.
[ -z "$BOOTED_SLOT" ] && \
    BOOTED_SLOT=$(grep -oP 'subvol=@?\K[^ ,]+' /proc/cmdline 2>/dev/null | head -1)
[ -z "$BOOTED_SLOT" ] && \
    BOOTED_SLOT=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
if [ -z "$BOOTED_SLOT" ]; then
    logger -t check-boot-failure "Cannot detect booted subvolume — skipping failure check."
    exit 0
fi

# The slot that was *supposed* to boot (the one that failed).
# shani-update._check_fallback_boot() expects boot_failure to contain
# this value so it can match it against /data/current-slot.
FAILED_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | tr -cd 'a-z')
[ -z "$FAILED_SLOT" ] && FAILED_SLOT="$BOOTED_SLOT"

# Sanity-check: current-slot must be a valid slot name. An invalid/empty
# value carries no signal, so derive a best-effort answer from the booted
# slot. current-slot legitimately CAN equal the booted slot — that is the
# normal steady-state (current-slot is only advanced to a new candidate
# during an active deploy's finalize_update(); once a slot has been the
# accepted default for a while, current-slot == BOOTED_SLOT). A same-slot
# timeout (this slot itself never reached mark-boot-success in time, no
# bootloader-level fallback occurred) must be recorded as itself, not
# "corrected" to the sibling slot.
#
# CONFIRMED LIVE BUG (fixed here): the previous version treated
# FAILED_SLOT == BOOTED_SLOT as invalid data and unconditionally flipped
# to the opposite slot. Reproduced in test-env: entering @blue with
# current-slot=blue (steady-state, no pending deploy) and boot_in_progress
# set produced boot_failure=green — blaming the untouched, healthy sibling
# instead of the slot that actually failed to confirm success. Verified
# the intended case still works correctly (entering @green with
# current-slot=blue — a genuine fallback — still correctly records
# boot_failure=blue). shani-deploy.sh's own rollback_system() has a
# SEPARATE, deeper version of the same "failed slot is always the
# non-booted slot" assumption baked into its core rollback-direction
# logic (not just this diagnostic marker) — that one needs a real design
# decision about what recovery should even DO for a same-slot failure
# (there is no "other slot's backup" to restore from), not a same-shape
# one-line fix; see AGENTS.md's known-issues entry, left unfixed here.
if [ "$FAILED_SLOT" != "blue" ] && [ "$FAILED_SLOT" != "green" ]; then
    if [ "$BOOTED_SLOT" = "blue" ]; then
        FAILED_SLOT="green"
    elif [ "$BOOTED_SLOT" = "green" ]; then
        FAILED_SLOT="blue"
    else
        logger -t check-boot-failure \
          "Cannot derive failed slot from booted slot '$BOOTED_SLOT' — skipping."
        exit 0
    fi
    logger -t check-boot-failure \
      "current-slot invalid — derived failed slot as '@${FAILED_SLOT}' from booted slot."
fi

# Hard failure already written by dracut hook — nothing more to do
if [ -f "$BOOT_HARD_FAILURE_FILE" ]; then
    logger -t check-boot-failure "Hard failure already recorded for slot '$FAILED_SLOT', skipping."
    exit 0
fi

# If system already recovered and booted the same slot successfully,
# any existing failure marker is stale and should be removed.
if [ -f "$BOOT_OK_FILE" ] && [ -f "$BOOT_FAILURE_FILE" ]; then
    RECORDED_FAILED=$(cat "$BOOT_FAILURE_FILE" | tr -cd 'a-z')
    if [ "$BOOTED_SLOT" = "$RECORDED_FAILED" ]; then
        rm -f "$BOOT_FAILURE_FILE" "$BOOT_FAILURE_ACKED"
        logger -t check-boot-failure \
          "Recovered slot '@${BOOTED_SLOT}' booted successfully — clearing stale failure marker."
    fi
fi

# Boot failed if still "in progress" and never marked ok
if [ -f "$BOOT_IN_PROGRESS_FILE" ] && [ ! -f "$BOOT_OK_FILE" ]; then
    if [ ! -f "$BOOT_FAILURE_FILE" ] && [ ! -f "$BOOT_FAILURE_ACKED" ]; then
        echo "$FAILED_SLOT" > "$BOOT_FAILURE_FILE"
        logger -t check-boot-failure \
          "Boot failure: slot '@${FAILED_SLOT}' failed to boot, system fell back to '@${BOOTED_SLOT}'."
    fi
fi
