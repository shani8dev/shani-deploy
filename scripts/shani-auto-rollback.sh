#!/bin/bash
# shani-auto-rollback.sh — unattended, system-level automatic rollback for a
# CONFIRMED boot failure. Exists because shani-update's fallback-detection
# dialog (_check_fallback_boot/_handle_fallback_boot in shani-update.sh)
# only runs under `shani-update --startup`, which requires BOTH a
# `systemd --user` session AND a graphical display (DISPLAY/WAYLAND_DISPLAY)
# — confirmed live by reading its own startup-mode guard, which exits
# immediately with "No display — skipping startup check" otherwise. That
# means it never runs at all on a headless boot (the `server` profile has
# no desktop by design), and never runs if the failure itself is what's
# preventing the desktop from starting — one of the most likely real
# failure shapes this mechanism needs to catch. This script has no such
# dependency: it is a system-level oneshot triggered directly by the
# marker-writing units themselves (mark-boot-in-progress's early boot
# point, and again after check-boot-failure.service's 15-minute check),
# with no session, display, or interactive confirmation of any kind.
#
# Deliberately conservative about WHAT it treats as "confirmed": it only
# acts on a real recorded failure marker (written by the dracut hard-failure
# hook or by check-boot-failure.sh), never guesses. As of 2026-09-19,
# shani-deploy.sh's `rollback_system()` can correctly handle BOTH shapes of
# a confirmed failure (see its own comments): a genuine bootloader-level
# fallback (repairs the sibling slot from backup, keeps booted as default),
# and a same-slot timeout (switches the default to the sibling slot with no
# subvolume repair, via switch_to_sibling_slot()) — so this script does not
# need to duplicate that direction logic here, only decide WHETHER to call
# shani-deploy --rollback at all.

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

DEFAULT_deploy_boot_failure="/data/boot_failure"
DEFAULT_deploy_boot_failure_acked="/data/boot_failure.acked"
DEFAULT_deploy_boot_hard_failure="/data/boot_hard_failure"
DEFAULT_deploy_auto_rollback_done="/data/auto_rollback_done"

if [[ -f /etc/shani/shani.conf ]]; then
    _load_ini_config /etc/shani/shani.conf
fi
if [[ -f "${XDG_CONFIG_HOME:-${HOME:-}/.config}/shani/shani.conf" ]]; then
    _load_ini_config "${XDG_CONFIG_HOME:-${HOME:-}/.config}/shani/shani.conf"
fi

BOOT_FAILURE_FILE="${deploy_boot_failure:-${DEFAULT_deploy_boot_failure}}"
BOOT_FAILURE_ACKED="${deploy_boot_failure_acked:-${DEFAULT_deploy_boot_failure_acked}}"
BOOT_HARD_FAILURE_FILE="${deploy_boot_hard_failure:-${DEFAULT_deploy_boot_hard_failure}}"
AUTO_ROLLBACK_DONE_FILE="${deploy_auto_rollback_done:-${DEFAULT_deploy_auto_rollback_done}}"

# Idempotency: this unit can fire more than once per boot (once early to
# catch a hard failure quickly, once again after check-boot-failure.timer's
# 15-minute check) — skip if already processed this boot. Cleared by
# mark-boot-in-progress.service at the START of the NEXT boot, same
# lifetime as boot_in_progress itself.
if [ -f "$AUTO_ROLLBACK_DONE_FILE" ]; then
    logger -t shani-auto-rollback "Already processed this boot — skipping."
    exit 0
fi

# Same booted-subvolume detection as check-boot-failure.sh/shani-deploy.sh/
# shani-update.sh/shani-health.sh — kept as an independent copy deliberately
# (see shani-deploy/AGENTS.md's "get_booted_subvol() — 5 copies" entry).
_rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2- 2>/dev/null || echo "")
BOOTED_SLOT=$(awk -F'subvol=' '{print $2}' <<< "$_rootflags" | cut -d, -f1)
BOOTED_SLOT="${BOOTED_SLOT#@}"
if [ -z "$BOOTED_SLOT" ]; then
    BOOTED_SLOT=$(grep -oP 'subvol=@?\K[^ ,]+' /proc/cmdline 2>/dev/null | head -1)
fi
if [ -z "$BOOTED_SLOT" ]; then
    BOOTED_SLOT=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
fi
if [ -z "$BOOTED_SLOT" ]; then
    logger -t shani-auto-rollback "Cannot detect booted subvolume — skipping."
    exit 0
fi

# Hard failure takes priority — dracut wrote it before root mount was even
# attempted, a stronger and earlier signal than the 15-minute timer check.
RECORDED_FAILED=""
FAILURE_KIND=""
if [ -f "$BOOT_HARD_FAILURE_FILE" ]; then
    RECORDED_FAILED=$(cat "$BOOT_HARD_FAILURE_FILE" 2>/dev/null | tr -cd 'a-z')
    FAILURE_KIND="hard"
elif [ -f "$BOOT_FAILURE_FILE" ]; then
    RECORDED_FAILED=$(cat "$BOOT_FAILURE_FILE" 2>/dev/null | tr -cd 'a-z')
    FAILURE_KIND="soft"
fi

if [ -z "$RECORDED_FAILED" ]; then
    logger -t shani-auto-rollback "No failure marker present — nothing to do."
    exit 0
fi

if [ "$RECORDED_FAILED" != "blue" ] && [ "$RECORDED_FAILED" != "green" ]; then
    logger -t shani-auto-rollback "Failure marker content '${RECORDED_FAILED}' is not a valid slot name — refusing to guess, leaving for manual recovery (shani-health/shani-deploy --rollback)."
    exit 0
fi

logger -t shani-auto-rollback "Confirmed failure marker: recorded='@${RECORDED_FAILED}' booted='@${BOOTED_SLOT}' kind=${FAILURE_KIND} — running automatic rollback."
command -v wall >/dev/null 2>&1 && wall "ShaniOS: a boot failure was detected (@${RECORDED_FAILED}, ${FAILURE_KIND}). Running automatic recovery now — see 'journalctl -t shani-auto-rollback' for details." 2>/dev/null || true

# Deliberately NOT `shani-deploy --rollback 2>&1 | logger ...; if [ $? ...`
# — a pipeline's exit status without `pipefail` reflects the LAST command
# (logger, which always succeeds), not shani-deploy's real result. This
# exact class of bug (a real failure masked by a trailing `| logger`/`|
# head`) was already found and fixed elsewhere in this ecosystem this
# session (shani-ci-commons' secret-scan CI guard) — confirmed live here
# too: shani-deploy crashed on an unbound $HOME (system-service context
# has none) and this script still logged "completed successfully" before
# this fix, because $? was logger's, not shani-deploy's.
_rollback_output=$(/usr/local/bin/shani-deploy --rollback 2>&1)
_rollback_rc=$?
echo "$_rollback_output" | logger -t shani-auto-rollback
if [ "$_rollback_rc" -eq 0 ]; then
    touch "$AUTO_ROLLBACK_DONE_FILE" 2>/dev/null || true
    logger -t shani-auto-rollback "Automatic rollback completed successfully."
    command -v wall >/dev/null 2>&1 && wall "ShaniOS: automatic recovery completed. Reboot to return to a known-good state. See 'journalctl -t shani-auto-rollback' for details." 2>/dev/null || true
else
    touch "$AUTO_ROLLBACK_DONE_FILE" 2>/dev/null || true
    logger -t shani-auto-rollback "ERROR: automatic rollback FAILED (see the shani-deploy output logged above). Manual intervention required: run 'shani-deploy --rollback' or check logs. Not retrying again this boot to avoid repeating a failing operation."
    command -v wall >/dev/null 2>&1 && wall "ShaniOS: automatic rollback FAILED. Manual intervention required — see 'journalctl -t shani-auto-rollback'." 2>/dev/null || true
    exit 1
fi
