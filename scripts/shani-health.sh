#!/bin/bash
# shani-health — ShaniOS system health, security, and diagnostics tool
#
# Standalone read-mostly companion to shani-deploy. Covers everything that
# is about inspecting and hardening the system, not about updating it.
#
# Usage:
#   shani-health                     Full system status report (default / --info)
#   shani-health --fix      Auto-fix all [auto] issues
#   shani-health --verify            Deep integrity check: UKI sigs + Btrfs scrub
#   shani-health --history [N]       Last N deploy/rollback events (default: 50)
#   shani-health --storage-info      Btrfs storage analysis (native, no shani-deploy needed)
#   shani-health --export-logs [DIR] Bundle logs + state for bug reports
#
# Install:  cp shani-health /usr/local/bin/shani-health && chmod +x $_
# Requires: root (auto-escalates via pkexec or sudo)
#
# Exit codes:
#   0  success / no issues
#   1  fatal error or (for --verify) integrity issues found

set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
### Constants                                                                ###
###############################################################################

readonly OS_NAME="shanios"
readonly ROOTLABEL="shani_root"
readonly ROOT_DEV="/dev/disk/by-label/shani_root"
readonly ESP="/boot/efi"
readonly GENEFI_BIN="/usr/local/bin/gen-efi"
readonly DEPLOY_BIN="/usr/local/bin/shani-deploy"
readonly USER_SETUP_BIN="/usr/local/bin/shani-user-setup"
readonly DEPLOY_LOG="/var/log/shanios-deploy.log"
readonly CHANNEL_FILE="/etc/shani-channel"
readonly GPG_SIGNING_KEY="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"
readonly GPG_SIGNING_KEY_FILE="/etc/shani-keys/signing.asc"

# /data state markers
readonly DATA_BOOT_OK="/data/boot-ok"
readonly DATA_BOOT_FAIL="/data/boot_failure"
readonly DATA_BOOT_FAIL_ACKED="/data/boot_failure.acked"
readonly DATA_BOOT_HARD_FAIL="/data/boot_hard_failure"
readonly DATA_CURRENT_SLOT="/data/current-slot"
readonly DATA_PREV_SLOT="/data/previous-slot"
readonly DATA_DEPLOY_PENDING="/data/deployment_pending"
readonly DATA_REBOOT_NEEDED="/run/shanios/reboot-needed"

declare -a ORIGINAL_ARGS=("$@")
VERBOSE="no"

# Caller identity — resolved once; used everywhere sudo/pkexec was invoked
# Priority: SUDO_USER (sudo) → SHANI_CALLER_USER (pkexec env) → USER → id -un
_CALLER_USER="${SUDO_USER:-${SHANI_CALLER_USER:-${USER:-$(id -un 2>/dev/null || echo "")}}}"

###############################################################################
### Privilege escalation                                                     ###
###############################################################################

_require_root() {
    [[ $(id -u) -eq 0 ]] && return 0
    local self; self=$(readlink -f "$0")
    # Prefer pkexec → sudo, in that order.
    # When escalating via pkexec, SUDO_USER is not set and the environment is
    # sanitised. Pass the key vars explicitly and export SHANI_CALLER_USER so
    # _sysd_user can target the right user session even under pkexec.
    local caller_user="${USER:-$(id -un 2>/dev/null || echo "")}"
    if command -v pkexec &>/dev/null; then
        exec pkexec env \
            "DISPLAY=${DISPLAY:-}" \
            "XAUTHORITY=${XAUTHORITY:-}" \
            "WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-}" \
            "XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-}" \
            "SHANI_CALLER_USER=${caller_user}" \
            "$self" "${ORIGINAL_ARGS[@]}"
    elif command -v sudo &>/dev/null; then
        exec sudo "$self" "${ORIGINAL_ARGS[@]}"
    fi
    _die "Must run as root — re-run with sudo or as root"
}

###############################################################################
### Logging                                                                  ###
###############################################################################

# ANSI colour codes — used by both the operational log and the status report
_C_RESET='\033[0m'
_C_BOLD='\033[1m'
_C_DIM='\033[2m'
_C_GREEN='\033[0;32m'
_C_YELLOW='\033[0;33m'
_C_RED='\033[0;31m'
_C_CYAN='\033[0;36m'
_C_BOLD_RED='\033[1;31m'

# Unicode status glyphs (used in _sym_* and in report rows)
_SYM_OK="✓"
_SYM_ERR="✗"
_SYM_WARN="⚠"
_SYM_INFO="—"
_SYM_SPIN="↻"

_ts()        { date '+%Y-%m-%d %H:%M:%S'; }
_log()       { printf '%s  %s\n'                            "$(_ts)" "$*"   >&2; }
_log_ok()    { printf "${_C_GREEN}%s  ${_SYM_OK}  %s${_C_RESET}\n"  "$(_ts)" "$*" >&2; }
_log_warn()  { printf "${_C_YELLOW}%s  ${_SYM_WARN}  %s${_C_RESET}\n" "$(_ts)" "$*" >&2; }
_log_err()   { printf "${_C_RED}%s  ${_SYM_ERR}  %s${_C_RESET}\n"  "$(_ts)" "$*" >&2; }
_log_debug() { [[ "$VERBOSE" == "yes" ]] && printf '%s  …  %s\n'     "$(_ts)" "$*" >&2 || true; }
_log_section(){
    local title="$1"
    local width=54
    local line; printf -v line '%*s' "$width" ''; line="${line// /─}"
    echo ""
    printf "  ┌%s┐\n" "$line"
    printf "  │  ${_C_BOLD}%-${width}s${_C_RESET}│\n" "$title"
    printf "  └%s┘\n" "$line"
}
_die()       { printf "${_C_BOLD_RED}%s  FATAL  %s${_C_RESET}\n" "$(_ts)" "$*" >&2; exit 1; }

# ── Report row helpers ────────────────────────────────────────────────────────
# Status-prefixed row: _row KEY "OK|!!|!|--|->|<- value"
# The leading token is colour-mapped to a glyph automatically.
# Raw text is also accepted — no transformation is applied then.
_row() {
    local key="$1" val="$2"
    local prefix="${val%%  *}"
    local rest="${val#*  }"
    local coloured
    case "$prefix" in
        OK)   coloured="${_C_GREEN}${_SYM_OK}${_C_RESET}  ${rest}" ;;
        !!)   coloured="${_C_RED}${_SYM_ERR}${_C_RESET}  ${rest}" ;;
        "!")  coloured="${_C_YELLOW}${_SYM_WARN}${_C_RESET}  ${rest}" ;;
        "--") coloured="${_C_DIM}${_SYM_INFO}${_C_RESET}  ${rest}" ;;
        "->") coloured="${_C_CYAN}${_SYM_SPIN}${_C_RESET}  ${rest}" ;;
        "N/A") coloured="${_C_DIM}${val}${_C_RESET}" ;;
        *)    coloured="$val" ;;  # no prefix recognised — pass through verbatim
    esac
    printf "    ${_C_BOLD}%-12s${_C_RESET}  %b\n" "$key" "$coloured"
}

# Continuation line — indented to align under the value column
_row2() {
    local text="$1"
    # Colour-map leading sigils in continuation lines too
    local prefix="${text%%  *}"
    local rest="${text#*  }"
    local coloured
    case "$prefix" in
        "!!")  coloured="${_C_RED}${_SYM_ERR}${_C_RESET}  ${rest}" ;;
        "!")   coloured="${_C_YELLOW}${_SYM_WARN}${_C_RESET}  ${rest}" ;;
        "--")  coloured="${_C_DIM}${_SYM_INFO}${_C_RESET}  ${rest}" ;;
        "->")  coloured="${_C_CYAN}${_SYM_SPIN}${_C_RESET}  ${rest}" ;;
        *)     coloured="$text" ;;
    esac
    printf "    %-14s%b\n" "" "$coloured"
}

# Section heading with a subtle underline
_head() {
    printf "\n  ${_C_BOLD}${_C_CYAN}%-40s${_C_RESET}\n" "$1"
    printf "  ${_C_DIM}%s${_C_RESET}\n" "----------------------------------------"
}

###############################################################################
### Shared helpers                                                           ###
###############################################################################

_is_mounted() { findmnt -M "$1" &>/dev/null; }

_get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2- || echo "")
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    [[ -z "$subvol" ]] && \
        subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    echo "${subvol:-unknown}"
}

# Mount ESP if not already mounted; sets _esp_mounted=1 if we did it ourselves.
# Callers must declare local _esp_mounted=0 before calling.
_esp_mount() {
    mountpoint -q "$ESP" 2>/dev/null && return 0
    mount "$ESP" 2>/dev/null && _esp_mounted=1 || true
}
_esp_umount() { (( _esp_mounted )) && umount "$ESP" 2>/dev/null || true; _esp_mounted=0; }

# Resolve the btrfs resume_offset for a swapfile; echoes offset or ""
_swapfile_offset() {
    local swapfile="$1"
    [[ -f "$swapfile" ]] || { echo ""; return; }
    local out; out=$(btrfs inspect-internal map-swapfile -r "$swapfile" 2>/dev/null || echo "")
    local offset
    offset=$(echo "$out" | \
        awk -F'[: \t]+' '/resume_offset/{print $2; found=1} END{if(!found)exit 1}' 2>/dev/null) \
        || offset=$(echo "$out" | awk 'NF{last=$NF} END{if(last+0>0)print last+0}' 2>/dev/null)
    echo "${offset:-}"
}

# Find the active non-zram swapfile; echoes path or ""
_find_swapfile() {
    local dev
    while IFS= read -r dev; do
        dev="${dev%%[[:space:]]*}"
        [[ -z "$dev" ]] && continue
        [[ -f "$dev" ]] && { echo "$dev"; return; }
    done < <(swapon --show=NAME --noheadings 2>/dev/null | grep -v zram || true)
    echo ""
}

# Global recommendations array — reset at the start of system_info
declare -a _RECS=()
_rec()        { _RECS+=("$*"); }
_recs_reset() { _RECS=(); }

# Join array elements with a space, regardless of IFS.
# Usage: local s; s=$(_join "${arr[@]}")
_join() { local IFS=' '; echo "$*"; }

# Populate an array with all interactive login users (uid>=1000, real shell).
# Usage: local -a users=(); _get_login_users users
_get_login_users() {
    local -n _glu_arr="$1"
    _glu_arr=()
    while IFS=: read -r name _ uid _ _ _ shell; do
        [[ "$uid" -ge 1000 ]] 2>/dev/null || continue
        [[ "$name" == "nobody" ]] && continue
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        _glu_arr+=("$name")
    done < /etc/passwd 2>/dev/null || true
}

# Resolve the Btrfs filesystem UUID for the shani_root label (LUKS-aware).
# Echoes UUID or "".
_get_bees_uuid() {
    local uuid
    uuid=$(blkid -s UUID -o value "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null || true)
    [[ -z "$uuid" && -e "/dev/mapper/${ROOTLABEL}" ]] && \
        uuid=$(blkid -s UUID -o value "/dev/mapper/${ROOTLABEL}" 2>/dev/null || true)
    echo "${uuid:-}"
}

# Recursive unmount helper used by analyze_storage (uses existing _is_mounted).
_umount_r() {
    local tgt="$1"
    _is_mounted "$tgt" || return 0
    umount -R "$tgt" 2>/dev/null || umount -R -l "$tgt" 2>/dev/null || true
}

# Run a systemctl --user command as the calling user's session.
# Must be called after _CALLER_USER is set.
# Usage: _sysd_user is-active foo.service
_sysd_user() {
    if [[ "$_CALLER_USER" != "root" && -n "$_CALLER_USER" ]]; then
        local _uid; _uid=$(id -u "$_CALLER_USER" 2>/dev/null || echo "")
        if [[ -n "$_uid" ]]; then
            sudo -u "$_CALLER_USER" \
                env \
                XDG_RUNTIME_DIR="/run/user/${_uid}" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
                systemctl --user "$@"
        else
            sudo -u "$_CALLER_USER" systemctl --user "$@"
        fi
    else
        systemctl --user "$@"
    fi
}

###############################################################################
### Section helpers                                                          ###
###############################################################################

_section_os_slots() {
    local booted="$1"
    local version profile channel slot_current slot_previous
    version=$(     cat /etc/shani-version   2>/dev/null || echo "unknown")
    profile=$(     cat /etc/shani-profile   2>/dev/null || echo "unknown")
    channel=$(     cat "$CHANNEL_FILE"      2>/dev/null | tr -d '[:space:]' || echo "unknown")
    slot_current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
    slot_previous=$(cat "$DATA_PREV_SLOT"   2>/dev/null | tr -d '[:space:]' || echo "unknown")

    _head "OS"
    _row "Version"   "--  $version"
    _row "Profile"   "--  $profile"

    # Hostname
    local hostname; hostname=$(cat /etc/hostname 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ -z "$hostname" ]]; then
        _row "Hostname"  "!   /etc/hostname is empty"
        _rec "Set a hostname: echo 'mymachine' > /etc/hostname"
    elif [[ "$hostname" == "localhost" ]]; then
        _row "Hostname"  "--  ${hostname}  (generic — consider personalising)"
    else
        _row "Hostname"  "--  ${hostname}"
    fi

    # Timezone
    if [[ -L /etc/localtime ]]; then
        local tz; tz=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' || echo "")
        if [[ -z "$tz" || ! -f /etc/localtime ]]; then
            _row "Timezone"  "!!  /etc/localtime symlink broken"
            _rec "Fix timezone: ln -sf /usr/share/zoneinfo/UTC /etc/localtime"
        else
            _row "Timezone"  "--  ${tz}"
        fi
    elif [[ -f /etc/localtime ]]; then
        _row "Timezone"  "--  (not a symlink — timedatectl may not work correctly)"
    else
        _row "Timezone"  "!!  /etc/localtime missing"
        _rec "Set timezone: ln -sf /usr/share/zoneinfo/UTC /etc/localtime"
    fi

    # Validate channel
    if [[ "$channel" == "stable" || "$channel" == "latest" ]]; then
        _row "Channel"   "--  $channel"
    elif [[ "$channel" == "unknown" ]]; then
        _row "Channel"   "--  not set (defaults to stable)"
    else
        _row "Channel"   "!   unknown value: ${channel}  (expected stable or latest)"
        _rec "Invalid channel '${channel}' in ${CHANNEL_FILE} — set to 'stable' or 'latest'"
    fi
    _row "Uptime"    "--  $(uptime -p 2>/dev/null | sed 's/^up //' || echo "unknown")"

    # Validate profile is a known value
    if [[ "$profile" != "gnome" && "$profile" != "plasma" && "$profile" != "unknown" ]]; then
        _rec "Unknown shani-profile '${profile}' — expected 'gnome' or 'plasma'"
    fi

    _head "Slots"

    # Booted — what is actually running right now
    _row "Booted"   "--  @${booted}"

    # Expected — the slot current-slot points to (what boots next time)
    if [[ "$booted" == "$slot_current" ]]; then
        _row "Expected"  "OK  @${slot_current}  (matches booted)"
    elif [[ -f "$DATA_REBOOT_NEEDED" ]]; then
        local rver; rver=$(cat "$DATA_REBOOT_NEEDED" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
        _row "Expected"  "!   @${slot_current}  (v${rver} ready — reboot to activate)"
    elif [[ -f "$DATA_BOOT_FAIL" || -f "$DATA_BOOT_HARD_FAIL" ]]; then
        local _failed_slot
        _failed_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' ||                        cat "$DATA_BOOT_HARD_FAIL" 2>/dev/null | tr -d '[:space:]' ||                        echo "$slot_current")
        [[ -z "$_failed_slot" ]] && _failed_slot="$slot_current"
        _row "Expected"  "!!  @${slot_current}  (booted @${booted} instead of expected — @${_failed_slot} failed)"
        _rec "Booted to candidate slot — expected slot failed; run: shani-deploy --rollback"
    else
        _row "Expected"  "!!  @${slot_current}  (mismatch — booted: @${booted})"
        _rec "Slot mismatch with no failure or reboot-needed marker — run: shani-deploy --rollback"
    fi

    # Fallback — the slot that is NOT current-slot (the true systemd-boot fallback).
    # slot_previous tracks last slot switch history, not the fallback target —
    # derive it directly as the other slot.
    local _fallback_slot
    [[ "$slot_current" == "blue" ]] && _fallback_slot="green" || _fallback_slot="blue"

    if [[ -f "$DATA_BOOT_FAIL" ]]; then
        local _fail_slot; _fail_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "")
        if [[ "$_fail_slot" == "$_fallback_slot" ]]; then
            _row "Candidate"  "!   @${_fallback_slot}  (has recorded boot failure)"
        else
            _row "Candidate"  "--  @${_fallback_slot}"
        fi
    else
        _row "Candidate"  "--  @${_fallback_slot}"
    fi
}


_section_boot_health() {
    _head "Boot Health"

    # ── Boot chain service results ────────────────────────────────────────────
    # These four services form the boot tracking pipeline. Check each one's
    # last run result (is-failed) rather than just enabled state.
    #
    # Pipeline (in order):
    #   mark-boot-in-progress  — Before=local-fs.target: plants boot_in_progress
    #   mark-boot-success      — After=multi-user.target: writes boot-ok, removes boot_in_progress
    #   bless-boot             — After=mark-boot-success (ConditionPathExists=/data/boot-ok): bootctl set-good
    #   check-boot-failure     — OnBootSec=15m timer: writes boot_failure if boot-ok never appeared
    local chain_failed=()
    for svc in mark-boot-in-progress.service mark-boot-success.service bless-boot.service; do
        if systemctl is-failed --quiet "$svc" 2>/dev/null; then
            chain_failed+=("$svc")
        fi
    done
    if [[ ${#chain_failed[@]} -gt 0 ]]; then
        _row "Boot chain" "!!  failed this boot: $(_join "${chain_failed[@]}")"
        _rec "Boot chain service(s) failed: $(_join "${chain_failed[@]}") — run: systemctl status <unit>"
    fi

    # ── Overlay boot services ─────────────────────────────────────────────────
    # mount-and-reload: runs mount -a then daemon-reload — must succeed for
    # bind-mount services to have their persistent state available.
    # start-overlay-services: starts services whose unit files live in the /etc
    # overlay (not baked into the base image). Failure = those services never start.
    local overlay_boot_failed=()
    for svc in mount-and-reload.service start-overlay-services.service; do
        if systemctl is-failed --quiet "$svc" 2>/dev/null; then
            overlay_boot_failed+=("$svc")
        fi
    done
    if [[ ${#overlay_boot_failed[@]} -gt 0 ]]; then
        _row "Overlay boot" "!!  failed: $(_join "${overlay_boot_failed[@]}")"
        _rec "Overlay boot service(s) failed: $(_join "${overlay_boot_failed[@]}") — run: systemctl status <unit>"
    fi

    # ── boot-ok: written by mark-boot-success after multi-user.target ────────
    if [[ -f "$DATA_BOOT_OK" ]]; then
        local last_ok; last_ok=$(stat -c '%y' "$DATA_BOOT_OK" 2>/dev/null | cut -d. -f1 || echo "?")
        _row "Last boot"  "OK  ${last_ok}"
    else
        local install_age=0
        if [[ -f /etc/shani-version ]]; then
            local epoch; epoch=$(stat -c '%Y' /etc/shani-version 2>/dev/null || echo "0")
            install_age=$(( ( $(date +%s) - epoch ) / 86400 ))
        fi
        if (( install_age <= 3 )) && [[ ! -f "$DATA_BOOT_FAIL" ]]; then
            _row "Last boot"  "--  no record yet (fresh install)"
        else
            _row "Last boot"  "!!  no successful boot recorded"
            _rec "No /data/boot-ok — mark-boot-success.service may have failed to run"
        fi
    fi

    # ── boot_in_progress: planted by mark-boot-in-progress, removed by mark-boot-success ──
    # Presence after boot-ok exists = mark-boot-success did not finish (failed/skipped)
    if [[ -f /data/boot_in_progress ]]; then
        if [[ -f "$DATA_BOOT_OK" ]]; then
            _row "In-progress" "!   boot_in_progress still set — mark-boot-success may not have completed"
            _rec "Stale /data/boot_in_progress — mark-boot-success.service may have failed"
        fi
        # If boot_in_progress exists and no boot-ok — boot is still in flight or timed out;
        # check-boot-failure.timer will record it at the 15-minute mark, so no extra rec needed here
    fi

    # ── Hard/soft failure markers ─────────────────────────────────────────────
    if [[ -f "$DATA_BOOT_HARD_FAIL" ]]; then
        local s; s=$(cat "$DATA_BOOT_HARD_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "?")
        _row "Hard fail"  "!!  @${s} failed to mount root — run: shani-deploy --rollback"
        _rec "HARD BOOT FAILURE: @${s} could not mount root filesystem — run: shani-deploy --rollback"
    elif [[ -f "$DATA_BOOT_FAIL" ]]; then
        local s; s=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "?")
        local booted_slot; booted_slot=$(_get_booted_subvol)
        local current_slot; current_slot=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
        if [[ "$booted_slot" == "$current_slot" ]]; then
            # Healthy: booted into the right slot; failure is for the other (fallback) slot.
            # This is a stale marker from a previous incident — not an emergency.
            _row "Failure"    "--  prior boot failure recorded for @${s} (current boot is healthy)"
            _rec "Stale boot failure marker for @${s} — run: shani-health --clear-boot-failure to remove it  [auto]"
        elif [[ "$s" == "$booted_slot" ]]; then
            # The failure marker names the slot we're currently booted into —
            # it had a prior failed attempt but succeeded this boot.
            _row "Failure"    "--  prior boot failure recorded for @${s} (booted successfully this time)"
            _rec "Stale boot failure marker for @${s} — run: shani-health --clear-boot-failure to remove it  [auto]"
        else
            _row "Failure"    "!   boot failure recorded for @${s}"
            # Slots section already emits a rollback rec for this case; skip duplicate
        fi
    fi

    # ── boot_failure.acked ────────────────────────────────────────────────────
    # mark-boot-in-progress CLEARS this on every boot, so its presence means:
    # the rollback dialog ran this boot but rollback may not have completed
    if [[ -f "$DATA_BOOT_FAIL_ACKED" ]]; then
        _row "Acked"      "!   failure acked but rollback may not have completed"
        _rec "boot_failure.acked present — run: shani-deploy --rollback to finish recovery"
    fi

    # ── /proc/cmdline slot cross-check ────────────────────────────────────────
    # Verify the running kernel's rootflags actually match the booted subvol
    # we detected. A mismatch means the UKI embedded the wrong slot cmdline.
    local cmdline_subvol
    cmdline_subvol=$(grep -o 'subvol=@[^ ,]*' /proc/cmdline 2>/dev/null \
        | head -1 | sed 's/subvol=@//' | sed 's/[, ].*//' || echo "")
    if [[ -n "$cmdline_subvol" ]]; then
        local _booted_now; _booted_now=$(_get_booted_subvol)
        if [[ "$cmdline_subvol" != "$_booted_now" ]]; then
            _row "Cmdline slot" "!!  /proc/cmdline says @${cmdline_subvol} but booted from @${_booted_now}"
            _rec "Cmdline slot mismatch — UKI may have wrong subvol embedded; run: gen-efi configure ${_booted_now}"
        fi
    fi

    # ── dracut 99shanios module ───────────────────────────────────────────────
    # This module installs the boot_hard_failure hook into the initramfs.
    # Without it, root mount failures are undetectable and rollback is blind.
    local dracut_mod="/usr/lib/dracut/modules.d/99shanios"
    if [[ -d "$dracut_mod" ]]; then
        local mod_files; mod_files=$(ls "$dracut_mod"/*.sh 2>/dev/null | wc -l || echo "0")
        if (( mod_files >= 2 )); then
            _row "Dracut mod"  "OK  99shanios module installed (${mod_files} hooks)"
        else
            _row "Dracut mod"  "!   99shanios module incomplete (${mod_files}/3 files)"
            _rec "dracut 99shanios module incomplete — reinstall ShaniOS dracut hooks"
        fi
    else
        _row "Dracut mod"  "!!  99shanios dracut module missing — hard boot failures undetectable"
        _rec "dracut 99shanios module missing — boot failure detection broken; reinstall dracut hooks"
    fi

    # ── check-boot-failure.timer ──────────────────────────────────────────────
    # Fires OnBootSec=15m; ConditionPathExists=/data/boot_in_progress — only runs
    # if boot_in_progress still exists at 15min, meaning mark-boot-success never ran
    local cbf_enabled; cbf_enabled=$(systemctl is-enabled check-boot-failure.timer 2>/dev/null || echo "disabled")
    local cbf_active;  cbf_active=$(systemctl is-active  check-boot-failure.timer 2>/dev/null || echo "inactive")
    if [[ "$cbf_enabled" == "disabled" || "$cbf_enabled" == "missing" || "$cbf_enabled" == "not-found" ]]; then
        _row "Fail timer" "!!  check-boot-failure.timer disabled — boot failures won't be auto-recorded"
        _rec "check-boot-failure.timer is disabled — automatic boot failure detection is broken"
    elif [[ "$cbf_active" == "failed" ]]; then
        _row "Fail timer" "!!  check-boot-failure.timer failed — boot failure detection broken"
        _rec "check-boot-failure.timer failed — run: systemctl reset-failed check-boot-failure.timer && systemctl start check-boot-failure.timer  [auto]"
    fi
}
_section_boot_entries() {
    _head "Boot Entries"

    if ! mountpoint -q "$ESP" 2>/dev/null; then
        _row "ESP"       "!!  could not mount — boot entries unavailable"
        return
    fi

    # ── ESP free space ────────────────────────────────────────────────────────
    # UKIs are ~100MB each; gen-efi fails silently if ESP fills up
    local esp_avail_mb
    esp_avail_mb=$(df -BM "$ESP" 2>/dev/null | awk 'NR==2{gsub(/M/,"",$4); print $4}' || echo "")
    if [[ "$esp_avail_mb" =~ ^[0-9]+$ ]]; then
        if (( esp_avail_mb < 50 )); then
            _row "ESP space"  "!!  ${esp_avail_mb} MB free — gen-efi will fail"
            _rec "ESP nearly full (${esp_avail_mb} MB) — clean old entries or expand ESP"
        elif (( esp_avail_mb < 150 )); then
            _row "ESP space"  "!   ${esp_avail_mb} MB free — getting tight"
        else
            _row "ESP space"  "OK  ${esp_avail_mb} MB free"
        fi
    fi

    # ── Shim and MokManager on ESP ────────────────────────────────────────────
    # shim (BOOTX64.EFI) — first-stage loader, Microsoft-signed
    # mmx64.efi — MokManager, needed for MOK enrollment at boot
    local shim_dst="$ESP/EFI/BOOT/BOOTX64.EFI"
    local mmx64_dst="$ESP/EFI/BOOT/mmx64.efi"
    local sdboot_dst="$ESP/EFI/BOOT/grubx64.efi"
    local efi_ok=() efi_missing=()
    [[ -f "$shim_dst"   ]] && efi_ok+=("shim")    || efi_missing+=("BOOTX64.EFI")
    [[ -f "$mmx64_dst"  ]] && efi_ok+=("mmx64")   || efi_missing+=("mmx64.efi")
    [[ -f "$sdboot_dst" ]] && efi_ok+=("sd-boot")  || efi_missing+=("grubx64.efi")
    if [[ ${#efi_missing[@]} -eq 0 ]]; then
        _row "EFI files"  "OK  shim + mmx64 + sd-boot present"
        # Check if source shim/sd-boot is newer than ESP copy — gen-efi auto-updates
        # but only when run; health warns so the user knows to trigger a UKI rebuild.
        local shim_src="/usr/share/shim-signed/shimx64.efi"
        local sdboot_src="/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
        local stale_efi=()
        [[ -f "$shim_src"   && "$shim_src"   -nt "$shim_dst"   ]] && stale_efi+=("shim")
        [[ -f "$sdboot_src" && "$sdboot_src" -nt "$sdboot_dst" ]] && stale_efi+=("sd-boot")
        if [[ ${#stale_efi[@]} -gt 0 ]]; then
            local _stale_str; _stale_str=$(IFS='+'; echo "${stale_efi[*]}")
            _row2 "!  ${_stale_str} source newer than ESP copy — run: gen-efi configure <booted_slot>  [auto]"
            _rec "ESP ${_stale_str} is stale (newer source available) — run: gen-efi configure <booted_slot>  [auto]"
        fi
    else
        local _em_str; _em_str=$(IFS=' '; echo "${efi_missing[*]}")
        _row "EFI files"  "!!  missing: ${_em_str}"
        _rec "EFI boot files missing (${_em_str}) — run: gen-efi configure <booted_slot>"
    fi

    local loader_conf="$ESP/loader/loader.conf"

    # ── vconsole.conf keymap ──────────────────────────────────────────────────
    # gen-efi embeds KEYMAP from /etc/vconsole.conf into the UKI as rd.vconsole.keymap.
    # If missing or unset, the UKI omits the keymap — LUKS passphrase entry at
    # boot may use the wrong keyboard layout, locking users out.
    local vconsole_keymap=""
    if [[ ! -f /etc/vconsole.conf ]]; then
        _row "Keymap"     "!   /etc/vconsole.conf missing — UKI will have no keymap"
        _rec "Create /etc/vconsole.conf with KEYMAP= set (e.g. KEYMAP=us) and regenerate UKI"
    else
        vconsole_keymap=$(grep -E '^KEYMAP=' /etc/vconsole.conf 2>/dev/null \
            | cut -d= -f2 | tr -d "\"'" | tr -cd 'A-Za-z0-9._-' || echo "")
        if [[ -z "$vconsole_keymap" ]]; then
            _row "Keymap"     "!   KEYMAP not set in /etc/vconsole.conf — UKI will have no keymap"
            _rec "Set KEYMAP= in /etc/vconsole.conf (e.g. KEYMAP=us) and regenerate UKI: gen-efi configure <slot>"
        else
            # Cross-check: is the embedded keymap in the running UKI consistent?
            local cmdline_keymap
            cmdline_keymap=$(grep -o 'rd.vconsole.keymap=[^ ]*' /proc/cmdline 2>/dev/null \
                | cut -d= -f2 || echo "")
            if [[ -n "$cmdline_keymap" && "$cmdline_keymap" != "$vconsole_keymap" ]]; then
                _row "Keymap"     "!   mismatch: UKI has '${cmdline_keymap}', vconsole.conf has '${vconsole_keymap}'"
                _rec "Keymap mismatch between running UKI and vconsole.conf — regenerate: gen-efi configure <slot>  [auto]"
            else
                _row "Keymap"     "OK  ${vconsole_keymap}${cmdline_keymap:+ (matches UKI)}"
            fi
        fi
    fi

    # ── UKI presence and relative age ────────────────────────────────────────
    # Both UKIs must exist; the candidate shouldn't be drastically older than current
    local booted_uki candidate_uki booted_ts candidate_ts
    local current_slot; current_slot=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
    local candidate_slot
    [[ "$current_slot" == "blue" ]] && candidate_slot="green" || candidate_slot="blue"

    booted_uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${booted}.efi"
    candidate_uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${candidate_slot}.efi"

    if [[ ! -f "$booted_uki" ]]; then
        _row "UKI"       "!!  current slot UKI missing: $(basename "$booted_uki")"
        _rec "Current slot UKI missing — run: gen-efi configure ${current_slot}  [auto]"
    elif [[ ! -f "$candidate_uki" ]]; then
        _row "UKI"       "!   candidate slot UKI missing: $(basename "$candidate_uki")"
        _rec "Candidate slot UKI missing — run: shani-deploy to rebuild it"
    else
        booted_ts=$(stat -c '%Y' "$booted_uki" 2>/dev/null || echo "0")
        candidate_ts=$(stat -c '%Y' "$candidate_uki" 2>/dev/null || echo "0")
        local age_diff=$(( booted_ts - candidate_ts ))
        if (( age_diff > 86400 * 30 )); then
            # Candidate UKI is >30 days older than current — likely stale rollback target
            local age_days=$(( age_diff / 86400 ))
            _row "UKI"   "!   candidate @${candidate_slot} UKI is ${age_days}d older than current"
            _rec "Candidate slot UKI is stale — run shani-deploy to refresh it"
        else
            _row "UKI"   "OK  both slots present"
        fi
    fi

    # ── loader.conf default= slot cross-check ────────────────────────────────
    # The default= entry in loader.conf controls which UKI boots by default.
    # It must point to the current slot; a mismatch means the wrong OS version
    # activates on next boot even though deployment succeeded.
    if [[ -f "$loader_conf" ]]; then
        local default_entry
        default_entry=$(grep '^default' "$loader_conf" 2>/dev/null | awk '{print $2}' || echo "")
        # default= is written as a glob by finalize_boot_entries:
        #   tries path  → shanios-blue+*.conf  (matches +3-0, +2-1 … as boot counting renames it)
        #   no-tries    → shanios-blue.conf    (rollback/restore — both slots known-good)
        # Check that the glob/filename contains the current-slot name as a distinct token.
        if [[ -n "$default_entry" && -n "$current_slot" ]]; then
            if echo "$default_entry" | grep -qiE "(^|[-_])${current_slot}([-_+.]|$)"; then
                _row "Boot default" "OK  default entry targets @${current_slot}  (${default_entry})"
            else
                _row "Boot default" "!!  default '${default_entry}' does not match current slot @${current_slot}"
                _rec "loader.conf default= points to wrong slot — run: gen-efi configure ${current_slot}"
            fi
        fi
    fi

    local orphans=()
    for slot in blue green; do
        local plain="$ESP/loader/entries/${OS_NAME}-${slot}.conf"
        local tries; tries=$(ls "$ESP/loader/entries/${OS_NAME}-${slot}"+*.conf \
            2>/dev/null | head -1 || echo "")
        [[ -f "$plain" && -n "$tries" ]] && orphans+=("${OS_NAME}-${slot}.conf")
    done
    if [[ ${#orphans[@]} -gt 0 ]]; then
        _row "Orphans"   "!   $(_join "${orphans[@]}")"
        _rec "Orphaned boot entries ($(_join "${orphans[@]}")) — run: shani-health --fix  [auto]"
    fi

    local editor; editor=$(grep '^editor' "$loader_conf" 2>/dev/null \
        | awk '{print $2}' || echo "not set")
    if [[ "$editor" == "0" ]]; then
        _row "Editor"    "OK  disabled"
    else
        _row "Editor"    "!!  not disabled (cmdline editable at boot)"
        _rec "systemd-boot editor not disabled — add 'editor 0' to loader.conf  [auto]"
    fi
}

_section_deployment() {
    _head "Deployment"

    if [[ -f "$DATA_DEPLOY_PENDING" ]]; then
        _row "State"     "!   deploy pending (interrupted?) — run: shani-deploy --rollback"
    elif [[ -f "$DATA_REBOOT_NEEDED" ]]; then
        local ver; ver=$(cat "$DATA_REBOOT_NEEDED" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
        local rn_age_days; rn_age_days=$(( ( $(date +%s) - $(stat -c '%Y' "$DATA_REBOOT_NEEDED" 2>/dev/null || echo "0") ) / 86400 ))
        if (( rn_age_days >= 3 )); then
            _row "State"     "!!  reboot overdue (${rn_age_days}d) — v${ver} waiting to activate"
            _rec "Reboot has been pending for ${rn_age_days} days — reboot to activate v${ver}"
        else
            _row "State"     "!   reboot required to activate v${ver}  (${rn_age_days}d pending)"
        fi
    else
        _row "State"     "OK  clean"
    fi

    # ── Stale deployment_pending marker ──────────────────────────────────────
    # deployment_pending surviving a reboot means an interrupted deploy left the
    # system in a half-updated state — the candidate slot may be inconsistent.
    if [[ -f /data/deployment_pending ]]; then
        local dp_age; dp_age=$(( ( $(date +%s) - $(stat -c '%Y' /data/deployment_pending 2>/dev/null || echo "0") ) / 60 ))
        if (( dp_age > 60 )); then
            _row "Deploy"   "!!  deployment_pending ${dp_age}min old — deploy interrupted?"
            _rec "Stale deployment_pending (${dp_age} min) — check: shani-deploy --rollback"
        fi
    fi

    if [[ -f /etc/shani-version ]]; then
        local version ver_ts
        version=$(cat /etc/shani-version 2>/dev/null || echo "?")
        ver_ts=$(stat -c '%y' /etc/shani-version 2>/dev/null | cut -d. -f1 || echo "?")
        _row "Installed"  "--  v${version}  (since ${ver_ts})"
    fi

    # ── Per-slot cmdline files ────────────────────────────────────────────────
    # gen-efi writes /etc/kernel/install_cmdline_<slot> — required for correct UKI rebuild
    local cmdline_missing=()
    for slot in blue green; do
        local cf="/etc/kernel/install_cmdline_${slot}"
        [[ -f "$cf" ]] || cmdline_missing+=("$slot")
    done
    if [[ ${#cmdline_missing[@]} -eq 0 ]]; then
        # Files exist — verify each contains the correct subvol for its slot
        local cmdline_wrong=()
        for slot in blue green; do
            local cf="/etc/kernel/install_cmdline_${slot}"
            local content; content=$(cat "$cf" 2>/dev/null || echo "")
            if ! echo "$content" | grep -q "subvol=@${slot}[,\ ]"; then
                cmdline_wrong+=("${slot}(missing subvol=@${slot})")
            fi
        done
        if [[ ${#cmdline_wrong[@]} -gt 0 ]]; then
            local _cw_str; _cw_str=$(IFS=' '; echo "${cmdline_wrong[*]}")
            _row "Cmdline"    "!!  wrong subvol in cmdline: ${_cw_str}"
            _rec "Cmdline files have wrong subvol — run: gen-efi configure <slot> for each  [auto]"
        else
            _row "Cmdline"    "OK  install_cmdline_{blue,green} present and correct"
        fi
    else
        _row "Cmdline"    "!!  missing for: $(_join "${cmdline_missing[@]}") — next gen-efi may produce wrong UKI"
        _rec "Cmdline files missing for @$(_join "${cmdline_missing[@]}") — run: gen-efi configure <slot> for each  [auto]"
    fi

    # ── Slot backup snapshots ─────────────────────────────────────────────────
    # Deploy keeps one backup per slot — if missing, --rollback has no snapshot to restore from
    local backup_missing=() backup_found=()
    for slot in blue green; do
        local has_backup
        has_backup=$(btrfs subvolume list / 2>/dev/null \
            | awk -v s="${slot}_backup_" '$NF ~ s {print $NF; exit}' || echo "")
        if [[ -n "$has_backup" ]]; then
            # Try to get the referenced size of the backup subvolume
            local bk_size=""
            local bk_path="/${has_backup}"
            if [[ -d "$bk_path" ]]; then
                local bk_mb; bk_mb=$(du -sm "$bk_path" 2>/dev/null | awk '{print $1}' || echo "")
                [[ "$bk_mb" =~ ^[0-9]+$ ]] && bk_size=" (${bk_mb} MB)"
            fi
            backup_found+=("@${slot}:$(basename "$has_backup")${bk_size}")
        else
            backup_missing+=("@${slot}")
        fi
    done
    if [[ ${#backup_missing[@]} -eq 0 ]]; then
        _row "Backups"    "OK  $(IFS=' '; echo "${backup_found[*]}")"
        # Warn if any backup snapshot is very old (>30 days)
        local _now_dep; _now_dep=$(date +%s)
        for slot in blue green; do
            local _bk_path; _bk_path=$(btrfs subvolume list / 2>/dev/null                 | awk -v s="${slot}_backup_" '$NF ~ s {print $NF; exit}' || echo "")
            [[ -z "$_bk_path" ]] && continue
            local _bk_created; _bk_created=$(btrfs subvolume show "/${_bk_path}" 2>/dev/null                 | awk -F'\t' '/Creation time:/{gsub(/^[[:space:]]+/,"",$2); print $2}' | head -1 || true)
            [[ -z "$_bk_created" ]] && continue
            local _bk_ep; _bk_ep=$(date -d "$_bk_created" +%s 2>/dev/null || echo "")
            [[ -z "$_bk_ep" ]] && continue
            local _bk_age=$(( (_now_dep - _bk_ep) / 86400 ))
            if (( _bk_age > 30 )); then
                _row2 "!   @${slot} backup is ${_bk_age}d old — deploy to refresh"
                _rec "Backup snapshot for @${slot} is ${_bk_age} days old — run shani-deploy to refresh"
            fi
        done
    else
        _row "Backups"    "!   no backup snapshot for: $(_join "${backup_missing[@]}") — rollback unavailable"
        _rec "No rollback backup for $(_join "${backup_missing[@]}") — run shani-deploy to create one"
    fi

    # ── Shani signing key file ────────────────────────────────────────────────
    # /etc/shani-keys/signing.asc ships with the OS and is the offline source
    # for importing the GPG key used to verify OS image downloads.
    local _skey_file="/etc/shani-keys/signing.asc"
    if [[ ! -f "$_skey_file" ]]; then
        _row "Key file"    "!   ${_skey_file} missing — GPG key must be fetched from keyserver"
        _rec "Signing key file missing — restore: ${_skey_file} (or import from keyserver)"
    fi

    # ── Deploy log size ───────────────────────────────────────────────────────
    # /var/log/shanios-deploy.log growing beyond ~10 MB usually indicates
    # repeated failed deploy attempts accumulating without rotation.
    if [[ -f "$DEPLOY_LOG" ]]; then
        local deploy_log_mb
        deploy_log_mb=$(du -sm "$DEPLOY_LOG" 2>/dev/null | awk '{print $1}' || echo "0")
        if [[ "$deploy_log_mb" =~ ^[0-9]+$ ]] && (( deploy_log_mb >= 10 )); then
            _row "Deploy log"  "!   ${deploy_log_mb} MB — may indicate repeated failures"
            _rec "Deploy log is ${deploy_log_mb} MB — review: tail -100 ${DEPLOY_LOG}"
        fi
    fi

    # ── Stale downloads ───────────────────────────────────────────────────────
    local dl_dir="/data/downloads"
    if [[ ! -d "$dl_dir" ]]; then
        _row "Downloads"  "!   /data/downloads missing — shani-deploy will fail to store images"
        _rec "/data/downloads directory missing — run: mkdir -p /data/downloads  [auto]"
    else
        local dl_size_mb
        dl_size_mb=$(du -sm "$dl_dir" 2>/dev/null | awk '{print $1}' || echo "0")
        if [[ "$dl_size_mb" =~ ^[0-9]+$ ]] && (( dl_size_mb > 5120 )); then
            _row "Downloads"  "!   ${dl_size_mb} MB in /data/downloads — run: shani-deploy --cleanup"
            _rec "Download cache is ${dl_size_mb} MB — free space with: shani-deploy --cleanup"
        elif [[ "$dl_size_mb" =~ ^[0-9]+$ ]] && (( dl_size_mb > 1024 )); then
            _row "Downloads"  "--  ${dl_size_mb} MB cached (run: shani-deploy --cleanup to free space)"
        fi
    fi

    # ── Stale shani-update lock ───────────────────────────────────────────────
    # Lock file is in XDG_RUNTIME_DIR or ~/.cache — if it survives across boots
    # (i.e. lives in a persistent location) and is old, the update process died
    local _login_u_dep="$_CALLER_USER"
    local _uhome_dep; _uhome_dep=$(getent passwd "${_login_u_dep}" 2>/dev/null | cut -d: -f6 || echo "")
    if [[ -n "$_uhome_dep" ]]; then
        local _lock="${_uhome_dep}/.cache/shani-update.lock"
        if [[ -f "$_lock" ]]; then
            local _lock_age; _lock_age=$(( ( $(date +%s) - $(stat -c '%Y' "$_lock" 2>/dev/null || echo "0") ) / 60 ))
            if (( _lock_age > 30 )); then
                _row "Upd lock"  "!   stale lock file (${_lock_age}min old) — update may be stuck"
                _rec "Stale shani-update lock — remove: rm ${_lock}"
            fi
        fi
    fi

    # ── GPG signing key ───────────────────────────────────────────────────────
    # Key must be imported for image verification.
    # Ships locally at GPG_SIGNING_KEY_FILE — no network required.
    if gpg --batch --list-keys "$GPG_SIGNING_KEY" &>/dev/null 2>&1; then
        _row "GPG key"    "OK  signing key imported"
    elif [[ -f "$GPG_SIGNING_KEY_FILE" ]]; then
        _row "GPG key"    "!!  signing key not in keyring — image verification will fail"
        _rec "Import GPG signing key: gpg --import ${GPG_SIGNING_KEY_FILE}  [auto]"
    else
        _row "GPG key"    "!!  signing key not in keyring — image verification will fail"
        _rec "Import GPG signing key: gpg --keyserver keys.openpgp.org --recv-keys ${GPG_SIGNING_KEY}  [auto]"
    fi

    # ── Download tools ────────────────────────────────────────────────────────
    # shani-deploy tries aria2c → wget → curl; at least one must be present.
    # pv is optional but provides progress display during extraction.
    local dl_tools=()
    command -v aria2c &>/dev/null && dl_tools+=("aria2c")
    command -v wget   &>/dev/null && dl_tools+=("wget")
    command -v curl   &>/dev/null && dl_tools+=("curl")
    if [[ ${#dl_tools[@]} -eq 0 ]]; then
        _row "DL tools"   "!!  no download tool found (aria2c/wget/curl) — updates will fail"
        _rec "No download tools available — install aria2c, wget, or curl"
    else
        command -v pv &>/dev/null || \
            _row2 "--  pv not installed (no extraction progress display)"
    fi

    # ── Last deploy action ────────────────────────────────────────────────────
    # Scan only the last 200 lines of the log — the most recent event is always
    # near the end. Avoids reading the entire log file line-by-line.
    if [[ -f "$DEPLOY_LOG" ]]; then
        local _last_line=""
        # Try current log first, fall back to .old if no match found
        for _logf in "$DEPLOY_LOG" "${DEPLOY_LOG}.old"; do
            [[ -f "$_logf" ]] || continue
            _last_line=$(tail -200 "$_logf" 2>/dev/null \
                | grep -E "Deployment successful|Emergency rollback complete|Fallback slot ready|Rollback complete|Running system:" \
                | tail -1 || echo "")
            [[ -n "$_last_line" ]] && break
        done
        if [[ -n "$_last_line" ]]; then
            local _ev_ts
            _ev_ts=$(echo "$_last_line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || echo "")
            if echo "$_last_line" | grep -q "Deployment successful"; then
                local _ver; _ver=$(echo "$_last_line" | grep -oE 'v[0-9]{8}' | head -1 || echo "")
                _row "Last deploy" "OK  ${_ev_ts}  deployed ${_ver}"
            elif echo "$_last_line" | grep -q "Emergency rollback complete"; then
                _row "Last deploy" "!   ${_ev_ts}  rollback (emergency — deploy failed)"
            elif echo "$_last_line" | grep -q "Fallback slot ready"; then
                _row "Last deploy" "!   ${_ev_ts}  rollback (no backup — snapshot of booted slot)"
            elif echo "$_last_line" | grep -q "Rollback complete"; then
                _row "Last deploy" "!   ${_ev_ts}  rollback (manual)"
            elif echo "$_last_line" | grep -q "Running system:"; then
                local _ver; _ver=$(echo "$_last_line" | grep -oE 'v[0-9]+' | head -1 || echo "")
                _row "Last deploy" "--  ${_ev_ts}  boot ${_ver}"
            fi
        fi
    fi
}
_section_data_state() {
    _head "Data State"

    # ── /data subvolume mount ─────────────────────────────────────────────────
    if ! findmnt -n /data &>/dev/null; then
        _row "/data"          "!!  not mounted — system state unavailable"
        _rec "/data subvolume not mounted — check fstab and Btrfs subvolume list"
        return
    fi
    _row "/data"          "OK  mounted"

    # ── shanios-tmpfiles-data.service ─────────────────────────────────────────
    # Creates /data/varlib, /data/varspool, /data/overlay/{upper,work} and other
    # persistent dirs on first boot or after a fresh @data subvolume. If it
    # failed, bind-mounts and the /etc overlay will be broken.
    local tmpfiles_res
    tmpfiles_res=$(systemctl show shanios-tmpfiles-data.service \
        --property=Result --value 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ "$tmpfiles_res" == "exit-code" || "$tmpfiles_res" == "core-dump" || "$tmpfiles_res" == "signal" ]]; then
        _row "tmpfiles"   "!!  shanios-tmpfiles-data.service failed — /data dirs may be missing"
        _rec "shanios-tmpfiles-data.service failed — run: systemctl restart shanios-tmpfiles-data.service  [auto]"
    elif [[ "$tmpfiles_res" == "success" || "$tmpfiles_res" == "" ]]; then
        : # OK or never ran (fresh boot) — dirs checked individually below
    fi
    # Written by shani-deploy on install/slot-switch.
    # Cleared by shani-user-setup after it runs successfully.
    # Setup is triggered by running the binary directly (no path/service unit).
    if [[ -f /data/user-setup-needed ]]; then
        local marker_age_days=0
        local marker_epoch; marker_epoch=$(stat -c '%Y' /data/user-setup-needed 2>/dev/null || echo "0")
        (( marker_epoch > 0 )) && \
            marker_age_days=$(( ( $(date +%s) - marker_epoch ) / 86400 ))

        if [[ ! -x "$USER_SETUP_BIN" ]]; then
            _row "User setup" "!!  marker present but ${USER_SETUP_BIN} missing or not executable"
            _rec "shani-user-setup binary missing — reinstall: ${USER_SETUP_BIN}"
        elif (( marker_age_days >= 1 )); then
            _row "User setup" "!   marker ${marker_age_days}d old — setup not yet run"
            _rec "user-setup-needed marker is ${marker_age_days}d old — run: shani-user-setup  [auto]"
        else
            _row "User setup" "--  pending (marker present, will run shortly)"
        fi
    else
        _row "User setup"  "OK  complete"
    fi

    # ── varlib / varspool bind-mount directories ───────────────────────────────
    # These live under /data and are bind-mounted into /var/lib and /var/spool
    # for services that need persistent state across the volatile /var tmpfs.
    local varlib_ok=0 varspool_ok=0
    [[ -d /data/varlib   ]] && varlib_ok=1
    [[ -d /data/varspool ]] && varspool_ok=1

    if (( varlib_ok )); then
        local varlib_svcs; varlib_svcs=$(ls /data/varlib 2>/dev/null | wc -l || echo "0")
        _row "varlib"   "OK  ${varlib_svcs} service dir(s) in /data/varlib"
    else
        _row "varlib"   "!   /data/varlib missing — service state bind-mounts may fail"
        _rec "/data/varlib directory missing — run: mkdir -p /data/varlib  [auto]"
    fi

    if (( varspool_ok )); then
        local varspool_svcs; varspool_svcs=$(ls /data/varspool 2>/dev/null | wc -l || echo "0")
        _row "varspool" "OK  ${varspool_svcs} spool dir(s) in /data/varspool"
    else
        _row "varspool" "!   /data/varspool missing — spool bind-mounts may fail"
        _rec "/data/varspool directory missing — run: mkdir -p /data/varspool  [auto]"
    fi

    # ── /data overlay directories (for /etc overlay) ──────────────────────────
    local overlay_upper="/data/overlay/etc/upper"
    local overlay_work="/data/overlay/etc/work"
    if [[ ! -d "$overlay_upper" || ! -d "$overlay_work" ]]; then
        _row "overlay"  "!   /data/overlay/etc/{upper,work} missing"
        _rec "/data/overlay dirs missing — run shanios-tmpfiles-data.service or: mkdir -p /data/overlay/etc/{upper,work}"
    fi

}

_section_immutability() {
    _head "Immutability"

    # ── Root filesystem ───────────────────────────────────────────────────────
    local opts; opts=$(findmnt -n -o OPTIONS / 2>/dev/null || true)
    if echo "$opts" | grep -qw ro; then
        _row "Root (/)"   "OK  read-only"
    else
        _row "Root (/)"   "!!  writable — immutability compromised"
        _rec "Root filesystem is writable — reboot may be required"
    fi

    # ── /var volatile (systemd.volatile=state) ────────────────────────────────
    if findmnt -n -t tmpfs /var &>/dev/null; then
        _row "/var"       "OK  tmpfs (volatile — cleared each boot)"
    else
        local var_opts; var_opts=$(findmnt -n -o OPTIONS /var 2>/dev/null || true)
        if [[ -n "$var_opts" ]]; then
            _row "/var"   "!   not tmpfs (${var_opts%%,*}) — systemd.volatile=state may be missing"
            _rec "'/var' is not tmpfs — check 'systemd.volatile=state' is in the UKI cmdline"
        else
            _row "/var"   "--  /var mount not detected"
        fi
    fi

    # ── /etc overlay ─────────────────────────────────────────────────────────
    local overlay_upper="/data/overlay/etc/upper"
    if [[ -d "$overlay_upper" ]]; then
        local count; count=$(find "$overlay_upper" -mindepth 1 2>/dev/null | wc -l || echo "0")
        local etc_mnt_opts; etc_mnt_opts=$(findmnt -n -o OPTIONS /etc 2>/dev/null || true)
        if [[ -n "$etc_mnt_opts" ]]; then
            # Verify required overlay options: index=off and metacopy=off
            local opts_ok=1
            echo "$etc_mnt_opts" | grep -q 'index=off'    || opts_ok=0
            echo "$etc_mnt_opts" | grep -q 'metacopy=off' || opts_ok=0
            if (( opts_ok )); then
                _row "/etc"   "OK  overlay active, ${count} file(s) modified vs base"
            else
                _row "/etc"   "!   overlay active but missing index=off or metacopy=off"
                _rec "/etc overlay missing required options (index=off,metacopy=off) — check fstab"
            fi
        else
            _row "/etc"   "!!  overlay NOT mounted — /etc from read-only root"
            _rec "/etc overlay not mounted — check etc-overlay.mount unit"
        fi
        if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 200 )); then
            _row2         "!  large overlay (${count} files) — significant config drift"
            _rec "Large /etc overlay (${count} files) — consider upstreaming to base image"
        elif [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
            local top_dirs
            top_dirs=$(find "$overlay_upper" -mindepth 2 -maxdepth 2 2>/dev/null \
                | sed "s|${overlay_upper}/||" | cut -d/ -f1 \
                | sort | uniq -c | sort -rn | head -5 \
                | awk '{printf "%s(%s) ",$2,$1}')
            [[ -n "$top_dirs" ]] && _row2 "--  top dirs: ${top_dirs}"
        fi
    else
        _row "/etc"   "!!  overlay upper dir missing — run shanios-tmpfiles-data.service"
        _rec "/etc overlay upper dir missing — run shanios-tmpfiles-data.service"
    fi

    # ── Critical subvolume health ─────────────────────────────────────────────
    # These subvolumes must exist and be mounted for the system to function.
    # @swap is optional (only if hibernation was configured at install).
    local -A subvol_mounts=(
        ["/home"]="@home"
        ["/data"]="@data"
        ["/nix"]="@nix"
        ["/var/log"]="@log"
        ["/var/lib/flatpak"]="@flatpak"
        ["/var/lib/containers"]="@containers"
    )
    local sv_missing=() sv_ok=0
    for mnt in /home /data /nix /var/log /var/lib/flatpak /var/lib/containers; do
        if findmnt -n "$mnt" &>/dev/null; then
            sv_ok=$(( sv_ok + 1 ))
        else
            sv_missing+=("${subvol_mounts[$mnt]}")
        fi
    done
    if [[ ${#sv_missing[@]} -eq 0 ]]; then
        _row "Subvolumes"  "OK  all ${sv_ok} critical subvolumes mounted"
    else
        _row "Subvolumes"  "!!  not mounted: $(_join "${sv_missing[@]}")"
        _rec "Critical Btrfs subvolumes not mounted ($(_join "${sv_missing[@]}")) — check fstab / shanios-tmpfiles-data.service"
    fi
}

# uki_booted_bad_ref and hibernate_stale are passed by name (printf -v trick)
_section_secureboot() {
    local booted="$1"
    local uki_booted_bad_ref="$2"
    local hibernate_stale="$3"

    _head "Secure Boot"

    if [[ ! -d /sys/firmware/efi ]]; then
        _row "Status"    "N/A  BIOS/legacy boot"
        return
    fi

    local sb_state; sb_state=$(mokutil --sb-state 2>/dev/null || echo "")

    # Check shim validation state — reuse sb_state to avoid calling mokutil twice
    local shim_validation_disabled=0
    echo "$sb_state" | grep -q "Secure Boot validation is disabled" \
        && shim_validation_disabled=1

    if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then
        if (( shim_validation_disabled )); then
            # SB on in firmware but shim is not validating signatures —
            # boot chain is active but shim bypass is in effect
            _row "Status"    "--  enabled (shim validation disabled)"
        else
            _row "Status"    "OK  enabled"
        fi
    else
        _row "Status"    "!!  disabled"
        _rec "Enable Secure Boot in BIOS/UEFI for full boot chain protection"
    fi

    local mok_count
    mok_count=$(mokutil --list-enrolled 2>/dev/null | grep -c 'SHA1 Fingerprint' || echo "0")
    local mok_der_check="/etc/secureboot/keys/MOK.der"

    # Compute local MOK.der fingerprint once — used for enrolled and pending checks
    local local_fp=""
    if [[ -f "$mok_der_check" ]] && command -v openssl &>/dev/null; then
        local_fp=$(openssl x509 -in "$mok_der_check" -inform DER -noout -fingerprint -sha1 \
            2>/dev/null | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' || echo "")
    fi


    if (( shim_validation_disabled )); then
        # Shim validation disabled — check if key is already enrolled.
        # If enrolled: run gen-efi enroll-mok again to re-enable validation
        #              (it was only disabled to skip the MokManager prompt).
        # If not enrolled: this is the expected pending state — key will be
        #              written to firmware on next boot, then enroll-mok
        #              re-enables validation automatically.
        local enrolled_match=0
        if [[ -n "$local_fp" ]] && \
           mokutil --list-enrolled 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]' \
           | grep -q "$local_fp"; then
            enrolled_match=1
        fi
        if (( enrolled_match )); then
            # Key enrolled but validation still disabled — re-enable it
            _row "MOK enrol" "!   shim validation disabled but key is enrolled — run: gen-efi enroll-mok"
            _rec "MOK key enrolled but shim validation still disabled — run: gen-efi enroll-mok  [auto]"
        else
            # Key pending — normal state after first enroll-mok run, before reboot
            _row "MOK enrol" "->  enrollment pending, shim validation bypassed — reboot, then run: gen-efi enroll-mok"
        fi
    else
        # Check if local key is pending enrollment
        local mok_pending=0
        if [[ -n "$local_fp" ]] && \
           mokutil --list-new 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]' \
           | grep -q "$local_fp"; then
            mok_pending=1
        fi

        if (( mok_pending )); then
            _row "MOK enrol" "->  enrollment pending — reboot, then run: gen-efi enroll-mok"
        elif (( mok_count > 0 )); then
            local enrolled_match=0
            if [[ -n "$local_fp" ]] && \
               mokutil --list-enrolled 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]' \
               | grep -q "$local_fp"; then
                enrolled_match=1
            fi
            if (( enrolled_match )); then
                _row "MOK enrol" "OK  ${mok_count} key(s) enrolled  (local key confirmed)"
            else
                _row "MOK enrol" "!   ${mok_count} key(s) enrolled but local MOK.der not matched — key may be stale"
                _rec "Enrolled MOK key does not match local MOK.der — re-enroll: gen-efi enroll-mok  [auto]"
            fi
        else
            _row "MOK enrol" "!!  no keys enrolled"
            _rec "Enroll MOK: gen-efi enroll-mok  [auto]"
        fi
    fi

    local mok_key="/etc/secureboot/keys/MOK.key"
    local mok_crt="/etc/secureboot/keys/MOK.crt"
    local mok_der="/etc/secureboot/keys/MOK.der"
    local mok_ok=0
    if [[ -f "$mok_key" && -f "$mok_crt" && -f "$mok_der" ]]; then
        mok_ok=1
        local expiry expiry_epoch now_epoch days_left
        expiry=$(openssl x509 -in "$mok_crt" -noout -enddate 2>/dev/null \
            | sed 's/notAfter=//' || echo "unknown")
        expiry_epoch=$(openssl x509 -in "$mok_crt" -noout -enddate 2>/dev/null \
            | sed 's/notAfter=//' | xargs -I{} date -d '{}' +%s 2>/dev/null || echo "0")
        now_epoch=$(date +%s)
        days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        if (( expiry_epoch > 0 && days_left < 0 )); then
            _row "MOK keys"  "!!  EXPIRED (${expiry}) — re-enroll MOK key"
            _rec "MOK signing key has expired — regenerate keys and re-enroll: gen-efi configure ${booted} then gen-efi enroll-mok"
        elif (( expiry_epoch > 0 && days_left < 90 )); then
            _row "MOK keys"  "!   expires in ${days_left} days (${expiry})"
            _rec "MOK cert expires in ${days_left} days — plan renewal before expiry to avoid Secure Boot breakage"
        else
            _row "MOK keys"  "OK  present (expires: ${expiry})"
        fi
    else
        _row "MOK keys"  "!!  missing"
        _rec "MOK signing keys missing — run: gen-efi configure ${booted}  (generates keys + rebuilds UKI), then: gen-efi enroll-mok"
    fi

    if (( mok_ok )); then
        # MOK.key must be 0600 — if readable by others, the signing key is exposed
        local mok_key_mode
        mok_key_mode=$(stat -c '%a' "$mok_key" 2>/dev/null || echo "")
        if [[ -n "$mok_key_mode" && "$mok_key_mode" != "600" ]]; then
            _row "MOK perms"  "!!  MOK.key is mode ${mok_key_mode} — should be 0600"
            _rec "MOK private key has wrong permissions — fix: chmod 600 ${mok_key}  [auto]"
        fi
        # Verify the key and cert form a valid pair (modulus match)
        local key_mod cert_mod
        key_mod=$(openssl rsa  -in "$mok_key" -noout -modulus 2>/dev/null | md5sum 2>/dev/null || echo "")
        cert_mod=$(openssl x509 -in "$mok_crt" -noout -modulus 2>/dev/null | md5sum 2>/dev/null || echo "")
        if [[ -n "$key_mod" && -n "$cert_mod" && "$key_mod" != "$cert_mod" ]]; then
            _row "MOK pair"   "!!  MOK.key and MOK.crt do not match — UKI signing will fail"
            _rec "MOK key/cert mismatch — regenerate: gen-efi configure ${booted} then gen-efi enroll-mok"
        fi

        local uki_ok=0 uki_bad=0 uki_miss=0
        local uki_bad_slots=() uki_miss_slots=()
        for slot in blue green; do
            local uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${slot}.efi"
            if [[ ! -f "$uki" ]]; then
                uki_miss=$(( uki_miss + 1 )); uki_miss_slots+=("$slot")
            elif sbverify --cert "$mok_crt" "$uki" &>/dev/null 2>&1; then
                uki_ok=$(( uki_ok + 1 ))
            else
                uki_bad=$(( uki_bad + 1 )); uki_bad_slots+=("$slot")
                [[ "$slot" == "$booted" ]] && printf -v "$uki_booted_bad_ref" '%s' "1"
            fi
        done

        if (( uki_bad > 0 || uki_miss > 0 )); then
            _row "UKI sigs"  "!!  ${uki_ok}/2 valid, ${uki_bad} invalid, ${uki_miss} missing"
            local fail_slot=""
            [[ -f "$DATA_BOOT_FAIL" ]] && \
                fail_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]')
            for bad in "${uki_bad_slots[@]}" "${uki_miss_slots[@]}"; do
                if [[ "$bad" == "$booted" ]]; then
                    local also=""
                    (( hibernate_stale )) && also=" (also fixes stale hibernate offset)"
                    _rec "UKI @${bad} (booted) invalid — run: gen-efi configure ${bad}${also}  [auto]"
                elif [[ -n "$fail_slot" && "$bad" == "$fail_slot" ]]; then
                    _rec "UKI @${bad} invalid (matches boot failure) — fixed by: shani-deploy --rollback"
                else
                    _rec "UKI @${bad} invalid — run: shani-deploy --rollback or a fresh deploy"
                fi
            done
        else
            _row "UKI sigs"  "OK  ${uki_ok}/2 valid"
        fi
    else
        _row "UKI sigs"  "--  cannot verify (MOK cert missing)"
    fi

    # ── UKI build tools ───────────────────────────────────────────────────────
    # dracut, sbsign and sbverify must all be present for gen-efi to build and
    # sign a UKI. Missing any one of them makes the next UKI rebuild impossible.
    local missing_tools=()
    for tool in dracut sbsign sbverify; do
        command -v "$tool" &>/dev/null || missing_tools+=("$tool")
    done
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        _row "UKI tools"  "!!  missing: $(_join "${missing_tools[@]}") — gen-efi / UKI rebuild will fail"
        _rec "Install missing UKI build tools: $(_join "${missing_tools[@]}")"
    fi
}

_section_kernel_security() {
    local sb_active="$1"   # "yes" if Secure Boot is enabled

    _head "Kernel Security"

    # ── LSM stack — check cmdline param and runtime state together ───────────
    local expected_lsm_param="landlock,lockdown,yama,integrity,apparmor,bpf"
    local actual_lsm_param; actual_lsm_param=$(grep -o 'lsm=[^ ]*' /proc/cmdline 2>/dev/null \
        | cut -d= -f2 || echo "")

    local active_lsms
    active_lsms=$(cat /sys/kernel/security/lsm 2>/dev/null | tr ',' ' ' || echo "unknown")

    local ima_compiled=0
    zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_IMA=y' && ima_compiled=1

    local expected=(landlock lockdown yama integrity apparmor bpf)
    local missing_lsms=() missing_build=()
    for lsm in "${expected[@]}"; do
        if ! echo "$active_lsms" | grep -qw "$lsm"; then
            [[ "$lsm" == "integrity" && $ima_compiled -eq 0 ]] \
                && missing_build+=("$lsm") || missing_lsms+=("$lsm")
        fi
    done

    local total='6'
    local active=$(( total - ${#missing_lsms[@]} - ${#missing_build[@]} ))

    if [[ "$actual_lsm_param" != "$expected_lsm_param" ]]; then
        # Cmdline is wrong — root cause of any missing LSMs
        if [[ -z "$actual_lsm_param" ]]; then
            _row "LSMs"  "!!  lsm= missing from cmdline — LSMs may not be active"
        else
            _row "LSMs"  "!   lsm= wrong: ${actual_lsm_param}"
        fi
        _rec "lsm= cmdline incorrect — regenerate UKI: gen-efi configure <slot>  [auto]"
    elif [[ ${#missing_lsms[@]} -eq 0 && ${#missing_build[@]} -eq 0 ]]; then
        _row "LSMs"  "OK  all ${total} active"
    elif [[ ${#missing_lsms[@]} -eq 0 ]]; then
        _row "LSMs"  "--  ${active}/${total} active ($(_join "${missing_build[@]}") not compiled in)"
    else
        _row "LSMs"  "!!  missing at runtime: $(_join "${missing_lsms[@]}")"
        _rec "LSMs not active: $(_join "${missing_lsms[@]}") — check lsm= kernel cmdline"
    fi

    # Lockdown — advisory rec only when SB is on and lockdown is none
    if [[ "$sb_active" == "yes" ]]; then
        local lockdown
        lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null \
            | grep -o '\[.*\]' | tr -d '[]' || echo "none")
        if [[ "$lockdown" == "none" ]]; then
            _rec "Kernel lockdown is 'none' despite Secure Boot active — consider adding lockdown=confidentiality to UKI cmdline"
        fi
    fi

    local bad_mods=()
    for mod in mei mei_me pcspkr; do
        lsmod 2>/dev/null | grep -qw "$mod" && bad_mods+=("$mod")
    done
    if [[ ${#bad_mods[@]} -eq 0 ]]; then
        _row "Blacklist"  "OK  mei/mei_me/pcspkr not loaded"
    else
        _row "Blacklist"  "!   loaded but should be blacklisted: $(_join "${bad_mods[@]}")"
        _rec "Modules $(_join "${bad_mods[@]}") should be blacklisted — check /etc/modprobe.d/"
    fi

}

_section_encryption() {
    _head "Encryption"

    if [[ ! -e "/dev/mapper/${ROOTLABEL}" ]]; then
        _row "LUKS"      "--  not encrypted"
        _rec "Disk not encrypted — re-install with LUKS2 for data protection"
        return
    fi

    local underlying
    underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
        | sed -n 's/^ *device: //p' || true)
    _row "LUKS"      "OK  active (${underlying:-/dev/mapper/${ROOTLABEL}})"
    [[ -z "$underlying" ]] && return

    local dump; dump=$(cryptsetup luksDump "$underlying" 2>/dev/null || true)
    local kdf;   kdf=$(echo "$dump" | awk '/PBKDF:/{print $2;exit}')
    if [[ "$kdf" == "argon2id" ]]; then
        _row "KDF"   "OK  argon2id"
    else
        _row "KDF"   "!   ${kdf:-unknown}  (argon2id recommended)"
        _rec "LUKS KDF is ${kdf:-unknown} — consider re-encrypting with argon2id"
    fi

    # ── LUKS slot count ───────────────────────────────────────────────────────
    local slot_count; slot_count=$(echo "$dump" | grep -c 'Key Slot [0-9]*: ENABLED' 2>/dev/null || echo "")
    if [[ "$slot_count" =~ ^[0-9]+$ ]] && (( slot_count >= 1 )); then
        _row "Key slots" "OK  ${slot_count} active slot(s)"
    fi

    # ── crypttab — required for dracut to embed LUKS unlock in initrd ─────────
    if [[ -f /etc/crypttab ]]; then
        local ct_entry; ct_entry=$(grep "^${ROOTLABEL}\b" /etc/crypttab 2>/dev/null | head -1 || echo "")
        if [[ -n "$ct_entry" ]]; then
            _row "crypttab"  "OK  entry for ${ROOTLABEL} present"
        else
            _row "crypttab"  "!!  /etc/crypttab exists but has no entry for ${ROOTLABEL}"
            _rec "crypttab missing entry for ${ROOTLABEL} — run: gen-efi configure <booted_slot>  [auto]"
        fi
    else
        _row "crypttab"  "!!  /etc/crypttab missing — initrd will not unlock LUKS"
        _rec "/etc/crypttab missing — run: gen-efi configure <booted_slot> to regenerate  [auto]"
    fi

    # ── dracut crypt config ───────────────────────────────────────────────────
    local crypt_conf="/etc/dracut.conf.d/99-crypt-key.conf"
    if [[ -f "$crypt_conf" ]]; then
        _row "Dracut crypt" "OK  99-crypt-key.conf present"
    else
        _row "Dracut crypt" "!!  /etc/dracut.conf.d/99-crypt-key.conf missing — initrd may not include crypttab"
        _rec "dracut crypt config missing — run: gen-efi configure <booted_slot>  [auto]"
    fi

}

_section_tpm2() {
    _head "TPM2"

    # TPM2 section needs the cryptenroll output — re-derive underlying device here
    local underlying=""
    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
            | sed -n 's/^ *device: //p' || true)
    fi
    local enroll_out=""
    [[ -n "$underlying" ]] && enroll_out=$(systemd-cryptenroll "$underlying" 2>/dev/null || true)

    if [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
        local tpm_info
        tpm_info=$(systemd-cryptenroll --tpm2-device=list 2>/dev/null \
            | grep -v '^PATH' | tail -1 || true)
        _row "Hardware"  "OK  present${tpm_info:+  (${tpm_info})}"
        if [[ -n "$underlying" ]]; then
            if echo "$enroll_out" | grep -q "tpm2"; then
                # Show PCR policy — parse from cryptsetup luksDump
                # gen-efi uses PCR 0+7 with Secure Boot, PCR 0 without
                local pcr_policy=""
                pcr_policy=$(cryptsetup luksDump "$underlying" 2>/dev/null \
                    | grep -A5 "systemd-tpm2" | grep -oP 'pcr-selection.*' \
                    | head -1 || echo "")
                [[ -z "$pcr_policy" ]] && \
                    pcr_policy=$(systemd-cryptenroll "$underlying" 2>/dev/null \
                        | awk '/tpm2/{print $0}' | head -1 || echo "")
                _row "Enrolled"  "OK  auto-unlock active${pcr_policy:+  (${pcr_policy})}"
                # Check PCR policy matches current Secure Boot state (gen-efi logic:
                # SB on → PCR 0+7, SB off → PCR 0 only)
                local _tpm_sb_state
                _tpm_sb_state=$(mokutil --sb-state 2>/dev/null || echo "")
                local _sb_on=0
                [[ "$_tpm_sb_state" == *"SecureBoot enabled"* ]] && _sb_on=1
                local _expected_pcrs; (( _sb_on )) && _expected_pcrs="0+7" || _expected_pcrs="0"
                # Detect enrolled PCR set from luksDump token section
                local _enrolled_pcrs=""
                _enrolled_pcrs=$(cryptsetup luksDump "$underlying" 2>/dev/null \
                    | grep -oP '(?<=tpm2-pcrs=)[0-9+]+' | head -1 || echo "")
                if [[ -n "$_enrolled_pcrs" && "$_enrolled_pcrs" != "$_expected_pcrs" ]]; then
                    local _sb_str; (( _sb_on )) && _sb_str="on" || _sb_str="off"
                    _row2 "!   PCR policy ${_enrolled_pcrs} but SB is ${_sb_str} — expected ${_expected_pcrs}"
                    _rec "TPM2 PCR policy mismatch (enrolled: ${_enrolled_pcrs}, expected: ${_expected_pcrs}) — re-enroll: gen-efi enroll-tpm2"
                fi
            else
                _row "Enrolled"  "!!  not enrolled"
                _rec "TPM2 not enrolled for auto-unlock — run: gen-efi enroll-tpm2"
            fi
        else
            _row "Enrolled"  "--  disk not encrypted (TPM2 enroll not applicable)"
        fi
    else
        _row "Hardware"  "--  not found or disabled in BIOS"
    fi
}

_section_security_services() {
    _head "Security Services"

    if command -v aa-status &>/dev/null; then
        if aa-status --enabled >/dev/null 2>&1; then
            local n; n=$(aa-status 2>/dev/null | awk '/enforce mode/{print $1}' | tr -d '[:space:]' || echo "?")
            _row "AppArmor"   "OK  ${n} profiles enforcing"
        else
            _row "AppArmor"   "!!  not enforcing"
            _rec "AppArmor not enforcing — run: systemctl enable --now apparmor  [auto]"
        fi
    else
        _row "AppArmor"   "--  aa-status not found"
    fi

    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            local zone; zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
            _row "Firewall"   "OK  active (zone: ${zone})"
        else
            _row "Firewall"   "!!  firewalld not running"
            _rec "Firewall not active — run: systemctl enable --now firewalld  [auto]"
        fi
    else
        _row "Firewall"   "--  not installed"
    fi

    if command -v fail2ban-client &>/dev/null; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            local jails
            jails=$(fail2ban-client status 2>/dev/null \
                | awk -F',' '/Jail list/{gsub(/[[:space:]]/,"",$0);print NF}' || echo "?")
            _row "fail2ban"   "OK  ${jails} jail(s) active"
        else
            _row "fail2ban"   "!!  not running"
            _rec "fail2ban not active — run: systemctl enable --now fail2ban  [auto]"
        fi
    else
        _row "fail2ban"   "--  not installed"
    fi

    # AppArmor denial count this boot — non-zero means a process is being blocked
    local aa_denials
    aa_denials=$(journalctl -k -b 0 --no-pager -q 2>/dev/null \
        | grep -c 'apparmor.*DENIED' || echo "0")
    if [[ "$aa_denials" =~ ^[0-9]+$ ]] && (( aa_denials > 0 )); then
        _row "AA denials" "!   ${aa_denials} DENIED event(s) this boot"
        # Show top offending profiles inline (saves running a separate command)
        local _aa_journal
        _aa_journal=$(journalctl -k -b 0 --no-pager -q 2>/dev/null | grep 'apparmor.*DENIED' || true)
        if [[ -n "$_aa_journal" ]]; then
            local _aa_top
            _aa_top=$(echo "$_aa_journal" \
                | grep -oP '(?<=profile=")[^"]+' \
                | sort | uniq -c | sort -rn | head -3 \
                | awk '{printf "%s (%d denial(s))\n", $2, $1}' || true)
            while IFS= read -r line; do
                [[ -n "$line" ]] && _row2 "--  $line"
            done <<< "$_aa_top"
        fi
        _rec "${aa_denials} AppArmor denial(s) this boot — check: journalctl -k -b 0 | grep 'apparmor.*DENIED'"
    fi

    # ── Polkit ───────────────────────────────────────────────────────────────
    # polkitd is required for pkexec-based privilege escalation (used by this
    # script itself) and for GUI admin actions in GNOME/Plasma.
    if systemctl is-active --quiet polkit 2>/dev/null; then
        _row "polkit"     "OK  running"
    elif systemctl is-enabled --quiet polkit 2>/dev/null; then
        _row "polkit"     "!!  enabled but not running — pkexec and GUI elevation broken"
        _rec "polkitd not running — run: systemctl start polkit  [auto]"
    else
        _row "polkit"     "!!  not enabled — pkexec and GUI elevation will fail"
        _rec "polkit not enabled — run: systemctl enable --now polkit  [auto]"
    fi

    # ── Audit daemon ──────────────────────────────────────────────────────────
    # auditd logs kernel security events (syscall auditing, file access, etc.)
    # Wiki confirms 'audit' is installed as part of the security stack
    if command -v auditctl &>/dev/null; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            local audit_rules; audit_rules=$(auditctl -l 2>/dev/null | grep -vc '^No rules' || echo "?")
            _row "auditd"    "OK  running${audit_rules:+ (${audit_rules} rule(s))}"
        else
            local audit_en; audit_en=$(systemctl is-enabled auditd 2>/dev/null || echo "disabled")
            if [[ "$audit_en" == "enabled" ]]; then
                _row "auditd"    "!   enabled but not running"
                _rec "auditd enabled but not active — run: systemctl start auditd  [auto]"
            else
                _row "auditd"    "--  installed but not enabled (kernel security event logging inactive)"
            fi
        fi
    fi

    # ── Lynis ─────────────────────────────────────────────────────────────────
    # Security auditing tool — show last scan date and hardening index if available
    if command -v lynis &>/dev/null; then
        local lynis_log="/var/log/lynis.log"
        local lynis_report="/var/log/lynis-report.dat"
        local lynis_last="" lynis_score=""

        # Check timer status first
        local lynis_timer_active=0
        local lynis_next=""
        if systemctl is-active --quiet lynis.timer 2>/dev/null; then
            lynis_timer_active=1
            local lynis_next_raw
            lynis_next_raw=$(systemctl show lynis.timer \
                --property=NextElapseUSecRealtime --value 2>/dev/null || echo "")
            [[ -z "$lynis_next_raw" || "$lynis_next_raw" == "0" ]] && \
                lynis_next_raw=$(systemctl show lynis.timer \
                    --property=NextElapseUSecMonotonic --value 2>/dev/null || echo "")
            if [[ "$lynis_next_raw" =~ ^[0-9]+$ ]] && (( lynis_next_raw > 0 )); then
                lynis_next=$(date -d "@$(( lynis_next_raw / 1000000 ))" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "")
            fi
        fi

        # Last scan date from report
        if [[ -f "$lynis_report" ]]; then
            lynis_last=$(grep '^report_datetime_start=' "$lynis_report" 2>/dev/null \
                | cut -d= -f2 | head -1 || echo "")
            lynis_score=$(grep '^hardening_index=' "$lynis_report" 2>/dev/null \
                | cut -d= -f2 | head -1 || echo "")
        elif [[ -f "$lynis_log" ]]; then
            lynis_last=$(grep 'Starting Lynis' "$lynis_log" 2>/dev/null \
                | tail -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1 || echo "")
        fi

        local lynis_score_str=""
        [[ -n "$lynis_score" ]] && lynis_score_str="  (hardening index: ${lynis_score})"
        local lynis_next_str=""
        [[ -n "$lynis_next" ]] && lynis_next_str="  (next: ${lynis_next})"

        if [[ -n "$lynis_last" ]]; then
            local lynis_age_days
            lynis_age_days=$(( ( $(date +%s) - $(date -d "$lynis_last" +%s 2>/dev/null || echo 0) ) / 86400 ))
            if (( lynis_timer_active )); then
                # Timer running — age warning threshold is higher since it runs automatically
                if (( lynis_age_days > 30 )); then
                    _row "lynis"     "!   timer active, last scan ${lynis_age_days}d ago${lynis_score_str}${lynis_next_str}"
                    _rec "Lynis timer active but last scan was ${lynis_age_days} days ago — check timer"
                else
                    _row "lynis"     "OK  timer active, last scan ${lynis_age_days}d ago${lynis_score_str}${lynis_next_str}"
                fi
            else
                if (( lynis_age_days > 30 )); then
                    _row "lynis"     "!   last scan ${lynis_age_days}d ago${lynis_score_str} — run: lynis audit system"
                    _rec "Lynis last ran ${lynis_age_days} days ago — enable timer: systemctl enable --now lynis.timer  [auto]"
                else
                    _row "lynis"     "OK  last scan ${lynis_age_days}d ago${lynis_score_str}"
                    _row2 "--  timer not active — run: systemctl enable --now lynis.timer  [auto]"
                fi
            fi
        else
            if (( lynis_timer_active )); then
                _row "lynis"     "--  timer active, no scan recorded yet${lynis_next_str}"
            else
                _row "lynis"     "--  installed, no scan recorded — run: lynis audit system"
                _rec "Enable lynis timer: systemctl enable --now lynis.timer  [auto]"
            fi
        fi
    fi

    # ── rkhunter ──────────────────────────────────────────────────────────────
    # Rootkit hunter — show last scan date and any warnings
    if command -v rkhunter &>/dev/null; then
        local rkh_log="/var/log/rkhunter.log"
        local rkh_last="" rkh_warnings=0
        if [[ -f "$rkh_log" ]]; then
            rkh_last=$(grep 'Start date' "$rkh_log" 2>/dev/null \
                | tail -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1 || echo "")
            rkh_warnings=$(grep -c 'Warning:' "$rkh_log" 2>/dev/null || echo "0")
        fi
        if [[ -n "$rkh_last" ]]; then
            local rkh_age_days
            rkh_age_days=$(( ( $(date +%s) - $(date -d "$rkh_last" +%s 2>/dev/null || echo 0) ) / 86400 ))
            if (( rkh_warnings > 0 )); then
                _row "rkhunter"  "!!  ${rkh_warnings} warning(s) in last scan (${rkh_last}) — check: cat ${rkh_log}"
                _rec "rkhunter reported ${rkh_warnings} warning(s) — review: grep Warning ${rkh_log}"
            elif (( rkh_age_days > 7 )); then
                _row "rkhunter"  "!   last scan ${rkh_age_days}d ago — run: rkhunter --check"
                _rec "rkhunter last ran ${rkh_age_days} days ago — run: rkhunter --check"
            else
                _row "rkhunter"  "OK  last scan ${rkh_age_days}d ago, no warnings"
            fi
        else
            _row "rkhunter"  "--  installed, no scan recorded — run: rkhunter --check"
        fi
    fi
}
_section_groups() {
    _head "Groups"

    # ── Source of truth: /etc/shani-extra-groups ──────────────────────────────
    # build-base-image.sh creates these groups and writes the list to
    # /etc/shani-extra-groups. shani-user-setup reads the same file to add
    # users. We check:
    #   1. Each group exists (getent works on overlayfs merged /etc/group)
    #   2. Static-GID groups have the expected GID (udev rules depend on exact GIDs)
    #   3. Every login user is a member of every group that exists
    #
    # Static GIDs from Arch archwiki / systemd basic.conf (same as build-base-image.sh):
    local -A STATIC_GIDS=([sys]=3 [lp]=7 [kvm]=78 [video]=91 [scanner]=96 [input]=97 [cups]=209)
    # Dynamic groups (no fixed GID — just need to exist):
    local DYNAMIC_GROUPS=(realtime nixbld lxd libvirt)
    # Also check storage/network — not in shani-extra-groups but critical for desktop use:
    local EXTRA_SYSTEM=(storage network audio)

    # Build login user list once
    local login_users=()
    _get_login_users login_users

    local groups_missing=() groups_ok=0
    local membership_missing=()  # "user:group" pairs

    # ── Check shani-extra-groups static-GID groups ────────────────────────────
    for grp in "${!STATIC_GIDS[@]}"; do
        local actual_gid; actual_gid=$(getent group "$grp" 2>/dev/null | cut -d: -f3 || echo "")
        if [[ -z "$actual_gid" ]]; then
            groups_missing+=("$grp")
        else
            groups_ok=$(( groups_ok + 1 ))
        fi
    done

    # ── Check dynamic groups ──────────────────────────────────────────────────
    for grp in "${DYNAMIC_GROUPS[@]}"; do
        if ! getent group "$grp" &>/dev/null; then
            groups_missing+=("$grp")
        else
            groups_ok=$(( groups_ok + 1 ))
        fi
    done

    # ── Check extra system groups ─────────────────────────────────────────────
    local sys_missing=()
    for grp in "${EXTRA_SYSTEM[@]}"; do
        getent group "$grp" &>/dev/null || sys_missing+=("$grp")
    done

    # ── Report group existence ────────────────────────────────────────────────
    if [[ ${#groups_missing[@]} -eq 0 ]]; then
        local total=$(( ${#STATIC_GIDS[@]} + ${#DYNAMIC_GROUPS[@]} ))
        _row "System grps" "OK  all ${total} shani groups present"
    else
        # Build a filtered list — omit optional groups when the feature isn't installed
        local _reportable_missing=()
        for grp in "${groups_missing[@]}"; do
            case "$grp" in
                libvirt) command -v virsh &>/dev/null || [[ -d /data/varlib/libvirt ]] && _reportable_missing+=("$grp") ;;
                lxd)     findmnt -n /var/lib/lxd &>/dev/null || [[ -d /data/varlib/lxd ]] && _reportable_missing+=("$grp") ;;
                *)       _reportable_missing+=("$grp") ;;
            esac
        done

        if [[ ${#_reportable_missing[@]} -gt 0 ]]; then
            local _miss_str; _miss_str=$(IFS=' '; echo "${_reportable_missing[*]}")
            _row "System grps" "!!  missing: ${_miss_str}"
        else
            local total=$(( ${#STATIC_GIDS[@]} + ${#DYNAMIC_GROUPS[@]} ))
            _row "System grps" "OK  all ${total} shani groups present (optional groups skipped)"
        fi

        for grp in "${groups_missing[@]}"; do
            case "$grp" in
                nixbld)   _row2 "!!  nixbld missing — 'nix build' and nix-daemon will fail"
                          _rec "Group 'nixbld' missing — Nix builds will fail: groupadd -r nixbld  [auto]" ;;
                kvm)      _row2 "!!  kvm missing — /dev/kvm inaccessible, VMs broken"
                          _rec "Group 'kvm' missing — VMs inaccessible: groupadd -r kvm  [auto]" ;;
                video)    _row2 "!!  video missing — GPU/display access broken"
                          _rec "Group 'video' missing — GPU access broken: groupadd -r video  [auto]" ;;
                input)    _row2 "!!  input missing — raw input devices inaccessible (Wayland)"
                          _rec "Group 'input' missing — Wayland input broken: groupadd -r input  [auto]" ;;
                realtime) _row2 "!   realtime missing — PipeWire RT scheduling unavailable"
                          _rec "Group 'realtime' missing — audio RT unavailable: groupadd -r realtime  [auto]" ;;
                libvirt)
                    if command -v virsh &>/dev/null || [[ -d /data/varlib/libvirt ]]; then
                        _row2 "!   libvirt missing — libvirt socket inaccessible"
                        _rec "Group 'libvirt' missing: groupadd -r libvirt  [auto]"
                    fi ;;
                lxd)
                    if findmnt -n /var/lib/lxd &>/dev/null || [[ -d /data/varlib/lxd ]]; then
                        _row2 "!   lxd missing — LXD socket inaccessible"
                        _rec "Group 'lxd' missing: groupadd -r lxd  [auto]"
                    fi ;;
                cups)     _row2 "!   cups missing — printing broken"
                          _rec "Group 'cups' missing: groupadd -r cups  [auto]" ;;
                *)        _rec "Group '${grp}' missing: groupadd -r ${grp}  [auto]" ;;
            esac
        done
    fi

    if [[ ${#sys_missing[@]} -gt 0 ]]; then
        local _sm_str; _sm_str=$(IFS=' '; echo "${sys_missing[*]}")
        _row "Util grps"  "!   missing: ${_sm_str} — udisks2/NM may not work"
        _rec "System groups missing (${_sm_str}) — automounting/networking may break"
    fi

    # ── User membership check ─────────────────────────────────────────────────
    # Read the actual wanted groups from /etc/shani-extra-groups (single source of truth)
    local wanted_groups=()
    if [[ -f /etc/shani-extra-groups ]]; then
        local _eg; _eg=$(head -n1 /etc/shani-extra-groups 2>/dev/null | tr -d '[:space:]')
        IFS=',' read -ra wanted_groups <<< "$_eg"
    fi

    if [[ ${#wanted_groups[@]} -gt 0 && ${#login_users[@]} -gt 0 ]]; then
        local mem_ok=0 mem_bad=()
        for u in "${login_users[@]}"; do
            local user_groups; user_groups=$(id -nG "$u" 2>/dev/null || true)
            local u_missing=()
            for grp in "${wanted_groups[@]}"; do
                # Only check groups that actually exist — skip missing ones (already reported above)
                getent group "$grp" &>/dev/null || continue
                echo "$user_groups" | grep -qw "$grp" || u_missing+=("$grp")
            done
            if [[ ${#u_missing[@]} -gt 0 ]]; then
                local _um_str; _um_str=$(IFS=,; echo "${u_missing[*]}")
                mem_bad+=("${u}:${_um_str}")
            else
                mem_ok=$(( mem_ok + 1 ))
            fi
        done

        if [[ ${#mem_bad[@]} -eq 0 ]]; then
            _row "Membership" "OK  all users in required groups"
        else
            for entry in "${mem_bad[@]}"; do
                local _u="${entry%%:*}" _missing_g="${entry#*:}"
                _row "Membership" "!   ${_u} missing: ${_missing_g}"
                _rec "User ${_u} not in groups (${_missing_g}) — run: shani-user-setup  [auto]"
            done
        fi
    fi
}

_section_users() {
    _head "Users & Access Control"

    # ── Login users ───────────────────────────────────────────────────────────
    local login_users=()
    _get_login_users login_users
    local _login_str; _login_str=$(IFS=' '; echo "${login_users[*]:-none detected}")
    _row "Login"     "--  ${_login_str}"

    # ── Login user password status ────────────────────────────────────────────
    local no_pass=()
    if [[ ${#login_users[@]} -gt 0 ]]; then
        for u in "${login_users[@]}"; do
            local pw_st; pw_st=$(passwd -S "$u" 2>/dev/null | awk '{print $2}' || echo "")
            [[ "$pw_st" == "NP" ]] && no_pass+=("$u")
        done
    fi
    if [[ ${#no_pass[@]} -gt 0 ]]; then
        _row "Passwords"  "!!  no password set for: $(_join "${no_pass[@]}")"
        _rec "User(s) $(_join "${no_pass[@]}") have no password — set one: passwd <username>"
    fi

    local wheel_line wheel_members=()
    wheel_line=$(getent group wheel 2>/dev/null || grep '^wheel:' /etc/group 2>/dev/null || true)
    local wheel_sudoers
    wheel_sudoers=$(grep -h '^%wheel' /etc/sudoers.d/wheel 2>/dev/null \
        | grep -v '^[[:space:]]*#' | head -1 || true)
    if [[ -z "$wheel_line" ]]; then
        _row "Wheel"     "!!  group does not exist — sudo access broken"
        _rec "wheel group missing — create it: groupadd wheel, then add users: usermod -aG wheel <username>"
    else
        IFS=',' read -ra wheel_members <<< "${wheel_line##*:}"
        if [[ -z "$wheel_sudoers" ]]; then
            _row "Wheel"     "!!  group exists but no sudoers rule found for %wheel"
            _rec "No sudoers rule for wheel — add: %wheel ALL=(ALL:ALL) ALL to /etc/sudoers.d/wheel"
        elif [[ ${#wheel_members[@]} -gt 0 && -n "${wheel_members[0]}" ]]; then
            # Check at least one wheel member is a real login user (uid >= 1000)
            local wheel_has_login=0
            for m in "${wheel_members[@]}"; do
                local m_uid; m_uid=$(id -u "$m" 2>/dev/null || echo "")
                [[ "$m_uid" =~ ^[0-9]+$ ]] && (( m_uid >= 1000 )) && { wheel_has_login=1; break; }
            done
            if (( wheel_has_login )); then
                local _wheel_str; _wheel_str=$(IFS=' '; echo "${wheel_members[*]}")
                _row "Wheel"     "OK  ${_wheel_str}"
            else
                _row "Wheel"     "!!  no regular user (uid≥1000) in wheel — sudo access effectively broken"
                _rec "wheel group has no regular login users — add one: usermod -aG wheel <username>"
            fi
        else
            _row "Wheel"     "!!  sudoers rule present but group has no members — no user can sudo"
            _rec "wheel group is empty — add a user: usermod -aG wheel <username>"
        fi
    fi

    # ── Duplicate UID 0 accounts ──────────────────────────────────────────────
    local uid0_accounts=()
    while IFS=: read -r name _ uid _; do
        [[ "$uid" -eq 0 && "$name" != "root" ]] && uid0_accounts+=("$name")
    done < /etc/passwd 2>/dev/null || true
    if [[ ${#uid0_accounts[@]} -gt 0 ]]; then
        local _uid0_str; _uid0_str=$(_join "${uid0_accounts[@]}")
        _row "UID 0"      "!!  non-root accounts with UID 0: ${_uid0_str}"
        _rec "Accounts with UID 0 besides root (${_uid0_str}) — remove or reassign UID"
    fi

    local nopasswd=()
    while IFS= read -r line; do
        echo "$line" | grep -qE 'NOPASSWD.*ALL\s*$|NOPASSWD.*ALL\)' && nopasswd+=("$line")
    done < <(grep -rh NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | grep -v '^[[:space:]]*#' || true)
    if [[ ${#nopasswd[@]} -gt 0 ]]; then
        _row "NOPASSWD"  "!   passwordless sudo entries found:"
        for e in "${nopasswd[@]}"; do _row2 "$(echo "$e" | xargs)"; done
        _rec "Passwordless sudo (NOPASSWD ALL) found — review /etc/sudoers.d/"
    else
        _row "NOPASSWD"  "OK  no unrestricted passwordless sudo"
    fi

    # ── Root account ──────────────────────────────────────────────────────────
    local root_st; root_st=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")
    case "$root_st" in
        L|LK) _row "Root acct"  "OK  locked" ;;
        P)    _row "Root acct"  "!   has a password (locked root recommended)"
              _rec "Root has a password — to lock: passwd -l root  [auto]" ;;
        *)    _row "Root acct"  "--  status unknown" ;;
    esac

    # ── SSH ───────────────────────────────────────────────────────────────────
    if [[ -f /etc/ssh/sshd_config ]] || [[ -d /etc/ssh/sshd_config.d ]]; then
        local ssh_root
        ssh_root=$(grep -rh '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ \
            2>/dev/null | tail -1 | awk '{print $2}' || echo "")
        if [[ -z "$ssh_root" ]]; then
            local ssh_ver; ssh_ver=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+' | head -1 || echo "0")
            if (( ssh_ver < 8 )); then
                _row "SSH root"   "!   default may allow login (OpenSSH <8)"
                _rec "Set PermitRootLogin no in sshd_config (OpenSSH <8 default risky)"
            fi
        else
            case "$ssh_root" in
                no|prohibit-password|without-password) ;;  # OK — no row needed
                yes)  _row "SSH root"  "!!  enabled (password login allowed)"
                      _rec "SSH root password login enabled — disable in sshd_config  [auto]" ;;
                *)    _row "SSH root"  "!   unknown value: ${ssh_root}" ;;
            esac
        fi
    fi

    # ── Rootless container namespaces (subuid/subgid) ─────────────────────────
    # /etc/subuid and /etc/subgid must have entries for every login user so
    # Podman and Distrobox can create rootless containers. This is a per-user
    # access control setting, not a service config.
    if command -v podman &>/dev/null || command -v distrobox &>/dev/null; then
        local sub_missing=()
        local _sub_login_users=()
        _get_login_users _sub_login_users
        for u in "${_sub_login_users[@]}"; do
            if ! grep -q "^${u}:" /etc/subuid 2>/dev/null || \
               ! grep -q "^${u}:" /etc/subgid 2>/dev/null; then
                sub_missing+=("$u")
            fi
        done
        if [[ ${#sub_missing[@]} -gt 0 ]]; then
            _row "subuid"   "!!  missing for: $(_join "${sub_missing[@]}") — rootless Podman/Distrobox will fail"
            _rec "subuid/subgid missing for $(_join "${sub_missing[@]}") — run: usermod --add-subuids 100000-165535 --add-subgids 100000-165535 <user>"
        else
            _row "subuid"   "OK  configured for all users"
        fi
    fi
}


###############################################################################
### system_info — master status report                                       ###
###############################################################################


_section_hardware() {
    _head "Hardware"

    # ── CPU ───────────────────────────────────────────────────────────────────
    local cpu_model cpu_cores cpu_arch cpu_flags
    cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null \
        | cut -d: -f2 | sed 's/^ *//' | sed 's/  */ /g' || echo "unknown")
    cpu_cores=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "?")
    cpu_arch=$(uname -m 2>/dev/null || echo "?")
    cpu_flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null \
        | cut -d: -f2 | tr -s ' ' | tr -d '\n' | sed 's/^ //' || echo "")

    _row "CPU"        "--  ${cpu_model} (${cpu_cores} threads, ${cpu_arch})"

    # ── CPU feature flags ─────────────────────────────────────────────────────
    # Report presence of key capability flags relevant to security and virt.
    local flags_ok=() flags_missing=()
    local -A flag_labels=(
        ["aes"]="AES-NI (hardware encryption)"
        ["avx"]="AVX (vector extensions)"
        ["avx2"]="AVX2"
    )
    for flag in aes avx avx2; do
        if echo "$cpu_flags" | grep -qw "$flag"; then
            flags_ok+=("$flag")
        else
            flags_missing+=("${flag_labels[$flag]:-$flag}")
        fi
    done
    if [[ ${#flags_ok[@]} -gt 0 ]]; then
        local flags_ok_str; flags_ok_str=$(IFS=' '; echo "${flags_ok[*]}")
        local flags_miss_str=""
        [[ ${#flags_missing[@]} -gt 0 ]] && flags_miss_str="  (missing: $(IFS=', '; echo "${flags_missing[*]}"))"
        _row "CPU flags"  "--  ${flags_ok_str}${flags_miss_str}"
    fi

    # ── CPU temperature ───────────────────────────────────────────────────────
    local cpu_temp=""
    # Try /sys/class/thermal first (most reliable, no extra tools)
    for zone in /sys/class/thermal/thermal_zone*/; do
        local type; type=$(cat "${zone}type" 2>/dev/null || echo "")
        if [[ "$type" == "x86_pkg_temp" || "$type" == "cpu_thermal" || "$type" == "cpu-thermal" ]]; then
            local raw; raw=$(cat "${zone}temp" 2>/dev/null || echo "")
            if [[ "$raw" =~ ^[0-9]+$ ]]; then
                cpu_temp=$(( raw / 1000 ))
                break
            fi
        fi
    done
    # Fallback: first thermal zone
    if [[ -z "$cpu_temp" ]]; then
        local raw; raw=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo "")
        [[ "$raw" =~ ^[0-9]+$ ]] && cpu_temp=$(( raw / 1000 ))
    fi
    if [[ -n "$cpu_temp" ]]; then
        if (( cpu_temp >= 90 )); then
            _row "CPU temp"   "!!  ${cpu_temp}°C — critically hot"
            _rec "CPU temperature is ${cpu_temp}°C — check cooling"
        elif (( cpu_temp >= 75 )); then
            _row "CPU temp"   "!   ${cpu_temp}°C (hot)"
        else
            _row "CPU temp"   "OK  ${cpu_temp}°C"
        fi
    fi

    # ── RAM ───────────────────────────────────────────────────────────────────
    local mem_total_kb mem_total_gb
    mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
    if [[ "$mem_total_kb" =~ ^[0-9]+$ ]] && (( mem_total_kb > 0 )); then
        mem_total_gb=$(awk "BEGIN{printf \"%.1f\", $mem_total_kb/1048576}")
        _row "RAM"       "--  ${mem_total_gb} GB"
    fi

    # ── Virtualisation ────────────────────────────────────────────────────────
    # Strategy:
    #   vmx/svm in /proc/cpuinfo flags → BIOS has it enabled → check /dev/kvm
    #   no flag, but CPU vendor is Intel/AMD → BIOS disabled it (not a HW limitation)
    #   no flag, non-Intel/non-AMD → genuinely no virt support
    local has_virt=0
    local cpu_vendor
    cpu_vendor=$(grep -m1 'vendor_id' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "")

    if echo "$cpu_flags" | grep -qE '\bvmx\b|\bsvm\b'; then
        has_virt=1
        local virt_type="VT-x"
        echo "$cpu_flags" | grep -qw 'svm' && virt_type="AMD-V"
        if [[ -e /dev/kvm ]]; then
            # Check if nested virt is enabled (useful for running VMs inside VMs)
            local nested=""
            local nested_f="/sys/module/kvm_intel/parameters/nested"
            [[ -f /sys/module/kvm_amd/parameters/nested ]] && \
                nested_f="/sys/module/kvm_amd/parameters/nested"
            [[ -f "$nested_f" ]] && nested=$(cat "$nested_f" 2>/dev/null || echo "")
            local nested_str=""
            [[ "$nested" == "1" || "$nested" == "Y" ]] && nested_str=", nested virt on"
            _row "Virt"      "OK  ${virt_type} enabled, /dev/kvm present${nested_str}"
        else
            _row "Virt"      "!   ${virt_type} flag present but /dev/kvm missing — kvm module not loaded?"
            _rec "VT-x/AMD-V flag visible but /dev/kvm absent — load kvm module or check BIOS"
        fi
    elif [[ "$cpu_vendor" == "GenuineIntel" || "$cpu_vendor" == "AuthenticAMD" ]]; then
        # Intel/AMD CPU but no vmx/svm in flags — BIOS has virtualisation disabled
        local virt_type="VT-x/AMD-V"
        [[ "$cpu_vendor" == "AuthenticAMD" ]] && virt_type="AMD-V (SVM)"
        [[ "$cpu_vendor" == "GenuineIntel" ]] && virt_type="VT-x"
        has_virt=0  # /dev/kvm won't exist either, but IOMMU section stays silent
        if [[ -e /dev/kvm ]]; then
            # Rare: /dev/kvm exists but flag hidden (e.g. some hypervisors)
            has_virt=1
            _row "Virt"      "OK  /dev/kvm present (${virt_type} flag not exposed by kernel)"
        else
            _row "Virt"      "!   ${virt_type} disabled in BIOS/UEFI — enable for VMs and containers"
            _rec "Enable ${virt_type} in BIOS/UEFI settings (look for Virtualisation, SVM Mode, or Intel VT)"
        fi
    else
        _row "Virt"      "--  no virtualisation support (non-Intel/AMD CPU)"
    fi

    # ── IOMMU (PCI passthrough) ───────────────────────────────────────────────
    # Only relevant on Intel/AMD — skip entirely on other architectures.
    # When virt is BIOS-disabled, IOMMU also won't be active, so skip silently.
    if [[ "$cpu_vendor" == "GenuineIntel" || "$cpu_vendor" == "AuthenticAMD" ]] && (( has_virt )); then
        local iommu_active=0
        # Check if IOMMU groups exist — definitive sign IOMMU is active
        if [[ -d /sys/kernel/iommu_groups ]] && \
           [[ $(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l) -gt 0 ]]; then
            iommu_active=1
        fi
        if (( iommu_active )); then
            local iommu_groups
            iommu_groups=$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l)
            _row "IOMMU"     "OK  active (${iommu_groups} groups — PCI passthrough available)"
        else
            # Check if it's in the cmdline but not working
            local iommu_cmdline
            iommu_cmdline=$(grep -oE 'iommu=on|intel_iommu=on|amd_iommu=on' /proc/cmdline 2>/dev/null || echo "")
            if [[ -n "$iommu_cmdline" ]]; then
                _row "IOMMU"     "!   enabled in cmdline but no groups visible"
                _rec "IOMMU enabled in cmdline but not active — check BIOS VT-d/AMD-Vi setting"
            else
                _row "IOMMU"     "--  not enabled (add intel_iommu=on or amd_iommu=on for PCI passthrough)"
            fi
        fi
    fi

    # ── GPU ───────────────────────────────────────────────────────────────────
    if command -v lspci &>/dev/null; then
        local gpu_lines=()
        mapfile -t gpu_lines < <(lspci 2>/dev/null \
            | grep -iE 'VGA compatible|3D controller|Display controller' \
            | sed 's/^[^ ]* //' \
            | sed 's/.*: //' \
            | sed 's/ (rev [0-9a-f]*)//' \
            | sed 's/Advanced Micro Devices, Inc\. \[AMD\/ATI\] /AMD /' \
            | sed 's/NVIDIA Corporation /NVIDIA /' \
            | sed 's/Intel Corporation /Intel /' \
            | sed 's/  */ /g' || true)
        if [[ ${#gpu_lines[@]} -gt 0 ]]; then
            for gpu in "${gpu_lines[@]}"; do
                # Identify driver via /sys/bus/pci — match on original lspci output
                local pci_addr; pci_addr=$(lspci 2>/dev/null \
                    | grep -iE 'VGA compatible|3D controller|Display controller' \
                    | grep -i "${gpu%%[*}" \
                    | awk '{print $1}' | head -1 || echo "")
                local drv=""
                if [[ -n "$pci_addr" ]]; then
                    drv=$(readlink "/sys/bus/pci/devices/0000:${pci_addr}/driver" 2>/dev/null \
                        | xargs basename 2>/dev/null || echo "")
                fi
                _row "GPU"      "--  ${gpu}${drv:+ [${drv}]}"
            done
        fi
    fi
}

_section_disk() {
    local booted="$1"
    local hibernate_stale_ref="$2"
    local uki_booted_bad="$3"

    _head "Disk"

    local root_disk
    root_disk=$(lsblk -no PKNAME \
        "$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/\[.*//')" 2>/dev/null | head -1 || true)
    [[ -z "$root_disk" ]] && \
        root_disk=$(lsblk -no PKNAME "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null | head -1 || echo "")

    if [[ -n "$root_disk" ]]; then
        local disk_model disk_size disk_type
        disk_model=$(lsblk -dno MODEL "/dev/${root_disk}" 2>/dev/null \
            | sed 's/[[:space:]]*$//' || echo "?")
        disk_size=$(lsblk -dno SIZE  "/dev/${root_disk}" 2>/dev/null || echo "?")
        disk_type=$(lsblk -dno ROTA  "/dev/${root_disk}" 2>/dev/null || echo "1")
        [[ "$disk_type" == "0" ]] && disk_type="SSD/NVMe" || disk_type="HDD"
        _row "Device"    "--  /dev/${root_disk}  ${disk_model}  (${disk_size}, ${disk_type})"

        if command -v smartctl &>/dev/null; then
            local smart
            smart=$(smartctl -H "/dev/${root_disk}" 2>/dev/null \
                | awk '/overall-health|result/{print $NF}' | head -1 || echo "")
            if [[ "$smart" == "PASSED" ]]; then
                _row "SMART"     "OK  PASSED"
            elif [[ -n "$smart" ]]; then
                _row "SMART"     "!!  ${smart}"
                _rec "SMART health ${smart} for /dev/${root_disk} — back up data immediately"
            else
                _row "SMART"     "--  not available (NVMe may need nvme-cli)"
            fi

            # Wear level and temperature — parse JSON output for both NVMe and SATA
            local smart_json
            smart_json=$(smartctl -j -A "/dev/${root_disk}" 2>/dev/null || true)
            if [[ -n "$smart_json" ]]; then
                # NVMe: percentage_used field; SATA: wear_leveling_count (ID 177)
                local nvme_wear nvme_temp sata_wear sata_temp wear temp
                nvme_wear=$(echo "$smart_json" | grep -o '"percentage_used"[^,}]*' \
                    | grep -o '[0-9]*' | head -1 || echo "")
                nvme_temp=$(echo "$smart_json" | grep -o '"temperature"[^,}]*' \
                    | grep -o '[0-9]\{2,3\}' | head -1 || echo "")
                sata_wear=$(echo "$smart_json" | grep -A5 '"id" *: *177' \
                    | grep '"value"' | grep -o '[0-9]*' | head -1 || echo "")
                sata_temp=$(echo "$smart_json" | grep -A5 '"id" *: *19[04]' \
                    | grep '"value"' | grep -o '[0-9]*' | head -1 || echo "")
                wear="${nvme_wear:-$sata_wear}"
                temp="${nvme_temp:-$sata_temp}"

                if [[ -n "$wear" ]]; then
                    if (( wear >= 90 )); then
                        _row "SSD wear"  "!!  ${wear}% used — replace soon"
                        _rec "SSD wear at ${wear}% — plan replacement before failure"
                    elif (( wear >= 70 )); then
                        _row "SSD wear"  "!   ${wear}% used"
                    else
                        _row "SSD wear"  "OK  ${wear}% used"
                    fi
                fi
                if [[ -n "$temp" ]]; then
                    if (( temp >= 65 )); then
                        _row "Disk temp"  "!!  ${temp}°C — critically hot"
                        _rec "Disk temperature is ${temp}°C — check cooling"
                    elif (( temp > 55 )); then
                        _row "Disk temp"  "!   ${temp}°C (warm — SSDs throttle at 70°C)"
                    else
                        _row "Disk temp"  "OK  ${temp}°C"
                    fi
                fi
            fi
        else
            _row "SMART"     "--  smartctl not installed"
        fi
    else
        _row "Device"    "--  could not detect root disk"
    fi

    # Swap & hibernate
    # First verify /swap is mounted — the swapfile lives there
    if [[ -f /proc/cmdline ]] && grep -q 'resume=' /proc/cmdline 2>/dev/null; then
        # Hibernate was configured — check the mount point exists
        if ! findmnt -n /swap &>/dev/null; then
            _row "Swap"      "!!  /swap not mounted — swapfile inaccessible, hibernate broken"
            _rec "@swap subvolume not mounted at /swap — check fstab"
        fi
    fi

    local swap_total swap_used
    swap_total=$(free -h 2>/dev/null | awk '/^Swap:/{print $2}' || echo "0")
    swap_used=$(  free -h 2>/dev/null | awk '/^Swap:/{print $3}' || echo "0")

    if [[ "$swap_total" == "0" || "$swap_total" == "0B" ]]; then
        _row "Swap"      "!   none active (hibernate unavailable)"
    else
        _row "Swap"      "OK  ${swap_used} / ${swap_total}"
        local has_zram=0 swapfile=""
        swapon --show=NAME --noheadings 2>/dev/null | grep -q zram && has_zram=1
        swapfile=$(_find_swapfile)
        local has_swapfile=0; [[ -n "$swapfile" ]] && has_swapfile=1

        if (( has_zram && has_swapfile )); then
            _row2 "zram + swapfile (hibernate capable)"
        elif (( has_zram )); then
            _row2 "zram only — hibernate not available"
        elif (( has_swapfile )); then
            _row2 "swapfile: $swapfile"
        fi

        if (( has_swapfile )); then
            local cmdline; cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
            local resume_ok=0 offset_ok=0
            echo "$cmdline" | grep -q 'resume='        && resume_ok=1
            echo "$cmdline" | grep -q 'resume_offset=' && offset_ok=1

            if (( resume_ok && offset_ok )); then
                local configured; configured=$(echo "$cmdline" \
                    | grep -o 'resume_offset=[^ ]*' | cut -d= -f2)
                local actual; actual=$(_swapfile_offset "$swapfile")
                if [[ -n "$actual" && "$actual" == "$configured" ]]; then
                    _row "Hibernate"  "OK  resume_offset=${configured} correct"
                elif [[ -n "$actual" && "$actual" != "$configured" ]]; then
                    printf -v "$hibernate_stale_ref" '%s' "1"
                    _row "Hibernate"  "!!  resume_offset stale"
                    _row2             "--  cmdline=${configured}, actual=${actual}"
                    _row2             "--  regenerate UKI before hibernating"
                    if (( ! uki_booted_bad )); then
                        _rec "Hibernate offset stale — run: gen-efi configure ${booted}  [auto]"
                    fi
                else
                    _row "Hibernate"  "OK  resume_offset present (offset unverifiable)"
                fi
            elif (( ! resume_ok )); then
                _row "Hibernate"  "!!  swapfile present but resume= missing from cmdline"
                _rec "Swapfile present but resume= missing — run: gen-efi configure ${booted}  [auto]"
            fi
        fi
    fi
}

###############################################################################
### Shared Btrfs storage helpers (used by _section_storage + analyze_storage)
###############################################################################

# Print free-space row. Pass mount point (/ for live system, STOR_MNT for subvolid=5).
# Reads btrfs filesystem usage -b for byte-accurate free space.
_stor_check_free() {
    local mnt="${1:-/}"
    local btrfs_free_bytes
    btrfs_free_bytes=$(btrfs filesystem usage -b "$mnt" 2>/dev/null \
        | awk '/Free \(estimated\):/{print $3}' || echo "0")
    if [[ "$btrfs_free_bytes" =~ ^[0-9]+$ ]] && (( btrfs_free_bytes > 0 )); then
        local btrfs_free_gb; btrfs_free_gb=$(awk "BEGIN{printf \"%.1f\", $btrfs_free_bytes/1073741824}")
        local free_gb_int;   free_gb_int=$(awk "BEGIN{printf \"%d\",   $btrfs_free_bytes/1073741824}")
        if (( free_gb_int < 5 )); then
            _row "Free"  "!!  ${btrfs_free_gb} GB — critically low (Btrfs may ENOSPC soon)"
            _rec "Btrfs free space is critically low (${btrfs_free_gb} GB) — run: shani-health --storage-info"
        elif (( free_gb_int < 15 )); then
            _row "Free"  "!   ${btrfs_free_gb} GB — getting low"
        else
            _row "Free"  "--  ${btrfs_free_gb} GB"
        fi
    else
        _row "Free"  "--  unknown"
    fi
}

# Print device error stats row. Pass mount point.
_stor_check_device_errors() {
    local mnt="${1:-/}"
    local dev_stats; dev_stats=$(btrfs device stats "$mnt" 2>/dev/null || true)
    [[ -z "$dev_stats" ]] && return
    local nonzero; nonzero=$(echo "$dev_stats" | awk '$NF != "0"' || true)
    if [[ -n "$nonzero" ]]; then
        _row "Dev errors" "!!  non-zero error counters detected"
        echo "$nonzero" | while IFS= read -r line; do _row2 "!  $line"; done
        _rec "Btrfs device errors detected — run: btrfs device stats ${mnt} and check drive health"
    else
        _row "Dev errors" "OK  all zero"
    fi
}

# Print bees dedup daemon status row.
_stor_check_bees() {
    local bees_uuid; bees_uuid=$(_get_bees_uuid)
    if [[ -z "$bees_uuid" ]]; then
        _row "bees"  "--  could not determine Btrfs UUID for ${ROOTLABEL}"
        return
    fi
    local bees_unit="beesd@${bees_uuid}"
    local bees_conf="/etc/bees/${bees_uuid}.conf"
    local bees_st;  bees_st=$(systemctl is-active  "$bees_unit" 2>/dev/null | tr -d '[:space:]' || echo "inactive")
    local bees_en;  bees_en=$(systemctl is-enabled "$bees_unit" 2>/dev/null | tr -d '[:space:]' || echo "disabled")
    local bees_short="${bees_uuid:0:8}…"
    if [[ "$bees_st" == "active" ]]; then
        local bees_dedup=""
        bees_dedup=$(journalctl -u "$bees_unit" -n 50 --no-pager -q 2>/dev/null \
            | grep -oE 'deduped [0-9.]+ [KMGT]?B' | tail -1 || echo "")
        _row "bees"  "OK  beesd@${bees_short} running${bees_dedup:+  (${bees_dedup})}"
    elif [[ ! -f "$bees_conf" ]]; then
        _row "bees"  "--  not configured (run beesd-setup to enable dedup)"
        _rec "bees not configured — run: beesd-setup, then: systemctl enable --now ${bees_unit}"
    elif [[ "$bees_en" == "enabled" ]]; then
        # Show when it last ran so user knows if it ever started
        local bees_last=""
        bees_last=$(systemctl show "$bees_unit" --property=ExecMainExitTimestamp --value \
            2>/dev/null | grep -v "^0$\|^$" || echo "")
        [[ -z "$bees_last" ]] && \
            bees_last=$(journalctl -u "$bees_unit" -n 1 --no-pager -q \
                --output=short-iso 2>/dev/null | awk '{print $1}' | head -1 || echo "")
        _row "bees"  "!!  beesd@${bees_short} enabled but not running${bees_last:+  (last run: ${bees_last})}"
        _rec "bees enabled but not running — run: systemctl start ${bees_unit}  [auto]"
    else
        _row "bees"  "!   beesd@${bees_short} configured but not enabled"
        _rec "bees not running — run: systemctl enable --now ${bees_unit}  [auto]"
    fi
}

_section_storage() {
    _head "Storage"

    # Free space — shared helper
    _stor_check_free /

    # Device error stats — shared helper
    _stor_check_device_errors /

    # ── Btrfs quota consistency ───────────────────────────────────────────────
    # Quota groups (qgroups) can become inconsistent after unclean shutdowns or
    # heavy subvolume activity. An inconsistent qgroup causes phantom ENOSPC
    # even when the filesystem has free space. Only check if quotas are enabled.
    local qgroup_out; qgroup_out=$(btrfs qgroup show / 2>&1 || true)
    if ! echo "$qgroup_out" | grep -q 'ERROR\|quota system is not enabled'; then
        if echo "$qgroup_out" | grep -qi 'inconsistent\|stale'; then
            _row "Quotas"    "!!  qgroup inconsistency detected — may cause phantom ENOSPC"
            _rec "Btrfs qgroup inconsistent — fix: btrfs quota rescan /  [auto]"
        fi
    fi

    local scrub_st scrub_res
    scrub_st=$(btrfs scrub status / 2>/dev/null || true)
    scrub_res=$(echo "$scrub_st" | awk '/Status:/{print $2}' | head -1 || echo "")
    local scrub_timer
    scrub_timer=$(systemctl is-active btrfs-scrub.timer 2>/dev/null || echo "inactive")

    if [[ "$scrub_timer" == "active" ]]; then
        # Use machine-readable property to get next trigger — avoids locale fragility
        local scrub_next=""
        scrub_next=$(systemctl show btrfs-scrub.timer \
            --property=NextElapseUSecRealtime --value 2>/dev/null || echo "")
        # Monotonic timer fallback
        if [[ -z "$scrub_next" || "$scrub_next" == "0" ]]; then
            scrub_next=$(systemctl show btrfs-scrub.timer \
                --property=NextElapseUSecMonotonic --value 2>/dev/null || echo "")
        fi
        local scrub_next_fmt=""
        if [[ "$scrub_next" =~ ^[0-9]+$ ]] && (( scrub_next > 0 )); then
            scrub_next_fmt=$(date -d "@$(( scrub_next / 1000000 ))" '+%Y-%m-%d %H:%M' 2>/dev/null \
                || echo "")
        fi
        if [[ -n "$scrub_next_fmt" ]]; then
            _row "Scrub tmr"  "OK  active (next: ${scrub_next_fmt})"
        else
            _row "Scrub tmr"  "OK  active"
        fi
    else
        _row "Scrub tmr"  "!!  btrfs-scrub.timer not active"
        _rec "btrfs-scrub.timer not active — run: systemctl enable --now btrfs-scrub.timer  [auto]"
    fi

    case "$scrub_res" in
        finished)
            local re ce co
            re=$(  echo "$scrub_st" | awk '/read_errors:/{print $2}'      | head -1 || echo "0")
            ce=$(  echo "$scrub_st" | awk '/csum_errors:/{print $2}'      | head -1 || echo "0")
            co=$(  echo "$scrub_st" | awk '/corrected_errors:/{print $2}' | head -1 || echo "0")
            if [[ "${re:-0}" != "0" || "${ce:-0}" != "0" || "${co:-0}" != "0" ]]; then
                _row "Scrub"    "!!  errors: read=${re} csum=${ce} corrected=${co}"
                _rec "Btrfs scrub found errors — investigate: btrfs scrub status /"
            else
                _row "Scrub"    "OK  last run clean"
            fi ;;
        running)  _row "Scrub"    "->  in progress" ;;
        "")        _row "Scrub"    "--  no scrub recorded yet" ;;
        *)         _row "Scrub"    "!   status: ${scrub_res}" ;;
    esac

    local t_ok=() t_bad=()
    for name in balance defrag trim; do
        local unit="btrfs-${name}.timer"
        [[ "$(systemctl is-active "$unit" 2>/dev/null)" == "active" ]] \
            && t_ok+=("$name") || t_bad+=("$name")
    done
    local t_ok_str; t_ok_str=$(IFS=,; echo "${t_ok[*]}" | tr ',' ' ')
    local t_bad_str; t_bad_str=$(IFS=,; echo "${t_bad[*]}" | tr ',' ' ')
    if [[ ${#t_bad[@]} -eq 0 ]]; then
        _row "Maint tmrs"  "OK  active: ${t_ok_str}"
        # Show next-run time for each active timer
        for name in "${t_ok[@]}"; do
            local unit="btrfs-${name}.timer"
            local t_next=""
            t_next=$(systemctl show "$unit" --property=NextElapseUSecRealtime --value 2>/dev/null || echo "")
            [[ -z "$t_next" || "$t_next" == "0" ]] && \
                t_next=$(systemctl show "$unit" --property=NextElapseUSecMonotonic --value 2>/dev/null || echo "")
            if [[ "$t_next" =~ ^[0-9]+$ ]] && (( t_next > 0 )); then
                local t_next_fmt
                t_next_fmt=$(date -d "@$(( t_next / 1000000 ))" '+%Y-%m-%d %H:%M' 2>/dev/null || echo "")
                [[ -n "$t_next_fmt" ]] && _row2 "--  ${name}: next ${t_next_fmt}"
            fi
        done
    elif [[ ${#t_ok[@]} -eq 0 ]]; then
        _row "Maint tmrs"  "!!  all inactive: ${t_bad_str}"
        local units; units=$(printf 'btrfs-%s.timer ' "${t_bad[@]}")
        _rec "Btrfs timers inactive (${t_bad_str}) — run: systemctl enable --now ${units% }  [auto]"
    else
        _row "Maint tmrs"  "!   active: ${t_ok_str}  |  inactive: ${t_bad_str}"
        local units; units=$(printf 'btrfs-%s.timer ' "${t_bad[@]}")
        _rec "Btrfs timers inactive (${t_bad_str}) — run: systemctl enable --now ${units% }  [auto]"
    fi

    # ── Btrfs subvolume size breakdown ────────────────────────────────────────
    # Enumerate mounted Btrfs subvolumes by matching findmnt subvol options
    # against btrfs subvolume list. This reliably catches /data, /nix, /home, etc.
    local _svol_sizes=()
    while IFS=$'\t' read -r mp opts; do
        [[ -z "$mp" || -z "$opts" ]] && continue
        local _subvol; _subvol=$(echo "$opts" | grep -oP '(?<=subvol=)[^,\s]+' | head -1 || echo "")
        [[ -z "$_subvol" || "$_subvol" == "/" ]] && continue
        # Only report named shani subvolumes (start with @)
        [[ "$_subvol" == @* ]] || continue
        local _sz; _sz=$(df -BM --output=used "$mp" 2>/dev/null | tail -1 | tr -d ' M' || echo "")
        [[ "$_sz" =~ ^[0-9]+$ ]] || continue
        (( _sz > 0 )) || continue
        _svol_sizes+=("${_subvol}:${_sz}MB")
    done < <(findmnt --list -n -o TARGET,OPTIONS -t btrfs 2>/dev/null || true)
    if [[ ${#_svol_sizes[@]} -gt 0 ]]; then
        _row "Subvol sz"  "--  $(_join "${_svol_sizes[@]}")"
    fi

    # ── Btrfs dedup (bees) ────────────────────────────────────────────────────
    _stor_check_bees

    # ── Tool hints ────────────────────────────────────────────────────────────
    if ! command -v compsize &>/dev/null; then
        _row "compsize"  "--  not installed — run: pacman -S compsize (needed for --storage-info)"
    fi
}

_section_battery() {
    # Only show this section if a battery is present (laptops/UPS systems)
    local bat_dir=""
    for d in /sys/class/power_supply/BAT* /sys/class/power_supply/CMB*; do
        [[ -d "$d" ]] && bat_dir="$d" && break
    done
    [[ -z "$bat_dir" ]] && return 0   # Desktop — skip silently

    _head "Battery"

    local status capacity technology cycle_count
    status=$(    cat "${bat_dir}/status"      2>/dev/null || echo "Unknown")
    capacity=$(  cat "${bat_dir}/capacity"    2>/dev/null || echo "")
    technology=$(cat "${bat_dir}/technology"  2>/dev/null || echo "")
    cycle_count=$(cat "${bat_dir}/cycle_count" 2>/dev/null || echo "")

    # ── Charge level ─────────────────────────────────────────────────────────
    if [[ -n "$capacity" && "$capacity" =~ ^[0-9]+$ ]]; then
        if [[ "$status" == "Charging" || "$status" == "Full" ]]; then
            _row "Battery"  "OK  ${capacity}%  (${status})"
        elif (( capacity <= 10 )); then
            _row "Battery"  "!!  ${capacity}%  (${status}) — critically low"
            _rec "Battery critically low (${capacity}%) — plug in power"
        elif (( capacity <= 20 )); then
            _row "Battery"  "!   ${capacity}%  (${status}) — low"
        else
            _row "Battery"  "OK  ${capacity}%  (${status})"
        fi
    else
        _row "Battery"  "--  present (capacity unknown)"
    fi

    # ── Technology ───────────────────────────────────────────────────────────
    [[ -n "$technology" ]] && _row "Chemistry"  "--  ${technology}"

    # ── Cycle count ──────────────────────────────────────────────────────────
    if [[ -n "$cycle_count" && "$cycle_count" =~ ^[0-9]+$ && "$cycle_count" -gt 0 ]]; then
        if (( cycle_count >= 800 )); then
            _row "Cycles"  "!   ${cycle_count}  (degraded — consider replacement)"
            _rec "Battery has ${cycle_count} charge cycles — capacity may be significantly reduced"
        elif (( cycle_count >= 500 )); then
            _row "Cycles"  "--  ${cycle_count}  (moderate wear)"
        else
            _row "Cycles"  "OK  ${cycle_count}"
        fi
    fi

    # ── Design vs full capacity (health %) ───────────────────────────────────
    local energy_full energy_full_design health_pct
    energy_full=$(        cat "${bat_dir}/energy_full"        2>/dev/null || \
                          cat "${bat_dir}/charge_full"        2>/dev/null || echo "")
    energy_full_design=$( cat "${bat_dir}/energy_full_design" 2>/dev/null || \
                          cat "${bat_dir}/charge_full_design" 2>/dev/null || echo "")
    if [[ -n "$energy_full" && -n "$energy_full_design" \
          && "$energy_full_design" =~ ^[0-9]+$ && "$energy_full_design" -gt 0 \
          && "$energy_full" =~ ^[0-9]+$ ]]; then
        health_pct=$(awk "BEGIN{printf \"%d\", ($energy_full/$energy_full_design)*100}")
        if (( health_pct < 60 )); then
            _row "Health"  "!!  ${health_pct}% of design capacity — replace battery"
            _rec "Battery health is ${health_pct}% — capacity severely degraded, consider replacement"
        elif (( health_pct < 80 )); then
            _row "Health"  "!   ${health_pct}% of design capacity"
        else
            _row "Health"  "OK  ${health_pct}% of design capacity"
        fi
    fi

    # ── Power supply / AC adapter ─────────────────────────────────────────────
    local ac_online=""
    for ac in /sys/class/power_supply/AC* /sys/class/power_supply/ADP*; do
        [[ -f "${ac}/online" ]] && ac_online=$(cat "${ac}/online" 2>/dev/null) && break
    done
    if [[ -n "$ac_online" ]]; then
        if [[ "$ac_online" == "1" ]]; then
            _row "AC power"  "OK  connected"
        else
            _row "AC power"  "--  on battery"
        fi
    fi

    # ── upower details (if available) ────────────────────────────────────────
    if command -v upower &>/dev/null; then
        local up_path; up_path=$(upower -e 2>/dev/null | grep -i 'battery' | head -1 || echo "")
        if [[ -n "$up_path" ]]; then
            local time_str=""
            time_str=$(upower -i "$up_path" 2>/dev/null \
                | awk '/time to (empty|full):/{printf "%s %s %s", $1,$2,$3; found=1} END{if(!found)exit 1}' \
                || echo "")
            [[ -n "$time_str" ]] && _row2 "--  ${time_str}"
        fi
    fi
}


_section_system_services() {
    _head "System Services"

    # ── CUPS printing ─────────────────────────────────────────────────────────
    if getent group cups &>/dev/null; then
        local cups_st; cups_st=$(systemctl is-active cups.socket 2>/dev/null || echo "inactive")
        if [[ "$cups_st" == "active" ]]; then
            _row "CUPS"      "OK  cups.socket active"
        elif systemctl is-enabled cups.service &>/dev/null 2>&1 || \
             systemctl is-enabled cups.socket  &>/dev/null 2>&1; then
            _row "CUPS"      "!   enabled but cups.socket is ${cups_st}"
            _rec "CUPS enabled but socket not active — run: systemctl enable --now cups.socket  [auto]"
        fi
        # Silent if cups not enabled — it's optional
    fi

    # ── Bluetooth ─────────────────────────────────────────────────────────────
    if [[ -d /sys/class/bluetooth ]] || systemctl cat bluetooth.service &>/dev/null 2>&1; then
        local bt_st; bt_st=$(systemctl is-active bluetooth.service 2>/dev/null || echo "inactive")
        local bt_en; bt_en=$(systemctl is-enabled bluetooth.service 2>/dev/null || echo "disabled")
        if [[ "$bt_st" == "active" ]]; then
            _row "Bluetooth"  "OK  bluetooth.service active"
        elif [[ "$bt_en" == "enabled" ]]; then
            _row "Bluetooth"  "!   enabled but not running (${bt_st})"
            _rec "bluetooth.service enabled but not active — run: systemctl start bluetooth  [auto]"
        elif [[ -d /sys/class/bluetooth ]]; then
            _row "Bluetooth"  "--  hardware present, service not enabled"
        fi
    fi

    # ── Power management ──────────────────────────────────────────────────────
    # power-profiles-daemon (ppd) is the correct daemon for Plasma and GNOME —
    # it exposes profiles (power-saver / balanced / performance) via D-Bus and
    # is what KDE Power Management and GNOME Power settings talk to.
    # TLP and auto-cpufreq CONFLICT with ppd — running them together causes
    # undefined behaviour. Only one power management stack should be active.
    local bat_present=0
    for _bd in /sys/class/power_supply/BAT* /sys/class/power_supply/CMB*; do
        [[ -d "$_bd" ]] && bat_present=1 && break
    done

    # Check ppd regardless of battery — it matters on AC-only desktops too
    local ppd_active=0 tlp_active=0 acpufreq_active=0
    systemctl is-active --quiet power-profiles-daemon 2>/dev/null && ppd_active=1
    systemctl is-active --quiet tlp                   2>/dev/null && tlp_active=1
    systemctl is-active --quiet auto-cpufreq          2>/dev/null && acpufreq_active=1

    if (( ppd_active )); then
        # Show current active profile (power-saver / balanced / performance)
        local ppd_profile=""
        if command -v powerprofilesctl &>/dev/null; then
            ppd_profile=$(powerprofilesctl get 2>/dev/null | tr -d '[:space:]' || echo "")
        fi
        _row "Power"  "OK  power-profiles-daemon active${ppd_profile:+ (${ppd_profile})}"

        # Conflict detection — TLP or auto-cpufreq running alongside ppd
        local conflicts=()
        (( tlp_active     )) && conflicts+=("tlp")
        (( acpufreq_active )) && conflicts+=("auto-cpufreq")
        if [[ ${#conflicts[@]} -gt 0 ]]; then
            local _cf_str; _cf_str=$(IFS='+'; echo "${conflicts[*]}")
            _row2 "!!  CONFLICT: ${_cf_str} also active — disable one"
            _rec "Power management conflict: power-profiles-daemon + ${_cf_str} running simultaneously — stop ${_cf_str}"
        fi
    elif (( tlp_active )); then
        _row "Power"  "--  tlp active (note: conflicts with power-profiles-daemon)"
    elif (( acpufreq_active )); then
        _row "Power"  "--  auto-cpufreq active (note: conflicts with power-profiles-daemon)"
    elif command -v power-profiles-daemon &>/dev/null; then
        local ppd_en; ppd_en=$(systemctl is-enabled power-profiles-daemon 2>/dev/null | tr -d '[:space:]' || echo "disabled")
        _row "Power"  "!   power-profiles-daemon installed but not running (${ppd_en})"
        _rec "power-profiles-daemon not active — run: systemctl enable --now power-profiles-daemon  [auto]"
    elif (( bat_present )); then
        _row "Power"  "--  no power manager detected (install: power-profiles-daemon)"
    fi

    # ── Time sync ─────────────────────────────────────────────────────────────
    if command -v timedatectl &>/dev/null; then
        local td_out ntp_active ntp_synced tsync
        td_out=$(timedatectl show 2>/dev/null || true)
        ntp_active=$(echo "$td_out" | awk -F= '/^NTP=/{print $2}'             | tr -d '[:space:]')
        ntp_synced=$(echo "$td_out" | awk -F= '/^NTPSynchronized=/{print $2}' | tr -d '[:space:]')
        tsync=$(systemctl is-active systemd-timesyncd 2>/dev/null || echo "inactive")
        if [[ "$ntp_synced" == "yes" && "$tsync" == "active" ]]; then
            _row "timesyncd"  "OK  synchronised"
        elif [[ "$ntp_active" == "yes" && "$tsync" == "active" ]]; then
            _row "timesyncd"  "!   running but not yet synchronised"
        elif [[ "$ntp_active" == "yes" ]]; then
            _row "timesyncd"  "!!  NTP enabled but service is ${tsync}"
            _rec "systemd-timesyncd not running — run: systemctl enable --now systemd-timesyncd  [auto]"
        else
            _row "timesyncd"  "!!  disabled"
            _rec "NTP disabled — run: systemctl enable --now systemd-timesyncd && timedatectl set-ntp true  [auto]"
        fi
    else
        _row "timesyncd"  "--  timedatectl not available"
    fi
}

_section_network() {
    _head "Network"

    # ── Network ───────────────────────────────────────────────────────────────
    systemctl is-active --quiet NetworkManager 2>/dev/null \
        && _row "Network"  "OK  NetworkManager active" \
        || _row "Network"  "!   NetworkManager not running"

    # ── Default route ─────────────────────────────────────────────────────────
    local default_route; default_route=$(ip route show default 2>/dev/null | head -1 || echo "")
    if [[ -z "$default_route" ]]; then
        _row "Route"      "!   no default route — network may be unconfigured"
        _rec "No default route detected — check NetworkManager connection"
    fi

    # openresolv (resolvconf) — Shanios uses this, NOT systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        _row "DNS"        "!!  systemd-resolved active — not supported on Shanios"
        _rec "systemd-resolved is active — Shanios uses openresolv; resolvectl will not work"
    fi

    # ── /etc/resolv.conf usability ────────────────────────────────────────────
    if [[ ! -f /etc/resolv.conf ]]; then
        _row "resolv.conf" "!!  missing — DNS resolution broken"
        _rec "/etc/resolv.conf missing — resolvconf or openresolv should generate it"
    elif [[ ! -s /etc/resolv.conf ]]; then
        _row "resolv.conf" "!!  empty — DNS resolution broken"
        _rec "/etc/resolv.conf is empty — check openresolv / resolvconf configuration"
    elif ! grep -q '^nameserver ' /etc/resolv.conf 2>/dev/null; then
        _row "resolv.conf" "!!  no nameserver entries — DNS resolution broken"
        _rec "/etc/resolv.conf has no nameserver lines — check openresolv configuration"
    fi


    # ── Tailscale connectivity ────────────────────────────────────────────────
    if systemctl is-active --quiet tailscaled 2>/dev/null; then
        local ts_out; ts_out=$(tailscale status 2>/dev/null || echo "")
        local ts_ip;  ts_ip=$(tailscale ip -4 2>/dev/null || echo "")
        if echo "$ts_out" | grep -qiE 'logged out|not logged in|stopped'; then
            _row "Tailscale"  "!   daemon running but not authenticated — run: tailscale up"
        elif [[ -n "$ts_ip" ]]; then
            _row "Tailscale"  "OK  connected  (${ts_ip})"
        else
            _row "Tailscale"  "--  daemon active (status unclear)"
        fi
    fi


    # ── Avahi mDNS ────────────────────────────────────────────────────────────
    # Needed for printer/scanner auto-discovery (cups-browsed), .local resolution
    if command -v avahi-daemon &>/dev/null; then
        if systemctl is-active --quiet avahi-daemon 2>/dev/null; then
            _row "Avahi"      "OK  mDNS/DNS-SD active"
        elif systemctl is-enabled --quiet avahi-daemon 2>/dev/null; then
            _row "Avahi"      "!   enabled but not running"
            _rec "avahi-daemon not running — run: systemctl start avahi-daemon  [auto]"
        fi
        # Silent if not enabled — it's optional
    fi
}

_section_audio_display() {
    _head "Audio & Display"

    # ── Realtime audio ────────────────────────────────────────────────────────
    local rtkit_st; rtkit_st=$(systemctl is-active rtkit-daemon 2>/dev/null || echo "inactive")
    if [[ "$rtkit_st" == "active" ]]; then
        _row "rtkit"     "OK  running"
    elif command -v pipewire &>/dev/null || command -v pulseaudio &>/dev/null; then
        _row "rtkit"     "!!  not running (PipeWire RT unavailable)"
        _rec "rtkit-daemon not running — run: systemctl enable --now rtkit-daemon  [auto]"
    fi

    local rt_line rt_members=()
    rt_line=$(getent group realtime 2>/dev/null || grep '^realtime:' /etc/group 2>/dev/null || true)
    if [[ -z "$rt_line" ]]; then
        _row "realtime"  "!!  group missing — install realtime-privileges"
        _rec "'realtime' group missing — install: pacman -S realtime-privileges"
    else
        IFS=',' read -ra rt_members <<< "${rt_line##*:}"
        local rt_display; rt_display=$(IFS=' '; echo "${rt_members[*]}" | tr -s ' ' | xargs)
        # Check every login user is in the realtime group
        local _rt_login=() _missing_rt=()
        _get_login_users _rt_login
        for u in "${_rt_login[@]}"; do
            id -nG "$u" 2>/dev/null | grep -qw realtime || _missing_rt+=("$u")
        done
        if [[ ${#_missing_rt[@]} -gt 0 ]]; then
            _row "realtime"  "!   users missing from group: $(_join "${_missing_rt[@]}")"
            _rec "User(s) $(_join "${_missing_rt[@]}") not in 'realtime' group — add: usermod -aG realtime <user>"
        elif [[ -z "$rt_display" ]]; then
            _row "realtime"  "!   group empty"
            _rec "'realtime' group empty — add users: usermod -aG realtime <user>"
        else
            _row "realtime"  "OK  ${rt_display}"
        fi
    fi

    # ── Profile Sync Daemon ───────────────────────────────────────────────────
    # Only flag if enabled but broken — silent when working or not installed
    if _sysd_user is-enabled --quiet psd 2>/dev/null && \
       ! _sysd_user is-active --quiet psd 2>/dev/null; then
        _row "PSD"        "!   enabled but not running"
        _rec "Profile Sync Daemon enabled but not active — run: systemctl --user start psd"
    fi







    # ── PipeWire audio stack ──────────────────────────────────────────────────
    if command -v pipewire &>/dev/null; then
        local pw_st wp_st
        pw_st=$(_sysd_user is-active pipewire    2>/dev/null | tr -d '[:space:]' || echo "inactive")
        wp_st=$(_sysd_user is-active wireplumber 2>/dev/null | tr -d '[:space:]' || echo "inactive")
        if [[ "$pw_st" == "active" && "$wp_st" == "active" ]]; then
            _row "PipeWire"  "OK  pipewire + wireplumber active"
        elif [[ "$pw_st" == "active" && "$wp_st" != "active" ]]; then
            _row "PipeWire"  "!   pipewire active but wireplumber is ${wp_st}"
            _rec "WirePlumber not running — audio routing broken: systemctl --user enable --now wireplumber"
        else
            # Both inactive — only flag if user has an active graphical (x11/wayland) session
            # Under sudo without a session, user services legitimately appear inactive
            local _has_session=0
            loginctl list-sessions --no-legend 2>/dev/null \
                | awk '{print $3}' | grep -qx "$_CALLER_USER" && _has_session=1
            if (( _has_session )); then
                _row "PipeWire"  "!   not running for ${_CALLER_USER} — audio will be silent"
                _rec "PipeWire not running — systemctl --user enable --now pipewire wireplumber"
            fi
            # Silent if no active session — running health at boot/tty before login is normal
        fi
    fi

    # ── Display manager ───────────────────────────────────────────────────────
    local profile_dm; profile_dm=$(cat /etc/shani-profile 2>/dev/null | tr -d '[:space:]' || echo "")
    local dm_svc=""
    [[ "$profile_dm" == "plasma" ]] && dm_svc="plasmalogin"
    [[ "$profile_dm" == "gnome"  ]] && dm_svc="gdm"
    if [[ -n "$dm_svc" ]]; then
        if systemctl is-active --quiet "${dm_svc}" 2>/dev/null; then
            _row "Display mgr" "OK  ${dm_svc} active"
        elif systemctl is-enabled --quiet "${dm_svc}" 2>/dev/null; then
            _row "Display mgr" "!   ${dm_svc} enabled but not running"
            _rec "${dm_svc} enabled but not active — run: systemctl start ${dm_svc}  [auto]"
        else
            _row "Display mgr" "!!  ${dm_svc} not enabled"
            _rec "${dm_svc} not enabled — run: systemctl enable --now ${dm_svc}  [auto]"
        fi
    fi

    # ── switcheroo-control (hybrid GPU) ───────────────────────────────────────
    # Only relevant when multiple GPUs are present (discrete + integrated)
    if command -v switcherooctl &>/dev/null; then
        local gpu_count; gpu_count=$(switcherooctl list 2>/dev/null | grep -c '^GPU' || echo "0")
        if [[ "$gpu_count" =~ ^[0-9]+$ ]] && (( gpu_count >= 2 )); then
            if systemctl is-active --quiet switcheroo-control 2>/dev/null; then
                _row "GPU switch"  "OK  switcheroo-control active (${gpu_count} GPUs)"
            else
                _row "GPU switch"  "!   ${gpu_count} GPUs found but switcheroo-control not running — PRIME offload unavailable"
                _rec "switcheroo-control not active — run: systemctl enable --now switcheroo-control  [auto]"
            fi
        fi
    fi


    # ── ananicy-cpp ───────────────────────────────────────────────────────────
    # Only flag when explicitly enabled but not running
    if { command -v ananicy-cpp &>/dev/null || systemctl cat ananicy-cpp &>/dev/null 2>&1; } && \
       systemctl is-enabled --quiet ananicy-cpp 2>/dev/null && \
       ! systemctl is-active --quiet ananicy-cpp 2>/dev/null; then
        _row "ananicy-cpp" "!   enabled but not running — CPU scheduling rules inactive"
        _rec "ananicy-cpp not running — run: systemctl enable --now ananicy-cpp  [auto]"
    fi
}

_section_units() {
    _head "Units"

    # ── Failed units ──────────────────────────────────────────────────────────
    local failed_units=()
    # Filter known transient oneshot units that legitimately enter failed state
    # (e.g. systemd-suspend.service fails after every suspend cycle by design)
    local _transient_ok="systemd-suspend.service|systemd-hibernate.service|systemd-hybrid-sleep.service"
    mapfile -t failed_units < <(
        systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null \
            | awk '{print $2}' | grep -v '^$' | grep '\.' \
            | grep -vE "^(${_transient_ok})$" || true)
    if [[ ${#failed_units[@]} -eq 0 ]]; then
        _row "Units"     "OK  no failed systemd units"
    else
        local _fu_str; _fu_str=$(IFS=' '; echo "${failed_units[*]}")
        _row "Units"     "!!  ${#failed_units[@]} failed: ${_fu_str}"
        _rec "Failed units: ${_fu_str} — run: systemctl status ${_fu_str}"
    fi
}

_section_package_managers() {
    _head "Package Managers"

    # ── Flatpak ───────────────────────────────────────────────────────────────
    if command -v flatpak &>/dev/null; then
        local flatpak_sys; flatpak_sys=$(systemctl is-active flatpak-update-system.timer 2>/dev/null || echo "inactive")
        local flatpak_apps flatpak_remotes flatpak_mb
        flatpak_apps=$(timeout 5 flatpak list --app --columns=application 2>/dev/null | wc -l || echo "?")
        flatpak_remotes=$(flatpak remotes 2>/dev/null | grep -c '.' || echo "0")
        flatpak_mb=$(du -sm /var/lib/flatpak 2>/dev/null | awk '{print $1}' || echo "")
        local fp_sz_str=""
        [[ "$flatpak_mb" =~ ^[0-9]+$ ]] && fp_sz_str=", ${flatpak_mb} MB"
        if [[ "$flatpak_sys" == "active" ]]; then
            _row "Flatpak"    "OK  auto-update active  (${flatpak_apps} apps, ${flatpak_remotes} remote(s)${fp_sz_str})"
        else
            _row "Flatpak"    "!   auto-update timer not active  (${flatpak_apps} apps${fp_sz_str})"
            _rec "Flatpak auto-update timer not active — run: systemctl enable --now flatpak-update-system.timer  [auto]"
        fi
        # Flatpak runtime count as continuation (size detail in --storage-info)
        if [[ "$flatpak_mb" =~ ^[0-9]+$ ]]; then
            local fp_unused=""
            fp_unused=$(timeout 10 flatpak list --runtime --columns=application 2>/dev/null | wc -l || echo "")
            [[ "$fp_unused" =~ ^[0-9]+$ ]] && (( fp_unused > 0 )) && \
                _row2 "--  ${fp_unused} runtime(s) installed"
        fi
        # Pending flatpak updates
        local flatpak_updates
        flatpak_updates=$(timeout 15 flatpak remote-ls --updates 2>/dev/null | wc -l || echo "")
        if [[ "$flatpak_updates" =~ ^[0-9]+$ ]] && (( flatpak_updates > 0 )); then
            _row "Flatpak upd" "--  ${flatpak_updates} update(s) pending (timer will apply automatically)"
        fi
    fi

    # ── Snap (snapd) ──────────────────────────────────────────────────────────
    if findmnt -n /var/lib/snapd &>/dev/null; then
        local snapd_sock; snapd_sock=$(systemctl is-active snapd.socket 2>/dev/null || echo "inactive")
        local snapd_aa;   snapd_aa=$(systemctl is-active snapd.apparmor.service 2>/dev/null || echo "inactive")
        local snap_count=""
        if [[ "$snapd_sock" == "active" ]] && command -v snap &>/dev/null; then
            snap_count=$(timeout 5 snap list 2>/dev/null | tail -n +2 | wc -l || echo "")
        fi
        # Pre-compute store size so it can go on the main row
        local snap_store_mb
        snap_store_mb=$(du -sm /var/lib/snapd/snaps 2>/dev/null | awk '{print $1}' || echo "")
        local snap_sz_str=""
        [[ "$snap_store_mb" =~ ^[0-9]+$ ]] && snap_sz_str=", ${snap_store_mb} MB"
        if [[ "$snapd_sock" == "active" && "$snapd_aa" == "active" ]]; then
            _row "Snap"       "OK  snapd + AppArmor active${snap_count:+  (${snap_count} snaps${snap_sz_str})}"
        elif [[ "$snapd_sock" == "active" ]]; then
            _row "Snap"       "!   snapd active but AppArmor service is ${snapd_aa} — confinement not enforced"
            _rec "snapd.apparmor.service not active — snap confinement broken  [auto]"
        else
            _row "Snap"       "!!  @snapd mounted but snapd.socket is ${snapd_sock}"
            _rec "snapd.socket not active — run: systemctl enable --now snapd.socket snapd.apparmor.service  [auto]"
        fi
        # Check for stale snap revisions — warn if present
        local snap_stale_count=""
        command -v snap &>/dev/null && \
            snap_stale_count=$(timeout 5 snap list --all 2>/dev/null \
                | awk '/disabled/{c++} END{print c+0}' || echo "")
        if [[ "$snap_stale_count" =~ ^[0-9]+$ ]] && (( snap_stale_count > 0 )); then
            _row2 "--  ${snap_stale_count} stale revision(s) — run: snap set system refresh.retain=2"
            _rec "Snap has ${snap_stale_count} stale revision(s) — free space: snap set system refresh.retain=2  [auto]"
        fi
        # Pending snap updates
        if [[ "$snapd_sock" == "active" ]] && command -v snap &>/dev/null; then
            local snap_updates
            snap_updates=$(timeout 10 snap refresh --list 2>/dev/null | tail -n +2 | wc -l || echo "")
            if [[ "$snap_updates" =~ ^[0-9]+$ ]]; then
                if (( snap_updates > 0 )); then
                    _row "Snap upd"   "--  ${snap_updates} update(s) pending — run: snap refresh  [auto]"
                    _rec "${snap_updates} snap update(s) available — run: snap refresh  [auto]"
                else
                    _row "Snap upd"   "OK  up to date"
                fi
            fi
        fi
    fi

    # ── Nix ───────────────────────────────────────────────────────────────────
    if findmnt -n /nix &>/dev/null; then
        # Store size and generation count — computed before the main row so they can be inlined
        local nix_store_mb
        nix_store_mb=$(du -sm /nix/store 2>/dev/null | awk '{print $1}' || echo "")
        local nix_gen_count=""
        local _nix_prof="/nix/var/nix/profiles"
        if [[ -d "$_nix_prof" ]]; then
            nix_gen_count=$(ls "$_nix_prof" 2>/dev/null | grep -cE '^system-[0-9]+-link$' || echo "")
        fi
        local nix_sz_str=""
        [[ "$nix_store_mb" =~ ^[0-9]+$ ]] && nix_sz_str=", ${nix_store_mb} MB"
        local nix_gen_str=""
        [[ "$nix_gen_count" =~ ^[0-9]+$ ]] && (( nix_gen_count > 0 )) && \
            nix_gen_str=", ${nix_gen_count} generation(s)"

        if systemctl is-active --quiet nix-daemon.socket 2>/dev/null; then
            local nix_ver=""
            nix_ver=$(nix --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
            local nix_channels=""
            local _nix_user="$_CALLER_USER"
            if [[ -n "$_nix_user" ]]; then
                nix_channels=$(timeout 5 runuser -u "$_nix_user" -- nix-channel --list 2>/dev/null | wc -l || echo "")
            fi
            _row "Nix" "OK  nix-daemon active${nix_ver:+  (v${nix_ver})}${nix_channels:+  ${nix_channels} channel(s)}${nix_sz_str}${nix_gen_str}"
        else
            _row "Nix" "!!  @nix mounted but nix-daemon.socket not active"
            _rec "nix-daemon.socket not active — run: systemctl enable --now nix-daemon.socket  [auto]"
        fi
        # Nix channel freshness — compare local channel age to detect stale channels.
        # nix-env --dry-run is too slow for a health check; instead check how old
        # the local channel manifest is. >7 days without update = suggest nix-channel --update.
        if [[ -n "$_nix_user" ]] && command -v nix-channel &>/dev/null; then
            local _nix_channel_dir
            _nix_channel_dir=$(runuser -u "$_nix_user" -- \
                sh -c 'echo "${HOME}/.nix-defexpr/channels"' 2>/dev/null || echo "")
            if [[ -d "$_nix_channel_dir" ]]; then
                local _nix_age_days
                _nix_age_days=$(( ( $(date +%s) - $(stat -c %Y "$_nix_channel_dir" 2>/dev/null || echo 0) ) / 86400 ))
                if (( _nix_age_days > 7 )); then
                    _row "Nix upd"    "--  channels ${_nix_age_days}d old — run: nix-channel --update"
                else
                    _row "Nix upd"    "OK  channels updated ${_nix_age_days}d ago"
                fi
            fi
        fi
        # Nix store: warn only when critically large (detail in --storage-info)
        if [[ "$nix_store_mb" =~ ^[0-9]+$ ]] && (( nix_store_mb > 51200 )); then
            _row2 "!   ${nix_store_mb} MB — run: nix-collect-garbage -d"
            _rec "Nix store is ${nix_store_mb} MB — free space: nix-collect-garbage -d"
        fi
    fi

    # ── AppImage FUSE ─────────────────────────────────────────────────────────
    # AppImages require FUSE to mount and run. Without it every .AppImage fails.
    if find /home /root 2>/dev/null -maxdepth 4 -name '*.AppImage' -quit 2>/dev/null | grep -q .; then
        local fuse_ok=0
        lsmod 2>/dev/null | grep -qw 'fuse' && fuse_ok=1
        command -v fusermount3 &>/dev/null && fuse_ok=1
        command -v fusermount  &>/dev/null && fuse_ok=1
        if (( fuse_ok )); then
            _row "AppImage"   "OK  FUSE available"
        else
            _row "AppImage"   "!!  .AppImage files found but FUSE not loaded — they will not run"
            _rec "FUSE not available — install fuse3 or load the fuse module"
        fi
    elif command -v fusermount3 &>/dev/null || lsmod 2>/dev/null | grep -qw 'fuse'; then
        _row "AppImage"   "--  FUSE available (no .AppImage files found)"
    fi

    # ── shani-update ─────────────────────────────────────────────────────────
    if _sysd_user is-active --quiet shani-update.timer 2>/dev/null; then
        _row "shani-upd"  "OK  update checker active"
    elif _sysd_user is-enabled --quiet shani-update.timer 2>/dev/null; then
        _row "shani-upd"  "--  enabled, not yet started (starts at login)"
    else
        _row "shani-upd"  "!   shani-update.timer not enabled — OS updates won't be auto-checked"
        _rec "shani-update.timer not enabled — run: systemctl --user enable --now shani-update.timer  [auto]"
    fi
}

_section_virtualization() {
    # Only show if libvirt or qemu is installed
    if ! command -v virsh &>/dev/null && \
       ! command -v qemu-system-x86_64 &>/dev/null && \
       ! command -v qemu-kvm &>/dev/null && \
       [[ ! -d /data/varlib/libvirt ]]; then
        return 0
    fi

    _head "Virtualization"

    # ── KVM / hardware virt ───────────────────────────────────────────────────
    if [[ -e /dev/kvm ]]; then
        local kvm_perms; kvm_perms=$(stat -c '%a' /dev/kvm 2>/dev/null || echo "")
        _row "KVM"        "OK  /dev/kvm present${kvm_perms:+  (mode ${kvm_perms})}"
    else
        _row "KVM"        "!!  /dev/kvm missing — VMs will not start"
        _rec "KVM device missing — enable AMD-V/VT-x in BIOS and ensure kvm/kvm-amd/kvm-intel module is loaded"
    fi

    # ── libvirt daemons ───────────────────────────────────────────────────────
    if command -v virsh &>/dev/null || [[ -d /data/varlib/libvirt ]]; then

        # Detect whether running modular (virtqemud) or monolithic (libvirtd) mode.
        # Arch libvirt defaults to modular since libvirt 6.0.
        local libvirt_active=0
        local libvirt_mode=""

        if systemctl is-active --quiet virtqemud.socket 2>/dev/null || \
           systemctl is-active --quiet virtqemud.service 2>/dev/null; then
            libvirt_active=1
            libvirt_mode="modular"
        elif systemctl is-active --quiet libvirtd.socket 2>/dev/null || \
             systemctl is-active --quiet libvirtd.service 2>/dev/null; then
            libvirt_active=1
            libvirt_mode="monolithic"
        fi

        if (( libvirt_active )); then
            local vm_count="" vm_running=""
            if command -v virsh &>/dev/null; then
                vm_count=$(timeout 5 virsh list --all 2>/dev/null \
                    | awk 'NR>2 && /^[[:space:]]*[0-9-]/' | wc -l || echo "")
                vm_running=$(timeout 5 virsh list 2>/dev/null \
                    | awk 'NR>2 && /running/' | wc -l || echo "0")
            fi
            _row "libvirtd"  "OK  active (${libvirt_mode})${vm_count:+  (${vm_count} VM(s) defined${vm_running:+, ${vm_running} running})}"
        elif systemctl is-enabled --quiet virtqemud.service 2>/dev/null || \
             systemctl is-enabled --quiet libvirtd.service  2>/dev/null; then
            _row "libvirtd"  "!   enabled but not running"
            _rec "libvirtd/virtqemud enabled but not active — run: systemctl start virtqemud.socket  [auto]"
        else
            _row "libvirtd"  "--  installed but not enabled"
        fi

        # ── Modular daemon health ─────────────────────────────────────────────
        # In modular mode, each subsystem is a separate daemon activated via
        # its .socket unit. Check .socket first (socket activation), then
        # .service (always-running). Per docs: virtlogd and virtlockd must
        # NEVER be stopped while VMs are running.
        if [[ "$libvirt_mode" == "modular" ]]; then
            # Format: "unit:description:critical"
            # critical=1 means stopping while VMs run causes data loss/corruption
            local _virt_daemons=(
                "virtqemud:QEMU/KVM driver:1"
                "virtnetworkd:virtual networking:0"
                "virtstoraged:storage pools:0"
                "virtlogd:VM console logging (must not stop while VMs run):1"
                "virtlockd:disk image locking (must not stop while VMs run):1"
                "virtsecretd:secrets/credentials:0"
                "virtnodedevd:host device management:0"
                "virtnwfilterd:network firewall rules:0"
            )
            local _virt_failed=() _virt_critical_failed=() _virt_ok=0
            for _entry in "${_virt_daemons[@]}"; do
                local _svc="${_entry%%:*}"
                local _rest="${_entry#*:}"
                local _desc="${_rest%%:*}"
                local _crit="${_rest##*:}"
                # Only check if the unit exists on this system
                if systemctl cat "${_svc}.socket" &>/dev/null 2>&1 || \
                   systemctl cat "${_svc}.service" &>/dev/null 2>&1; then
                    if systemctl is-active --quiet "${_svc}.socket"  2>/dev/null || \
                       systemctl is-active --quiet "${_svc}.service" 2>/dev/null; then
                        _virt_ok=$(( _virt_ok + 1 ))
                    else
                        if [[ "$_crit" == "1" ]]; then
                            _virt_critical_failed+=("$_svc")
                        else
                            _virt_failed+=("$_svc")
                        fi
                    fi
                fi
            done

            if [[ ${#_virt_critical_failed[@]} -gt 0 ]]; then
                _row "virt daemons" "!!  critical not running: $(_join "${_virt_critical_failed[@]}")"
                for _f in "${_virt_critical_failed[@]}"; do
                    _rec "${_f} not active — STOP all VMs first, then: systemctl enable --now ${_f}.socket  [auto]"
                done
            fi
            if [[ ${#_virt_failed[@]} -gt 0 ]]; then
                _row2 "!   not running: $(_join "${_virt_failed[@]}")"
                for _f in "${_virt_failed[@]}"; do
                    _rec "${_f} not active — run: systemctl enable --now ${_f}.socket  [auto]"
                done
            fi
            if [[ ${#_virt_critical_failed[@]} -eq 0 && ${#_virt_failed[@]} -eq 0 ]]; then
                _row "virt daemons" "OK  ${_virt_ok} modular daemon(s) active"
            fi

            # virtproxyd — only relevant for remote connections; warn if TCP/TLS sockets active
            if systemctl is-active --quiet virtproxyd-tcp.socket 2>/dev/null || \
               systemctl is-active --quiet virtproxyd-tls.socket 2>/dev/null; then
                _row "virtproxyd"   "--  remote access active (TCP/TLS) — ensure auth is configured"
            fi

            # libvirt-guests — saves/restores VMs on host shutdown
            if systemctl cat libvirt-guests.service &>/dev/null 2>&1; then
                local lg_en; lg_en=$(systemctl is-enabled libvirt-guests.service 2>/dev/null || echo "disabled")
                if [[ "$lg_en" == "enabled" ]]; then
                    _row "virt-guests" "OK  enabled (VMs saved/restored on host shutdown)"
                else
                    _row "virt-guests" "--  disabled (VMs will be killed on host shutdown)"
                fi
            fi
        else
            # Monolithic mode — virtlogd and virtlockd are helpers, must not stop while VMs run
            for _vhelper in virtlogd virtlockd; do
                if systemctl cat "${_vhelper}.socket" &>/dev/null 2>&1; then
                    if ! systemctl is-active --quiet "${_vhelper}.socket"  2>/dev/null && \
                       ! systemctl is-active --quiet "${_vhelper}.service" 2>/dev/null; then
                        _row "$_vhelper"   "!!  not running — STOP all VMs first, then start it"
                        _rec "${_vhelper} not active — must not stop while VMs run: systemctl enable --now ${_vhelper}.socket  [auto]"
                    fi
                fi
            done
        fi

        # ── Groups ───────────────────────────────────────────────────────────
        local _virt_login=()
        _get_login_users _virt_login

        # kvm group — needed for /dev/kvm access
        if getent group kvm &>/dev/null; then
            local _kvm_missing=()
            for u in "${_virt_login[@]}"; do
                id -nG "$u" 2>/dev/null | grep -qw kvm || _kvm_missing+=("$u")
            done
            if [[ ${#_kvm_missing[@]} -gt 0 ]]; then
                _row "kvm group"  "!   $(_join "${_kvm_missing[@]}") not in kvm group"
                _rec "User(s) $(_join "${_kvm_missing[@]}") not in kvm group — run: usermod -aG kvm <user>"
            else
                _row "kvm group"  "OK  users have kvm access"
            fi
        else
            _row "kvm group"  "!!  kvm group missing"
            _rec "kvm group missing — create: groupadd -r kvm  [auto]"
        fi

        # libvirt group — needed for virsh/virt-manager without sudo
        if getent group libvirt &>/dev/null; then
            local _libvirt_missing=()
            for u in "${_virt_login[@]}"; do
                id -nG "$u" 2>/dev/null | grep -qw libvirt || _libvirt_missing+=("$u")
            done
            if [[ ${#_libvirt_missing[@]} -gt 0 ]]; then
                _row "libvirt grp" "!   $(_join "${_libvirt_missing[@]}") not in libvirt group"
                _rec "User(s) $(_join "${_libvirt_missing[@]}") not in libvirt group — run: usermod -aG libvirt <user>"
            else
                _row "libvirt grp" "OK  users have libvirt access"
            fi
        else
            _row "libvirt grp" "!!  libvirt group missing"
            _rec "libvirt group missing — create: groupadd -r libvirt  [auto]"
        fi

        # ── AppArmor profiles for libvirt ─────────────────────────────────────
        # libvirt ships AppArmor profiles for qemu/kvm — if AA is enforcing but
        # the libvirt profile is not loaded, VMs may fail to start
        if command -v aa-status &>/dev/null && aa-status --enabled >/dev/null 2>&1; then
            local aa_libvirt=0
            aa-status 2>/dev/null | grep -q 'libvirt\|qemu' && aa_libvirt=1
            if (( aa_libvirt )); then
                _row "AA/libvirt"  "OK  AppArmor profiles loaded for libvirt/qemu"
            else
                _row "AA/libvirt"  "--  no AppArmor profiles for libvirt/qemu (may be unconfined)"
            fi
        fi

        # ── Default network ───────────────────────────────────────────────────
        if (( libvirt_active )) && command -v virsh &>/dev/null; then
            local net_state="" net_autostart=""
            net_state=$(timeout 5 virsh net-info default 2>/dev/null \
                | awk '/^Active:/{print $2}' || echo "")
            net_autostart=$(timeout 5 virsh net-info default 2>/dev/null \
                | awk '/^Autostart:/{print $2}' || echo "")
            if [[ "$net_state" == "yes" ]]; then
                local net_as_str=""
                [[ "$net_autostart" == "no" ]] && net_as_str="  (autostart off — run: virsh net-autostart default)"
                _row "Virt net"   "OK  default network active (virbr0)${net_as_str}"
                [[ "$net_autostart" == "no" ]] && \
                    _rec "libvirt default network autostart disabled — run: virsh net-autostart default"
            elif [[ -n "$net_state" ]]; then
                _row "Virt net"   "!   default network inactive"
                _rec "libvirt default network inactive — run: virsh net-start default && virsh net-autostart default"
            fi

            # dnsmasq — libvirt's NAT networking depends on it
            if ! pgrep -x dnsmasq &>/dev/null; then
                _row "dnsmasq"    "--  not running (needed for VM NAT networking)"
            fi
        fi

        # ── Storage pools ─────────────────────────────────────────────────────
        if (( libvirt_active )) && command -v virsh &>/dev/null; then
            local pool_list="" pool_inactive_list=()
            pool_list=$(timeout 5 virsh pool-list --all 2>/dev/null || echo "")
            while IFS= read -r line; do
                # Skip header/separator lines
                [[ "$line" =~ ^[[:space:]]*Name || "$line" =~ ^[-[:space:]]+$ || -z "$line" ]] && continue
                local pool_name pool_state
                pool_name=$(echo "$line" | awk '{print $1}')
                pool_state=$(echo "$line" | awk '{print $2}')
                [[ "$pool_state" != "active" && -n "$pool_name" ]] && pool_inactive_list+=("$pool_name")
            done <<< "$pool_list"
            if [[ ${#pool_inactive_list[@]} -gt 0 ]]; then
                _row "Virt pools"  "!   inactive: $(_join "${pool_inactive_list[@]}")"
                _rec "libvirt storage pool(s) inactive ($(_join "${pool_inactive_list[@]}")) — run: virsh pool-start <pool>"
            fi
        fi

        # ── hugepages ─────────────────────────────────────────────────────────
        # If libvirt VMs are configured with hugepages, check they're available
        local hugepages_total hugepages_free
        hugepages_total=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo "0")
        if (( hugepages_total > 0 )); then
            hugepages_free=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null || echo "0")
            _row "Hugepages"  "--  ${hugepages_free}/${hugepages_total} free  ($(( hugepages_total * 2 )) MB reserved)"
        fi

        # ── QEMU version ──────────────────────────────────────────────────────
        local qemu_ver=""
        for qemu_bin in qemu-system-x86_64 qemu-kvm; do
            command -v "$qemu_bin" &>/dev/null && \
                qemu_ver=$("$qemu_bin" --version 2>/dev/null \
                    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "") && break
        done
        [[ -n "$qemu_ver" ]] && _row "QEMU"       "--  v${qemu_ver}"

        # ── @qemu subvolume ───────────────────────────────────────────────────
        # VM disk images live on @qemu (nodatacow for performance).
        if findmnt -n /var/lib/qemu &>/dev/null; then
            local qemu_mb=""
            qemu_mb=$(du -sm /var/lib/qemu 2>/dev/null | awk '{print $1}' || echo "")
            _row "@qemu"      "OK  mounted${qemu_mb:+  (${qemu_mb} MB)}"
        else
            _row "@qemu"      "!!  /var/lib/qemu not mounted — VM images inaccessible"
            _rec "@qemu subvolume not mounted at /var/lib/qemu — check fstab"
        fi

        # ── @libvirt subvolume ────────────────────────────────────────────────
        if findmnt -n /var/lib/libvirt &>/dev/null || [[ -d /data/varlib/libvirt ]]; then
            local libvirt_mb=""
            libvirt_mb=$(du -sm /var/lib/libvirt /data/varlib/libvirt 2>/dev/null \
                | awk '{s+=$1} END{if(s>0)print s}' || echo "")
            if findmnt -n /var/lib/libvirt &>/dev/null; then
                _row "@libvirt"   "OK  mounted${libvirt_mb:+  (${libvirt_mb} MB)}"
            else
                _row "@libvirt"   "--  via /data/varlib/libvirt${libvirt_mb:+  (${libvirt_mb} MB)}"
            fi
            if [[ "$libvirt_mb" =~ ^[0-9]+$ ]] && (( libvirt_mb > 20480 )); then
                _row2 "!   ${libvirt_mb} MB — review VM disk images"
                _rec "libvirt storage is ${libvirt_mb} MB — review VM disk images"
            fi
        fi
    fi
}

_section_containers() {
    _head "Containers"

    # ── Podman ────────────────────────────────────────────────────────────────
    if command -v podman &>/dev/null; then
        local podman_sys_st podman_usr_st podman_ver=""
        podman_sys_st=$(systemctl is-active podman.socket 2>/dev/null || echo "inactive")
        podman_usr_st=$(_sysd_user is-active podman.socket 2>/dev/null || echo "inactive")
        podman_ver=$(podman --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        # Rootless capable: needs unprivileged userns + subuid
        local rootless_ok=1
        local _rl_user="$_CALLER_USER"
        [[ -n "$_rl_user" ]] && { grep -q "^${_rl_user}:" /etc/subuid 2>/dev/null || rootless_ok=0; }
        local userns_val; userns_val=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "1")
        [[ "$userns_val" == "0" ]] && rootless_ok=0
        local rl_str=""
        (( rootless_ok )) && rl_str=", rootless-capable" || rl_str=", rootless BROKEN (check subuid/userns)"
        if [[ "$podman_sys_st" == "active" ]]; then
            _row "Podman"     "OK  socket active (system)${podman_ver:+  v${podman_ver}}${rl_str}"
        elif [[ "$podman_usr_st" == "active" ]]; then
            _row "Podman"     "OK  socket active (user)${podman_ver:+  v${podman_ver}}${rl_str}"
        else
            _row "Podman"     "--  installed${podman_ver:+  v${podman_ver}}  socket inactive${rl_str}"
        fi
        # Distrobox: depends on Podman — flag if installed but Podman socket is down
        if command -v distrobox &>/dev/null && \
           [[ "$podman_sys_st" != "active" && "$podman_usr_st" != "active" ]]; then
            _row2 "!  Distrobox installed but Podman socket not active — containers won't start"
        fi
        # Image storage — warn only when critically large (detail in --storage-info)
        local podman_img_mb
        podman_img_mb=$(du -sm /var/lib/containers/storage/overlay 2>/dev/null | awk '{print $1}' || echo "")
        if [[ "$podman_img_mb" =~ ^[0-9]+$ ]] && (( podman_img_mb > 20480 )); then
            _row2 "!   ${podman_img_mb} MB in image storage — run: podman image prune"
            _rec "Podman image storage is ${podman_img_mb} MB — free space: podman image prune"
        fi
    fi

    # ── LXD / lxcfs ──────────────────────────────────────────────────────────
    if { findmnt -n /var/lib/lxd &>/dev/null || [[ -d /data/varlib/lxd ]]; }; then
        if systemctl is-active --quiet lxd.socket 2>/dev/null; then
            local lxd_count=""
            # Only call lxc list if LXD has been initialised (preseed/init already run).
            # An active socket on an uninitialised LXD will hang indefinitely.
            local lxd_initialised=0
            [[ -f /var/lib/lxd/server.crt || -f /var/snap/lxd/common/lxd/server.crt || \
               -d /var/lib/lxd/networks || -d /data/varlib/lxd/networks ]] && lxd_initialised=1
            if (( lxd_initialised )); then
                lxd_count=$(timeout 5 lxc list --format=csv 2>/dev/null | wc -l || echo "")
                _row "LXD"        "OK  lxd.socket active${lxd_count:+  (${lxd_count} container(s))}"
            else
                _row "LXD"        "--  lxd.socket active but LXD not yet initialised (run: lxd init)"
            fi
        else
            _row "LXD"        "!   @lxd data present but lxd.socket not active"
            _rec "LXD socket not active — run: systemctl enable --now lxd.socket  [auto]"
        fi
        # lxcfs: provides container-aware /proc stats — silent when working
        if command -v lxcfs &>/dev/null && systemctl is-enabled --quiet lxcfs 2>/dev/null; then
            if ! systemctl is-active --quiet lxcfs 2>/dev/null; then
                _row2 "!  lxcfs enabled but not running — containers see host stats"
                _rec "lxcfs not running — run: systemctl enable --now lxcfs  [auto]"
            fi
        fi
        # LXD storage — warn only when large (detail in --storage-info)
        local lxd_mb
        lxd_mb=$(du -sm /var/lib/lxd /data/varlib/lxd 2>/dev/null | awk '{s+=$1} END{print s}' || echo "")
        if [[ "$lxd_mb" =~ ^[0-9]+$ ]] && (( lxd_mb > 20480 )); then
            _row2 "!   ${lxd_mb} MB — review with: lxc storage info default"
            _rec "LXD storage is ${lxd_mb} MB — review: lxc storage info default"
        fi
    fi

    # ── Waydroid ─────────────────────────────────────────────────────────────
    if findmnt -n /var/lib/waydroid &>/dev/null; then
        local waydroid_st; waydroid_st=$(systemctl is-active waydroid-container 2>/dev/null || echo "inactive")
        # Storage size — Android images can be several GB
        local waydroid_mb
        waydroid_mb=$(du -sm /var/lib/waydroid 2>/dev/null | awk '{print $1}' || echo "")
        local wd_sz_str=""
        [[ "$waydroid_mb" =~ ^[0-9]+$ ]] && wd_sz_str="  (${waydroid_mb} MB)"
        if [[ "$waydroid_st" == "active" ]]; then
            _row "Waydroid"   "OK  Android container active${wd_sz_str}"
        else
            _row "Waydroid"   "!   @waydroid mounted but container service is ${waydroid_st}${wd_sz_str}"
            _rec "Waydroid container not running — run: systemctl enable --now waydroid-container  [auto]"
        fi
    fi

    # ── systemd-nspawn (systemd-machined) ─────────────────────────────────────
    # machinectl manages nspawn containers and VMs. Only check when machines dir
    # has content or machined is already running.
    if command -v machinectl &>/dev/null; then
        local machines_dir="/var/lib/machines"
        local has_machines=0
        { [[ -d "$machines_dir" ]] && [[ $(ls "$machines_dir" 2>/dev/null | wc -l) -gt 0 ]]; } \
            && has_machines=1
        systemctl is-active --quiet systemd-machined 2>/dev/null && has_machines=1
        if (( has_machines )); then
            local machined_st; machined_st=$(systemctl is-active systemd-machined 2>/dev/null || echo "inactive")
            local machine_count=""
            machine_count=$(timeout 5 machinectl list --no-legend 2>/dev/null | wc -l || echo "")
            if [[ "$machined_st" == "active" ]]; then
                _row "nspawn"     "OK  systemd-machined active${machine_count:+  (${machine_count} machine(s))}"
            else
                _row "nspawn"     "!   machines present but systemd-machined is ${machined_st}"
                _rec "systemd-machined not active — run: systemctl start systemd-machined  [auto]"
            fi
            # nspawn storage detail in --storage-info
        fi
    fi

    # ── Apptainer ────────────────────────────────────────────────────────────
    # Rootless HPC container runtime. No daemon — just needs userns support.
    if command -v apptainer &>/dev/null || command -v singularity &>/dev/null; then
        local apt_bin="apptainer"; command -v apptainer &>/dev/null || apt_bin="singularity"
        local apt_ver; apt_ver=$("$apt_bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        local userns_val; userns_val=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "1")
        if [[ "$userns_val" == "0" ]]; then
            _row "Apptainer"  "!!  installed but unprivileged_userns_clone=0 — rootless containers disabled"
            _rec "kernel.unprivileged_userns_clone must be 1 for rootless Apptainer"
        else
            _row "Apptainer"  "OK  ${apt_bin}${apt_ver:+  v${apt_ver}}  (rootless-capable)"
        fi
        # Apptainer cache detail in --storage-info
    fi
}


_section_firmware() {
    _head "Firmware"

    if ! command -v fwupdmgr &>/dev/null; then
        _row "fwupd"     "--  not available"
        return
    fi

    # fwupd-refresh.timer — must be active for automatic firmware update checks
    local refresh_timer; refresh_timer=$(systemctl is-active fwupd-refresh.timer 2>/dev/null || echo "inactive")
    if [[ "$refresh_timer" == "active" ]]; then
        _row "fwupd tmr"  "OK  fwupd-refresh.timer active"
    else
        _row "fwupd tmr"  "!!  fwupd-refresh.timer not active — firmware checks won't run automatically"
        _rec "fwupd-refresh.timer not active — run: systemctl enable --now fwupd-refresh.timer  [auto]"
    fi

    local fw_out; fw_out=$(fwupdmgr get-updates --offline 2>/dev/null || true)
    if echo "$fw_out" | grep -q 'GUID\|Version'; then
        local n; n=$(echo "$fw_out" | grep -c 'GUID' || echo "1")
        _row "Updates"   "!   ${n} update(s) available — run: fwupdmgr update"
        _rec "${n} firmware update(s) available — run: fwupdmgr update"
    else
        _row "Updates"   "OK  up to date (cached)"
    fi
}

_section_runtime_health() {
    _head "Runtime Health"

    # ── CPU load ──────────────────────────────────────────────────────────────
    local load1 ncores load_int
    load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "")
    ncores=$(nproc 2>/dev/null || echo "1")
    if [[ -n "$load1" && "$ncores" =~ ^[0-9]+$ ]]; then
        load_int=$(awk "BEGIN{printf \"%d\", $load1}" 2>/dev/null || echo "0")
        if (( load_int >= ncores * 4 )); then
            _row "CPU load"   "!!  ${load1}  (${ncores} cores) — critically high"
            _rec "CPU load average ${load1} on ${ncores} cores — check: ps aux --sort=-%cpu | head"
        elif (( load_int >= ncores * 2 )); then
            _row "CPU load"   "!   ${load1}  (${ncores} cores) — high"
        else
            _row "CPU load"   "OK  ${load1}  (${ncores} cores)"
        fi
    fi

    # ── Memory pressure ───────────────────────────────────────────────────────
    local mem_available_kb mem_total_kb
    mem_available_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
    mem_total_kb=$(    awk '/^MemTotal:/{print $2}'     /proc/meminfo 2>/dev/null || echo "0")
    if [[ "$mem_available_kb" =~ ^[0-9]+$ && "$mem_total_kb" =~ ^[0-9]+$ && "$mem_total_kb" -gt 0 ]]; then
        local mem_avail_mb=$(( mem_available_kb / 1024 ))
        local mem_total_mb=$(( mem_total_kb / 1024 ))
        local mem_pct=$(( mem_available_kb * 100 / mem_total_kb ))
        if (( mem_available_kb < 102400 )); then   # < 100 MB
            _row "Memory"     "!!  ${mem_avail_mb} MB available / ${mem_total_mb} MB total — critically low"
            _rec "Memory critically low (${mem_avail_mb} MB free) — consider closing applications or adding RAM"
        elif (( mem_available_kb < 307200 )); then  # < 300 MB
            _row "Memory"     "!   ${mem_avail_mb} MB available / ${mem_total_mb} MB total (${mem_pct}%)"
        else
            _row "Memory"     "OK  ${mem_avail_mb} MB available / ${mem_total_mb} MB total"
        fi
    fi

    # ── Journal persistence ───────────────────────────────────────────────────
    # On ShaniOS /var is a tmpfs — journal is volatile unless Storage=persistent
    # in journald.conf AND a persistent journal dir exists on /data or similar.
    # Without persistence, logs are lost on reboot which makes debugging hard.
    local journald_storage
    journald_storage=$(grep -rh '^[[:space:]]*Storage=' \
        /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ \
        2>/dev/null | tail -1 | sed 's/.*=//' | tr -d '[:space:]' || echo "")
    if findmnt -n -t tmpfs /var &>/dev/null; then
        # /var is tmpfs — journal is volatile unless explicitly redirected
        if [[ "$journald_storage" == "persistent" ]]; then
            # persistent set — check the backing dir actually exists
            local journal_dir
            for d in /data/journal /var/log/journal; do
                [[ -d "$d" ]] && journal_dir="$d" && break
            done
            if [[ -n "$journal_dir" ]]; then
                local journal_mb
                journal_mb=$(du -sm "$journal_dir" 2>/dev/null | awk '{print $1}' || echo "0")
                if [[ "$journal_mb" =~ ^[0-9]+$ ]] && (( journal_mb > 2048 )); then
                    _row "J. store"  "!   ${journal_mb} MB at ${journal_dir} — getting large"
                    _rec "Persistent journal is ${journal_mb} MB — vacuum: journalctl --vacuum-size=500M  [auto]"
                else
                    _row "J. store"  "OK  persistent (${journal_dir}, ${journal_mb} MB)"
                fi
            else
                _row "J. store"  "!   Storage=persistent but no journal dir found"
                _rec "journald Storage=persistent but no backing directory — create: mkdir -p /data/journal"
            fi
        else
            _row "J. store"  "--  volatile (/var is tmpfs) — logs lost on reboot"
        fi
    fi

    local running installed
    running=$(uname -r 2>/dev/null || echo "")
    installed=$(find /usr/lib/modules/ -maxdepth 1 -mindepth 1 -type d 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^/]*$' | sort -V | tail -1 || echo "")
    if [[ -n "$running" && -n "$installed" ]]; then
        if [[ "$running" == "$installed" ]]; then
            _row "Kernel"     "OK  ${running}"
        else
            _row "Kernel"     "!   running ${running}  /  installed ${installed}"
            _rec "Kernel mismatch: running ${running}, installed ${installed} — reboot"
        fi
    fi

    # ── Boot time ─────────────────────────────────────────────────────────────
    if command -v systemd-analyze &>/dev/null; then
        local bt bt_sec
        bt=$(systemd-analyze 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+s' | tail -1 || echo "")
        if [[ -n "$bt" ]]; then
            bt_sec=$(echo "$bt" | grep -oE '^[0-9]+' || echo "0")
            if (( bt_sec >= 30 )); then
                _row "Boot time"  "!   ${bt}  (slow — run: systemd-analyze blame)"
                # Inline top 3 slowest units — filter transient/sleep units
                # that appear in blame but are not boot-critical
                local _blame
                _blame=$(systemd-analyze blame 2>/dev/null \
                    | grep -vE "systemd-(suspend|hibernate|hybrid-sleep|sleep)\.service" \
                    | head -3 | sed 's/^ *//' || true)
                while IFS= read -r line; do
                    [[ -n "$line" ]] && _row2 "--  $line"
                done <<< "$_blame"
            else
                _row "Boot time"  "OK  ${bt}"
            fi
        fi
    fi

    # ── OOM kills ─────────────────────────────────────────────────────────────
    local oom
    oom=$(journalctl -k -b 0 --no-pager -q 2>/dev/null \
        | grep -c 'Out of memory\|oom_kill_process\|Killed process' || echo "0")
    if [[ "$oom" =~ ^[0-9]+$ ]] && (( oom > 0 )); then
        _row "OOM kills"  "!   ${oom} event(s) this boot"
        _rec "${oom} OOM kill(s) this boot — consider more RAM or swap"
    else
        _row "OOM kills"  "OK  none this boot"
    fi

    # ── /home usage per user ──────────────────────────────────────────────────
    if findmnt -n /home &>/dev/null; then
        local home_warn=() home_crit=() home_info=()
        for user_dir in /home/*/; do
            [[ -d "$user_dir" ]] || continue
            local uname; uname=$(basename "$user_dir")
            local used_mb
            used_mb=$(du -sm "$user_dir" 2>/dev/null | awk '{print $1}' || echo "")
            [[ "$used_mb" =~ ^[0-9]+$ ]] || continue
            if (( used_mb > 51200 )); then      # > 50 GB
                home_crit+=("${uname}:${used_mb}MB")
            elif (( used_mb > 20480 )); then    # > 20 GB
                home_warn+=("${uname}:${used_mb}MB")
            else
                home_info+=("${uname}:${used_mb}MB")
            fi
        done
        if [[ ${#home_crit[@]} -gt 0 ]]; then
            _row "Home usage" "!   large: $(_join "${home_crit[@]}")"
            _rec "Home directories using significant space ($(_join "${home_crit[@]}")) — review with: du -sh /home/*"
        elif [[ ${#home_warn[@]} -gt 0 ]]; then
            _row "Home usage" "--  $(_join "${home_warn[@]}")"
        fi
        # Always show all users' usage so nothing is invisible
        if [[ ${#home_info[@]} -gt 0 ]]; then
            local _info_str; _info_str=$(IFS=' '; echo "${home_info[*]}")
            _row2 "--  also: ${_info_str}"
        fi
    fi

    # ── Journal errors ────────────────────────────────────────────────────────
    local j_err j_crit
    j_err=$( journalctl -b 0 -p err  --no-pager -q 2>/dev/null | wc -l || echo "0")
    j_crit=$(journalctl -b 0 -p crit --no-pager -q 2>/dev/null | wc -l || echo "0")
    if [[ "$j_crit" =~ ^[0-9]+$ ]] && (( j_crit > 0 )); then
        _row "Journal"    "!!  ${j_err} error(s), ${j_crit} critical — journalctl -b 0 -p crit"
        _rec "${j_crit} critical journal message(s) this boot — run: journalctl -b 0 -p crit"
    elif [[ "$j_err" =~ ^[0-9]+$ ]] && (( j_err > 20 )); then
        _row "Journal"    "!   ${j_err} error(s) this boot"
    else
        _row "Journal"    "OK  ${j_err:-0} error(s) (normal range)"
    fi
}

security_report() {
    _recs_reset

    local _esp_mounted=0
    _esp_mount

    local booted; booted=$(_get_booted_subvol)
    local uki_booted_bad="0"
    local hibernate_stale="0"

    # Pre-compute hibernate offset staleness — same logic as system_info
    local swapfile; swapfile=$(_find_swapfile)
    if [[ -n "$swapfile" ]] && command -v btrfs &>/dev/null; then
        local a_off; a_off=$(_swapfile_offset "$swapfile")
        local c_off; c_off=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2 || echo "")
        [[ -n "$a_off" && -n "$c_off" && "$a_off" != "$c_off" ]] && hibernate_stale="1"
    fi

    local sb_active="no"
    [[ -d /sys/firmware/efi ]] && \
        local _sb_state_tmp; _sb_state_tmp=$(mokutil --sb-state 2>/dev/null || echo "")
        # Only treat as fully active if SB enabled AND shim validation not disabled
        if [[ "$_sb_state_tmp" == *"SecureBoot enabled"* ]] && \
           ! echo "$_sb_state_tmp" | grep -q "Secure Boot validation is disabled"; then
            sb_active="yes"
        fi

    echo ""
    printf "  ${_C_BOLD}┌──────────────────────────────────────────────┐${_C_RESET}\n"
    printf "  ${_C_BOLD}│  %-44s│${_C_RESET}\n" "ShaniOS Security Report"
    printf "  ${_C_BOLD}│  ${_C_DIM}%-44s${_C_BOLD}│${_C_RESET}\n" "$(date '+%Y-%m-%d %H:%M')"
    printf "  ${_C_BOLD}└──────────────────────────────────────────────┘${_C_RESET}\n"

    _section_secureboot         "$booted" uki_booted_bad "$hibernate_stale"
    _section_kernel_security    "$sb_active"
    _section_encryption
    _section_tpm2
    _section_security_services
    _section_users
    _section_groups

    echo ""
    if [[ ${#_RECS[@]} -eq 0 ]]; then
        printf "  ${_C_GREEN}${_C_BOLD}${_SYM_OK}  No security issues found${_C_RESET}\n"
    else
        printf "  ${_C_BOLD}${_C_YELLOW}Security Recommendations (${#_RECS[@]})${_C_RESET}\n"
        printf "  ${_C_DIM}%.54s${_C_RESET}\n" "──────────────────────────────────────────────────────"
        local i=1
        for rec in "${_RECS[@]}"; do
            local display="${rec/\[auto\]/${_C_CYAN}[auto]${_C_RESET}}"
            printf "    ${_C_BOLD}%2d.${_C_RESET}  %b\n" "$i" "$display"
            i=$(( i + 1 ))
        done
        echo ""
        printf "  ${_C_DIM}Items marked ${_C_CYAN}[auto]${_C_DIM} can be fixed by: shani-health --fix${_C_RESET}\n"
    fi
    echo ""

    _esp_umount
}

system_info() {
    _recs_reset

    local _esp_mounted=0
    _esp_mount

    local booted; booted=$(_get_booted_subvol)
    local uki_booted_bad="0"
    local hibernate_stale="0"

    # Pre-check hibernate offset — result shared between _section_secureboot and _section_disk
    local swapfile; swapfile=$(_find_swapfile)
    if [[ -n "$swapfile" ]] && command -v btrfs &>/dev/null; then
        local a_off; a_off=$(_swapfile_offset "$swapfile")
        local c_off; c_off=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2 || echo "")
        [[ -n "$a_off" && -n "$c_off" && "$a_off" != "$c_off" ]] && hibernate_stale="1"
    fi

    local sb_active="no"
    [[ -d /sys/firmware/efi ]] && \
        local _sb_state_tmp; _sb_state_tmp=$(mokutil --sb-state 2>/dev/null || echo "")
        # Only treat as fully active if SB enabled AND shim validation not disabled
        if [[ "$_sb_state_tmp" == *"SecureBoot enabled"* ]] && \
           ! echo "$_sb_state_tmp" | grep -q "Secure Boot validation is disabled"; then
            sb_active="yes"
        fi

    echo ""
    printf "  ${_C_BOLD}┌──────────────────────────────────────────────┐${_C_RESET}\n"
    printf "  ${_C_BOLD}│  %-44s│${_C_RESET}\n" "ShaniOS System Status"
    printf "  ${_C_BOLD}│  ${_C_DIM}%-44s${_C_BOLD}│${_C_RESET}\n" "$(date '+%Y-%m-%d %H:%M')"
    printf "  ${_C_BOLD}└──────────────────────────────────────────────┘${_C_RESET}\n"

    # ── Identity ──────────────────────────────────────────────────────────────
    _section_os_slots           "$booted"

    # ── Boot ──────────────────────────────────────────────────────────────────
    _section_boot_health
    _section_boot_entries

    # ── System State ──────────────────────────────────────────────────────────
    _section_deployment
    _section_data_state
    _section_immutability

    # ── Security ──────────────────────────────────────────────────────────────
    _section_secureboot         "$booted" uki_booted_bad "$hibernate_stale"
    _section_kernel_security    "$sb_active"
    _section_encryption
    _section_tpm2
    _section_security_services

    # ── Access Control ────────────────────────────────────────────────────────
    _section_users
    _section_groups

    # ── Hardware ──────────────────────────────────────────────────────────────
    _section_hardware
    _section_disk               "$booted" hibernate_stale "$uki_booted_bad"
    _section_battery
    _section_storage
    _section_firmware

    # ── Services ──────────────────────────────────────────────────────────────
    _section_system_services
    _section_network
    _section_audio_display
    _section_units
    _section_package_managers
    _section_containers
    _section_virtualization

    # ── Runtime ───────────────────────────────────────────────────────────────
    _section_runtime_health

    # Summary
    echo ""
    if [[ ${#_RECS[@]} -eq 0 ]]; then
        printf "  ${_C_GREEN}${_C_BOLD}${_SYM_OK}  All checks passed — no issues found${_C_RESET}\n"
    else
        printf "  ${_C_BOLD}${_C_YELLOW}Recommendations (${#_RECS[@]})${_C_RESET}\n"
        printf "  ${_C_DIM}%.54s${_C_RESET}\n" "──────────────────────────────────────────────────────"
        local i=1
        for rec in "${_RECS[@]}"; do
            # Highlight [auto] tag in cyan
            local display="${rec/\[auto\]/${_C_CYAN}[auto]${_C_RESET}}"
            printf "    ${_C_BOLD}%2d.${_C_RESET}  %b\n" "$i" "$display"
            i=$(( i + 1 ))
        done
        echo ""
        printf "  ${_C_DIM}Items marked ${_C_CYAN}[auto]${_C_DIM} can be fixed by: shani-health --fix${_C_RESET}\n"
    fi
    echo ""

    _esp_umount
}

###############################################################################
### fix                                                             ###
###############################################################################

fix() {
    _log_section "Auto-Fix"

    # Resolve booted slot once — reused by all UKI regeneration steps below
    local _fix_booted; _fix_booted=$(_get_booted_subvol)

    # Internal helper: run a fix, updating counters
    # Each _fix_* sub-function declares its own local fixed/failed and calls _apply_fix.
    _apply_fix() {
        local desc="$1"; shift
        _log "Fixing: ${desc}..."
        if "$@" 2>/dev/null; then
            _log_ok "${desc}"
            fixed=$(( fixed + 1 ))
        else
            _log_warn "${desc} — FAILED"
            failed=$(( failed + 1 ))
        fi
    }

    _fix_services
    _fix_security
    _fix_boot
    _fix_data
    _fix_users

    echo ""
    _log "Run 'shani-health' to verify fixes"
}

_fix_services() {
    local fixed=0 failed=0
    _log_section "Services & Daemons"
    # CUPS socket
    if getent group cups &>/dev/null; then
        if { systemctl is-enabled cups.service &>/dev/null 2>&1 || \
             systemctl is-enabled cups.socket  &>/dev/null 2>&1; } && \
           ! systemctl is-active --quiet cups.socket 2>/dev/null; then
            _apply_fix "Enable cups.socket"  systemctl enable --now cups.socket
        fi
    fi

    # Bluetooth
    if [[ -d /sys/class/bluetooth ]] && \
       systemctl is-enabled bluetooth.service &>/dev/null 2>&1 && \
       ! systemctl is-active --quiet bluetooth.service 2>/dev/null; then
        _apply_fix "Start bluetooth.service"  systemctl start bluetooth.service
    fi

    # Avahi mDNS
    if command -v avahi-daemon &>/dev/null && \
       systemctl is-enabled --quiet avahi-daemon 2>/dev/null && \
       ! systemctl is-active --quiet avahi-daemon 2>/dev/null; then
        _apply_fix "Start avahi-daemon"  systemctl start avahi-daemon
    fi

    # switcheroo-control (only when multiple GPUs present)
    if command -v switcherooctl &>/dev/null; then
        local _gpu_n; _gpu_n=$(switcherooctl list 2>/dev/null | grep -c '^GPU' || echo "0")
        if [[ "$_gpu_n" =~ ^[0-9]+$ ]] && (( _gpu_n >= 2 )) && \
           ! systemctl is-active --quiet switcheroo-control 2>/dev/null; then
            _apply_fix "Enable switcheroo-control"  systemctl enable --now switcheroo-control
        fi
    fi

    # lxcfs (only when enabled but not running)
    if command -v lxcfs &>/dev/null && \
       systemctl is-enabled --quiet lxcfs 2>/dev/null && \
       ! systemctl is-active --quiet lxcfs 2>/dev/null; then
        _apply_fix "Enable lxcfs"  systemctl enable --now lxcfs
    fi

    # LXD socket
    if { findmnt -n /var/lib/lxd &>/dev/null || [[ -d /data/varlib/lxd ]]; } && \
       ! systemctl is-active --quiet lxd.socket 2>/dev/null; then
        _apply_fix "Enable lxd.socket"  systemctl enable --now lxd.socket
    fi

    # ananicy-cpp (only when enabled but not running)
    if { command -v ananicy-cpp &>/dev/null || systemctl cat ananicy-cpp &>/dev/null 2>&1; } && \
       systemctl is-enabled --quiet ananicy-cpp 2>/dev/null && \
       ! systemctl is-active --quiet ananicy-cpp 2>/dev/null; then
        _apply_fix "Enable ananicy-cpp"  systemctl enable --now ananicy-cpp
    fi

    # Display manager
    local _dm_profile; _dm_profile=$(cat /etc/shani-profile 2>/dev/null | tr -d '[:space:]' || echo "")
    local _dm_svc=""
    [[ "$_dm_profile" == "plasma" ]] && _dm_svc="plasmalogin"
    [[ "$_dm_profile" == "gnome"  ]] && _dm_svc="gdm"
    if [[ -n "$_dm_svc" ]] && ! systemctl is-active --quiet "$_dm_svc" 2>/dev/null; then
        _apply_fix "Enable ${_dm_svc}"  systemctl enable --now "$_dm_svc"
    fi

    # auditd
    if command -v auditctl &>/dev/null && \
       systemctl is-enabled --quiet auditd 2>/dev/null && \
       ! systemctl is-active --quiet auditd 2>/dev/null; then
        _apply_fix "Start auditd"  systemctl start auditd
    fi

    # Power management — enable ppd, stop conflicting daemons if found
    local _ppd_active=0 _tlp_active=0 _acpufreq_active=0
    systemctl is-active --quiet power-profiles-daemon 2>/dev/null && _ppd_active=1
    systemctl is-active --quiet tlp                   2>/dev/null && _tlp_active=1
    systemctl is-active --quiet auto-cpufreq          2>/dev/null && _acpufreq_active=1
    if command -v power-profiles-daemon &>/dev/null && (( ! _ppd_active )); then
        _apply_fix "Enable power-profiles-daemon"  systemctl enable --now power-profiles-daemon
    fi
    if (( _ppd_active && _tlp_active )); then
        _apply_fix "Stop conflicting tlp"  systemctl disable --now tlp
    fi
    if (( _ppd_active && _acpufreq_active )); then
        _apply_fix "Stop conflicting auto-cpufreq"  systemctl disable --now auto-cpufreq
    fi

    echo ""
    (( fixed + failed > 0 )) && _log "  fixed: ${fixed}  failed: ${failed}"
}

_fix_security() {
    local fixed=0 failed=0
    _log_section "Security"
    # Stale boot failure marker — clear it if current boot is healthy
    if [[ -f "$DATA_BOOT_FAIL" ]]; then
        local _bfail_current; _bfail_current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
        local _bfail_slot; _bfail_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "?")
        if [[ "$_fix_booted" == "$_bfail_current" || "$_bfail_slot" == "$_fix_booted" ]]; then
            _log "Clearing stale boot_failure marker for @${_bfail_slot} (currently booted @${_fix_booted} successfully)..."
            if rm -f "$DATA_BOOT_FAIL" "$DATA_BOOT_FAIL_ACKED" 2>/dev/null; then
                _log_ok "Stale boot_failure marker cleared"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "Failed to clear boot_failure marker"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # check-boot-failure.timer — reset and restart if failed
    if systemctl is-failed --quiet check-boot-failure.timer 2>/dev/null; then
        _apply_fix "Reset check-boot-failure.timer" \
            bash -c "systemctl reset-failed check-boot-failure.timer && systemctl start check-boot-failure.timer"
    fi

    # Lock root account if it has a password
    local _root_st; _root_st=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "")
    if [[ "$_root_st" == "P" ]]; then
        _apply_fix "Lock root account"  passwd -l root
    fi
    declare -A _FIX_STATIC_GIDS=([sys]=1 [lp]=1 [kvm]=1 [video]=1 [scanner]=1 [input]=1 [cups]=1)
    local _fix_dynamic=(realtime nixbld lxd libvirt)
    for grp in "${!_FIX_STATIC_GIDS[@]}"; do
        getent group "$grp" &>/dev/null || \
            _apply_fix "Create group ${grp}"  groupadd -r "$grp"
    done
    for grp in "${_fix_dynamic[@]}"; do
        getent group "$grp" &>/dev/null || \
            _apply_fix "Create group ${grp}"  groupadd -r "$grp"
    done

    # AppArmor
    command -v aa-status &>/dev/null && ! aa-status --enabled >/dev/null 2>&1 && \
        _apply_fix "Enable AppArmor"  systemctl enable --now apparmor

    # Polkit
    if systemctl cat polkit &>/dev/null 2>&1 && \
       ! systemctl is-active --quiet polkit 2>/dev/null; then
        _apply_fix "Enable polkit"  systemctl enable --now polkit
    fi

    # Firewall
    command -v firewall-cmd &>/dev/null && ! systemctl is-active --quiet firewalld 2>/dev/null && \
        _apply_fix "Enable firewalld"  systemctl enable --now firewalld

    # fail2ban
    command -v fail2ban-client &>/dev/null && ! systemctl is-active --quiet fail2ban 2>/dev/null && \
        _apply_fix "Enable fail2ban"  systemctl enable --now fail2ban

    # SSH root login
    if [[ -f /etc/ssh/sshd_config ]]; then
        local ssh_root
        ssh_root=$(grep -rh '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ \
            2>/dev/null | tail -1 | awk '{print $2}' || echo "")
        if [[ "$ssh_root" == "yes" ]]; then
            if sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null \
                && systemctl reload sshd 2>/dev/null; then
                _log_ok "SSH root login disabled"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "Failed to disable SSH root login"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    echo ""
    (( fixed + failed > 0 )) && _log "  fixed: ${fixed}  failed: ${failed}"
}

_fix_boot() {
    local fixed=0 failed=0
    _log_section "Boot & UKI"
    # systemd-boot editor + orphaned entries
    local _esp_mounted=0
    _esp_mount
    if mountpoint -q "$ESP" 2>/dev/null; then
        local loader_conf="$ESP/loader/loader.conf"
        local editor_val
        editor_val=$(grep '^editor' "$loader_conf" 2>/dev/null | awk '{print $2}' || echo "not set")
        if [[ "$editor_val" != "0" ]]; then
            if grep -q '^editor' "$loader_conf" 2>/dev/null; then
                sed -i 's/^editor .*/editor 0/' "$loader_conf"
            else
                echo "editor 0" >> "$loader_conf"
            fi
            _log_ok "systemd-boot editor disabled"
            fixed=$(( fixed + 1 ))
        fi

        # Fix default= slot mismatch — rewrite using same glob logic as finalize_boot_entries:
        #   tries path  → shanios-<slot>+*.conf
        #   no-tries    → shanios-<slot>.conf  (rollback/restore — plain .conf, no boot counting)
        local _fix_current_slot
        _fix_current_slot=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
        if [[ -n "$_fix_current_slot" ]]; then
            local _def_entry
            _def_entry=$(grep '^default' "$loader_conf" 2>/dev/null | awk '{print $2}' || echo "")
            if [[ -n "$_def_entry" ]] && \
               ! echo "$_def_entry" | grep -qiE "(^|[-_])${_fix_current_slot}([-_+.]|$)"; then
                # Determine correct glob: use tries if a +N-N entry exists for this slot,
                # else use the plain filename (rollback/no-tries path)
                local _new_default
                if ls "$ESP/loader/entries/${OS_NAME}-${_fix_current_slot}"+*.conf \
                        &>/dev/null 2>&1; then
                    _new_default="${OS_NAME}-${_fix_current_slot}+*.conf"
                else
                    _new_default="${OS_NAME}-${_fix_current_slot}.conf"
                fi
                if grep -q '^default' "$loader_conf" 2>/dev/null; then
                    grep -v "^default " "$loader_conf" > "${loader_conf}.tmp" || true
                    echo "default ${_new_default}" >> "${loader_conf}.tmp"
                    mv "${loader_conf}.tmp" "$loader_conf"
                else
                    echo "default ${_new_default}" >> "$loader_conf"
                fi
                _log_ok "loader.conf default= updated to ${_new_default}"
                fixed=$(( fixed + 1 ))
            fi
        fi

        for slot in blue green; do
            local plain="$ESP/loader/entries/${OS_NAME}-${slot}.conf"
            local tries; tries=$(ls "$ESP/loader/entries/${OS_NAME}-${slot}"+*.conf \
                2>/dev/null | head -1 || echo "")
            if [[ -f "$plain" && -n "$tries" ]]; then
                rm -f "$plain" 2>/dev/null && \
                    { _log_ok "Removed orphaned entry: $(basename "$plain")"; fixed=$(( fixed + 1 )); } || \
                    { _log_warn "Failed to remove: $(basename "$plain")";     failed=$(( failed + 1 )); }
            fi
        done
    fi
    _esp_umount

    # rtkit-daemon
    if command -v pipewire &>/dev/null || command -v pulseaudio &>/dev/null; then
        [[ "$(systemctl is-active rtkit-daemon 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable rtkit-daemon"  systemctl enable --now rtkit-daemon
    fi

    # Btrfs maintenance timers + fwupd refresh + flatpak update timer
    for timer in btrfs-scrub.timer btrfs-balance.timer btrfs-defrag.timer btrfs-trim.timer \
                 fwupd-refresh.timer flatpak-update-system.timer; do
        [[ "$(systemctl is-active "$timer" 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable ${timer}"  systemctl enable --now "$timer"
    done

    # Nix daemon socket — only if @nix subvolume is mounted
    if findmnt -n /nix &>/dev/null; then
        [[ "$(systemctl is-active nix-daemon.socket 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable nix-daemon.socket"  systemctl enable --now nix-daemon.socket
    fi

    # Waydroid container — only if @waydroid subvolume is mounted
    if findmnt -n /var/lib/waydroid &>/dev/null; then
        [[ "$(systemctl is-active waydroid-container 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable waydroid-container"  systemctl enable --now waydroid-container
    fi

    # systemd-machined — only when machines dir has content
    if command -v machinectl &>/dev/null; then
        local _machines_dir="/var/lib/machines"
        if [[ -d "$_machines_dir" ]] && [[ $(ls "$_machines_dir" 2>/dev/null | wc -l) -gt 0 ]]; then
            [[ "$(systemctl is-active systemd-machined 2>/dev/null)" != "active" ]] && \
                _apply_fix "Start systemd-machined"  systemctl start systemd-machined
        fi
    fi

    # snapd — only if @snapd subvolume is mounted
    if findmnt -n /var/lib/snapd &>/dev/null; then
        [[ "$(systemctl is-active snapd.socket 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable snapd.socket"  systemctl enable --now snapd.socket
        [[ "$(systemctl is-active snapd.apparmor.service 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable snapd.apparmor"  systemctl enable --now snapd.apparmor.service
        # Snap pending updates
        if command -v snap &>/dev/null && \
           [[ "$(systemctl is-active snapd.socket 2>/dev/null)" == "active" ]]; then
            local _snap_upd
            _snap_upd=$(timeout 10 snap refresh --list 2>/dev/null | tail -n +2 | wc -l || echo "0")
            if [[ "$_snap_upd" =~ ^[0-9]+$ ]] && (( _snap_upd > 0 )); then
                _apply_fix "Refresh ${_snap_upd} snap(s)"  snap refresh
            fi
        fi
    fi

    # shani-update.timer — enable as the calling user
    if ! _sysd_user is-active --quiet shani-update.timer 2>/dev/null && \
       _sysd_user is-enabled --quiet shani-update.timer 2>/dev/null; then
        _log "Enabling shani-update.timer for ${_CALLER_USER}..."
        if _sysd_user enable --now shani-update.timer 2>/dev/null; then
            _log_ok "shani-update.timer enabled"
            fixed=$(( fixed + 1 ))
        else
            _log_warn "shani-update.timer enable failed"
            failed=$(( failed + 1 ))
        fi
    fi

    # bees
    local bees_uuid; bees_uuid=$(_get_bees_uuid)
    if [[ -n "$bees_uuid" ]]; then
        local bees_unit="beesd@${bees_uuid}"
        if [[ "$(systemctl is-active "$bees_unit" 2>/dev/null)" != "active" ]]; then
            if [[ ! -f "/etc/bees/${bees_uuid}.conf" ]]; then
                _log_warn "bees not configured — run beesd-setup.service first"
                failed=$(( failed + 1 ))
            else
                _apply_fix "Enable ${bees_unit}"  systemctl enable --now "$bees_unit"
            fi
        fi
    fi

    # GPG signing key — import from local file (no network needed)
    if ! gpg --batch --list-keys "$GPG_SIGNING_KEY" &>/dev/null 2>&1; then
        if [[ -f "$GPG_SIGNING_KEY_FILE" ]]; then
            _log "Importing ShaniOS signing key from ${GPG_SIGNING_KEY_FILE}..."
            if gpg --batch --import "$GPG_SIGNING_KEY_FILE" 2>/dev/null; then
                _log_ok "GPG signing key imported"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "GPG key import failed — check: gpg --import ${GPG_SIGNING_KEY_FILE}"
                failed=$(( failed + 1 ))
            fi
        else
            _log "Fetching ShaniOS signing key from keyserver (local file absent)..."
            if gpg --batch --keyserver keys.openpgp.org --recv-keys "$GPG_SIGNING_KEY" 2>/dev/null; then
                _log_ok "GPG signing key imported from keyserver"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "GPG key fetch failed — try manually: gpg --keyserver keys.openpgp.org --recv-keys ${GPG_SIGNING_KEY}"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # MOK enroll — skip entirely if shim validation is already disabled
    local _mok_der="/etc/secureboot/keys/MOK.der"
    if [[ -f "$_mok_der" ]] && command -v mokutil &>/dev/null && \
       ! mokutil --sb-state 2>/dev/null | grep -q "Secure Boot validation is disabled"; then
        local _mok_enrolled_count
        _mok_enrolled_count=$(mokutil --list-enrolled 2>/dev/null | grep -c 'SHA1 Fingerprint' || echo "0")
        local _local_fp
        _local_fp=$(openssl x509 -in "$_mok_der" -inform DER -noout -fingerprint -sha1 \
            2>/dev/null | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' || echo "")
        local _enrolled_match=0
        if [[ -n "$_local_fp" ]]; then
            mokutil --list-enrolled 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]' \
                | grep -q "$_local_fp" && _enrolled_match=1
        fi
        # Check if already pending — if so, nothing to do but reboot
        local _mok_pending=0
        if [[ -n "$_local_fp" ]]; then
            mokutil --list-new 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]' \
                | grep -q "$_local_fp" && _mok_pending=1
        fi
        if (( _mok_pending )); then
            _log "MOK enrollment already pending — reboot and confirm in MokManager"
        elif (( _mok_enrolled_count == 0 )) || (( ! _enrolled_match )); then
            if [[ "$_fix_booted" != "unknown" && -x "$GENEFI_BIN" ]]; then
                _log "MOK key not enrolled or stale — running gen-efi enroll-mok..."
                if "$GENEFI_BIN" enroll-mok 2>&1; then
                    _log_ok "gen-efi enroll-mok succeeded — reboot and confirm MOK enrollment in MokManager"
                    fixed=$(( fixed + 1 ))
                else
                    _log_warn "gen-efi enroll-mok failed — check manually"
                    failed=$(( failed + 1 ))
                fi
            else
                _log_warn "MOK not enrolled — run: gen-efi enroll-mok"
            fi
        fi
    fi

    # TPM2 — requires user interaction (cannot auto-enroll without passphrase/keyfile)
    if [[ -e "/dev/mapper/${ROOTLABEL}" ]] && [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
        local underlying
        underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
            | sed -n 's/^ *device: //p' || true)
        if [[ -n "$underlying" ]] && \
            ! systemd-cryptenroll "$underlying" 2>/dev/null | grep -q tpm2; then
            _log_warn "TPM2 not enrolled — requires user interaction: gen-efi enroll-tpm2"
        fi
    fi

    # lsm= kernel cmdline — regenerate UKI if the parameter is wrong or missing
    local expected_lsm_param="landlock,lockdown,yama,integrity,apparmor,bpf"
    local actual_lsm_param; actual_lsm_param=$(grep -o 'lsm=[^ ]*' /proc/cmdline 2>/dev/null \
        | cut -d= -f2 || echo "")
    if [[ "$actual_lsm_param" != "$expected_lsm_param" && -x "$GENEFI_BIN" ]]; then
        if [[ "$_fix_booted" != "unknown" ]]; then
            _log "lsm= cmdline incorrect — regenerating UKI for @${_fix_booted}..."
            if "$GENEFI_BIN" configure "$_fix_booted" 2>&1; then
                _log_ok "UKI regenerated for @${_fix_booted} — reboot to apply correct lsm="
                fixed=$(( fixed + 1 ))
            else
                _log_warn "UKI regeneration failed — lsm= param still incorrect"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # Hibernate resume_offset — regenerate booted slot UKI
    local swapfile; swapfile=$(_find_swapfile)
    if [[ -n "$swapfile" ]] && command -v btrfs &>/dev/null; then
        local actual_off; actual_off=$(_swapfile_offset "$swapfile")
        local cmdline_off
        cmdline_off=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2 || echo "")
        if [[ -n "$actual_off" && -n "$cmdline_off" && "$actual_off" != "$cmdline_off" ]]; then
            if [[ "$_fix_booted" != "unknown" && -x "$GENEFI_BIN" ]]; then
                _log "Regenerating UKI for @${_fix_booted} (resume_offset ${cmdline_off} -> ${actual_off})..."
                if "$GENEFI_BIN" configure "$_fix_booted" 2>&1; then
                    _log_ok "UKI regenerated for @${_fix_booted}"
                    fixed=$(( fixed + 1 ))
                else
                    _log_warn "UKI regeneration failed"
                    failed=$(( failed + 1 ))
                fi
            fi
        fi
    fi

    echo ""
    (( fixed + failed > 0 )) && _log "  fixed: ${fixed}  failed: ${failed}"
}

_fix_data() {
    local fixed=0 failed=0
    _log_section "Data & Filesystem"
    # systemd-timesyncd + NTP + RTC sync
    if command -v timedatectl &>/dev/null; then
        local td ntp_a ntp_s tsync_a _ntp_fixed=0
        td=$(timedatectl show 2>/dev/null || true)
        ntp_a=$(  echo "$td" | awk -F= '/^NTP=/{print $2}'             | tr -d '[:space:]')
        ntp_s=$(  echo "$td" | awk -F= '/^NTPSynchronized=/{print $2}' | tr -d '[:space:]')
        tsync_a=$(systemctl is-active systemd-timesyncd 2>/dev/null || echo "inactive")

        if [[ "$tsync_a" != "active" ]]; then
            _apply_fix "Enable systemd-timesyncd"  systemctl enable --now systemd-timesyncd
            _ntp_fixed=1
        fi
        if [[ "$ntp_a" != "yes" ]]; then
            if timedatectl set-ntp true 2>/dev/null; then
                _log_ok "NTP enabled"
                (( _ntp_fixed )) || fixed=$(( fixed + 1 ))
            else
                _log_warn "timedatectl set-ntp true failed"
                failed=$(( failed + 1 ))
            fi
        fi
        if [[ "$ntp_s" == "yes" ]] && command -v hwclock &>/dev/null; then
            hwclock --systohc 2>/dev/null && _log_ok "RTC synced (hwclock --systohc)" \
                || _log_warn "hwclock --systohc failed"
        fi
    fi

    # /data directory structure — create missing dirs (including downloads)
    for _d in /data/varlib /data/varspool /data/overlay/etc/upper /data/overlay/etc/work /data/downloads; do
        if [[ ! -d "$_d" ]]; then
            if mkdir -p "$_d" 2>/dev/null; then
                _log_ok "Created ${_d}"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "Failed to create ${_d}"
                failed=$(( failed + 1 ))
            fi
        fi
    done

    # MOK.key permissions — must be 0600
    local _mok_key="/etc/secureboot/keys/MOK.key"
    if [[ -f "$_mok_key" ]]; then
        local _mok_mode; _mok_mode=$(stat -c '%a' "$_mok_key" 2>/dev/null || echo "")
        if [[ -n "$_mok_mode" && "$_mok_mode" != "600" ]]; then
            if chmod 600 "$_mok_key" 2>/dev/null; then
                _log_ok "MOK.key permissions fixed (${_mok_mode} → 600)"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "Failed to chmod MOK.key"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # Btrfs qgroup inconsistency — rescan to fix phantom ENOSPC
    local _qout; _qout=$(btrfs qgroup show / 2>&1 || true)
    if ! echo "$_qout" | grep -q 'ERROR\|quota system is not enabled'; then
        if echo "$_qout" | grep -qi 'inconsistent\|stale'; then
            _log "Running btrfs quota rescan to fix qgroup inconsistency..."
            if btrfs quota rescan / 2>/dev/null; then
                _log_ok "Btrfs qgroup rescan started"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "btrfs quota rescan failed"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # shanios-tmpfiles-data.service — restart if failed
    local _tmpfiles_res
    _tmpfiles_res=$(systemctl show shanios-tmpfiles-data.service \
        --property=Result --value 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ "$_tmpfiles_res" == "exit-code" || "$_tmpfiles_res" == "core-dump" || "$_tmpfiles_res" == "signal" ]]; then
        _apply_fix "Restart shanios-tmpfiles-data.service" \
            systemctl restart shanios-tmpfiles-data.service
    fi

    # Persistent journal size — vacuum if over 2 GB
    local _journal_dir=""
    for _jd in /data/journal /var/log/journal; do
        [[ -d "$_jd" ]] && _journal_dir="$_jd" && break
    done
    if [[ -n "$_journal_dir" ]]; then
        local _jmb; _jmb=$(du -sm "$_journal_dir" 2>/dev/null | awk '{print $1}' || echo "0")
        if [[ "$_jmb" =~ ^[0-9]+$ ]] && (( _jmb > 2048 )); then
            _log "Vacuuming journal (${_jmb} MB → 500 MB cap)..."
            if journalctl --vacuum-size=500M 2>/dev/null; then
                _log_ok "Journal vacuumed"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "journalctl --vacuum-size failed"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # Keymap UKI mismatch — regenerate booted slot UKI
    local _vconsole_km=""
    [[ -f /etc/vconsole.conf ]] && \
        _vconsole_km=$(grep -E '^KEYMAP=' /etc/vconsole.conf 2>/dev/null \
            | cut -d= -f2 | tr -d '"'"'" | tr -cd 'A-Za-z0-9._-' || echo "")
    local _cmdline_km
    _cmdline_km=$(grep -o 'rd.vconsole.keymap=[^ ]*' /proc/cmdline 2>/dev/null \
        | cut -d= -f2 || echo "")
    if [[ -n "$_vconsole_km" && -n "$_cmdline_km" && "$_vconsole_km" != "$_cmdline_km" ]]; then
        if [[ "$_fix_booted" != "unknown" && -x "$GENEFI_BIN" ]]; then
            _log "Keymap mismatch (UKI: ${_cmdline_km}, vconsole: ${_vconsole_km}) — regenerating UKI for @${_fix_booted}..."
            if "$GENEFI_BIN" configure "$_fix_booted" 2>&1; then
                _log_ok "UKI regenerated for @${_fix_booted} with keymap ${_vconsole_km}"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "UKI regeneration failed"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    echo ""
    (( fixed + failed > 0 )) && _log "  fixed: ${fixed}  failed: ${failed}"
}

_fix_users() {
    local fixed=0 failed=0
    _log_section "Users & Setup"
    # user-setup-needed — run binary directly then remove marker
    if [[ -f /data/user-setup-needed ]]; then
        if [[ ! -x "$USER_SETUP_BIN" ]]; then
            _log_warn "shani-user-setup binary not found at ${USER_SETUP_BIN} — cannot run setup"
            failed=$(( failed + 1 ))
        else
            _log "Running ${USER_SETUP_BIN} to provision users..."
            if "$USER_SETUP_BIN"; then
                _log_ok "shani-user-setup completed"
                rm -f /data/user-setup-needed && \
                    { _log_ok "user-setup-needed marker removed"; fixed=$(( fixed + 1 )); } || \
                    { _log_warn "Could not remove marker — remove manually: rm /data/user-setup-needed"; failed=$(( failed + 1 )); }
            else
                _log_warn "shani-user-setup failed — check: journalctl -t shani-user-setup"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    echo ""
    (( fixed + failed > 0 )) && _log "  fixed: ${fixed}  failed: ${failed}"
}

###############################################################################
### clear_boot_failure — remove stale boot_failure marker                   ###
###############################################################################

clear_boot_failure() {
    local booted; booted=$(_get_booted_subvol)
    local current; current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")

    if [[ ! -f "$DATA_BOOT_FAIL" ]]; then
        _log "No boot_failure marker present — nothing to clear."
        return 0
    fi

    local failed_slot; failed_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "?")

    # Allow clearing in two safe cases:
    #   1. booted == current-slot  — normal healthy boot, failure is for the other slot
    #   2. failed_slot == booted   — the marker is for the slot we're successfully running now (stale)
    # In any other case the system is in genuine fallback and --rollback is required first.
    if [[ "$booted" != "$current" && "$failed_slot" != "$booted" ]]; then
        _die "System is in fallback mode (booted @${booted}, current @${current}) — use 'shani-deploy --rollback' instead"
    fi

    _log "Clearing stale boot_failure marker for @${failed_slot} (currently booted @${booted} successfully)..."
    rm -f "$DATA_BOOT_FAIL" "$DATA_BOOT_FAIL_ACKED"
    _log_ok "boot_failure marker cleared."
    if [[ "$booted" != "$current" ]]; then
        _log "Note: system is still in fallback mode — run: shani-deploy --rollback to fully repair @${current}"
    fi
}



verify_system() {
    _log_section "System Integrity Verification"
    local errors=0

    # UKI signatures
    echo ""
    _log "Checking UKI signatures..."
    local mok_crt="/etc/secureboot/keys/MOK.crt"
    local _esp_mounted=0
    _esp_mount

    if [[ ! -f "$mok_crt" ]]; then
        _log_warn "MOK cert not found at ${mok_crt} — skipping UKI verification"
    else
        for slot in blue green; do
            local uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${slot}.efi"
            if [[ ! -f "$uki" ]]; then
                _log_warn "UKI missing: ${uki}"; errors=$(( errors + 1 ))
            elif sbverify --cert "$mok_crt" "$uki" &>/dev/null 2>&1; then
                _log_ok "UKI valid:   @${slot}"
            else
                _log_err "UKI INVALID: @${slot}"
                errors=$(( errors + 1 ))
            fi
        done
    fi
    _esp_umount

    # Btrfs data integrity
    echo ""
    _log "Checking Btrfs data integrity (scrub both slots)..."
    local mnt_tmp; mnt_tmp=$(mktemp -d /run/shanios-verify.XXXXXX)
    if ! mount -o subvolid=5,ro "$ROOT_DEV" "$mnt_tmp" 2>/dev/null; then
        _log_err "Cannot mount filesystem root — skipping Btrfs check"
        rmdir "$mnt_tmp" 2>/dev/null || true
        errors=$(( errors + 1 ))
    else
        for slot in blue green; do
            local subvol="$mnt_tmp/@${slot}"
            if [[ ! -d "$subvol" ]]; then
                _log_warn "@${slot} not found on disk — skipping"; continue
            fi
            if btrfs scrub start -Br "$subvol" &>/dev/null 2>&1; then
                local sc_out
                sc_out=$(btrfs scrub status "$subvol" 2>/dev/null || true)
                local re ce co
                re=$(echo "$sc_out" | awk '/read_errors:/{print $2}'      | head -1 || echo "0")
                ce=$(echo "$sc_out" | awk '/csum_errors:/{print $2}'      | head -1 || echo "0")
                co=$(echo "$sc_out" | awk '/corrected_errors:/{print $2}' | head -1 || echo "0")
                if [[ "${re:-0}" != "0" || "${ce:-0}" != "0" || "${co:-0}" != "0" ]]; then
                    _log_err "Btrfs errors on @${slot}: read=${re} csum=${ce} corrected=${co}"
                    errors=$(( errors + 1 ))
                else
                    _log_ok "Btrfs clean: @${slot}"
                fi
            else
                local last; last=$(btrfs scrub status / 2>/dev/null \
                    | awk '/Status:/{print $2}' | head -1 || echo "")
                [[ "$last" == "finished" ]] \
                    && _log "@${slot}: live scrub unavailable (mounted) — last run clean" \
                    || _log_warn "@${slot}: cannot scrub live fs — run: btrfs scrub start /"
            fi
        done
        umount "$mnt_tmp" 2>/dev/null || true
        rmdir  "$mnt_tmp" 2>/dev/null || true
    fi

    # Slot marker consistency
    echo ""
    _log "Checking slot marker consistency..."
    local current; current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
    local booted;  booted=$(_get_booted_subvol)
    if [[ ! "$current" =~ ^(blue|green)$ ]]; then
        _log_err "current-slot invalid or missing: '${current}'"
        errors=$(( errors + 1 ))
    else
        _log_ok "Markers OK:  current=@${current}  booted=@${booted}"
    fi

    # Boot entry consistency
    echo ""
    _log "Checking boot entry consistency..."
    local _esp_mounted=0
    _esp_mount
    local loader_conf="$ESP/loader/loader.conf"
    if [[ -f "$loader_conf" ]]; then
        local def_entry resolved
        def_entry=$(grep '^default' "$loader_conf" | awk '{print $2}' || echo "")
        # shellcheck disable=SC2086
        resolved=$(ls "$ESP/loader/entries/"${def_entry} 2>/dev/null | head -1 || echo "")
        if [[ -n "$resolved" ]]; then
            _log_ok "Boot entry OK: '${def_entry}' -> $(basename "$resolved")"
        else
            _log_err "Boot entry '${def_entry}' matches no file in loader/entries/"
            errors=$(( errors + 1 ))
        fi
    else
        _log_warn "loader.conf not found — cannot verify boot entries"
    fi
    _esp_umount

    # Immutability verification
    echo ""
    _log "Checking system immutability..."
    # Root must be read-only
    if findmnt -n -o OPTIONS / 2>/dev/null | grep -q '\bro\b'; then
        _log_ok "Root (/): read-only"
    else
        _log_err "Root (/): WRITABLE — immutability compromised"
        errors=$(( errors + 1 ))
    fi
    # /var must be tmpfs
    local var_fstype; var_fstype=$(findmnt -n -o FSTYPE /var 2>/dev/null || echo "")
    if [[ "$var_fstype" == "tmpfs" ]]; then
        _log_ok "/var: tmpfs (volatile)"
    else
        _log_warn "/var: not tmpfs (${var_fstype:-unknown}) — volatile state may not be enforced"
    fi
    # /etc must have an overlay mount
    local etc_fstype; etc_fstype=$(findmnt -n -o FSTYPE /etc 2>/dev/null || echo "")
    if [[ "$etc_fstype" == "overlay" ]]; then
        local etc_files; etc_files=$(find /etc/. -maxdepth 0 -newer /etc/../usr 2>/dev/null | wc -l || echo "?")
        _log_ok "/etc: overlay active"
    else
        _log_err "/etc: overlay NOT mounted (fstype: ${etc_fstype:-none}) — /etc is from read-only root"
        errors=$(( errors + 1 ))
    fi
    # Critical subvolumes must be mounted
    local sv_errors=0
    for sv in data nix home containers; do
        local mp="/$sv"
        [[ "$sv" == "containers" ]] && mp="/var/lib/containers"
        if findmnt -n "$mp" &>/dev/null; then
            _log_ok "@${sv}: mounted at ${mp}"
        else
            _log_warn "@${sv}: not mounted at ${mp} (may not be installed)"
        fi
    done

    echo ""
    if (( errors == 0 )); then
        _log_ok "Verification passed — no integrity issues"
    else
        _log_err "Verification found ${errors} issue(s)"
    fi
    echo ""
    return $(( errors > 0 ? 1 : 0 ))
}

###############################################################################
### show_history                                                             ###
###############################################################################

# Top-level helper — nested functions cannot write to caller's array in bash
_scan_log_file() {
    local logfile="$1" tmpfile="$2"
    [[ -f "$logfile" ]] || return 0
    local line ts rest ver
    while IFS= read -r line; do
        ts=$(echo "$line" | \
            grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || true)
        [[ -z "$ts" ]] && continue
        rest="${line#*] }"
        if echo "$line" | grep -q "Deployment successful"; then
            ver=$(echo "$line" | grep -oE 'v[0-9]{8}' | head -1 || echo "")
            echo "${ts}  DEPLOY   ${ver}" >> "$tmpfile"
        elif echo "$line" | grep -q "Emergency rollback complete"; then
            echo "${ts}  ROLLBACK (emergency - deploy failed)" >> "$tmpfile"
        elif echo "$line" | grep -q "Fallback slot ready"; then
            echo "${ts}  ROLLBACK (no backup - snapshot of booted slot)" >> "$tmpfile"
        elif echo "$line" | grep -q "Rollback complete"; then
            echo "${ts}  ROLLBACK (manual)" >> "$tmpfile"
        elif echo "$line" | grep -q "Running system:"; then
            ver=$(echo "$rest" | grep -oE 'v[0-9]+' | head -1 || echo "")
            echo "${ts}  START    ${ver}" >> "$tmpfile"
        fi
    done < "$logfile"
}

show_journal() {
    local level="${1:-crit}"   # crit, err, warning
    local since="${2:-}"       # optional: "-1h", "-1d", etc.

    echo ""
    printf "  ${_C_BOLD}┌──────────────────────────────────────────────┐${_C_RESET}\n"
    printf "  ${_C_BOLD}│  %-44s│${_C_RESET}\n" "ShaniOS Journal — ${level} and above"
    printf "  ${_C_BOLD}│  ${_C_DIM}%-44s${_C_BOLD}│${_C_RESET}\n" "$(date '+%Y-%m-%d %H:%M')"
    printf "  ${_C_BOLD}└──────────────────────────────────────────────┘${_C_RESET}\n"

    # Map level name to journalctl priority number for display
    local level_desc
    case "$level" in
        crit)    level_desc="critical (0–2)" ;;
        err)     level_desc="errors (0–3)" ;;
        warning) level_desc="warnings (0–4)" ;;
        *)       level_desc="$level" ;;
    esac

    local since_args=()
    [[ -n "$since" ]] && since_args=(--since "$since") || since_args=(-b 0)

    # ── Critical / error journal entries ─────────────────────────────────────
    _head "Journal Messages (this boot)"
    local j_crit j_err
    j_crit=$(journalctl -b 0 -p crit  --no-pager -q 2>/dev/null | wc -l || echo "0")
    j_err=$( journalctl -b 0 -p err   --no-pager -q 2>/dev/null | wc -l || echo "0")
    local j_warn
    j_warn=$(journalctl -b 0 -p warning --no-pager -q 2>/dev/null | wc -l || echo "0")
    _row "Critical"  "${j_crit:+!!  }${j_crit:-0} message(s)"
    _row "Errors"    "--  ${j_err:-0} message(s)"
    _row "Warnings"  "--  ${j_warn:-0} message(s)"

    echo ""
    printf "  ${_C_DIM}%s${_C_RESET}\n" "── Critical messages ──────────────────────────────────"
    echo ""
    journalctl "${since_args[@]}" -p crit --no-pager -o short-precise 2>/dev/null \
        | grep -v '^--' | sed 's/^/    /' || true

    if [[ "$level" == "err" || "$level" == "warning" ]]; then
        echo ""
        printf "  ${_C_DIM}%s${_C_RESET}\n" "── Errors (non-critical) ──────────────────────────────"
        echo ""
        journalctl "${since_args[@]}" -p err..err --no-pager -o short-precise 2>/dev/null \
            | grep -v '^--' | sed 's/^/    /' | head -50 || true
    fi

    if [[ "$level" == "warning" ]]; then
        echo ""
        printf "  ${_C_DIM}%s${_C_RESET}\n" "── Warnings ───────────────────────────────────────────"
        echo ""
        journalctl "${since_args[@]}" -p warning..warning --no-pager -o short-precise 2>/dev/null \
            | grep -v '^--' | sed 's/^/    /' | head -50 || true
    fi

    # ── AppArmor denials ──────────────────────────────────────────────────────
    _head "AppArmor Denials (this boot)"
    local aa_count
    aa_count=$(journalctl -k -b 0 --no-pager -q 2>/dev/null | grep -c 'apparmor.*DENIED' || echo "0")
    if [[ "$aa_count" =~ ^[0-9]+$ ]] && (( aa_count > 0 )); then
        _row "Denials"  "!   ${aa_count} total this boot"
        echo ""
        journalctl -k -b 0 --no-pager -q 2>/dev/null \
            | grep 'apparmor.*DENIED' \
            | grep -oP 'profile="[^"]+"|comm="[^"]+"|name="[^"]+"' \
            | sort | uniq -c | sort -rn \
            | sed 's/^/    /' | head -20 || true
        echo ""
        printf "    ${_C_DIM}Full log: journalctl -k -b 0 | grep apparmor.*DENIED${_C_RESET}\n"
    else
        _row "Denials"  "OK  none this boot"
    fi

    # ── OOM kills ─────────────────────────────────────────────────────────────
    _head "OOM Events (this boot)"
    local oom_count
    oom_count=$(journalctl -k -b 0 --no-pager -q 2>/dev/null \
        | grep -c 'Out of memory\|oom_kill_process\|Killed process' || echo "0")
    if [[ "$oom_count" =~ ^[0-9]+$ ]] && (( oom_count > 0 )); then
        _row "OOM kills" "!   ${oom_count} event(s)"
        journalctl -k -b 0 --no-pager -q 2>/dev/null \
            | grep 'Out of memory\|oom_kill_process\|Killed process' \
            | tail -5 | sed 's/^/    /' || true
    else
        _row "OOM kills" "OK  none this boot"
    fi

    # ── Failed units summary ──────────────────────────────────────────────────
    _head "Failed Units"
    local failed_now=()
    mapfile -t failed_now < <(
        systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null \
            | awk '{print $2}' | grep -v '^$' | grep '\.' || true)
    if [[ ${#failed_now[@]} -eq 0 ]]; then
        _row "Units"  "OK  no failed units"
    else
        for u in "${failed_now[@]}"; do
            _row "  ${u}" "!!  failed"
            # Show the most recent error line from this unit
            local _uerr
            _uerr=$(journalctl -u "$u" -b 0 --no-pager -q -n 1 2>/dev/null | tail -1 || true)
            [[ -n "$_uerr" ]] && _row2 "--  ${_uerr:0:80}"
        done
    fi

    echo ""
}

show_history() {
    local lines="${1:-50}"

    echo ""
    printf "  ${_C_BOLD}┌──────────────────────────────────────────────┐${_C_RESET}\n"
    printf "  ${_C_BOLD}│  %-44s│${_C_RESET}\n" "ShaniOS Deploy History"
    printf "  ${_C_BOLD}└──────────────────────────────────────────────┘${_C_RESET}\n"

    if [[ ! -f "$DEPLOY_LOG" ]]; then
        echo "    No log file found at ${DEPLOY_LOG}"
        echo ""
        return 0
    fi

    local tmp; tmp=$(mktemp)
    _scan_log_file "$DEPLOY_LOG"       "$tmp"
    _scan_log_file "${DEPLOY_LOG}.old" "$tmp"

    local -a events=()
    mapfile -t events < <(sort "$tmp")
    rm -f "$tmp"

    if [[ ${#events[@]} -eq 0 ]]; then
        echo "    No deploy events recorded yet."
        echo "    Log: ${DEPLOY_LOG}"
        echo ""
        return 0
    fi

    local total=${#events[@]}
    local start=$(( total > lines ? total - lines : 0 ))
    echo ""
    for (( i=start; i<total; i++ )); do
        local ev="${events[$i]}"
        if   [[ "$ev" == *"  DEPLOY   "* ]]; then
            ev="${ev//  DEPLOY   /  ${_C_GREEN}+${_C_RESET}  }"
        elif [[ "$ev" == *"  ROLLBACK "* ]]; then
            ev="${ev//  ROLLBACK /  ${_C_YELLOW}<${_C_RESET}  }"
        elif [[ "$ev" == *"  START    "* ]]; then
            ev="${ev//  START    /  ${_C_CYAN}>${_C_RESET}  }"
        fi
        printf "    %b\n" "$ev"
    done
    echo ""
    (( start > 0 )) && echo "    (showing last ${lines} of ${total} — use: --history ${total} for all)"
    echo "    Full log: ${DEPLOY_LOG}"
    echo ""
}

###############################################################################
### analyze_storage — native Btrfs storage analysis                         ###
###############################################################################

# Print one subvolume size row for analyze_storage.
# Usage: _stor_subvol_row <subvol_name> <path> <now_epoch>
_stor_subvol_row() {
    local sv="$1" path="$2" now="$3"
    [[ -d "$path" ]] || return 0

    # Size — prefer compsize for compression ratio, fall back to btrfs du
    local excl_size total_size=""
    if command -v compsize &>/dev/null; then
        local cs_out; cs_out=$(compsize -x "$path" 2>/dev/null | tail -1 || true)
        total_size=$(echo "$cs_out" | awk '{print $3}' || true)
        local ratio;  ratio=$(echo "$cs_out" | awk '{print $NF}' || true)
        excl_size="${total_size}${ratio:+ (ratio: ${ratio})}"
    else
        local du_out; du_out=$(btrfs filesystem du -s "$path" 2>/dev/null | tail -1 || true)
        local excl; excl=$(echo "$du_out" | awk '{print $2}' || true)
        local tot;  tot=$( echo "$du_out" | awk '{print $1}' || true)
        excl_size="${tot:-?} total, ${excl:-?} exclusive"
    fi

    # Snapshot creation time and age
    local snap_info; snap_info=$(btrfs subvolume show "$path" 2>/dev/null || true)
    local created; created=$(echo "$snap_info"         | awk -F'	' '/Creation time:/{gsub(/^[[:space:]]+/,"",$2); print $2}'         | head -1 || true)
    local age_str=""
    local parent_uuid; parent_uuid=$(echo "$snap_info"         | awk -F'	' '/Parent UUID:/{gsub(/^[[:space:]]+/,"",$2); print $2}'         | head -1 || true)
    if [[ -n "$parent_uuid" && "$parent_uuid" != "-" && -n "$created" ]]; then
        local created_epoch; created_epoch=$(date -d "$created" +%s 2>/dev/null || echo "")
        if [[ -n "$created_epoch" ]]; then
            local age_days=$(( (now - created_epoch) / 86400 ))
            age_str=" — ${age_days}d old"
        fi
    fi

    # Warn on stale backup snapshots (>30 days old)
    local level="--"
    if [[ "$sv" == *_backup_* ]]; then
        local age_days_int=0
        [[ -n "$age_str" ]] && age_days_int=$(echo "$age_str" | grep -oE '[0-9]+' | head -1 || echo 0)
        (( age_days_int > 30 )) && level="!"
    fi

    _row "${sv}" "${level}  ${excl_size:-?}${age_str}"
}

analyze_storage() {
    local STOR_MNT; STOR_MNT=$(mktemp -d /tmp/shani-storage-XXXXXX)
    trap '_umount_r "$STOR_MNT"; rmdir "$STOR_MNT" 2>/dev/null || true' RETURN

    # Mount at subvolid=5 (the Btrfs root) so every subvolume is reachable
    if ! mount -o subvolid=5,ro "$ROOT_DEV" "$STOR_MNT" 2>/dev/null; then
        _die "Could not mount ${ROOT_DEV} at subvolid=5 — is ${ROOTLABEL} the correct label?"
    fi

    echo ""
    printf "  ${_C_BOLD}┌──────────────────────────────────────────────┐${_C_RESET}\n"
    printf "  ${_C_BOLD}│  %-44s│${_C_RESET}\n" "ShaniOS Storage Analysis"
    printf "  ${_C_BOLD}│  ${_C_DIM}%-44s${_C_BOLD}│${_C_RESET}\n" "$(date '+%Y-%m-%d %H:%M')"
    printf "  ${_C_BOLD}└──────────────────────────────────────────────┘${_C_RESET}\n"

    # ── Part 1: Standard storage section (same as main report) ───────────────
    # Re-initialise recommendations so they print at the end of this run
    _recs_reset

    # Reuse _section_storage but redirect the shared helpers to use STOR_MNT
    # so free space and device stats are read from the subvolid=5 view.
    _stor_check_free "$STOR_MNT"

    # Qgroup consistency
    local qgroup_out; qgroup_out=$(btrfs qgroup show "$STOR_MNT" 2>&1 || true)
    if ! echo "$qgroup_out" | grep -q 'ERROR\|quota system is not enabled'; then
        if echo "$qgroup_out" | grep -qi 'inconsistent\|stale'; then
            _row "Quotas"    "!!  qgroup inconsistency detected — may cause phantom ENOSPC"
            _rec "Btrfs qgroup inconsistent — fix: btrfs quota rescan /  [auto]"
        else
            _row "Quotas"    "OK  consistent"
        fi
    fi

    # Scrub status
    local scrub_st scrub_res
    scrub_st=$(btrfs scrub status / 2>/dev/null || true)
    scrub_res=$(echo "$scrub_st" | awk '/Status:/{print $2}' | head -1 || echo "")
    local scrub_timer; scrub_timer=$(systemctl is-active btrfs-scrub.timer 2>/dev/null || echo "inactive")
    if [[ "$scrub_timer" == "active" ]]; then
        _row "Scrub tmr"  "OK  active"
    else
        _row "Scrub tmr"  "!!  btrfs-scrub.timer not active"
        _rec "btrfs-scrub.timer not active — run: systemctl enable --now btrfs-scrub.timer  [auto]"
    fi
    case "$scrub_res" in
        finished)
            local re ce co
            re=$(echo "$scrub_st" | awk '/read_errors:/{print $2}'      | head -1 || echo "0")
            ce=$(echo "$scrub_st" | awk '/csum_errors:/{print $2}'      | head -1 || echo "0")
            co=$(echo "$scrub_st" | awk '/corrected_errors:/{print $2}' | head -1 || echo "0")
            if [[ "${re:-0}" != "0" || "${ce:-0}" != "0" || "${co:-0}" != "0" ]]; then
                _row "Scrub"    "!!  errors: read=${re} csum=${ce} corrected=${co}"
                _rec "Btrfs scrub found errors — investigate: btrfs scrub status /"
            else
                _row "Scrub"    "OK  last run clean"
            fi ;;
        running) _row "Scrub" "->  in progress" ;;
        "")      _row "Scrub" "--  no scrub recorded yet" ;;
        *)       _row "Scrub" "!   status: ${scrub_res}" ;;
    esac

    # Maintenance timers
    local t_ok=() t_bad=()
    for name in balance defrag trim; do
        [[ "$(systemctl is-active "btrfs-${name}.timer" 2>/dev/null)" == "active" ]] \
            && t_ok+=("$name") || t_bad+=("$name")
    done
    local t_ok_str; t_ok_str=$(_join "${t_ok[@]}")
    local t_bad_str; t_bad_str=$(_join "${t_bad[@]}")
    if   [[ ${#t_bad[@]} -eq 0 ]]; then _row "Maint tmrs" "OK  active: ${t_ok_str}"
    elif [[ ${#t_ok[@]}  -eq 0 ]]; then _row "Maint tmrs" "!!  all inactive: ${t_bad_str}"
    else                                 _row "Maint tmrs" "!   active: ${t_ok_str}  |  inactive: ${t_bad_str}"
    fi

    # Bees + subvol quick summary (shared helpers)
    _stor_check_bees
    _stor_check_device_errors "$STOR_MNT"

    # ── Part 2: Deep analysis (requires subvolid=5 mount) ────────────────────
    echo ""
    printf "  ${_C_DIM}%.54s${_C_RESET}\n" "── Deep Analysis ──────────────────────────────────────"

    # ── Filesystem-level usage detail ────────────────────────────────────────
    _head "Filesystem Usage"
    local fs_usage; fs_usage=$(btrfs filesystem usage "$STOR_MNT" 2>/dev/null || true)
    if [[ -n "$fs_usage" ]]; then
        local fs_total fs_used
        fs_total=$(echo "$fs_usage" | awk '/Device size:/{print $3}' | head -1)
        fs_used=$( echo "$fs_usage" | awk '/Used:/{print $2}'        | head -1)
        [[ -n "$fs_total" ]] && _row "Total"  "--  ${fs_total}"
        [[ -n "$fs_used"  ]] && _row "Used"   "--  ${fs_used}"
        echo ""
        printf "  ${_C_DIM}%s${_C_RESET}\n" "Block group profiles:"
        echo "$fs_usage" | awk '/^(Data|Metadata|System),/{printf "    %-32s %s\n", $1, $2}' \
            | sed 's/,/ /' || true
    fi

    # ── Per-subvolume compression + size ─────────────────────────────────────
    _head "Subvolume Analysis"

    # Enumerate all subvolumes from the subvolid=5 mount
    local subvol_list
    subvol_list=$(btrfs subvolume list "$STOR_MNT" 2>/dev/null | awk '{print $NF}' | sort || true)

    # Decide display order: slots first, then data/swap/nix/containers, then backups, then rest
    local -a primary=() backups=() others=()
    while IFS= read -r sv; do
        [[ -z "$sv" ]] && continue
        case "$sv" in
            @blue|@green|@data|@swap|@nix|@containers|@home|@waydroid)
                primary+=("$sv") ;;
            *_backup_*)
                backups+=("$sv") ;;
            *)
                others+=("$sv") ;;
        esac
    done <<< "$subvol_list"

    local now; now=$(date +%s)

    if [[ ${#primary[@]} -gt 0 ]]; then
        for sv in "${primary[@]}"; do
            _stor_subvol_row "$sv" "${STOR_MNT}/${sv}" "$now"
        done
    fi

    if [[ ${#backups[@]} -gt 0 ]]; then
        echo ""
        printf "    ${_C_DIM}── Backup snapshots ──────────────────────────────${_C_RESET}\n"
        for sv in "${backups[@]}"; do
            _stor_subvol_row "$sv" "${STOR_MNT}/${sv}" "$now"
        done
    fi

    if [[ ${#others[@]} -gt 0 ]]; then
        local others_present=()
        for sv in "${others[@]}"; do
            [[ -d "${STOR_MNT}/${sv}" ]] && others_present+=("$sv")
        done
        if [[ ${#others_present[@]} -gt 0 ]]; then
            echo ""
            printf "    ${_C_DIM}── Other subvolumes ──────────────────────────────${_C_RESET}\n"
            for sv in "${others_present[@]}"; do
                _stor_subvol_row "$sv" "${STOR_MNT}/${sv}" "$now"
            done
        fi
    fi

    # ── Application & container storage ──────────────────────────────────────
    _head "Application Storage"

    # Flatpak
    if command -v flatpak &>/dev/null; then
        local fp_mb; fp_mb=$(du -sm /var/lib/flatpak 2>/dev/null | awk '{print $1}' || echo "")
        local fp_apps; fp_apps=$(timeout 5 flatpak list --app --columns=application 2>/dev/null | wc -l || echo "?")
        local fp_rt;   fp_rt=$(timeout 5 flatpak list --runtime --columns=application 2>/dev/null | wc -l || echo "?")
        if [[ "$fp_mb" =~ ^[0-9]+$ ]]; then
            if (( fp_mb > 20480 )); then
                _row "Flatpak"  "!   ${fp_mb} MB  (${fp_apps} apps, ${fp_rt} runtimes) — run: flatpak uninstall --unused"
                _rec "Flatpak storage is ${fp_mb} MB — free space: flatpak uninstall --unused"
            else
                _row "Flatpak"  "--  ${fp_mb} MB  (${fp_apps} apps, ${fp_rt} runtimes)"
            fi
        fi
    fi

    # Snap
    if findmnt -n /var/lib/snapd &>/dev/null; then
        local snap_mb;    snap_mb=$(du -sm /var/lib/snapd/snaps 2>/dev/null | awk '{print $1}' || echo "")
        local snap_total; snap_total=$(du -sm /var/lib/snapd 2>/dev/null | awk '{print $1}' || echo "")
        local snap_stale; snap_stale=$(timeout 5 snap list --all 2>/dev/null \
            | awk '/disabled/{c++} END{print c+0}' || echo "0")
        local snap_str=""
        [[ "$snap_stale" =~ ^[0-9]+$ ]] && (( snap_stale > 0 )) && snap_str=", ${snap_stale} stale"
        if [[ "$snap_mb" =~ ^[0-9]+$ ]]; then
            if (( snap_mb > 10240 )); then
                _row "Snap"     "!   ${snap_mb} MB snaps${snap_str} — run: snap set system refresh.retain=2"
                _rec "Snap storage is ${snap_mb} MB — limit old revisions: snap set system refresh.retain=2"
            else
                _row "Snap"     "--  ${snap_mb} MB snaps${snap_str}${snap_total:+  (${snap_total} MB total)}"
            fi
        fi
    fi

    # Nix store
    if findmnt -n /nix &>/dev/null; then
        local nix_mb; nix_mb=$(du -sm /nix/store 2>/dev/null | awk '{print $1}' || echo "")
        local nix_gen; nix_gen=$(ls /nix/var/nix/profiles 2>/dev/null | grep -cE '^system-[0-9]+-link$' || echo "")
        local nix_str=""
        [[ "$nix_gen" =~ ^[0-9]+$ ]] && (( nix_gen > 0 )) && nix_str=", ${nix_gen} generation(s)"
        if [[ "$nix_mb" =~ ^[0-9]+$ ]]; then
            if (( nix_mb > 51200 )); then
                _row "Nix"      "!   ${nix_mb} MB${nix_str} — run: nix-collect-garbage -d"
                _rec "Nix store is ${nix_mb} MB — free space: nix-collect-garbage -d"
            else
                _row "Nix"      "--  ${nix_mb} MB${nix_str}"
            fi
        fi
    fi

    # Podman (system + rootless)
    if command -v podman &>/dev/null; then
        local pod_sys; pod_sys=$(du -sm /var/lib/containers/storage/overlay 2>/dev/null | awk '{print $1}' || echo "")
        [[ "$pod_sys" =~ ^[0-9]+$ ]] && _row "Podman sys" "--  ${pod_sys} MB system image storage"
        local _pod_user="$_CALLER_USER"
        if [[ -n "$_pod_user" ]]; then
            local _pod_home; _pod_home=$(getent passwd "$_pod_user" 2>/dev/null | cut -d: -f6 || echo "")
            if [[ -n "$_pod_home" ]]; then
                local pod_usr; pod_usr=$(du -sm "${_pod_home}/.local/share/containers/storage/overlay" \
                    2>/dev/null | awk '{print $1}' || echo "")
                [[ "$pod_usr" =~ ^[0-9]+$ ]] && (( pod_usr > 0 )) && \
                    _row "Podman usr" "--  ${pod_usr} MB ${_pod_user} rootless storage"
            fi
        fi
    fi

    # LXD
    if { findmnt -n /var/lib/lxd &>/dev/null || [[ -d /data/varlib/lxd ]]; }; then
        local lxd_mb; lxd_mb=$(du -sm /var/lib/lxd /data/varlib/lxd 2>/dev/null | awk '{s+=$1} END{print s}' || echo "")
        [[ "$lxd_mb" =~ ^[0-9]+$ ]] && _row "LXD"        "--  ${lxd_mb} MB"
    fi

    # Waydroid
    if findmnt -n /var/lib/waydroid &>/dev/null; then
        local wd_mb; wd_mb=$(du -sm /var/lib/waydroid 2>/dev/null | awk '{print $1}' || echo "")
        [[ "$wd_mb" =~ ^[0-9]+$ ]] && _row "Waydroid"    "--  ${wd_mb} MB"
    fi

    # Apptainer cache
    if command -v apptainer &>/dev/null || command -v singularity &>/dev/null; then
        local _apt_user="$_CALLER_USER"
        if [[ -n "$_apt_user" ]]; then
            local _apt_home; _apt_home=$(getent passwd "$_apt_user" 2>/dev/null | cut -d: -f6 || echo "")
            if [[ -n "$_apt_home" ]]; then
                local _apt_cache="${APPTAINER_CACHEDIR:-${_apt_home}/.apptainer/cache}"
                local apt_mb; apt_mb=$(du -sm "$_apt_cache" 2>/dev/null | awk '{print $1}' || echo "")
                if [[ "$apt_mb" =~ ^[0-9]+$ ]] && (( apt_mb > 0 )); then
                    if (( apt_mb > 10240 )); then
                        _row "Apptainer"  "!   ${apt_mb} MB cache — run: apptainer cache clean"
                        _rec "Apptainer cache is ${apt_mb} MB — free space: apptainer cache clean"
                    else
                        _row "Apptainer"  "--  ${apt_mb} MB cache"
                    fi
                fi
            fi
        fi
    fi

    # /home per-user
    if findmnt -n /home &>/dev/null; then
        for user_dir in /home/*/; do
            [[ -d "$user_dir" ]] || continue
            local uname; uname=$(basename "$user_dir")
            local used_mb; used_mb=$(du -sm "$user_dir" 2>/dev/null | awk '{print $1}' || echo "")
            [[ "$used_mb" =~ ^[0-9]+$ ]] && (( used_mb > 0 )) && \
                _row "Home/${uname}" "--  ${used_mb} MB"
        done
    fi

    # ── Snapshot summary ──────────────────────────────────────────────────────
    _head "Snapshot Summary"
    local snap_count; snap_count=$(btrfs subvolume list -s "$STOR_MNT" 2>/dev/null | wc -l || echo "0")
    _row "Snapshots"  "--  ${snap_count} total"

    # List snapshots with their parent and creation date, newest first
    btrfs subvolume list -s --sort=-rootid "$STOR_MNT" 2>/dev/null \
        | awk '{printf "    %-42s  %s %s\n", $NF, $(NF-3), $(NF-2)}' \
        | head -20 || true

    # ── Space reclaim hints ───────────────────────────────────────────────────
    _head "Reclaim Hints"
    local hints=0

    # duperemove hint when cross-slot savings are likely
    if command -v duperemove &>/dev/null; then
        hints=$(( hints + 1 ))
        _row "Dedup"      "--  duperemove available — run: shani-deploy --optimize"
        _row2 "--  deduplicates @blue/@green and backup snapshots across slots"
    else
        hints=$(( hints + 1 ))
        _row "Dedup"      "--  duperemove not installed — install for cross-slot deduplication"
        _row2 "--  pacman -S duperemove  then: shani-deploy --optimize"
    fi

    # bees status — only flag here if not already reported in Part 1 as running
    local _bees_was_ok=0
    systemctl is-active --quiet "beesd@$(_get_bees_uuid 2>/dev/null)" 2>/dev/null && _bees_was_ok=1
    if (( ! _bees_was_ok )); then
        hints=$(( hints + 1 ))
        _stor_check_bees
    fi

    if (( hints == 0 )); then
        printf "    ${_C_GREEN}${_SYM_OK}${_C_RESET}  No reclaim actions needed\n"
    fi

    # ── Recommendations summary ───────────────────────────────────────────────
    echo ""
    if [[ ${#_RECS[@]} -gt 0 ]]; then
        printf "  ${_C_BOLD}${_C_YELLOW}Recommendations (${#_RECS[@]})${_C_RESET}\n"
        printf "  ${_C_DIM}%.54s${_C_RESET}\n" "──────────────────────────────────────────────────────"
        local i=1
        for rec in "${_RECS[@]}"; do
            local display="${rec/\[auto\]/${_C_CYAN}[auto]${_C_RESET}}"
            printf "    ${_C_BOLD}%2d.${_C_RESET}  %b\n" "$i" "$display"
            i=$(( i + 1 ))
        done
        echo ""
        printf "  ${_C_DIM}Items marked ${_C_CYAN}[auto]${_C_DIM} can be fixed by: shani-health --fix${_C_RESET}\n"
    fi
    echo ""
}

###############################################################################
### export_logs                                                              ###
###############################################################################

export_logs() {
    local out_dir="${1:-/tmp}"
    local ts; ts=$(date '+%Y%m%d-%H%M%S')
    local bundle="${out_dir}/shanios-report-${ts}.tar.gz"
    local staging; staging=$(mktemp -d /tmp/shanios-report-staging.XXXXXX)

    _log "Collecting system information for bug report..."

    [[ -f "$DEPLOY_LOG"       ]] && cp "$DEPLOY_LOG"       "$staging/shanios-deploy.log"     2>/dev/null || true
    [[ -f "${DEPLOY_LOG}.old" ]] && cp "${DEPLOY_LOG}.old" "$staging/shanios-deploy.log.old" 2>/dev/null || true

    journalctl -b 0 --no-pager -n 500 -o short-iso 2>/dev/null \
        | grep -vi 'password\|passwd\|secret\|token\|luks\|PIN' \
        > "$staging/journal-boot.log" 2>/dev/null || true

    journalctl --no-pager -n 100 -u systemd-boot 2>/dev/null \
        > "$staging/journal-systemd-boot.log" 2>/dev/null || true

    {
        echo "=== shani-health bug report — $(date) ==="
        echo ""
        echo "=== /proc/cmdline ===";         cat /proc/cmdline            2>/dev/null; echo ""
        echo "=== uname -a ===";              uname -a                     2>/dev/null; echo ""
        echo "=== /etc/shani-version ===";    cat /etc/shani-version       2>/dev/null; echo ""
        echo "=== /etc/shani-profile ===";    cat /etc/shani-profile       2>/dev/null; echo ""
        echo "=== /etc/shani-channel ===";    cat "$CHANNEL_FILE"          2>/dev/null || echo "(not set)"; echo ""
        echo "=== /data/current-slot ===";    cat "$DATA_CURRENT_SLOT"     2>/dev/null || echo "(missing)"; echo ""
        echo "=== /data/previous-slot ===";   cat "$DATA_PREV_SLOT"        2>/dev/null || echo "(missing)"; echo ""
        echo "=== Boot markers ==="
        for f in boot-ok boot_in_progress boot_failure boot_failure.acked \
                 boot_hard_failure deployment_pending; do
            if [[ -f "/data/${f}" ]]; then
                printf "  /data/%s: %s\n" "$f" "$(cat "/data/${f}" 2>/dev/null || echo "(empty)")"
            else
                printf "  /data/%s: (absent)\n" "$f"
            fi
        done
        echo ""
        echo "=== shani-user-setup ==="
        printf "  binary: %s\n" "$(test -x "$USER_SETUP_BIN" && echo "present" || echo "MISSING")"
        printf "  /data/user-setup-needed: %s\n" \
            "$(test -f /data/user-setup-needed && echo "present ($(stat -c '%y' /data/user-setup-needed 2>/dev/null | cut -d. -f1))" || echo "absent")"
        echo ""
        echo "=== Btrfs subvolumes ==="; btrfs subvolume list / 2>/dev/null || echo "(unavailable)"; echo ""
        echo "=== findmnt ===";          findmnt                2>/dev/null || true; echo ""
        echo "=== systemctl --failed ==="; \
            systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null || true
    } > "$staging/system-state.txt" 2>/dev/null

    local _esp_mounted=0
    _esp_mount
    if mountpoint -q "$ESP" 2>/dev/null; then
        cp "$ESP/loader/loader.conf" "$staging/loader.conf"      2>/dev/null || true
        ls -la "$ESP/loader/entries/" > "$staging/loader-entries.txt" 2>/dev/null || true
        ls -la "$ESP/EFI/${OS_NAME}/" > "$staging/efi-binaries.txt"   2>/dev/null || true
    fi
    _esp_umount

    tar -czf "$bundle" -C "$(dirname "$staging")" "$(basename "$staging")" 2>/dev/null \
        || _die "Failed to create bundle at ${bundle}"
    rm -rf "$staging"

    _log_ok "Report bundle: ${bundle}"
    _log    "No passwords or private keys included"
    echo ""
}

###############################################################################
### Usage                                                                    ###
###############################################################################

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

  ShaniOS system health, security, and diagnostics.

Options:
  (no args)               Full system status report
  -i, --info              Alias for full system status report
  --fix                   Auto-fix all [auto] issues
  --verify                Deep integrity check: UKI sigs, Btrfs scrub, immutability
  --security              Security-focused report: boot chain, encryption, users, groups
  --journal [level]       Show journal entries (level: crit, err, warning — default: crit)
  -s, --storage-info      Btrfs storage analysis: subvolume sizes, compression, snapshots
  --history [N]           Last N deploy/rollback events from log (default: 50)
  --clear-boot-failure    Clear a stale boot failure marker (when current boot is healthy)
  --export-logs [DIR]     Bundle logs + state for bug reports (default: /tmp)
  -v, --verbose           Verbose/debug output
  -h, --help              Show this help

Examples:
  shani-health                        Full status report
  shani-health --fix                  Auto-fix automatable issues
  shani-health --security             Security audit report
  shani-health --journal              Show critical journal messages
  shani-health --journal err          Show errors and above
  shani-health --storage-info         Btrfs subvolume + compression analysis
  shani-health --verify               Deep integrity check (runs scrub — takes time)
  shani-health --history 100          Last 100 deploy events
  shani-health --export-logs ~/       Bundle diagnostics to home dir

Install:
  cp shani-health /usr/local/bin/shani-health
  chmod +x /usr/local/bin/shani-health
EOF
}

###############################################################################
### Main                                                                     ###
###############################################################################

main() {
    local MODE="info"
    local HISTORY_LINES=50
    local EXPORT_DIR="/tmp"
    local JOURNAL_LEVEL="crit"
    local JOURNAL_SINCE=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)          usage; exit 0 ;;
            -i|--info)          MODE="info";         shift ;;
            --fix)              MODE="fix";           shift ;;
            --verify)           MODE="verify";       shift ;;
            -s|--storage-info)  MODE="storage-info"; shift ;;
            --security)         MODE="security";     shift ;;
            --journal)
                MODE="journal"
                if [[ -n "${2:-}" && "${2:-}" =~ ^(crit|err|warning)$ ]]; then
                    JOURNAL_LEVEL="$2"; shift 2
                elif [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                    JOURNAL_SINCE="$2"; shift 2
                else
                    shift
                fi ;;
            --history)
                MODE="history"
                if [[ -n "${2:-}" && "${2:-}" =~ ^[0-9]+$ ]]; then
                    HISTORY_LINES="$2"; shift 2
                else
                    shift
                fi ;;
            --clear-boot-failure)  MODE="clear-boot-failure"; shift ;;
            --export-logs)
                MODE="export-logs"
                if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                    EXPORT_DIR="$2"; shift 2
                else
                    shift
                fi ;;
            -v|--verbose)       VERBOSE="yes"; shift ;;
            *)  _log_warn "Unknown option: $1"; shift ;;
        esac
    done

    _require_root

    case "$MODE" in
        info)                system_info ;;
        fix)                 fix ;;
        verify)              verify_system; exit $? ;;
        security)            security_report ;;
        journal)             show_journal "$JOURNAL_LEVEL" "$JOURNAL_SINCE" ;;
        history)             show_history "$HISTORY_LINES" ;;
        storage-info)        analyze_storage ;;
        clear-boot-failure)  clear_boot_failure ;;
        export-logs)         export_logs "$EXPORT_DIR" ;;
    esac
}

main "$@"
