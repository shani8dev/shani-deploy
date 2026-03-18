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
#   shani-health --storage-info      Btrfs storage analysis (delegates to shani-deploy)
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

readonly SCRIPT_VERSION="2.4"
readonly OS_NAME="shanios"
readonly ROOTLABEL="shani_root"
readonly ROOT_DEV="/dev/disk/by-label/shani_root"
readonly ESP="/boot/efi"
readonly GENEFI_BIN="/usr/local/bin/gen-efi"
readonly DEPLOY_BIN="/usr/local/bin/shani-deploy"
readonly USER_SETUP_BIN="/usr/local/bin/shani-user-setup"
readonly DEPLOY_LOG="/var/log/shanios-deploy.log"
readonly CHANNEL_FILE="/etc/shani-channel"

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
    if [[ "$booted" == "$slot_current" ]]; then
        _row "Active"    "OK  @${slot_current}  (booted)"
    elif [[ -f "$DATA_REBOOT_NEEDED" ]]; then
        # Update deployed, waiting for reboot — not a failure
        local rver; rver=$(cat "$DATA_REBOOT_NEEDED" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
        _row "Active"    "!   @${booted}  (new v${rver} ready — reboot to activate @${slot_current})"
    elif [[ -f "$DATA_BOOT_FAIL" || -f "$DATA_BOOT_HARD_FAIL" ]]; then
        # Booted slot != current-slot AND failure marker present = fallback boot
        _row "Active"    "!!  @${booted}  (FALLBACK — @${slot_current} failed to boot)"
        _rec "Fallback boot confirmed — run: shani-deploy --rollback"
    else
        # Mismatch with no reboot-needed and no failure = unexpected
        _row "Active"    "!!  @${slot_current}  mismatch — booted: @${booted}"
        _rec "Slot mismatch with no failure or reboot-needed marker — run: shani-deploy --rollback"
    fi

    # Fallback slot display — distinguish stale failure (other slot is fine) from active problem
    if [[ -f "$DATA_BOOT_FAIL" ]]; then
        local _fail_slot; _fail_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "")
        # Determine the fallback slot name for display
        local _fallback_slot="$slot_previous"
        [[ -z "$_fallback_slot" || "$_fallback_slot" == "unknown" ]] && \
            _fallback_slot="$_fail_slot"

        if [[ "$booted" == "$slot_current" ]]; then
            # We are booted into the *current* slot successfully — the failure
            # marker is for the *other* slot and is a historical record, not
            # an emergency. Inform the user but don't trigger rollback rec here
            # (Boot Health section handles the rec).
            _row "Fallback"  "!   @${_fallback_slot}  (prior boot failure recorded — may need: shani-deploy --rollback)"
        elif [[ "$_fail_slot" == "$slot_previous" ]]; then
            _row "Fallback"  "!   @${slot_previous}  (has recorded boot failure — run: shani-deploy --rollback)"
        else
            _row "Fallback"  "--  @${slot_previous}"
        fi
    else
        _row "Fallback"  "--  @${slot_previous}"
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
        _row "Boot chain" "!!  failed this boot: ${chain_failed[*]}"
        _rec "Boot chain service(s) failed: ${chain_failed[*]} — run: systemctl status <unit>"
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
        _row "Overlay boot" "!!  failed: ${overlay_boot_failed[*]}"
        _rec "Overlay boot service(s) failed: ${overlay_boot_failed[*]} — run: systemctl status <unit>"
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
            _rec "Stale boot failure marker for @${s} — system is running correctly on @${booted_slot}; run: shani-deploy --rollback to repair @${s} and clear the marker"
        else
            _row "Failure"    "!   boot failure recorded for @${s}"
            _rec "Boot failure for @${s} — run: shani-deploy --rollback"
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
        _rec "check-boot-failure.timer failed — run: systemctl reset-failed check-boot-failure.timer && systemctl start check-boot-failure.timer"
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
        _row "Cmdline"    "!!  missing for: ${cmdline_missing[*]} — next gen-efi may produce wrong UKI"
        _rec "Cmdline files missing for @${cmdline_missing[*]} — run: gen-efi configure <slot> for each  [auto]"
    fi

    # ── Slot backup snapshots ─────────────────────────────────────────────────
    # Deploy keeps one backup per slot — if missing, --rollback has no snapshot to restore from
    local backup_missing=() backup_found=()
    for slot in blue green; do
        local has_backup
        has_backup=$(btrfs subvolume list / 2>/dev/null \
            | awk -v s="${slot}_backup_" '$NF ~ s {print $NF; exit}' || echo "")
        if [[ -n "$has_backup" ]]; then
            backup_found+=("@${slot}:$(basename "$has_backup")")
        else
            backup_missing+=("@${slot}")
        fi
    done
    if [[ ${#backup_missing[@]} -eq 0 ]]; then
        _row "Backups"    "OK  $(IFS=' '; echo "${backup_found[*]}")"
    else
        _row "Backups"    "!   no backup snapshot for: ${backup_missing[*]} — rollback unavailable"
        _rec "No rollback backup for ${backup_missing[*]} — run shani-deploy to create one"
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
            _row "Downloads"  "--  ${dl_size_mb} MB cached (run --cleanup to free space)"
        fi
    fi

    # ── Stale shani-update lock ───────────────────────────────────────────────
    # Lock file is in XDG_RUNTIME_DIR or ~/.cache — if it survives across boots
    # (i.e. lives in a persistent location) and is old, the update process died
    local _login_u_dep="${SUDO_USER:-${SHANI_CALLER_USER:-${USER:-}}}"
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
    # Key 7B927BFFD4A9EAAA8B666B77DE217F3DA8014792 must be imported for image verification.
    # The key ships locally at /etc/shani-keys/signing.asc — no network required.
    local gpg_key="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"
    local gpg_key_file="/etc/shani-keys/signing.asc"
    if gpg --batch --list-keys "$gpg_key" &>/dev/null 2>&1; then
        _row "GPG key"    "OK  signing key imported"
    elif [[ -f "$gpg_key_file" ]]; then
        _row "GPG key"    "!!  signing key not in keyring — image verification will fail"
        _rec "Import GPG signing key: gpg --import ${gpg_key_file}  [auto]"
    else
        _row "GPG key"    "!!  signing key not in keyring — image verification will fail"
        _rec "Import GPG signing key: gpg --keyserver keys.openpgp.org --recv-keys ${gpg_key}  [auto]"
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

    # ── shani-update last check ───────────────────────────────────────────────
    # Shows the last line from the user's shani-update.log so the report gives
    # a quick snapshot of when the update checker last ran and what it found.
    local _upd_login_u="${SUDO_USER:-${SHANI_CALLER_USER:-${USER:-}}}"
    local _upd_home; _upd_home=$(getent passwd "${_upd_login_u}" 2>/dev/null | cut -d: -f6 || echo "$HOME")
    local upd_log="${_upd_home}/.cache/shani-update.log"
    if [[ -f "$upd_log" ]]; then
        local last_raw; last_raw=$(tail -1 "$upd_log" 2>/dev/null || echo "")
        if [[ -n "$last_raw" ]]; then
            local last_ts; last_ts=$(echo "$last_raw" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1 || echo "?")
            local last_line; last_line=$(echo "$last_raw" | sed 's/\[[0-9 :-]*\] *//' | sed 's/^[0-9-]* [0-9:]* //' || echo "$last_raw")
            _row "Upd log"    "--  ${last_ts}: ${last_line:0:60}"
        fi
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
        _row "Subvolumes"  "!!  not mounted: ${sv_missing[*]}"
        _rec "Critical Btrfs subvolumes not mounted (${sv_missing[*]}) — check fstab / shanios-tmpfiles-data.service"
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
    if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then
        _row "Status"    "OK  enabled"
    else
        _row "Status"    "!!  disabled"
        _rec "Enable Secure Boot in BIOS/UEFI for full boot chain protection"
    fi

    local mok_count
    mok_count=$(mokutil --list-enrolled 2>/dev/null | grep -c 'SHA1 Fingerprint' || echo "0")
    if (( mok_count > 0 )); then
        _row "MOK enrol" "OK  ${mok_count} key(s) enrolled"
    else
        _row "MOK enrol" "!!  no keys enrolled"
        _rec "Enroll MOK: mokutil --import /etc/secureboot/keys/MOK.der --root-pw, then reboot"
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
            _rec "MOK signing key has expired — regenerate: gen-efi configure <slot> then re-enroll via mokutil"
        elif (( expiry_epoch > 0 && days_left < 90 )); then
            _row "MOK keys"  "!   expires in ${days_left} days (${expiry})"
            _rec "MOK cert expires in ${days_left} days — plan renewal before expiry to avoid Secure Boot breakage"
        else
            _row "MOK keys"  "OK  present (expires: ${expiry})"
        fi
    else
        _row "MOK keys"  "!!  missing"
        _rec "MOK signing keys missing — run: gen-efi configure <slot>"
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
            _rec "MOK key/cert mismatch — regenerate: gen-efi configure <slot>"
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
        _row "UKI tools"  "!!  missing: ${missing_tools[*]} — gen-efi / UKI rebuild will fail"
        _rec "Install missing UKI build tools: ${missing_tools[*]}"
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
        _row "LSMs"  "--  ${active}/${total} active (${missing_build[*]} not compiled in)"
    else
        _row "LSMs"  "!!  missing at runtime: ${missing_lsms[*]}"
        _rec "LSMs not active: ${missing_lsms[*]} — check lsm= kernel cmdline"
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

    # Sysctl hardening table: key  target  cmp(min|max|eq|info)  label
    # kernel.unprivileged_userns_clone: required =1 when rootless containers are
    # present (Podman/Distrobox/LXC); purely advisory when they are not.
    local _userns_cmp="info"
    local _userns_label="restrict user namespaces (set to 1 if using rootless containers)"
    if command -v podman &>/dev/null || command -v distrobox &>/dev/null || \
       command -v lxc &>/dev/null || command -v lxd &>/dev/null; then
        _userns_cmp="eq"
        _userns_label="required for rootless containers (Podman/Distrobox/LXC)"
    fi

    local sysctl_table=(
        # ── Kernel info leaks ──────────────────────────────────────────────────
        "kernel.kptr_restrict"               "1"  "min"  "hide kernel pointers from non-root"
        "kernel.dmesg_restrict"              "1"  "eq"   "restrict dmesg to root"
        # ── ASLR ──────────────────────────────────────────────────────────────
        "kernel.randomize_va_space"          "2"  "eq"   "full ASLR (stack+heap+mmap)"
        # ── BPF ───────────────────────────────────────────────────────────────
        "kernel.unprivileged_bpf_disabled"   "1"  "min"  "disable unprivileged BPF"
        "net.core.bpf_jit_harden"            "2"  "min"  "harden BPF JIT"
        "net.core.bpf_jit_kallsyms"          "0"  "eq"   "hide BPF JIT addresses from kallsyms"
        # ── ptrace ────────────────────────────────────────────────────────────
        "kernel.yama.ptrace_scope"           "1"  "min"  "restrict ptrace to parent processes"
        # ── perf ──────────────────────────────────────────────────────────────
        "kernel.perf_event_paranoid"         "2"  "min"  "restrict perf_event access to root"
        # ── core dumps ────────────────────────────────────────────────────────
        "fs.suid_dumpable"                   "0"  "eq"   "prevent suid coredumps leaking sensitive memory"
        # ── filesystem hardening ───────────────────────────────────────────────
        "fs.protected_hardlinks"             "1"  "eq"   "block hardlink attacks in sticky dirs"
        "fs.protected_symlinks"              "1"  "eq"   "block symlink TOCTOU attacks in sticky dirs"
        # ── SysRq (advisory — policy choice on desktop) ───────────────────────
        "kernel.sysrq"                       "0"  "info" "disable SysRq (allows unauth reboot/kill if console access)"
        # ── network: ICMP redirects ────────────────────────────────────────────
        "net.ipv4.conf.all.accept_redirects"     "0"  "max"  "ignore IPv4 ICMP redirects (all)"
        "net.ipv4.conf.default.accept_redirects" "0"  "max"  "ignore IPv4 ICMP redirects (default)"
        "net.ipv6.conf.all.accept_redirects"     "0"  "max"  "ignore IPv6 ICMP redirects (all)"
        "net.ipv6.conf.default.accept_redirects" "0"  "max"  "ignore IPv6 ICMP redirects (default)"
        "net.ipv4.conf.all.send_redirects"       "0"  "max"  "do not send ICMP redirects (not a router)"
        "net.ipv4.conf.default.send_redirects"   "0"  "max"  "do not send ICMP redirects (default)"
        # ── network: source routing ────────────────────────────────────────────
        "net.ipv4.conf.all.accept_source_route"     "0"  "max"  "ignore IP source routing (obsolete, MITM vector)"
        "net.ipv4.conf.default.accept_source_route" "0"  "max"  "ignore IP source routing (default)"
        # ── network: TCP hardening ─────────────────────────────────────────────
        "net.ipv4.tcp_syncookies"            "1"  "eq"   "TCP SYN cookies (SYN flood mitigation)"
        "net.ipv4.tcp_rfc1337"               "1"  "eq"   "protect against TCP time-wait assassination"
        # ── network: advisory ─────────────────────────────────────────────────
        "net.ipv4.conf.all.rp_filter"        "1"  "info" "reverse path filter (safe on single-homed)"
        # ── user namespaces ────────────────────────────────────────────────────
        "kernel.unprivileged_userns_clone"   "1"  "$_userns_cmp"  "$_userns_label"
    )
    local sc_ok=0 sc_total=0 sc_warn=() sc_info=()
    local i=0
    while (( i < ${#sysctl_table[@]} )); do
        local key="${sysctl_table[$i]}"       target="${sysctl_table[$((i+1))]}"
        local cmp="${sysctl_table[$((i+2))]}" label="${sysctl_table[$((i+3))]}"
        i=$(( i + 4 ))
        local actual; actual=$(sysctl -n "$key" 2>/dev/null || echo "")
        [[ -z "$actual" ]] && continue
        if [[ "$cmp" == "info" ]]; then
            [[ "$actual" != "$target" ]] && sc_info+=("${key}=${actual}  (recommended ${target} — ${label})")
            continue
        fi
        sc_total=$(( sc_total + 1 ))
        local pass=0
        case "$cmp" in
            min) [[ "$actual" =~ ^[0-9]+$ ]] && (( actual >= target )) && pass=1 ;;
            max) [[ "$actual" =~ ^[0-9]+$ ]] && (( actual <= target )) && pass=1 ;;
            eq)  [[ "$actual" == "$target" ]] && pass=1 ;;
        esac
        if (( pass )); then
            sc_ok=$(( sc_ok + 1 ))
        else
            sc_warn+=("${key}=${actual}  (want ${cmp} ${target} — ${label})")
        fi
    done
    if [[ ${#sc_warn[@]} -eq 0 ]]; then
        _row "Sysctl"    "OK  ${sc_ok}/${sc_total} hardening keys correct"
    else
        _row "Sysctl"    "!   ${sc_ok}/${sc_total} correct"
        for w in "${sc_warn[@]}"; do _row2 "!  $w"; done
        _rec "Sysctl hardening gaps — check /etc/sysctl.d/"
    fi
    for info in "${sc_info[@]}"; do _row2 "--  $info"; done


    local bad_mods=()
    for mod in mei mei_me pcspkr; do
        lsmod 2>/dev/null | grep -qw "$mod" && bad_mods+=("$mod")
    done
    if [[ ${#bad_mods[@]} -eq 0 ]]; then
        _row "Blacklist"  "OK  mei/mei_me/pcspkr not loaded"
    else
        _row "Blacklist"  "!   loaded but should be blacklisted: ${bad_mods[*]}"
        _rec "Modules ${bad_mods[*]} should be blacklisted — check /etc/modprobe.d/"
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
                _row "Enrolled"  "OK  auto-unlock active"
            else
                _row "Enrolled"  "!!  not enrolled"
                _rec "TPM2 not enrolled for auto-unlock — run: gen-efi enroll-tpm2  [auto]"
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
        _rec "${aa_denials} AppArmor denial(s) this boot — check: journalctl -k -b 0 | grep 'apparmor.*DENIED'"
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
}

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
                    if (( temp >= 70 )); then
                        _row "Disk temp"  "!!  ${temp}°C — critically hot"
                        _rec "Disk temperature is ${temp}°C — check cooling"
                    elif (( temp > 55 )); then
                        _row "Disk temp"  "!   ${temp}°C (warm)"
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

_section_storage() {
    _head "Storage"

    # Free space with threshold warning — Btrfs can ENOSPC before df shows 0
    local btrfs_free_bytes btrfs_free_gb
    btrfs_free_bytes=$(btrfs filesystem usage -b / 2>/dev/null \
        | awk '/Free \(estimated\):/{print $3}' || echo "0")
    if [[ "$btrfs_free_bytes" =~ ^[0-9]+$ ]] && (( btrfs_free_bytes > 0 )); then
        btrfs_free_gb=$(awk "BEGIN{printf \"%.1f\", $btrfs_free_bytes/1073741824}")
        local free_gb_int; free_gb_int=$(awk "BEGIN{printf \"%d\", $btrfs_free_bytes/1073741824}")
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

    # Btrfs device error stats — most actionable low-level corruption signal
    local dev_stats; dev_stats=$(btrfs device stats / 2>/dev/null || true)
    if [[ -n "$dev_stats" ]]; then
        local nonzero; nonzero=$(echo "$dev_stats" | awk '$NF != "0" {print}' || true)
        if [[ -n "$nonzero" ]]; then
            _row "Dev errors" "!!  non-zero error counters detected"
            echo "$nonzero" | while IFS= read -r line; do _row2 "!  $line"; done
            _rec "Btrfs device errors detected — run: btrfs device stats / and check drive health"
        else
            _row "Dev errors" "OK  all zero"
        fi
    fi

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

    # ── Btrfs dedup (bees) ────────────────────────────────────────────────────
    # beesd@<uuid> deduplicates the Btrfs filesystem in the background.
    # The unit name is derived from the filesystem UUID — check both the plain
    # label device and the LUKS mapper so encrypted systems are covered.
    local bees_uuid
    bees_uuid=$(blkid -s UUID -o value "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null || true)
    [[ -z "$bees_uuid" && -e "/dev/mapper/${ROOTLABEL}" ]] && \
        bees_uuid=$(blkid -s UUID -o value "/dev/mapper/${ROOTLABEL}" 2>/dev/null || true)
    if [[ -n "$bees_uuid" ]]; then
        local bees_unit="beesd@${bees_uuid}"
        local bees_conf="/etc/bees/${bees_uuid}.conf"
        local bees_st; bees_st=$(systemctl is-active "$bees_unit" 2>/dev/null || echo "inactive")
        local bees_en; bees_en=$(systemctl is-enabled "$bees_unit" 2>/dev/null || echo "disabled")
        if [[ "$bees_st" == "active" ]]; then
            # Show last-run stats if available from the journal
            local bees_dedup=""
            bees_dedup=$(journalctl -u "$bees_unit" -n 50 --no-pager -q 2>/dev/null \
                | grep -oE 'deduped [0-9.]+ [KMGT]?B' | tail -1 || echo "")
            _row "bees"      "OK  ${bees_unit} running${bees_dedup:+  (${bees_dedup})}"
        elif [[ ! -f "$bees_conf" ]]; then
            _row "bees"      "--  not configured (run beesd-setup to enable dedup)"
            _rec "bees not configured — run: beesd-setup, then: systemctl enable --now ${bees_unit}"
        elif [[ "$bees_en" == "enabled" ]]; then
            _row "bees"      "!!  ${bees_unit} enabled but not running (${bees_st})"
            _rec "bees enabled but not running — run: systemctl start ${bees_unit}  [auto]"
        else
            _row "bees"      "!   ${bees_unit} configured but not enabled"
            _rec "bees not running — run: systemctl enable --now ${bees_unit}  [auto]"
        fi
    else
        _row "bees"      "--  could not determine Btrfs UUID for ${ROOTLABEL}"
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

_section_services() {
    _head "Services"

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
        local rt_display; rt_display=$(echo "${rt_members[*]}" | tr -s ' ' | xargs)
        # Check every login user is in the realtime group
        local _rt_login=() _missing_rt=()
        while IFS=: read -r name _ uid _ _ _ shell; do
            [[ "$uid" -ge 1000 ]] 2>/dev/null || continue
            [[ "$name" == "nobody" ]] && continue
            [[ "$shell" == */nologin || "$shell" == */false ]] && continue
            _rt_login+=("$name")
        done < /etc/passwd 2>/dev/null || true
        for u in "${_rt_login[@]}"; do
            id -nG "$u" 2>/dev/null | grep -qw realtime || _missing_rt+=("$u")
        done
        if [[ ${#_missing_rt[@]} -gt 0 ]]; then
            _row "realtime"  "!   users missing from group: ${_missing_rt[*]}"
            _rec "User(s) ${_missing_rt[*]} not in 'realtime' group — add: usermod -aG realtime <user>"
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
                | awk '{print $3}' | grep -qx "$_LOGIN_USER" && _has_session=1
            if (( _has_session )); then
                _row "PipeWire"  "!   not running for ${_LOGIN_USER} — audio will be silent"
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

    # ── Failed units ──────────────────────────────────────────────────────────
    local failed_units=()
    mapfile -t failed_units < <(
        systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null \
            | awk '{print $1}' || true)
    if [[ ${#failed_units[@]} -eq 0 ]]; then
        _row "Units"     "OK  no failed systemd units"
    else
        _row "Units"     "!!  ${#failed_units[@]} failed: ${failed_units[*]}"
        _rec "Failed units: ${failed_units[*]} — run: systemctl status <unit>"
    fi
}

_section_packages() {
    _head "Packages & Containers"

    # ── Flatpak ───────────────────────────────────────────────────────────────
    if command -v flatpak &>/dev/null; then
        local flatpak_sys; flatpak_sys=$(systemctl is-active flatpak-update-system.timer 2>/dev/null || echo "inactive")
        local flatpak_apps flatpak_remotes
        flatpak_apps=$(timeout 5 flatpak list --app --columns=application 2>/dev/null | wc -l || echo "?")
        flatpak_remotes=$(flatpak remotes 2>/dev/null | grep -c '.' || echo "0")
        if [[ "$flatpak_sys" == "active" ]]; then
            _row "Flatpak"    "OK  auto-update active  (${flatpak_apps} apps, ${flatpak_remotes} remote(s))"
        else
            _row "Flatpak"    "!   auto-update timer not active  (${flatpak_apps} apps)"
            _rec "Flatpak auto-update timer not active — run: systemctl enable --now flatpak-update-system.timer  [auto]"
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
        if [[ "$snapd_sock" == "active" && "$snapd_aa" == "active" ]]; then
            _row "Snap"       "OK  snapd + AppArmor active${snap_count:+  (${snap_count} snaps)}"
        elif [[ "$snapd_sock" == "active" ]]; then
            _row "Snap"       "!   snapd active but AppArmor service is ${snapd_aa} — confinement not enforced"
            _rec "snapd.apparmor.service not active — snap confinement broken  [auto]"
        else
            _row "Snap"       "!!  @snapd mounted but snapd.socket is ${snapd_sock}"
            _rec "snapd.socket not active — run: systemctl enable --now snapd.socket snapd.apparmor.service  [auto]"
        fi
    fi

    # ── Nix ───────────────────────────────────────────────────────────────────
    if findmnt -n /nix &>/dev/null; then
        if systemctl is-active --quiet nix-daemon.socket 2>/dev/null; then
            local nix_ver=""
            nix_ver=$(nix --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
            local nix_channels=""
            local _nix_user="${SUDO_USER:-${SHANI_CALLER_USER:-${USER:-}}}"
            if [[ -n "$_nix_user" ]]; then
                nix_channels=$(timeout 5 runuser -u "$_nix_user" -- nix-channel --list 2>/dev/null | wc -l || echo "")
            fi
            _row "Nix"        "OK  nix-daemon active${nix_ver:+  (v${nix_ver})}${nix_channels:+  ${nix_channels} channel(s)}"
        else
            _row "Nix"        "!!  @nix mounted but nix-daemon.socket not active"
            _rec "nix-daemon.socket not active — run: systemctl enable --now nix-daemon.socket  [auto]"
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
        _rec "shani-update.timer not enabled — run as your user: systemctl --user enable --now shani-update.timer"
    fi

    # ── Podman ────────────────────────────────────────────────────────────────
    if command -v podman &>/dev/null; then
        local podman_sys_st podman_usr_st podman_ver=""
        podman_sys_st=$(systemctl is-active podman.socket 2>/dev/null || echo "inactive")
        podman_usr_st=$(_sysd_user is-active podman.socket 2>/dev/null || echo "inactive")
        podman_ver=$(podman --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        # Rootless capable: needs unprivileged userns + subuid
        local rootless_ok=1
        local _rl_user="${SUDO_USER:-${SHANI_CALLER_USER:-${USER:-}}}"
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
    fi

    # ── Waydroid ─────────────────────────────────────────────────────────────
    if findmnt -n /var/lib/waydroid &>/dev/null; then
        local waydroid_st; waydroid_st=$(systemctl is-active waydroid-container 2>/dev/null || echo "inactive")
        if [[ "$waydroid_st" == "active" ]]; then
            _row "Waydroid"   "OK  Android container active"
        else
            _row "Waydroid"   "!   @waydroid mounted but container service is ${waydroid_st}"
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

    booted_uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${current_slot}.efi"
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
        if [[ -n "$default_entry" && -n "$current_slot" ]]; then
            if echo "$default_entry" | grep -qi "$current_slot"; then
                _row "Boot default" "OK  default entry targets @${current_slot}"
            else
                _row "Boot default" "!!  default entry '${default_entry}' does not match current slot @${current_slot}"
                _rec "loader.conf default= points to wrong slot — run: gen-efi configure ${current_slot}  [auto]"
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
        _row "Orphans"   "!   ${orphans[*]}"
        _rec "Orphaned boot entries (${orphans[*]}) — run: shani-health --fix  [auto]"
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
    while IFS=: read -r name _ uid _ _ _ shell; do
        [[ "$uid" -ge 1000 ]] 2>/dev/null || continue
        [[ "$name" == "nobody" ]] && continue
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        login_users+=("$name")
    done < /etc/passwd 2>/dev/null || true

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
    while IFS=: read -r name _ uid _ _ _ shell; do
        [[ "$uid" -ge 1000 ]] 2>/dev/null || continue
        [[ "$name" == "nobody" ]] && continue
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        login_users+=("$name")
    done < /etc/passwd 2>/dev/null || true
    _row "Login"     "--  ${login_users[*]:-none detected}"

    local wheel_line wheel_members=()
    wheel_line=$(getent group wheel 2>/dev/null || grep '^wheel:' /etc/group 2>/dev/null || true)
    [[ -n "$wheel_line" ]] && IFS=',' read -ra wheel_members <<< "${wheel_line##*:}"
    if [[ ${#wheel_members[@]} -gt 0 && -n "${wheel_members[0]}" ]]; then
        _row "Wheel"     "--  ${wheel_members[*]}"
    else
        _row "Wheel"     "--  no members"
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
              _rec "Root has a password — lock: passwd -l root  [auto]" ;;
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
        while IFS=: read -r name _ uid _ _ _ shell; do
            [[ "$uid" -ge 1000 ]] 2>/dev/null || continue
            [[ "$name" == "nobody" ]] && continue
            [[ "$shell" == */nologin || "$shell" == */false ]] && continue
            _sub_login_users+=("$name")
        done < /etc/passwd 2>/dev/null || true
        for u in "${_sub_login_users[@]}"; do
            if ! grep -q "^${u}:" /etc/subuid 2>/dev/null || \
               ! grep -q "^${u}:" /etc/subgid 2>/dev/null; then
                sub_missing+=("$u")
            fi
        done
        if [[ ${#sub_missing[@]} -gt 0 ]]; then
            _row "subuid"   "!!  missing for: ${sub_missing[*]} — rootless Podman/Distrobox will fail"
            _rec "subuid/subgid missing for ${sub_missing[*]} — run: usermod --add-subuids 100000-165535 --add-subgids 100000-165535 <user>"
        else
            _row "subuid"   "OK  configured for all users"
        fi
    fi
}


###############################################################################
### system_info — master status report                                       ###
###############################################################################

system_info() {
    _recs_reset

    local _esp_mounted=0
    _esp_mount

    # When running under sudo/pkexec, --user systemctl queries must target the
    # real user's session. Priority: SUDO_USER (sudo) → SHANI_CALLER_USER (pkexec)
    # → current USER. _sysd_user() also sets DBUS_SESSION_BUS_ADDRESS so that
    # systemctl --user can talk to the user's D-Bus socket when needed.
    local _LOGIN_USER="${SUDO_USER:-${SHANI_CALLER_USER:-${USER:-$(id -un)}}}"
    _sysd_user() {
        if [[ "$_LOGIN_USER" != "root" && -n "$_LOGIN_USER" ]]; then
            local _uid; _uid=$(id -u "$_LOGIN_USER" 2>/dev/null || echo "")
            if [[ -n "$_uid" ]]; then
                sudo -u "$_LOGIN_USER" \
                    env \
                    XDG_RUNTIME_DIR="/run/user/${_uid}" \
                    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
                    systemctl --user "$@"
            else
                sudo -u "$_LOGIN_USER" systemctl --user "$@"
            fi
        else
            systemctl --user "$@"
        fi
    }

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
        [[ "$(mokutil --sb-state 2>/dev/null)" == *"SecureBoot enabled"* ]] && sb_active="yes"

    echo ""
    printf "  ${_C_BOLD}┌──────────────────────────────────────────────┐${_C_RESET}\n"
    printf "  ${_C_BOLD}│  %-44s│${_C_RESET}\n" "ShaniOS System Status"
    printf "  ${_C_BOLD}│  ${_C_DIM}%-44s${_C_BOLD}│${_C_RESET}\n" "shani-health v${SCRIPT_VERSION}  $(date '+%Y-%m-%d %H:%M')"
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
    _section_services
    _section_packages

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
    _log_section "Security Auto-Fix"
    local fixed=0 failed=0

    # Internal helper: run a fix, updating counters
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

    # Stale boot failure marker — clear it if current boot is healthy
    if [[ -f "$DATA_BOOT_FAIL" ]]; then
        local _bfail_booted; _bfail_booted=$(_get_booted_subvol)
        local _bfail_current; _bfail_current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
        if [[ "$_bfail_booted" == "$_bfail_current" ]]; then
            local _bfail_slot; _bfail_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "?")
            _log "Clearing stale boot_failure marker for @${_bfail_slot} (current boot @${_bfail_booted} is healthy)..."
            if rm -f "$DATA_BOOT_FAIL" "$DATA_BOOT_FAIL_ACKED" 2>/dev/null; then
                _log_ok "Stale boot_failure marker cleared"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "Failed to clear boot_failure marker"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # Missing system groups — create without fixed GIDs (Arch assigns them dynamically)
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

    # Firewall
    command -v firewall-cmd &>/dev/null && ! systemctl is-active --quiet firewalld 2>/dev/null && \
        _apply_fix "Enable firewalld"  systemctl enable --now firewalld

    # fail2ban
    command -v fail2ban-client &>/dev/null && ! systemctl is-active --quiet fail2ban 2>/dev/null && \
        _apply_fix "Enable fail2ban"  systemctl enable --now fail2ban

    # Lock root
    local root_st; root_st=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "")
    [[ "$root_st" == "P" ]] && _apply_fix "Lock root account"  passwd -l root

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
    fi

    # bees
    local bees_uuid
    bees_uuid=$(blkid -s UUID -o value "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null || true)
    [[ -z "$bees_uuid" && -e "/dev/mapper/${ROOTLABEL}" ]] && \
        bees_uuid=$(blkid -s UUID -o value "/dev/mapper/${ROOTLABEL}" 2>/dev/null || true)
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
    local _gpg_key="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"
    local _gpg_key_file="/etc/shani-keys/signing.asc"
    if ! gpg --batch --list-keys "$_gpg_key" &>/dev/null 2>&1; then
        if [[ -f "$_gpg_key_file" ]]; then
            _log "Importing ShaniOS signing key from ${_gpg_key_file}..."
            if gpg --batch --import "$_gpg_key_file" 2>/dev/null; then
                _log_ok "GPG signing key imported"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "GPG key import failed — check: gpg --import ${_gpg_key_file}"
                failed=$(( failed + 1 ))
            fi
        else
            _log "Fetching ShaniOS signing key from keyserver (local file absent)..."
            if gpg --batch --keyserver keys.openpgp.org --recv-keys "$_gpg_key" 2>/dev/null; then
                _log_ok "GPG signing key imported from keyserver"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "GPG key fetch failed — try manually: gpg --keyserver keys.openpgp.org --recv-keys ${_gpg_key}"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # TPM2 — requires user interaction
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
        local _lsm_booted; _lsm_booted=$(_get_booted_subvol)
        if [[ "$_lsm_booted" != "unknown" ]]; then
            _log "lsm= cmdline incorrect — regenerating UKI for @${_lsm_booted}..."
            if "$GENEFI_BIN" configure "$_lsm_booted" 2>&1; then
                _log_ok "UKI regenerated for @${_lsm_booted} — reboot to apply correct lsm="
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
            local booted; booted=$(_get_booted_subvol)
            if [[ "$booted" != "unknown" && -x "$GENEFI_BIN" ]]; then
                _log "Regenerating UKI for @${booted} (resume_offset ${cmdline_off} -> ${actual_off})..."
                if "$GENEFI_BIN" configure "$booted" 2>&1; then
                    _log_ok "UKI regenerated for @${booted}"
                    fixed=$(( fixed + 1 ))
                else
                    _log_warn "UKI regeneration failed"
                    failed=$(( failed + 1 ))
                fi
            fi
        fi
    fi

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
        local _km_booted; _km_booted=$(_get_booted_subvol)
        if [[ "$_km_booted" != "unknown" && -x "$GENEFI_BIN" ]]; then
            _log "Keymap mismatch (UKI: ${_cmdline_km}, vconsole: ${_vconsole_km}) — regenerating UKI for @${_km_booted}..."
            if "$GENEFI_BIN" configure "$_km_booted" 2>&1; then
                _log_ok "UKI regenerated for @${_km_booted} with keymap ${_vconsole_km}"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "UKI regeneration failed"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

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
    if (( fixed + failed == 0 )); then
        _log_ok "Nothing to fix — system already hardened"
    else
        _log "Fixed: ${fixed} | Failed: ${failed}"
    fi
    echo ""
    _log "Run 'shani-health' to verify"
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

    # Only allow clearing when the current boot is healthy (booted == current-slot)
    if [[ "$booted" != "$current" ]]; then
        _die "System is in fallback mode (booted @${booted}, current @${current}) — use 'shani-deploy --rollback' instead"
    fi

    _log "Current boot is healthy (@${booted}). Clearing stale failure marker for @${failed_slot}..."
    rm -f "$DATA_BOOT_FAIL" "$DATA_BOOT_FAIL_ACKED"
    _log_ok "boot_failure marker cleared. @${failed_slot} will be treated as a valid fallback again."
    _log    "To fully repair @${failed_slot}, run: shani-deploy --rollback"
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
### analyze_storage — delegates to shani-deploy --storage-info              ###
###############################################################################

analyze_storage() {
    [[ -x "$DEPLOY_BIN" ]] && { "$DEPLOY_BIN" --storage-info; return $?; }
    _die "shani-deploy not found at ${DEPLOY_BIN}"
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
        echo "=== shani-health ${SCRIPT_VERSION} bug report — $(date) ==="
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
  --fix          Auto-fix all [auto] issues
  --verify                UKI signatures + Btrfs data integrity check
  --history [N]           Last N deploy/rollback events from log (default: 50)
  -s, --storage-info      Btrfs compression/subvolume analysis (via shani-deploy)
  --clear-boot-failure    Clear a stale boot failure marker (when current boot is healthy)
  -v, --verbose           Verbose/debug output
  -h, --help              Show this help

Examples:
  shani-health                     Full status report
  shani-health --fix      Auto-fix automatable issues
  shani-health --verify            Deep integrity check
  shani-health --history 100       Last 100 deploy events
  shani-health --clear-boot-failure  Clear stale @green/@blue boot failure marker

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

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)          usage; exit 0 ;;
            -i|--info)          MODE="info";         shift ;;
            --fix)     MODE="fix"; shift ;;
            --verify)           MODE="verify";       shift ;;
            -s|--storage-info)  MODE="storage-info"; shift ;;
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
        info)           system_info ;;
        fix)   fix ;;
        verify)         verify_system; exit $? ;;
        history)        show_history "$HISTORY_LINES" ;;
        storage-info)   analyze_storage ;;
        clear-boot-failure) clear_boot_failure ;;

    esac
}

main "$@"
