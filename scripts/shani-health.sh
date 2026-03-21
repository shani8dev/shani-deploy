#!/bin/bash
# shani-health — ShaniOS system health, security, and diagnostics tool
# Standalone read-mostly companion to shani-deploy. Covers everything that
# is about inspecting and hardening the system, not about updating it.
# Usage:
#   shani-health                     Full system status report (default / --info)
#   shani-health --security          Security report: boot chain, encryption, users
#   shani-health --boot              Boot report: slots, entries, deployment, UKI
#   shani-health --network           Network report: NM, DNS, VPN, firewall, servers
#   shani-health --hardware          Hardware report: CPU, disk, SMART, temps, firmware
#   shani-health --packages          Package report: flatpak, snap, nix, containers
#   shani-health --verify            Deep integrity check: UKI sigs + Btrfs scrub
#   shani-health --history [N]       Last N deploy/rollback events (default: 50)
#   shani-health --storage-info      Btrfs storage analysis (native, no shani-deploy needed)
#   shani-health --journal [level]   Show journal entries (crit/err/warning)
#   shani-health --clean-logs [DAYS] Clean old app logs from /var/log
#   shani-health --export-logs [DIR] Bundle logs + state for bug reports
# Install:  cp shani-health /usr/local/bin/shani-health && chmod +x $_
# Requires: root (auto-escalates via pkexec or sudo)
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
readonly USER_SETUP_BIN="/usr/abin/shani-user-setup"
readonly DEPLOY_LOG="/var/log/shanios-deploy.log"
readonly CHANNEL_FILE="/etc/shani-channel"
readonly GPG_SIGNING_KEY="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"
readonly GPG_SIGNING_KEY_FILE="/etc/shani-keys/signing.asc"

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
_SYM_IDLE="○"
_SYM_READY="◉"
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

# Status-prefixed row: _row KEY "OK|!!|!|--|->|<- value"
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
        "~~") coloured="${_C_CYAN}${_SYM_IDLE}${_C_RESET}  ${rest}" ;;
        ">>") coloured="${_C_GREEN}${_C_DIM}${_SYM_READY}${_C_RESET}  ${rest}" ;;
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
        "~~")  coloured="${_C_CYAN}${_SYM_IDLE}${_C_RESET}  ${rest}" ;;
        ">>")  coloured="${_C_GREEN}${_C_DIM}${_SYM_READY}${_C_RESET}  ${rest}" ;;
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

# Lightweight subsection divider — used for "Optional" group at bottom of sections
_subhead() {
    printf "  ${_C_DIM}— %s —${_C_RESET}\n" "${1,,}"
}

_OPT_BUF=""          # temp file path, set by _optional_begin

_optional_begin() {
    _OPT_BUF=$(mktemp /tmp/.shani-opt.XXXXXX)
    # Redirect fd 1 to the temp file, save original fd 1 as fd 9
    exec 9>&1 >"$_OPT_BUF"
}

_optional_end() {
    exec 1>&9 9>&-
    if [[ -s "$_OPT_BUF" ]]; then
        _subhead "Optional"
        cat "$_OPT_BUF"
    fi
    rm -f "$_OPT_BUF"
    _OPT_BUF=""
}

_SRV_OPT_BUF=""

_srv_is_notable() {
    # Returns 0 (true) if any of the given units is active or enabled
    local u
    for u in "$@"; do
        systemctl is-active  --quiet "$u" 2>/dev/null && return 0
        systemctl is-enabled --quiet "$u" 2>/dev/null && return 0
    done
    return 1
}

_srv_opt_begin() {
    [[ -z "$_SRV_OPT_BUF" ]] && _SRV_OPT_BUF=$(mktemp /tmp/.shani-srv-opt.XXXXXX)
    exec 9>&1 >>"$_SRV_OPT_BUF"
}

_srv_opt_end() {
    exec 1>&9 9>&-
}

_srv_opt_flush() {
    if [[ -n "$_SRV_OPT_BUF" && -s "$_SRV_OPT_BUF" ]]; then
        _subhead "Optional"
        cat "$_SRV_OPT_BUF"
    fi
    rm -f "$_SRV_OPT_BUF"
    _SRV_OPT_BUF=""
}

# Emit a single optional-section row (wraps _srv_opt_begin/_row/_srv_opt_end).
_srv_opt_row() { _srv_opt_begin; _row "$@"; _srv_opt_end; }
_srv_opt_row2() { _srv_opt_begin; _row "$1" "$2"; _row2 "$3"; _srv_opt_end; }

###############################################################################
### Shared helpers                                                           ###
###############################################################################

_is_mounted() { findmnt -M "$1" &>/dev/null; }

_get_booted_subvol() {
    local subvol=""
    # Prefer rootflags=...subvol=@name... from /proc/cmdline
    local rootflags
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2- || echo "")
    if [[ -n "$rootflags" ]]; then
        subvol=$(echo "$rootflags" | grep -oP '(?<=subvol=@?)[^,]+' | head -1 || echo "")
        subvol="${subvol#@}"
    fi
    # Fallback: top-level subvol=@name directly on cmdline (no rootflags wrapper)
    if [[ -z "$subvol" ]]; then
        subvol=$(grep -oP '(?<=subvol=@?)[^ ,]+' /proc/cmdline 2>/dev/null | head -1 || echo "")
        subvol="${subvol#@}"
    fi
    # Last resort: btrfs default subvolume
    [[ -z "$subvol" ]] && \
        subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}' || echo "")
    echo "${subvol:-unknown}"
}

# Mount ESP if not already mounted; sets _esp_mounted=1 if we did it ourselves.
_esp_mounted=0  # global; managed by _esp_mount/_esp_umount
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

# Print accumulated recommendations. Optional arg: empty-state message.
# Usage: _recs_print "No issues found"   or   _recs_print
_recs_print() {
    local empty_msg="${1:-No issues found}"
    echo ""
    if [[ ${#_RECS[@]} -eq 0 ]]; then
        printf "  ${_C_GREEN}${_C_BOLD}${_SYM_OK}  %s${_C_RESET}\n" "$empty_msg"
    else
        printf "  ${_C_BOLD}${_C_YELLOW}Recommendations (%d)${_C_RESET}\n" "${#_RECS[@]}"
        printf "  ${_C_DIM}%s${_C_RESET}\n" "──────────────────────────────────────────────────────"
        local i=1
        for rec in "${_RECS[@]}"; do
            printf "    ${_C_BOLD}%2d.${_C_RESET}  %b\n" "$i" "$rec"
            i=$(( i + 1 ))
        done
        echo ""
    fi
    echo ""
}

# Return the active NM dns= setting (default if unset).
_nm_dns() {
    local _d
    _d=$(grep -rshE '^dns[[:space:]]*='         /usr/lib/NetworkManager/conf.d/         /etc/NetworkManager/conf.d/         /etc/NetworkManager/NetworkManager.conf 2>/dev/null         | tail -1 | awk -F= '{print $2}' | tr -d '[:space:]' || echo "")
    echo "${_d:-default}"
}

# Check a standalone DNS resolver for NM conflict.
# Usage: _dns_conflict_row <label> <svc> <nm_dns_mode>
# Prints !! row + rec if conflict, ! row if enabled but not running with dns=none.
_dns_conflict_row() {
    local label="$1" svc="$2" nm_dns="$3"
    if [[ "$nm_dns" == "none" ]]; then
        # NM delegates DNS ownership — resolver enabled but not running is a real problem
        _row "$label" "!   enabled but not running (NM dns=none expects it to own resolv.conf)"
    else
        _row "$label" "!!  enabled standalone — conflicts with NM dns=${nm_dns}; disable: systemctl disable --now ${svc}  or set NM dns=none first"
        _rec "${label} enabled standalone — conflicts with NM dns=${nm_dns}; disable: systemctl disable --now ${svc}"
    fi
}
# Warn when a caching DNS resolver is running but NM is still writing resolv.conf.
# Usage: _dns_resolver_active_warn <label> <name>
_dns_resolver_active_warn() {
    local label="$1" name="$2"
    local _d; _d=$(_nm_dns)
    [[ "$_d" == "none" ]] && return 0
    _row2 "!   NM dns=${_d} — set dns=none so ${name} owns /etc/resolv.conf"
    _rec "${name} running but NM dns!=none — add dns=none in /etc/NetworkManager/NetworkManager.conf"
}

# Row + rec for a VPN plugin that should be managed by NM, not standalone.
_nm_vpn_conflict() {
    local label="$1" svc="$2" plugin="$3"
    _row "$label" "!!  enabled standalone — conflicts with NM; disable: systemctl disable --now ${svc}"
    _rec "${label} enabled standalone — conflicts with NM-${plugin} plugin; disable: systemctl disable --now ${svc}"
}

# Check a caching DNS resolver: warn if running with wrong NM config, or use
# _dns_conflict_row if enabled-but-not-running.
# Usage: _check_dns_resolver <row_label> <svc_name> <is_active> [<is_enabled>]
# Callers still handle the OK row themselves (resolver-specific status info).

# Join array elements with a space, regardless of IFS.
# Usage: local s; s=$(_join "${arr[@]}")
_join() { local IFS=' '; echo "$*"; }

# Return a human-readable next-trigger time for a systemd timer.
_timer_next_fmt() {
    local unit="$1"
    local raw=""
    raw=$(systemctl show "$unit" --property=NextElapseUSecRealtime --value 2>/dev/null || echo "")
    [[ -z "$raw" || "$raw" == "0" ]] && \
        raw=$(systemctl show "$unit" --property=NextElapseUSecMonotonic --value 2>/dev/null || echo "")
    if [[ "$raw" =~ ^[0-9]+$ ]] && (( raw > 0 )); then
        date -d "@$(( raw / 1000000 ))" '+%Y-%m-%d %H:%M' 2>/dev/null || echo ""
    else
        echo ""
    fi
}

# Format a size in MiB as a human-readable string.
_mb_to_human() {
    local mb="${1:-0}"
    if [[ "$mb" =~ ^[0-9]+$ ]] && (( mb >= 1024 )); then
        awk "BEGIN{printf \"%.1f GB\", $mb/1024}"
    else
        echo "${mb} MB"
    fi
}

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
    local uuid=$(blkid -s UUID -o value "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null || true)
    [[ -z "$uuid" && -e "/dev/mapper/${ROOTLABEL}" ]] && \
        uuid=$(blkid -s UUID -o value "/dev/mapper/${ROOTLABEL}" 2>/dev/null || true)
    echo "${uuid:-}"
}

# True if a service/command is installed on this system.
# Checks binary presence OR systemd unit existence.
_svc_present() { command -v "$1" &>/dev/null || systemctl cat "$1" &>/dev/null 2>&1; }

# Recursive unmount helper used by analyze_storage (uses existing _is_mounted).
_umount_r() {
    local tgt="$1"
    _is_mounted "$tgt" || return 0
    umount -R "$tgt" 2>/dev/null || umount -R -l "$tgt" 2>/dev/null || true
}

# Check that a command exists AND is executable.
_is_executable() {
    local _path
    _path=$(command -v "$1" 2>/dev/null) || return 1
    [[ -x "$_path" ]]
}

# Like _is_executable but also emits a !! row and recommendation if the file exists
_check_tool_executable() {
    local _bin="$1"       # binary name to look up
    local _label="$2"     # display label for _row (e.g. "rkhunter")
    local _path
    _path=$(command -v "$_bin" 2>/dev/null) || return 1   # not installed — silent
    if [[ ! -x "$_path" ]]; then
        _row "$_label"  "!!  installed but not executable (${_path}) — fix: chmod +x ${_path}"
        _rec "${_label} binary is not executable — run: chmod +x ${_path}"
        return 1
    fi
    return 0
}

# Run a systemctl --user command as the calling user's session.
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
    local version profile channel slot_current
    version=$(     cat /etc/shani-version   2>/dev/null || echo "unknown")
    profile=$(     cat /etc/shani-profile   2>/dev/null || echo "unknown")
    channel=$(     cat "$CHANNEL_FILE"      2>/dev/null | tr -d '[:space:]' || echo "unknown")
    slot_current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "unknown")

    _head "OS"
    _row "Version"   "--  $version"
    _row "Profile"   "--  $profile"

    local hostname; hostname=$(cat /etc/hostname 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ -z "$hostname" ]]; then
        _row "Hostname"  "!   /etc/hostname is empty"
        _rec "Set a hostname: hostnamectl set-hostname mymachine"
    elif [[ "$hostname" == "localhost" ]]; then _row "Hostname"  "--  ${hostname}  (generic — consider personalising)"
    else
        _row "Hostname"  "--  ${hostname}"
    fi

    # /etc/hosts — hostname must resolve locally
    if [[ -f /etc/hosts && -n "$hostname" && "$hostname" != "localhost" ]]; then
        if ! grep -qE "^(127\.0\.0\.1|127\.0\.1\.1|::1)[[:space:]].*\b${hostname}\b" /etc/hosts 2>/dev/null; then
            _row "hosts"     "!   ${hostname} not in /etc/hosts — local hostname won't resolve"
            _rec "Add hostname to /etc/hosts (via overlay): echo '127.0.1.1 ${hostname}' >> /etc/hosts"
        fi
    fi

    if [[ -L /etc/localtime ]]; then
        local tz=""
        if command -v timedatectl &>/dev/null; then
            tz=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "")
        fi
        [[ -z "$tz" ]] && \
            tz=$(readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' || echo "")
        if [[ -z "$tz" ]]; then
            _row "Timezone"  "!!  /etc/localtime symlink is broken"
            _rec "Fix timezone: timedatectl set-timezone UTC (or your region)"
        else
            _row "Timezone"  "--  ${tz}"
        fi
    elif [[ -f /etc/localtime ]]; then
        _row "Timezone"  "--  (not a symlink — timedatectl may not work correctly)"
    else
        _row "Timezone"  "!!  /etc/localtime missing"
        _rec "Set timezone: timedatectl set-timezone UTC  (or your region)"
    fi

    if [[ "$channel" == "stable" || "$channel" == "latest" ]]; then
        _row "Channel"   "--  $channel"
    elif [[ "$channel" == "unknown" ]]; then _row "Channel"   "--  not set (defaults to stable)"
    else
        _row "Channel"   "!   unknown value: ${channel}  (expected stable or latest)"
        _rec "Invalid channel '${channel}' in ${CHANNEL_FILE} — set to 'stable' or 'latest'"
    fi
    local _uptime_str; _uptime_str=$(uptime -p 2>/dev/null | sed 's/^up //' || echo "unknown")
    local _uptime_days=0
    _uptime_days=$(awk '{print int($1/86400)}' /proc/uptime 2>/dev/null || echo "0")
    if (( _uptime_days >= 30 )); then
        if [[ -f "$DATA_REBOOT_NEEDED" ]]; then
            local _rver; _rver=$(cat "$DATA_REBOOT_NEEDED" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
            _row "Uptime"    "!   ${_uptime_str}  (${_uptime_days}d — v${_rver} pending, reboot to activate)"
            _rec "System has been up ${_uptime_days} days with a pending deploy (v${_rver}) — reboot to activate"
        else
            _row "Uptime"    "--  ${_uptime_str}  (${_uptime_days}d)"
        fi
    else
        _row "Uptime"    "--  ${_uptime_str}"
    fi

    # Validate profile is a known value
    if [[ "$profile" != "gnome" && "$profile" != "plasma" && "$profile" != "unknown" ]]; then
        _rec "Unknown shani-profile '${profile}' — expected 'gnome' or 'plasma'"
    fi

    # machine-id — must exist, be non-empty, and be 32 hex chars
    local mid=""
    mid=$(cat /etc/machine-id 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ -z "$mid" ]]; then
        _row "machine-id"  "!!  /etc/machine-id missing or empty"
        _rec "machine-id missing — run: systemd-machine-id-setup"
    elif ! [[ "$mid" =~ ^[0-9a-f]{32}$ ]]; then
        _row "machine-id"  "!   invalid format: ${mid}"
        _rec "machine-id '${mid}' is not a valid 32-char hex ID — run: systemd-machine-id-setup"
    else
        _row "machine-id"  "--  ${mid}"
    fi

    # Locale — /etc/locale.conf must exist and set LANG
    local sys_lang=""
    # localectl reads /etc/locale.conf and kernel cmdline — use it for the effective value
    if command -v localectl &>/dev/null; then
        sys_lang=$(localectl status 2>/dev/null \
            | awk -F'=' '/System Locale:/{gsub(/.*LANG=/,"",$0); print $1}' \
            | awk '{print $1}' | tr -d '"' || echo "")
    fi
    [[ -z "$sys_lang" ]] && [[ -f /etc/locale.conf ]] && \
        sys_lang=$(grep -E '^LANG=' /etc/locale.conf 2>/dev/null | cut -d= -f2- | tr -d '"' || echo "")
    if [[ -z "$sys_lang" ]]; then
        _row "Locale"     "!   LANG not set — locale not configured"
        _rec "Set LANG: echo LANG=en_US.UTF-8 >> /etc/locale.conf  (via /etc overlay)"
    else
        # Check locale is actually generated
        local locale_ok=1
        if command -v locale &>/dev/null; then
            local _locale_list; _locale_list=$(locale -a 2>/dev/null || echo "")
            if [[ -n "$_locale_list" ]]; then
                echo "$_locale_list" | grep -qx "${sys_lang}" || \
                    echo "$_locale_list" | grep -qx "${sys_lang%%.*}.utf8" || \
                    echo "$_locale_list" | grep -qx "${sys_lang%%.*}.UTF-8" || locale_ok=0
            fi
        fi
        if (( locale_ok )); then _row "Locale"     "OK  ${sys_lang}"
        else
            _row "Locale"     "!   ${sys_lang}  (not generated — run: locale-gen)"
            _rec "Locale '${sys_lang}' set but not generated — run: locale-gen"
        fi
    fi

    # Live keymap (what localectl reports as currently active, not just the UKI param)
    local live_keymap="" vconsole_km=""
    if command -v localectl &>/dev/null; then
        local _lctl_os; _lctl_os=$(localectl status 2>/dev/null || echo "")
        live_keymap=$(echo "$_lctl_os" \
            | awk -F': ' '/VC Keymap/{gsub(/^[[:space:]]+/,"",$2); print $2}' | head -1 || echo "")
        vconsole_km=$(echo "$_lctl_os" \
            | awk -F': +' '/VC Keymap:/{print $2}' | tr -d '[:space:]' || echo "")
    fi
    [[ -z "$vconsole_km" ]] && \
        vconsole_km=$(grep -E '^KEYMAP=' /etc/vconsole.conf 2>/dev/null \
            | cut -d= -f2 | tr -d "\"'" | tr -cd 'A-Za-z0-9._-' || echo "")
    if [[ -n "$live_keymap" && -n "$vconsole_km" && "$live_keymap" != "$vconsole_km" ]]; then
        _row "Keymap"      "!   live='${live_keymap}' but vconsole.conf='${vconsole_km}' — run: localectl set-keymap ${vconsole_km}"
        _rec "Live keymap '${live_keymap}' differs from vconsole.conf '${vconsole_km}' — run: localectl set-keymap ${vconsole_km}"
    elif [[ -n "$live_keymap" ]]; then
        _row "Keymap"      "OK  ${live_keymap}  (live)"
    elif [[ -n "$vconsole_km" ]]; then _row "Keymap"      "--  ${vconsole_km}  (from vconsole.conf, not yet applied)"
    fi

    # Console font (vconsole.conf FONT=)
    local vconsole_font=""
    vconsole_font=$(grep -E '^FONT=' /etc/vconsole.conf 2>/dev/null \
        | cut -d= -f2 | tr -d "\"'" || echo "")
    [[ -n "$vconsole_font" ]] && _row "Font"        "--  ${vconsole_font}  (vconsole)"

    # Pretty hostname — cosmetic but useful for mDNS/hostnamectl
    local pretty_hostname=""
    if command -v hostnamectl &>/dev/null; then
        pretty_hostname=$(hostnamectl --no-ask-password 2>/dev/null \
            | grep -i 'Pretty hostname' | cut -d: -f2- | sed 's/^ *//' || echo "")
    fi
    if [[ -z "$pretty_hostname" || "$pretty_hostname" == "$hostname" ]]; then
        _row "Pretty host"  "--  not set  (optional: hostnamectl set-hostname --pretty 'My PC')"
    else
        _row "Pretty host"  "--  ${pretty_hostname}"
    fi

    # Chassis type (hostnamectl) — informational
    local chassis=""
    if command -v hostnamectl &>/dev/null; then
        chassis=$(hostnamectl --no-ask-password 2>/dev/null \
            | grep -i 'Chassis' | cut -d: -f2- | sed 's/^ *//' || echo "")
    fi
    [[ -n "$chassis" ]] && _row "Chassis"     "--  ${chassis}"

    _head "Slots"

    # Booted — what is actually running right now
    _row "Booted"   "OK  @${booted}"

    # Expected — the slot current-slot points to (what boots next time)
    if [[ "$booted" == "$slot_current" ]]; then
        _row "Expected"  "OK  @${slot_current}  (matches booted)"
    elif [[ -f "$DATA_REBOOT_NEEDED" ]]; then
        local rver; rver=$(cat "$DATA_REBOOT_NEEDED" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
        _row "Expected"  "!   @${slot_current}  (v${rver} ready — reboot to activate)"
    elif [[ -f "$DATA_BOOT_FAIL" || -f "$DATA_BOOT_HARD_FAIL" ]]; then
        local _failed_slot
        _failed_slot=$(cat "$DATA_BOOT_FAIL"      2>/dev/null | tr -d '[:space:]' || \
                       cat "$DATA_BOOT_HARD_FAIL" 2>/dev/null | tr -d '[:space:]' || \
                       echo "$slot_current")
        [[ -z "$_failed_slot" ]] && _failed_slot="$slot_current"
        _row "Expected"  "!!  @${slot_current}  (booted @${booted} instead of expected — @${_failed_slot} failed)"
        _rec "Booted to candidate slot — expected slot failed; run: shani-deploy --rollback"
    else
        _row "Expected"  "!!  @${slot_current}  (mismatch — booted: @${booted})"
        _rec "Slot mismatch with no failure or reboot-needed marker — run: shani-deploy --rollback"
    fi

    # Fallback — the slot that is NOT current-slot (the true systemd-boot fallback).
    # Fallback is the other slot — derive directly.
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

    # Previous slot — what was booted before the last deploy/rollback
    local _prev_slot=$(cat "$DATA_PREV_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
    [[ -n "$_prev_slot" ]] && _row "Previous"  "--  @${_prev_slot}"
}

_section_boot_health() {
    _head "Boot Health"
    local chain_failed=()
    for svc in mark-boot-in-progress.service mark-boot-success.service bless-boot.service; do
        systemctl is-failed --quiet "$svc" 2>/dev/null && chain_failed+=("$svc")
    done
    if [[ ${#chain_failed[@]} -gt 0 ]]; then
        _row "Boot chain" "!!  failed this boot: $(_join "${chain_failed[@]}")"
        _rec "Boot chain service(s) failed: $(_join "${chain_failed[@]}") — run: systemctl status <unit>"
    fi
    local overlay_boot_failed=()
    for svc in etc-daemon-reload.service etc-start-services.service; do
        systemctl is-failed --quiet "$svc" 2>/dev/null && overlay_boot_failed+=("$svc")
    done
    if [[ ${#overlay_boot_failed[@]} -gt 0 ]]; then
        _row "Overlay boot" "!!  failed: $(_join "${overlay_boot_failed[@]}")"
        _rec "Overlay boot service(s) failed: $(_join "${overlay_boot_failed[@]}") — run: systemctl status <unit>"
    fi
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
            _rec "No /data/boot-ok — check: systemctl status mark-boot-success.service"
        fi
    fi
    # Presence after boot-ok exists = mark-boot-success did not finish (failed/skipped)
    if [[ -f /data/boot_in_progress ]]; then
        if [[ -f "$DATA_BOOT_OK" ]]; then
            _row "In-progress" "!   boot_in_progress still set — mark-boot-success may not have completed"
            _rec "Stale /data/boot_in_progress — check: systemctl status mark-boot-success.service"
        fi
        # If boot_in_progress exists and no boot-ok — boot is still in flight or timed out;
        # check-boot-failure.timer will record it at the 15-minute mark, so no extra rec needed here
    fi
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
            _rec "Stale boot failure marker for @${s} — run: shani-health --clear-boot-failure to remove it"
        elif [[ "$s" == "$booted_slot" ]]; then
            # The failure marker names the slot we're currently booted into —
            # it had a prior failed attempt but succeeded this boot.
            _row "Failure"    "--  prior boot failure recorded for @${s} (booted successfully this time)"
        else
            _row "Failure"    "!   boot failure recorded for @${s}"
            # Slots section already emits a rollback rec for this case; skip duplicate
        fi
    fi
    # mark-boot-in-progress CLEARS this on every boot, so its presence means:
    # the rollback dialog ran this boot but rollback may not have completed
    if [[ -f "$DATA_BOOT_FAIL_ACKED" ]]; then
        _row "Acked"      "!   failure acked but rollback may not have completed"
        _rec "boot_failure.acked present — run: shani-deploy --rollback to finish recovery"
    fi
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
    # This module installs the boot_hard_failure hook into the initramfs.
    # Without it, root mount failures are undetectable and rollback is blind.
    local dracut_mod="/usr/lib/dracut/modules.d/99shanios"
    if [[ -d "$dracut_mod" ]]; then
        local mod_files; mod_files=$(ls "$dracut_mod"/*.sh 2>/dev/null | wc -l || echo "0")
        if (( mod_files >= 2 )); then _row "Dracut mod"  "OK  99shanios module installed (${mod_files} hooks)"
        else
            _row "Dracut mod"  "!   99shanios module incomplete (${mod_files}/3 files)"
            _rec "dracut 99shanios module incomplete — reinstall ShaniOS dracut hooks"
        fi
    else
        _row "Dracut mod"  "!!  99shanios dracut module missing — hard boot failures undetectable"
        _rec "dracut 99shanios module missing — boot failure detection broken; reinstall dracut hooks"
    fi
    # Fires OnBootSec=15m; ConditionPathExists=/data/boot_in_progress — only runs
    # if boot_in_progress still exists at 15min, meaning mark-boot-success never ran
    local cbf_enabled; cbf_enabled=$(systemctl is-enabled check-boot-failure.timer 2>/dev/null || echo "disabled")
    # Note: this timer fires OnBootSec=15m then goes inactive — is-active=inactive is normal.
    # Only check is-enabled (must be enabled) and is-failed (must not have errored).
    if [[ "$cbf_enabled" == "disabled" || "$cbf_enabled" == "missing" || "$cbf_enabled" == "not-found" ]]; then
        _row "Fail timer" "!!  check-boot-failure.timer disabled — boot failures won't be auto-recorded"
        _rec "check-boot-failure.timer is disabled — automatic boot failure detection is broken"
    elif systemctl is-failed --quiet check-boot-failure.timer 2>/dev/null; then
        _row "Fail timer" "!!  check-boot-failure.timer failed — boot failure detection broken"
    else
        _row "Fail timer" "OK  enabled"
    fi
}
_section_boot_entries() {
    _head "Boot Entries"

    if ! mountpoint -q "$ESP" 2>/dev/null; then
        _row "ESP"       "!!  could not mount — boot entries unavailable"
        return 0
    fi
    # UKIs are ~100MB each; gen-efi fails silently if ESP fills up
    local esp_avail_mb=$(df -BM "$ESP" 2>/dev/null | awk 'NR==2{gsub(/M/,"",$4); print $4}' || echo "")
    if [[ "$esp_avail_mb" =~ ^[0-9]+$ ]]; then
        if (( esp_avail_mb < 50 )); then
            _row "ESP space"  "!!  ${esp_avail_mb} MB free — gen-efi will fail"
            _rec "ESP nearly full (${esp_avail_mb} MB) — clean old entries or expand ESP"
        elif (( esp_avail_mb < 150 )); then _row "ESP space"  "!   ${esp_avail_mb} MB free — getting tight"
        else
            _row "ESP space"  "OK  ${esp_avail_mb} MB free"
        fi
    fi
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
            _row2 "!   ${_stale_str} source newer than ESP copy — run: gen-efi configure ${booted:-blue}"
            _rec "ESP ${_stale_str} is stale (newer source available) — run: gen-efi configure ${booted:-blue}"
        fi
    else
        local _em_str; _em_str=$(IFS=' '; echo "${efi_missing[*]}")
        _row "EFI files"  "!!  missing: ${_em_str}"
        _rec "EFI boot files missing (${_em_str}) — run: gen-efi configure ${booted:-blue}"
    fi

    local loader_conf="$ESP/loader/loader.conf"
    if [[ ! -f /etc/vconsole.conf ]]; then
        _row "vconsole"   "!!  /etc/vconsole.conf missing — UKI will have no keymap"
        _rec "Create /etc/vconsole.conf with KEYMAP= set (e.g. KEYMAP=us) and regenerate UKI: gen-efi configure ${booted:-blue}"
    else
        # Read straight from the file — same source gen-efi uses
        local vconsole_keymap
        vconsole_keymap=$(grep -E '^KEYMAP=' /etc/vconsole.conf 2>/dev/null \
            | cut -d= -f2 | tr -d "\"'" | tr -cd 'A-Za-z0-9._-' || echo "")

        # KEYMAP — mandatory for LUKS passphrase entry at boot
        if [[ -z "$vconsole_keymap" ]]; then
            _row "Keymap"     "!   KEYMAP not set in /etc/vconsole.conf — UKI will have no keymap"
            _rec "Set KEYMAP= in /etc/vconsole.conf (e.g. KEYMAP=us) and regenerate UKI: gen-efi configure ${booted:-blue}"
        else
            local cmdline_keymap
            cmdline_keymap=$(grep -o 'rd.vconsole.keymap=[^ ]*' /proc/cmdline 2>/dev/null \
                | cut -d= -f2 || echo "")
            if [[ -n "$cmdline_keymap" && "$cmdline_keymap" != "$vconsole_keymap" ]]; then
                _row "Keymap"     "!   mismatch: UKI has '${cmdline_keymap}', vconsole.conf has '${vconsole_keymap}'"
                _rec "Keymap mismatch between running UKI and vconsole.conf — regenerate: gen-efi configure ${booted:-blue}"
            else
                _row "Keymap"     "OK  ${vconsole_keymap}${cmdline_keymap:+ (matches UKI)}"
            fi
        fi

    fi
    # Both UKIs must exist; the candidate shouldn't be drastically older than current
    local booted_uki candidate_uki booted_ts candidate_ts
    local current_slot; current_slot=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
    local candidate_slot
    [[ "$current_slot" == "blue" ]] && candidate_slot="green" || candidate_slot="blue"

    booted_uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${booted}.efi"
    candidate_uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${candidate_slot}.efi"

    if [[ ! -f "$booted_uki" ]]; then
        _row "UKI"       "!!  current slot UKI missing: $(basename "$booted_uki")"
        _rec "Current slot UKI missing — run: gen-efi configure ${current_slot}"
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
    if [[ -f "$loader_conf" ]]; then
        local default_entry=$(grep '^default' "$loader_conf" 2>/dev/null | awk '{print $2}' || echo "")
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
        _rec "Orphaned boot entries ($(_join "${orphans[@]}")) — remove with: bootctl unlink <entry>"
    fi

    local editor; editor=$(grep '^editor' "$loader_conf" 2>/dev/null \
        | awk '{print $2}' || echo "not set")
    if [[ "$editor" == "0" ]]; then _row "Editor"    "OK  disabled"
    else
        _row "Editor"    "!!  not disabled (cmdline editable at boot)"
        _rec "systemd-boot editor not disabled — add 'editor 0' to loader.conf"
    fi
}

_section_deployment() {
    _head "Deployment"

    if [[ -f "$DATA_DEPLOY_PENDING" ]]; then
        local dp_age; dp_age=$(( ( $(date +%s) - $(stat -c '%Y' "$DATA_DEPLOY_PENDING" 2>/dev/null || echo "0") ) / 60 ))
        if (( dp_age > 60 )); then
            _row "State"     "!!  deployment_pending ${dp_age}min old — deploy interrupted?"
            _rec "Stale deployment_pending (${dp_age} min) — check: shani-deploy --rollback"
        else
            _row "State"     "!   deploy pending (interrupted?) — run: shani-deploy --rollback"
        fi
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

    local version ver_ts
    version=$(cat /etc/shani-version 2>/dev/null || echo "?")
    ver_ts=$(stat -c '%y' /etc/shani-version 2>/dev/null | cut -d. -f1 || echo "?")
    _row "Installed"  "--  v${version}  (since ${ver_ts})"
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
            ! echo "$content" | grep -q "subvol=@${slot}[,\ ]" && cmdline_wrong+=("${slot}(missing subvol=@${slot})")
        done
        if [[ ${#cmdline_wrong[@]} -gt 0 ]]; then
            local _cw_str; _cw_str=$(IFS=' '; echo "${cmdline_wrong[*]}")
            _row "Cmdline"    "!!  wrong subvol in cmdline: ${_cw_str}"
            _rec "Cmdline files have wrong subvol — run: gen-efi configure ${booted:-blue} for each"
        else
            _row "Cmdline"    "OK  install_cmdline_{blue,green} present and correct"
        fi
    else
        _row "Cmdline"    "!!  missing for: $(_join "${cmdline_missing[@]}") — next gen-efi may produce wrong UKI"
        _rec "Cmdline files missing for @$(_join "${cmdline_missing[@]}") — run: gen-efi configure ${booted:-blue} for each"
    fi
    # Deploy keeps one backup per slot — if missing, --rollback has no snapshot to restore from
    # Cache subvolume list once — reused for both existence check and age check below.
    local _svol_list; _svol_list=$(btrfs subvolume list / 2>/dev/null || echo "")
    local backup_missing=() backup_found=()
    for slot in blue green; do
        local has_backup
        has_backup=$(echo "$_svol_list" \
            | awk -v s="${slot}_backup_" '$NF ~ s {print $NF; exit}' || echo "")
        if [[ -n "$has_backup" ]]; then
            local bk_size=""
            local bk_path="/${has_backup}"
            if [[ -d "$bk_path" ]]; then
                local bk_mb; bk_mb=$(du -sm "$bk_path" 2>/dev/null | awk '{print $1}' || echo "")
                [[ "$bk_mb" =~ ^[0-9]+$ ]] && bk_size=" ($(_mb_to_human "$bk_mb"))"
            fi
            backup_found+=("@${slot}:$(basename "$has_backup")${bk_size}")
        else
            backup_missing+=("@${slot}")
        fi
    done
    if [[ ${#backup_missing[@]} -eq 0 ]]; then
        _row "Backups"    "OK  $(IFS=' '; echo "${backup_found[*]}")"
        local _now_dep; _now_dep=$(date +%s)
        for slot in blue green; do
            local _bk_path; _bk_path=$(echo "$_svol_list" \
                | awk -v s="${slot}_backup_" '$NF ~ s {print $NF; exit}' || echo "")
            [[ -z "$_bk_path" ]] && continue
            local _bk_created; _bk_created=$(btrfs subvolume show "/${_bk_path}" 2>/dev/null \
                | awk -F'\t' '/Creation time:/{gsub(/^[[:space:]]+/,"",$2); print $2}' | head -1 || true)
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

}

_section_update_tools() {
    _head "Update Tools"
    # gen-efi is the core UKI builder — without it, deploys cannot sign or install boot images.
    if [[ -x "$GENEFI_BIN" ]]; then
        _row "gen-efi"    "OK  present (${GENEFI_BIN})"
    elif [[ -f "$GENEFI_BIN" ]]; then
        _row "gen-efi"    "!!  present but not executable — run: chmod +x ${GENEFI_BIN}"
        _rec "gen-efi binary not executable — run: chmod +x ${GENEFI_BIN}"
    else
        _row "gen-efi"    "!!  missing — UKI builds and deploys will fail"
        _rec "gen-efi binary missing at ${GENEFI_BIN} — reinstall ShaniOS deploy tools"
    fi
    # Key must be imported for image verification.
    # Ships locally at GPG_SIGNING_KEY_FILE — no network required.
    if gpg --batch --list-keys "$GPG_SIGNING_KEY" &>/dev/null 2>&1; then
        _row "GPG key"    "OK  signing key imported"
    elif [[ -f "$GPG_SIGNING_KEY_FILE" ]]; then
        _row "GPG key"    "!!  signing key not in keyring — image verification will fail"
        _rec "GPG signing key not imported — run: gpg --import ${GPG_SIGNING_KEY_FILE}"
    else
        _row "GPG key"    "!!  signing key not in keyring — image verification will fail"
        _rec "GPG signing key not imported — run: gpg --keyserver keys.openpgp.org --recv-keys ${GPG_SIGNING_KEY}"
    fi
    # /etc/shani-keys/signing.asc ships with the OS and is the offline source
    # for importing the GPG key used to verify OS image downloads.
    local _skey_file="/etc/shani-keys/signing.asc"
    if [[ ! -f "$_skey_file" ]]; then
        _row "Key file"    "!   ${_skey_file} missing — GPG key must be fetched from keyserver"
        _rec "Signing key file missing — restore: ${_skey_file} (or import from keyserver)"
    fi
    # /var/log/shanios-deploy.log growing beyond ~10 MB usually indicates
    # repeated failed deploy attempts accumulating without rotation.
    if [[ -f "$DEPLOY_LOG" ]]; then
        local deploy_log_mb=$(du -sm "$DEPLOY_LOG" 2>/dev/null | awk '{print $1}' || echo "0")
        if [[ "$deploy_log_mb" =~ ^[0-9]+$ ]] && (( deploy_log_mb >= 10 )); then
            _row "Deploy log"  "!   ${deploy_log_mb} MB — may indicate repeated failures"
            _rec "Deploy log is ${deploy_log_mb} MB — review: tail -100 ${DEPLOY_LOG}"
        fi
    fi
    local dl_dir="/data/downloads"
    if [[ ! -d "$dl_dir" ]]; then
        _row "Downloads"  "!   /data/downloads missing — shani-deploy will fail to store images"
        _rec "/data/downloads directory missing — run: mkdir -p /data/downloads"
    else
        local dl_size_mb=$(du -sm "$dl_dir" 2>/dev/null | awk '{print $1}' || echo "0")
        if [[ "$dl_size_mb" =~ ^[0-9]+$ ]] && (( dl_size_mb > 5120 )); then
            _row "Downloads"  "!   ${dl_size_mb} MB in /data/downloads — run: shani-deploy --cleanup"
            _rec "Download cache is ${dl_size_mb} MB — free space with: shani-deploy --cleanup"
        elif [[ "$dl_size_mb" =~ ^[0-9]+$ ]] && (( dl_size_mb > 1024 )); then
            _row "Downloads"  "--  ${dl_size_mb} MB cached (run: shani-deploy --cleanup to free space)"
        fi
        # Stale partial downloads — interrupted deploys leave .part or .tmp files
        # that consume space and can confuse shani-deploy on the next run.
        local _stale_parts=0
        _stale_parts=$(find "$dl_dir" \( -name '*.part' -o -name '*.tmp' -o -name '*.partial' \) \
            -type f 2>/dev/null | wc -l || echo "0")
        if [[ "$_stale_parts" =~ ^[0-9]+$ ]] && (( _stale_parts > 0 )); then
            _row2 "!   ${_stale_parts} partial download(s) — interrupted deploy; run: shani-deploy --cleanup"
            _rec "Partial downloads in /data/downloads — clean up: shani-deploy --cleanup"
        fi
    fi
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
    # shani-deploy tries aria2c → wget → curl; at least one must be present.
    # pv is optional but provides progress display during extraction.
    local dl_tools=()
    command -v aria2c &>/dev/null && dl_tools+=("aria2c")
    command -v wget   &>/dev/null && dl_tools+=("wget")
    command -v curl   &>/dev/null && dl_tools+=("curl")
    if [[ ${#dl_tools[@]} -eq 0 ]]; then
        _row "DL tools"   "!!  no download tool found (aria2c/wget/curl) — updates will fail"
        _rec "No download tools (aria2c/wget/curl) — shani-deploy requires at least one; should be in base image"
    else
        command -v pv &>/dev/null || \
            _row2 "--  pv not installed (no extraction progress display)"
    fi
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
    if ! findmnt -n /data &>/dev/null; then
        _row "/data"          "!!  not mounted — system state unavailable"
        _rec "/data not mounted — check: systemctl status data.mount && cat /etc/fstab"
        return 0
    fi
    _row "/data"          "OK  mounted"
    local tmpfiles_res
    tmpfiles_res=$(systemctl show shanios-tmpfiles-data.service \
        --property=Result --value 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ "$tmpfiles_res" == "exit-code" || "$tmpfiles_res" == "core-dump" || "$tmpfiles_res" == "signal" ]]; then
        _row "tmpfiles"   "!!  shanios-tmpfiles-data.service failed — /data dirs may be missing"
        _rec "shanios-tmpfiles-data.service failed — run: systemctl restart shanios-tmpfiles-data.service"
    elif [[ "$tmpfiles_res" == "success" ]]; then _row "tmpfiles"   "OK  shanios-tmpfiles-data ran successfully"
    fi
    local usp_st; usp_st=$(systemctl is-active shani-user-setup.path 2>/dev/null || echo "inactive")
    local usp_en; usp_en=$(systemctl is-enabled shani-user-setup.path 2>/dev/null || echo "disabled")
    if [[ "$usp_st" == "active" ]]; then
        _row "User watcher" "OK  shani-user-setup.path active"
    elif [[ "$usp_en" == "enabled" || "$usp_en" == "static" ]]; then
        _row "User watcher" "!   shani-user-setup.path enabled but not active — new users won't auto-provision"
    else
        _row "User watcher" "!!  shani-user-setup.path not enabled — new users won't get required groups"
        _rec "Enable shani-user-setup.path: systemctl enable --now shani-user-setup.path"
    fi

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
            _rec "user-setup-needed marker is ${marker_age_days}d old — run: shani-user-setup"
        else
            _row "User setup" "--  pending (marker present, will run shortly)"
        fi
    else
        _row "User setup"  "OK  complete"
    fi
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
        _rec "/data/varlib directory missing — run: mkdir -p /data/varlib"
    fi

    if (( varspool_ok )); then
        local varspool_svcs; varspool_svcs=$(ls /data/varspool 2>/dev/null | wc -l || echo "0")
        _row "varspool" "OK  ${varspool_svcs} spool dir(s) in /data/varspool"
    else
        _row "varspool" "!   /data/varspool missing — spool bind-mounts may fail"
        _rec "/data/varspool directory missing — run: mkdir -p /data/varspool"
    fi
    local overlay_upper="/data/overlay/etc/upper"
    local overlay_work="/data/overlay/etc/work"
    if [[ ! -d "$overlay_upper" || ! -d "$overlay_work" ]]; then
        _row "overlay"  "!   /data/overlay/etc/{upper,work} missing"
        _rec "/data/overlay dirs missing — run shanios-tmpfiles-data.service or: mkdir -p /data/overlay/etc/{upper,work}"
    fi
}

_section_immutability() {
    _head "Immutability"
    local opts; opts=$(findmnt -n -o OPTIONS / 2>/dev/null || true)
    if echo "$opts" | grep -qw ro; then _row "Root (/)"   "OK  read-only"
    else
        _row "Root (/)"   "!!  writable — immutability compromised"
        _rec "Root filesystem is writable — reboot may be required"
    fi
    if findmnt -n -t tmpfs /var &>/dev/null; then _row "/var"       "OK  tmpfs (volatile — cleared each boot)"
    else
        local var_opts; var_opts=$(findmnt -n -o OPTIONS /var 2>/dev/null || true)
        if [[ -n "$var_opts" ]]; then
            _row "/var"   "!   not tmpfs (${var_opts%%,*}) — systemd.volatile=state may be missing"
            _rec "/var is not tmpfs — verify systemd.volatile=state in cmdline: cat /proc/cmdline"
        else
            _row "/var"   "--  /var mount not detected"
        fi
    fi
    local overlay_upper="/data/overlay/etc/upper"
    if [[ -d "$overlay_upper" ]]; then
        local count; count=$(find "$overlay_upper" -mindepth 1 2>/dev/null | wc -l || echo "0")
        local etc_mnt_opts; etc_mnt_opts=$(findmnt -n -o OPTIONS /etc 2>/dev/null || true)
        if [[ -n "$etc_mnt_opts" ]]; then
            # Verify required overlay options: index=off and metacopy=off
            local opts_ok=1
            echo "$etc_mnt_opts" | grep -q 'index=off'    || opts_ok=0
            echo "$etc_mnt_opts" | grep -q 'metacopy=off' || opts_ok=0
            if (( opts_ok )); then _row "/etc"   "OK  overlay active, ${count} file(s) modified vs base"
            else
                _row "/etc"   "!   overlay active but missing index=off or metacopy=off"
                _rec "/etc overlay missing required options (index=off,metacopy=off) — check fstab"
            fi
        else
            _row "/etc"   "!!  overlay NOT mounted — /etc from read-only root"
            _rec "/etc overlay not mounted — check etc-overlay.mount unit"
        fi
        if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 200 )); then
            _row2         "!   large overlay (${count} files) — significant config drift"
        elif [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
            local top_dirs overlay_size
            top_dirs=$(find "$overlay_upper" -mindepth 2 -maxdepth 2 2>/dev/null \
                | sed "s|${overlay_upper}/||" | cut -d/ -f1 \
                | sort | uniq -c | sort -rn | head -5 \
                | awk '{printf "%s(%s) ",$2,$1}')
            overlay_size=$(du -sh "$overlay_upper" 2>/dev/null | awk '{print $1}' || echo "")
            [[ -n "$top_dirs" ]] && _row2 "--  top dirs: ${top_dirs}"
            [[ -n "$overlay_size" ]] && _row2 "--  overlay size: ${overlay_size}"
        fi
    else
        _row "/etc"   "!!  overlay upper dir missing — run shanios-tmpfiles-data.service"
        _rec "/etc overlay upper dir missing — run shanios-tmpfiles-data.service"
    fi
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
        if findmnt -n "$mnt" &>/dev/null; then sv_ok=$(( sv_ok + 1 )); else sv_missing+=("${subvol_mounts[$mnt]}"); fi
    done
    if [[ ${#sv_missing[@]} -eq 0 ]]; then _row "Subvolumes"  "OK  all ${sv_ok} critical subvolumes mounted"
    else
        _row "Subvolumes"  "!!  not mounted: $(_join "${sv_missing[@]}")"
        _rec "Btrfs subvolumes not mounted ($(_join "${sv_missing[@]}")) — check: systemctl status shanios-tmpfiles-data.service && findmnt -t btrfs"
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
        return 0
    fi

    local sb_state; sb_state=$(mokutil --sb-state 2>/dev/null || echo "")

    if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then _row "Status"    "OK  enabled"
    else
        _row "Status"    "--  disabled"
        # Informational only — user may have deliberately left SB off; no _rec emitted
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

    # Check if local key is pending enrollment (staged via mokutil --import, not yet confirmed)
    local mok_pending=0
    if [[ -n "$local_fp" ]] && \
       mokutil --list-new 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]' \
       | grep -q "$local_fp"; then
        mok_pending=1
    fi

    local _sb_enabled=0
    [[ "$sb_state" == *"SecureBoot enabled"* ]] && _sb_enabled=1

    if (( mok_pending )); then
        _row "MOK enrol" "->  enrollment pending — reboot and confirm in MokManager"
    elif (( mok_count > 0 )); then
        local enrolled_match=0
        if [[ -n "$local_fp" ]] && \
           mokutil --list-enrolled 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]' \
           | grep -q "$local_fp"; then
            enrolled_match=1
        fi
        if (( enrolled_match )); then _row "MOK enrol" "OK  ${mok_count} key(s) enrolled  (local key confirmed)"
        else
            if (( _sb_enabled )); then
                _row "MOK enrol" "!   ${mok_count} key(s) enrolled but local MOK.der not matched — key may be stale"
                _rec "Enrolled MOK key does not match local MOK.der — re-enroll: gen-efi enroll-mok"
            else
                _row "MOK enrol" "--  ${mok_count} key(s) enrolled but local MOK.der not matched (Secure Boot off — no immediate impact)"
                _rec "Enrolled MOK key does not match local MOK.der — re-enroll before enabling Secure Boot: gen-efi enroll-mok"
            fi
        fi
    else
        if (( _sb_enabled )); then
            # SB is on but no key enrolled — system may not boot after next UKI rebuild
            _row "MOK enrol" "!!  no keys enrolled — Secure Boot will reject unsigned UKIs"
            _rec "Enroll MOK key: gen-efi enroll-mok  [auto: stages enrollment, reboot required]"
        else
            # SB off — enrollment is staged but not yet confirmed, or not yet done
            _row "MOK enrol" "--  no keys enrolled (Secure Boot is disabled — enroll before enabling SB)"
            _rec "Enroll MOK key before enabling Secure Boot: gen-efi enroll-mok  [auto: stages enrollment, reboot required]"
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
        local mok_key_mode=$(stat -c '%a' "$mok_key" 2>/dev/null || echo "")
        if [[ -n "$mok_key_mode" && "$mok_key_mode" != "600" ]]; then
            _row "MOK perms"  "!!  MOK.key is mode ${mok_key_mode} — should be 0600"
            _rec "MOK private key has wrong permissions — fix: chmod 600 ${mok_key}"
        fi
        # Verify the key and cert form a valid pair (modulus match)
        local key_mod cert_mod
        key_mod=$(openssl rsa  -in "$mok_key" -noout -modulus 2>/dev/null | sha256sum 2>/dev/null || echo "")
        cert_mod=$(openssl x509 -in "$mok_crt" -noout -modulus 2>/dev/null | sha256sum 2>/dev/null || echo "")
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
            elif sbverify --cert "$mok_crt" "$uki" &>/dev/null 2>&1; then uki_ok=$(( uki_ok + 1 ))
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
                    _rec "UKI @${bad} (booted) invalid — run: gen-efi configure ${bad}${also}"
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
    # dracut, sbsign and sbverify must all be present for gen-efi to build and
    # sign a UKI. Missing any one of them makes the next UKI rebuild impossible.
    local missing_tools=()
    for tool in dracut sbsign sbverify; do
        command -v "$tool" &>/dev/null || missing_tools+=("$tool")
    done
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        _row "UKI tools"  "!!  missing: $(_join "${missing_tools[@]}") — gen-efi / UKI rebuild will fail"
        _rec "Missing UKI build tools ($(_join "${missing_tools[@]}")) — add to base image; UKI rebuilds will fail"
    fi
}

_section_kernel_security() {
    local sb_active="$1"   # "yes" if Secure Boot is enabled

    _head "Kernel Security"
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
        if [[ -z "$actual_lsm_param" ]]; then _row "LSMs"  "!!  lsm= missing from cmdline — LSMs may not be active"
        else
            _row "LSMs"  "!   lsm= wrong: ${actual_lsm_param}"
        fi
        _rec "lsm= cmdline incorrect — regenerate UKI: gen-efi configure ${booted:-<booted_slot>}"
    elif [[ ${#missing_lsms[@]} -eq 0 && ${#missing_build[@]} -eq 0 ]]; then
        _row "LSMs"  "OK  all ${total} active"
    elif [[ ${#missing_lsms[@]} -eq 0 ]]; then
        _row "LSMs"  "--  ${active}/${total} active ($(_join "${missing_build[@]}") not compiled in)"
    else
        _row "LSMs"  "!!  missing at runtime: $(_join "${missing_lsms[@]}")"
        _rec "LSMs not active ($(_join "${missing_lsms[@]}")) — check lsm= in: cat /proc/cmdline; then regenerate UKI: gen-efi configure ${booted:-blue}"
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
    if [[ ${#bad_mods[@]} -eq 0 ]]; then _row "Blacklist"  "OK  mei/mei_me/pcspkr not loaded"
    else
        _row "Blacklist"  "!   loaded but should be blacklisted: $(_join "${bad_mods[@]}")"
        _rec "Modules $(_join "${bad_mods[@]}") should be blacklisted — add: echo 'blacklist ${bad_mods[0]}' >> /etc/modprobe.d/shani-blacklist.conf"
    fi
    # dccp/sctp/rds/tipc are not needed on a desktop and add kernel attack surface.
    local _proto_missing=()
    for _proto in dccp sctp rds tipc; do
        grep -qrE "install ${_proto}[[:space:]]+/bin/false" \
            /etc/modprobe.d/ /usr/lib/modprobe.d/ 2>/dev/null || \
            _proto_missing+=("$_proto")
    done
    if [[ ${#_proto_missing[@]} -eq 0 ]]; then _row "Protocols"  "OK  dccp/sctp/rds/tipc blacklisted"
    else
        local _pm_str; _pm_str=$(IFS='/'; echo "${_proto_missing[*]}")
        _row "Protocols"  "!   not blacklisted: ${_pm_str}"
        _rec "Unused protocols not blacklisted (${_pm_str}) — add install rules to /etc/modprobe.d/"
    fi

}

_section_encryption() {
    _head "Encryption"

    if [[ ! -e "/dev/mapper/${ROOTLABEL}" ]]; then
        _row "LUKS"      "--  not encrypted"
        # Informational only — full-disk encryption requires reinstallation; no _rec emitted
        return 0
    fi

    local underlying
    underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
        | sed -n 's/^ *device: //p' || true)
    _row "LUKS"      "OK  active (${underlying:-/dev/mapper/${ROOTLABEL}})"
    [[ -z "$underlying" ]] && return 0

    local dump; dump=$(cryptsetup luksDump "$underlying" 2>/dev/null || true)
    local kdf;   kdf=$(echo "$dump" | awk '/PBKDF:/{print $2;exit}')
    if [[ "$kdf" == "argon2id" ]]; then _row "KDF"   "OK  argon2id"
    else
        _row "KDF"   "!   ${kdf:-unknown}  (argon2id recommended)"
        _rec "LUKS KDF is ${kdf:-unknown} (argon2id preferred) — re-encrypt: cryptsetup luksConvertKey --pbkdf argon2id ${underlying}"
    fi
    local slot_count; slot_count=$(echo "$dump" | grep -c 'Key Slot [0-9]*: ENABLED' 2>/dev/null || echo "")
    [[ "$slot_count" =~ ^[0-9]+$ ]] && (( slot_count >= 1 )) && _row "Key slots" "OK  ${slot_count} active slot(s)"
    if [[ -f /etc/crypttab ]]; then
        local ct_entry; ct_entry=$(grep "^${ROOTLABEL}\b" /etc/crypttab 2>/dev/null | head -1 || echo "")
        if [[ -n "$ct_entry" ]]; then _row "crypttab"  "OK  entry for ${ROOTLABEL} present"
        else
            _row "crypttab"  "!!  /etc/crypttab exists but has no entry for ${ROOTLABEL}"
            _rec "crypttab missing entry for ${ROOTLABEL} — run: gen-efi configure ${booted:-blue}"
        fi
    else
        _row "crypttab"  "!!  /etc/crypttab missing — initrd will not unlock LUKS"
        _rec "/etc/crypttab missing — run: gen-efi configure ${booted:-blue} to regenerate"
    fi
    local crypt_conf="/etc/dracut.conf.d/99-crypt-key.conf"
    if [[ -f "$crypt_conf" ]]; then _row "Dracut crypt" "OK  99-crypt-key.conf present"
    else
        _row "Dracut crypt" "!!  /etc/dracut.conf.d/99-crypt-key.conf missing — initrd may not include crypttab"
        _rec "dracut crypt config missing — run: gen-efi configure ${booted:-blue}"
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
                local _tpm_sb_state=$(mokutil --sb-state 2>/dev/null || echo "")
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
    if _check_tool_executable "aa-status" "AppArmor"; then
        if aa-status --enabled >/dev/null 2>&1; then
            local n; n=$(aa-status 2>/dev/null | awk '/enforce mode/{print $1}' | tr -d '[:space:]' || echo "?")
            _row "AppArmor"   "OK  ${n} profiles enforcing"
        else
            _row "AppArmor"   "!!  not enforcing"
            _rec "AppArmor not enforcing — run: systemctl enable --now apparmor"
        fi
    else
        ! command -v aa-status &>/dev/null && _row "AppArmor"   "--  aa-status not found"
        # else: found but not executable — _check_tool_executable already emitted the !! row
    fi

    # AppArmor denial count this boot — non-zero means a process is being blocked
    local _aa_journal
    _aa_journal=$(journalctl -k -b 0 --no-pager -q 2>/dev/null | grep 'apparmor.*DENIED' || true)
    local aa_denials; aa_denials=$(echo "$_aa_journal" | grep -c . 2>/dev/null || echo "0")
    [[ "$aa_denials" =~ ^[0-9]+$ ]] || aa_denials=0
    if (( aa_denials > 0 )); then
        _row "AA denials" "!   ${aa_denials} DENIED event(s) this boot"
        # Show top offending profiles inline
        local _aa_top
        _aa_top=$(echo "$_aa_journal" \
            | grep -oP '(?<=profile=")[^"]+' \
            | sort | uniq -c | sort -rn | head -3 \
            | awk '{printf "%s (%d denial(s))\n", $2, $1}' || true)
        while IFS= read -r line; do
            [[ -n "$line" ]] && _row2 "--  $line"
        done <<< "$_aa_top"
        _rec "${aa_denials} AppArmor denial(s) this boot — check: journalctl -k -b 0 | grep 'apparmor.*DENIED'"
    fi

    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            local zone; zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
            _row "Firewall"   "OK  active (zone: ${zone})"
        else
            _row "Firewall"   "!!  firewalld not running"
            _rec "Firewall not active — run: systemctl enable --now firewalld"
        fi
    elif systemctl is-active --quiet ufw 2>/dev/null || \
         { command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; }; then
        _row "Firewall"   "OK  active (ufw)"
    elif systemctl is-active --quiet nftables 2>/dev/null; then
        local _nft_rules=""
        _nft_rules=$(nft list ruleset 2>/dev/null | grep -c 'chain' || echo "")
        _row "Firewall"   "OK  active (nftables${_nft_rules:+, ${_nft_rules} chain(s)})"
    elif command -v ufw &>/dev/null; then
        _row "Firewall"   "!!  ufw installed but not active"
        _rec "Firewall not active — run: systemctl enable --now ufw && ufw enable"
    else
        _row "Firewall"   "!!  not installed — system has no firewall"
    fi
    local _fw_active=()
    systemctl is-active --quiet firewalld 2>/dev/null && _fw_active+=("firewalld")
    systemctl is-active --quiet nftables  2>/dev/null && _fw_active+=("nftables")
    { command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; } && _fw_active+=("ufw")
    if (( ${#_fw_active[@]} > 1 )); then
        _row "Firewall"    "!!  multiple firewall front-ends active: ${_fw_active[*]} — rule sets may conflict"
        _rec "Multiple firewall front-ends active (${_fw_active[*]}) — disable all but one"
    fi
    # polkitd is required for pkexec-based privilege escalation (used by this
    # script itself) and for GUI admin actions in GNOME/Plasma.
    if systemctl is-active --quiet polkit 2>/dev/null; then
        _row "polkit"     "OK  running"
    elif systemctl is-enabled --quiet polkit 2>/dev/null; then
        _row "polkit"     "!!  enabled but not running — pkexec and GUI elevation broken"
    else
        _row "polkit"     "!   not enabled — pkexec and GUI elevation will fail"
        _rec "polkit not enabled — run: systemctl enable --now polkit"
    fi

    # fail2ban is a default ShaniOS service — bans IPs after repeated auth failures.
    if systemctl cat fail2ban &>/dev/null 2>&1; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            local jails
            jails=$(fail2ban-client status 2>/dev/null \
                | awk -F'Jail list:' '/Jail list:/{
                    gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2)
                    if($2==""){print 0}
                    else{n=split($2,a,/,[[:space:]]*/); print n}
                  }' || echo "?")
            if [[ "$jails" == "0" ]]; then
                _row "fail2ban"   "!   running but 0 jails configured — no protection active"
                local _f2b_rec="fail2ban has no jails — create /etc/fail2ban/jail.local"
                if systemctl is-enabled --quiet sshd 2>/dev/null || \
                   systemctl is-active  --quiet sshd 2>/dev/null; then
                    _f2b_rec+=" with at least [sshd] enabled"
                fi
                _rec "$_f2b_rec"
            else
                _row "fail2ban"   "OK  ${jails} jail(s) active"
            fi
        elif systemctl is-enabled --quiet fail2ban 2>/dev/null; then _row "fail2ban"   "!   enabled but not running"
        else
            _row "fail2ban"   "!   installed but not enabled"
            _rec "fail2ban not enabled — run: systemctl enable --now fail2ban"
        fi
    else
        # Not installed — downgrade severity based on whether sshguard is covering the gap
        if systemctl is-active --quiet sshguard 2>/dev/null; then
            _row "fail2ban"   "~~  not installed  (sshguard active — brute-force protection present)"
        else
            _row "fail2ban"   "!   not installed — no brute-force protection"
            _rec "fail2ban not installed — add to ShaniOS base image or install via overlay"
        fi
    fi
    # sshguard is an alternative to fail2ban — only one should be active.
    if _svc_present sshguard; then
        if systemctl is-active --quiet sshguard 2>/dev/null; then
            if systemctl is-active --quiet fail2ban 2>/dev/null; then
                _row "sshguard"    "!   running alongside fail2ban — duplicate brute-force protection, disable one"
                _rec "Both sshguard and fail2ban are active — disable sshguard: systemctl disable --now sshguard"
            else
                _row "sshguard"    "OK  running"
            fi
        elif systemctl is-enabled --quiet sshguard 2>/dev/null; then
            if systemctl is-active --quiet fail2ban 2>/dev/null; then
                _row "sshguard"    "--  enabled but fail2ban already active — redundant, consider: systemctl disable --now sshguard"
            else
                _row "sshguard"    "!   enabled but not running"
            fi
        fi
        # Silent if not installed/enabled — fail2ban is the default
    fi


    # ── Hardware authentication ─────────────────────────────────────────────
    # libfido2 is required for FIDO2/U2F hardware keys (YubiKey, SoloKey, etc.)
    # to work in browsers and for sudo/login 2FA via pam-u2f.
    if [[ -f /usr/lib/libfido2.so.1 ]] || [[ -f /usr/lib/libfido2.so ]] || ldconfig -p 2>/dev/null | grep -q libfido2; then
        # libfido2 ships 70-u2f.rules; without it FIDO2 devices are root-only.
        local _fido_rules=""
        for _f in /usr/lib/udev/rules.d/70-u2f.rules \
                  /etc/udev/rules.d/70-u2f.rules \
                  /usr/lib/udev/rules.d/60-fido-id.rules; do
            [[ -f "$_f" ]] && _fido_rules="$_f" && break
        done

        local _fido_devs=""
        if command -v fido2-token &>/dev/null; then
            _fido_devs=$(fido2-token -L 2>/dev/null | grep -c '/dev/' || echo "0")
            [[ "$_fido_devs" =~ ^[0-9]+$ ]] || _fido_devs=0
        fi

        local _pamu2f=0
        [[ -f /usr/lib/security/pam_u2f.so ]] && _pamu2f=1

        local _fido_detail=""
        [[ -n "$_fido_rules" ]] && _fido_detail+="udev rules present" \
                                || _fido_detail+="udev rules MISSING"
        (( _fido_devs > 0 )) && _fido_detail+=", ${_fido_devs} device(s) connected"

        if [[ -z "$_fido_rules" ]]; then
            _row "libfido2"    "!   installed but udev rules missing — FIDO2 keys inaccessible to users"
            _rec "libfido2 udev rules missing — reinstall libfido2 package"
        elif (( _fido_devs > 0 )); then
            _row "libfido2"    "OK  ${_fido_detail}"
            (( ! _pamu2f )) && _row2 "--  pam-u2f not installed — cannot use key for sudo/login 2FA"
        else
            _row "libfido2"    "OK  installed  (${_fido_detail})"
            if (( _pamu2f )); then
                # pam-u2f installed — check if any login user has keys configured
                local _u2f_configured=() _u2f_missing=()
                local _fido_login_users=()
                _get_login_users _fido_login_users
                for _u in "${_fido_login_users[@]}"; do
                    local _uhome; _uhome=$(getent passwd "$_u" 2>/dev/null | cut -d: -f6 || echo "")
                    if [[ -f "${_uhome}/.config/Yubico/u2f_keys" || \
                          -f "/etc/u2f_mappings" ]]; then
                        _u2f_configured+=("$_u")
                    else
                        _u2f_missing+=("$_u")
                    fi
                done
                if [[ ${#_u2f_configured[@]} -gt 0 ]]; then
                    _row2 "OK  pam-u2f configured for: $(_join "${_u2f_configured[@]}")"
                else
                    _row2 "--  pam-u2f installed but no keys enrolled — run: pamu2fcfg > ~/.config/Yubico/u2f_keys"
                fi
            fi
        fi
    else
        # libfido2 not installed — only show if pcscd is present (implies hardware key intent)
        if [[ -d /usr/lib/pcsc ]] || systemctl cat pcscd &>/dev/null 2>&1; then
            _row "libfido2"    "~~  not installed — needed for FIDO2/U2F hardware keys"
            _rec "Install libfido2 for FIDO2/U2F hardware key support (add to image or install via overlay)"
        fi
    fi
    # pcscd is needed for PIV smart cards and PIV-mode YubiKeys (GPG, SSH certs).
    # FIDO2/U2F mode does NOT require pcscd — libfido2 talks to hidraw directly.
    local pcsc_en; pcsc_en=$(systemctl is-enabled pcscd.socket 2>/dev/null || echo "")
    if [[ "$pcsc_en" == "enabled" || "$pcsc_en" == "static" ]]; then
        _row "pcscd"      "OK  socket enabled  (PIV smart cards / YubiKey PIV)"
    elif [[ -n "$pcsc_en" ]]; then
        _row "pcscd"      "!   pcscd.socket not enabled — PIV smart cards won't work"
        _rec "Enable pcscd.socket: systemctl enable pcscd.socket"
    elif command -v pcsc_scan &>/dev/null || [[ -d /usr/lib/pcsc ]]; then
        _row "pcscd"      "!   pcscd.socket not enabled — PIV smart cards won't work"
    fi
    # Silent if pcscd is not installed — not required for FIDO2-only setups
    if _svc_present fprintd; then
        local fprint_hw=0
        if ls /sys/bus/usb/devices/*/idVendor 2>/dev/null \
           | xargs grep -lqiE '(2109|056a|04f3|04b3|06cb|138a|27c6|10a5|1c7a)' 2>/dev/null; then
            fprint_hw=1
        elif fprintd-list 2>/dev/null | grep -qv "^No devices"; then fprint_hw=1
        fi
        if (( fprint_hw )); then
            if systemctl is-active --quiet fprintd 2>/dev/null; then
                local fprint_enrolled=() fprint_missing=()
                local _fp_login=()
                _get_login_users _fp_login
                for u in "${_fp_login[@]}"; do
                    local enrolled=$(fprintd-list "$u" 2>/dev/null || echo "")
                    if echo "$enrolled" | grep -qiE 'right-index|left-index|any'; then fprint_enrolled+=("$u")
                    else
                        fprint_missing+=("$u")
                    fi
                done
                if [[ ${#fprint_enrolled[@]} -gt 0 && ${#fprint_missing[@]} -eq 0 ]]; then
                    _row "fprintd"  "OK  running, enrolled: $(_join "${fprint_enrolled[@]}")"
                elif [[ ${#fprint_enrolled[@]} -gt 0 ]]; then
                    _row "fprintd"  "--  running, enrolled: $(_join "${fprint_enrolled[@]}") | not enrolled: $(_join "${fprint_missing[@]}")"
                    _rec "Fingerprint not enrolled for $(_join "${fprint_missing[@]}") — run: fprintd-enroll <user>"
                else
                    _row "fprintd"  "!   running but no users enrolled"
                    _rec "No fingerprints enrolled — run: fprintd-enroll <user> for each login user"
                fi
            elif systemctl is-enabled --quiet fprintd 2>/dev/null; then
                _row "fprintd"  "!   hardware present, enabled but not running"
                else
                _row "fprintd"  "!   hardware present but fprintd not enabled"
                _rec "Enable fprintd for fingerprint login: systemctl enable --now fprintd"
            fi
        else
            local _fpr_svc_en=0 _fpr_sock_en=0
            systemctl is-enabled --quiet fprintd 2>/dev/null        && _fpr_svc_en=1
            systemctl is-enabled --quiet fprintd.socket 2>/dev/null && _fpr_sock_en=1
            if (( _fpr_svc_en || _fpr_sock_en )); then
                _row "fprintd"  ">>  enabled (idle — no fingerprint hardware detected; will activate when connected)"
            else
                _row "fprintd"  "~~  no fingerprint hardware detected — enroll a finger once hardware is connected: fprintd-enroll"
            fi
        fi
    fi

    _optional_begin
    # gpg-agent / dirmngr / keyboxd: socket-activated user services.
    # Idle between gpg operations is normal — only warn on hard failure state.
    if command -v gpg &>/dev/null || command -v gpg2 &>/dev/null; then
        for _gpg_unit in gpg-agent dirmngr keyboxd; do
            if _sysd_user cat "${_gpg_unit}.service" &>/dev/null 2>&1 || \
               _sysd_user cat "${_gpg_unit}.socket"  &>/dev/null 2>&1; then
                if _sysd_user is-failed --quiet "${_gpg_unit}.service" 2>/dev/null; then
                    _row "gpg/${_gpg_unit}" "!   failed — gpg operations may hang"
                    _rec "gpg ${_gpg_unit} in failed state — run: systemctl --user reset-failed ${_gpg_unit}"
                fi
                # Silent when idle or active — socket-activated, idle is normal
            fi
        done
    fi

    _optional_end
}

_section_security_audit() {
    _head "Security Tools"
    # Security auditing tools — show last scan date and hardening index if available
    if _check_tool_executable "lynis" "lynis"; then
        local lynis_log="/var/log/lynis.log"
        local lynis_report="/var/log/lynis-report.dat"
        local lynis_last="" lynis_score=""

        # Check timer status first
        local lynis_timer_active=0
        local lynis_next=""
        local _lynis_timer_en; _lynis_timer_en=$(systemctl is-enabled lynis.timer 2>/dev/null || echo "disabled")
        if [[ "$_lynis_timer_en" == "enabled" || "$_lynis_timer_en" == "static" ]]; then
            lynis_timer_active=1
            lynis_next=$(_timer_next_fmt lynis.timer)
        fi

        local lynis_warnings=0 lynis_suggestions=0
        if [[ -f "$lynis_report" && -s "$lynis_report" ]]; then
            lynis_last=$(grep '^report_datetime_start=' "$lynis_report" 2>/dev/null \
                | cut -d= -f2- | tr -d '\r' | head -1 || echo "")
            lynis_score=$(grep '^hardening_index=' "$lynis_report" 2>/dev/null \
                | cut -d= -f2 | tr -d '[:space:]' | head -1 || echo "")
            lynis_warnings=$(grep -c '^warning\[\]=' "$lynis_report" 2>/dev/null || echo "0")
            lynis_suggestions=$(grep -c '^suggestion\[\]=' "$lynis_report" 2>/dev/null || echo "0")
            [[ "$lynis_warnings"    =~ ^[0-9]+$ ]] || lynis_warnings=0
            [[ "$lynis_suggestions" =~ ^[0-9]+$ ]] || lynis_suggestions=0
        fi
        # Fall back to log file if report missing or empty (can happen on immutable-root systems)
        if [[ -z "$lynis_last" && -f "$lynis_log" && -s "$lynis_log" ]]; then
            lynis_last=$(grep 'Starting Lynis' "$lynis_log" 2>/dev/null \
                | tail -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1 || echo "")
            if [[ -z "$lynis_score" ]]; then
                lynis_score=$(grep -i 'hardening.index' "$lynis_log" 2>/dev/null \
                    | grep -oE '[0-9]+' | tail -1 || echo "")
            fi
        fi

        # Build score string with threshold context
        local lynis_score_str=""
        if [[ "$lynis_score" =~ ^[0-9]+$ ]]; then
            if (( lynis_score >= 85 )); then
                lynis_score_str="  (index: ${lynis_score}/100 — excellent)"
            elif (( lynis_score >= 70 )); then
                lynis_score_str="  (index: ${lynis_score}/100 — good)"
            elif (( lynis_score >= 50 )); then lynis_score_str="  (index: ${lynis_score}/100 — fair)"
            else
                lynis_score_str="  (index: ${lynis_score}/100 — poor)"
            fi
        fi
        local lynis_next_str=""
        [[ -n "$lynis_next" ]] && lynis_next_str="  (next: ${lynis_next})"

        if [[ -n "$lynis_last" ]]; then
            local lynis_age_days=$(( ( $(date +%s) - $(date -d "$lynis_last" +%s 2>/dev/null || echo 0) ) / 86400 ))

            # Choose status glyph based on hardening index and warning count
            local _lynis_sym="OK"
            if [[ "$lynis_score" =~ ^[0-9]+$ ]] && (( lynis_score < 50 )); then
                _lynis_sym="!!"
                _rec "Lynis hardening index is ${lynis_score}/100 (poor) — review suggestions: lynis show details"
            elif (( lynis_warnings > 0 )); then
                _lynis_sym="!"
                _rec "Lynis reported ${lynis_warnings} warning(s) — run: lynis show warnings"
            elif [[ "$lynis_score" =~ ^[0-9]+$ ]] && (( lynis_score < 70 )); then
                _lynis_sym="!"
                _rec "Lynis hardening index is ${lynis_score}/100 — review top suggestions to improve score"
            fi

            if (( lynis_timer_active )); then
                if (( lynis_age_days > 30 )); then
                    _row "lynis"  "!   timer active, last scan ${lynis_age_days}d ago${lynis_score_str}${lynis_next_str}"
                    _rec "Lynis timer stale — check: systemctl status lynis.timer && journalctl -u lynis"
                else
                    _row "lynis"  "${_lynis_sym}  timer active, last scan ${lynis_age_days}d ago${lynis_score_str}${lynis_next_str}"
                fi
            else
                if (( lynis_age_days > 30 )); then
                    _row "lynis"  "!   last scan ${lynis_age_days}d ago${lynis_score_str} — run: lynis audit system"
                    _rec "Lynis last ran ${lynis_age_days} days ago — enable timer: systemctl enable --now lynis.timer"
                else
                    _row "lynis"  "${_lynis_sym}  last scan ${lynis_age_days}d ago${lynis_score_str}"
                    _row2 "--  timer not active — run: systemctl enable --now lynis.timer"
                fi
            fi

            # Show warning/suggestion detail as continuation lines
            local _lynis_detail=""
            (( lynis_warnings    > 0 )) && _lynis_detail+="${lynis_warnings} warning(s)  "
            (( lynis_suggestions > 0 )) && _lynis_detail+="${lynis_suggestions} suggestion(s)"
            [[ -n "$_lynis_detail" ]] && _row2 "--  ${_lynis_detail%  }"
        else
            if (( lynis_timer_active )); then
                _row "lynis"     "--  timer active, no scan recorded yet${lynis_next_str}"
            else
                _row "lynis"     "~~  no scan recorded — run: lynis audit system"
                _rec "Enable lynis timer: systemctl enable --now lynis.timer"
            fi
        fi
    fi
    # Rootkit hunter — show last scan date and any warnings
    if _check_tool_executable "rkhunter" "rkhunter"; then
        local rkh_log="/var/log/rkhunter.log"
        local rkh_last="" rkh_warnings=0
        if [[ -f "$rkh_log" ]]; then
            # rkhunter logs date as "Start date is Sat Mar 21 10:22:45 2026" (locale format, not ISO)
            # Extract the full date string and convert it via date -d for reliable parsing
            local _rkh_raw_date=""
            _rkh_raw_date=$(grep 'Start date' "$rkh_log" 2>/dev/null \
                | tail -1 | sed 's/.*Start date is //' | tr -d '[]' || echo "")
            if [[ -n "$_rkh_raw_date" ]]; then
                # Try ISO format first (some versions do log it), then locale format
                rkh_last=$(echo "$_rkh_raw_date" \
                    | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1 || echo "")
                if [[ -z "$rkh_last" ]]; then
                    # Convert locale date string to ISO — e.g. "Sat Mar 21 10:22:45 2026"
                    rkh_last=$(date -d "$_rkh_raw_date" '+%Y-%m-%d' 2>/dev/null || echo "")
                fi
            fi
            rkh_warnings=$(grep -c 'Warning:' "$rkh_log" 2>/dev/null || echo "0")
        fi
        if [[ -n "$rkh_last" ]]; then
            local rkh_age_days=$(( ( $(date +%s) - $(date -d "$rkh_last" +%s 2>/dev/null || echo 0) ) / 86400 ))
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
            _row "rkhunter"  "~~  no scan recorded — run: rkhunter --check to baseline"
        fi
    fi
}

_section_krb5() {
    # Show whenever krb5 client tools are installed — even if not configured.
    command -v kinit &>/dev/null || return 0

    _head "Kerberos"
    if [[ ! -f /etc/krb5.conf ]]; then
        _row "krb5"        "~~  not configured — /etc/krb5.conf absent"
        return 0
    fi

    local _krb5_realm=""
    _krb5_realm=$(grep -E '^\s*default_realm\s*=' /etc/krb5.conf 2>/dev/null \
        | head -1 | sed 's/.*=\s*//' | tr -d '[:space:]' || echo "")

    if [[ -z "$_krb5_realm" ]]; then
        _row "krb5"        "!   /etc/krb5.conf present but default_realm not set"
        _rec "Set default_realm in /etc/krb5.conf [libdefaults] section"
        return 0
    fi
    _row "Realm"       "--  ${_krb5_realm}"
    # Extract KDC hostname from [realms] section. Parse line by line —
    # the realm block starts at "REALM = {" and kdc = host appears inside it.
    local _kdc_host=""
    local _in_realm=0
    while IFS= read -r _kl; do
        # Entering our realm's block
        if echo "$_kl" | grep -qE "^[[:space:]]*${_krb5_realm}[[:space:]]*="; then
            _in_realm=1
            continue
        fi
        # Leaving the block (closing brace)
        if (( _in_realm )) && echo "$_kl" | grep -q '^[[:space:]]*}'; then
            break
        fi
        # Extract kdc = value inside the block
        if (( _in_realm )) && echo "$_kl" | grep -qE '^[[:space:]]*kdc[[:space:]]*='; then
            _kdc_host=$(echo "$_kl" | sed 's/.*=[[:space:]]*//' | sed 's/:.*//' | tr -d '[:space:]')
            break
        fi
    done < /etc/krb5.conf
    # Fall back to lowercased realm name if no explicit kdc= found
    [[ -z "$_kdc_host" ]] && _kdc_host="${_krb5_realm,,}"

    local _kdc_ok=0
    if command -v nc &>/dev/null; then
        nc -z -w 3 "$_kdc_host" 88 &>/dev/null 2>&1 && _kdc_ok=1
    else
        ping -c1 -W2 -q "$_kdc_host" &>/dev/null 2>&1 && _kdc_ok=1
    fi

    local _krb5_active=0
    [[ -f /etc/sssd/sssd.conf ]] && grep -q 'krb5\|kerberos' /etc/sssd/sssd.conf 2>/dev/null && _krb5_active=1
    if (( ! _krb5_active )); then
        # Check if any login user has a ccache
        local _ck_users=(); _get_login_users _ck_users
        for _ck in "${_ck_users[@]}"; do
            local _cuid; _cuid=$(id -u "$_ck" 2>/dev/null || echo "")
            [[ -f "/tmp/krb5cc_${_cuid}" ]] && _krb5_active=1 && break
        done
    fi

    if (( _kdc_ok )); then
        _row "KDC"        "OK  reachable  (${_kdc_host}:88)"
    elif (( _krb5_active )); then
        _row "KDC"        "!!  cannot reach KDC ${_kdc_host}:88"
        _rec "KDC unreachable — verify: nc -z -w3 ${_kdc_host} 88 && ping -c1 ${_kdc_host}"
    else
        _row "KDC"        "--  ${_kdc_host}:88 unreachable (no active Kerberos sessions)"
    fi
    # Only show clock skew and ticket state when Kerberos is actively in use
    if (( _kdc_ok || _krb5_active )); then
        local _ntp_sync=""
        _ntp_sync=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "")
        if [[ "$_ntp_sync" == "yes" ]]; then
            _row "Clock skew"  "OK  NTP synchronised"
        elif [[ "$_ntp_sync" == "no" ]]; then
            _row "Clock skew"  "!   NTP not synchronised — Kerberos auth will fail if skew > 5 min"
        fi
    fi
    local _krb5_login_users=()
    _get_login_users _krb5_login_users
    # Only show per-user ticket rows when Kerberos is actively in use or KDC reachable
    if (( _kdc_ok || _krb5_active )); then
        for _ku in "${_krb5_login_users[@]}"; do
            local _uhome; _uhome=$(getent passwd "$_ku" 2>/dev/null | cut -d: -f6 || echo "")
            local _uid;   _uid=$(id -u "$_ku" 2>/dev/null || echo "")
            local _ccache=""

            # Prefer KCM (systemd-based), fall back to FILE ccache
            if _sysd_user is-active --quiet krb5-ccache-monitor 2>/dev/null; then _ccache="KCM"
            else
                # Check default FILE ccache locations
                for _cc in "/tmp/krb5cc_${_uid}" \
                           "${_uhome}/.krb5cc" \
                           "${_uhome}/.kerberos/krb5cc"; do
                    [[ -f "$_cc" ]] && _ccache="$_cc" && break
                done
            fi

            if [[ -n "$_ccache" ]]; then
                # Parse ticket expiry
                local _klist_out; _klist_out=$(klist -c "$_ccache" 2>/dev/null || echo "")
                local _tgt_exp=""
                _tgt_exp=$(echo "$_klist_out" | grep "krbtgt/" \
                    | awk '{print $2, $3}' | head -1 || echo "")
                if [[ -n "$_tgt_exp" ]]; then
                    local _exp_ts; _exp_ts=$(date -d "$_tgt_exp" +%s 2>/dev/null || echo "0")
                    local _now_ts; _now_ts=$(date +%s)
                    if (( _exp_ts < _now_ts )); then
                        _row "Tickets"  "!   ${_ku}: TGT expired — run: kinit ${_ku}@${_krb5_realm}"
                    else
                        local _hrs_left=$(( (_exp_ts - _now_ts) / 3600 ))
                        _row "Tickets"  "OK  ${_ku}: TGT valid (${_hrs_left}h remaining)"
                    fi
                else
                    _row "Tickets"  "--  ${_ku}: no TGT in cache — run: kinit ${_ku}@${_krb5_realm}"
                fi
            else
                _row "Tickets"  "~~  ${_ku}: no credential cache"
            fi
        done
        if [[ -f /etc/krb5.keytab ]]; then
            local _kt_perms; _kt_perms=$(stat -c '%a' /etc/krb5.keytab 2>/dev/null || echo "")
            local _kt_principals; _kt_principals=$(klist -kt /etc/krb5.keytab 2>/dev/null \
                | grep -c '@' || echo "0")
            if [[ "$_kt_perms" != "600" && "$_kt_perms" != "400" ]]; then
                _row "keytab"    "!   /etc/krb5.keytab permissions ${_kt_perms} — should be 600"
                _rec "Fix keytab permissions: chmod 600 /etc/krb5.keytab"
            else
                _row "keytab"    "OK  present (${_kt_principals} principal(s), perms ${_kt_perms})"
            fi
        fi
    fi  # end: only when Kerberos active
    if _svc_present sssd; then
        if systemctl is-active --quiet sssd 2>/dev/null; then
            local _sssd_domains=""
            _sssd_domains=$(grep -E '^\[domain/' /etc/sssd/sssd.conf 2>/dev/null \
                | sed 's/\[domain\///' | tr -d ']' | tr '\n' ' ' | sed 's/ $//' || echo "")
            _row "sssd"      "OK  running${_sssd_domains:+  (${_sssd_domains})}"
        elif systemctl is-enabled --quiet sssd 2>/dev/null; then
            _row "sssd"      "!   enabled but not running — Kerberos auth via SSSD broken"
        else
            _row "sssd"      "!   not enabled — Kerberos auth will require manual kinit"
            _rec "Enable sssd for automatic Kerberos ticket management: systemctl enable --now sssd"
        fi
    fi
}

_section_users() {
    _head "Users & Access Control"
    local login_users=()
    _get_login_users login_users
    local _login_str; _login_str=$(IFS=' '; echo "${login_users[*]:-none detected}")
    _row "Login"     "--  ${_login_str}"
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
    if command -v chage &>/dev/null; then
        local _no_expiry=()
        for _u in "${login_users[@]}"; do
            local _pw_st; _pw_st=$(passwd -S "$_u" 2>/dev/null | awk '{print $2}' || echo "")
            [[ "$_pw_st" != "P" ]] && continue
            local _max_days
            _max_days=$(chage -l "$_u" 2>/dev/null \
                | awk -F": " '/Maximum number of days/{print $2}' | tr -d '[:space:]' || echo "")
            [[ "$_max_days" == "99999" || "$_max_days" == "-1" ]] && _no_expiry+=("$_u")
        done
        if [[ ${#_no_expiry[@]} -gt 0 ]]; then
            _row "Pw expiry"   "--  no expiry: $(_join "${_no_expiry[@]}") (to set: chage -M 365 <user>)"
        fi
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
        echo "$line" | grep -qE 'NOPASSWD[[:space:]]*:[[:space:]]*ALL[[:space:]]*$|NOPASSWD[[:space:]]*:[[:space:]]*ALL[[:space:]]*\)' && nopasswd+=("$line")
    done < <(grep -rh NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | grep -v '^[[:space:]]*#' || true)
    if [[ ${#nopasswd[@]} -gt 0 ]]; then
        _row "NOPASSWD"  "!   passwordless sudo entries found:"
        for e in "${nopasswd[@]}"; do _row2 "$(echo "$e" | xargs)"; done
        _rec "Passwordless sudo (NOPASSWD ALL) found — review /etc/sudoers.d/"
    else
        _row "NOPASSWD"  "OK  no unrestricted passwordless sudo"
    fi
    # Files in /etc/sudoers.d/ must be 0440 (root:root) — lynis FILE-7524.
    # World-readable sudoers files expose policy details to all users.
    if [[ -d /etc/sudoers.d ]]; then
        local _sudoers_bad=()
        while IFS= read -r _sf; do
            [[ -f "$_sf" ]] || continue
            local _mode; _mode=$(stat -c '%a' "$_sf" 2>/dev/null || echo "")
            # Acceptable: 0440, 0400 — anything with write or other-read is wrong
            if [[ -n "$_mode" && "$_mode" != "440" && "$_mode" != "400" ]]; then
                _sudoers_bad+=("$(basename "$_sf"):${_mode}")
            fi
        done < <(find /etc/sudoers.d/ -maxdepth 1 -type f 2>/dev/null || true)
        if [[ ${#_sudoers_bad[@]} -gt 0 ]]; then
            local _sb_str; _sb_str=$(IFS=' '; echo "${_sudoers_bad[*]}")
            _row "Sudoers perm" "!   wrong permissions: ${_sb_str}  (should be 0440)"
            _rec "Fix sudoers.d permissions — run: chmod 440 /etc/sudoers.d/*"
        else
            _row "Sudoers perm" "OK  /etc/sudoers.d/* permissions correct"
        fi
    fi
    # lynis FILE-7524: cron files should be 600, cron dirs 700.
    local _cron_perm_bad=()
    for _cf in /etc/crontab /etc/cron.deny /etc/cron.allow; do
        [[ -f "$_cf" ]] || continue
        local _cfm; _cfm=$(stat -c '%a' "$_cf" 2>/dev/null || echo "")
        [[ -n "$_cfm" && "$_cfm" != "600" ]] && _cron_perm_bad+=("$(basename "$_cf"):${_cfm}")
    done
    for _cd in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [[ -d "$_cd" ]] || continue
        local _cdm; _cdm=$(stat -c '%a' "$_cd" 2>/dev/null || echo "")
        [[ -n "$_cdm" && "$_cdm" != "700" && "$_cdm" != "750" ]] &&             _cron_perm_bad+=("$(basename "$_cd"):${_cdm}")
    done
    if [[ ${#_cron_perm_bad[@]} -gt 0 ]]; then
        local _cp_str; _cp_str=$(IFS=' '; echo "${_cron_perm_bad[*]}")
        _row "Cron perms"  "!   wrong permissions: ${_cp_str}  (should be 600/700)"
        _rec "Cron file/dir permissions incorrect — fix: chmod 600 /etc/cron* and chmod 700 /etc/cron.*"
    else
        _row "Cron perms"  "OK  cron file/dir permissions correct"
    fi
    # lynis FILE-7524: /etc/ssh/sshd_config should be 600.
    if [[ -f /etc/ssh/sshd_config ]]; then
        local _sshd_m; _sshd_m=$(stat -c '%a' /etc/ssh/sshd_config 2>/dev/null || echo "")
        if [[ -n "$_sshd_m" && "$_sshd_m" != "600" ]]; then
            _row "sshd_config"  "!   wrong permissions: ${_sshd_m}  (should be 600)"
            _rec "sshd_config has wrong permissions (${_sshd_m}) — fix: chmod 600 /etc/ssh/sshd_config"
        else
            _row "sshd_config"  "OK  permissions correct (${_sshd_m})"
        fi
    fi
    if [[ -d /home ]]; then
        local _home_perm_bad=()
        for _hdir in /home/*/; do
            [[ -d "$_hdir" ]] || continue
            local _huser; _huser=$(basename "$_hdir")
            # Skip non-login accounts (uid outside 1000–59999).
            # If id lookup fails (e.g. chroot user not in running db), skip to be safe.
            local _huid; _huid=$(id -u "$_huser" 2>/dev/null || echo "")
            [[ -z "$_huid" || ! "$_huid" =~ ^[0-9]+$ ]] && continue   # can't determine uid — skip
            (( _huid < 1000 || _huid >= 60000 )) && continue
            local _hmode; _hmode=$(stat -c '%a' "$_hdir" 2>/dev/null || echo "")
            if [[ -n "$_hmode" ]]; then
                local _world_bits=$(( 8#$_hmode & 8#007 ))
                (( _world_bits > 0 )) && _home_perm_bad+=("${_huser}:${_hmode}")
            fi
        done
        if [[ ${#_home_perm_bad[@]} -gt 0 ]]; then
            local _hpb_str; _hpb_str=$(IFS=' '; echo "${_home_perm_bad[*]}")
            _row "Home perms"  "!   world-accessible: ${_hpb_str}  (recommend 0750 or 0700)"
            _rec "Home directories are world-accessible — fix: chmod 750 /home/<user>"
        else
            _row "Home perms"  "OK  no world-accessible home directories"
        fi
    fi
    local root_st; root_st=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")
    case "$root_st" in
        L|LK) _row "Root acct"  "OK  locked" ;;
        P)    _row "Root acct"  "!   has a password (locked root recommended)"
              _rec "Root has a password — to lock: passwd -l root" ;;
        *)    _row "Root acct"  "--  status unknown" ;;
    esac
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
            _rec "subuid/subgid missing for $(_join "${sub_missing[@]}") — run: usermod --add-sub-uids 100000-165535 --add-sub-gids 100000-165535 <user>  or: shani-user-setup"
        else
            _row "subuid"   "OK  configured for all users"
        fi
    fi
    # Pre-check: homed enabled-but-broken must always show
    if systemctl cat systemd-homed &>/dev/null 2>&1 && \
       systemctl is-enabled --quiet systemd-homed 2>/dev/null && \
       ! systemctl is-active --quiet systemd-homed 2>/dev/null; then
        _row "homed"       "!!  enabled but not running — homed users cannot log in"
    fi
    _optional_begin
    # Manages LUKS-encrypted, self-contained home directories. Only surface when
    # active or enabled — most systems don't use homed.
    if systemctl cat systemd-homed &>/dev/null 2>&1; then
        if systemctl is-active --quiet systemd-homed 2>/dev/null; then
            local _homed_users=""
            _homed_users=$(homectl list 2>/dev/null | grep -c '^' || echo "")
            _row "homed"       "OK  running${_homed_users:+  (${_homed_users} user(s))}"
        elif systemctl is-enabled --quiet systemd-homed 2>/dev/null; then
            _row "homed"       "!!  enabled but not running — homed users cannot log in"
            else
            _row "homed"       "~~  not enabled — portable encrypted home directories"
        fi
    fi

    _optional_end
}

_section_groups() {
    _head "Groups"
    local -A STATIC_GIDS=([sys]=3 [lp]=7 [kvm]=78 [video]=91 [scanner]=96 [input]=97 [cups]=209)
    # Dynamic groups (no fixed GID — just need to exist):
    local DYNAMIC_GROUPS=(realtime nixbld lxd libvirt)
    # Also check storage/network — not in shani-extra-groups but critical for desktop use:
    local EXTRA_SYSTEM=(storage network audio)

    # Build login user list once
    local login_users=()
    _get_login_users login_users

    local groups_missing=() groups_ok=0 groups_gid_wrong=()
    local membership_missing=()  # "user:group" pairs
    for grp in "${!STATIC_GIDS[@]}"; do
        local actual_gid; actual_gid=$(getent group "$grp" 2>/dev/null | cut -d: -f3 || echo "")
        if [[ -z "$actual_gid" ]]; then
            groups_missing+=("$grp")
        elif [[ "$actual_gid" != "${STATIC_GIDS[$grp]}" ]]; then
            groups_gid_wrong+=("${grp}(expected:${STATIC_GIDS[$grp]},actual:${actual_gid})")
            groups_ok=$(( groups_ok + 1 ))  # group exists, just wrong GID
        else
            groups_ok=$(( groups_ok + 1 ))
        fi
    done
    for grp in "${DYNAMIC_GROUPS[@]}"; do
        if ! getent group "$grp" &>/dev/null; then groups_missing+=("$grp"); else groups_ok=$(( groups_ok + 1 )); fi
    done
    local sys_missing=()
    for grp in "${EXTRA_SYSTEM[@]}"; do
        getent group "$grp" &>/dev/null || sys_missing+=("$grp")
    done
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
                          _rec "Group 'nixbld' missing — should be in ShaniOS base image; run: groupadd -r nixbld" ;;
                kvm)      _row2 "!!  kvm missing — /dev/kvm inaccessible, VMs broken"
                          _rec "Group 'kvm' missing — should be in base image; run: groupadd -r kvm" ;;
                video)    _row2 "!!  video missing — GPU/display access broken"
                          _rec "Group 'video' missing — should be in base image; run: groupadd -r video" ;;
                input)    _row2 "!!  input missing — raw input devices inaccessible (Wayland)"
                          _rec "Group 'input' missing — should be in base image; run: groupadd -r input" ;;
                realtime) _row2 "!   realtime missing — PipeWire RT scheduling unavailable"
                          _rec "Group 'realtime' missing — should be in base image; run: groupadd -r realtime" ;;
                libvirt)
                    if command -v virsh &>/dev/null || [[ -d /data/varlib/libvirt ]]; then
                        _row2 "!   libvirt missing — libvirt socket inaccessible"
                        _rec "Group 'libvirt' missing — run: groupadd -r libvirt"
                    fi ;;
                lxd)
                    if findmnt -n /var/lib/lxd &>/dev/null || [[ -d /data/varlib/lxd ]]; then
                        _row2 "!   lxd missing — LXD socket inaccessible"
                        _rec "Group 'lxd' missing — run: groupadd -r lxd"
                    fi ;;
                cups)     _row2 "!   cups missing — printing broken"
                          _rec "Group 'cups' missing — should be in base image; run: groupadd -r cups" ;;
                *)        _rec "Group '${grp}' missing: groupadd -r ${grp}" ;;
            esac
        done
    fi
    # GID mismatch — group exists but has wrong numeric ID; file permissions will be wrong
    if [[ ${#groups_gid_wrong[@]} -gt 0 ]]; then
        local _gw_str; _gw_str=$(IFS=' '; echo "${groups_gid_wrong[*]}")
        _row "GID wrong"  "!!  GID mismatch: ${_gw_str} — file permissions may be broken"
        _rec "System group GIDs don't match expected values — base image may be misconfigured"
    fi

    if [[ ${#sys_missing[@]} -gt 0 ]]; then
        local _sm_str; _sm_str=$(IFS=' '; echo "${sys_missing[*]}")
        _row "Util grps"  "!   missing: ${_sm_str} — udisks2/NM may not work"
        _rec "System groups missing (${_sm_str}) — should be in base image; run: groupadd ${_sm_str%% *}"
    fi
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

        if [[ ${#mem_bad[@]} -eq 0 ]]; then _row "Membership" "OK  all users in required groups"
        else
            for entry in "${mem_bad[@]}"; do
                local _u="${entry%%:*}" _missing_g="${entry#*:}"
                _row "Membership" "!   ${_u} missing: ${_missing_g}"
                _rec "User ${_u} not in groups (${_missing_g}) — run: shani-user-setup"
            done
        fi
    fi
    # Every login user must be in the realtime group for PipeWire RT scheduling.
    local rt_line rt_members=()
    rt_line=$(getent group realtime 2>/dev/null || grep '^realtime:' /etc/group 2>/dev/null || true)
    if [[ -z "$rt_line" ]]; then _row "realtime"  "!!  group missing — realtime-privileges package required"
    else
        IFS=',' read -ra rt_members <<< "${rt_line##*:}"
        local rt_display; rt_display=$(IFS=' '; echo "${rt_members[*]}" | tr -s ' ' | xargs)
        local _rt_login=() _missing_rt=()
        _get_login_users _rt_login
        for u in "${_rt_login[@]}"; do
            id -nG "$u" 2>/dev/null | grep -qw realtime || _missing_rt+=("$u")
        done
        if [[ ${#_missing_rt[@]} -gt 0 ]]; then
            _row "realtime"  "!   users missing from group: $(_join "${_missing_rt[@]}")"
            _rec "User(s) $(_join "${_missing_rt[@]}") not in 'realtime' group — run: shani-user-setup"
        elif [[ -z "$rt_display" ]]; then
            _row "realtime"  "!   group empty"
            _rec "'realtime' group empty — run: shani-user-setup"
        else
            _row "realtime"  "OK  ${rt_display}"
        fi
    fi

}

###############################################################################
### system_info — master status report                                       ###
###############################################################################

_section_hardware() {
    _head "Hardware"
    local cpu_model cpu_cores cpu_arch cpu_flags
    cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null \
        | cut -d: -f2 | sed 's/^ *//' | sed 's/  */ /g' || echo "unknown")
    cpu_cores=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "?")
    cpu_arch=$(uname -m 2>/dev/null || echo "?")
    cpu_flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null \
        | cut -d: -f2 | tr -s ' ' | tr -d '\n' | sed 's/^ //' || echo "")

    _row "CPU"        "--  ${cpu_model} (${cpu_cores} threads, ${cpu_arch})"
    # Report presence of key capability flags relevant to security and virt.
    local flags_ok=() flags_missing=()
    local -A flag_labels=(
        ["aes"]="AES-NI (hardware encryption)"
        ["avx"]="AVX (vector extensions)"
        ["avx2"]="AVX2"
    )
    for flag in aes avx avx2; do
        if echo "$cpu_flags" | grep -qw "$flag"; then flags_ok+=("$flag")
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
    # Outdated microcode leaves CPU vulnerability mitigations partially ineffective.
    local _ucode_rev=""
    _ucode_rev=$(grep -m1 "microcode" /proc/cpuinfo 2>/dev/null \
        | awk -F": " '{print $2}' | tr -d '[:space:]' || echo "")
    [[ -n "$_ucode_rev" ]] && _row "Microcode"   "--  revision ${_ucode_rev} (verify against vendor errata)"
    local mem_total_kb mem_total_gb
    mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo "0")
    if [[ "$mem_total_kb" =~ ^[0-9]+$ ]] && (( mem_total_kb > 0 )); then
        mem_total_gb=$(awk "BEGIN{printf \"%.1f\", $mem_total_kb/1048576}")
        _row "RAM"       "--  ${mem_total_gb} GB"
    fi
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
    # Only relevant when multiple GPUs are present (discrete + integrated)
    if command -v switcherooctl &>/dev/null; then
        local gpu_count; gpu_count=$(switcherooctl list 2>/dev/null | grep -c '^GPU' || echo "0")
        if [[ "$gpu_count" =~ ^[0-9]+$ ]] && (( gpu_count >= 2 )); then
            if systemctl is-active --quiet switcheroo-control 2>/dev/null; then
                _row "GPU switch"  "OK  switcheroo-control active (${gpu_count} GPUs)"
            else
                _row "GPU switch"  "!   ${gpu_count} GPUs found but switcheroo-control not running — PRIME offload unavailable"
                fi
        fi
    fi
    # Keeps GPU context loaded between jobs — reduces latency for CUDA/compute.
    # Only relevant on NVIDIA hardware.
    if command -v nvidia-persistenced &>/dev/null || \
       systemctl cat nvidia-persistenced &>/dev/null 2>&1; then
        local _has_nvidia=0
        lspci 2>/dev/null | grep -qi 'NVIDIA' && _has_nvidia=1
        if (( _has_nvidia )); then
            if systemctl is-active --quiet nvidia-persistenced 2>/dev/null; then
                _row "nvidia-pd"   "OK  nvidia-persistenced running"
            elif systemctl is-enabled --quiet nvidia-persistenced 2>/dev/null; then
                _row "nvidia-pd"   "!   enabled but not running"
            else
                _row "nvidia-pd"   "~~  not enabled — to enable: systemctl enable --now nvidia-persistenced"
            fi
        fi
        # Silent on non-NVIDIA systems
    fi
    # Shows the scaling governor when power-profiles-daemon is NOT active.
    if ! systemctl is-active --quiet power-profiles-daemon 2>/dev/null; then
        local _gov_file="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
        if [[ -r "$_gov_file" ]]; then
            local _gov; _gov=$(cat "$_gov_file" 2>/dev/null | tr -d '[:space:]' || echo "")
            if [[ -n "$_gov" ]]; then
                case "$_gov" in
                    performance)  _row "CPU gov" "--  ${_gov} (max speed, high power)" ;;
                    powersave)    _row "CPU gov" "--  ${_gov} (low power, may throttle)" ;;
                    schedutil|ondemand|conservative)
                                  _row "CPU gov" "OK  ${_gov} (dynamic scaling)" ;;
                    *)            _row "CPU gov" "--  ${_gov}" ;;
                esac
            fi
        fi
    fi
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
        elif (( cpu_temp >= 75 )); then _row "CPU temp"   "!   ${cpu_temp}°C (hot)"
        else
            _row "CPU temp"   "OK  ${cpu_temp}°C"
        fi
    fi
    # AMD: /sys/class/drm/card*/device/hwmon/hwmon*/temp1_input (millidegrees)
    # NVIDIA: nvidia-smi (if installed)
    local gpu_temp=""
    for _hwmon in /sys/class/drm/card*/device/hwmon/hwmon*/temp1_input; do
        [[ -f "$_hwmon" ]] || continue
        local _raw; _raw=$(cat "$_hwmon" 2>/dev/null || echo "")
        if [[ "$_raw" =~ ^[0-9]+$ ]] && (( _raw > 0 )); then
            gpu_temp=$(( _raw / 1000 ))
            break
        fi
    done
    if [[ -z "$gpu_temp" ]] && command -v nvidia-smi &>/dev/null; then
        gpu_temp=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader 2>/dev/null \
            | head -1 | tr -d '[:space:]' || echo "")
    fi
    if [[ "$gpu_temp" =~ ^[0-9]+$ ]]; then
        if (( gpu_temp >= 90 )); then
            _row "GPU temp"   "!!  ${gpu_temp}°C — critically hot"
            _rec "GPU temperature is ${gpu_temp}°C — check cooling and GPU fan"
        elif (( gpu_temp >= 75 )); then _row "GPU temp"   "!   ${gpu_temp}°C (hot)"
        else
            _row "GPU temp"   "OK  ${gpu_temp}°C"
        fi
    fi
    local has_virt=0
    local cpu_vendor=$(grep -m1 'vendor_id' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "")

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
            _rec "VT-x/AMD-V visible but /dev/kvm missing — load: modprobe kvm && modprobe kvm_amd  (or kvm_intel)"
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
            _row "Virt"      "!   ${virt_type} disabled in BIOS/UEFI — required for KVM/QEMU VMs"
            _rec "Enable ${virt_type} in BIOS/UEFI settings (look for Virtualisation, SVM Mode, or Intel VT) — Podman containers work without it"
        fi
    else
        _row "Virt"      "--  no virtualisation support (non-Intel/AMD CPU)"
    fi
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
            local iommu_groups=$(ls /sys/kernel/iommu_groups/ 2>/dev/null | wc -l)
            _row "IOMMU"     "OK  active (${iommu_groups} groups — PCI passthrough available)"
        else
            # Check if it's in the cmdline but not working
            local iommu_cmdline
            iommu_cmdline=$(grep -oE 'iommu=on|intel_iommu=on|amd_iommu=on' /proc/cmdline 2>/dev/null || echo "")
            if [[ -n "$iommu_cmdline" ]]; then
                _row "IOMMU"     "!   enabled in cmdline but no groups visible"
                _rec "IOMMU enabled in cmdline but not active — check BIOS VT-d/AMD-Vi setting"
            else
                _row "IOMMU"     "~~  not enabled — add intel_iommu=on or amd_iommu=on for PCI passthrough"
            fi
        fi
    fi
    if [[ -d /sys/class/bluetooth ]] || systemctl cat bluetooth.service &>/dev/null 2>&1; then
        local bt_st; bt_st=$(systemctl is-active bluetooth.service 2>/dev/null || echo "inactive")
        local bt_en; bt_en=$(systemctl is-enabled bluetooth.service 2>/dev/null || echo "disabled")
        local bt_hw=0; [[ -d /sys/class/bluetooth ]] && bt_hw=1
        if [[ "$bt_st" == "active" ]]; then
            _row "Bluetooth"  "OK  bluetooth.service active"
        elif [[ "$bt_en" == "enabled" ]]; then
            _row "Bluetooth"  "!   enabled but not running (${bt_st})"
        elif (( bt_hw )); then
            _row "Bluetooth"  "!   hardware present but bluetooth.service not enabled"
            _rec "Enable bluetooth: systemctl enable --now bluetooth"
        else
            _row "Bluetooth"  "~~  not enabled — to enable: systemctl enable --now bluetooth"
        fi
    fi

    # geoclue: D-Bus-activated location service. Idle is normal.
    if systemctl cat geoclue &>/dev/null 2>&1; then
        if systemctl is-active --quiet geoclue 2>/dev/null; then
            _row "geoclue"      "OK  running"
        elif systemctl is-enabled --quiet geoclue 2>/dev/null; then
            _row "geoclue"      ">>  enabled (idle — starts on demand via D-Bus)"
        else
            _row "geoclue"      "~~  not enabled — location services inactive: systemctl enable --now geoclue"
        fi
    fi
    if _svc_present usbmuxd; then
        local _ios_present=0
        grep -rql '05ac' /sys/bus/usb/devices/*/idVendor 2>/dev/null && _ios_present=1
        if systemctl is-active --quiet usbmuxd 2>/dev/null; then
            _row "usbmuxd"     "OK  running (iOS device access active)"
        elif (( _ios_present )); then
            if systemctl is-enabled --quiet usbmuxd 2>/dev/null || \
               systemctl is-enabled --quiet usbmuxd.socket 2>/dev/null; then
                _row "usbmuxd"     "!   Apple device detected but usbmuxd not responding — run: systemctl start usbmuxd"
                else
                _row "usbmuxd"     "!   Apple device detected but usbmuxd not enabled — iOS access unavailable"
                _rec "Enable usbmuxd for iOS device access: systemctl enable --now usbmuxd"
            fi
        elif systemctl is-enabled --quiet usbmuxd 2>/dev/null || \
             systemctl is-enabled --quiet usbmuxd.socket 2>/dev/null; then
            _row "usbmuxd"     ">>  enabled (idle — activates when Apple device is connected)"
        fi
        # Silent when not enabled and no iOS device present
    fi
    if _svc_present ratbagd; then
        if systemctl is-active --quiet ratbagd 2>/dev/null; then
            local _rb_devs=""
            _rb_devs=$(ratbagctl list 2>/dev/null | grep -c '.' || echo "")
            _row "ratbagd"     "OK  running${_rb_devs:+  (${_rb_devs} supported device(s))}"
        elif systemctl is-enabled --quiet ratbagd 2>/dev/null; then
            _row "ratbagd"     ">>  enabled (idle — activates on supported device connect)"
        else
            _row "ratbagd"     "~~  not enabled — gaming mouse daemon; activates on supported device"
        fi
    fi
    if _svc_present lircd; then
        local _lirc_cfg=0
        _lirc_has_remote() {
            grep -qlE '^[[:space:]]*begin[[:space:]]+remote' "$1" 2>/dev/null
        }
        if [[ -f /etc/lirc/lircd.conf ]] && _lirc_has_remote /etc/lirc/lircd.conf; then
            _lirc_cfg=1
        elif ls /etc/lirc/lircd.conf.d/*.conf &>/dev/null 2>&1; then
            for _lf in /etc/lirc/lircd.conf.d/*.conf; do
                _lirc_has_remote "$_lf" && { _lirc_cfg=1; break; }
            done
        fi
        if systemctl is-active --quiet lircd 2>/dev/null; then
            local _lirc_remotes=""
            _lirc_remotes=$(irsend LIST "" "" 2>/dev/null | grep -c '.' || echo "")
            _row "lircd"        "OK  running${_lirc_remotes:+  (${_lirc_remotes} remote(s))}"
        elif systemctl is-enabled --quiet lircd 2>/dev/null; then
            _row "lircd"        "!   enabled but not running"
        elif (( _lirc_cfg )); then
            _row "lircd"        "~~  configured, not enabled — to enable: systemctl enable --now lircd"
        fi
        # Silent when not configured and not enabled
    fi
    if command -v speech-dispatcher &>/dev/null || \
       _sysd_user cat speech-dispatcher &>/dev/null 2>&1; then
        local _orca_active=0
        pgrep -x orca &>/dev/null && _orca_active=1
        if _sysd_user is-active --quiet speech-dispatcher 2>/dev/null; then
            _row "speech-disp"  "OK  speech-dispatcher running"
        elif _sysd_user is-enabled --quiet speech-dispatcher 2>/dev/null; then
            _row "speech-disp"  ">>  enabled (idle — starts on demand)"
        elif (( _orca_active )); then
            _row "speech-disp"  "!   Orca is running but speech-dispatcher not enabled — TTS may fail"
            _rec "Enable speech-dispatcher for Orca TTS: systemctl --user enable --now speech-dispatcher"
        fi
        # Silent when neither enabled nor Orca active
    fi
    if command -v orca &>/dev/null; then
        pgrep -x orca &>/dev/null && _row "Orca"         "OK  running"
        # Silent when not running
    fi
    if _svc_present gpsd; then
        local gpsd_socket_active=0 gpsd_active=0
        systemctl is-active --quiet gpsd.socket 2>/dev/null && gpsd_socket_active=1
        systemctl is-active --quiet gpsd        2>/dev/null && gpsd_active=1
        if (( gpsd_active )) || (( gpsd_socket_active )); then
            local gpsd_dev=""
            gpsd_dev=$(grep -oP '(?<=^DEVICES=")[^"]+' /etc/conf.d/gpsd 2>/dev/null \
                | head -1 || echo "")
            [[ -z "$gpsd_dev" ]] && \
                gpsd_dev=$(grep -oP '(?<=^DEVICES=")[^"]+' /etc/default/gpsd 2>/dev/null \
                | head -1 || echo "")
            [[ -z "$gpsd_dev" ]] && \
                gpsd_dev=$(grep -oP '(?<=^DEVICES=)[^ ]+' /etc/gpsd.conf 2>/dev/null \
                | head -1 || echo "")
            if (( gpsd_socket_active )); then _row "gpsd"        "OK  socket active${gpsd_dev:+  (${gpsd_dev})}"
            else
                _row "gpsd"        "OK  running${gpsd_dev:+  (${gpsd_dev})}"
            fi
        elif systemctl is-enabled --quiet gpsd 2>/dev/null || \
             systemctl is-enabled --quiet gpsd.socket 2>/dev/null; then
            local _gpsd_dev=""
            _gpsd_dev=$(grep -oP '(?<=^DEVICES=")[^"]+' /etc/conf.d/gpsd 2>/dev/null | head -1 || \
                        grep -oP '(?<=^DEVICES=")[^"]+' /etc/default/gpsd 2>/dev/null | head -1 || echo "")
            if [[ -z "$_gpsd_dev" ]]; then
                _row "gpsd"            "!   enabled but not configured — set DEVICES= in /etc/conf.d/gpsd"
                _rec "gpsd enabled but DEVICES not set in /etc/conf.d/gpsd — add your GPS device path"
            else
                _row "gpsd"            "!   enabled but not running"
                fi
        else
            _row "gpsd"            "~~  not enabled — GPS inactive; set DEVICES in /etc/conf.d/gpsd then: systemctl enable --now gpsd.socket"
        fi
    fi

    _optional_begin
    if _svc_present apcupsd; then
        if systemctl is-active --quiet apcupsd 2>/dev/null; then
            local ups_status="" ups_bcharge="" ups_timeleft=""
            if command -v apcaccess &>/dev/null; then
                local _apc_out; _apc_out=$(apcaccess status 2>/dev/null || echo "")
                ups_status=$(awk  -F': +' '/^STATUS/{gsub(/ /,"",$2); print $2}' <<< "$_apc_out" | head -1)
                ups_bcharge=$(awk -F': +' '/^BCHARGE/{print $2}'              <<< "$_apc_out" | head -1)
                ups_timeleft=$(awk -F': +' '/^TIMELEFT/{print $2}'            <<< "$_apc_out" | head -1)
            fi
            local ups_info=""
            [[ -n "$ups_status"   ]] && ups_info+="status: ${ups_status}"
            [[ -n "$ups_bcharge"  ]] && ups_info+="${ups_info:+  }battery: ${ups_bcharge}"
            [[ -n "$ups_timeleft" ]] && ups_info+="${ups_info:+  }runtime: ${ups_timeleft}"
            _row "apcupsd"     "OK  running${ups_info:+  (${ups_info})}"
        elif systemctl is-enabled --quiet apcupsd 2>/dev/null; then
            local _apc_upstype=""
            _apc_upstype=$(grep -oP '(?<=^UPSTYPE\s)\S+' /etc/apcupsd/apcupsd.conf 2>/dev/null | head -1 || echo "")
            local _apc_device=""
            _apc_device=$(grep -oP '(?<=^DEVICE\s)\S+' /etc/apcupsd/apcupsd.conf 2>/dev/null | head -1 || echo "")
            if [[ -z "$_apc_upstype" || "$_apc_upstype" == "dumb" ]]; then
                _row "apcupsd"     "!   enabled but not configured — set UPSTYPE and DEVICE in /etc/apcupsd/apcupsd.conf"
                _rec "apcupsd enabled but UPSTYPE/DEVICE not configured — edit /etc/apcupsd/apcupsd.conf"
            else
                _row "apcupsd"     "!   enabled but not running"
            fi
        else
            _row "apcupsd"     "~~  not configured — edit /etc/apcupsd/apcupsd.conf, set UPSTYPE/DEVICE, then systemctl enable --now apcupsd"
        fi
    fi
    if [[ -d /sys/bus/thunderbolt ]] && \
       [[ $(ls /sys/bus/thunderbolt/devices/ 2>/dev/null | wc -l) -gt 0 ]]; then
        if _svc_present bolt; then
            local bolt_st; bolt_st=$(systemctl is-active bolt 2>/dev/null || echo "inactive")
            local bolt_en; bolt_en=$(systemctl is-enabled bolt 2>/dev/null || echo "disabled")
            if [[ "$bolt_st" == "active" ]]; then
                local bolt_enrolled="" bolt_connected=""
                if command -v boltctl &>/dev/null; then
                    bolt_enrolled=$(timeout 5 boltctl list 2>/dev/null | grep -c 'status:' || echo "")
                    bolt_connected=$(timeout 5 boltctl list 2>/dev/null | grep -c 'connected' || echo "")
                fi
                _row "Thunderbolt" "OK  bolt active${bolt_enrolled:+  (${bolt_enrolled} device(s) enrolled${bolt_connected:+, ${bolt_connected} connected})}"
            elif [[ "$bolt_en" == "enabled" ]]; then
                _row "Thunderbolt" "!   hardware present, bolt enabled but not running"
                else
                _row "Thunderbolt" "!   hardware present but bolt not enabled — devices will need manual auth"
                _rec "Enable bolt for Thunderbolt device authorization: systemctl enable --now bolt"
            fi
        else
            _row "Thunderbolt" "--  hardware present, bolt not installed"
        fi
    fi
    if command -v monitor-sensor &>/dev/null || \
       systemctl cat iio-sensor-proxy &>/dev/null 2>&1; then
        local _iio_devs=0
        [[ -d /sys/bus/iio/devices ]] && \
            _iio_devs=$(ls /sys/bus/iio/devices/ 2>/dev/null | wc -l || echo 0)
        if (( _iio_devs > 0 )); then
            if systemctl is-active --quiet iio-sensor-proxy 2>/dev/null; then
                _row "IIO sensors"  "OK  iio-sensor-proxy active (${_iio_devs} device(s))"
            elif systemctl is-enabled --quiet iio-sensor-proxy 2>/dev/null; then
                _row "IIO sensors"  "!   enabled but not running — auto-rotate/brightness unavailable"
                else
                _row "IIO sensors"  "!   IIO hardware present but iio-sensor-proxy not enabled — auto-rotate/brightness unavailable"
                _rec "Enable iio-sensor-proxy: systemctl enable --now iio-sensor-proxy"
            fi
        fi
        # Silent when no IIO devices present (most desktops)
    fi
    if command -v tablet-mode-switch &>/dev/null || \
       systemctl cat tablet-mode-switch &>/dev/null 2>&1; then
        if systemctl is-active --quiet tablet-mode-switch 2>/dev/null; then
            _row "tablet-mode"  "OK  running"
        elif systemctl is-enabled --quiet tablet-mode-switch 2>/dev/null; then
            _row "tablet-mode"  "!   enabled but not running"
        fi
        # Silent when not enabled
    fi
    if _svc_present acpid; then
        if systemctl is-active --quiet acpid 2>/dev/null; then
            local _acpi_handlers=""
            _acpi_handlers=$(find /etc/acpi/events/ -type f 2>/dev/null | wc -l || echo "")
            _row "acpid"        "OK  running${_acpi_handlers:+  (${_acpi_handlers} event handler(s))}"
        elif systemctl is-enabled --quiet acpid 2>/dev/null; then _row "acpid"        "!   enabled but not running"
            else
            _row "acpid"        "~~  not enabled — ACPI event scripts beyond logind; to enable: systemctl enable --now acpid"
        fi
    fi
    if _svc_present keyd; then
        if systemctl is-active --quiet keyd 2>/dev/null; then
            _row "keyd"        "OK  running"
        elif systemctl is-enabled --quiet keyd 2>/dev/null; then
            _row "keyd"        "!   enabled but not running — key remapping inactive"
        else
            _row "keyd"        "~~  not enabled — key remapping inactive; to enable: systemctl enable --now keyd"
        fi
    fi
    if _svc_present kanata; then
        if systemctl is-active --quiet kanata 2>/dev/null || \
           _sysd_user is-active --quiet kanata 2>/dev/null; then
            _row "kanata"      "OK  running"
        elif systemctl is-enabled --quiet kanata 2>/dev/null || \
             _sysd_user is-enabled --quiet kanata 2>/dev/null; then
            _row "kanata"      "!   enabled but not running"
        else
            _row "kanata"      "~~  not enabled — key remapping inactive; to enable: systemctl --user enable --now kanata"
        fi
    fi
    if _svc_present inputattach; then
        local _ia_cfg=0
        [[ -f /etc/conf.d/inputattach ]] && \
            grep -qE '^[[:space:]]*DEVICE=[^"'"'"'\s][^"'"'"'\s]*|^[[:space:]]*DEVICE=["'"'"'][^"'"'"']+["'"'"']' \
            /etc/conf.d/inputattach 2>/dev/null \
            && _ia_cfg=1
        if systemctl is-active --quiet inputattach 2>/dev/null; then
            local _ia_dev=""
            _ia_dev=$(grep -oP '(?<=^DEVICE=)[^ ]+' /etc/conf.d/inputattach 2>/dev/null \
                | head -1 || echo "")
            _row "inputattach"  "OK  running${_ia_dev:+  (${_ia_dev})}"
        elif systemctl is-enabled --quiet inputattach 2>/dev/null; then
            _row "inputattach"  "!   enabled but not running"
        elif (( _ia_cfg )); then
            _row "inputattach"  "~~  configured, not enabled — to enable: systemctl enable --now inputattach"
        fi
        # Silent when not configured and not enabled
    fi
    if _svc_present brltty; then
        if systemctl is-active --quiet brltty 2>/dev/null; then
            _row "brltty"       "OK  running"
        elif systemctl is-enabled --quiet brltty 2>/dev/null; then _row "brltty"       "!   enabled but not running"
        else
            _row "brltty"       "~~  not enabled — Braille display daemon; to enable: systemctl enable --now brltty"
        fi
    fi

    _optional_end
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
        local _pt_type=""
        _pt_type=$(lsblk -dno PTTYPE "/dev/${root_disk}" 2>/dev/null | tr -d '[:space:]' || echo "")
        if [[ -n "$_pt_type" ]]; then
            case "$_pt_type" in
                gpt)  _row "Part table"  "OK  GPT" ;;
                dos)  _row "Part table"  "!   MBR/DOS — UEFI systems should use GPT"
                      _rec "Root disk uses MBR — consider converting to GPT for full UEFI support" ;;
                *)    _row "Part table"  "--  ${_pt_type}" ;;
            esac
        fi

        if command -v smartctl &>/dev/null; then
            local smart
            smart=$(smartctl -H "/dev/${root_disk}" 2>/dev/null \
                | awk '/overall-health|result/{print $NF}' | head -1 || echo "")
            if [[ "$smart" == "PASSED" ]]; then
                _row "SMART"     "OK  PASSED"
            elif [[ -n "$smart" ]]; then
                _row "SMART"     "!!  ${smart}"
                _rec "SMART health FAILED on /dev/${root_disk} — back up data now: smartctl -a /dev/${root_disk}"
            else
                _row "SMART"     "--  not available (NVMe may need nvme-cli)"
            fi

            local smart_json=$(smartctl -j -a "/dev/${root_disk}" 2>/dev/null || true)
            if [[ -n "$smart_json" ]]; then
                local nvme_wear="" nvme_temp="" sata_wear="" sata_temp="" wear="" temp=""
                nvme_wear=$(echo "$smart_json" | grep -o '"percentage_used"[^,}]*' \
                    | grep -o '[0-9]*' | head -1 || echo "")
                # Top-level temperature object — SCT or NVMe thermal (most reliable)
                nvme_temp=$(echo "$smart_json" \
                    | grep -o '"temperature"[[:space:]]*:[[:space:]]*{[^}]*}' \
                    | grep -o '"current"[[:space:]]*:[[:space:]]*[0-9]*' \
                    | grep -o '[0-9]*' | head -1 || echo "")
                # Fallback: flat "temperature" value (older smartctl JSON format)
                [[ -z "$nvme_temp" ]] && \
                    nvme_temp=$(echo "$smart_json" \
                        | grep -o '"temperature"[[:space:]]*:[[:space:]]*[0-9]\{2,3\}' \
                        | grep -o '[0-9]\{2,3\}' | head -1 || echo "")

                # SATA wear: try IDs 177, 233, 173 (normalized: 100=new, decreases)
                local _sata_wear_val=""
                for _wear_id in 177 233 173; do
                    _sata_wear_val=$(echo "$smart_json" | grep -A10 "\"id\"[[:space:]]*:[[:space:]]*${_wear_id}[^0-9]" \
                        | grep '"value"' | grep -o '[0-9]*' | head -1 || echo "")
                    if [[ -n "$_sata_wear_val" && "$_sata_wear_val" =~ ^[0-9]+$ ]]; then
                        sata_wear=$(( 100 - _sata_wear_val ))
                        (( sata_wear < 0 )) && sata_wear=0
                        break
                    fi
                done
                # ID 202: value IS remaining life% — invert to get wear%
                if [[ -z "$sata_wear" ]]; then
                    local _sata_202_val=""
                    _sata_202_val=$(echo "$smart_json" | grep -A10 '"id"[[:space:]]*:[[:space:]]*202[^0-9]' \
                        | grep '"value"' | grep -o '[0-9]*' | head -1 || echo "")
                    if [[ -n "$_sata_202_val" && "$_sata_202_val" =~ ^[0-9]+$ ]]; then
                        sata_wear=$(( 100 - _sata_202_val ))
                        (( sata_wear < 0 )) && sata_wear=0
                    fi
                fi

                # SATA temp: try ID 190, 194, 231 raw_value, then fall back to top-level temp
                sata_temp=$(echo "$smart_json" | grep -A15 '"id"[[:space:]]*:[[:space:]]*19[04][^0-9]' \
                    | grep '"raw_value"' | grep -o '[0-9]\{2,3\}' | head -1 || echo "")
                # Sanity-check: raw_value for temp IDs can encode extra bytes in upper bits;
                # values > 127 are almost certainly encoded — use normalized value instead
                if [[ "$sata_temp" =~ ^[0-9]+$ ]] && (( sata_temp > 127 )); then
                    sata_temp=$(echo "$smart_json" | grep -A15 '"id"[[:space:]]*:[[:space:]]*19[04][^0-9]' \
                        | grep '"value"' | grep -o '[0-9]\{2,3\}' | head -1 || echo "")
                fi
                # ID 231 Temperature_Celsius (WD Green, some Intel SSDs)
                if [[ -z "$sata_temp" ]]; then
                    sata_temp=$(echo "$smart_json" | grep -A15 '"id"[[:space:]]*:[[:space:]]*231[^0-9]' \
                        | grep '"raw_value"' | grep -o '[0-9]\{2,3\}' | head -1 || echo "")
                    if [[ "$sata_temp" =~ ^[0-9]+$ ]] && (( sata_temp > 127 )); then
                        sata_temp=$(echo "$smart_json" | grep -A15 '"id"[[:space:]]*:[[:space:]]*231[^0-9]' \
                            | grep '"value"' | grep -o '[0-9]\{2,3\}' | head -1 || echo "")
                    fi
                fi
                # Final fallback: top-level temperature (SCT) already parsed as nvme_temp
                [[ -z "$sata_temp" ]] && sata_temp="$nvme_temp"

                wear="${nvme_wear:-$sata_wear}"
                temp="${nvme_temp:-$sata_temp}"

                if [[ -n "$wear" && "$wear" =~ ^[0-9]+$ ]]; then
                    if (( wear >= 90 )); then
                        _row "SSD wear"  "!!  ${wear}% used — replace soon"
                        _rec "SSD wear at ${wear}% — plan replacement before failure"
                    elif (( wear >= 70 )); then _row "SSD wear"  "!   ${wear}% used"
                    else
                        _row "SSD wear"  "OK  ${wear}% used"
                    fi
                fi
                if [[ -n "$temp" && "$temp" =~ ^[0-9]+$ ]]; then
                    if (( temp >= 65 )); then
                        _row "Disk temp"  "!!  ${temp}°C — critically hot"
                        _rec "Disk temperature is ${temp}°C — check cooling"
                    elif (( temp > 55 )); then _row "Disk temp"  "!   ${temp}°C (warm — SSDs throttle at 70°C)"
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
            _rec "@swap not mounted — check: systemctl status swap.mount && grep swap /etc/fstab"
        fi
    fi

    local swap_total swap_used
    swap_total=$(free -h 2>/dev/null | awk '/^Swap:/{print $2}' || echo "0")
    swap_used=$(  free -h 2>/dev/null | awk '/^Swap:/{print $3}' || echo "0")

    if [[ "$swap_total" == "0" || "$swap_total" == "0B" ]]; then
        _row "Swap"      "!   none active (hibernate unavailable)"
    else
        local _swap_disp
        if [[ "$swap_used" == "0B" || "$swap_used" == "0" ]]; then _swap_disp="${swap_total} total"
        else
            _swap_disp="${swap_used} used / ${swap_total}"
        fi
        _row "Swap"      "OK  ${_swap_disp}"
        local has_zram=0 swapfile=""
        swapon --show=NAME --noheadings 2>/dev/null | grep -q zram && has_zram=1
        swapfile=$(_find_swapfile)
        local has_swapfile=0; [[ -n "$swapfile" ]] && has_swapfile=1

        if (( has_zram && has_swapfile )); then
            _row2 "--  zram + swapfile (hibernate capable)"
        elif (( has_zram )); then
            _row2 "--  zram only — hibernate not available"
        elif (( has_swapfile )); then _row2 "--  swapfile: $swapfile"
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
                    (( ! uki_booted_bad )) && _rec "Hibernate offset stale — run: gen-efi configure ${booted}"
                else
                    _row "Hibernate"  "OK  resume_offset present (offset unverifiable)"
                fi
            elif (( ! resume_ok )); then
                _row "Hibernate"  "!!  swapfile present but resume= missing from cmdline"
                _rec "Swapfile present but resume= missing — run: gen-efi configure ${booted}"
            fi
        fi
    fi
    # Only relevant when /proc/mdstat shows active arrays.
    if [[ -f /proc/mdstat ]] && grep -q '^md[0-9]' /proc/mdstat 2>/dev/null; then
        local _md_arrays=$(grep -c '^md[0-9]' /proc/mdstat 2>/dev/null || echo "0")
        if systemctl is-active --quiet mdmonitor 2>/dev/null; then
            _row "mdmonitor"   "OK  running  (${_md_arrays} array(s))"
        elif systemctl is-enabled --quiet mdmonitor 2>/dev/null; then
            _row "mdmonitor"   "!   enabled but not running — RAID events will not be reported"
        else
            _row "mdmonitor"   "!   ${_md_arrays} RAID array(s) present but mdmonitor not enabled — failures will go unreported"
            _rec "Enable RAID monitoring: systemctl enable --now mdmonitor"
        fi
    fi
    # Monitors thin pools, mirrors and snapshots — alerts before they fill up.
    # Only relevant when LVM volume groups exist.
    if command -v vgs &>/dev/null; then
        local _vg_count=$(vgs --noheadings 2>/dev/null | wc -l || echo "0")
        if (( _vg_count > 0 )); then
            if systemctl is-active --quiet lvm2-monitor 2>/dev/null || \
               systemctl is-active --quiet dmeventd    2>/dev/null; then
                _row "lvm2-monitor" "OK  running  (${_vg_count} VG(s))"
            elif systemctl is-enabled --quiet lvm2-monitor 2>/dev/null || \
                 systemctl is-enabled --quiet dmeventd    2>/dev/null; then
                _row "lvm2-monitor" "!   enabled but not running — thin pool/mirror events missed"
                else
                _row "lvm2-monitor" "!   LVM VGs present but lvm2-monitor not enabled — thin pool overflows will go undetected"
                fi

            if systemctl cat lvm2-lvmpolld.socket &>/dev/null 2>&1; then
                if systemctl is-failed --quiet lvm2-lvmpolld.service 2>/dev/null; then
                    _row "lvmpolld"    "!   lvm2-lvmpolld.service failed — pvmove/lvconvert may stall"
                        elif ! systemctl is-enabled --quiet lvm2-lvmpolld.socket 2>/dev/null && \
                     ! systemctl is-active  --quiet lvm2-lvmpolld.socket 2>/dev/null; then
                    _row "lvmpolld"    "--  lvm2-lvmpolld.socket not enabled — pvmove/lvconvert polling unavailable"
                        fi
                # Silent when socket enabled/active and service idle — that is normal
            fi
        fi
    fi
    if systemctl cat e2scrub_all.timer &>/dev/null 2>&1; then
        local _has_ext4_lvm=0
        # Check for ext4 mounts that sit on an LVM device (dm- prefix)
        while IFS= read -r _src _tgt _fstype _rest; do
            if [[ "$_fstype" == "ext4" ]] && \
               [[ "$_src" == /dev/mapper/* || "$_src" == /dev/dm-* ]]; then
                _has_ext4_lvm=1; break
            fi
        done < <(findmnt --list -n -o SOURCE,TARGET,FSTYPE 2>/dev/null || true)
        if (( _has_ext4_lvm )); then
            if systemctl is-active --quiet e2scrub_all.timer 2>/dev/null; then
                _row "e2scrub"     "OK  timer active (ext4-on-LVM integrity checks scheduled)"
            elif systemctl is-enabled --quiet e2scrub_all.timer 2>/dev/null; then
                _row "e2scrub"     "!   timer enabled but not active"
                else
                _row "e2scrub"     "!   ext4-on-LVM volumes present but e2scrub_all.timer not enabled"
                _rec "Enable ext4 integrity checks: systemctl enable --now e2scrub_all.timer"
            fi
        fi
        # Silent when no ext4-on-LVM volumes detected
    fi

    _optional_begin
    # Monitors NVDIMM health events (media errors, unsafe shutdowns) via kernel
    # notifications. Only relevant when NVDIMM namespaces are present.
    if _svc_present ndctl-monitor; then
        local _ndctl_ns=""
        _ndctl_ns=$(ndctl list -N 2>/dev/null | grep -c '"dev"' || echo "0")
        if [[ "$_ndctl_ns" =~ ^[0-9]+$ ]] && (( _ndctl_ns > 0 )); then
            if systemctl is-active --quiet ndctl-monitor 2>/dev/null; then
                _row "ndctl-mon"   "OK  running  (${_ndctl_ns} namespace(s))"
            elif systemctl is-enabled --quiet ndctl-monitor 2>/dev/null; then
                _row "ndctl-mon"   "!   enabled but not running — NVDIMM health events not monitored"
                else
                _row "ndctl-mon"   "!   NVDIMM namespaces present but ndctl-monitor not enabled"
                fi
        fi
        # Silent when no NVDIMM namespaces detected
    fi
    # Monitors CXL (Compute Express Link) memory device events. Only relevant
    # when CXL devices are present.
    if _svc_present cxl-monitor; then
        local _cxl_devs=""
        _cxl_devs=$(cxl list -M 2>/dev/null | grep -c '"memdev"' || echo "0")
        if [[ "$_cxl_devs" =~ ^[0-9]+$ ]] && (( _cxl_devs > 0 )); then
            if systemctl is-active --quiet cxl-monitor 2>/dev/null; then
                _row "cxl-monitor"  "OK  running  (${_cxl_devs} CXL device(s))"
            elif systemctl is-enabled --quiet cxl-monitor 2>/dev/null; then
                _row "cxl-monitor"  "!   enabled but not running — CXL health events not monitored"
                else
                _row "cxl-monitor"  "!   CXL device(s) present but cxl-monitor not enabled"
                fi
        fi
        # Silent when no CXL devices detected
    fi
    # Sends quota warning messages to users via netlink. Only relevant when
    # disk quotas are enabled in /etc/fstab (usrquota/grpquota/prjquota).
    if _svc_present quota_nld; then
        local _quota_enabled=0
        grep -qE '\busrquota\b|\bgrpquota\b|\bprjquota\b' /etc/fstab 2>/dev/null \
            && _quota_enabled=1
        if (( _quota_enabled )); then
            if systemctl is-active --quiet quota_nld 2>/dev/null; then
                _row "quota_nld"   "OK  running"
            elif systemctl is-enabled --quiet quota_nld 2>/dev/null; then
                _row "quota_nld"   "!   enabled but not running"
                else
                _row "quota_nld"   "!   quotas in fstab but quota_nld not enabled — quota warnings won't be delivered"
                _rec "Enable quota daemon: systemctl enable --now quota_nld"
            fi
        fi
        # Silent when no quotas configured
    fi

    _optional_end
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
        elif (( free_gb_int < 15 )); then _row "Free"  "!   ${btrfs_free_gb} GB — getting low"
        else
            _row "Free"  "OK  ${btrfs_free_gb} GB"
        fi
    else
        _row "Free"  "--  unknown"
    fi
}

# Print device error stats row. Pass mount point.
_stor_check_device_errors() {
    local mnt="${1:-/}"
    local dev_stats; dev_stats=$(btrfs device stats "$mnt" 2>/dev/null || true)
    [[ -z "$dev_stats" ]] && return 0
    local nonzero; nonzero=$(echo "$dev_stats" | awk '$NF != "0"' || true)
    if [[ -n "$nonzero" ]]; then
        _row "Dev errors" "!!  non-zero error counters detected"
        echo "$nonzero" | while IFS= read -r line; do _row2 "!   $line"; done
        _rec "Btrfs device errors detected — run: btrfs device stats ${mnt} and check drive health"
    else
        _row "Dev errors" "OK  all zero"
    fi
}

# Print bees dedup daemon status row.
_stor_check_bees() {
    local bees_uuid; bees_uuid=$(_get_bees_uuid)
    if [[ -z "$bees_uuid" ]]; then
        _row "bees"  "--  could not determine Btrfs UUID for ${ROOTLABEL} (label may differ or LUKS device)"
        return 0
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
        _row "bees"  "!   beesd@${bees_short} enabled but not running${bees_last:+  (last run: ${bees_last})}"
    else
        _row "bees"  "!   beesd@${bees_short} configured but not enabled"
    fi
}

_section_storage() {
    _head "Storage"

    # Free space — shared helper
    _stor_check_free /

    # Device error stats — shared helper
    _stor_check_device_errors /
    local qgroup_out; qgroup_out=$(btrfs qgroup show / 2>&1 || true)
    if ! echo "$qgroup_out" | grep -q 'ERROR\|quota system is not enabled'; then
        if echo "$qgroup_out" | grep -qi 'inconsistent\|stale'; then
            _row "Quotas"    "!!  qgroup inconsistency detected — may cause phantom ENOSPC"
            _rec "Btrfs qgroup inconsistent — fix: btrfs quota rescan /"
        fi
    fi

    local scrub_st scrub_res
    scrub_st=$(btrfs scrub status / 2>/dev/null || true)
    scrub_res=$(echo "$scrub_st" | awk '/Status:/{print $2}' | head -1 || echo "")
    local scrub_timer_state
    scrub_timer_state=$(systemctl is-enabled btrfs-scrub.timer 2>/dev/null || echo "disabled")

    if [[ "$scrub_timer_state" == "enabled" || "$scrub_timer_state" == "static" ]]; then
        local scrub_next_fmt; scrub_next_fmt=$(_timer_next_fmt btrfs-scrub.timer)
        if [[ -n "$scrub_next_fmt" ]]; then _row "Scrub tmr"  "OK  enabled (next: ${scrub_next_fmt})"
        else
            _row "Scrub tmr"  "OK  enabled"
        fi
    else
        _row "Scrub tmr"  "!!  btrfs-scrub.timer not enabled"
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
        local _t_active=0; systemctl is-active --quiet "$unit" 2>/dev/null && _t_active=1
        local _t_state; _t_state=$(systemctl is-enabled "$unit" 2>/dev/null || echo "disabled")
        if (( _t_active )) || [[ "$_t_state" == "enabled" || "$_t_state" == "static" ]]; then
            t_ok+=("$name")
        else
            t_bad+=("$name")
        fi
    done
    local t_ok_str; t_ok_str=$(IFS=,; echo "${t_ok[*]}" | tr ',' ' ')
    local t_bad_str; t_bad_str=$(IFS=,; echo "${t_bad[*]}" | tr ',' ' ')
    if [[ ${#t_bad[@]} -eq 0 ]]; then
        _row "Maint tmrs"  "OK  enabled: ${t_ok_str}"
        for name in "${t_ok[@]}"; do
            local t_next_fmt; t_next_fmt=$(_timer_next_fmt "btrfs-${name}.timer")
            [[ -n "$t_next_fmt" ]] && _row2 "--  ${name}: next ${t_next_fmt}"
        done
    elif [[ ${#t_ok[@]} -eq 0 ]]; then
        _row "Maint tmrs"  "!!  all not enabled: ${t_bad_str}"
        local units; units=$(printf 'btrfs-%s.timer ' "${t_bad[@]}")
        _rec "Btrfs timers not enabled (${t_bad_str}) — run: systemctl enable --now ${units% }"
    else
        _row "Maint tmrs"  "!   enabled: ${t_ok_str}  |  not enabled: ${t_bad_str}"
        local units; units=$(printf 'btrfs-%s.timer ' "${t_bad[@]}")
    fi
    local _bal_last=""
    # LastTriggerUSec is the correct realtime property (LastTriggerUSecRealtime does not exist)
    _bal_last=$(systemctl show btrfs-balance.timer \
        --property=LastTriggerUSec --value 2>/dev/null \
        | grep -v "^0$\|^n/a\|^$" | head -1 || echo "")
    if [[ -n "$_bal_last" ]]; then
        # Value is a human-readable timestamp like "Sat 2026-03-21 00:41:03 IST"
        # Extract the ISO date part or pass through date -d for conversion
        local _bal_iso=""
        _bal_iso=$(echo "$_bal_last" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1 || echo "")
        [[ -z "$_bal_iso" ]] && \
            _bal_iso=$(date -d "$_bal_last" '+%Y-%m-%d' 2>/dev/null || echo "")
        [[ -n "$_bal_iso" ]] && _bal_last="$_bal_iso" || _bal_last=""
    fi
    if [[ -n "$_bal_last" ]]; then _row "Balance"     "--  last run: ${_bal_last}"
    else
        _row "Balance"     "--  no balance recorded (run: btrfs balance start -dusage=5 / )"
    fi
    if systemctl cat fstrim.timer &>/dev/null 2>&1; then
        local _ft_en; _ft_en=$(systemctl is-enabled fstrim.timer 2>/dev/null || echo "disabled")
        if [[ "$_ft_en" == "enabled" || "$_ft_en" == "static" ]]; then
            local _ft_fmt; _ft_fmt=$(_timer_next_fmt fstrim.timer)
            _row "fstrim"      "OK  timer enabled${_ft_fmt:+  (next: ${_ft_fmt})}"
        else
            # Check if btrfs-trim.timer covers this (Btrfs-specific TRIM, different from fstrim.timer)
            local _btrfs_trim_en; _btrfs_trim_en=$(systemctl is-enabled btrfs-trim.timer 2>/dev/null || echo "disabled")
            if [[ "$_btrfs_trim_en" == "enabled" || "$_btrfs_trim_en" == "static" ]]; then
                _row "fstrim"  "--  fstrim.timer not enabled (btrfs-trim.timer enabled — Btrfs TRIM covered)"
            else
                _row "fstrim"  "!   fstrim.timer not enabled — SSD TRIM not running periodically"
                _rec "Enable periodic TRIM: systemctl enable --now fstrim.timer"
            fi
        fi
    fi
    _stor_check_bees
    ! command -v compsize &>/dev/null && findmnt -n -t btrfs / &>/dev/null && _row "compsize"  "--  not installed"
    # D-Bus-activated — provides automount, format, and SMART info to desktop
    # file managers and KDE/GNOME settings. Starts on demand; idle is normal.
    if _svc_present udisks2; then
        if systemctl is-active --quiet udisks2 2>/dev/null; then
            _row "udisks2"     "OK  running"
        elif systemctl is-enabled --quiet udisks2 2>/dev/null; then
            _row "udisks2"     ">>  enabled (idle — starts on demand via D-Bus)"
        else
            _row "udisks2"     "!   not enabled — removable storage and automount will not work"
            _rec "Enable udisks2: systemctl enable udisks2"
        fi
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
    if [[ -n "$capacity" && "$capacity" =~ ^[0-9]+$ ]]; then
        if [[ "$status" == "Charging" || "$status" == "Full" ]]; then
            _row "Battery"  "OK  ${capacity}%  (${status})"
        elif (( capacity <= 10 )); then
            _row "Battery"  "!!  ${capacity}%  (${status}) — critically low"
            _rec "Battery critically low (${capacity}%) — plug in power"
        elif (( capacity <= 20 )); then _row "Battery"  "!   ${capacity}%  (${status}) — low"
        else
            _row "Battery"  "OK  ${capacity}%  (${status})"
        fi
    else
        _row "Battery"  "--  present (capacity unknown)"
    fi
    [[ -n "$technology" ]] && _row "Chemistry"  "--  ${technology}"
    if [[ -n "$cycle_count" && "$cycle_count" =~ ^[0-9]+$ && "$cycle_count" -gt 0 ]]; then
        if (( cycle_count >= 800 )); then
            _row "Cycles"  "!   ${cycle_count}  (degraded — consider replacement)"
            _rec "Battery has ${cycle_count} charge cycles — capacity may be significantly reduced"
        elif (( cycle_count >= 500 )); then _row "Cycles"  "--  ${cycle_count}  (moderate wear)"
        else
            _row "Cycles"  "OK  ${cycle_count}"
        fi
    fi
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
        elif (( health_pct < 80 )); then _row "Health"  "!   ${health_pct}% of design capacity"
        else
            _row "Health"  "OK  ${health_pct}% of design capacity"
        fi
    fi
    local ac_online=""
    for ac in /sys/class/power_supply/AC* /sys/class/power_supply/ADP*; do
        [[ -f "${ac}/online" ]] && ac_online=$(cat "${ac}/online" 2>/dev/null) && break
    done
    if [[ -n "$ac_online" ]]; then
        if [[ "$ac_online" == "1" ]]; then _row "AC power"  "OK  connected"; else _row "AC power"  "--  on battery"; fi
    fi
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

_section_printing() {
    _head "Printing & Scanning"
    if getent group cups &>/dev/null; then
        local cups_st; cups_st=$(systemctl is-active cups.socket 2>/dev/null || echo "inactive")
        if [[ "$cups_st" == "active" ]]; then
            _row "CUPS"      "OK  cups.socket active"
        elif systemctl is-enabled cups.service &>/dev/null 2>&1 || \
             systemctl is-enabled cups.socket  &>/dev/null 2>&1; then
            _row "CUPS"      "!   enabled but cups.socket is ${cups_st}"
            else
            _row "CUPS"      "~~  not enabled — printing inactive; to enable: systemctl enable --now cups.socket"
        fi
    fi
    if systemctl cat cups-browsed.service &>/dev/null 2>&1; then
        if systemctl is-active --quiet cups-browsed 2>/dev/null; then
            _row "cups-browsed" "OK  running"
        elif systemctl is-enabled --quiet cups-browsed 2>/dev/null; then
            _row "cups-browsed" "!   enabled but not running"
        else
            _row "cups-browsed" "~~  not enabled — network printer discovery inactive; to enable: systemctl enable --now cups-browsed"
        fi
    fi
    if _svc_present ipp-usb; then
        if systemctl is-active --quiet ipp-usb 2>/dev/null; then
            _row "ipp-usb"    "OK  running"
        elif systemctl is-enabled --quiet ipp-usb 2>/dev/null; then
            # Distinguish a clean exit-0 (no device) from an actual failure
            local _ipp_result
            _ipp_result=$(systemctl show ipp-usb --property=Result --value 2>/dev/null \
                | tr -d '[:space:]' || echo "")
            if [[ "$_ipp_result" == "success" || "$_ipp_result" == "" ]]; then
                _row "ipp-usb"    "OK  enabled (idle — no USB IPP device currently connected)"
            else
                _row "ipp-usb"    "!   enabled but not running — driverless USB printing/scanning unavailable"
                fi
        else
            _row "ipp-usb"    "~~  not enabled — driverless USB printing/scanning inactive; to enable: systemctl enable --now ipp-usb"
            _rec "Enable ipp-usb for driverless USB printers/scanners: systemctl enable --now ipp-usb"
        fi
    fi
    # Socket-activated — is-active is always inactive between scan jobs; check
    # is-enabled instead. If not enabled, all scanning silently fails.
    if command -v sane-find-scanner &>/dev/null || [[ -f /etc/sane.d/dll.conf ]]; then
        local saned_en; saned_en=$(systemctl is-enabled saned.socket 2>/dev/null || echo "disabled")
        if [[ "$saned_en" == "enabled" || "$saned_en" == "static" ]]; then
            _row "SANE"       "OK  saned.socket enabled"
        else
            _row "SANE"       "--  saned.socket not enabled (network scanning unavailable; local USB scanning still works)"
            _rec "Enable saned.socket for network scanning access: systemctl enable saned.socket"
        fi
    fi

}

# Lightweight service status check used by _section_servers for simple services.
# Prints OK/!/~~ row. Pass: label cmd_or_unit "opt description" [config_check_cmd]
_check_svc() {
    local label="$1" unit="$2" desc="$3"
    ! command -v "$unit" &>/dev/null && ! systemctl cat "$unit" &>/dev/null 2>&1 && return 0
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        _row "$label"  "OK  running"
    elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then _row "$label"  "!   enabled but not running"
    else
        _srv_opt_row "$label"  "~~  ${desc}"
    fi
}

# Check a simple web server: version info, 3-state active/enabled/optional.
# _check_webserver LABEL SVC VER_CMD OPT_MSG
_check_webserver() {
    local label="$1" svc="$2" ver_cmd="$3" opt_msg="$4"
    _svc_present "$svc" || return 0
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        local _ver; _ver=$(eval "$ver_cmd" 2>/dev/null || echo "")
        _row "$label"  "OK  running${_ver:+  (${_ver})}"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then _row "$label"  "!   enabled but not running"
    else
        _srv_opt_row "$label"  "~~  ${opt_msg}"
    fi
}
_section_servers() {
    # Only show if at least one server package is present
    local _any=0
    for _bin in smbd rpcbind exportfs gssproxy nbd-server \
                sshd rsync named unbound stubby kresd rec_control dnsmasq \
                snmpd \
                caddy nginx httpd php-fpm haproxy squid stunnel cockpit \
                mysqld mariadbd postgres redis-server memcached slapd \
                postfix dovecot minidlnad jellyfin rygel \
                transmission-daemon aria2c syncthing; do
        command -v "$_bin" &>/dev/null && { _any=1; break; }
    done
    _srv_opt_begin
    if (( ! _any )); then
        for _unit in smb nfs-server rpcbind gssproxy nbd-server \
                     sshd rsyncd named unbound stubby knot-resolver pdns-recursor dnsmasq \
                     snmpd \
                     caddy nginx httpd php-fpm haproxy squid stunnel cockpit \
                     mariadb postgresql redis memcached slapd \
                     postfix dovecot minidlna jellyfin rygel \
                     transmission aria2 syncthing; do
            systemctl cat "$_unit" &>/dev/null 2>&1 && { _any=1; break; }
        done
    fi
    _srv_opt_end
    (( _any )) || return 0

    _head "Servers"
    if [[ -f /etc/ssh/sshd_config ]] || [[ -d /etc/ssh/sshd_config.d ]] || \
       command -v sshd &>/dev/null; then

        local sshd_enabled=0 sshd_active=0 sshd_socket=0
        systemctl is-enabled --quiet sshd        2>/dev/null && sshd_enabled=1
        systemctl is-enabled --quiet sshd.socket 2>/dev/null && sshd_enabled=1
        systemctl is-active  --quiet sshd        2>/dev/null && sshd_active=1
        systemctl is-active  --quiet sshd.socket 2>/dev/null && sshd_socket=1

        if (( sshd_active )); then
            local ssh_port ssh_ver
            ssh_port=$(ss -tlnp 2>/dev/null \
                | awk '/sshd/{match($4,/:([0-9]+)$/,a); if(a[1]) print a[1]}' \
                | head -1 || echo "22")
            ssh_ver=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | head -1 || echo "")
            _row "sshd"      "OK  running${ssh_ver:+  (${ssh_ver})}${ssh_port:+  port ${ssh_port}}"
        elif (( sshd_socket )); then
            _row "sshd"      ">>  enabled (idle — socket-activated)"
        elif (( sshd_enabled )); then
            if systemctl is-failed --quiet sshd 2>/dev/null; then
                _row "sshd"  "!!  failed — run: systemctl status sshd"
                _rec "sshd in failed state — run: systemctl reset-failed sshd && systemctl start sshd"
            else
                _row "sshd"  "!!  enabled but not running"
                fi
        else
            _srv_opt_row "sshd"      "~~  not enabled — to allow remote login: systemctl enable --now sshd"
        fi

        if (( sshd_enabled )); then
            local missing_keys=()
            for keytype in rsa ecdsa ed25519; do
                [[ -f "/etc/ssh/ssh_host_${keytype}_key" ]] || missing_keys+=("$keytype")
            done
            if [[ ${#missing_keys[@]} -gt 0 ]]; then
                _row "SSH keys"  "!   host keys missing: $(_join "${missing_keys[@]}")"
                _rec "SSH host keys missing (${missing_keys[*]}) — regenerate: ssh-keygen -A"
            else
                _row "SSH keys"  "OK  host keys present (rsa ecdsa ed25519)"
            fi
        fi

        if (( sshd_enabled )) && \
           { [[ -f /etc/ssh/sshd_config ]] || [[ -d /etc/ssh/sshd_config.d ]]; }; then
            local ssh_root ssh_pw_auth
            # sshd -T dumps the fully merged effective config including all Include directives
            local _sshd_T; _sshd_T=$(sshd -T 2>/dev/null || echo "")
            if [[ -n "$_sshd_T" ]]; then
                ssh_root=$(echo "$_sshd_T" | awk '/^permitrootlogin /{print $2}' | head -1 || echo "")
                ssh_pw_auth=$(echo "$_sshd_T" | awk '/^passwordauthentication /{print $2}' | head -1 || echo "")
            else
                ssh_root=$(grep -rsh '^PermitRootLogin' \
                    /usr/lib/ssh/sshd_config.d/ /etc/ssh/sshd_config.d/ /etc/ssh/sshd_config \
                    2>/dev/null | tail -1 | awk '{print $2}' || echo "")
                ssh_pw_auth=$(grep -rsh '^PasswordAuthentication' \
                    /usr/lib/ssh/sshd_config.d/ /etc/ssh/sshd_config.d/ /etc/ssh/sshd_config \
                    2>/dev/null | tail -1 | awk '{print $2}' || echo "")
            fi

            if [[ -z "$ssh_root" ]]; then
                local _ssh_ver_maj
                _ssh_ver_maj=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+' | head -1 || echo "0")
                if (( _ssh_ver_maj < 8 )); then
                    _row "SSH root"   "!   not set — default may allow root login (OpenSSH <8)"
                    _rec "Set PermitRootLogin no in /etc/ssh/sshd_config (via /etc overlay)"
                fi
            else
                case "$ssh_root" in
                    no|prohibit-password|without-password)
                        _row "SSH root"  "OK  ${ssh_root}" ;;
                    yes)
                        _row "SSH root"  "!!  enabled — root password login allowed"
                        _rec "SSH root login enabled — set PermitRootLogin no in sshd_config" ;;
                    *)
                        _row "SSH root"  "!   unknown value: ${ssh_root}" ;;
                esac
            fi

            if [[ "$ssh_pw_auth" == "yes" ]]; then
                _row "SSH passwd"  "!   PasswordAuthentication yes — key-based auth recommended"
                _rec "SSH password authentication enabled — disable if using key-based auth only"
            elif [[ "$ssh_pw_auth" == "no" ]]; then _row "SSH passwd"  "OK  disabled (key-based only)"
            fi
        fi
    fi
    if _svc_present rsyncd; then
        local _rsyncd_cfg=0
        if [[ -f /etc/rsyncd.conf ]]; then
            local _in_module=0
            while IFS= read -r _rl; do
                if [[ "$_rl" =~ ^\[[[:space:]]*([^][:space:]]+)[[:space:]]*\] ]]; then
                    [[ "${BASH_REMATCH[1]}" != "global" ]] && _in_module=1 || _in_module=0
                elif (( _in_module )) && [[ "$_rl" =~ ^[[:space:]]*path[[:space:]]*= ]]; then _rsyncd_cfg=1; break
                fi
            done < /etc/rsyncd.conf
        fi
        if (( _rsyncd_cfg )); then
            local rsyncd_st; rsyncd_st=$(systemctl is-active rsyncd 2>/dev/null || echo "inactive")
            if [[ "$rsyncd_st" == "active" ]]; then
                local mod_count
                mod_count=$(grep -c '^\[' /etc/rsyncd.conf 2>/dev/null || echo "?")
                _row "rsyncd"      "OK  running  (${mod_count} module(s))"
                # Warn if any module allows anonymous writes (grep whole file — no -A needed)
                if grep -q 'read only *= *\(false\|no\)' /etc/rsyncd.conf 2>/dev/null; then
                    if ! grep -q 'auth users' /etc/rsyncd.conf 2>/dev/null; then
                        _row2 "!!  read only = false with no auth users — anonymous write access"
                        _rec  "rsyncd has writable module(s) with no auth — set 'auth users' and 'secrets file' in /etc/rsyncd.conf"
                    fi
                fi
            elif systemctl is-enabled --quiet rsyncd 2>/dev/null; then
                _row "rsyncd"      "!   enabled but not running"
                else
                _srv_opt_row "rsyncd"      "~~  configured, not enabled — to enable: systemctl enable --now rsyncd"
            fi
        else
            _srv_opt_row "rsyncd"          "~~  not configured — create /etc/rsyncd.conf with [module] sections, then systemctl enable --now rsyncd"
        fi
    fi
    if _svc_present dnsmasq; then
        local _dm_standalone=0
        # Standalone config: require at least one real directive, not just non-comment content
        # Default dnsmasq.conf ships with commented-out examples
        if [[ -f /etc/dnsmasq.conf ]] && \
           grep -qE '^[[:space:]]*(server|address|listen-address|interface|port|domain|dhcp-range)=' \
           /etc/dnsmasq.conf 2>/dev/null; then
            _dm_standalone=1
        elif ls /etc/dnsmasq.d/*.conf &>/dev/null 2>&1; then
            if grep -rlE '^[[:space:]]*(server|address|listen-address|interface|port|domain|dhcp-range)=' \
               /etc/dnsmasq.d/*.conf &>/dev/null 2>&1; then
                _dm_standalone=1
            fi
        fi
        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            local _dm_upstream
            _dm_upstream=$(grep -rh '^server=' /etc/dnsmasq.conf /etc/dnsmasq.d/ \
                2>/dev/null | wc -l || echo "0")
            _row "dnsmasq"     "OK  running${_dm_upstream:+  (${_dm_upstream} upstream server(s))}"
            # Warn if systemd-resolved stub listener conflicts on port 53
            if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
                local _stub
                _stub=$(grep -rshiE '^DNSStubListener=' \
                    /usr/lib/systemd/resolved.conf.d/ \
                    /etc/systemd/resolved.conf.d/ \
                    /etc/systemd/resolved.conf 2>/dev/null \
                    | tail -1 | cut -d= -f2 | tr -d '[:space:]' || echo "")
                if [[ "$_stub" != "no" && "$_stub" != "No" ]]; then
                    _row2 "!   systemd-resolved stub listener may conflict on port 53"
                    _rec "Set DNSStubListener=no in /etc/systemd/resolved.conf (via /etc overlay)"
                fi
            fi
        elif systemctl is-enabled --quiet dnsmasq 2>/dev/null; then
            local _nm_dns_dm; _nm_dns_dm=$(_nm_dns)
            if [[ "$_nm_dns_dm" == "dnsmasq" ]]; then _row "dnsmasq"     "!   enabled but not running"
            else
                _dns_conflict_row "dnsmasq" "dnsmasq" "$_nm_dns_dm"
            fi
        fi
    fi
    if _svc_present named; then
        local _named_cfg=0
        # Require a user-defined zone — default named.conf only has ".", "localhost",
        # and reverse-lookup zones for 127/0/255 which ship with the package.
        _named_has_user_zone() {
            local _f="$1"
            [[ -f "$_f" ]] || return 1
            grep -E '^[[:space:]]*zone[[:space:]]+"[^"]+"' "$_f" 2>/dev/null | \
                grep -qvE '"\."|"localhost"|"localhost\.localdomain"|"0\.0\.127\.in-addr\.arpa"|"1\.0\.0\.127\.in-addr\.arpa"|"255\.in-addr\.arpa"|"0\.in-addr\.arpa"|"\.ip6\.arpa"'
        }
        if command -v named-checkconf &>/dev/null && [[ -f /etc/named.conf ]]; then
            if named-checkconf /etc/named.conf &>/dev/null 2>&1; then
                _named_has_user_zone /etc/named.conf && _named_cfg=1
                # Also check any include files for user zones
                if (( ! _named_cfg )); then
                    while IFS= read -r _inc; do
                        _named_has_user_zone "$_inc" && { _named_cfg=1; break; }
                    done < <(grep -E '^[[:space:]]*include[[:space:]]+"' /etc/named.conf 2>/dev/null \
                        | grep -oE '"[^"]+"' | tr -d '"' || true)
                fi
            fi
        fi
        # Fallback: file check if named-checkconf not available
        (( ! _named_cfg )) && _named_has_user_zone /etc/named.conf && _named_cfg=1
        if systemctl is-active --quiet named 2>/dev/null; then
            local _named_zones=""
            _named_zones=$(rndc status 2>/dev/null \
                | awk '/number of zones/{print $NF}' | head -1 || echo "")
            _row "named"       "OK  running${_named_zones:+  (${_named_zones} zone(s))}"
        elif systemctl is-enabled --quiet named 2>/dev/null; then _dns_conflict_row "named" "named" "$(_nm_dns)"
        fi
    fi
    if _svc_present unbound; then
        local _ub_cfg=0
        # Require a real server: directive (interface: or access-control:) not just defaults
        if [[ -f /etc/unbound/unbound.conf ]] && \
           grep -qE '^[[:space:]]*(interface|access-control|forward-zone|stub-zone|auth-zone):' \
           /etc/unbound/unbound.conf 2>/dev/null; then
            _ub_cfg=1
        elif ls /etc/unbound/unbound.conf.d/*.conf &>/dev/null 2>&1; then
            grep -rlE '^[[:space:]]*(interface|access-control|forward-zone|stub-zone):' \
                /etc/unbound/unbound.conf.d/ &>/dev/null 2>&1 && _ub_cfg=1
        fi
        if systemctl is-active --quiet unbound 2>/dev/null; then
            local _ub_stats=""
            _ub_stats=$(unbound-control stats_noreset 2>/dev/null \
                | awk -F= '/^total.num.queries=/{print $2}' | head -1 || echo "")
            _row "unbound"     "OK  running${_ub_stats:+  (${_ub_stats} queries)}"
            # Warn if NM is not configured to use unbound
            _dns_resolver_active_warn "unbound" "unbound"
        elif systemctl is-enabled --quiet unbound 2>/dev/null; then _dns_conflict_row "unbound" "unbound" "$(_nm_dns)"
        fi
    fi
    if _svc_present stubby; then
        local _stubby_cfg=0
        if [[ -f /etc/stubby/stubby.yml ]] && \
           grep -qE '^[[:space:]]*(upstream_recursive_servers|listen_addresses):' \
           /etc/stubby/stubby.yml 2>/dev/null; then
            _stubby_cfg=1
        fi
        if systemctl is-active --quiet stubby 2>/dev/null; then
            local _stubby_listen=""
            _stubby_listen=$(grep -oP "(?<=address_data: )[^\s]+" \
                /etc/stubby/stubby.yml 2>/dev/null | head -1 || echo "")
            _row "stubby"      "OK  running${_stubby_listen:+  (${_stubby_listen})}"
        elif systemctl is-enabled --quiet stubby 2>/dev/null; then
            _row "stubby"      "!   enabled but not running"
        elif (( _stubby_cfg )); then
            _srv_opt_row "stubby"      "~~  configured, not enabled — typically used as upstream for dnsmasq/unbound; to enable: systemctl enable --now stubby"
        else
            _srv_opt_row "stubby"      "~~  not configured — configure /etc/stubby/stubby.yml with upstream TLS servers"
        fi
    fi
    # Knot Resolver is a modern DNSSEC-validating caching resolver.
    # Conflicts with NM dns=default — requires dns=none to own resolv.conf.
    if command -v kresctl &>/dev/null || command -v kresd &>/dev/null || \
       systemctl cat knot-resolver &>/dev/null 2>&1 || \
       systemctl cat kresd@1 &>/dev/null 2>&1; then
        local _kresd_unit="knot-resolver"
        systemctl cat kresd@1 &>/dev/null 2>&1 && _kresd_unit="kresd@1"
        if systemctl is-active --quiet "$_kresd_unit" 2>/dev/null; then
            _row "knot-res"    "OK  running"
            _dns_resolver_active_warn "knot-res" "knot-resolver"
        elif systemctl is-enabled --quiet "$_kresd_unit" 2>/dev/null; then
            _dns_conflict_row "knot-res" "${_kresd_unit}" "$(_nm_dns)"
        fi
    fi
    # PowerDNS Recursor is a high-performance DNS resolver.
    # Conflicts with NM dns=default — requires dns=none to own resolv.conf.
    if _svc_present pdns-recursor; then
        local _pdns_cfg=0
        [[ -f /etc/powerdns/recursor.conf ]] && \
            grep -qvE '^[[:space:]]*#|^[[:space:]]*$' /etc/powerdns/recursor.conf 2>/dev/null && \
            _pdns_cfg=1
        if systemctl is-active --quiet pdns-recursor 2>/dev/null; then
            local _pdns_queries=""
            _pdns_queries=$(rec_control get all-outqueries 2>/dev/null | head -1 || echo "")
            _row "pdns-rec"    "OK  running${_pdns_queries:+  (${_pdns_queries} outqueries)}"
            _dns_resolver_active_warn "pdns-rec" "pdns-recursor"
        elif systemctl is-enabled --quiet pdns-recursor 2>/dev/null; then
            _dns_conflict_row "pdns-rec" "pdns-recursor" "$(_nm_dns)"
        fi
    fi
    if _svc_present snmpd; then
        local _snmp_cfg=0
        local _snmp_conf="/etc/snmp/snmpd.conf"
        # Require a non-default community/user — default snmpd.conf has example content
        if [[ -f "$_snmp_conf" ]]; then
            if grep -qE '^[[:space:]]*(rocommunity|rwcommunity|rouser|rwuser)[[:space:]]+' "$_snmp_conf" 2>/dev/null && \
               ! grep -qE '^[[:space:]]*(rocommunity|rwcommunity)[[:space:]]+public[[:space:]]*$' "$_snmp_conf" 2>/dev/null; then
                _snmp_cfg=1
            fi
        fi
        if systemctl is-active --quiet snmpd 2>/dev/null; then
            _row "snmpd"       "OK  running"
            # Warn on default insecure community string
            if grep -qE '^[[:space:]]*rocommunity[[:space:]]+public' \
               /etc/snmp/snmpd.conf 2>/dev/null; then
                _row2 "!!  rocommunity public — exposes system info to all hosts"
                _rec "snmpd uses default 'public' community — restrict access in /etc/snmp/snmpd.conf"
            fi
        elif systemctl is-enabled --quiet snmpd 2>/dev/null; then
            if (( ! _snmp_cfg )); then
                _row "snmpd"       "!   enabled but not configured — edit /etc/snmp/snmpd.conf"
                _rec "snmpd enabled but /etc/snmp/snmpd.conf is empty or missing — configure communities/access before starting"
            else
                _row "snmpd"       "!   enabled but not running"
            fi
        elif (( _snmp_cfg )); then
            _srv_opt_row "snmpd"       "~~  configured, not enabled — to enable: systemctl enable --now snmpd"
        else
            _srv_opt_row "snmpd"       "~~  not enabled — SNMP monitoring inactive; to enable: systemctl enable --now snmpd"
        fi
    fi
    local _rd_profile; _rd_profile=$(cat /etc/shani-profile 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ "$_rd_profile" == "plasma" ]] || command -v krdp &>/dev/null; then
        if _sysd_user is-active --quiet plasma-krdp_server 2>/dev/null || \
           _sysd_user is-active --quiet krdp             2>/dev/null; then
            local _krdp_port=""
            _krdp_port=$(ss -tlnp 2>/dev/null \
                | awk '/krdp/{match($4,/:([0-9]+)$/,a); if(a[1]) print a[1]}' | head -1 || echo "")
            _row "krdp"        "OK  KDE RDP server active${_krdp_port:+  (port ${_krdp_port})}"
        elif _sysd_user is-enabled --quiet plasma-krdp_server 2>/dev/null || \
             _sysd_user is-enabled --quiet krdp            2>/dev/null; then
            _row "krdp"        "!   enabled but not running"
        elif command -v krdp &>/dev/null; then
            _srv_opt_row "krdp"        "~~  not enabled — to enable KDE RDP: systemctl --user enable --now plasma-krdp_server"
        fi
    fi
    if [[ "$_rd_profile" == "plasma" ]] || command -v krfb &>/dev/null; then
        if _sysd_user is-active --quiet krfb 2>/dev/null || \
           pgrep -x krfb &>/dev/null; then
            _row "krfb"        "OK  KDE VNC server active"
        elif _sysd_user is-enabled --quiet krfb 2>/dev/null; then
            _row "krfb"        "!   enabled but not running"
        elif command -v krfb &>/dev/null; then
            _srv_opt_row "krfb"        "~~  not enabled — to enable KDE VNC: enable via System Settings → Sharing → Remote Desktop"
        fi
    fi
    if [[ "$_rd_profile" == "gnome" ]] || \
       command -v grdctl &>/dev/null || \
       _sysd_user cat gnome-remote-desktop &>/dev/null 2>&1; then
        if _sysd_user is-active --quiet gnome-remote-desktop 2>/dev/null; then
            # Detect which protocols are enabled via gsettings
            local _grd_rdp="" _grd_vnc=""
            if command -v gsettings &>/dev/null; then
                _grd_rdp=$(gsettings get org.gnome.desktop.remote-desktop.rdp enable \
                    2>/dev/null | tr -d "'" || echo "")
                _grd_vnc=$(gsettings get org.gnome.desktop.remote-desktop.vnc enable \
                    2>/dev/null | tr -d "'" || echo "")
            fi
            local _grd_proto=""
            [[ "$_grd_rdp" == "true"  ]] && _grd_proto+="RDP"
            [[ "$_grd_vnc" == "true"  ]] && _grd_proto+="${_grd_proto:+, }VNC"
            [[ -z "$_grd_proto"       ]] && _grd_proto="no protocol enabled"
            _row "GRD"         "OK  gnome-remote-desktop active  (${_grd_proto})"
        elif _sysd_user is-enabled --quiet gnome-remote-desktop 2>/dev/null; then
            _row "GRD"         "!   enabled but not running"
        elif [[ "$_rd_profile" == "gnome" ]] && command -v grdctl &>/dev/null; then
            _srv_opt_row "GRD"         "~~  not enabled — to enable: Settings → Sharing → Remote Desktop"
        fi
    fi
    if _svc_present smb; then
        if [[ -f /etc/samba/smb.conf ]] && \
           grep -E '^\[' /etc/samba/smb.conf 2>/dev/null | grep -qvE '^\[(global|homes|printers|print\$)\]'; then
            local smbd_st; smbd_st=$(systemctl is-active smb 2>/dev/null || \
                                      systemctl is-active smbd 2>/dev/null || echo "inactive")
            if [[ "$smbd_st" == "active" ]]; then
                _row "Samba"      "OK  smbd running"
            elif systemctl is-enabled --quiet smb 2>/dev/null || \
                 systemctl is-enabled --quiet smbd 2>/dev/null; then
                _row "Samba"      "!   enabled but not running"
                else
                _srv_opt_row "Samba"      "~~  configured, not enabled — to enable: systemctl enable --now smb"
            fi
            if systemctl cat nmb &>/dev/null 2>&1 || command -v nmbd &>/dev/null; then
                if systemctl is-active --quiet nmb 2>/dev/null; then
                    _row "nmbd"       "OK  NetBIOS name resolution active"
                elif systemctl is-enabled --quiet nmb 2>/dev/null; then
                    _row "nmbd"       "!   enabled but not running"
                        else
                    _srv_opt_row "nmbd"       "~~  not enabled — NetBIOS browsing inactive: systemctl enable --now nmb"
                fi
            fi
            if systemctl cat winbind &>/dev/null 2>&1 || command -v winbindd &>/dev/null; then
                local _smb_security=""
                _smb_security=$(grep -i '^\s*security\s*=' /etc/samba/smb.conf 2>/dev/null \
                    | awk -F= '{print $2}' | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | head -1 || echo "")
                if [[ "$_smb_security" == "ads" || "$_smb_security" == "domain" ]]; then
                    if systemctl is-active --quiet winbind 2>/dev/null; then
                        _row "winbind"    "OK  running (AD/domain auth active)"
                    elif systemctl is-enabled --quiet winbind 2>/dev/null; then
                        _row "winbind"    "!   enabled but not running — domain auth broken"
                            else
                        _row "winbind"    "!   security=ads/domain set but winbind not enabled"
                        _rec "Enable winbind for AD/domain auth: systemctl enable --now winbind"
                    fi
                fi
            fi
        else
            _srv_opt_row "Samba"          "~~  not configured — create shares in /etc/samba/smb.conf, then systemctl enable --now smb"
        fi
    fi
    if _svc_present wsdd; then
        local _smb_cfg=0
        [[ -f /etc/samba/smb.conf ]] && grep -q '^\[' /etc/samba/smb.conf 2>/dev/null && _smb_cfg=1
        if systemctl is-active --quiet wsdd 2>/dev/null; then
            _row "wsdd"        "OK  running (WS-Discovery active)"
        elif systemctl is-enabled --quiet wsdd 2>/dev/null; then
            _row "wsdd"        "!   enabled but not running"
        elif (( _smb_cfg )); then
            _row "wsdd"        "--  Samba configured but wsdd not enabled (Windows network discovery will not work: systemctl enable --now wsdd)"
        fi
    fi
    if _svc_present rpcbind; then
        if systemctl is-active --quiet rpcbind 2>/dev/null || \
           systemctl is-active --quiet rpcbind.socket 2>/dev/null; then
            _row "rpcbind"     "OK  running"
        elif systemctl is-enabled --quiet rpcbind 2>/dev/null || \
             systemctl is-enabled --quiet rpcbind.socket 2>/dev/null; then
            if systemctl is-active --quiet rpcbind.socket 2>/dev/null || \
               systemctl is-enabled --quiet rpcbind.socket 2>/dev/null; then
                _row "rpcbind"     ">>  enabled (idle — socket-activated)"
            else
                _row "rpcbind"     "!   enabled but not running"
                fi
        else
            _srv_opt_row "rpcbind"     "~~  not enabled — required if using NFS: systemctl enable --now rpcbind"
        fi
    fi
    if _svc_present nfs-server; then
        if [[ -f /etc/exports ]] && grep -qv '^[[:space:]]*#' /etc/exports 2>/dev/null; then
            if systemctl is-active --quiet nfs-server 2>/dev/null; then
                local export_count
                export_count=$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' /etc/exports 2>/dev/null || echo "?")
                _row "NFS"        "OK  nfs-server running  (${export_count} export(s))"
                if command -v rpcbind &>/dev/null && \
                   ! systemctl is-active --quiet rpcbind 2>/dev/null; then
                    _row2 "!!  rpcbind not running — NFS clients will fail to mount"
                    _rec  "NFS active but rpcbind is down — run: systemctl enable --now rpcbind"
                fi
                if systemctl cat nfs-idmapd &>/dev/null 2>&1; then
                    if ! systemctl is-active --quiet nfs-idmapd 2>/dev/null; then
                        _row2 "!   nfs-idmapd not running — NFSv4 ownership may show as 'nobody'"
                                fi
                fi
                if systemctl cat rpc-statd &>/dev/null 2>&1; then
                    if systemctl is-enabled --quiet rpc-statd 2>/dev/null && \
                       ! systemctl is-active --quiet rpc-statd 2>/dev/null; then
                        _row2 "!   rpc-statd enabled but not running — NFSv3 lock recovery broken"
                                fi
                fi
                if systemctl cat rpc-gssd &>/dev/null 2>&1; then
                    if systemctl is-enabled --quiet rpc-gssd 2>/dev/null && \
                       ! systemctl is-active --quiet rpc-gssd 2>/dev/null; then
                        _row2 "!   rpc-gssd enabled but not running — Kerberos NFS mounts will fail"
                                fi
                fi
            elif systemctl is-enabled --quiet nfs-server 2>/dev/null; then
                _row "NFS"        "!   enabled but not running"
                else
                _row "NFS"        "--  /etc/exports has entries but nfs-server not enabled"
                _rec "NFS exports defined but service not enabled — run: systemctl enable --now nfs-server"
            fi
        else
            _srv_opt_row "NFS"            "~~  not configured — add exports to /etc/exports, then systemctl enable --now nfs-server"
        fi
    fi
    if _svc_present gssproxy; then
        if systemctl is-active --quiet gssproxy 2>/dev/null; then
            _row "gssproxy"     "OK  running"
        elif systemctl is-enabled --quiet gssproxy 2>/dev/null; then
            _row "gssproxy"     "!   enabled but not running — Kerberos auth will fail"
        else
            _srv_opt_row "gssproxy"     "~~  not enabled — Kerberos/NFS GSSAPI proxy; to enable: systemctl enable --now gssproxy"
        fi
    fi
    if _svc_present nbd-server; then
        if [[ -f /etc/nbd-server/config ]] && \
           grep -E '^\[' /etc/nbd-server/config 2>/dev/null | grep -qvE '^\[generic\]'; then
            local nbd_st; nbd_st=$(systemctl is-active nbd-server 2>/dev/null || echo "inactive")
            if [[ "$nbd_st" == "active" ]]; then
                local nbd_exports
                nbd_exports=$(grep -c '^\[' /etc/nbd-server/config 2>/dev/null || echo "?")
                _row "nbd-server"  "OK  running  (${nbd_exports} export(s))"
            elif systemctl is-enabled --quiet nbd-server 2>/dev/null; then
                _row "nbd-server"  "!   enabled but not running"
                else
                _srv_opt_row "nbd-server"  "~~  configured, not enabled — to enable: systemctl enable --now nbd-server"
            fi
        else
            _srv_opt_row "nbd-server"      "~~  not configured — create /etc/nbd-server/config with [export] sections, then systemctl enable --now nbd-server"
        fi
    fi
    if _svc_present caddy; then
        if systemctl is-active --quiet caddy 2>/dev/null; then
            local caddy_ver caddy_cfg_ok=0
            caddy_ver=$(caddy version 2>/dev/null | awk '{print $1}' | head -1 || echo "")
            [[ -f /etc/caddy/Caddyfile ]] && caddy_cfg_ok=1
            if (( caddy_cfg_ok )); then _row "Caddy"     "OK  running${caddy_ver:+  (${caddy_ver})}"
            else
                _row "Caddy"     "OK  running${caddy_ver:+  (${caddy_ver})} — no Caddyfile found"
                _row2 "--  create /etc/caddy/Caddyfile to configure sites"
            fi
        elif systemctl is-enabled --quiet caddy 2>/dev/null; then _row "Caddy"     "!   enabled but not running"
            else
            _srv_opt_row "Caddy"     "~~  not configured — to serve sites: create /etc/caddy/Caddyfile, then systemctl enable --now caddy"
        fi
    fi
    _check_webserver "nginx" "nginx" "nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1" "not enabled — to serve sites: systemctl enable --now nginx"
    _check_webserver "Apache" "httpd" "httpd -v 2>/dev/null | grep -oE 'Apache/[0-9]+\.[0-9]+\.[0-9]+' | head -1" "not enabled — to serve sites: systemctl enable --now httpd"
    # Required for nginx/Apache to serve PHP applications. Multiple versioned
    # units may exist (php-fpm, php83-fpm, etc.) — check any that are installed.
    local _php_fpm_found=0
    for _phpfpm_unit in php-fpm php83-fpm php82-fpm php81-fpm; do
        if command -v "${_phpfpm_unit}" &>/dev/null || \
           systemctl cat "${_phpfpm_unit}" &>/dev/null 2>&1; then
            _php_fpm_found=1
            if systemctl is-active --quiet "${_phpfpm_unit}" 2>/dev/null; then
                local _php_ver=""
                _php_ver=$(php --version 2>/dev/null | grep -oE '^PHP [0-9]+\.[0-9]+' | head -1 || echo "")
                _row "php-fpm"     "OK  ${_phpfpm_unit} running${_php_ver:+  (${_php_ver})}"
            elif systemctl is-enabled --quiet "${_phpfpm_unit}" 2>/dev/null; then
                _row "php-fpm"     "!   ${_phpfpm_unit} enabled but not running"
                else
                _row "php-fpm"     "--  ${_phpfpm_unit} installed, not enabled (to serve PHP: systemctl enable --now ${_phpfpm_unit})"
            fi
            break
        fi
    done
    if _svc_present haproxy; then
        local _hap_cfg=0
        local _hap_conf="${HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
        # Require a real frontend/backend/listen block — default config only has global+defaults
        if [[ -f "$_hap_conf" ]] && \
           grep -qE '^[[:space:]]*(frontend|backend|listen)[[:space:]]+\S' "$_hap_conf" 2>/dev/null; then
            # CLI: validate it's not just example content by confirming haproxy accepts it
            if command -v haproxy &>/dev/null; then haproxy -c -f "$_hap_conf" &>/dev/null 2>&1 && _hap_cfg=1
            else
                _hap_cfg=1
            fi
        fi
        if systemctl is-active --quiet haproxy 2>/dev/null; then
            local _hap_ver=""
            _hap_ver=$(haproxy -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
            _row "HAProxy"     "OK  running${_hap_ver:+  (v${_hap_ver})}"
        elif systemctl is-enabled --quiet haproxy 2>/dev/null; then
            if (( ! _hap_cfg )); then
                _row "HAProxy"     "!   enabled but not configured — add frontend/backend to /etc/haproxy/haproxy.cfg"
                _rec "HAProxy enabled but no frontend/backend in /etc/haproxy/haproxy.cfg — configure before starting"
            else
                _row "HAProxy"     "!   enabled but not running"
                fi
        elif (( _hap_cfg )); then
            _srv_opt_row "HAProxy"     "~~  configured, not enabled — to enable: systemctl enable --now haproxy"
        else
            _srv_opt_row "HAProxy"     "~~  not enabled — to enable: systemctl enable --now haproxy"
        fi
    fi
    if _svc_present squid; then
        local _squid_cfg=0
        [[ -f /etc/squid/squid.conf ]] &&             grep -qE '^http_access allow' /etc/squid/squid.conf 2>/dev/null &&             ! grep -qE '^http_access allow all' /etc/squid/squid.conf 2>/dev/null &&             _squid_cfg=1
        # Also accept if config has a custom acl definition
        [[ -f /etc/squid/squid.conf ]] &&             grep -qE '^acl\s+localnet\s+src\s+[0-9]' /etc/squid/squid.conf 2>/dev/null &&             _squid_cfg=1
        if systemctl is-active --quiet squid 2>/dev/null; then
            _row "squid"       "OK  running"
        elif systemctl is-enabled --quiet squid 2>/dev/null; then
            if (( ! _squid_cfg )); then
                _row "squid"       "!   enabled but not configured — define acl/http_access in /etc/squid/squid.conf"
                _rec "Squid enabled but no custom acl/http_access in /etc/squid/squid.conf — configure before starting"
            else
                _row "squid"       "!   enabled but not running"
                fi
        elif (( _squid_cfg )); then
            _srv_opt_row "squid"       "~~  configured, not enabled — to enable: systemctl enable --now squid"
        else
            _srv_opt_row "squid"       "~~  not enabled — proxy inactive; configure /etc/squid/squid.conf then: systemctl enable --now squid"
        fi
    fi
    if _svc_present stunnel; then
        local _stunnel_cfg=0
        for _sf in /etc/stunnel/*.conf; do
            [[ -f "$_sf" ]] || continue
            # Require a named [service] block with a connect= directive — not just a global conf
            if grep -qE '^\[[^[:space:]]+\]' "$_sf" 2>/dev/null && \
               grep -qE '^[[:space:]]*connect[[:space:]]*=' "$_sf" 2>/dev/null; then
                _stunnel_cfg=1; break
            fi
        done
        if systemctl is-active --quiet stunnel 2>/dev/null; then
            _row "stunnel"     "OK  running"
        elif systemctl is-enabled --quiet stunnel 2>/dev/null; then
            if (( ! _stunnel_cfg )); then
                _row "stunnel"     "!   enabled but not configured — create /etc/stunnel/<name>.conf with cert and connect settings"
                _rec "stunnel enabled but no .conf found in /etc/stunnel/ — create a tunnel config before starting"
            else
                _row "stunnel"     "!   enabled but not running"
                fi
        elif (( _stunnel_cfg )); then
            _srv_opt_row "stunnel"     "~~  configured, not enabled — to enable: systemctl enable --now stunnel"
        else
            _srv_opt_row "stunnel"     "~~  not enabled — TLS tunnel inactive; create /etc/stunnel/<n>.conf then: systemctl enable --now stunnel"
        fi
    fi
    _check_svc "Cockpit" "cockpit.socket" "not enabled — systemctl enable --now cockpit.socket"
    if command -v mariadbd &>/dev/null || command -v mysqld &>/dev/null || \
       systemctl cat mariadb &>/dev/null 2>&1 || systemctl cat mysqld &>/dev/null 2>&1; then
        local _db_unit="mariadb"
        systemctl cat mysqld &>/dev/null 2>&1 && ! systemctl cat mariadb &>/dev/null 2>&1 && _db_unit="mysqld"
        local _db_ver; _db_ver=$(mariadb --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
            || mysql --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        if systemctl is-active --quiet "$_db_unit" 2>/dev/null; then
            _row "MariaDB"     "OK  running${_db_ver:+  (v${_db_ver})}"
        elif systemctl is-enabled --quiet "$_db_unit" 2>/dev/null; then
            _row "MariaDB"     "!   enabled but not running"
        else
            _srv_opt_row "MariaDB"     "~~  not enabled — to enable: systemctl enable --now mariadb"
        fi
    fi
    _check_webserver "PostgreSQL" "postgresql" "psql --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1" "not enabled — to enable: systemctl enable --now postgresql"
    if _svc_present redis; then
        local _redis_unit="redis"
        _svc_present redis-server && ! _svc_present redis && _redis_unit="redis-server"
        if systemctl is-active --quiet "$_redis_unit" 2>/dev/null; then
            local _redis_ver=""
            _redis_ver=$(redis-cli --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
            _row "Redis"       "OK  running${_redis_ver:+  (v${_redis_ver})}"
        elif systemctl is-enabled --quiet "$_redis_unit" 2>/dev/null; then
            _row "Redis"       "!   enabled but not running"
        else
            _srv_opt_row "Redis"       "~~  not enabled — to enable: systemctl enable --now redis"
        fi
    fi
    _check_svc "Memcached" "memcached" "not enabled — systemctl enable --now memcached"
    if _svc_present slapd; then
        local _ldap_cfg=0
        # CLI: check for a real user database beyond the default {-1}frontend / {0}config
        if command -v slaptest &>/dev/null; then
            if slaptest -Q -u 2>/dev/null | grep -qE 'config file testing succeeded' \
               || slaptest -Q -u &>/dev/null 2>&1; then
                # slaptest passes even on default install — check for non-default database
                # with a non-placeholder suffix (default ships dc=my-domain,dc=com)
                if [[ -d /etc/openldap/slapd.d ]]; then
                    local _mdb_file
                    _mdb_file=$(grep -rl '^olcDatabase:[[:space:]]*(mdb|hdb|bdb|ldif|sql)' \
                        /etc/openldap/slapd.d/ 2>/dev/null | head -1 || echo "")
                    if [[ -n "$_mdb_file" ]] && \
                       grep -q '^olcSuffix:' "$_mdb_file" 2>/dev/null && \
                       ! grep -qE '^olcSuffix:[[:space:]]*(dc=my-domain,dc=com|dc=example,dc=com|dc=nodomain)' \
                           "$_mdb_file" 2>/dev/null; then
                        _ldap_cfg=1
                    fi
                fi
            fi
        fi
        # Fallback: file check — require a real backend database with non-placeholder suffix
        if (( ! _ldap_cfg )); then
            if [[ -f /etc/openldap/slapd.conf ]] && \
               grep -qE '^[[:space:]]*database[[:space:]]+(mdb|hdb|bdb|ldif|sql)' \
               /etc/openldap/slapd.conf 2>/dev/null && \
               ! grep -qE '^[[:space:]]*suffix[[:space:]]+"(dc=my-domain,dc=com|dc=example,dc=com|dc=nodomain)"' \
               /etc/openldap/slapd.conf 2>/dev/null; then
                _ldap_cfg=1
            fi
            if [[ -d /etc/openldap/slapd.d ]]; then
                local _mdb_file2
                _mdb_file2=$(grep -rl '^olcDatabase:[[:space:]]*(mdb|hdb|bdb|ldif|sql)' \
                    /etc/openldap/slapd.d/ 2>/dev/null | head -1 || echo "")
                if [[ -n "$_mdb_file2" ]] && \
                   grep -q '^olcSuffix:' "$_mdb_file2" 2>/dev/null && \
                   ! grep -qE '^olcSuffix:[[:space:]]*(dc=my-domain,dc=com|dc=example,dc=com|dc=nodomain)' \
                       "$_mdb_file2" 2>/dev/null; then
                    _ldap_cfg=1
                fi
            fi
        fi
        if systemctl is-active --quiet slapd 2>/dev/null; then
            _row "slapd"         "OK  OpenLDAP running"
        elif systemctl is-enabled --quiet slapd 2>/dev/null; then
            _row "slapd"         "!   enabled but not running"
        elif (( _ldap_cfg )); then
            _srv_opt_row "slapd"         "~~  configured, not enabled — to enable: systemctl enable --now slapd"
        else
            _srv_opt_row "slapd"         "~~  not configured — configure /etc/openldap/slapd.conf, then systemctl enable --now slapd"
        fi
    fi
    # Commonly used for sending system mail (cron output, logwatch alerts).
    if _svc_present postfix; then
        local _pf_cfg=0
        # CLI: postconf reads compiled config including $config_directory includes
        if command -v postconf &>/dev/null; then
            local _pf_relay _pf_dest _pf_ifaces
            _pf_relay=$(postconf -h relayhost 2>/dev/null | tr -d '[:space:]')
            _pf_dest=$(postconf -h mydestination 2>/dev/null | tr -d '[:space:]')
            _pf_ifaces=$(postconf -h inet_interfaces 2>/dev/null | tr -d '[:space:]')
            # relayhost set → sending to a smarthost: clearly configured
            [[ -n "$_pf_relay" ]] && _pf_cfg=1
            # inet_interfaces != loopback-only → listening externally: clearly configured
            [[ "$_pf_ifaces" != "loopback-only" && "$_pf_ifaces" != "localhost" ]] && _pf_cfg=1
            # mydestination: only count as configured if it differs from all known defaults
            # Default installs ship one of these values:
            if (( ! _pf_cfg )) && [[ -n "$_pf_dest" ]]; then
                case "$_pf_dest" in
                    '$myhostname,localhost.$mydomain,localhost' | \
                    '$myhostname,localhost.$mydomain,localhost,$mydomain' | \
                    'localhost')
                        : ;; # default — not configured
                    *)
                        _pf_cfg=1 ;;
                esac
            fi
        fi
        # Fallback: file check — only relayhost or non-loopback inet_interfaces signal real config
        if (( ! _pf_cfg )); then
            [[ -f /etc/postfix/main.cf ]] && \
                grep -qE '^(relayhost|inet_interfaces)\s*=\s*\S' /etc/postfix/main.cf 2>/dev/null && \
                ! grep -qE '^inet_interfaces\s*=\s*(loopback-only|localhost)\s*$' /etc/postfix/main.cf 2>/dev/null && \
                _pf_cfg=1
        fi
        if systemctl is-active --quiet postfix 2>/dev/null; then
            local _pf_queue=""
            _pf_queue=$(postqueue -p 2>/dev/null | tail -1 | grep -oE '[0-9]+' | head -1 || echo "")
            _row "Postfix"     "OK  running${_pf_queue:+  (${_pf_queue} message(s) queued)}"
        elif systemctl is-enabled --quiet postfix 2>/dev/null; then
            if (( ! _pf_cfg )); then
                _row "Postfix"     "!   enabled but not configured — set relayhost/mydestination in /etc/postfix/main.cf"
                _rec "Postfix enabled but /etc/postfix/main.cf has no relayhost or mydestination — configure before starting"
            else
                _row "Postfix"     "!   enabled but not running — system mail delivery broken"
            fi
        elif (( _pf_cfg )); then
            _srv_opt_row "Postfix"     "~~  configured, not enabled — to enable: systemctl enable --now postfix"
        else
            _srv_opt_row "Postfix"     "~~  not enabled — to send system mail: systemctl enable --now postfix"
        fi
    fi
    if _svc_present dovecot; then
        local _dv_cfg=0
        # CLI: doveconf reads all conf.d/ includes and returns the compiled value
        if command -v doveconf &>/dev/null; then
            local _dv_mailloc=$(doveconf mail_location 2>/dev/null | awk -F'=' '{print $2}' | tr -d '[:space:]')
            [[ -n "$_dv_mailloc" && "$_dv_mailloc" != "" ]] && _dv_cfg=1
        fi
        # Fallback: file check if doveconf not available
        if (( ! _dv_cfg )); then
            { [[ -f /etc/dovecot/dovecot.conf ]] &&                 grep -qE '^mail_location\s*=' /etc/dovecot/dovecot.conf 2>/dev/null; } && _dv_cfg=1
            { [[ -f /etc/dovecot/conf.d/10-mail.conf ]] &&                 grep -qE '^mail_location\s*=' /etc/dovecot/conf.d/10-mail.conf 2>/dev/null; } && _dv_cfg=1
        fi
        if systemctl is-active --quiet dovecot 2>/dev/null; then
            _row "Dovecot"     "OK  running"
        elif systemctl is-enabled --quiet dovecot 2>/dev/null; then
            if (( ! _dv_cfg )); then
                _row "Dovecot"     "!   enabled but not configured — set mail_location in /etc/dovecot/conf.d/10-mail.conf"
                _rec "Dovecot enabled but mail_location not set — configure /etc/dovecot/conf.d/10-mail.conf before starting"
            else
                _row "Dovecot"     "!   enabled but not running — IMAP/POP3 unavailable"
            fi
        elif (( _dv_cfg )); then
            _srv_opt_row "Dovecot"     "~~  configured, not enabled — to enable: systemctl enable --now dovecot"
        else
            _srv_opt_row "Dovecot"     "~~  not enabled — to serve IMAP/POP3: systemctl enable --now dovecot"
        fi
    fi
    if _svc_present minidlna; then
        local _dlna_cfg=0
        [[ -f /etc/minidlna.conf ]] &&             grep -qE '^media_dir=' /etc/minidlna.conf 2>/dev/null &&             _dlna_cfg=1
        if systemctl is-active --quiet minidlna 2>/dev/null; then
            _row "minidlna"    "OK  running"
        elif systemctl is-enabled --quiet minidlna 2>/dev/null; then
            if (( ! _dlna_cfg )); then
                _row "minidlna"    "!   enabled but not configured — set media_dir= in /etc/minidlna.conf"
                _rec "minidlna enabled but media_dir not set in /etc/minidlna.conf — configure before starting"
            else
                _row "minidlna"    "!   enabled but not running"
            fi
        elif (( _dlna_cfg )); then
            _srv_opt_row "minidlna"    "~~  configured, not enabled — to enable: systemctl enable --now minidlna"
        else
            _srv_opt_row "minidlna"    "~~  not enabled — to serve DLNA: systemctl enable --now minidlna"
        fi
    fi
    _check_svc "Jellyfin" "jellyfin" "not enabled — to stream media: systemctl enable --now jellyfin"

    _srv_opt_flush
}

_section_performance() {
    _head "Performance"

    # ── Power management ──────────────────────────────────────────────────────
    # power-profiles-daemon (ppd) is the correct daemon for Plasma and GNOME.
    # TLP and auto-cpufreq CONFLICT with ppd — only one stack should be active.
    local bat_present=0
    for _bd in /sys/class/power_supply/BAT* /sys/class/power_supply/CMB*; do
        [[ -d "$_bd" ]] && bat_present=1 && break
    done
    local ppd_active=0 tlp_active=0 acpufreq_active=0
    systemctl is-active --quiet power-profiles-daemon 2>/dev/null && ppd_active=1
    systemctl is-active --quiet tlp                   2>/dev/null && tlp_active=1
    systemctl is-active --quiet auto-cpufreq          2>/dev/null && acpufreq_active=1
    if (( ppd_active )); then
        local ppd_profile=""
        if command -v powerprofilesctl &>/dev/null; then
            ppd_profile=$(powerprofilesctl get 2>/dev/null | tr -d '[:space:]' || echo "")
        fi
        _row "Power"  "OK  power-profiles-daemon active${ppd_profile:+ (${ppd_profile})}"
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
        _row "Power"  "--  no power manager detected"
    fi

    # ── irqbalance ────────────────────────────────────────────────────────────
    # Distributes hardware interrupts across CPU cores — important for NVMe and
    # high-bandwidth network cards. Without it one core handles all IRQs.
    if command -v irqbalance &>/dev/null || systemctl cat irqbalance &>/dev/null 2>&1; then
        if systemctl is-active --quiet irqbalance 2>/dev/null; then
            _row "irqbalance"  "OK  running"
        elif systemctl is-enabled --quiet irqbalance 2>/dev/null; then
            _row "irqbalance"  "!   enabled but not running"
            _rec "irqbalance not running — run: systemctl start irqbalance  [auto]"
        else
            _row "irqbalance"  "!   not enabled — IRQs not distributed across cores"
            _rec "Enable irqbalance: systemctl enable --now irqbalance  [auto]"
        fi
    else
        _row "irqbalance"  "!   not installed — all IRQs handled by one core"
    fi

    # ── ananicy-cpp ───────────────────────────────────────────────────────────
    if command -v ananicy-cpp &>/dev/null || systemctl cat ananicy-cpp &>/dev/null 2>&1; then
        if systemctl is-active --quiet ananicy-cpp 2>/dev/null; then
            _row "ananicy-cpp" "OK  running"
        elif systemctl is-enabled --quiet ananicy-cpp 2>/dev/null; then
            _row "ananicy-cpp" "!   enabled but not running — CPU scheduling rules inactive"
            _rec "ananicy-cpp not running — run: systemctl enable --now ananicy-cpp  [auto]"
        else
            _row "ananicy-cpp" "!   not enabled — process priority management inactive"
            _rec "Enable ananicy-cpp: systemctl enable --now ananicy-cpp  [auto]"
        fi
    else
        _row "ananicy-cpp" "--  not installed"
    fi

    # ── gamemode ──────────────────────────────────────────────────────────────
    # gamemoded applies CPU governor, I/O priority, and GPU performance mode
    # when games launch. Wiki says enabled globally for all users.
    # gamemoded is a user-level service — check via _sysd_user, not systemctl.
    if command -v gamemoded &>/dev/null || \
       _sysd_user cat gamemoded.service &>/dev/null 2>&1 || \
       systemctl cat gamemoded.service &>/dev/null 2>&1; then
        if _sysd_user is-active --quiet gamemoded 2>/dev/null; then
            _row "gamemode"   "OK  gamemoded running"
        elif _sysd_user is-enabled --quiet gamemoded 2>/dev/null; then
            _row "gamemode"   "!   enabled but not running"
            _rec "gamemoded not running — run: systemctl --user enable --now gamemoded  [auto]"
        else
            _row "gamemode"   "!   not enabled — games won't get automatic performance boost"
            _rec "Enable gamemoded: systemctl --user enable --now gamemoded  [auto]"
        fi
    fi

    # ── Transparent Huge Pages ───────────────────────────────────────────────
    # THP=always causes latency spikes in Redis, databases, and games.
    local _thp_file="/sys/kernel/mm/transparent_hugepage/enabled"
    if [[ -f "$_thp_file" ]]; then
        local _thp
        _thp=$(cat "$_thp_file" 2>/dev/null | grep -oP '\[\K[^\]]+' || echo "")
        case "$_thp" in
            always)  _row "THP"  "!   always — may cause latency spikes in Redis/databases"
                     _rec "Set THP to madvise: echo madvise > /sys/kernel/mm/transparent_hugepage/enabled (persist via tmpfiles.d)" ;;
            madvise) _row "THP"  "OK  madvise (apps opt in)" ;;
            never)   _row "THP"  "--  disabled" ;;
            *)       [[ -n "$_thp" ]] && _row "THP"  "--  ${_thp}" ;;
        esac
    fi

    _optional_begin
    # ── thermald (Intel thermal management daemon) ────────────────────────────
    # Only relevant on Intel CPUs — gates on vendor check.
    if command -v thermald &>/dev/null || systemctl cat thermald &>/dev/null 2>&1; then
        local _is_intel=0
        grep -qi 'GenuineIntel' /proc/cpuinfo 2>/dev/null && _is_intel=1
        if (( _is_intel )); then
            if systemctl is-active --quiet thermald 2>/dev/null; then
                _row "thermald"   "OK  running (Intel thermal management active)"
            elif systemctl is-enabled --quiet thermald 2>/dev/null; then
                _row "thermald"   "!   enabled but not running"
                _rec "thermald not running — run: systemctl start thermald  [auto]"
            else
                _row "thermald"   "~~  not enabled — Intel CPU detected: systemctl enable --now thermald"
            fi
        fi
        # Silent on AMD/ARM
    fi

    # ── tuned (system performance tuning daemon) ──────────────────────────────
    # Applies performance/power profiles via tuned-profiles. Conflicts with
    # power-profiles-daemon (ppd) which is the preferred stack for GNOME/Plasma.
    if command -v tuned &>/dev/null || systemctl cat tuned &>/dev/null 2>&1; then
        if systemctl is-active --quiet tuned 2>/dev/null; then
            local _tuned_profile=""
            _tuned_profile=$(tuned-adm active 2>/dev/null \
                | awk -F': ' '/Current active profile/{print $2}' || echo "")
            _row "tuned"       "OK  running${_tuned_profile:+  (${_tuned_profile})}"
            if systemctl is-active --quiet power-profiles-daemon 2>/dev/null; then
                _row2 "!   power-profiles-daemon also active — may conflict"
                _rec  "Both tuned and power-profiles-daemon active — disable one"
            fi
        elif systemctl is-enabled --quiet tuned 2>/dev/null; then
            _row "tuned"       "!   enabled but not running"
            _rec "tuned not running — run: systemctl start tuned  [auto]"
        else
            _row "tuned"       "~~  not enabled — to enable: systemctl enable --now tuned"
        fi
    fi

    # ── preload (adaptive readahead daemon) ───────────────────────────────────
    # Monitors app usage and preloads frequently-used binaries into page cache.
    if command -v preload &>/dev/null || systemctl cat preload &>/dev/null 2>&1; then
        if systemctl is-active --quiet preload 2>/dev/null; then
            _row "preload"     "OK  running"
        elif systemctl is-enabled --quiet preload 2>/dev/null; then
            _row "preload"     "!   enabled but not running"
            _rec "preload not running — run: systemctl start preload  [auto]"
        else
            _row "preload"     "~~  not enabled — to enable: systemctl enable --now preload"
        fi
    fi
    _optional_end
}

_section_network() {
    _head "Network"
    if ! systemctl is-active --quiet NetworkManager 2>/dev/null; then
        _row "Network"  "!   NetworkManager not running"
        _rec "NetworkManager not running — run: systemctl enable --now NetworkManager"
    fi
    # Services that take over interface/DHCP management and conflict with NM.
    # Only warn when NM is actually active — if NM isn't running these are fine.
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then

        # Read NM DHCP backend early — used in dhcpcd conflict check below
        local _nm_dhcp=""
        _nm_dhcp=$(grep -rshE '^dhcp\s*=' \
            /usr/lib/NetworkManager/conf.d/ \
            /etc/NetworkManager/conf.d/ \
            /etc/NetworkManager/NetworkManager.conf 2>/dev/null \
            | tail -1 | awk -F'=' '{print $2}' | tr -d '[:space:]' || echo "")
        [[ -z "$_nm_dhcp" ]] && _nm_dhcp="internal"

        # systemd-networkd — direct conflict: both manage interfaces via udev rules
        if systemctl is-active --quiet systemd-networkd 2>/dev/null; then
            _row "networkd"    "!!  systemd-networkd active alongside NetworkManager — interfaces may fight"
            _rec "Both NetworkManager and systemd-networkd are active — disable one: systemctl disable --now systemd-networkd"
        fi

        # connman — direct conflict: its own DHCP, DNS, and interface manager
        if systemctl is-active --quiet connman 2>/dev/null; then
            _row "connman"     "!!  connman active alongside NetworkManager — network conflict"
            _rec "connman conflicts with NetworkManager — disable: systemctl disable --now connman"
            fi

        if systemctl is-active --quiet dhcpcd 2>/dev/null; then
            if [[ "$_nm_dhcp" == "dhcpcd" ]]; then
                : # NM is using dhcpcd as its DHCP backend — expected, not a conflict
            else
                local _dhcpcd_ifaces=""
                _dhcpcd_ifaces=$(ps -C dhcpcd -o args= 2>/dev/null \
                    | grep -oP '(?<=\s)\w+$' | sort -u | paste -sd ',' || echo "")
                local _nm_managed=""
                _nm_managed=$(nmcli -t -f DEVICE,STATE d 2>/dev/null \
                    | awk -F: '$2 != "unmanaged" {print $1}' | paste -sd ',' || echo "")
                local _overlap=0
                if [[ -n "$_dhcpcd_ifaces" && -n "$_nm_managed" ]]; then
                    while IFS=',' read -ra _dif; do
                        for _di in "${_dif[@]}"; do
                            [[ ",$_nm_managed," == *",${_di},"* ]] && { _overlap=1; break 2; }
                        done
                    done <<< "$_dhcpcd_ifaces"
                elif [[ -z "$_dhcpcd_ifaces" ]]; then _overlap=1
                fi
                if (( _overlap )); then
                    _row "dhcpcd"  "!!  dhcpcd running on NM-managed interface(s) — DHCP conflict${_dhcpcd_ifaces:+  (${_dhcpcd_ifaces})}"
                    _rec "dhcpcd and NetworkManager both managing DHCP — disable: systemctl disable --now dhcpcd"
                else
                    _row "dhcpcd"  "!   dhcpcd running alongside NM (unmanaged interface${_dhcpcd_ifaces:+: ${_dhcpcd_ifaces}}) — monitor for conflicts"
                fi
            fi
        fi

        # netctl — profile-based network manager, mutually exclusive with NM
        if systemctl is-active --quiet netctl 2>/dev/null; then
            _row "netctl"      "!!  netctl active alongside NetworkManager — network conflict"
            fi

        # wicd — legacy wireless/wired manager, mutually exclusive with NM
        if systemctl is-active --quiet wicd 2>/dev/null; then
            _row "wicd"        "!!  wicd active alongside NetworkManager — network conflict"
            fi

        # networking.service (Debian/Ubuntu ifupdown) — manages interfaces via /etc/network/interfaces
        if systemctl is-active --quiet networking 2>/dev/null; then
            _row "networking"  "!!  networking.service (ifupdown) active alongside NetworkManager — interface conflict"
            fi

    fi
    # Only check when NM is active — these are meaningless otherwise.
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        local _nm_conf="/etc/NetworkManager/NetworkManager.conf"
        local _nm_conf_dir="/etc/NetworkManager/conf.d"
        local _nm_lib_conf_dir="/usr/lib/NetworkManager/conf.d"

        local _nm_dns; _nm_dns=$(_nm_dns)

        case "$_nm_dns" in
            resolvconf|openresolv)
                # Needs resolvconf binary and openresolv dispatcher script
                if ! command -v resolvconf &>/dev/null; then
                    _row "NM dns"     "!!  dns=resolvconf but resolvconf not installed — DNS updates will fail"
                    _rec "NetworkManager dns=resolvconf but resolvconf binary missing — openresolv should be in base image"
                else
                    # Check dispatcher script exists
                    if [[ ! -f /etc/NetworkManager/dispatcher.d/09-openresolv ]] &&                        [[ ! -f /etc/NetworkManager/dispatcher.d/99-openresolv ]]; then
                        _row "NM dns"     "!   dns=resolvconf but NM dispatcher script missing"
                        _rec "NetworkManager openresolv dispatcher script not found in /etc/NetworkManager/dispatcher.d/ — DNS may not update on connect"
                    else
                        _row "NM dns"     "OK  dns=resolvconf (openresolv dispatcher present)"
                    fi
                fi
                ;;
            systemd-resolved)
                if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
                    _row "NM dns"     "!!  dns=systemd-resolved but systemd-resolved not running"
                    _rec "NetworkManager dns=systemd-resolved but systemd-resolved is not active — DNS updates will fail"
                else
                    _row "NM dns"     "OK  dns=systemd-resolved"
                fi
                ;;
            dnsmasq)
                # NM spawns its own dnsmasq instance — dnsmasq must be installed
                if ! command -v dnsmasq &>/dev/null; then
                    _row "NM dns"     "!!  dns=dnsmasq but dnsmasq not installed"
                    _rec "NetworkManager dns=dnsmasq but dnsmasq binary missing — install dnsmasq"
                else
                    _row "NM dns"     "OK  dns=dnsmasq"
                fi
                ;;
            none|"")
                _row "NM dns"     "--  dns=none (resolv.conf managed externally)"
                ;;
            default|*)
                # Silent — default behaviour, NM writes resolv.conf directly
                ;;
        esac

        case "$_nm_dhcp" in
            dhclient)
                if ! command -v dhclient &>/dev/null; then
                    _row "NM dhcp"    "!!  dhcp=dhclient but dhclient not installed — DHCP will fail"
                    _rec "NetworkManager dhcp=dhclient but dhclient binary missing — install dhclient or change to dhcp=internal"
                else
                    _row "NM dhcp"    "--  dhcp=dhclient"
                fi
                ;;
            dhcpcd)
                if ! command -v dhcpcd &>/dev/null; then
                    _row "NM dhcp"    "!!  dhcp=dhcpcd but dhcpcd not installed — DHCP will fail"
                    _rec "NetworkManager dhcp=dhcpcd but dhcpcd binary missing — install dhcpcd or change to dhcp=internal"
                else
                    _row "NM dhcp"    "--  dhcp=dhcpcd"
                fi
                ;;
            internal|*)
                # internal is the default — no extra binary needed, silent
                ;;
        esac

        local _nm_wifi_backend=""
        _nm_wifi_backend=$(grep -rshE '^wifi\.backend\s*=' "$_nm_lib_conf_dir"/ "$_nm_conf_dir"/ "$_nm_conf" 2>/dev/null \
            | tail -1 | awk -F'=' '{print $2}' | tr -d '[:space:]' || echo "")
        [[ -z "$_nm_wifi_backend" ]] && _nm_wifi_backend="wpa_supplicant"

        case "$_nm_wifi_backend" in
            iwd)
                if ! command -v iwctl &>/dev/null; then
                    _row "NM wifi"    "!!  wifi.backend=iwd but iwd not installed — Wi-Fi unavailable"
                    _rec "NetworkManager wifi.backend=iwd but iwd not installed — install iwd or change backend to wpa_supplicant"
                elif ! systemctl is-active --quiet iwd 2>/dev/null; then
                    _row "NM wifi"    "!!  wifi.backend=iwd but iwd not running — Wi-Fi unavailable"
                    _rec "NetworkManager uses iwd as Wi-Fi backend but iwd is not active — run: systemctl enable --now iwd"
                else
                    _row "NM wifi"    "OK  wifi.backend=iwd (iwd running)"
                fi
                ;;
            wpa_supplicant|*)
                # wpa_supplicant is default — NM manages it internally, silent unless broken
                ;;
        esac

        local _nm_conn_dirs=(
            /etc/NetworkManager/system-connections/
            /run/NetworkManager/system-connections/
        )

        # Map vpn service-type to the plugin binary NM invokes
        declare -A _nm_vpn_bins=(
            ["openvpn"]="nm-openvpn-service"
            ["vpnc"]="nm-vpnc-service"
            ["openconnect"]="nm-openconnect-service"
            ["wireguard"]="nm-wireguard-service"
            ["strongswan"]="nm-strongswan-service"
            ["l2tp"]="nm-l2tp-service"
            ["pptp"]="nm-pptp-service"
            ["ssh"]="nm-ssh-service"
            ["fortisslvpn"]="nm-fortisslvpn-service"
        )

        local _vpn_missing=()
        for _vpn_type in "${!_nm_vpn_bins[@]}"; do
            if grep -rqs "service-type.*${_vpn_type}" "${_nm_conn_dirs[@]}" 2>/dev/null; then
                local _plugin_bin="${_nm_vpn_bins[$_vpn_type]}"
                if ! command -v "$_plugin_bin" &>/dev/null && \
                   [[ ! -f "/usr/lib/NetworkManager/${_plugin_bin}" ]] && \
                   [[ ! -f "/usr/libexec/${_plugin_bin}" ]]; then
                    _vpn_missing+=("${_vpn_type}")
                fi
            fi
        done

        if [[ ${#_vpn_missing[@]} -gt 0 ]]; then
            local _vm_str; _vm_str=$(IFS=', '; echo "${_vpn_missing[*]}")
            _row "NM VPN"      "!!  saved VPN connection(s) missing plugin: ${_vm_str}"
            _rec "NM VPN plugin(s) missing for: ${_vm_str} — install networkmanager-${_vpn_missing[0]} (and others)"
        fi

    fi
    if command -v wpa_supplicant &>/dev/null || \
       systemctl cat wpa_supplicant.service &>/dev/null 2>&1; then
        local _nm_active=0
        systemctl is-active --quiet NetworkManager 2>/dev/null && _nm_active=1
        if systemctl is-failed --quiet wpa_supplicant.service 2>/dev/null; then
            _row "wpa_supp"    "!   wpa_supplicant.service failed — Wi-Fi auth broken"
        elif (( ! _nm_active )); then
            # NM not managing Wi-Fi — check if wpa_supplicant is running directly
            if systemctl is-active --quiet wpa_supplicant 2>/dev/null; then
                _row "wpa_supp"    "OK  running (standalone mode)"
            elif systemctl is-enabled --quiet wpa_supplicant 2>/dev/null; then
                _row "wpa_supp"    "!   enabled but not running — Wi-Fi auth unavailable"
                fi
        fi
        # Silent when NM is active and wpa_supplicant is healthy — NM manages it
    fi
    # Can be used standalone or as the Wi-Fi backend for NetworkManager.
    # If both iwd and wpa_supplicant are active, they may conflict.
    if _svc_present iwd; then
        if systemctl is-active --quiet iwd 2>/dev/null; then
            local _iwd_nets=""
            _iwd_nets=$(iwctl station list 2>/dev/null | grep -c 'connected' || echo "")
            _row "iwd"         "OK  running${_iwd_nets:+  (${_iwd_nets} connected)}"
            # Warn if wpa_supplicant is also active — they conflict
            if systemctl is-active --quiet wpa_supplicant 2>/dev/null; then
                _row2 "!   wpa_supplicant also active — iwd and wpa_supplicant conflict"
                _rec "Both iwd and wpa_supplicant active — disable one to avoid Wi-Fi conflicts"
            fi
        elif systemctl is-enabled --quiet iwd 2>/dev/null; then
            # Check if NM is configured to use iwd as its backend
            local _nm_wifi_be_iwd=""
            _nm_wifi_be_iwd=$(grep -rshE '^wifi\.backend\s*=' \
                /usr/lib/NetworkManager/conf.d/ \
                /etc/NetworkManager/conf.d/ \
                /etc/NetworkManager/NetworkManager.conf 2>/dev/null \
                | tail -1 | awk -F= '{print $2}' | tr -d '[:space:]' || echo "")
            if [[ "$_nm_wifi_be_iwd" == "iwd" ]]; then
                _row "iwd"     "!   enabled but not running — NM wifi.backend=iwd requires it"
                else
                _row "iwd"     "!!  enabled standalone — conflicts with NM/wpa_supplicant; disable: systemctl disable --now iwd"
                _rec "iwd enabled standalone conflicts with NM wpa_supplicant backend — disable: systemctl disable --now iwd  or switch NM to wifi.backend=iwd"
            fi
        fi
        # Silent when not installed/enabled and NM+wpa_supplicant is handling Wi-Fi
    fi
    if command -v mmcli &>/dev/null; then
        if systemctl is-active --quiet ModemManager 2>/dev/null; then
            # Show modem info if any modems are present
            local _mm_modems=""
            _mm_modems=$(timeout 5 mmcli -L 2>/dev/null \
                | grep -oE '/org/freedesktop/ModemManager[^ ]+' | wc -l || echo "0")
            if [[ "$_mm_modems" =~ ^[0-9]+$ ]] && (( _mm_modems > 0 )); then
                local _mm_info=""
                _mm_info=$(timeout 5 mmcli -L 2>/dev/null \
                    | grep -oE '\(.*\)' | head -1 | tr -d '()' || echo "")
                _row "ModemMgr"   "OK  running  (${_mm_modems} modem(s)${_mm_info:+: ${_mm_info}})"
            fi
            # Silent when running but no modem plugged in — NM activates on demand
        elif systemctl is-enabled --quiet ModemManager 2>/dev/null; then
            _row "ModemMgr"   "!   enabled but not running — mobile broadband unavailable"
        fi
        # Silent when not enabled — NM activates it on demand when a modem is present
    fi
    local _nm_conn _nm_type _nm_ip4
    _nm_conn=$(nmcli -t -f NAME,TYPE,STATE con show --active 2>/dev/null \
        | grep ':activated$' | head -1 || echo "")
    if [[ -n "$_nm_conn" ]]; then
        local _cn _ct
        _cn=$(echo "$_nm_conn" | cut -d: -f1)
        _ct=$(echo "$_nm_conn" | cut -d: -f2)
        case "$_ct" in
            802-3-ethernet) _ct="ethernet" ;;
            802-11-wireless) _ct="wifi" ;;
            vpn) _ct="vpn" ;;
        esac
        _nm_ip4=$(nmcli -t -f IP4.ADDRESS con show "$_cn" 2>/dev/null \
            | awk -F: '{print $2}' | head -1 | cut -d/ -f1 || echo "")
        _row "Connection" "--  ${_cn}  (${_ct})${_nm_ip4:+  ${_nm_ip4}}"
    fi
    local default_route; default_route=$(ip route show default 2>/dev/null | head -1 || echo "")
    if [[ -z "$default_route" ]]; then
        _row "Route"      "!   no default route — network may be unconfigured"
        _rec "No default route — check: nmcli c show && ip route"
    else
        local _gw; _gw=$(echo "$default_route" | awk '/via/{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' || echo "")
        local _dev; _dev=$(echo "$default_route" | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' || echo "")
        _row "Route"      "OK  default via ${_gw:-?}${_dev:+ (${_dev})}"
    fi
    # DNS probe alone doesn't confirm internet — test a real TCP connection
    local _inet_ok=0
    if command -v nc &>/dev/null; then
        nc -z -w 3 1.1.1.1 53 &>/dev/null 2>&1 && _inet_ok=1
    fi
    if (( ! _inet_ok )); then
        ping -c1 -W2 -q 8.8.8.8 &>/dev/null 2>&1 && _inet_ok=1
    fi
    if (( _inet_ok )); then
        _row "Internet"   "OK  reachable"
        # IPv6 — informational, show if active
        local _ipv6_ok=0
        if command -v nc &>/dev/null; then
            nc -6 -z -w 3 2606:4700:4700::1111 53 &>/dev/null 2>&1 && _ipv6_ok=1
        else
            ping6 -c1 -W2 -q 2606:4700:4700::1111 &>/dev/null 2>&1 && _ipv6_ok=1
        fi
        local _ipv6_addr=""
        _ipv6_addr=$(ip -6 addr show scope global 2>/dev/null \
            | awk '/inet6/{print $2}' | grep -v '^fd' | head -1 | cut -d/ -f1 || echo "")
        if (( _ipv6_ok )); then
            _row2 "--  IPv6 reachable${_ipv6_addr:+  (${_ipv6_addr})}"
        elif [[ -n "$_ipv6_addr" ]]; then _row2 "--  IPv6 address present but unreachable (${_ipv6_addr})"
        fi
        # Silent when IPv6 not configured — IPv4-only is normal
    else
        _row "Internet"   "!!  no internet connectivity"
        _rec "No internet — check: ip route && nmcli d status"
    fi
    # openresolv (resolvconf) — Shanios uses this, NOT systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        _row "DNS"        "!!  systemd-resolved active — not supported on ShaniOS"
        _rec "systemd-resolved conflicts with ShaniOS openresolv — disable: systemctl disable --now systemd-resolved"
    fi
    # Determine who is expected to own resolv.conf based on NM dns= setting
    local _nm_dns_resolv; _nm_dns_resolv=$(_nm_dns)

    if command -v resolvconf &>/dev/null; then
        local _resolv_managed=0
        [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf 2>/dev/null | grep -q 'resolvconf' && _resolv_managed=1
        if [[ "$_resolv_managed" -eq 0 && -f /etc/resolv.conf ]]; then
            grep -q 'Generated by resolvconf\|openresolv' /etc/resolv.conf 2>/dev/null && _resolv_managed=1
        fi
        case "$_nm_dns_resolv" in
            resolvconf|openresolv)
                # openresolv should be actively managing resolv.conf
                if (( _resolv_managed )); then _row "openresolv" "OK  resolvconf managing /etc/resolv.conf"
                else
                    _row "openresolv" "!   installed but not managing /etc/resolv.conf — NM dns=resolvconf expects it to"
                    _rec "openresolv installed but /etc/resolv.conf not generated by resolvconf — check NM dispatcher script"
                fi
                ;;
            default|none|*)
                # NM writes resolv.conf directly — openresolv is present but not in the path
                if (( _resolv_managed )); then
                    _row "openresolv" "!   managing /etc/resolv.conf but NM dns=${_nm_dns_resolv} — NM may overwrite it"
                    _rec "openresolv is managing /etc/resolv.conf but NM dns=${_nm_dns_resolv} writes it directly — set NM dns=resolvconf or dns=none"
                fi
                # Silent when installed but idle — NM owns resolv.conf, nothing to say
                ;;
        esac
    else
        case "$_nm_dns_resolv" in
            resolvconf|openresolv)
                _row "openresolv" "!!  resolvconf not found — NM dns=resolvconf requires it"
                _rec "NetworkManager dns=resolvconf but resolvconf binary missing — openresolv should be in base image"
                ;;
            *)
                # NM manages resolv.conf directly — openresolv not needed
                ;;
        esac
    fi
    if [[ ! -f /etc/resolv.conf ]]; then
        _row "resolv.conf" "!!  missing — DNS resolution broken"
        _rec "/etc/resolv.conf missing — check NM dns=${_nm_dns_resolv} configuration"
    elif [[ ! -s /etc/resolv.conf ]]; then
        _row "resolv.conf" "!!  empty — DNS resolution broken"
        _rec "/etc/resolv.conf is empty — check NM dns=${_nm_dns_resolv} configuration"
    elif ! grep -q '^nameserver ' /etc/resolv.conf 2>/dev/null; then
        _row "resolv.conf" "!!  no nameserver entries — DNS resolution broken"
        _rec "/etc/resolv.conf has no nameserver lines — check NM dns=${_nm_dns_resolv} configuration"
    else
        # Identify who wrote it — only surface non-default ownership
        local _resolv_owner=""
        if [[ -L /etc/resolv.conf ]]; then
            _resolv_owner=$(readlink /etc/resolv.conf 2>/dev/null || echo "")
            _row "resolv.conf" "--  symlink → ${_resolv_owner}"
        elif grep -q 'Generated by resolvconf\|openresolv' /etc/resolv.conf 2>/dev/null; then
            _row "resolv.conf" "--  managed by openresolv"
        fi
        # Silent when managed by NM or unknown — DNS server row below shows what matters
    fi
    local _ns_list
    _ns_list=$(grep '^nameserver ' /etc/resolv.conf 2>/dev/null \
        | awk '{print $2}' \
        | grep -v '^[[:space:]]*$' \
        | grep -v ':' \
        | paste -sd ',' || echo "")
    [[ -z "$_ns_list" ]] && \
        _ns_list=$(grep '^nameserver ' /etc/resolv.conf 2>/dev/null \
            | awk '{print $2}' | paste -sd ',' || echo "")
    [[ -n "$_ns_list" ]] && _row "DNS server"  "--  ${_ns_list}"
    local _dns_probe="one.one.one.one"
    local _dns_resolved=""
    if command -v dig &>/dev/null; then
        _dns_resolved=$(dig +short +timeout=3 "$_dns_probe" A 2>/dev/null \
            | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -1 || echo "")
    elif command -v getent &>/dev/null; then
        _dns_resolved=$(getent hosts "$_dns_probe" 2>/dev/null | awk '{print $1}' | head -1 || echo "")
    fi
    if [[ -z "$_dns_resolved" ]]; then
        _row "DNS probe"  "!!  failed to resolve ${_dns_probe} — DNS broken or no internet"
        _rec "DNS probe failed — check nameservers in /etc/resolv.conf and network connectivity"
    fi
    # Silent when DNS resolves — Internet row already confirms connectivity
    # OpenVPN — check for active tun/tap interfaces or running openvpn processes
    local _ovpn_iface _ovpn_active=0
    _ovpn_iface=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
        | grep -E '^tun[0-9]+$' | head -1 || echo "")
    pgrep -x openvpn &>/dev/null && _ovpn_active=1
    if [[ -n "$_ovpn_iface" ]] || (( _ovpn_active )); then
        local _ovpn_ip
        _ovpn_ip=$(ip -o -4 addr show "$_ovpn_iface" 2>/dev/null \
            | awk '{print $4}' | cut -d/ -f1 | head -1 || echo "")
        _row "OpenVPN"   "OK  tunnel active${_ovpn_iface:+  (${_ovpn_iface})}${_ovpn_ip:+  ${_ovpn_ip}}"
    fi

    # WireGuard — check for wg interfaces
    local _wg_ifaces=""
    if command -v wg &>/dev/null; then _wg_ifaces=$(wg show interfaces 2>/dev/null || echo "")
    else
        _wg_ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' \
            | grep -E '^wg[0-9]+$' | paste -sd ' ' || echo "")
    fi
    [[ -n "$_wg_ifaces" ]] && _row "WireGuard"  "OK  tunnel(s) active  (${_wg_ifaces})"
    if command -v swanctl &>/dev/null || command -v ipsec &>/dev/null || \
       systemctl cat strongswan         &>/dev/null 2>&1 || \
       systemctl cat strongswan-starter &>/dev/null 2>&1; then
        # strongswan.service (swanctl/modern) preferred over strongswan-starter (ipsec/legacy)
        local _swan_unit=""
        systemctl cat strongswan         &>/dev/null 2>&1 && _swan_unit="strongswan"
        systemctl cat strongswan-starter &>/dev/null 2>&1 && [[ -z "$_swan_unit" ]] \
            && _swan_unit="strongswan-starter"
        local _swan_active=0
        [[ -n "$_swan_unit" ]] && systemctl is-active --quiet "$_swan_unit" 2>/dev/null \
            && _swan_active=1
        local _swan_cfg=0
        _check_swan_cfg() {
            local _sf="$1"
            [[ -f "$_sf" ]] || return 1
            awk '
                /^[[:space:]]*#/ { next }
                /connections[[:space:]]*\{/ { in_conn=1 }
                in_conn && /^[[:space:]]*[a-zA-Z0-9_-]+[[:space:]]*\{/ { found=1 }
                END { exit !found }
            ' "$_sf" 2>/dev/null
        }
        if _check_swan_cfg /etc/swanctl/swanctl.conf; then
            _swan_cfg=1
        elif ls /etc/swanctl/conf.d/*.conf &>/dev/null 2>&1; then
            for _swf in /etc/swanctl/conf.d/*.conf; do
                _check_swan_cfg "$_swf" && { _swan_cfg=1; break; }
            done
        fi
        if (( _swan_active )); then
            local _swan_conns=""
            _swan_conns=$(swanctl --list-conns 2>/dev/null | grep -c ':' || echo "")
            _row "strongSwan" "OK  running${_swan_conns:+  (${_swan_conns} connection(s))}"
        elif [[ -n "$_swan_unit" ]] && systemctl is-enabled --quiet "$_swan_unit" 2>/dev/null; then
            _nm_vpn_conflict "strongSwan" "${_swan_unit}" "strongswan"
        fi
    fi
    # L2TP/IPsec VPN backend — pairs with strongSwan for NM L2TP connections.
    # Only surface when configured or enabled; NM manages the lifecycle normally.
    if _svc_present xl2tpd; then
        if systemctl is-active --quiet xl2tpd 2>/dev/null; then
            _row "xl2tpd"      "OK  running"
        elif systemctl is-enabled --quiet xl2tpd 2>/dev/null; then _nm_vpn_conflict "xl2tpd" "xl2tpd" "l2tp"
        fi
    fi
    if command -v avahi-daemon &>/dev/null; then
        if systemctl is-active --quiet avahi-daemon 2>/dev/null; then
            _row "Avahi"      "OK  mDNS/DNS-SD active"
        elif systemctl is-active  --quiet avahi-daemon.socket 2>/dev/null || \
             systemctl is-enabled --quiet avahi-daemon.socket 2>/dev/null; then
            _row "Avahi"      ">>  enabled (idle — socket-activated)"
        elif systemctl is-enabled --quiet avahi-daemon 2>/dev/null; then
            _row "Avahi"      "!   enabled but not running"
        else
            _row "Avahi"      "~~  not enabled — to enable mDNS/.local resolution: systemctl enable --now avahi-daemon"
        fi
    fi
    # Silent when Avahi not installed — mDNS is optional

    # Pre-check: pppd standalone conflict must always show
    if _svc_present pppd; then
        local _ppp_en_pre=""
        _ppp_en_pre=$(systemctl list-unit-files 'ppp@*.service' \
            --state=enabled --no-legend --no-pager 2>/dev/null \
            | awk '{print $1}' | paste -sd ',' || echo "")
        [[ -n "$_ppp_en_pre" ]] && _nm_vpn_conflict "pppd" "${_ppp_en_pre%%,*}" "ppp"
    fi
    _optional_begin
    if _svc_present tailscaled; then
        if systemctl is-active --quiet tailscaled 2>/dev/null; then
            local ts_out; ts_out=$(timeout 5 tailscale status 2>/dev/null || echo "")
            local ts_ip;  ts_ip=$(timeout 5 tailscale ip -4 2>/dev/null || echo "")
            if echo "$ts_out" | grep -qiE 'logged out|not logged in|stopped'; then
                _row "Tailscale"  "!   daemon running but not authenticated — run: tailscale up"
            elif [[ -n "$ts_ip" ]]; then _row "Tailscale"  "OK  connected  (${ts_ip})"
            else
                _row "Tailscale"  "--  daemon active (status unclear)"
            fi
        elif systemctl is-enabled --quiet tailscaled 2>/dev/null; then _row "Tailscale"  "!   enabled but not running"
        else
            _row "Tailscale"  "~~  not enabled — to join a tailnet: systemctl enable --now tailscaled && tailscale up"
        fi
    fi
    if _svc_present cloudflared; then
        local _cf_cfg=0
        # CLI: cloudflared tunnel list queries local credential store
        if command -v cloudflared &>/dev/null; then
            local _cf_tunnels
            _cf_tunnels=$(cloudflared tunnel list --output json 2>/dev/null \
                | grep -c '"id"' 2>/dev/null || true)
            [[ "$_cf_tunnels" =~ ^[0-9]+$ ]] || _cf_tunnels=0
            (( _cf_tunnels > 0 )) && _cf_cfg=1
        fi
        # Fallback: credential file check
        if (( ! _cf_cfg )); then
            { ls /etc/cloudflared/*.json &>/dev/null 2>&1 || \
              ls /root/.cloudflared/*.json &>/dev/null 2>&1 || \
              ls /home/*/.cloudflared/*.json &>/dev/null 2>&1; } && _cf_cfg=1
        fi
        if systemctl is-active --quiet cloudflared 2>/dev/null; then
            local cf_tunnel=""
            cf_tunnel=$(cloudflared tunnel list 2>/dev/null \
                | awk 'NR==2{print $2}' || echo "")
            if [[ -n "$cf_tunnel" ]]; then _row "cloudflared" "OK  running, tunnel: ${cf_tunnel}"
            else
                _row "cloudflared" "OK  running (no tunnel configured)"
            fi
        elif systemctl is-enabled --quiet cloudflared 2>/dev/null; then
            if (( ! _cf_cfg )); then
                _row "cloudflared" "!   enabled but not configured — run: cloudflared tunnel create <n>"
                _rec "cloudflared enabled but no tunnel credentials found — run: cloudflared tunnel create <n>"
            else
                _row "cloudflared" "!   enabled but not running"
                fi
        elif (( _cf_cfg )); then
            _row "cloudflared" "~~  configured, not enabled — to enable: systemctl enable --now cloudflared"
        else
            _row "cloudflared" "~~  not enabled — to create a tunnel: cloudflared tunnel create <n>"
        fi
    fi
    # Point-to-Point Protocol daemon for DSL/dial-up/mobile broadband links
    # not managed by ModemManager. Surface when a ppp@ instance is enabled.
    if _svc_present pppd; then
        local _ppp_active=""
        _ppp_active=$(systemctl list-units 'ppp@*.service' \
            --state=active --no-legend --no-pager 2>/dev/null \
            | awk '{print $1}' | paste -sd ',' || echo "")
        local _ppp_enabled=""
        _ppp_enabled=$(systemctl list-unit-files 'ppp@*.service' \
            --state=enabled --no-legend --no-pager 2>/dev/null \
            | awk '{print $1}' | paste -sd ',' || echo "")
        if [[ -n "$_ppp_active" ]]; then
            _row "pppd"          "OK  running  (${_ppp_active})"
        elif [[ -n "$_ppp_enabled" ]]; then
            _row "pppd"          "!!  enabled standalone — conflicts with NM; disable: systemctl disable --now ${_ppp_enabled%%,*}"
            fi
    fi
    _optional_end
}

_section_audio_display() {
    _head "Audio & Display"
    local rtkit_st; rtkit_st=$(systemctl is-active rtkit-daemon 2>/dev/null || echo "inactive")
    if [[ "$rtkit_st" == "active" ]]; then
        _row "rtkit"     "OK  running"
    elif command -v pipewire &>/dev/null || command -v pulseaudio &>/dev/null; then
        _row "rtkit"     "!!  not running (PipeWire RT unavailable)"
    fi
    if command -v pipewire &>/dev/null; then
        local pw_st wp_st
        pw_st=$(_sysd_user is-active pipewire    2>/dev/null | tr -d '[:space:]' || echo "inactive")
        wp_st=$(_sysd_user is-active wireplumber 2>/dev/null | tr -d '[:space:]' || echo "inactive")
        if [[ "$pw_st" == "active" && "$wp_st" == "active" ]]; then
            _row "PipeWire"  "OK  pipewire + wireplumber active"
        elif [[ "$pw_st" == "active" && "$wp_st" != "active" ]]; then
            _row "PipeWire"  "!   pipewire active but wireplumber is ${wp_st}"
        else
            # Both inactive — only flag if user has an active graphical (x11/wayland) session
            # Under sudo without a session, user services legitimately appear inactive
            local _has_session=0
            loginctl list-sessions --no-legend 2>/dev/null \
                | awk '{print $3}' | grep -qx "$_CALLER_USER" && _has_session=1
            (( _has_session )) && _row "PipeWire"  "!   not running for ${_CALLER_USER} — audio will be silent"
            # Silent if no active session — running health at boot/tty before login is normal
        fi
    fi
    local _cpu_vau=$(grep -m1 "vendor_id" /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo "")
    if [[ "$_cpu_vau" == "GenuineIntel" ]]; then
        if [[ -d /lib/firmware/intel/sof ]] || [[ -d /usr/lib/firmware/intel/sof ]] || \
           [[ -d /usr/lib/firmware/intel/sof-ipc4 ]] || ls /usr/lib/firmware/intel/sof*.ri &>/dev/null 2>&1; then
            _row "sof-fw"     "OK  sof-firmware present"
        else
            # Only warn if an HDA DSP device is present
            if find /sys/class/sound/ -name "hwC*D*" 2>/dev/null | head -1 | \
               xargs -r sh -c 'cat "$1/chip_name" 2>/dev/null' _ | grep -qi "sof\|hda-dsp"; then
                _row "sof-fw"     "!   SOF audio device present but sof-firmware not installed"
                _rec "sof-firmware missing — add to ShaniOS base image for Intel audio support"
            fi
        fi
    fi
    # WAYLAND_DISPLAY and DISPLAY are stripped by sudo/pkexec — use loginctl
    # to read the session type from the session manager instead.
    local _sess_type=""
    if command -v loginctl &>/dev/null && [[ -n "$_CALLER_USER" ]]; then
        local _sess_id
        _sess_id=$(loginctl list-sessions --no-legend 2>/dev/null \
            | awk -v u="$_CALLER_USER" '$3==u{print $1; exit}' || echo "")
        if [[ -n "$_sess_id" ]]; then
            _sess_type=$(loginctl show-session "$_sess_id" \
                -p Type --value 2>/dev/null | tr -d '[:space:]' || echo "")
        fi
    fi
    # Fallback to env vars if loginctl gave nothing (e.g. no active graphical session)
    if [[ -z "$_sess_type" ]]; then
        [[ -n "${WAYLAND_DISPLAY:-}" ]] && _sess_type="wayland"
        [[ -z "$_sess_type" && -n "${DISPLAY:-}" ]] && _sess_type="x11"
    fi
    # Only surface session type when it's a graphical session — "unspecified" or "tty"
    # just means the health check ran from a terminal/sudo and adds no useful info.
    if [[ "$_sess_type" == "wayland" || "$_sess_type" == "x11" || "$_sess_type" == "mir" ]]; then
        _row "Session" "--  ${_sess_type}"
    fi
    local profile_dm; profile_dm=$(cat /etc/shani-profile 2>/dev/null | tr -d '[:space:]' || echo "")
    local dm_svc=""
    [[ "$profile_dm" == "plasma" ]] && dm_svc="plasmalogin"
    [[ "$profile_dm" == "gnome"  ]] && dm_svc="gdm"
    if [[ -n "$dm_svc" ]]; then
        if systemctl is-active --quiet "${dm_svc}" 2>/dev/null; then
            _row "Display mgr" "OK  ${dm_svc} active"
        elif systemctl is-enabled --quiet "${dm_svc}" 2>/dev/null; then
            _row "Display mgr" "!   ${dm_svc} enabled but not running"
            else
            _row "Display mgr" "!!  ${dm_svc} not enabled"
            _rec "${dm_svc} not enabled — run: systemctl enable --now ${dm_svc}"
        fi
    fi
    if _svc_present plymouth; then
        local _ply_theme=""
        _ply_theme=$(plymouth-set-default-theme 2>/dev/null | tr -d '[:space:]' || echo "")
        if [[ -z "$_ply_theme" || "$_ply_theme" == "text" ]]; then
            _row "Plymouth"    "~~  no graphical theme set — plymouth-set-default-theme <theme>"
        else
            if [[ -d "/usr/share/plymouth/themes/${_ply_theme}" ]]; then _row "Plymouth"    "OK  theme: ${_ply_theme}"
            else
                _row "Plymouth"    "!   theme '${_ply_theme}' set but not found in /usr/share/plymouth/themes/"
                _rec "Plymouth theme missing — reinstall theme or choose another: plymouth-set-default-theme <theme>"
            fi
        fi
    fi
    if command -v xdg-desktop-portal &>/dev/null || \
       systemctl --user cat xdg-desktop-portal.service &>/dev/null 2>&1 || \
       _sysd_user cat xdg-desktop-portal.service &>/dev/null 2>&1; then
        local _xdp_st; _xdp_st=$(_sysd_user is-active xdg-desktop-portal 2>/dev/null | tr -d '[:space:]' || echo "inactive")
        local _xdp_backend=""
        if _sysd_user is-active plasma-xdg-desktop-portal-kde &>/dev/null 2>&1; then
            _xdp_backend="kde"
        elif _sysd_user is-active xdg-desktop-portal-gnome &>/dev/null 2>&1; then
            _xdp_backend="gnome"
        elif _sysd_user is-active xdg-desktop-portal-gtk &>/dev/null 2>&1; then _xdp_backend="gtk"
        fi
        if [[ "$_xdp_st" == "active" ]]; then
            _row "XDG portal"  "OK  active${_xdp_backend:+  (${_xdp_backend} backend)}"
            local _xdp_profile; _xdp_profile=$(cat /etc/shani-profile 2>/dev/null | tr -d '[:space:]' || echo "")
            if [[ "$_xdp_profile" == "plasma" && "$_xdp_backend" != "kde" ]]; then
                _row2 "!   expected kde backend for Plasma — xdg-desktop-portal-kde may not be running"
                _rec "XDG portal using ${_xdp_backend:-unknown} backend on Plasma — xdg-desktop-portal-kde should be active"
            elif [[ "$_xdp_profile" == "gnome" && "$_xdp_backend" != "gnome" ]]; then
                _row2 "!   expected gnome backend for GNOME — xdg-desktop-portal-gnome may not be running"
                _rec "XDG portal using ${_xdp_backend:-unknown} backend on GNOME — xdg-desktop-portal-gnome should be active"
            fi
        elif [[ "$_xdp_st" == "activating" ]]; then _row "XDG portal"  "--  activating"
        else
            _row "XDG portal"  "!   not running — Flatpak portals and screen sharing unavailable"
        fi
    fi
    if _svc_present colord; then
        if systemctl is-active --quiet colord 2>/dev/null; then
            local _icc_count=""
            _icc_count=$(colormgr get-profiles 2>/dev/null | grep -c 'Profile ID' || echo "")
            _row "colord"       "OK  running${_icc_count:+  (${_icc_count} profile(s))}"
        elif systemctl is-enabled --quiet colord 2>/dev/null; then
            _row "colord"       ">>  enabled (idle — starts on demand via D-Bus)"
        else
            _row "colord"       "~~  not enabled — colour profiles inactive: systemctl enable --now colord"
        fi
    fi

    _optional_begin
    if _svc_present ddcutil-service; then
        if systemctl is-active --quiet ddcutil-service 2>/dev/null; then
            local _ddc_monitors=""
            _ddc_monitors=$(ddcutil detect --brief 2>/dev/null | grep -c '^Display' || echo "")
            _row "ddcutil"     "OK  ddcutil-service running${_ddc_monitors:+  (${_ddc_monitors} monitor(s))}"
        elif systemctl is-enabled --quiet ddcutil-service 2>/dev/null; then
            _row "ddcutil"     "!   enabled but not running"
        fi
        # Silent when not enabled
    fi

    _optional_end
}

_section_units() {
    _head "Units"
    local failed_units=()
    # Filter known transient oneshot units that legitimately enter failed state
    # (e.g. systemd-suspend.service fails after every suspend cycle by design)
    local _transient_ok="systemd-suspend.service|systemd-hibernate.service|systemd-hybrid-sleep.service|drkonqi-coredump-processor@.*\.service"
    mapfile -t failed_units < <(
        systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null \
            | awk '{print $2}' | grep -v '^$' | grep '\.' \
            | grep -vE "^(${_transient_ok})$" || true)

    if [[ ${#failed_units[@]} -eq 0 ]]; then _row "Units"     "OK  no failed systemd units"
    else
        local _fu_str; _fu_str=$(IFS=' '; echo "${failed_units[*]}")
        _row "Units"     "!!  ${#failed_units[@]} failed: ${_fu_str}"
        _rec "Failed units: ${_fu_str} — run: systemctl status ${_fu_str}"
    fi
    local _user_transient_ok="drkonqi-coredump-pickup.service|drkonqi-coredump-launcher.service"
    if [[ -n "$_CALLER_USER" && "$_CALLER_USER" != "root" ]]; then
        local failed_user_units=()
        mapfile -t failed_user_units < <(
            _sysd_user list-units --state=failed --no-legend --no-pager 2>/dev/null \
                | awk '{print $2}' | grep -v '^$' | grep '\.' \
                | grep -vE "^(${_user_transient_ok})$" || true)
        if [[ ${#failed_user_units[@]} -eq 0 ]]; then _row "User units" "OK  no failed user units (${_CALLER_USER})"
        else
            local _fuu_str; _fuu_str=$(IFS=' '; echo "${failed_user_units[*]}")
            _row "User units" "!!  ${#failed_user_units[@]} failed (${_CALLER_USER}): ${_fuu_str}"
            _rec "Failed user units (${_CALLER_USER}): ${_fuu_str} — run: systemctl --user status ${_fuu_str}"
        fi
    fi
    # Inhibitors that block shutdown/sleep can cause hangs at power-off or
    # prevent suspend from working. Show any non-idle block or delay locks.
    if command -v systemd-inhibit &>/dev/null; then
        local _inh_list; _inh_list=$(systemd-inhibit --list --no-legend 2>/dev/null || true)
        local _inh_block _inh_delay
        _inh_block=$(echo "$_inh_list" | grep -c 'block' || true)
        _inh_delay=$(echo "$_inh_list" | grep -c 'delay' || true)
        local _inh_total=$(( ${_inh_block:-0} + ${_inh_delay:-0} ))
        if (( _inh_total > 0 )); then
            _row "Inhibitors" "--  ${_inh_block:-0} block, ${_inh_delay:-0} delay — run: systemd-inhibit --list"
        fi
    fi

}

_section_package_managers() {
    _head "Package Managers"
    if command -v flatpak &>/dev/null; then
        local flatpak_sys; flatpak_sys=$(systemctl is-enabled flatpak-update-system.timer 2>/dev/null || echo "disabled")
        local flatpak_usr; flatpak_usr=$(_sysd_user is-enabled flatpak-update-user.timer 2>/dev/null || echo "disabled")
        local flatpak_apps flatpak_remotes flatpak_mb
        flatpak_apps=$(timeout 5 flatpak list --app --columns=application 2>/dev/null | wc -l || echo "?")
        flatpak_remotes=$(flatpak remotes 2>/dev/null | grep -c '.' || echo "0")
        flatpak_mb=$(du -sm /var/lib/flatpak 2>/dev/null | awk '{print $1}' || echo "")
        local fp_sz_str=""
        [[ "$flatpak_mb" =~ ^[0-9]+$ ]] && fp_sz_str=", $(_mb_to_human "$flatpak_mb")"
        if [[ "$flatpak_sys" == "enabled" || "$flatpak_sys" == "static" ]]; then
            _row "Flatpak"    "OK  auto-update active  (${flatpak_apps} apps, ${flatpak_remotes} remote(s)${fp_sz_str})"
        else
            _row "Flatpak"    "!   auto-update timer not enabled  (${flatpak_apps} apps${fp_sz_str})"
        fi
        # Per-user timer — only check if the user has an active session
        local _fp_has_session=0
        loginctl list-sessions --no-legend 2>/dev/null \
            | awk '{print $3}' | grep -qx "$_CALLER_USER" && _fp_has_session=1
        if (( _fp_has_session )) && [[ "$flatpak_usr" != "enabled" && "$flatpak_usr" != "static" ]]; then
            _row2 "!   flatpak-update-user.timer not enabled for ${_CALLER_USER}"
        fi
        # Flatpak runtime count as continuation (size detail in --storage-info)
        if [[ "$flatpak_mb" =~ ^[0-9]+$ ]]; then
            local fp_unused=""
            fp_unused=$(timeout 10 flatpak list --runtime --columns=application 2>/dev/null | wc -l || echo "")
            [[ "$fp_unused" =~ ^[0-9]+$ ]] && (( fp_unused > 0 )) && \
                _row2 "--  ${fp_unused} runtime(s) installed"
        fi
        # Pending flatpak updates
        local flatpak_updates=$(timeout 15 flatpak remote-ls --updates 2>/dev/null | wc -l || echo "")
        if [[ "$flatpak_updates" =~ ^[0-9]+$ ]] && (( flatpak_updates > 0 )); then
            _row "Flatpak upd" "--  ${flatpak_updates} update(s) pending"
        fi
    fi
    if findmnt -n /var/lib/snapd &>/dev/null; then
        local snapd_sock; snapd_sock=$(systemctl is-active snapd.socket 2>/dev/null || echo "inactive")
        local snapd_aa;   snapd_aa=$(systemctl is-active snapd.apparmor.service 2>/dev/null || echo "inactive")
        local snap_count=""
        if [[ "$snapd_sock" == "active" ]] && command -v snap &>/dev/null; then
            snap_count=$(timeout 5 snap list 2>/dev/null | tail -n +2 | wc -l || echo "")
        fi
        # Pre-compute store size so it can go on the main row
        local snap_store_mb=$(du -sm /var/lib/snapd/snaps 2>/dev/null | awk '{print $1}' || echo "")
        local snap_sz_str=""
        [[ "$snap_store_mb" =~ ^[0-9]+$ ]] && snap_sz_str=", $(_mb_to_human "$snap_store_mb")"
        if [[ "$snapd_sock" == "active" && "$snapd_aa" == "active" ]]; then
            _row "Snap"       "OK  snapd + AppArmor active${snap_count:+  (${snap_count} snaps${snap_sz_str})}"
        elif [[ "$snapd_sock" == "active" ]]; then
            _row "Snap"       "!   snapd active but AppArmor service is ${snapd_aa} — confinement not enforced"
        else
            _row "Snap"       "!!  @snapd mounted but snapd.socket is ${snapd_sock}"
        fi
        # Check for stale snap revisions — warn if present
        local snap_stale_count=""
        command -v snap &>/dev/null && \
            snap_stale_count=$(timeout 5 snap list --all 2>/dev/null \
                | awk '/disabled/{c++} END{print c+0}' || echo "")
        if [[ "$snap_stale_count" =~ ^[0-9]+$ ]] && (( snap_stale_count > 0 )); then
            _row2 "--  ${snap_stale_count} stale revision(s) — run: snap set system refresh.retain=2"
            _rec "Snap has ${snap_stale_count} stale revision(s) — free space: snap set system refresh.retain=2"
        fi
        # Pending snap updates
        if [[ "$snapd_sock" == "active" ]] && command -v snap &>/dev/null; then
            local snap_updates=$(timeout 10 snap refresh --list 2>/dev/null | tail -n +2 | wc -l || echo "")
            if [[ "$snap_updates" =~ ^[0-9]+$ ]]; then
                if (( snap_updates > 0 )); then
                    _row "Snap upd"   "--  ${snap_updates} update(s) pending — run: snap refresh"
                    _rec "${snap_updates} snap update(s) available — run: snap refresh"
                else
                    _row "Snap upd"   "OK  up to date"
                fi
            fi
        fi
    elif _svc_present snapd; then _row "Snap"       "~~  @snapd subvolume not mounted"
    fi
    # @nix subvolume is pre-created on ShaniOS — always check.
    if ! findmnt -n /nix &>/dev/null; then
        _row "Nix"   "!!  @nix subvolume not mounted — Nix package manager unavailable"
        _rec "Mount @nix: check fstab entry for /nix"
    else
        # Store size and generation count — computed before the main row so they can be inlined
        local nix_store_mb=$(du -sm /nix/store 2>/dev/null | awk '{print $1}' || echo "")
        local nix_gen_count=""
        local _nix_prof="/nix/var/nix/profiles"
        if [[ -d "$_nix_prof" ]]; then
            nix_gen_count=$(ls "$_nix_prof" 2>/dev/null | grep -cE '^system-[0-9]+-link$' || echo "")
        fi
        local nix_sz_str=""
        [[ "$nix_store_mb" =~ ^[0-9]+$ ]] && nix_sz_str=", $(_mb_to_human "$nix_store_mb")"
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
        fi
        if [[ -n "$_nix_user" ]] && command -v nix-channel &>/dev/null; then
            local _nix_channel_dir
            _nix_channel_dir=$(runuser -u "$_nix_user" -- \
                sh -c 'echo "${HOME}/.nix-defexpr/channels"' 2>/dev/null || echo "")
            if [[ -d "$_nix_channel_dir" ]]; then
                local _nix_age_days
                _nix_age_days=$(( ( $(date +%s) - $(stat -c %Y "$_nix_channel_dir" 2>/dev/null || echo 0) ) / 86400 ))
                if (( _nix_age_days > 30 )); then
                    _row "Nix upd"    "!   channels ${_nix_age_days}d old — run: nix-channel --update"
                    _rec "Nix channels are ${_nix_age_days} days old — update: nix-channel --update"
                elif (( _nix_age_days > 7 )); then
                    _row "Nix upd"    "--  channels ${_nix_age_days}d old — run: nix-channel --update"
                else
                    _row "Nix upd"    "OK  channels updated ${_nix_age_days}d ago"
                fi
            fi
        fi
        # Nix store: warn only when critically large (detail in --storage-info)
        if [[ "$nix_store_mb" =~ ^[0-9]+$ ]] && (( nix_store_mb > 51200 )); then
            _row2 "!   $(_mb_to_human "$nix_store_mb") — run: nix-collect-garbage -d"
            _rec "Nix store is $(_mb_to_human "$nix_store_mb") — free space: nix-collect-garbage -d"
        fi
    fi
    # AppImages require FUSE to mount and run. Without it every .AppImage fails.
    if find /home /root 2>/dev/null -maxdepth 4 -name '*.AppImage' -quit 2>/dev/null | grep -q .; then
        local fuse_ok=0
        lsmod 2>/dev/null | grep -qw 'fuse' && fuse_ok=1
        command -v fusermount3 &>/dev/null && fuse_ok=1
        command -v fusermount  &>/dev/null && fuse_ok=1
        if (( fuse_ok )); then _row "AppImage"   "OK  FUSE available"
        else
            _row "AppImage"   "!!  .AppImage files found but FUSE not loaded — they will not run"
            fi
    fi
    if _svc_present man-db.timer; then
        local _mandb_active=0; systemctl is-active --quiet man-db.timer 2>/dev/null && _mandb_active=1
        local _mandb_en; _mandb_en=$(systemctl is-enabled man-db.timer 2>/dev/null || echo "disabled")
        if (( _mandb_active )) || [[ "$_mandb_en" == "enabled" || "$_mandb_en" == "static" ]]; then
            _row "man-db"      "OK  cache rebuild timer active"
        else
            _row "man-db"      "--  timer not enabled (apropos/whatis cache won't auto-update: systemctl enable --now man-db.timer)"
        fi
    fi
    if _svc_present plocate-updatedb.timer; then
        local _pl_active=0; systemctl is-active --quiet plocate-updatedb.timer 2>/dev/null && _pl_active=1
        local _pl_en; _pl_en=$(systemctl is-enabled plocate-updatedb.timer 2>/dev/null || echo "disabled")
        if (( _pl_active )) || [[ "$_pl_en" == "enabled" || "$_pl_en" == "static" ]]; then
            local _pl_last=""
            _pl_last=$(systemctl show plocate-updatedb.service \
                --property=ExecMainExitTimestamp --value 2>/dev/null \
                | grep -v '^n/a\|^$' | head -1 || echo "")
            _row "plocate"     "OK  index update timer active${_pl_last:+  (last: ${_pl_last})}"
        else
            _row "plocate"     "!   plocate-updatedb.timer not enabled — locate results will be stale"
        fi
    fi
    if _sysd_user is-active --quiet shani-update.timer 2>/dev/null; then
        _row "shani-upd"  "OK  update checker active"
    elif _sysd_user is-enabled --quiet shani-update.timer 2>/dev/null; then
        _row "shani-upd"  "--  enabled, not yet started (starts at login)"
    else
        _row "shani-upd"  "!   shani-update.timer not enabled — OS updates won't be auto-checked"
    fi

    # Pre-check: PackageKit failure must always show
    if systemctl cat packagekit &>/dev/null 2>&1 && \
       systemctl is-failed --quiet packagekit 2>/dev/null; then
        _row "PackageKit"  "!   packagekit.service failed — KDE Discover / GNOME Software may not work"
    fi
    _optional_begin
    if _svc_present reflector; then
        local _ref_en; _ref_en=$(systemctl is-enabled reflector.timer 2>/dev/null || echo "disabled")
        if [[ "$_ref_en" == "enabled" || "$_ref_en" == "static" ]]; then
            _row "reflector"   "OK  mirror update timer active"
        else
            _row "reflector"   "~~  not enabled — to auto-update mirrors: systemctl enable --now reflector.timer"
        fi
    fi
    if _svc_present packagekit; then
        if systemctl is-failed --quiet packagekit.service 2>/dev/null; then
            _row "PackageKit"  "!   packagekit.service failed — KDE Discover / GNOME Software may not work"
            _rec "PackageKit failed — run: systemctl reset-failed packagekit"
        elif systemctl is-active --quiet packagekit.service 2>/dev/null; then _row "PackageKit"  "OK  running"
        fi
        # Silent when idle — D-Bus-activated, not running between GUI operations is normal
    fi
    _optional_end
}

_section_containers() {
    _head "Containers"
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
        # Running containers — fetch before main row so count can be inlined
        local podman_running=""
        podman_running=$(podman ps -q 2>/dev/null | wc -l | tr -d '[:space:]' || echo "")
        if [[ "$podman_sys_st" == "active" ]]; then
            _row "Podman"     "OK  socket active (system)${podman_ver:+  v${podman_ver}}${podman_running:+, ${podman_running} running}${rl_str}"
        elif [[ "$podman_usr_st" == "active" ]]; then
            _row "Podman"     "OK  socket active (user)${podman_ver:+  v${podman_ver}}${podman_running:+, ${podman_running} running}${rl_str}"
        else
            _row "Podman"     "--  installed${podman_ver:+  v${podman_ver}}  socket inactive${rl_str}"
        fi
        # Distrobox: depends on Podman — flag if installed but Podman socket is down
        if command -v distrobox &>/dev/null && \
           [[ "$podman_sys_st" != "active" && "$podman_usr_st" != "active" ]]; then
            _row2 "!   Distrobox installed but Podman socket not active — containers won't start"
        fi
        # System image/volume storage — always show size
        local podman_img_mb podman_vol_mb
        podman_img_mb=$(du -sm /var/lib/containers/storage 2>/dev/null | awk '{print $1}' || echo "")
        podman_vol_mb=$(du -sm /var/lib/containers/volumes 2>/dev/null | awk '{print $1}' || echo "")
        local _pdm_sz_parts=()
        [[ "$podman_img_mb" =~ ^[0-9]+$ ]] && _pdm_sz_parts+=("images/layers: $(_mb_to_human "$podman_img_mb")")
        [[ "$podman_vol_mb" =~ ^[0-9]+$ ]] && (( podman_vol_mb > 0 )) && _pdm_sz_parts+=("volumes: $(_mb_to_human "$podman_vol_mb")")
        if [[ ${#_pdm_sz_parts[@]} -gt 0 ]]; then
            local _pdm_sz_str; _pdm_sz_str=$(IFS=', '; echo "${_pdm_sz_parts[*]}")
            if [[ "$podman_img_mb" =~ ^[0-9]+$ ]] && (( podman_img_mb > 20480 )); then
                _row2 "!   system storage: ${_pdm_sz_str} — run: podman image prune"
                _rec "Podman system image storage is ${podman_img_mb} MB — free space: podman image prune"
            else
                _row2 "--  system storage: ${_pdm_sz_str}"
            fi
        fi
        # User-level Podman storage (rootless)
        local _rl_user="$_CALLER_USER"
        if [[ -n "$_rl_user" ]]; then
            local _user_home; _user_home=$(getent passwd "$_rl_user" 2>/dev/null | cut -d: -f6 || echo "")
            if [[ -n "$_user_home" ]]; then
                local _user_img_mb _user_vol_mb
                _user_img_mb=$(du -sm "${_user_home}/.local/share/containers/storage" 2>/dev/null | awk '{print $1}' || echo "")
                _user_vol_mb=$(du -sm "${_user_home}/.local/share/containers/volumes" 2>/dev/null | awk '{print $1}' || echo "")
                local _usr_sz_parts=()
                [[ "$_user_img_mb" =~ ^[0-9]+$ ]] && (( _user_img_mb > 0 )) && _usr_sz_parts+=("images/layers: $(_mb_to_human "$_user_img_mb")")
                [[ "$_user_vol_mb" =~ ^[0-9]+$ ]] && (( _user_vol_mb > 0 )) && _usr_sz_parts+=("volumes: $(_mb_to_human "$_user_vol_mb")")
                if [[ ${#_usr_sz_parts[@]} -gt 0 ]]; then
                    local _usr_sz_str; _usr_sz_str=$(IFS=', '; echo "${_usr_sz_parts[*]}")
                    if [[ "$_user_img_mb" =~ ^[0-9]+$ ]] && (( _user_img_mb > 10240 )); then
                        _row2 "!   user storage (${_rl_user}): ${_usr_sz_str} — run: podman image prune"
                        _rec "Podman user image storage for ${_rl_user} is ${_user_img_mb} MB — free space: podman image prune"
                    else
                        _row2 "--  user storage (${_rl_user}): ${_usr_sz_str}"
                    fi
                fi
            fi
        fi
    fi
    if command -v podman &>/dev/null; then
        local _pdm_drv=""
        _pdm_drv=$(podman info --format '{{.Store.GraphDriverName}}' 2>/dev/null \
            | tr -d '[:space:]' || echo "")
        if [[ -n "$_pdm_drv" ]]; then
            case "$_pdm_drv" in
                vfs)           _row "Podman drv"  "!   storage=vfs — very slow and space-inefficient"
                               _rec "Switch Podman to overlay: set driver=overlay in ~/.config/containers/storage.conf" ;;
                overlay|btrfs|zfs) _row "Podman drv"  "OK  storage=${_pdm_drv}" ;;
                *)             _row "Podman drv"  "--  storage=${_pdm_drv}" ;;
            esac
        fi
    fi
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
        fi
        # lxcfs: provides container-aware /proc stats — silent when working
        if command -v lxcfs &>/dev/null && systemctl is-enabled --quiet lxcfs 2>/dev/null; then
            if ! systemctl is-active --quiet lxcfs 2>/dev/null; then
                _row2 "!   lxcfs enabled but not running — containers see host stats"
                fi
        fi
        # LXD storage — only show when non-zero
        local lxd_mb=$(du -sm /var/lib/lxd /data/varlib/lxd 2>/dev/null | awk '{s+=$1} END{print s}' || echo "")
        if [[ "$lxd_mb" =~ ^[0-9]+$ ]] && (( lxd_mb > 0 )); then
            if (( lxd_mb > 20480 )); then
                _row2 "!   $(_mb_to_human "$lxd_mb") — review with: lxc storage info default"
                _rec "LXD storage is $(_mb_to_human "$lxd_mb") — review: lxc storage info default"
            else
                _row2 "--  $(_mb_to_human "$lxd_mb")"
            fi
        fi
    fi
    # Skip if 'docker' is provided by podman-docker (a shim — real engine is Podman above).
    local _is_podman_docker=0
    if command -v docker &>/dev/null; then
        docker --version 2>/dev/null | grep -qi 'podman' && _is_podman_docker=1
        # Also detect via symlink (podman-docker installs docker as a symlink to podman)
        if (( ! _is_podman_docker )); then
            local _docker_bin; _docker_bin=$(command -v docker 2>/dev/null || echo "")
            [[ -L "$_docker_bin" ]] && readlink -f "$_docker_bin" 2>/dev/null | grep -qi 'podman' && _is_podman_docker=1
        fi
    fi
    if (( ! _is_podman_docker )) && { _svc_present docker; }; then
        local docker_st; docker_st=$(systemctl is-active docker 2>/dev/null || echo "inactive")
        local docker_ver; docker_ver=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        if [[ "$docker_st" == "active" ]]; then
            local docker_running=""
            docker_running=$(timeout 5 docker ps -q 2>/dev/null | wc -l | tr -d '[:space:]' || echo "")
            _row "Docker"     "OK  running${docker_ver:+  v${docker_ver}}${docker_running:+  (${docker_running} container(s))}"
        elif systemctl is-enabled --quiet docker 2>/dev/null; then _row "Docker"     "!   enabled but not running"
        else
            _row "Docker"     "~~  not enabled — to enable: systemctl enable --now docker"
        fi
        # Docker image/volume/build cache storage
        local docker_root; docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo "/var/lib/docker")
        local docker_img_mb docker_vol_mb docker_build_mb
        docker_img_mb=$(du -sm "${docker_root}/overlay2" 2>/dev/null | awk '{print $1}' || echo "")
        docker_vol_mb=$(du -sm "${docker_root}/volumes"  2>/dev/null | awk '{print $1}' || echo "")
        docker_build_mb=$(du -sm "${docker_root}/buildkit" 2>/dev/null | awk '{print $1}' || echo "")
        local _dk_sz_parts=()
        [[ "$docker_img_mb"   =~ ^[0-9]+$ ]] && (( docker_img_mb   > 0 )) && _dk_sz_parts+=("images/layers: $(_mb_to_human "$docker_img_mb")")
        [[ "$docker_vol_mb"   =~ ^[0-9]+$ ]] && (( docker_vol_mb   > 0 )) && _dk_sz_parts+=("volumes: $(_mb_to_human "$docker_vol_mb")")
        [[ "$docker_build_mb" =~ ^[0-9]+$ ]] && (( docker_build_mb > 0 )) && _dk_sz_parts+=("build cache: $(_mb_to_human "$docker_build_mb")")
        if [[ ${#_dk_sz_parts[@]} -gt 0 ]]; then
            local _dk_sz_str; _dk_sz_str=$(IFS=', '; echo "${_dk_sz_parts[*]}")
            if [[ "$docker_img_mb" =~ ^[0-9]+$ ]] && (( docker_img_mb > 20480 )); then
                _row2 "!   storage: ${_dk_sz_str} — run: docker system prune"
                _rec "Docker image storage is ${docker_img_mb} MB — free space: docker system prune"
            else
                _row2 "--  storage: ${_dk_sz_str}"
            fi
        fi
    fi
    if findmnt -n /var/lib/waydroid &>/dev/null; then
        local waydroid_st; waydroid_st=$(systemctl is-active waydroid-container 2>/dev/null || echo "inactive")
        local waydroid_mb=$(du -sm /var/lib/waydroid 2>/dev/null | awk '{print $1}' || echo "")
        local wd_sz_str=""
        [[ "$waydroid_mb" =~ ^[0-9]+$ ]] && wd_sz_str="  ($(_mb_to_human "$waydroid_mb"))"
        if [[ "$waydroid_st" == "active" ]]; then _row "Waydroid"   "OK  Android container active${wd_sz_str}"
        else
            _row "Waydroid"   "!   @waydroid mounted but container service is ${waydroid_st}${wd_sz_str}"
        fi
    elif command -v waydroid &>/dev/null; then _row "Waydroid"   "~~  not initialised"
    fi
    # Always show when machinectl is installed — provides visibility even on
    # systems with no machines configured yet.
    if command -v machinectl &>/dev/null; then
        local machines_dir="/var/lib/machines"
        local has_machines=0
        { [[ -d "$machines_dir" ]] && [[ $(ls "$machines_dir" 2>/dev/null | wc -l) -gt 0 ]]; } \
            && has_machines=1
        systemctl is-active --quiet systemd-machined 2>/dev/null && has_machines=1
        # Also surface if any nspawn@ unit is enabled/active
        systemctl list-units 'systemd-nspawn@*.service' --no-legend --no-pager 2>/dev/null \
            | grep -q . && has_machines=1
        if (( has_machines )); then
            local machined_st; machined_st=$(systemctl is-active systemd-machined 2>/dev/null || echo "inactive")
            if [[ "$machined_st" == "active" ]]; then
                # Gather per-machine info: name, state, IP, OS
                local _mc_raw=""
                _mc_raw=$(timeout 5 machinectl list --no-legend 2>/dev/null || echo "")
                local _mc_count=0
                [[ -n "$_mc_raw" ]] && _mc_count=$(echo "$_mc_raw" | grep -c . || echo 0)
                local _mc_running=0
                _mc_running=$(echo "$_mc_raw" | grep -c running 2>/dev/null || echo 0)
                # Total disk usage of machines dir
                local nspawn_mb=""
                nspawn_mb=$(du -sm "$machines_dir" 2>/dev/null | awk '{print $1}' || echo "")
                _row "nspawn" "OK  machined active  (${_mc_count} machine(s)${_mc_running:+, ${_mc_running} running}${nspawn_mb:+, ${nspawn_mb} MB})"
                # Per-machine rows
                if [[ -n "$_mc_raw" ]]; then
                    while IFS= read -r _mc_line; do
                        [[ -z "$_mc_line" ]] && continue
                        local _mc_name _mc_class _mc_service _mc_os _mc_addr
                        _mc_name=$(echo "$_mc_line" | awk '{print $1}')
                        _mc_class=$(echo "$_mc_line" | awk '{print $2}')
                        _mc_service=$(echo "$_mc_line" | awk '{print $3}')
                        # Get address and OS from machinectl status
                        _mc_addr=$(timeout 3 machinectl status "$_mc_name" 2>/dev/null \
                            | awk '/Address:/{print $2}' | head -1 || echo "")
                        _mc_os=$(timeout 3 machinectl status "$_mc_name" 2>/dev/null \
                            | awk '/OS:/{$1=""; print $0}' | head -1 | xargs || echo "")
                        local _mc_disk=""
                        _mc_disk=$(du -sm "${machines_dir}/${_mc_name}" 2>/dev/null \
                            | awk '{print $1}' || echo "")
                        local _mc_detail=""
                        [[ -n "$_mc_os"   ]] && _mc_detail+="${_mc_os}"
                        [[ -n "$_mc_addr" ]] && _mc_detail+="${_mc_detail:+  }${_mc_addr}"
                        [[ -n "$_mc_disk" ]] && _mc_detail+="${_mc_detail:+  }$(_mb_to_human "$_mc_disk")"
                        _row2 "--  ${_mc_name}  (${_mc_service:-${_mc_class}})${_mc_detail:+  ${_mc_detail}}"
                    done <<< "$_mc_raw"
                fi
                # Enabled-but-stopped machines (in /etc/systemd/nspawn/ or unit files)
                local _nspawn_enabled=""
                _nspawn_enabled=$(systemctl list-unit-files 'systemd-nspawn@*.service' \
                    --state=enabled --no-legend --no-pager 2>/dev/null \
                    | awk '{gsub(/systemd-nspawn@|\.service/,"",$1); print $1}' | paste -sd ',' || echo "")
                if [[ -n "$_nspawn_enabled" ]]; then
                    local _nspawn_inactive=""
                    _nspawn_inactive=$(systemctl list-units 'systemd-nspawn@*.service' \
                        --state=inactive --no-legend --no-pager 2>/dev/null \
                        | awk '{gsub(/systemd-nspawn@|\.service/,"",$1); print $1}' | paste -sd ',' || echo "")
                    [[ -n "$_nspawn_inactive" ]] && \
                        _row2 "--  enabled but not running: ${_nspawn_inactive} — run: machinectl start <name>"
                fi
            else
                _row "nspawn" "!   machines present but systemd-machined is ${machined_st}"
                    local nspawn_mb=""
                nspawn_mb=$(du -sm "$machines_dir" 2>/dev/null | awk '{print $1}' || echo "")
                [[ "$nspawn_mb" =~ ^[0-9]+$ ]] && (( nspawn_mb > 0 )) && \
                    _row2 "--  ${nspawn_mb} MB in ${machines_dir}"
            fi
        else
            # No machines configured yet — show a stub so the row is always visible
            _row "nspawn" "~~  no machines — to create one: machinectl pull-tar <url> <n>"
        fi
    fi

    _optional_begin
    # Rootless HPC container runtime. No daemon — just needs userns support.
    if command -v apptainer &>/dev/null || command -v singularity &>/dev/null; then
        local apt_bin="apptainer"; command -v apptainer &>/dev/null || apt_bin="singularity"
        local apt_ver; apt_ver=$("$apt_bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        local userns_val; userns_val=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "1")
        if [[ "$userns_val" == "0" ]]; then
            _row "Apptainer"  "!!  installed but unprivileged_userns_clone=0 — rootless containers disabled"
            _rec "Apptainer rootless containers disabled — run: sysctl -w kernel.unprivileged_userns_clone=1"
        else
            _row "Apptainer"  "OK  ${apt_bin}${apt_ver:+  v${apt_ver}}  (rootless-capable)"
        fi
        # Cache storage
        local _rl_user="$_CALLER_USER"
        if [[ -n "$_rl_user" ]]; then
            local _user_home; _user_home=$(getent passwd "$_rl_user" 2>/dev/null | cut -d: -f6 || echo "")
            if [[ -n "$_user_home" ]]; then
                local apt_cache_mb
                apt_cache_mb=$(du -sm "${_user_home}/.apptainer/cache" "${_user_home}/.singularity/cache" 2>/dev/null | awk '{s+=$1} END{print s}' || echo "")
                [[ "$apt_cache_mb" =~ ^[0-9]+$ ]] && (( apt_cache_mb > 0 )) && _row2 "--  cache: $(_mb_to_human "$apt_cache_mb") (${_rl_user})"
            fi
        fi
    fi
    # Fork of LXD; manages containers and VMs via the incus daemon.
    if _svc_present incus; then
        if systemctl is-active --quiet incus 2>/dev/null; then
            local _incus_inst=""
            _incus_inst=$(incus list --format csv 2>/dev/null | wc -l | tr -d '[:space:]' || echo "")
            _row "Incus"       "OK  running${_incus_inst:+  (${_incus_inst} instance(s))}"
        elif systemctl is-enabled --quiet incus 2>/dev/null; then _row "Incus"       "!   enabled but not running"
        else
            _row "Incus"       "~~  not enabled — to manage containers: systemctl enable --now incus"
        fi
        local incus_mb=$(du -sm /var/lib/incus 2>/dev/null | awk '{print $1}' || echo "")
        [[ "$incus_mb" =~ ^[0-9]+$ ]] && (( incus_mb > 0 )) && _row2 "--  $(_mb_to_human "$incus_mb")"
    fi
    _optional_end
}

# Check a VM guest agent: rows OK/not-running/not-enabled based on DMI detection.
# _check_vm_guest LABEL SVC DMI_RE OK_MSG DISABLED_MSG [REC_MSG]
_check_vm_guest() {
    local label="$1" svc="$2" dmi_re="$3" ok_msg="$4" dis_msg="$5" rec_msg="${6:-}"
    _svc_present "$svc" || return 0
    grep -qiE "$dmi_re" /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null || return 0
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        _row "$label" "OK  $ok_msg"
    elif systemctl is-enabled --quiet "$svc" 2>/dev/null; then _row "$label" "!   enabled but not running"
    else
        _row "$label" "!   $dis_msg"
        [[ -n "$rec_msg" ]] && _rec "$rec_msg"
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
    if [[ -e /dev/kvm ]]; then
        local kvm_perms; kvm_perms=$(stat -c '%a' /dev/kvm 2>/dev/null || echo "")
        _row "KVM"        "OK  /dev/kvm present${kvm_perms:+  (mode ${kvm_perms})}"
    else
        _row "KVM"        "!!  /dev/kvm missing — VMs will not start"
        _rec "KVM device missing — enable AMD-V/VT-x in BIOS and ensure kvm/kvm-amd/kvm-intel module is loaded"
    fi
    if [[ -e /dev/kvm ]]; then
        if lsmod 2>/dev/null | grep -q "^vhost_net"; then
            _row "vhost_net"   "OK  loaded (VM network acceleration active)"
        elif modinfo vhost_net &>/dev/null 2>&1; then _row "vhost_net"   "--  available, auto-loads when VM starts"
        fi
    fi
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
            # QEMU version inline
            local _qemu_ver=""
            for _qbin in qemu-system-x86_64 qemu-kvm; do
                command -v "$_qbin" &>/dev/null && \
                    _qemu_ver=$("$_qbin" --version 2>/dev/null \
                        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "") && break
            done
            # @qemu storage inline
            local _qemu_mb=""
            findmnt -n /var/lib/qemu &>/dev/null && \
                _qemu_mb=$(du -sm /var/lib/qemu 2>/dev/null | awk '{print $1}' || echo "")
            if command -v virsh &>/dev/null; then
                vm_count=$(timeout 5 virsh list --all 2>/dev/null \
                    | awk 'NR>2 && /^[[:space:]]*[0-9-]/' | wc -l || echo "")
                vm_running=$(timeout 5 virsh list 2>/dev/null \
                    | awk 'NR>2 && /running/' | wc -l || echo "0")
            fi
            _row "libvirtd"  "OK  active (${libvirt_mode})${_qemu_ver:+  QEMU v${_qemu_ver}}${vm_count:+  (${vm_count} VM(s) defined${vm_running:+, ${vm_running} running})${_qemu_mb:+, $(_mb_to_human "$_qemu_mb")}}"
            # Per-VM rows: name, state, vCPUs, memory
            if command -v virsh &>/dev/null && [[ "$vm_count" =~ ^[0-9]+$ ]] && (( vm_count > 0 )); then
                while IFS= read -r _vl; do
                    [[ -z "$_vl" ]] && continue
                    local _vid _vname _vstate
                    _vid=$(echo "$_vl" | awk '{print $1}')
                    _vname=$(echo "$_vl" | awk '{print $2}')
                    _vstate=$(echo "$_vl" | awk '{$1=$2=""; print $0}' | xargs)
                    # Get vCPU and memory from dominfo (quick, no XML needed)
                    local _vcpus="" _vmem=""
                    local _dominfo=""
                    _dominfo=$(timeout 3 virsh dominfo "$_vname" 2>/dev/null || echo "")
                    _vcpus=$(echo "$_dominfo" | awk '/^CPU\(s\):/{print $2}' | head -1)
                    _vmem=$(echo "$_dominfo" | awk '/^Used memory:/{printf "%.0f MB", $3/1024}' | head -1)
                    _row2 "--  ${_vname}  (${_vstate}${_vcpus:+, ${_vcpus} vCPU}${_vmem:+, ${_vmem}})"
                done < <(timeout 5 virsh list --all 2>/dev/null | awk 'NR>2 && /^[[:space:]]*[0-9-]/')
            fi
        elif systemctl is-enabled --quiet virtqemud.service 2>/dev/null || \
             systemctl is-enabled --quiet libvirtd.service  2>/dev/null; then
            _row "libvirtd"  "!   enabled but not running"
        else
            _row "libvirtd"  "~~  not enabled"
        fi

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
                        if [[ "$_crit" == "1" ]]; then _virt_critical_failed+=("$_svc")
                        else
                            _virt_failed+=("$_svc")
                        fi
                    fi
                fi
            done

            if [[ ${#_virt_critical_failed[@]} -gt 0 ]]; then
                _row "virt daemons" "!!  critical not running: $(_join "${_virt_critical_failed[@]}")"
                for _f in "${_virt_critical_failed[@]}"; do
                    _rec "${_f} not active — STOP all VMs first, then: systemctl enable --now ${_f}.socket"
                done
            fi
            if [[ ${#_virt_failed[@]} -gt 0 ]]; then
                _row2 "!   not running: $(_join "${_virt_failed[@]}")"
                for _f in "${_virt_failed[@]}"; do
                    _rec "${_f} not active — run: systemctl enable --now ${_f}.socket"
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
                        _rec "${_vhelper} not active — must not stop while VMs run: systemctl enable --now ${_vhelper}.socket"
                    fi
                fi
            done
        fi

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
                _rec "User(s) $(_join "${_kvm_missing[@]}") not in kvm group — run: shani-user-setup"
            else
                _row "kvm group"  "OK  users have kvm access"
            fi
        else
            _row "kvm group"  "!!  kvm group missing"
            _rec "kvm group missing — should be in base image; run: groupadd -r kvm"
        fi

        # libvirt group — needed for virsh/virt-manager without sudo
        if getent group libvirt &>/dev/null; then
            local _libvirt_missing=()
            for u in "${_virt_login[@]}"; do
                id -nG "$u" 2>/dev/null | grep -qw libvirt || _libvirt_missing+=("$u")
            done
            if [[ ${#_libvirt_missing[@]} -gt 0 ]]; then
                _row "libvirt grp" "!   $(_join "${_libvirt_missing[@]}") not in libvirt group"
                _rec "User(s) $(_join "${_libvirt_missing[@]}") not in libvirt group — run: shani-user-setup"
            else
                _row "libvirt grp" "OK  users have libvirt access"
            fi
        else
            _row "libvirt grp" "!!  libvirt group missing"
            _rec "libvirt group missing — run: groupadd -r libvirt"
        fi

        if command -v aa-status &>/dev/null && aa-status --enabled >/dev/null 2>&1; then
            local aa_libvirt=0
            aa-status 2>/dev/null | grep -q 'libvirt\|qemu' && aa_libvirt=1
            if (( aa_libvirt )); then _row "AA/libvirt"  "OK  AppArmor profiles loaded for libvirt/qemu"
            else
                _row "AA/libvirt"  "--  no AppArmor profiles for libvirt/qemu (may be unconfined)"
            fi
        fi

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
            ! pgrep -x dnsmasq &>/dev/null && _row "dnsmasq"    "--  not running (needed for VM NAT networking)"
        fi

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

        # If libvirt VMs are configured with hugepages, check they're available
        local hugepages_total hugepages_free
        hugepages_total=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo "0")
        if (( hugepages_total > 0 )); then
            hugepages_free=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null || echo "0")
            _row "Hugepages"  "--  ${hugepages_free}/${hugepages_total} free  ($(( hugepages_total * 2 )) MB reserved)"
        fi

        if ! findmnt -n /var/lib/qemu &>/dev/null; then
            _row "@qemu"      "!!  /var/lib/qemu not mounted — VM images inaccessible"
            _rec "@qemu subvolume not mounted at /var/lib/qemu — check fstab"
        fi

        if findmnt -n /var/lib/libvirt &>/dev/null || [[ -d /data/varlib/libvirt ]]; then
            local libvirt_mb=""
            libvirt_mb=$(du -sm /var/lib/libvirt /data/varlib/libvirt 2>/dev/null \
                | awk '{s+=$1} END{if(s>0)print s}' || echo "")
            if findmnt -n /var/lib/libvirt &>/dev/null; then
                _row "@libvirt"   "OK  mounted${libvirt_mb:+  ($(_mb_to_human "$libvirt_mb"))}"
            else
                _row "@libvirt"   "--  via /data/varlib/libvirt${libvirt_mb:+  ($(_mb_to_human "$libvirt_mb"))}"
            fi
            if [[ "$libvirt_mb" =~ ^[0-9]+$ ]] && (( libvirt_mb > 20480 )); then
                _row2 "!   $(_mb_to_human "$libvirt_mb") — review VM disk images"
                _rec "libvirt storage is $(_mb_to_human "$libvirt_mb") — review VM disk images"
            fi
        fi
    fi

    # Profile used by both the GNOME sharing stack and Remote Desktop blocks
    # Only relevant inside a SPICE virtual machine — skip on bare metal.
    _check_vm_guest "SPICE" "spice-vdagentd" "qemu|kvm|vmware|virtualbox|xen|hyperv" \
        "spice-vdagentd running (VM guest features active)" \
        "spice-vdagentd not enabled (clipboard/resize will not work)" \
        "Enable SPICE guest agent: systemctl enable --now spice-vdagentd"
    _check_vm_guest "VMware" "vmtoolsd" "vmware" \
        "vmtoolsd running (VMware guest features active)" \
        "vmtoolsd not enabled (clipboard/resize will not work)" \
        "Enable VMware guest agent: systemctl enable --now vmtoolsd"
    _check_vm_guest "VirtualBox" "vboxservice" "virtualbox|vbox" \
        "VBoxService running (VBox guest features active)" \
        "vboxservice not enabled (clipboard/shared folders will not work)" \
        "Enable VirtualBox guest agent: systemctl enable --now vboxservice"
    # Enables host-initiated shutdown, file system freeze for snapshots,
    # and guest info reporting inside KVM/QEMU VMs.
    if _svc_present qemu-guest-agent; then
        local _in_kvm=0
        grep -qiE 'qemu|kvm' /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null && _in_kvm=1
        [[ $_in_kvm -eq 0 ]] && ls /sys/bus/virtio/devices/ 2>/dev/null | grep -q '.' && _in_kvm=1
        if (( _in_kvm )); then
            if systemctl is-active --quiet qemu-guest-agent 2>/dev/null; then
                _row "QEMU agent"  "OK  qemu-guest-agent running"
            elif systemctl is-enabled --quiet qemu-guest-agent 2>/dev/null; then
                _row "QEMU agent"  "!   enabled but not running"
            else
                _row "QEMU agent"  "!   not enabled (snapshots/shutdown coordination unavailable)"
            fi
        fi
    fi
    # hv_kvp_daemon (key-value pair), hv_vss_daemon (volume shadow copy),
    # hv_fcopy_daemon (file copy) — enable host↔guest integration.
    if systemctl cat hv_kvp_daemon &>/dev/null 2>&1 || \
       systemctl cat hyperv-daemons.hv-kvp-daemon &>/dev/null 2>&1; then
        local _in_hyperv=0
        grep -qiE 'microsoft|hyper-v|hyperv' \
            /sys/class/dmi/id/sys_vendor \
            /sys/class/dmi/id/product_name 2>/dev/null && _in_hyperv=1
        if (( _in_hyperv )); then
            local _hv_ok=0 _hv_fail=()
            for _hvsvc in hv_kvp_daemon hv_vss_daemon hv_fcopy_daemon; do
                if systemctl is-active --quiet "$_hvsvc" 2>/dev/null; then
                    _hv_ok=$(( _hv_ok + 1 ))
                elif systemctl cat "$_hvsvc" &>/dev/null 2>&1; then _hv_fail+=("$_hvsvc")
                fi
            done
            if [[ ${#_hv_fail[@]} -eq 0 && $_hv_ok -gt 0 ]]; then
                _row "Hyper-V"    "OK  guest daemons running (${_hv_ok})"
            elif [[ ${#_hv_fail[@]} -gt 0 ]]; then
                _row "Hyper-V"    "!   some guest daemons not running: $(_join "${_hv_fail[@]}")"
                else
                _row "Hyper-V"    "!   running in Hyper-V but guest daemons not enabled"
            fi
        fi
        # Silent on bare metal
    fi

}

_section_firmware() {
    _head "Firmware"
    local _cpu_vfw=$(grep -m1 "vendor_id" /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo "")
    case "$_cpu_vfw" in
        AuthenticAMD)
            if [[ -f /boot/amd-ucode.img ]] || [[ -d /usr/lib/firmware/amd-ucode ]] || ls /usr/lib/firmware/amd-ucode* &>/dev/null 2>&1; then
                local _uv; _uv=$(grep -m1 "microcode" /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo "")
                _row "CPU ucode"   "OK  amd-ucode present${_uv:+  (rev ${_uv})}"
            else
                _row "CPU ucode"   "!   amd-ucode not installed — CPU mitigations may be incomplete"
                _rec "amd-ucode not found — add to ShaniOS base image and regenerate UKI"
            fi ;;
        GenuineIntel)
            if [[ -f /boot/intel-ucode.img ]] || [[ -d /usr/lib/firmware/intel-ucode ]]; then
                local _uv; _uv=$(grep -m1 "microcode" /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo "")
                _row "CPU ucode"   "OK  intel-ucode present${_uv:+  (rev ${_uv})}"
            else
                _row "CPU ucode"   "!   intel-ucode not installed — CPU mitigations may be incomplete"
                _rec "intel-ucode not found — add to ShaniOS base image and regenerate UKI"
            fi ;;
    esac

    if ! command -v fwupdmgr &>/dev/null; then
        _row "fwupd"     "--  not available"
        return 0
    fi

    # fwupd.service — D-Bus activated so inactive between calls is normal;
    # only flag if not enabled or in failed state.
    local fwupd_en; fwupd_en=$(systemctl is-enabled fwupd.service 2>/dev/null || echo "disabled")
    if [[ "$fwupd_en" == "enabled" || "$fwupd_en" == "static" ]]; then
        if systemctl is-failed --quiet fwupd.service 2>/dev/null; then
            _row "fwupd svc"  "!!  fwupd.service failed — firmware updates broken"
            fi
    else
        _row "fwupd svc"  "!!  fwupd.service not enabled — firmware updates disabled"
        _rec "Enable fwupd: systemctl enable --now fwupd.service fwupd-refresh.timer"
    fi

    # fwupd-refresh.timer — must be enabled for automatic firmware update checks
    local refresh_timer; refresh_timer=$(systemctl is-enabled fwupd-refresh.timer 2>/dev/null || echo "disabled")
    if [[ "$refresh_timer" == "enabled" || "$refresh_timer" == "static" ]]; then _row "fwupd tmr"  "OK  fwupd-refresh.timer enabled"
    else
        _row "fwupd tmr"  "!!  fwupd-refresh.timer not enabled — firmware checks won't run automatically"
    fi

    local fw_out; fw_out=$(timeout 15 fwupdmgr get-updates --offline 2>/dev/null || true)
    if echo "$fw_out" | grep -q 'GUID\|Version'; then
        local n; n=$(echo "$fw_out" | grep -c 'GUID' || echo "1")
        _row "Updates"   "!   ${n} update(s) available — run: fwupdmgr update"
        _rec "${n} firmware update(s) available — run: fwupdmgr update"
    else
        _row "Updates"   "OK  up to date (cached)"
    fi
    if _svc_present passim; then
        local _passim_en=$(systemctl is-enabled passim 2>/dev/null || echo "disabled")
        if systemctl is-active --quiet passim 2>/dev/null; then
            _row "passim"      "OK  running (local update cache active)"
        elif [[ "$_passim_en" == "static" ]]; then
            _row "passim"      ">>  enabled (idle — activated by fwupd on demand)"
        elif [[ "$_passim_en" == "enabled" ]]; then _row "passim"      "!   enabled but not running"
        else
            _row "passim"      "~~  not enabled — local LAN update cache: systemctl enable --now passim"
        fi
    fi
}

_section_monitoring() {
    _head "Monitoring"
    # Runs permanently, polls drives on a schedule, emails on failure.
    if _svc_present smartd; then
        if systemctl is-active --quiet smartd 2>/dev/null; then
            local _smartd_devs=""
            _smartd_devs=$(smartctl --scan 2>/dev/null | wc -l || echo "")
            _row "smartd"      "OK  running${_smartd_devs:+  (${_smartd_devs} device(s) monitored)}"
        elif systemctl is-enabled --quiet smartd 2>/dev/null; then
            _row "smartd"      "!   enabled but not running — disk failure alerts inactive"
        else
            _row "smartd"      "~~  not enabled — continuous disk monitoring inactive: systemctl enable --now smartd"
        fi
    fi
    # arpwatch detects ARP spoofing / unexpected IP-MAC changes on the LAN.
    if _svc_present arpwatch; then
        if systemctl is-active --quiet arpwatch 2>/dev/null; then
            _row "arpwatch"    "OK  running"
        elif systemctl is-enabled --quiet arpwatch 2>/dev/null; then
            _row "arpwatch"    "!   enabled but not running"
        else
            _row "arpwatch"    "~~  not enabled — ARP spoofing detection inactive"
        fi
    fi
    if _svc_present vnstatd; then
        if systemctl is-active --quiet vnstatd 2>/dev/null; then
            local vn_ifaces=""
            vn_ifaces=$(vnstat --json 2>/dev/null \
                | python3 -c \
                  "import sys,json; d=json.load(sys.stdin); print(', '.join(i['name'] for i in d.get('interfaces',[])))" \
                2>/dev/null || echo "")
            _row "vnstatd"     "OK  running${vn_ifaces:+  (${vn_ifaces})}"
        elif systemctl is-enabled --quiet vnstatd 2>/dev/null; then _row "vnstatd"     "!   enabled but not running"
        else
            _row "vnstatd"     "~~  not enabled — traffic monitoring inactive; to enable: systemctl enable --now vnstatd"
        fi
    fi
    # service + collect + summary timers all needed for sar/iostat history.
    if _svc_present sysstat.service; then
        local _ss_svc _ss_collect _ss_summary
        _ss_svc=$(systemctl is-active sysstat.service 2>/dev/null || echo "inactive")
        _ss_collect=$(systemctl is-enabled sysstat-collect.timer 2>/dev/null || echo "disabled")
        _ss_summary=$(systemctl is-enabled sysstat-summary.timer 2>/dev/null || echo "disabled")
        local _ss_collect_ok=0 _ss_summary_ok=0
        [[ "$_ss_collect" == "enabled" || "$_ss_collect" == "static" ]] && _ss_collect_ok=1
        [[ "$_ss_summary" == "enabled" || "$_ss_summary" == "static" ]] && _ss_summary_ok=1
        if [[ "$_ss_svc" == "active" ]] && (( _ss_collect_ok && _ss_summary_ok )); then
            _row "sysstat"     "OK  accounting active (service + collect + summary timers enabled)"
        elif systemctl is-enabled --quiet sysstat.service 2>/dev/null || \
             systemctl is-active  --quiet sysstat.service 2>/dev/null; then
            local _ss_issues=()
            [[ "$_ss_svc"  != "active" ]] && _ss_issues+=("sysstat.service inactive")
            (( ! _ss_collect_ok ))         && _ss_issues+=("collect timer not enabled")
            (( ! _ss_summary_ok ))         && _ss_issues+=("summary timer not enabled")
            if [[ ${#_ss_issues[@]} -gt 0 ]]; then _row "sysstat"     "!   partially active — ${_ss_issues[*]}"
            else
                _row "sysstat"     "OK  accounting active"
            fi
        else
            _row "sysstat"     "~~  not enabled — sar/iostat history unavailable: systemctl enable --now sysstat.service"
        fi
    fi
    # Without it, logs grow unbounded. Only the timer needs to be active.
    if _svc_present logrotate; then
        local _lr_active=0; systemctl is-active --quiet logrotate.timer 2>/dev/null && _lr_active=1
        local _lr_en; _lr_en=$(systemctl is-enabled logrotate.timer 2>/dev/null || echo "disabled")
        local _lr_enabled=0
        [[ "$_lr_en" == "enabled" || "$_lr_en" == "static" ]] && _lr_enabled=1
        if (( _lr_active || _lr_enabled )); then
            local _lr_last=""
            _lr_last=$(systemctl show logrotate.service \
                --property=ExecMainExitTimestamp --value 2>/dev/null \
                | grep -v '^n/a\|^$' | head -1 || echo "")
            _row "logrotate"   "OK  timer active${_lr_last:+  (last run: ${_lr_last})}"
        else
            _row "logrotate"   "!   timer not enabled — logs will not be rotated automatically"
            _rec "Enable log rotation: systemctl enable --now logrotate.timer"
        fi
    fi
    # If dead, all user and system cron jobs silently stop running.
    if _svc_present cronie; then
        if systemctl is-active --quiet cronie 2>/dev/null; then
            local _cron_jobs=""
            _cron_jobs=$(crontab -l 2>/dev/null | grep -cvE '^[[:space:]]*#|^[[:space:]]*$' || echo "")
            _row "cronie"      "OK  running${_cron_jobs:+  (${_cron_jobs} root crontab job(s))}"
        elif systemctl is-enabled --quiet cronie 2>/dev/null; then
            _row "cronie"      "!   enabled but not running — cron jobs not executing"
        else
            _row "cronie"      "~~  not enabled — scheduled tasks inactive: systemctl enable --now cronie"
        fi
    fi
    # Purges stale sockets, old locks, and cruft from /tmp, /var/tmp, /run.
    if systemctl cat systemd-tmpfiles-clean.timer &>/dev/null 2>&1; then
        local _tfc_active=0; systemctl is-active --quiet systemd-tmpfiles-clean.timer 2>/dev/null && _tfc_active=1
        local _tfc_en; _tfc_en=$(systemctl is-enabled systemd-tmpfiles-clean.timer 2>/dev/null || echo "disabled")
        if (( _tfc_active )) || [[ "$_tfc_en" == "enabled" || "$_tfc_en" == "static" ]]; then
            _row "tmpfiles"    "OK  cleanup timer active"
        else
            _row "tmpfiles"    "!   systemd-tmpfiles-clean.timer not enabled — stale file cleanup inactive"
            _rec "Enable tmpfiles cleanup: systemctl enable --now systemd-tmpfiles-clean.timer"
        fi
    fi
    # Logs kernel security events (syscall auditing, file access, etc.)
    if command -v auditctl &>/dev/null; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            local audit_rules; audit_rules=$(auditctl -l 2>/dev/null | grep -c '^-' || true)
            [[ -z "$audit_rules" ]] && audit_rules="?"
            if [[ "$audit_rules" == "0" ]]; then
                _row "auditd"    "!   running but no rules configured"
                _rec "Audit daemon has no rules — create /etc/audit/rules.d/local.rules"
            else
                _row "auditd"    "OK  running (${audit_rules} rule(s))"
            fi
        else
            local audit_en; audit_en=$(systemctl is-enabled auditd 2>/dev/null || echo "disabled")
            if [[ "$audit_en" == "enabled" ]]; then _row "auditd"    "!   enabled but not running"
                    else
                _row "auditd"    "~~  not enabled"
            fi
        fi
    fi
    if command -v timedatectl &>/dev/null; then
        local td_out ntp_active ntp_synced tsync
        td_out=$(timedatectl show 2>/dev/null || true)
        ntp_active=$(echo "$td_out" | awk -F= '/^NTP=/{print $2}'             | tr -d '[:space:]')
        ntp_synced=$(echo "$td_out" | awk -F= '/^NTPSynchronized=/{print $2}' | tr -d '[:space:]')
        tsync=$(systemctl is-active systemd-timesyncd 2>/dev/null || echo "inactive")
        if [[ "$ntp_synced" == "yes" && "$tsync" == "active" ]]; then
            local _ntp_server="" _ntp_offset=""
            _ntp_server=$(timedatectl timesync-status 2>/dev/null \
                | awk '/^[[:space:]]*Server:/{print $2}' | head -1 || echo "")
            [[ -z "$_ntp_server" ]] && \
                _ntp_server=$(journalctl -u systemd-timesyncd -n 50 --no-pager 2>/dev/null \
                    | grep -oP '(?<=synchronized to )\S+' | tail -1 || echo "")
            _ntp_offset=$(timedatectl timesync-status 2>/dev/null \
                | awk '/^[[:space:]]*Offset:/{print $2,$3}' | head -1 || echo "")
            _row "timesyncd"  "OK  synchronised${_ntp_server:+  (${_ntp_server})}"
            if [[ -n "$_ntp_offset" ]]; then
                local _off_ms; _off_ms=$(echo "$_ntp_offset" | grep -oE '[0-9]+' | head -1 || echo "0")
                local _off_unit; _off_unit=$(echo "$_ntp_offset" | grep -oE '[a-z]+' | head -1 || echo "")
                local _off_large=0
                [[ "$_off_unit" == "s" || "$_off_unit" == "min" ]] && _off_large=1
                [[ "$_off_unit" == "ms" && "$_off_ms" =~ ^[0-9]+$ ]] && (( _off_ms > 1000 )) && _off_large=1
                if (( _off_large )); then
                    _row2 "!   offset ${_ntp_offset} — large clock drift, check hardware clock"
                    _rec "NTP clock offset is ${_ntp_offset} — large drift; check: hwclock --systohc"
                else
                    _row2 "--  offset ${_ntp_offset}"
                fi
            fi
        elif [[ "$ntp_active" == "yes" && "$tsync" == "active" ]]; then
            _row "timesyncd"  "!   running but not yet synchronised"
        elif [[ "$ntp_active" == "yes" ]]; then _row "timesyncd"  "!!  NTP enabled but service is ${tsync}"
        else
            _row "timesyncd"  "!!  disabled"
            _rec "NTP disabled — run: systemctl enable --now systemd-timesyncd && timedatectl set-ntp true"
        fi
    else
        _row "timesyncd"  "--  timedatectl not available"
    fi
    if _svc_present chronyd; then
        local _chrony_cfg=0
        [[ -f /etc/chrony.conf ]] && \
            grep -qE '^(server|pool) ' /etc/chrony.conf 2>/dev/null && \
            _chrony_cfg=1
        if systemctl is-active --quiet chronyd 2>/dev/null; then
            local _chr_src=""
            _chr_src=$(chronyc tracking 2>/dev/null \
                | awk '/^Reference ID/{print $5}' | head -1 || echo "")
            _row "chrony"      "OK  running${_chr_src:+  (${_chr_src})}"
            if systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
                _row2 "!   systemd-timesyncd also active — NTP conflict"
                _rec "Both chrony and systemd-timesyncd active — disable one: systemctl disable --now systemd-timesyncd"
            fi
        elif systemctl is-enabled --quiet chronyd 2>/dev/null; then
            if (( ! _chrony_cfg )); then
                _row "chrony"      "!   enabled but not configured — add server/pool lines to /etc/chrony.conf"
                _rec "chrony enabled but no server/pool in /etc/chrony.conf — add NTP servers before starting"
            elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
                _row "chrony"      "!!  enabled but timesyncd also active — NTP conflict; disable one: systemctl disable --now systemd-timesyncd  or  systemctl disable --now chronyd"
                _rec "chrony and timesyncd both enabled — disable timesyncd first: systemctl disable --now systemd-timesyncd"
            else
                _row "chrony"      "!   enabled but not running"
                fi
        elif (( _chrony_cfg )); then
            _row "chrony"      "~~  configured, not enabled — timesyncd active; to switch: systemctl disable --now systemd-timesyncd"
        fi
    fi
    if _svc_present openntpd; then
        local _ntpd_cfg=0
        [[ -f /etc/ntpd.conf ]] && \
            grep -qE '^(server|servers) ' /etc/ntpd.conf 2>/dev/null && \
            _ntpd_cfg=1
        if systemctl is-active --quiet openntpd 2>/dev/null; then
            _row "openntpd"    "OK  running"
            if systemctl is-active --quiet systemd-timesyncd 2>/dev/null || \
               systemctl is-active --quiet chronyd 2>/dev/null; then
                _row2 "!   another NTP daemon also active — conflict likely"
                _rec "Multiple NTP daemons active alongside openntpd — disable duplicates"
            fi
        elif systemctl is-enabled --quiet openntpd 2>/dev/null; then
            if (( ! _ntpd_cfg )); then
                _row "openntpd"    "!   enabled but not configured — add server lines to /etc/ntpd.conf"
                _rec "openntpd enabled but no server entries in /etc/ntpd.conf — configure NTP servers before starting"
            elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null || \
                 systemctl is-active --quiet chronyd 2>/dev/null; then
                _row "openntpd"    "!!  enabled but another NTP daemon also active — conflict; disable one first"
                _rec "openntpd and another NTP daemon both enabled — disable timesyncd: systemctl disable --now systemd-timesyncd"
            else
                _row "openntpd"    "!   enabled but not running"
            fi
        elif (( _ntpd_cfg )); then
            _row "openntpd"    "~~  configured, not enabled — timesyncd active; to switch: systemctl disable --now systemd-timesyncd"
        fi
    fi
    # Both conflict with journald if they duplicate log collection; surface when
    # installed and enabled so the user knows the logging stack in use.
    for _syslog_unit in rsyslog syslog-ng; do
        if command -v "$_syslog_unit" &>/dev/null || \
           systemctl cat "$_syslog_unit" &>/dev/null 2>&1; then
            if systemctl is-active --quiet "$_syslog_unit" 2>/dev/null; then
                _row "$_syslog_unit"   "OK  running (syslog alongside journald)"
            elif systemctl is-enabled --quiet "$_syslog_unit" 2>/dev/null; then
                _row "$_syslog_unit"   "!   enabled but not running"
                else
                _row "$_syslog_unit"   "~~  not enabled — journald handles logging by default"
            fi
        fi
    done
    # journal-remote receives logs from remote hosts via its .socket unit.
    # journal-upload pushes local logs to a remote collector.
    for _jfwd_unit in systemd-journal-remote systemd-journal-upload; do
        if systemctl cat "${_jfwd_unit}" &>/dev/null 2>&1; then
            local _jfwd_en=$(systemctl is-enabled "${_jfwd_unit}" 2>/dev/null || echo "disabled")
            if systemctl is-active --quiet "${_jfwd_unit}" 2>/dev/null; then
                _row "${_jfwd_unit##*-}"  "OK  ${_jfwd_unit} running"
            elif [[ "$_jfwd_en" == "static" ]]; then
                _row "${_jfwd_unit##*-}"  ">>  enabled (idle — socket-activated)"
            elif [[ "$_jfwd_en" == "enabled" ]]; then
                _row "${_jfwd_unit##*-}"  "!   ${_jfwd_unit} enabled but not running"
                fi
        fi
    done
}

_section_runtime_health() {
    _head "Runtime Health"
    local load1 ncores load_int
    load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "")
    ncores=$(nproc 2>/dev/null || echo "1")
    if [[ -n "$load1" && "$ncores" =~ ^[0-9]+$ ]]; then
        load_int=$(awk "BEGIN{printf \"%d\", $load1}" 2>/dev/null || echo "0")
        if (( load_int >= ncores * 4 )); then
            _row "CPU load"   "!!  ${load1}  (${ncores} cores) — critically high"
            _rec "CPU load average ${load1} on ${ncores} cores — check: ps aux --sort=-%cpu | head"
        elif (( load_int >= ncores * 2 )); then _row "CPU load"   "!   ${load1}  (${ncores} cores) — high"
        else
            _row "CPU load"   "OK  ${load1}  (${ncores} cores)"
        fi
    fi
    if [[ -f /proc/pressure/cpu ]]; then
        local psi_cpu=""
        psi_cpu=$(awk '/^some/{for(i=1;i<=NF;i++) if($i~/^avg10=/) {sub(/avg10=/,"",$i); printf "%.1f",$i}}'             /proc/pressure/cpu 2>/dev/null || echo "")
        if [[ -n "$psi_cpu" ]]; then
            local psi_cpu_int; psi_cpu_int=$(printf "%.0f" "$psi_cpu" 2>/dev/null || echo "0")
            if (( psi_cpu_int >= 50 )); then
                _row "CPU PSI"    "!   some=${psi_cpu}% — high CPU contention"
                _rec "CPU pressure (PSI some) is ${psi_cpu}% — system is CPU-starved; check: ps aux --sort=-%cpu | head"
            fi
        fi
    fi
    if [[ -f /proc/pressure/io ]]; then
        local psi_io=""
        psi_io=$(awk '/^some/{for(i=1;i<=NF;i++) if($i~/^avg10=/) {sub(/avg10=/,"",$i); printf "%.1f",$i}}'             /proc/pressure/io 2>/dev/null || echo "")
        if [[ -n "$psi_io" ]]; then
            local psi_io_int; psi_io_int=$(printf "%.0f" "$psi_io" 2>/dev/null || echo "0")
            if (( psi_io_int >= 30 )); then
                _row "I/O PSI"    "!   some=${psi_io}% — significant I/O wait"
                _rec "I/O pressure ${psi_io}% — check: iotop -o or iostat -x 1 5"
            fi
        fi
    fi
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
    local zram_devs; zram_devs=$(ls /dev/zram* 2>/dev/null | wc -l || echo "0")
    if [[ "$zram_devs" =~ ^[0-9]+$ ]] && (( zram_devs > 0 )); then
        local zram_active=0
        swapon --show=NAME --noheadings 2>/dev/null | grep -q zram && zram_active=1
        if (( zram_active )); then
            local zram_size zram_algo
            zram_size=$(swapon --show=SIZE --noheadings 2>/dev/null \
                | grep zram | head -1 | awk '{print $1}' | tr -d ' ' || echo "")
            zram_algo=$(cat /sys/block/zram0/comp_algorithm 2>/dev/null \
                | grep -oP '\[\K[^\]]+' || echo "")
            _row "ZRAM"      "OK  active${zram_size:+  (${zram_size})}${zram_algo:+  algo: ${zram_algo}}"
        else
            _row "ZRAM"      "!   device present but not active as swap"
            _rec "ZRAM device found but not in use — check /etc/systemd/zram-generator.conf"
        fi
    else
        _row "ZRAM"          "!   not configured — memory pressure handled by swapfile only"
    fi
    if systemctl is-active --quiet systemd-oomd 2>/dev/null; then
        # Show memory pressure if PSI is available — gives context for oomd activity
        local psi_mem=""
        if [[ -f /proc/pressure/memory ]]; then
            local _psi_raw; _psi_raw=$(awk '/^some/{for(i=1;i<=NF;i++) if($i~/^avg10=/) {sub(/avg10=/,"",$i); printf "%.1f",$i}}'                 /proc/pressure/memory 2>/dev/null || echo "")
            [[ -n "$_psi_raw" ]] && psi_mem="PSI some=${_psi_raw}%"
            # Warn if memory pressure is high (oomd threshold is typically 60%)
            if [[ -n "$_psi_raw" ]]; then
                local _psi_int; _psi_int=$(printf "%.0f" "$_psi_raw" 2>/dev/null || echo "0")
                if (( _psi_int >= 40 )); then
                    _rec "Memory pressure (PSI some) is ${_psi_raw}% — system under memory stress; consider more RAM or reducing load"
                fi
            fi
        fi
        _row "oomd"        "OK  running${psi_mem:+  (${psi_mem})}"
    elif systemctl is-enabled --quiet systemd-oomd 2>/dev/null; then
        _row "oomd"        "!   enabled but not running — system freeze protection inactive"
    else
        if systemctl is-active --quiet earlyoom 2>/dev/null; then _row "oomd"    "--  not enabled (earlyoom active)"
        else
            _row "oomd"        "!   not enabled — system freeze protection inactive"
            _rec "Enable systemd-oomd: systemctl enable --now systemd-oomd"
        fi
    fi
    local _iface_errors=()
    while IFS= read -r _iface; do
        [[ -z "$_iface" || "$_iface" == lo ]] && continue
        local _rx_err _tx_err _rx_drop _tx_drop
        _rx_err=$(ip  -s link show "$_iface" 2>/dev/null | awk '/RX:/{getline; print $3}' | head -1 || echo "0")
        _tx_err=$(ip  -s link show "$_iface" 2>/dev/null | awk '/TX:/{getline; print $3}' | head -1 || echo "0")
        _rx_drop=$(ip -s link show "$_iface" 2>/dev/null | awk '/RX:/{getline; print $4}' | head -1 || echo "0")
        _tx_drop=$(ip -s link show "$_iface" 2>/dev/null | awk '/TX:/{getline; print $4}' | head -1 || echo "0")
        local _tot_err=$(( ${_rx_err:-0} + ${_tx_err:-0} ))
        local _tot_drop=$(( ${_rx_drop:-0} + ${_tx_drop:-0} ))
        # Detect wireless: name starts with wl, or phy present in /sys
        local _is_wireless=0
        [[ "$_iface" == wl* ]] && _is_wireless=1
        [[ $_is_wireless -eq 0 && -d "/sys/class/net/${_iface}/wireless" ]] && _is_wireless=1
        # Errors always flagged; drop threshold: 10k for wireless (normal churn), 5k for wired
        local _drop_thresh=5000
        (( _is_wireless )) && _drop_thresh=10000
        if (( _tot_err > 0 || _tot_drop > _drop_thresh )); then
            _iface_errors+=("${_iface}: err=${_tot_err} drop=${_tot_drop}")
        fi
    done < <(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)
    if [[ ${#_iface_errors[@]} -gt 0 ]]; then
        _row "NIC errors"  "!   ${_iface_errors[0]}"
        for (( _ni=1; _ni<${#_iface_errors[@]}; _ni++ )); do
            _row2 "!   ${_iface_errors[$_ni]}"
        done
        _rec "Network interface errors/drops — check: ip -s link show <iface>"
    fi

    # Pre-check: earlyoom+oomd conflict must always show
    if _svc_present earlyoom; then
        if systemctl is-enabled --quiet earlyoom 2>/dev/null && \
           systemctl is-active  --quiet systemd-oomd 2>/dev/null; then
            _row "earlyoom" "!!  enabled but systemd-oomd already active — duplicate OOM handling; disable one: systemctl disable --now earlyoom"
            _rec "earlyoom enabled but systemd-oomd already active — disable one: systemctl disable --now earlyoom"
        fi
    fi
    _optional_begin
    if _svc_present earlyoom; then
        if systemctl is-active --quiet earlyoom 2>/dev/null; then
            _row "earlyoom"    "OK  running"
            if systemctl is-active --quiet systemd-oomd 2>/dev/null; then
                _row2 "!   systemd-oomd also active — duplicate OOM handling"
                _rec  "Both earlyoom and systemd-oomd are active — disable one to avoid conflicts"
            fi
        elif systemctl is-enabled --quiet earlyoom 2>/dev/null; then
            if systemctl is-active --quiet systemd-oomd 2>/dev/null; then
                : # already reported above the optional block
            else
                _row "earlyoom"    "!   enabled but not running"
            fi
        fi
        # Silent when not installed/enabled
    fi

    _optional_end
}

_section_coredump() {
    _head "Core Dumps"

    # systemd-coredump — is the handler wired up?
    local core_pattern=""
    core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "")

    if [[ "$core_pattern" == "|/usr/lib/systemd/systemd-coredump"* ]]; then
        _row "Handler"    "OK  systemd-coredump active"
    elif [[ "$core_pattern" == "core"* || "$core_pattern" == "./"* || "$core_pattern" =~ ^/ ]]; then
        _row "Handler"    "--  writing to file: ${core_pattern}  (systemd-coredump not configured)"
    elif [[ -z "$core_pattern" ]]; then _row "Handler"    "!   core_pattern empty — crashes silently lost"
    else
        _row "Handler"    "--  custom: ${core_pattern}"
    fi

    # Is systemd-coredump installed and the socket present?
    if systemctl cat systemd-coredump.socket &>/dev/null 2>&1; then
        local _cd_en; _cd_en=$(systemctl is-enabled systemd-coredump.socket 2>/dev/null || echo "")
        local _cd_failed=0
        systemctl is-failed --quiet systemd-coredump.socket 2>/dev/null && _cd_failed=1
        if (( _cd_failed )); then
            _row "Socket"     "!!  systemd-coredump.socket failed — core dump capture broken"
            _rec "Reset coredump socket: systemctl reset-failed systemd-coredump.socket"
        elif [[ "$_cd_en" == "static" ]]; then
            # static = socket-activated, wakes on crash signal — inactive is expected/normal
            _row "Socket"     "OK  systemd-coredump.socket ready (socket-activated)"
        elif systemctl is-active --quiet systemd-coredump.socket 2>/dev/null; then
            _row "Socket"     "OK  systemd-coredump.socket active"
        elif [[ "$_cd_en" == "enabled" ]]; then _row "Socket"     "!   systemd-coredump.socket enabled but not active"
            else
            _row "Socket"     "--  systemd-coredump installed but socket not enabled"
            _rec "Enable coredump capture: systemctl enable --now systemd-coredump.socket"
        fi
    else
        _row "Socket"     "--  systemd-coredump not installed "
    fi

    # Check storage config — /etc/systemd/coredump.conf
    local coredump_storage=""
    # Read coredump storage setting from all config layers (usr/lib < etc drop-ins < etc main)
    coredump_storage=$(grep -rshE '^Storage=' \
        /usr/lib/systemd/coredump.conf.d/ \
        /etc/systemd/coredump.conf.d/ \
        /etc/systemd/coredump.conf 2>/dev/null \
        | tail -1 | cut -d= -f2 | tr -d '[:space:]' || echo "")
    if [[ -n "$coredump_storage" ]]; then
        _row "Storage"    "--  ${coredump_storage}"
        [[ "$coredump_storage" == "none" ]] && _row2 "!   Storage=none — core dumps discarded even if captured"
    fi

    # Recent core dumps this boot
    local coredump_count=0
    if command -v coredumpctl &>/dev/null; then
        coredump_count=$(coredumpctl list --no-pager -q 2>/dev/null | grep -c '' || echo "0")
        coredump_count=$(echo "${coredump_count:-0}" | tr -d '[:space:]')
        [[ "$coredump_count" =~ ^[0-9]+$ ]] || coredump_count=0
        if (( coredump_count > 0 )); then
            _row "Dumps"      "!   ${coredump_count} core dump(s) recorded — run: coredumpctl list"
            local _last_crash=""
            # coredumpctl list columns: TIME(weekday date time zone) UID GID PID SIG COREFILE EXE
            # Extract date+time (fields 1-3) and executable (last non-dash field)
            _last_crash=$(coredumpctl list --no-pager -q 2>/dev/null | tail -1 \
                | awk '{
                    ts = $1 " " $2 " " $3
                    # Walk fields from end; skip dash placeholders
                    exe = ""
                    for (i = NF; i > 3; i--) {
                        if ($i != "-") { exe = $i; break }
                    }
                    print ts (exe ? "  " exe : "")
                }' || echo "")
            [[ -n "$_last_crash" ]] && _row2 "--  last: ${_last_crash}"
        else
            _row "Dumps"      "OK  no core dumps recorded"
        fi
    fi
}

_section_system_health() {
    _head "System Health"
    if systemctl is-active --quiet dbus 2>/dev/null || \
       systemctl is-active --quiet dbus.socket 2>/dev/null; then
        _row "D-Bus"        "OK  running"
    else
        _row "D-Bus"        "!!  not running — most desktop services will fail"
        _rec "D-Bus is not running — run: systemctl enable --now dbus"
    fi
    if systemctl is-active --quiet systemd-logind 2>/dev/null; then _row "logind"       "OK  running"
    else
        local _logind_en; _logind_en=$(systemctl is-enabled systemd-logind 2>/dev/null || echo "")
        if [[ "$_logind_en" == "enabled" || "$_logind_en" == "static" ]]; then
            _row "logind"   "!!  not running — session/seat management broken"
        else
            _row "logind"   "!!  disabled — session/seat management unavailable"
        fi
    fi
    # accountsservice: core dependency for GDM, KDE login manager, user settings.
    if systemctl cat accounts-daemon &>/dev/null 2>&1; then
        if systemctl is-active --quiet accounts-daemon 2>/dev/null; then
            _row "accountssvc"  "OK  accounts-daemon running"
        else
            _row "accountssvc"  "!!  not running — user login/settings panels may fail"
        fi
    fi
    # A broken nsswitch.conf causes silent failures in getent, sudo, login, etc.
    if [[ -f /etc/nsswitch.conf ]]; then
        local nss_passwd nss_hosts
        nss_passwd=$(grep -E '^passwd:' /etc/nsswitch.conf 2>/dev/null | head -1 || echo "")
        nss_hosts=$(grep  -E '^hosts:'  /etc/nsswitch.conf 2>/dev/null | head -1 || echo "")
        local nss_issues=()
        [[ -z "$nss_passwd" ]] && nss_issues+=("passwd line missing")
        [[ -z "$nss_hosts"  ]] && nss_issues+=("hosts line missing")
        # hosts line should include 'files' and 'dns' at minimum
        if [[ -n "$nss_hosts" ]]; then
            echo "$nss_hosts" | grep -q '\bfiles\b' || nss_issues+=("hosts: 'files' missing")
            echo "$nss_hosts" | grep -q '\bdns\b'   || nss_issues+=("hosts: 'dns' missing")
        fi
        if [[ ${#nss_issues[@]} -eq 0 ]]; then _row "nsswitch"     "OK  passwd + hosts entries present"
        else
            _row "nsswitch"     "!   ${nss_issues[*]}"
            _rec "nsswitch.conf issues: ${nss_issues[*]} — check /etc/nsswitch.conf"
        fi
    else
        _row "nsswitch"         "!!  /etc/nsswitch.conf missing — name resolution broken"
        _rec "/etc/nsswitch.conf missing — restore from /etc/nsswitch.conf.pacsave or reinstall glibc"
    fi
    if command -v lastb &>/dev/null && [[ -f /var/log/btmp ]]; then
        local _lastb_count=0
        local _since_ts; _since_ts=$(date -d '-24 hours' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")
        if [[ -n "$_since_ts" ]]; then
            # Filter out the trailing "btmp begins..." summary line and blank lines
            _lastb_count=$(lastb -s "$_since_ts" 2>/dev/null \
                | grep -cvE '^$|^btmp begins' || echo "0")
        else
            # Fallback: count all entries (no since filter)
            _lastb_count=$(lastb 2>/dev/null \
                | grep -cvE '^$|^btmp begins' || echo "0")
        fi
        _lastb_count=$(echo "${_lastb_count:-0}" | tr -d '[:space:]')
        [[ "$_lastb_count" =~ ^[0-9]+$ ]] || _lastb_count=0
        if (( _lastb_count >= 20 )); then
            _row "Failed logins" "!   ${_lastb_count} failed attempt(s) in last 24h — run: lastb | head"
            _rec "${_lastb_count} failed login attempts in 24h — check: lastb | head -20"
        elif (( _lastb_count > 0 )); then _row "Failed logins" "--  ${_lastb_count} failed attempt(s) in last 24h"
        else
            _row "Failed logins" "OK  none in last 24h"
        fi
    fi
    # loginctl list-sessions columns: SESSION  UID  USER  SEAT  TTY
    if command -v loginctl &>/dev/null; then
        local _sessions=$(loginctl list-sessions --no-legend 2>/dev/null | grep -c '.' || echo "0")
        _sessions=$(echo "${_sessions:-0}" | tr -d '[:space:]')
        [[ "$_sessions" =~ ^[0-9]+$ ]] || _sessions=0
        if (( _sessions > 0 )); then
            local _sess_detail
            # Show: user@seat (tty) — e.g. shlok@seat0 (tty2)
            _sess_detail=$(loginctl list-sessions --no-legend 2>/dev/null \
                | awk '{
                    user=$3; seat=$4; tty=$5
                    if (seat == "-") seat=""
                    if (tty == "-" || tty+0 == tty) tty=""
                    label = user
                    if (seat != "") label = label "@" seat
                    if (tty != "") label = label " (" tty ")"
                    printf "%s ", label
                }' | sed 's/[[:space:]]*$//' || echo "")
            _row "Sessions"    "--  ${_sessions} active: ${_sess_detail}"
        fi
    fi
    local running installed
    running=$(uname -r 2>/dev/null || echo "")
    installed=$(find /usr/lib/modules/ -maxdepth 1 -mindepth 1 -type d 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^/]*$' | sort -V | tail -1 || echo "")
    if [[ -n "$running" && -n "$installed" ]]; then
        if [[ "$running" == "$installed" ]]; then _row "Kernel"     "OK  ${running}"
        else
            _row "Kernel"     "!   running ${running}  /  installed ${installed}"
            _rec "Kernel mismatch: running ${running}, installed ${installed} — reboot"
        fi
    fi
    if command -v systemd-analyze &>/dev/null; then
        local bt bt_sec bt_raw
        # systemd-analyze outputs: "Startup finished in Xs (kernel) + Ys (userspace) = TOTALs"
        # or "= Xmin Y.Zs" on longer boots. Extract the total after '='.
        bt_raw=$(systemd-analyze 2>/dev/null | head -1 || echo "")
        bt=$(echo "$bt_raw" | sed 's/.*= *//' | tr -d '\n' | sed 's/[[:space:]]*$//' || echo "")
        if [[ -n "$bt" ]]; then
            # Convert to integer seconds for threshold comparison.
            # Handle "Xmin Y.Zs", "X.Ys", "Xs"
            if echo "$bt" | grep -q 'min'; then
                local _bt_mins _bt_secs
                _bt_mins=$(echo "$bt" | awk -F'min' '{gsub(/[^0-9]/,"",$1); print $1+0}')
                _bt_secs=$(echo "$bt" | grep -oE '[0-9]+(\.[0-9]+)?s' | grep -oE '^[0-9]+' | tail -1 || echo "0")
                bt_sec=$(( _bt_mins * 60 + _bt_secs ))
            else
                bt_sec=$(echo "$bt" | grep -oE '^[0-9]+' || echo "0")
            fi
            if (( bt_sec >= 45 )); then
                _row "Boot time"  "!   ${bt}  (slow — run: systemd-analyze blame)"
                # Inline top 3 slowest units — filter transient/sleep units
                # that appear in blame but are not boot-critical
                local _blame
                _blame=$(systemd-analyze blame 2>/dev/null \
                    | grep -vE "systemd-(suspend|hibernate|hybrid-sleep|sleep)\.service|shani-user-setup\.service|man-db\.service" \
                    | head -3 | sed 's/^ *//' || true)
                while IFS= read -r line; do
                    [[ -n "$line" ]] && _row2 "--  $line"
                done <<< "$_blame"
                # Targeted advice for the two most common desktop slow-boot culprits
                if echo "$_blame" | grep -q 'NetworkManager-wait-online'; then
                    _rec "NetworkManager-wait-online.service is slowing boot — disable if not needed: systemctl disable NetworkManager-wait-online.service"
                fi
                if echo "$_blame" | grep -qE 'dev-tpm0\.device|tpm.*device'; then
                    _rec "TPM device enumeration is slowing boot — if TPM auto-unlock is not used, consider disabling dev-tpm0.device"
                fi
            else
                _row "Boot time"  "OK  ${bt}"
            fi
        fi
    fi
    # Cache kernel journal once — reused by OOM and oops checks below.
    local _kjournal
    _kjournal=$(journalctl -k -b 0 --no-pager -q 2>/dev/null || true)
    local oom_kernel oom_oomd oom_total
    oom_kernel=$(echo "$_kjournal" \
        | grep -c 'Out of memory\|oom_kill_process\|Killed process' 2>/dev/null || echo "0")
    oom_kernel=$(echo "${oom_kernel:-0}" | tr -d '[:space:]')
    [[ "$oom_kernel" =~ ^[0-9]+$ ]] || oom_kernel=0
    oom_oomd=$(journalctl -b 0 --no-pager -q -u systemd-oomd 2>/dev/null \
        | grep -c 'Killed\|killed' 2>/dev/null || echo "0")
    oom_oomd=$(echo "${oom_oomd:-0}" | tr -d '[:space:]')
    [[ "$oom_oomd" =~ ^[0-9]+$ ]] || oom_oomd=0
    oom_total=$(( oom_kernel + oom_oomd ))
    if (( oom_total > 0 )); then
        local _oom_detail=""
        (( oom_kernel > 0 )) && _oom_detail+=" kernel:${oom_kernel}"
        (( oom_oomd   > 0 )) && _oom_detail+=" oomd:${oom_oomd}"
        _row "OOM kills"  "!   ${oom_total} event(s) this boot (${_oom_detail# })"
        _rec "${oom_total} OOM kill(s) this boot — consider more RAM or swap"
    else
        _row "OOM kills"  "OK  none this boot"
    fi
    local dirty_kb writeback_kb
    dirty_kb=$(    awk '/^Dirty:/     {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    writeback_kb=$(awk '/^Writeback:/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
    dirty_kb=$(echo "${dirty_kb:-0}" | tr -d '[:space:]')
    writeback_kb=$(echo "${writeback_kb:-0}" | tr -d '[:space:]')
    if [[ "$dirty_kb" =~ ^[0-9]+$ ]] && (( dirty_kb > 524288 )); then
        # > 512 MB dirty — noteworthy
        local dirty_mb=$(( dirty_kb / 1024 ))
        _row "Dirty mem"  "!   ${dirty_mb} MB dirty — high unflushed write buffer"
        _rec "High dirty memory (${dirty_mb} MB) — possible I/O pressure; check: iostat -x 1 5"
    fi
    if [[ "$writeback_kb" =~ ^[0-9]+$ ]] && (( writeback_kb > 102400 )); then
        local wb_mb=$(( writeback_kb / 1024 ))
        _row "Writeback"  "!   ${wb_mb} MB writeback in progress — I/O under pressure"
    fi
    # After a kernel or glibc update, running processes still use old code.
    # needrestart is the standard tool for this on Arch-based systems.
    if command -v needrestart &>/dev/null; then
        local _nr_out _nr_kernel _nr_services
        _nr_out=$(needrestart -b 2>/dev/null || true)
        _nr_kernel=$(echo "$_nr_out" | awk -F: '/NEEDRESTART-KSTA/{gsub(/ /,"",$2); print $2}' || echo "")
        _nr_services=$(echo "$_nr_out" | grep -c 'NEEDRESTART-SVC' || true)
        # kernel status: 1=up-to-date, 2=ABI-compatible upgrade, 3=version change
        if [[ "$_nr_kernel" == "3" ]]; then
            _row "Needs restart" "!   kernel updated — reboot required to run new kernel"
            _rec "Kernel was updated — reboot to activate new kernel"
        elif [[ "$_nr_kernel" == "2" ]]; then
            _row "Needs restart" "--  kernel ABI upgrade pending — reboot recommended"
        fi
        if [[ "$_nr_services" =~ ^[0-9]+$ ]] && (( _nr_services > 0 )); then
            _row2 "--  ${_nr_services} service(s) using outdated libraries — run: needrestart"
        fi
    fi
    local _oops_count=0
    _oops_count=$(echo "$_kjournal" \
        | grep -cE 'BUG:|kernel BUG|Oops:|general protection fault|Kernel panic' \
        || echo "0")
    _oops_count=$(echo "${_oops_count:-0}" | tr -d '[:space:]')
    [[ "$_oops_count" =~ ^[0-9]+$ ]] || _oops_count=0
    if (( _oops_count > 0 )); then
        _row "Kernel oops"  "!!  ${_oops_count} BUG/Oops/panic event(s) this boot"
        _rec "${_oops_count} kernel fault(s) — run: journalctl -k -b 0 | grep -A5 'BUG:\|Oops:'"
    fi
    local _mce_count=0
    _mce_count=$(echo "$_kjournal" \
        | grep -iE \
            'mce:.*\[Hardware Error\]|machine check exception|Machine check events logged|'\
'EDAC [A-Z]+[0-9]+: [0-9]+ (UE|CE) |'\
'mce: Corrected MCE|mce: [0-9]+ me=|'\
'hardware error|uncorrected error' \
        | grep -ivE \
            'Giving out device|registered to driver|DRAM-Error-Check|Ver: [0-9]|'\
'F[0-9]+h.*Enabled|support.*MCE|CPU supports.*MCE bank|'\
'mce: This is not a hardware problem|test injection' \
        | wc -l || echo "0")
    _mce_count=$(echo "${_mce_count:-0}" | tr -d '[:space:]')
    [[ "$_mce_count" =~ ^[0-9]+$ ]] || _mce_count=0
    if (( _mce_count > 0 )); then
        _row "HW errors"  "!!  ${_mce_count} MCE/EDAC event(s) this boot — possible hardware fault"
        _rec "${_mce_count} hardware error(s) in kernel log — check: journalctl -k -b 0 | grep -i mce"
    fi
    local _entropy=""
    _entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ "$_entropy" =~ ^[0-9]+$ ]] && (( _entropy < 256 )); then
        _row "Entropy"    "!   ${_entropy} bits — low (may stall crypto on older kernels)"
    fi

    # Zombie processes — defunct children whose parent hasn't called wait().
    # A handful is normal (transient), but accumulation indicates stuck service parents.
    local _zombie_count=0
    _zombie_count=$(ps -eo stat= 2>/dev/null | grep -c '^Z' || echo "0")
    _zombie_count=$(echo "${_zombie_count:-0}" | tr -d '[:space:]')
    [[ "$_zombie_count" =~ ^[0-9]+$ ]] || _zombie_count=0
    if (( _zombie_count >= 10 )); then
        _row "Zombies"    "!   ${_zombie_count} zombie processes — check: ps -eo pid,ppid,stat,comm | awk '\$3~/^Z/'"
        _rec "${_zombie_count} zombie processes accumulating — identify stuck parent: ps -eo ppid,stat,comm | awk '\$2~/Z/{print \$1}' | sort | uniq -c | sort -rn"
    elif (( _zombie_count > 0 )); then
        _row "Zombies"    "--  ${_zombie_count} (transient — normal)"
    fi

    local tmp_type="" tmp_size=""
    tmp_type=$(findmnt -n -o FSTYPE /tmp 2>/dev/null | tr -d '[:space:]' || echo "")
    tmp_size=$(findmnt -n -o SIZE   /tmp 2>/dev/null | tr -d '[:space:]' || echo "")
    if [[ "$tmp_type" == "tmpfs" ]]; then
        _row "/tmp"         "OK  tmpfs${tmp_size:+  (${tmp_size})}"
    elif [[ -z "$tmp_type" ]]; then
        # /tmp not separately mounted — lives on root; fine but worth noting
        _row "/tmp"         "--  on root filesystem (not a tmpfs)"
    else
        _row "/tmp"         "--  ${tmp_type}${tmp_size:+  (${tmp_size})}  (not tmpfs)"
    fi
    if findmnt -n /home &>/dev/null; then
        local home_warn=() home_crit=() home_info=()
        for user_dir in /home/*/; do
            [[ -d "$user_dir" ]] || continue
            local uname; uname=$(basename "$user_dir")
            local used_mb=$(du -sm "$user_dir" 2>/dev/null | awk '{print $1}' || echo "")
            [[ "$used_mb" =~ ^[0-9]+$ ]] || continue
            (( used_mb == 0 )) && continue   # skip empty home dirs (e.g. builduser)
            local used_disp; used_disp=$(_mb_to_human "$used_mb")
            if (( used_mb > 51200 )); then      # > 50 GB
                home_crit+=("${uname}:${used_disp}")
            elif (( used_mb > 20480 )); then    # > 20 GB
                home_warn+=("${uname}:${used_disp}")
            else
                home_info+=("${uname}:${used_disp}")
            fi
        done
        if [[ ${#home_crit[@]} -gt 0 ]]; then
            _row "Home usage" "!   large: $(_join "${home_crit[@]}")"
            # No _rec — sizes are already shown inline; user can run: du -sh /home/* for detail
            if [[ ${#home_warn[@]} -gt 0 || ${#home_info[@]} -gt 0 ]]; then
                local _rest_str; _rest_str=$(IFS=' '; echo "${home_warn[*]} ${home_info[*]}" | xargs)
                _row2 "--  also: ${_rest_str}"
            fi
        elif [[ ${#home_warn[@]} -gt 0 ]]; then
            _row "Home usage" "--  $(_join "${home_warn[@]}")"
            if [[ ${#home_info[@]} -gt 0 ]]; then
                local _info_str; _info_str=$(IFS=' '; echo "${home_info[*]}")
                _row2 "--  also: ${_info_str}"
            fi
        elif [[ ${#home_info[@]} -gt 0 ]]; then
            local _info_str; _info_str=$(IFS=' '; echo "${home_info[*]}")
            _row "Home usage" "--  ${_info_str}"
        fi
    fi
    local j_err j_crit
    j_crit=$(journalctl -b 0 -p crit      --no-pager -q 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    j_err=$( journalctl -b 0 -p err..err  --no-pager -q 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    if [[ "$j_crit" =~ ^[0-9]+$ ]] && (( j_crit > 0 )); then
        _row "Journal"    "!!  ${j_crit} critical (p≤2), ${j_err} errors (p≤3) — journalctl -b 0 -p crit"
        _rec "${j_crit} critical journal message(s) this boot — run: journalctl -b 0 -p crit"
    elif [[ "$j_err" =~ ^[0-9]+$ ]] && (( j_err > 20 )); then _row "Journal"    "!   ${j_err} error(s) this boot"
    else
        _row "Journal"    "OK  ${j_err:-0} error(s) (normal range)"
    fi
    # journalctl --disk-usage: "Archived and active journals take up X.XG in the file system."
    if command -v journalctl &>/dev/null; then
        local j_disk_usage=""
        j_disk_usage=$(journalctl --disk-usage 2>/dev/null \
            | sed -n 's/.*take up \([^ ][^ ]*\) in.*/\1/p' | head -1 || echo "")
        local j_max_use=""
        j_max_use=$(grep -rshE '^SystemMaxUse=' \
            /usr/lib/systemd/journald.conf.d/ \
            /etc/systemd/journald.conf.d/ \
            /etc/systemd/journald.conf 2>/dev/null \
            | tail -1 | cut -d= -f2 | tr -d '[:space:]' || echo "")
        [[ -n "$j_disk_usage" ]] && _row2 "--  journal: ${j_disk_usage}${j_max_use:+  (limit: ${j_max_use})}"
    fi
    # /var/log is a persistent Btrfs subvolume (@log) — survives reboots.
    # Show size, journal limit context, and flag when app logs exceed the cap.
    if findmnt -n /var/log &>/dev/null; then
        # Check for stale journal dirs from old machine-IDs before size reporting
        local _stale_journal_dirs=()
        if [[ -d /var/log/journal ]]; then
            local _cur_mid; _cur_mid=$(cat /etc/machine-id 2>/dev/null | tr -d '[:space:]' || echo "")
            if [[ -n "$_cur_mid" ]]; then
                for _sjd in /var/log/journal/*/; do
                    [[ -d "$_sjd" ]] || continue
                    local _sjid; _sjid=$(basename "$_sjd")
                    [[ "$_sjid" != "$_cur_mid" ]] && _stale_journal_dirs+=("$_sjid")
                done
            fi
        fi
        if [[ ${#_stale_journal_dirs[@]} -gt 0 ]]; then
            local _stale_kb; _stale_kb=$(du -sk /var/log/journal/ 2>/dev/null | awk '{print $1}' || echo "0")
            # Subtract current dir size for accurate stale estimate
            local _cur_kb; _cur_kb=$(du -sk "/var/log/journal/${_cur_mid:-__none__}" 2>/dev/null | awk '{print $1}' || echo "0")
            local _stale_only_kb=$(( _stale_kb - _cur_kb ))
            _row "Journal"  "!   ${#_stale_journal_dirs[@]} stale machine-id dir(s) using ~$(_kb_to_human "$_stale_only_kb")"
            _rec "Stale journal dirs from old machine-IDs (~$(_kb_to_human "$_stale_only_kb")) — remove with: journalctl --vacuum-files=1"
        else
            local _cur_journal_mb; _cur_journal_mb=$(du -sm "/var/log/journal/${_cur_mid:-}" 2>/dev/null | awk '{print $1}' || echo "")
            [[ -n "$_cur_journal_mb" ]] && _row2 "--  ${_cur_journal_mb} MB (current machine)"
        fi

        local _log_used_mb _log_pool_avail_kb _log_pool_avail_mb
        _log_used_mb=$(du -sm /var/log 2>/dev/null | awk '{print $1}' || echo "")
        _log_pool_avail_kb=$(df -k /var/log 2>/dev/null | awk 'NR==2{print $4}' || echo "")
        if [[ "$_log_used_mb"       =~ ^[0-9]+$ && \
              "$_log_pool_avail_kb" =~ ^[0-9]+$ ]]; then
            _log_pool_avail_mb=$(( _log_pool_avail_kb / 1024 ))
            local _jmax=""
            _jmax=$(grep -rshE '^SystemMaxUse=' \
                /usr/lib/systemd/journald.conf.d/ \
                /etc/systemd/journald.conf.d/ \
                /etc/systemd/journald.conf 2>/dev/null \
                | tail -1 | cut -d= -f2 | tr -d '[:space:]' || echo "")
            local _jmax_str="${_jmax:+  journal limit: ${_jmax}}"
            # Parse journal limit to MB for comparison
            local _jmax_mb=0
            if [[ -n "$_jmax" ]]; then
                local _jmax_unit="${_jmax: -1}" _jmax_num="${_jmax%?}"
                case "$_jmax_unit" in
                    G|g) _jmax_mb=$(( _jmax_num * 1024 )) ;;
                    M|m) _jmax_mb=$_jmax_num ;;
                    K|k) _jmax_mb=$(( _jmax_num / 1024 )) ;;
                esac
            fi
            if (( _log_used_mb >= 2048 )); then
                _row "@log"   "!!  $(_mb_to_human "$_log_used_mb") used / $(_mb_to_human "$_log_pool_avail_mb") pool free — very large${_jmax_str}"
                _rec "@log is $(_mb_to_human "$_log_used_mb") — run: shani-health --clean-logs to free space"
            elif (( _log_used_mb >= 512 )); then
                _row "@log"   "!   $(_mb_to_human "$_log_used_mb") used / $(_mb_to_human "$_log_pool_avail_mb") pool free${_jmax_str}"
                if [[ -n "$_jmax" ]] && (( _log_used_mb > _jmax_mb + 100 )); then
                    _rec "@log is $(_mb_to_human "$_log_used_mb") (journal capped at ${_jmax}) — app logs filling /var/log, run: shani-health --clean-logs"
                else
                    _rec "@log is $(_mb_to_human "$_log_used_mb") — run: shani-health --clean-logs to free space"
                fi
            else
                _row "@log"   "--  $(_mb_to_human "$_log_used_mb") used / $(_mb_to_human "$_log_pool_avail_mb") pool free${_jmax_str}"
            fi
        fi
    else
        _row "@log"   "!!  /var/log not mounted — @log subvolume missing or fstab broken"
        _rec "@log subvolume not mounted — check fstab entry for /var/log"
    fi

}

# Init shared by all top-level report functions.
_report_init() {
    _recs_reset
    _esp_mount
    _report_preamble
}
security_report() {
    _report_init

    _focused_header "ShaniOS Security Report"

    _section_secureboot         "$booted" uki_booted_bad "$hibernate_stale"
    _section_kernel_security    "$sb_active"
    _section_encryption
    _section_tpm2
    _section_security_services
    _section_security_audit
    _section_krb5
    _section_users
    _section_groups

    _recs_print "No security issues found"
    _esp_umount
}

system_info() {
    _report_init

    _focused_header "ShaniOS System Status"
    _section_os_slots           "$booted"
    _section_boot_health
    _section_boot_entries
    _section_deployment
    _section_update_tools
    _section_data_state
    _section_immutability
    _section_secureboot         "$booted" uki_booted_bad "$hibernate_stale"
    _section_kernel_security    "$sb_active"
    _section_encryption
    _section_tpm2
    _section_security_services
    _section_security_audit
    _section_users
    _section_groups
    _section_hardware
    _section_disk               "$booted" hibernate_stale "$uki_booted_bad"
    _section_battery
    _section_storage
    _section_firmware
    _section_performance
    _section_network
    _section_servers
    _section_audio_display
    _section_printing
    _section_package_managers
    _section_containers
    _section_virtualization
    _section_monitoring
    _section_runtime_health
    _section_units
    _section_coredump
    _section_system_health

    _recs_print "All checks passed — no issues found"
    _esp_umount
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
    local _esp_mounted=0   # shared across both ESP access windows in this function

    # UKI signatures
    echo ""
    _log "Checking UKI signatures..."
    local mok_crt="/etc/secureboot/keys/MOK.crt"
    _esp_mount

    if [[ ! -f "$mok_crt" ]]; then _log_warn "MOK cert not found at ${mok_crt} — skipping UKI verification"
    else
        for slot in blue green; do
            local uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${slot}.efi"
            if [[ ! -f "$uki" ]]; then
                _log_err "UKI missing: ${uki}"; errors=$(( errors + 1 ))
            elif sbverify --cert "$mok_crt" "$uki" &>/dev/null 2>&1; then _log_ok "UKI valid:   @${slot}"
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
                _log_warn "@${slot} not found on disk — skipping"
                continue
            fi
            if btrfs scrub start -Br "$subvol" &>/dev/null 2>&1; then
                local sc_out=$(btrfs scrub status "$subvol" 2>/dev/null || true)
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
    _esp_mount
    local loader_conf="$ESP/loader/loader.conf"
    if [[ -f "$loader_conf" ]]; then
        local def_entry resolved
        def_entry=$(grep '^default' "$loader_conf" | awk '{print $2}' || echo "")
        # shellcheck disable=SC2086
        resolved=$(ls "$ESP/loader/entries/"${def_entry} 2>/dev/null | head -1 || echo "")
        if [[ -n "$resolved" ]]; then _log_ok "Boot entry OK: '${def_entry}' -> $(basename "$resolved")"
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
    if [[ "$var_fstype" == "tmpfs" ]]; then _log_ok "/var: tmpfs (volatile)"
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
        if findmnt -n "$mp" &>/dev/null; then _log_ok "@${sv}: mounted at ${mp}"
        else
            _log_warn "@${sv}: not mounted at ${mp} (may not be installed)"
        fi
    done

    echo ""
    if (( errors == 0 )); then _log_ok "Verification passed — no integrity issues"
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

    local since_args=()
    [[ -n "$since" ]] && since_args=(--since "$since") || since_args=(-b 0)
    _head "Journal Messages (this boot)"
    local j_crit j_err j_warn
    j_crit=$(journalctl -b 0 -p crit           --no-pager -q 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    j_err=$( journalctl -b 0 -p err..err       --no-pager -q 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    j_warn=$(journalctl -b 0 -p warning..warning --no-pager -q 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    if [[ "${j_crit:-0}" -gt 0 ]]; then _row "Critical"  "!!  ${j_crit} message(s)"
    else
        _row "Critical"  "OK  none"
    fi
    if [[ "${j_err:-0}" -gt 0 ]]; then _row "Errors"    "!   ${j_err} message(s)"; else _row "Errors"    "OK  none"; fi
    if [[ "${j_warn:-0}" -gt 0 ]]; then _row "Warnings"  "--  ${j_warn} message(s)"
    else
        _row "Warnings"  "OK  none"
    fi

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
    _head "AppArmor Denials"
    # Cache kernel journal once — reused for AA and OOM sections below
    local _jklog
    _jklog=$(journalctl -k "${since_args[@]}" --no-pager -q 2>/dev/null || true)
    local aa_count=$(echo "$_jklog" | grep -c 'apparmor.*DENIED' || echo "0")
    if [[ "$aa_count" =~ ^[0-9]+$ ]] && (( aa_count > 0 )); then
        _row "Denials"  "!   ${aa_count} total"
        echo ""
        echo "$_jklog" \
            | grep 'apparmor.*DENIED' \
            | grep -oP 'profile="[^"]+"|comm="[^"]+"|name="[^"]+"' \
            | sort | uniq -c | sort -rn \
            | sed 's/^/    /' | head -20 || true
        echo ""
        printf "    ${_C_DIM}Full log: journalctl -k | grep apparmor.*DENIED${_C_RESET}\n"
    else
        _row "Denials"  "OK  none"
    fi
    _head "OOM Events"
    local oom_count oom_oomd_count
    oom_count=$(echo "$_jklog" \
        | grep -c 'Out of memory\|oom_kill_process\|Killed process' 2>/dev/null || echo "0")
    oom_count=$(echo "${oom_count:-0}" | tr -d '[:space:]')
    [[ "$oom_count" =~ ^[0-9]+$ ]] || oom_count=0
    oom_oomd_count=$(journalctl "${since_args[@]}" --no-pager -q -u systemd-oomd 2>/dev/null \
        | grep -c 'Killed\|killed' 2>/dev/null || echo "0")
    oom_oomd_count=$(echo "${oom_oomd_count:-0}" | tr -d '[:space:]')
    [[ "$oom_oomd_count" =~ ^[0-9]+$ ]] || oom_oomd_count=0
    local oom_total_j=$(( oom_count + oom_oomd_count ))
    if (( oom_total_j > 0 )); then
        local _joom_detail=""
        (( oom_count       > 0 )) && _joom_detail+=" kernel:${oom_count}"
        (( oom_oomd_count  > 0 )) && _joom_detail+=" oomd:${oom_oomd_count}"
        _row "OOM kills" "!   ${oom_total_j} event(s) (${_joom_detail# })"
        echo "$_jklog" \
            | grep 'Out of memory\|oom_kill_process\|Killed process' \
            | tail -5 | sed 's/^/    /' || true
    else
        _row "OOM kills" "OK  none"
    fi
    _head "Failed Units"
    local failed_now=()
    mapfile -t failed_now < <(
        systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null \
            | awk '{print $2}' | grep -v '^$' | grep '\.' || true)
    if [[ ${#failed_now[@]} -eq 0 ]]; then _row "Units"  "OK  no failed units"
    else
        local _fail_str; _fail_str=$(IFS=' '; echo "${failed_now[*]}")
        _row "Units"  "!!  ${#failed_now[@]} failed: ${_fail_str}"
        for u in "${failed_now[@]}"; do
            # Show the most recent error line from each unit
            local _uerr
            _uerr=$(journalctl -u "$u" "${since_args[@]}" --no-pager -q -n 1 2>/dev/null | tail -1 || true)
            [[ -n "$_uerr" ]] && _row2 "!   ${u}: ${_uerr:0:72}"
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
        elif [[ "$ev" == *"  START    "* ]]; then ev="${ev//  START    /  ${_C_CYAN}>${_C_RESET}  }"
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
    local created; created=$(echo "$snap_info" \
        | awk -F'\t' '/Creation time:/{gsub(/^[[:space:]]+/,"",$2); print $2}' \
        | head -1 || true)
    local age_str=""
    local parent_uuid; parent_uuid=$(echo "$snap_info" \
        | awk -F'\t' '/Parent UUID:/{gsub(/^[[:space:]]+/,"",$2); print $2}' \
        | head -1 || true)
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
        else
            _row "Quotas"    "OK  consistent"
        fi
    fi

    # Scrub status
    local scrub_st scrub_res
    scrub_st=$(btrfs scrub status / 2>/dev/null || true)
    scrub_res=$(echo "$scrub_st" | awk '/Status:/{print $2}' | head -1 || echo "")
    local scrub_timer; scrub_timer=$(systemctl is-enabled btrfs-scrub.timer 2>/dev/null || echo "disabled")
    if [[ "$scrub_timer" == "enabled" || "$scrub_timer" == "static" ]]; then _row "Scrub tmr"  "OK  enabled"
    else
        _row "Scrub tmr"  "!!  btrfs-scrub.timer not enabled"
        _rec "btrfs-scrub.timer not enabled — run: systemctl enable --now btrfs-scrub.timer"
    fi
    case "$scrub_res" in
        finished)
            local re ce co
            re=$(echo "$scrub_st" | awk '/read_errors:/{print $2}'      | head -1 || echo "0")
            ce=$(echo "$scrub_st" | awk '/csum_errors:/{print $2}'      | head -1 || echo "0")
            co=$(echo "$scrub_st" | awk '/corrected_errors:/{print $2}' | head -1 || echo "0")
            if [[ "${re:-0}" != "0" || "${ce:-0}" != "0" || "${co:-0}" != "0" ]]; then
                _row "Scrub"    "!!  errors: read=${re} csum=${ce} corrected=${co}"
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
        local _t_act=0; systemctl is-active --quiet "btrfs-${name}.timer" 2>/dev/null && _t_act=1
        local _t_st; _t_st=$(systemctl is-enabled "btrfs-${name}.timer" 2>/dev/null || echo "disabled")
        if (( _t_act )) || [[ "$_t_st" == "enabled" || "$_t_st" == "static" ]]; then
            t_ok+=("$name")
        else
            t_bad+=("$name")
        fi
    done
    local t_ok_str; t_ok_str=$(_join "${t_ok[@]}")
    local t_bad_str; t_bad_str=$(_join "${t_bad[@]}")
    if   [[ ${#t_bad[@]} -eq 0 ]]; then _row "Maint tmrs" "OK  enabled: ${t_ok_str}"
    elif [[ ${#t_ok[@]}  -eq 0 ]]; then _row "Maint tmrs" "!!  all not enabled: ${t_bad_str}"
    else                                 _row "Maint tmrs" "!   enabled: ${t_ok_str}  |  not enabled: ${t_bad_str}"
    fi

    # Bees + subvol quick summary (shared helpers)
    _stor_check_bees
    _stor_check_device_errors "$STOR_MNT"
    echo ""
    printf "  ${_C_DIM}%s${_C_RESET}\n" "── Deep Analysis ──────────────────────────────────────"
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
    _head "Application Storage"

    # Flatpak
    if command -v flatpak &>/dev/null; then
        local fp_mb; fp_mb=$(du -sm /var/lib/flatpak 2>/dev/null | awk '{print $1}' || echo "")
        local fp_apps; fp_apps=$(timeout 5 flatpak list --app --columns=application 2>/dev/null | wc -l || echo "?")
        local fp_rt;   fp_rt=$(timeout 5 flatpak list --runtime --columns=application 2>/dev/null | wc -l || echo "?")
        if [[ "$fp_mb" =~ ^[0-9]+$ ]]; then
            if (( fp_mb > 20480 )); then
                _row "Flatpak"  "!   $(_mb_to_human "$fp_mb")  (${fp_apps} apps, ${fp_rt} runtimes) — run: flatpak uninstall --unused"
                _rec "Flatpak storage is $(_mb_to_human "$fp_mb") — free space: flatpak uninstall --unused"
            else
                _row "Flatpak"  "--  $(_mb_to_human "$fp_mb")  (${fp_apps} apps, ${fp_rt} runtimes)"
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
                _row "Snap"     "!   $(_mb_to_human "$snap_mb") snaps${snap_str} — run: snap set system refresh.retain=2"
                _rec "Snap storage is $(_mb_to_human "$snap_mb") — limit old revisions: snap set system refresh.retain=2"
            else
                _row "Snap"     "--  $(_mb_to_human "$snap_mb") snaps${snap_str}${snap_total:+  ($(_mb_to_human "$snap_total") total)}"
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
                _row "Nix"      "!   $(_mb_to_human "$nix_mb")${nix_str} — run: nix-collect-garbage -d"
                _rec "Nix store is $(_mb_to_human "$nix_mb") — free space: nix-collect-garbage -d"
            else
                _row "Nix"      "--  $(_mb_to_human "$nix_mb")${nix_str}"
            fi
        fi
    fi

    # Podman (system + rootless)
    if command -v podman &>/dev/null; then
        local pod_sys; pod_sys=$(du -sm /var/lib/containers/storage/overlay 2>/dev/null | awk '{print $1}' || echo "")
        [[ "$pod_sys" =~ ^[0-9]+$ ]] && _row "Podman sys" "--  $(_mb_to_human "$pod_sys") system image storage"
        local _pod_user="$_CALLER_USER"
        if [[ -n "$_pod_user" ]]; then
            local _pod_home; _pod_home=$(getent passwd "$_pod_user" 2>/dev/null | cut -d: -f6 || echo "")
            if [[ -n "$_pod_home" ]]; then
                local pod_usr; pod_usr=$(du -sm "${_pod_home}/.local/share/containers/storage/overlay" \
                    2>/dev/null | awk '{print $1}' || echo "")
                [[ "$pod_usr" =~ ^[0-9]+$ ]] && (( pod_usr > 0 )) && \
                    _row "Podman usr" "--  $(_mb_to_human "$pod_usr") ${_pod_user} rootless storage"
            fi
        fi
    fi

    # LXD
    if { findmnt -n /var/lib/lxd &>/dev/null || [[ -d /data/varlib/lxd ]]; }; then
        local lxd_mb; lxd_mb=$(du -sm /var/lib/lxd /data/varlib/lxd 2>/dev/null | awk '{s+=$1} END{print s}' || echo "")
        [[ "$lxd_mb" =~ ^[0-9]+$ ]] && _row "LXD"        "--  $(_mb_to_human "$lxd_mb")"
    fi

    # Waydroid
    if findmnt -n /var/lib/waydroid &>/dev/null; then
        local wd_mb; wd_mb=$(du -sm /var/lib/waydroid 2>/dev/null | awk '{print $1}' || echo "")
        [[ "$wd_mb" =~ ^[0-9]+$ ]] && _row "Waydroid"    "--  $(_mb_to_human "$wd_mb")"
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
                        _row "Apptainer"  "!   $(_mb_to_human "$apt_mb") cache — run: apptainer cache clean"
                        _rec "Apptainer cache is $(_mb_to_human "$apt_mb") — free space: apptainer cache clean"
                    else
                        _row "Apptainer"  "--  $(_mb_to_human "$apt_mb") cache"
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
                _row "Home/${uname}" "--  $(_mb_to_human "$used_mb")"
        done
    fi
    _head "Snapshot Summary"
    local snap_count; snap_count=$(btrfs subvolume list -s "$STOR_MNT" 2>/dev/null | wc -l || echo "0")
    _row "Snapshots"  "--  ${snap_count} total"

    # List snapshots with their parent and creation date, newest first
    btrfs subvolume list -s --sort=-rootid "$STOR_MNT" 2>/dev/null \
        | awk '{printf "    %-42s  %s %s\n", $NF, $(NF-3), $(NF-2)}' \
        | head -20 || true
    _head "Reclaim Hints"
    local hints=0

    # duperemove hint when cross-slot savings are likely
    if command -v duperemove &>/dev/null; then
        hints=$(( hints + 1 ))
        _row "Dedup"      "--  duperemove available — run: shani-deploy --optimize"
        _row2 "--  deduplicates @blue/@green and backup snapshots across slots"
    else
        hints=$(( hints + 1 ))
        _row "Dedup"      "--  duperemove not installed — cross-slot deduplication unavailable"
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
    echo ""
    [[ ${#_RECS[@]} -gt 0 ]] && _recs_print
    echo ""
}

###############################################################################
### export_logs                                                              ###
###############################################################################

###############################################################################
### Focused reports                                                          ###
###############################################################################

# Resolves booted slot, hibernate staleness, and Secure Boot state.
_report_preamble() {
    declare -g booted uki_booted_bad hibernate_stale sb_active
    booted=$(_get_booted_subvol)
    uki_booted_bad="0"
    hibernate_stale="0"
    sb_active="no"

    local swapfile; swapfile=$(_find_swapfile)
    if [[ -n "$swapfile" ]] && command -v btrfs &>/dev/null; then
        local a_off; a_off=$(_swapfile_offset "$swapfile")
        local c_off; c_off=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2 || echo "")
        [[ -n "$a_off" && -n "$c_off" && "$a_off" != "$c_off" ]] && hibernate_stale="1"
    fi

    if [[ -d /sys/firmware/efi ]]; then
        local _sb_tmp; _sb_tmp=$(mokutil --sb-state 2>/dev/null || echo "")
        if [[ "$_sb_tmp" == *"SecureBoot enabled"* ]] && \
           ! echo "$_sb_tmp" | grep -q "Secure Boot validation is disabled"; then
            sb_active="yes"
        fi
    fi
}

_focused_header() {
    local title="$1"
    echo ""
    printf "  ${_C_BOLD}┌──────────────────────────────────────────────┐${_C_RESET}\n"
    printf "  ${_C_BOLD}│  %-44s│${_C_RESET}\n" "$title"
    local _h_host; _h_host=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null | tr -d '[:space:]' || echo "unknown")
    printf "  ${_C_BOLD}│  ${_C_DIM}%-44s${_C_BOLD}│${_C_RESET}\n" "$(date '+%Y-%m-%d %H:%M')  ${_h_host}"
    printf "  ${_C_BOLD}└──────────────────────────────────────────────┘${_C_RESET}\n"
}

_focused_summary() { _recs_print "No issues found"; }

boot_report() {
    _report_init

    _focused_header "ShaniOS Boot Report"

    _section_os_slots          "$booted"
    _section_boot_health
    _section_boot_entries
    _section_deployment
    _section_update_tools
    _section_data_state
    _section_secureboot        "$booted" uki_booted_bad "$hibernate_stale"

    _focused_summary
    _esp_umount
}

network_report() {
    _recs_reset
    _focused_header "ShaniOS Network Report"

    _section_network
    _section_servers

    _focused_summary
}

hardware_report() {
    _report_init

    _focused_header "ShaniOS Hardware Report"

    _section_hardware
    _section_disk              "$booted" hibernate_stale "$uki_booted_bad"
    _section_battery
    _section_storage
    _section_firmware

    _focused_summary
    _esp_umount
}

packages_report() {
    _recs_reset
    _focused_header "ShaniOS Package Report"

    _section_package_managers
    _section_containers
    _section_virtualization
    _section_monitoring

    _focused_summary
}

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
        for _ef_label_cmd in \
            "/proc/cmdline|cat /proc/cmdline" \
            "uname -a|uname -a" \
            "/etc/shani-version|cat /etc/shani-version" \
            "/etc/shani-profile|cat /etc/shani-profile" \
            "/etc/shani-channel|cat $CHANNEL_FILE || echo (not set)" \
            "/data/current-slot|cat $DATA_CURRENT_SLOT || echo (missing)" \
            "/data/previous-slot|cat $DATA_PREV_SLOT || echo (missing)"; do
            local _ef_lbl="${_ef_label_cmd%%|*}" _ef_cmd="${_ef_label_cmd#*|}"
            echo "=== ${_ef_lbl} ==="; eval "$_ef_cmd" 2>/dev/null; echo ""
        done
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
        echo "=== findmnt ==="; findmnt 2>/dev/null || true; echo ""
        echo "=== systemctl --failed ==="; systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null || true
    } > "$staging/system-state.txt" 2>/dev/null
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
### clean_logs — clean old app logs from @log (/var/log)                   ###
###############################################################################

clean_logs() {
    local keep_days="${1:-30}"
    local log_dir="/var/log"

    _log_section "Log Cleanup  (keep last ${keep_days} days)"

    if ! findmnt -n "$log_dir" &>/dev/null; then
        _log_err "@log subvolume not mounted at ${log_dir}"
        return 1
    fi

    local before_mb; before_mb=$(du -sm "$log_dir" 2>/dev/null | awk '{print $1}' || echo "?")
    local freed=0 errors=0
    _cl_remove() {
        local path="$1"
        local size_kb; size_kb=$(du -sk "$path" 2>/dev/null | awk '{print $1}' || echo "0")
        if rm -f "$path" 2>/dev/null; then
            freed=$(( freed + size_kb ))
            _log_ok "Removed: ${path}  ($(_kb_to_human "$size_kb"))"
        else
            _log_err "Could not remove: ${path}"
            errors=$(( errors + 1 ))
        fi
    }

    _cl_truncate() {
        local path="$1" reason="${2:-}"
        local size_kb; size_kb=$(du -sk "$path" 2>/dev/null | awk '{print $1}' || echo "0")
        if : > "$path" 2>/dev/null; then
            freed=$(( freed + size_kb ))
            _log_ok "Truncated: ${path}  ($(_kb_to_human "$size_kb")${reason:+  — ${reason}})"
        else
            _log_err "Could not truncate: ${path}"
            errors=$(( errors + 1 ))
        fi
    }

    _cl_trim() {
        local path="$1" lines="$2"
        local _sz; _sz=$(du -sk "$path" 2>/dev/null | awk '{print $1}' || echo "0")
        local _tmp; _tmp=$(mktemp)
        tail -"$lines" "$path" > "$_tmp" 2>/dev/null && mv "$_tmp" "$path" 2>/dev/null             && { freed=$(( freed + _sz )); _log_ok "Trimmed: ${path}  (kept last ${lines} lines)"; }             || { rm -f "$_tmp" 2>/dev/null; _log_err "Could not trim ${path}"; errors=$(( errors + 1 )); }
    }

    _kb_to_human() {
        local kb="$1"
        if (( kb >= 1048576 )); then
            printf "%d GB" $(( kb / 1048576 ))
        elif (( kb >= 1024 )); then printf "%d MB" $(( kb / 1024 ))
        else
            printf "%d KB" "$kb"
        fi
    }
    if [[ -d "${log_dir}/journal" ]]; then
        local _cur_mid; _cur_mid=$(cat /etc/machine-id 2>/dev/null | tr -d '[:space:]' || echo "")
        local _stale_count=0
        if [[ -n "$_cur_mid" ]]; then
            for _jdir in "${log_dir}/journal"/*/; do
                [[ -d "$_jdir" ]] || continue
                local _jid; _jid=$(basename "$_jdir")
                if [[ "$_jid" != "$_cur_mid" ]]; then
                    local _jdir_kb; _jdir_kb=$(du -sk "$_jdir" 2>/dev/null | awk '{print $1}' || echo "0")
                    if rm -rf "$_jdir" 2>/dev/null; then
                        freed=$(( freed + _jdir_kb ))
                        _log_ok "Removed stale journal dir: ${_jid}  ($(_kb_to_human "$_jdir_kb"))"
                        _stale_count=$(( _stale_count + 1 ))
                    else
                        _log_err "Could not remove: ${_jdir}"
                        errors=$(( errors + 1 ))
                    fi
                fi
            done
        fi
        (( _stale_count == 0 )) && _log "  No stale journal directories found"

        # Now vacuum the current machine's journal to its configured cap
        if command -v journalctl &>/dev/null; then
            local _jmax=""
            _jmax=$(grep -rshE '^SystemMaxUse=' \
                /etc/systemd/journald.conf \
                /etc/systemd/journald.conf.d/ \
                /usr/lib/systemd/journald.conf.d/ \
                2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]' || echo "")
            local _journal_mb; _journal_mb=$(du -sm "${log_dir}/journal" 2>/dev/null | awk '{print $1}' || echo "0")
            if [[ -n "$_jmax" ]]; then
                _log "Vacuuming journal to configured cap (${_jmax})..."
                journalctl --vacuum-size="$_jmax" 2>/dev/null || true
            else
                _log "Vacuuming journal entries older than ${keep_days} days..."
                journalctl --vacuum-time="${keep_days}d" 2>/dev/null || true
            fi
            local _journal_after_mb; _journal_after_mb=$(du -sm "${log_dir}/journal" 2>/dev/null | awk '{print $1}' || echo "0")
            local _j_freed=$(( (_journal_mb - _journal_after_mb) * 1024 ))
            (( _j_freed > 0 )) && freed=$(( freed + _j_freed )) \
                && _log_ok "Journal vacuumed  (${_journal_after_mb} MB remaining)"
        fi
    fi
    # Safe to delete: logrotate-produced .gz, .bz2, .xz, .zst, and numbered copies.
    # Never touch: current (unnumbered, uncompressed) active log files.
    _log "Scanning for rotated log archives older than ${keep_days} days..."
    local _rotated_count=0
    while IFS= read -r f; do
        _cl_remove "$f"
        _rotated_count=$(( _rotated_count + 1 ))

    done < <(find "$log_dir" \
        \( -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -o -name "*.zst" \
           -o -name "*.[0-9]" -o -name "*.[0-9][0-9]" \) \
        -not -path "*/journal/*" \
        -mtime +"$keep_days" \
        -type f 2>/dev/null | sort || true)
    (( _rotated_count == 0 )) && _log "  No rotated archives older than ${keep_days} days"
    if [[ -d "${log_dir}/old" ]]; then
        while IFS= read -r f; do
            _cl_remove "$f"
        done < <(find "${log_dir}/old" -type f -mtime +"$keep_days" 2>/dev/null | sort || true)
    fi
    # Waydroid container logs can grow to hundreds of MB with verbose output.
    for _wdir in "${log_dir}/waydroid" "/var/lib/waydroid/data/media/0/Android/data"; do
        if [[ -d "$_wdir" ]]; then
            while IFS= read -r f; do
                _cl_remove "$f"
            done < <(find "$_wdir" -name "*.log" -o -name "*.log.*" \
                -type f -mtime +"$keep_days" 2>/dev/null | sort || true)
        fi
    done
    # Never touch audit.log (current). Only delete audit.log.N archives.
    if [[ -d "${log_dir}/audit" ]]; then
        while IFS= read -r f; do
            [[ "$f" == */audit.log ]] && continue  # never delete the current log
            _cl_remove "$f"
        done < <(find "${log_dir}/audit" -name "audit.log.*" \
            -type f -mtime +"$keep_days" 2>/dev/null | sort || true)
    fi
    # access_log records every print job. error_log is kept (may contain issues).
    for _cf in "${log_dir}/cups/access_log" "${log_dir}/cups/page_log"; do
        [[ -f "$_cf" ]] && (( $(du -sk "$_cf" 2>/dev/null | awk '{print $1}') > 1024 )) && _cl_trim "$_cf" 1000
    done
    # These are binary login records. lastb/last read them.
    # Safe to truncate: old records have no operational use.
    for _bf in "${log_dir}/btmp" "${log_dir}/wtmp"; do
        if [[ -f "$_bf" ]]; then
            local _bf_kb; _bf_kb=$(du -sk "$_bf" 2>/dev/null | awk '{print $1}' || echo "0")
            if (( _bf_kb > 10240 )); then  # only truncate if >10 MB
                _cl_truncate "$_bf" "binary login records"
            fi
        fi
    done
    for _sl in "${log_dir}/rkhunter.log" "${log_dir}/lynis.log" \
                "${log_dir}/lynis-report.dat"; do
        if [[ -f "$_sl" ]]; then
            local _sl_age; _sl_age=$(( ( $(date +%s) - $(stat -c %Y "$_sl" 2>/dev/null || echo 0) ) / 86400 ))
            (( _sl_age > keep_days )) && _cl_remove "$_sl"
        fi
    done
    # Trim to last 5000 lines — keeps recent install history without unbounded growth.
    # Trim to last 5000 lines.
    [[ -f "$DEPLOY_LOG" ]] && (( $(du -sk "$DEPLOY_LOG" 2>/dev/null | awk '{print $1}') > 2048 )) && _cl_trim "$DEPLOY_LOG" 5000
    # sysstat writes daily saNN files. Keep only within keep_days; older = stale stats.
    if [[ -d "${log_dir}/sa" ]]; then
        while IFS= read -r f; do
            _cl_remove "$f"
        done < <(find "${log_dir}/sa" -maxdepth 1 -type f -mtime +"$keep_days" 2>/dev/null | sort || true)
    fi
    # fail2ban.log — fail2ban not installed; log was left behind
    if [[ -f "${log_dir}/fail2ban.log" ]] && \
       ! command -v fail2ban-client &>/dev/null && \
       ! systemctl cat fail2ban &>/dev/null 2>&1; then
        _cl_remove "${log_dir}/fail2ban.log"
    fi
    # apcupsd.events — apcupsd not configured; empty or stale event file
    if [[ -f "${log_dir}/apcupsd.events" ]] && \
       ! systemctl is-active --quiet apcupsd 2>/dev/null; then
        local _apc_kb; _apc_kb=$(du -sk "${log_dir}/apcupsd.events" 2>/dev/null | awk '{print $1}' || echo "0")
        (( _apc_kb > 0 )) && _cl_remove "${log_dir}/apcupsd.events"
    fi
    [[ -f "${log_dir}/passim/audit.log" ]] && (( $(du -sk "${log_dir}/passim/audit.log" 2>/dev/null | awk '{print $1}') > 1024 )) && _cl_trim "${log_dir}/passim/audit.log" 1000
    # private/ is root-only; access via the known log path if readable
    local _dnscrypt_log="${log_dir}/private/dnscrypt-proxy/dnscrypt-proxy.log"
    [[ -f "$_dnscrypt_log" ]] && (( $(du -sk "$_dnscrypt_log" 2>/dev/null | awk '{print $1}') > 2048 )) && _cl_trim "$_dnscrypt_log" 5000
    for _svclog_dir in "${log_dir}/caddy" "${log_dir}/ipp-usb" "${log_dir}/firewalld"; do
        [[ -d "$_svclog_dir" ]] || continue
        while IFS= read -r f; do
            _cl_remove "$f"
        done < <(find "$_svclog_dir" \
            \( -name "*.gz" -o -name "*.bz2" -o -name "*.xz" -o -name "*.zst" \
               -o -name "*.[0-9]" -o -name "*.[0-9][0-9]" \) \
            -type f -mtime +"$keep_days" 2>/dev/null | sort || true)
    done

    local after_mb; after_mb=$(du -sm "$log_dir" 2>/dev/null | awk '{print $1}' || echo "?")
    echo ""
    if [[ "$before_mb" =~ ^[0-9]+$ && "$after_mb" =~ ^[0-9]+$ ]]; then
        local net_freed=$(( before_mb - after_mb ))
        _log "Before: ${before_mb} MB  →  After: ${after_mb} MB  (freed: ${net_freed} MB)"
    fi
    (( errors > 0 )) && _log_warn "${errors} file(s) could not be cleaned"
    _log "Run 'shani-health' to verify @log size"
}

###

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

  ShaniOS system health, security, and diagnostics.

Options:
  (no args)               Full system status report
  -i, --info              Alias for full system status report
  --clean-logs [DAYS]     Clean old app logs from /var/log (default: keep last 30 days)
  --verify                Deep integrity check: UKI sigs, Btrfs scrub, immutability
  --security              Security report: boot chain, encryption, services, users, Kerberos
  --journal [level]       Show journal entries (level: crit, err, warning — default: crit)
  --since TIME            Limit journal output to entries since TIME (e.g. -1h, -2d, '2026-01-01')
  -s, --storage-info      Btrfs storage analysis: subvolume sizes, compression, snapshots
  --history [N]           Last N deploy/rollback events from log (default: 50)
  --clear-boot-failure    Clear a stale boot failure marker (when current boot is healthy)
  --boot                  Boot report: slots, entries, deployment, UKI, network
  --network               Network report: NM, DNS, VPN, firewall, SSH, servers
  --hardware              Hardware report: CPU, disk, SMART, temps, battery, firmware
  --packages              Package report: flatpak, snap, nix, containers, virtualisation
  --export-logs [DIR]     Bundle logs + state for bug reports (default: /tmp)
  -v, --verbose           Verbose/debug output
  -h, --help              Show this help

Examples:
  shani-health                        Full status report
  shani-health --clean-logs           Clean app logs older than 30 days
  shani-health --clean-logs 7         Clean app logs older than 7 days
  shani-health --security             Security report
  shani-health --boot                 Boot chain and deployment status
  shani-health --network              Network and connectivity status
  shani-health --hardware             Hardware health and disk status
  shani-health --packages             Package manager and container status
  shani-health --journal              Show critical journal messages
  shani-health --journal err          Show errors and above
  shani-health --journal err -1h      Show errors in the last hour
  shani-health --since -2d --journal warning  Warnings in the last 2 days
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
    local CLEAN_LOGS_DAYS=30

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)          usage; exit 0 ;;
            -i|--info)          MODE="info";         shift ;;
            --clean-logs)
                MODE="clean-logs"
                if [[ -n "${2:-}" && "${2:-}" =~ ^[0-9]+$ ]]; then CLEAN_LOGS_DAYS="$2"; shift 2
                else
                    shift
                fi ;;
            --verify)           MODE="verify";       shift ;;
            -s|--storage-info)  MODE="storage-info"; shift ;;
            --security)         MODE="security";     shift ;;
            --journal)
                MODE="journal"
                if [[ -n "${2:-}" && "${2:-}" =~ ^(crit|err|warning)$ ]]; then
                    JOURNAL_LEVEL="$2"; shift 2
                    # optional: --journal err -1h  (since as third arg)
                    [[ -n "${2:-}" && "${2:-}" =~ ^- && "${2:-}" != --* ]] && JOURNAL_SINCE="$2"; shift
                elif [[ -n "${2:-}" && "${2:-}" != -* ]]; then JOURNAL_SINCE="$2"; shift 2
                else
                    shift
                fi ;;
            --since)
                if [[ -n "${2:-}" ]]; then JOURNAL_SINCE="$2"; shift 2
                else
                    _log_warn "--since requires an argument (e.g. -1h, -2d, '2026-01-01')"; shift
                fi ;;
            --history)
                MODE="history"
                if [[ -n "${2:-}" && "${2:-}" =~ ^[0-9]+$ ]]; then HISTORY_LINES="$2"; shift 2
                else
                    shift
                fi ;;
            --boot)             MODE="boot";         shift ;;
            --network)          MODE="network";      shift ;;
            --hardware)         MODE="hardware";     shift ;;
            --packages)         MODE="packages";     shift ;;
            --clear-boot-failure)  MODE="clear-boot-failure"; shift ;;
            --export-logs)
                MODE="export-logs"
                if [[ -n "${2:-}" && "${2:-}" != -* ]]; then EXPORT_DIR="$2"; shift 2
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
        clean-logs)          clean_logs "$CLEAN_LOGS_DAYS" ;;
        verify)              verify_system; exit $? ;;
        security)            security_report ;;
        journal)             show_journal "$JOURNAL_LEVEL" "$JOURNAL_SINCE" ;;
        history)             show_history "$HISTORY_LINES" ;;
        storage-info)        analyze_storage ;;
        boot)                boot_report ;;
        network)             network_report ;;
        hardware)            hardware_report ;;
        packages)            packages_report ;;
        clear-boot-failure)  clear_boot_failure ;;
        export-logs)         export_logs "$EXPORT_DIR" ;;
    esac
}

main "$@"
