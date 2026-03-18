#!/bin/bash
# shani-update — ShaniOS update manager
#
# Handles fallback-boot detection, candidate-boot testing, rollback, and
# OS update checking/installation. Replaces both shani-update and startup-check.
#
# Usage:
#   shani-update [--startup]      Run at login: fallback check → candidate check → update check
#   shani-update                  Interactive: candidate check → update check
#   shani-update --rollback       Roll back the inactive slot immediately
#   shani-update --force          Force deploy even if version matches
#   shani-update --channel CHAN   Update channel: stable|latest (default: stable)
#   shani-update --verbose        Verbose output from shani-deploy
#   shani-update --dry-run        Simulate without changes
#   shani-update --storage-info   Show disk/storage analysis
#   shani-update --info           Show system status (Secure Boot, encryption, TPM2…)
#   shani-update --fix-security   Auto-fix security issues found by --info
#
# Install: /usr/local/bin/shani-update
# Autostart desktop entry: Exec=shani-update --startup
# Autostart systemd unit:  ExecStart=/usr/local/bin/shani-update --startup

set -Eeuo pipefail
IFS=$'\n\t'

#####################################
### Constants                     ###
#####################################

readonly SCRIPT_VERSION="3.0"
readonly OS_NAME="shanios"
readonly DEPLOY_BIN="/usr/local/bin/shani-deploy"
readonly DEFER_DELAY=86400
readonly UPDATE_CHANNEL_DEFAULT="stable"
readonly BASE_URL="https://sourceforge.net/projects/shanios/files"
readonly R2_BASE_URL="https://downloads.shani.dev"
readonly LOCAL_VERSION_FILE="/etc/shani-version"
readonly LOCAL_PROFILE_FILE="/etc/shani-profile"
readonly CURRENT_SLOT_FILE="/data/current-slot"
readonly BOOT_FAILURE_FILE="/data/boot_failure"
readonly BOOT_HARD_FAILURE_FILE="/data/boot_hard_failure"
readonly BOOT_OK_FILE="/data/boot-ok"
# Matches shani-deploy's path — /run is tmpfs so the file auto-clears on reboot.
readonly REBOOT_NEEDED_FILE="/run/shanios/reboot-needed"
readonly LOG_TAG="shani-update"
readonly NETWORK_TIMEOUT=30
readonly CURL_RETRIES=3
readonly CURL_RETRY_DELAY=5

# LOG_DIR: validate stays within HOME to prevent log injection via XDG_CACHE_HOME
_lcd="${XDG_CACHE_HOME:-$HOME/.cache}"
[[ "$_lcd" != "$HOME"* ]] && _lcd="$HOME/.cache"
readonly LOG_DIR="$_lcd"
unset _lcd

readonly LOG_FILE="$LOG_DIR/shani-update.log"

# Lock: prefer XDG_RUNTIME_DIR (user-private 0700) — startup mode requires it.
# In interactive mode LOG_DIR is an acceptable fallback.
readonly LOCK_FILE="${XDG_RUNTIME_DIR:-$LOG_DIR}/shani-update.lock"

mkdir -p "$LOG_DIR"

#####################################
### Global State                  ###
#####################################

MODE="interactive"          # interactive | startup | rollback | storage-info | info | fix-security
FORCE_UPDATE="no"
DEPLOY_CHANNEL="$UPDATE_CHANNEL_DEFAULT"
VERBOSE_DEPLOY="no"
DRY_RUN_DEPLOY="no"

LOCAL_VERSION=""
LOCAL_PROFILE=""
REMOTE_VERSION=""
REMOTE_PROFILE=""
TERMINAL=""
CURRENT_SLOT=""
BOOTED_SLOT=""
FAILED_SLOT=""              # set only when a fallback boot is confirmed
FALLBACK_DETECTED=0         # set to 1 when _check_fallback_boot confirms a fallback
REBOOT_VERSION=""           # set when reboot-needed marker is present

#####################################
### Logging                       ###
#####################################

log() {
    local ts msg
    ts=$(date '+%F %T')
    msg="[$ts] $*"
    # Rotate at 1 MB
    if [[ -f "$LOG_FILE" ]]; then
        local sz=0
        sz=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
        [[ $sz -gt 1048576 ]] && mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
    fi
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    echo "$msg" >&2
    if command -v systemd-cat &>/dev/null; then
        echo "$*" | systemd-cat -t "$LOG_TAG" 2>/dev/null || true
    elif command -v logger &>/dev/null; then
        logger -t "$LOG_TAG" "$*" 2>/dev/null || true
    fi
}

warn() { log "WARNING: $*"; }

err() {
    log "ERROR: $*"
    _cleanup_and_exit 1
}

#####################################
### Lock                          ###
#####################################

_acquire_lock() {
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        if [[ -f "$LOCK_FILE/pid" ]]; then
            local pid
            pid=$(cat "$LOCK_FILE/pid" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                echo "Another instance is already running (PID: $pid)" >&2
                exit 1
            fi
            log "Removing stale lock"
            rm -rf "$LOCK_FILE"
            mkdir "$LOCK_FILE" || { echo "Failed to acquire lock" >&2; exit 1; }
        else
            echo "Failed to acquire lock" >&2; exit 1
        fi
    fi
    echo $$ > "$LOCK_FILE/pid"
}

_cleanup_and_exit() {
    rm -rf "$LOCK_FILE" 2>/dev/null || true
    exit "${1:-0}"
}

#####################################
### Environment                   ###
#####################################

_validate_environment() {
    [[ -d /etc && -d /usr ]] || err "Invalid system environment"
    local required=(curl bash mkdir rm pkexec)
    for cmd in "${required[@]}"; do
        command -v "$cmd" &>/dev/null || err "Required command not found: $cmd"
    done
    systemctl --user status &>/dev/null || warn "systemd user session unavailable"
    command -v btrfs &>/dev/null        || warn "btrfs not available — slot detection may be limited"
}

#####################################
### Slot Helpers                  ###
#####################################

_get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2- 2>/dev/null || echo "")
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    [[ -z "$subvol" ]] && subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    if [[ -z "$subvol" ]]; then
        err "Cannot detect booted subvolume — /proc/cmdline has no subvol= and btrfs get-default returned nothing"
    fi
    echo "$subvol"
}

_other_slot() {
    [[ "$1" == "blue" ]] && echo "green" || echo "blue"
}

#####################################
### Fallback Boot Detection       ###
#####################################

# Returns 0 and sets FAILED_SLOT if a real boot failure occurred.
_check_fallback_boot() {
    BOOTED_SLOT=$(_get_booted_subvol)

    if [[ -f "$BOOT_HARD_FAILURE_FILE" ]]; then
        FAILED_SLOT=$(cat "$BOOT_HARD_FAILURE_FILE" 2>/dev/null | tr -d '[:space:]')
        # Validate — fall back to current-slot if file is empty or garbage
        if [[ ! "$FAILED_SLOT" =~ ^(blue|green)$ ]]; then
            FAILED_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | tr -d '[:space:]')
        fi
        [[ ! "$FAILED_SLOT" =~ ^(blue|green)$ ]] && FAILED_SLOT=$(_other_slot "$BOOTED_SLOT")
        log "Hard failure marker present — slot '@${FAILED_SLOT}' failed to mount"
        FALLBACK_DETECTED=1
        return 0
    fi

    if [[ -f "$BOOT_OK_FILE" && ! -f "$BOOT_FAILURE_FILE" ]]; then
        log "Clean boot on @${BOOTED_SLOT}"
        return 1
    fi

    CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | tr -d '[:space:]')
    if [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log "Invalid/missing slot marker — using booted slot"
        CURRENT_SLOT="$BOOTED_SLOT"
    fi

    log "Slot marker: @${CURRENT_SLOT} | Booted: @${BOOTED_SLOT}"

    [[ "$BOOTED_SLOT" == "$CURRENT_SLOT" ]] && {
        log "Booted slot matches marker — no fallback"
        return 1
    }

    [[ ! -f "$BOOT_FAILURE_FILE" ]] && {
        log "Slot mismatch but no failure file — nothing to act on"
        return 1
    }

    FAILED_SLOT=$(cat "$BOOT_FAILURE_FILE" 2>/dev/null | tr -d '[:space:]')
    if [[ "$FAILED_SLOT" != "$CURRENT_SLOT" ]]; then
        warn "Failure slot '@${FAILED_SLOT}' doesn't match marker '@${CURRENT_SLOT}' — ignoring"
        return 1
    fi

    log "Fallback confirmed: booted=@${BOOTED_SLOT} failed=@${FAILED_SLOT}"
    FALLBACK_DETECTED=1
    # Acknowledge the failure marker so mark-boot-in-progress doesn't
    # destroy it before shani-update processes it on the next reboot.
    mv "$BOOT_FAILURE_FILE" "${BOOT_FAILURE_FILE}.acked" 2>/dev/null || true
    return 0
}

#####################################
### Candidate Boot Detection      ###
#####################################

# Returns 0 if currently running the newly updated (candidate) slot.
# Must not fire when we already know this is a fallback boot — in that case
# the slot mismatch (booted != current-slot) is explained by the fallback,
# not by a new deployment being tested.
_check_candidate_boot() {
    if (( FALLBACK_DETECTED )); then
        log "Fallback already detected — skipping candidate boot check"
        return 1
    fi
    if [[ -r "$CURRENT_SLOT_FILE" ]]; then
        CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | xargs)
    fi
    if [[ -z "$CURRENT_SLOT" || ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log "No valid slot marker — cannot determine candidate boot state, skipping"
        return 1
    fi

    BOOTED_SLOT=$(_get_booted_subvol)
    log "Booted: @${BOOTED_SLOT} | Marker: @${CURRENT_SLOT}"

    if [[ "$BOOTED_SLOT" != "$CURRENT_SLOT" ]]; then
        local candidate
        candidate=$(_other_slot "$CURRENT_SLOT")
        if [[ "$BOOTED_SLOT" == "$candidate" ]]; then
            log "Candidate boot: running newly updated @${BOOTED_SLOT}"
            return 0
        fi
        warn "Unexpected boot state: @${BOOTED_SLOT} (expected @${CURRENT_SLOT} or @${candidate})"
    fi
    return 1
}

#####################################
### Terminal Detection            ###
#####################################

_find_terminal() {
    local known=(alacritty kitty wezterm foot gnome-terminal kgx tilix
        xfce4-terminal konsole lxterminal mate-terminal deepin-terminal
        terminator xterm urxvt st)

    # Env vars — strip path prefix, validate against allowlist only
    for var in TERMINAL TERMINAL_EMULATOR COLORTERM TERM_PROGRAM; do
        local emu="${!var:-}"
        emu="${emu##*/}"
        if [[ -n "$emu" ]]; then
            for k in "${known[@]}"; do
                [[ "$emu" == "$k" ]] && command -v "$emu" &>/dev/null && { echo "$emu"; return 0; }
            done
        fi
    done

    for term in "${known[@]}"; do
        command -v "$term" &>/dev/null && { echo "$term"; return 0; }
    done
    return 1
}

_build_terminal_args() {
    local terminal="$1" title="$2"
    local -n _arr="$3"
    shift 3
    local -a cmd=("$@")
    case "$terminal" in
        gnome-terminal|kgx|tilix|xfce4-terminal|lxterminal|mate-terminal|deepin-terminal)
            _arr=("$terminal" "--title=$title" "--" "${cmd[@]}") ;;
        konsole|alacritty)
            _arr=("$terminal" "--title" "$title" "-e" "${cmd[@]}") ;;
        kitty|foot)
            _arr=("$terminal" "--title=$title" "${cmd[@]}") ;;
        wezterm)
            _arr=("$terminal" "start" "--class" "$title" "${cmd[@]}") ;;
        terminator)
            _arr=("$terminal" "--title=$title" "-x" "${cmd[@]}") ;;
        xterm|urxvt|st)
            _arr=("$terminal" "-T" "$title" "-e" "${cmd[@]}") ;;
        *)
            _arr=("$terminal" "-e" "${cmd[@]}") ;;
    esac
}

#####################################
### Display Env                   ###
#####################################

_build_pkexec_env() {
    # Usage: _build_pkexec_env <nameref_array>
    local -n _pe="$1"
    local display_env xauth_env wayland_display
    display_env=$(printf '%s'     "${DISPLAY:-:0}"                   | tr -cd '[:alnum:]:._-/')
    xauth_env=$(printf '%s'       "${XAUTHORITY:-$HOME/.Xauthority}" | tr -cd '[:alnum:]/_.-')
    wayland_display=$(printf '%s' "${WAYLAND_DISPLAY:-}"             | tr -cd '[:alnum:]/_.-')
    _pe=(pkexec env "DISPLAY=$display_env" "XAUTHORITY=$xauth_env")
    [[ -n "$wayland_display" ]] && _pe+=("WAYLAND_DISPLAY=$wayland_display")
}

#####################################
### GUI Dialog                    ###
#####################################

# show_dialog TITLE TEXT OK_LABEL CANCEL_LABEL [TIMEOUT [ICON]]
# Returns: 0=confirmed  1=cancelled/timeout/closed  2=no GUI
show_dialog() {
    local title="$1" text="$2" ok_label="${3:-OK}" cancel_label="${4:-Cancel}"
    local timeout="${5:-120}" icon="${6:-software-update-available}"
    local session="${XDG_SESSION_TYPE:-unknown}"

    if command -v yad &>/dev/null; then
        local -a backends=()
        [[ "$session" == "wayland" ]] && backends=("wayland" "x11" "") || backends=("x11" "wayland" "")
        for backend in "${backends[@]}"; do
            local -a yad_cmd=()
            [[ -n "$backend" ]] && yad_cmd=(env "GDK_BACKEND=$backend")
            yad_cmd+=(yad
                --title="$title"
                --window-icon="$icon"
                --image="$icon"
                --image-on-top
                --text="$text"
                --text-align=center
                --wrap
                --width=480
                --borders=12
                --center
                --on-top
                --sticky
                --button="${ok_label}:0"
                --button="${cancel_label}:1"
            )
            [[ $timeout -gt 0 ]] && yad_cmd+=(--timeout="$timeout" --timeout-indicator=bottom)
            "${yad_cmd[@]}" 2>/dev/null
            local rc=$?
            [[ $rc -eq 0 ]]   && return 0
            [[ $rc -eq 1 ]]   && return 1
            [[ $rc -eq 70 ]]  && return 1
            [[ $rc -eq 252 ]] && return 1
            # non-standard exit = bad backend, try next
        done
    fi

    if command -v zenity &>/dev/null; then
        local -a z=(zenity --question --title="$title" --icon-name="$icon"
            --width=450 --text="$text" --ok-label="$ok_label" --cancel-label="$cancel_label")
        [[ $timeout -gt 0 ]] && z+=(--timeout="$timeout")
        "${z[@]}" 2>/dev/null && return 0 || return 1
    fi

    if command -v kdialog &>/dev/null; then
        kdialog --title "$title" --yesno "$text" \
            --yes-label "$ok_label" --no-label "$cancel_label" 2>/dev/null && return 0 || return 1
    fi

    return 2
}

#####################################
### Rollback                      ###
#####################################

_run_rollback() {
    local title="${1:-Shani OS — Rollback}"
    log "Launching rollback"

    if ! TERMINAL=$(_find_terminal); then
        err "No terminal emulator found — install gnome-terminal, alacritty, kitty, or xterm"
    fi

    local -a pkexec_args
    _build_pkexec_env pkexec_args
    pkexec_args+=("$DEPLOY_BIN" --rollback)
    [[ "$VERBOSE_DEPLOY" == "yes" ]] && pkexec_args+=(--verbose)
    [[ "$DRY_RUN_DEPLOY" == "yes" ]] && pkexec_args+=(--dry-run)

    local -a terminal_args
    _build_terminal_args "$TERMINAL" "$title" terminal_args "${pkexec_args[@]}"
    "${terminal_args[@]}"
}

_post_rollback_dialog() {
    local text
    text=$(printf 'Rollback completed.\n\n<b>@%s</b> has been restored.\n\nRestart now to boot back into <b>@%s</b>.' \
        "${FAILED_SLOT:-inactive}" "${BOOTED_SLOT:-current}")

    show_dialog "Shani OS — Rollback Complete" "$text" "Restart Now" "Restart Later" 300 "system-reboot"
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        log "Restarting after rollback"
        pkexec systemctl reboot 2>/dev/null || \
        pkexec /usr/sbin/shutdown -r now 2>/dev/null || \
        { warn "Automatic restart failed — please restart manually"
          command -v notify-send &>/dev/null && \
              notify-send -u critical -i dialog-error \
                  "Shani OS — Please Restart" "Rollback done. Restart manually." 2>/dev/null || true; }
    else
        log "User will restart later after rollback"
        command -v notify-send &>/dev/null && \
            notify-send -u low -i system-reboot \
                "Shani OS — Restart When Ready" \
                "Rollback complete. Restart when convenient." 2>/dev/null || true
        [[ -t 1 ]] && printf '\n✓ Rollback complete. Restart your system when ready.\n\n'
    fi
}

#####################################
### Fallback Boot Handler         ###
#####################################

_handle_fallback_boot() {
    # Called when _check_fallback_boot returns 0 (soft or hard failure).
    # Hard failures (boot_hard_failure present) show extra context explaining
    # that the slot failed to mount — not just that it booted incorrectly.
    local title text hard_failure=0
    [[ -f "$BOOT_HARD_FAILURE_FILE" ]] && hard_failure=1

    if (( hard_failure )); then
        title="Shani OS — Hard Boot Failure"
        text=$(printf '<b>Hard boot failure detected!</b>\n\nSlot <b>@%s</b> could not be mounted by the bootloader.\nThe system fell back to <b>@%s</b>.\n\nRoll back <b>@%s</b> now to restore a clean state?' \
            "$FAILED_SLOT" "$BOOTED_SLOT" "$FAILED_SLOT")
    else
        title="Shani OS — Boot Failure Detected"
        text=$(printf '<b>Boot failure detected!</b>\n\nSlot <b>@%s</b> failed to boot.\nThe system fell back to <b>@%s</b>.\n\nRoll back <b>@%s</b> now so it boots correctly next time?' \
            "$FAILED_SLOT" "$BOOTED_SLOT" "$FAILED_SLOT")
    fi

    show_dialog "$title" "$text" "Roll Back Now" "Ignore" 120 "dialog-warning"
    local rc=$?

    if [[ $rc -eq 2 ]]; then
        # No GUI — console or notify
        local notify_msg
        if (( hard_failure )); then
            notify_msg="Slot @${FAILED_SLOT} failed to mount. Run 'shani-update --rollback'."
        else
            notify_msg="Slot @${FAILED_SLOT} failed to boot. Run 'shani-update --rollback'."
        fi
        command -v notify-send &>/dev/null && \
            notify-send -u critical -i dialog-warning \
                "$title" "$notify_msg" 2>/dev/null || true
        if [[ -t 0 && -t 1 ]]; then
            printf '\n===================================\n  Shani OS — Boot Failure\n===================================\n'
            (( hard_failure )) && printf 'HARD FAILURE (slot failed to mount)\n'
            printf 'Failed: @%s  |  Booted: @%s\n\n' "$FAILED_SLOT" "$BOOTED_SLOT"
            read -rp "Roll back now? [y/N]: " -t 60 response || response="n"
            [[ "${response,,}" == y* ]] && rc=0 || return 0
        else
            return 0
        fi
    fi

    if [[ $rc -eq 0 ]]; then
        log "User approved rollback of @${FAILED_SLOT}"
        if _run_rollback "Shani OS — Rollback"; then
            log "Rollback succeeded"
            # Clear failure markers now that rollback is done
            rm -f "$BOOT_FAILURE_FILE" "${BOOT_FAILURE_FILE}.acked" \
                  "$BOOT_HARD_FAILURE_FILE" 2>/dev/null || true
            _post_rollback_dialog
            _cleanup_and_exit 0
        else
            log "ERROR: Rollback failed or cancelled"
            command -v notify-send &>/dev/null && \
                notify-send -u critical -i dialog-error \
                    "Shani OS — Rollback Failed" "Check $LOG_FILE." 2>/dev/null || true
            _cleanup_and_exit 1
        fi
    else
        log "User declined rollback"
    fi
}

#####################################
### Candidate Boot Handler        ###
#####################################

_handle_candidate_boot() {
    local candidate="$BOOTED_SLOT"
    local text
    text=$(printf "You're running the newly updated system (<b>@%s</b>).\n\nIf everything looks good, no action needed.\nIf something is broken, roll back to <b>@%s</b> now." \
        "$candidate" "$CURRENT_SLOT")

    show_dialog "Shani OS — Testing New System" "$text" "Roll Back Now" "Keep Testing" 0 "system-reboot"
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        log "User requested rollback from candidate boot @${candidate}"
        FAILED_SLOT="$candidate"
        if _run_rollback "Shani OS — Rollback"; then
            log "Rollback from candidate boot succeeded"
            _post_rollback_dialog
            _cleanup_and_exit 0
        else
            log "ERROR: Rollback failed"
            command -v notify-send &>/dev/null && \
                notify-send -u critical -i dialog-error \
                    "Shani OS — Rollback Failed" "Check $LOG_FILE." 2>/dev/null || true
            _cleanup_and_exit 1
        fi
    else
        log "User chose to keep testing @${candidate}"
        command -v notify-send &>/dev/null && \
            notify-send -u normal -i software-update-available \
                "Shani OS — System Testing" \
                "Testing @${candidate}. Run 'shani-update --rollback' if needed." 2>/dev/null || true
        _cleanup_and_exit 0
    fi
}

#####################################
### Reboot Needed Detection       ###
#####################################

# Returns 0 and sets REBOOT_VERSION if a reboot-needed marker is present.
# No manual cleanup needed — /run is tmpfs and is wiped on every reboot,
# so the file is gone as soon as the user reboots into the new slot.
_check_reboot_needed() {
    [[ -f "$REBOOT_NEEDED_FILE" ]] || return 1

    REBOOT_VERSION=$(cat "$REBOOT_NEEDED_FILE" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
    BOOTED_SLOT=$(_get_booted_subvol)
    log "Reboot needed: deployed v${REBOOT_VERSION}, still running @${BOOTED_SLOT}"
    return 0
}

_handle_reboot_needed() {
    local ver="${REBOOT_VERSION:-unknown}"
    local text
    text=$(printf 'Shani OS has been updated to <b>v%s</b>.\n\nRestart now to boot into the updated system.\nYou can continue using your current session and restart later.' "$ver")

    show_dialog "Shani OS — Restart Required" "$text" "Restart Now" "Restart Later" 300 "system-reboot"
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        log "User chose to restart now after update to v${ver}"
        pkexec systemctl reboot 2>/dev/null || \
        pkexec /usr/sbin/shutdown -r now 2>/dev/null || \
        { warn "Automatic restart failed — please restart manually"
          command -v notify-send &>/dev/null && \
              notify-send -u critical -i system-restart \
                  "Shani OS — Please Restart" \
                  "Updated to v${ver}. Restart manually." 2>/dev/null || true; }
    elif [[ $rc -eq 1 ]]; then
        log "User chose to restart later after update to v${ver}"
        command -v notify-send &>/dev/null && \
            notify-send -u normal -i system-reboot \
                "Shani OS Updated to v${ver}" \
                "Restart when convenient to activate the new system." 2>/dev/null || true
    else
        # No GUI — fall back to notification or console
        command -v notify-send &>/dev/null && \
            notify-send -u critical -i software-update-available \
                "Shani OS Updated — Restart Required" \
                "v${ver} is ready. Restart to activate." 2>/dev/null || true
        if [[ -t 0 && -t 1 ]]; then
            printf '\n========================================\n'
            printf '  Shani OS v%s — Restart Required\n' "$ver"
            printf '========================================\n'
            read -rp "Restart now? [y/N]: " -t 60 response || response="n"
            if [[ "${response,,}" == y* ]]; then
                pkexec systemctl reboot 2>/dev/null || \
                pkexec /usr/sbin/shutdown -r now 2>/dev/null || \
                warn "Restart failed — please restart manually"
            fi
        fi
    fi
}

#####################################
### Network & Version Helpers     ###
#####################################

_read_file_or_default() {
    local file="$1" default="$2" filter="$3"
    [[ ! -r "$file" ]] && { echo "$default"; return 0; }
    local content
    content=$(head -n1 "$file" 2>/dev/null | tr -cd "$filter" | xargs echo)
    [[ -z "$content" ]] && { warn "Invalid data in $file — using default: $default"; echo "$default"; return 0; }
    echo "$content"
}

_check_network() {
    log "Checking network connectivity..."
    local dns=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    for d in "${dns[@]}"; do
        ping -c 1 -W 5 "$d" &>/dev/null && { log "Network OK"; return 0; }
    done
    local urls=("https://www.google.com" "https://github.com")
    for u in "${urls[@]}"; do
        curl -fsSL --connect-timeout 5 --max-time 10 --head "$u" &>/dev/null && { log "Network OK"; return 0; }
    done
    nslookup google.com &>/dev/null || dig +short google.com &>/dev/null || \
        host google.com &>/dev/null && { log "Network OK via DNS"; return 0; }
    log "No network connectivity"
    return 1
}

_fetch_remote_info() {
    local url="$1"
    local tmp
    tmp=$(mktemp) || { log "ERROR: mktemp failed"; return 1; }
    if ! curl -fsSL \
        --retry "$CURL_RETRIES" --retry-delay "$CURL_RETRY_DELAY" \
        --max-time "$NETWORK_TIMEOUT" --connect-timeout 10 \
        --user-agent "shani-update/$SCRIPT_VERSION" \
        --output "$tmp" "$url" 2>/dev/null; then
        rm -f "$tmp"; log "ERROR: fetch failed for $url"; return 1
    fi
    local sz=0
    sz=$(stat -c%s "$tmp" 2>/dev/null || stat -f%z "$tmp" 2>/dev/null || echo 0)
    if [[ $sz -gt 1024 ]]; then
        rm -f "$tmp"; log "ERROR: Response too large ($sz bytes)"; return 1
    fi
    local content
    content=$(head -n1 "$tmp" 2>/dev/null | tr -cd 'A-Za-z0-9.-' | xargs echo)
    rm -f "$tmp"
    [[ -z "$content" ]] && { log "ERROR: Empty response"; return 1; }
    echo "$content"
}

_validate_version() {
    local v="$1"
    [[ "$v" =~ ^[0-9]{8}$ ]] || return 1
    local y="${v:0:4}" m="${v:4:2}" d="${v:6:2}"
    [[ "$y" < "2020" || "$y" > "2050" ]] && return 1
    [[ "$m" < "01"   || "$m" > "12"   ]] && return 1
    [[ "$d" < "01"   || "$d" > "31"   ]] && return 1
    return 0
}

_version_compare() {
    # Returns 0=equal 1=v1<v2(update available) 2=v1>v2
    local v1="$1" v2="$2"
    [[ "$v1" == "$v2" ]] && return 0
    [[ "$v1" < "$v2"  ]] && return 1
    return 2
}

_is_update_needed() {
    local lv="$1" lp="$2" rv="$3" rp="$4"
    _version_compare "$lv" "$rv"
    case $? in
        0) [[ "$lp" != "$rp" ]] && { log "Profile update: $lp → $rp"; return 0; }
           log "System is current (v${lv}-${lp})"; return 1 ;;
        1) log "Update available: v${lv} → v${rv}"; return 0 ;;
        2) log "System is ahead of remote (v${lv} vs v${rv})"; return 1 ;;
    esac
}

#####################################
### Update Flow                   ###
#####################################

_decide_action() {
    local current="v$LOCAL_VERSION-$LOCAL_PROFILE"
    local remote="v$REMOTE_VERSION-$REMOTE_PROFILE"
    local text
    text=$(printf 'A system update is available for Shani OS.\n\n<b>Current:</b>  %s\n<b>Available:</b> %s\n\nThe update will download and install in a terminal window.\nYou can continue using your computer during the process.' \
        "$current" "$remote")

    log "Session: ${XDG_SESSION_TYPE:-unknown} (${XDG_CURRENT_DESKTOP:-unknown})"
    show_dialog "Shani OS — Update Available" "$text" "Install Now" "Remind Me Later" 120
    local rc=$?

    [[ $rc -eq 0 ]] && { log "User chose to install"; return 0; }
    [[ $rc -eq 1 ]] && { log "User chose to postpone"; return 1; }

    # rc=2: no GUI
    command -v notify-send &>/dev/null && \
        notify-send -u critical -i software-update-available \
            "Shani OS Update Available" \
            "$current → $remote. Run 'shani-update' to install." 2>/dev/null || true

    if [[ -t 0 && -t 1 ]]; then
        printf '\n========================================\n'
        printf '     Shani OS System Update Available   \n'
        printf '========================================\n'
        printf '  Current:   %s\n  Available: %s\n\n' "$current" "$remote"
        read -rp "Install update now? [y/N]: " -t 60 response || response="n"
        [[ "${response,,}" == y* ]] && { log "User chose to install (console)"; return 0; }
        log "User chose to postpone (console)"
        return 1
    fi

    log "No interactive interface — defaulting to postpone"
    return 1
}

_run_update_check() {
    LOCAL_VERSION=$(_read_file_or_default "$LOCAL_VERSION_FILE" "19700101" "0-9")
    LOCAL_PROFILE=$(_read_file_or_default "$LOCAL_PROFILE_FILE" "default"  "A-Za-z")
    _validate_version "$LOCAL_VERSION" || { warn "Corrupted version — treating as outdated"; LOCAL_VERSION="19700101"; }
    log "Local: v${LOCAL_VERSION}-${LOCAL_PROFILE}"

    _check_network || {
        warn "No internet — retrying in 30s..."
        sleep 30
        _check_network || err "No internet connection after retry"
        log "Connection restored"
    }

    local channel_url="$BASE_URL/$LOCAL_PROFILE/$DEPLOY_CHANNEL.txt"
    local r2_url="$R2_BASE_URL/$LOCAL_PROFILE/$DEPLOY_CHANNEL.txt"
    local remote_image
    # Try R2 first (same priority as shani-deploy), fall back to SourceForge.
    remote_image=$(_fetch_remote_info "$r2_url") || \
    remote_image=$(_fetch_remote_info "$channel_url") || \
        err "Unable to fetch update info from server"

    if [[ "$remote_image" =~ ^shanios-([0-9]{8})-([A-Za-z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"
        _validate_version "$REMOTE_VERSION" || err "Invalid remote version: $REMOTE_VERSION"
    else
        err "Unexpected server response: '$remote_image'"
    fi
    log "Remote: v${REMOTE_VERSION}-${REMOTE_PROFILE}"

    _is_update_needed "$LOCAL_VERSION" "$LOCAL_PROFILE" "$REMOTE_VERSION" "$REMOTE_PROFILE" || {
        log "System is up to date"
        _cleanup_and_exit 0
    }

    _decide_action || {
        log "Update postponed — scheduling reminder"
        if systemctl --user status &>/dev/null; then
            # Cancel any previously deferred reminders before creating a new one
            # so they don't accumulate across multiple defer sessions.
            systemctl --user stop "${LOG_TAG}-defer-"*.timer 2>/dev/null || true
            systemctl --user reset-failed "${LOG_TAG}-defer-"*.timer 2>/dev/null || true
            local unit="${LOG_TAG}-defer-$(date +%s)-$$"
            systemd-run --user \
                --unit="$unit" \
                --description="Deferred Shani OS update reminder" \
                --on-active="${DEFER_DELAY}s" \
                "/usr/local/bin/shani-update" 2>/dev/null && \
                log "Reminder set for ${DEFER_DELAY}s" || warn "Could not schedule reminder"
        fi
        _cleanup_and_exit 0
    }

    log "User approved update — launching shani-deploy"

    if ! TERMINAL=$(_find_terminal); then
        err "No terminal found. Install gnome-terminal, alacritty, kitty, or xterm."
    fi
    log "Terminal: $TERMINAL"

    local -a pkexec_args
    _build_pkexec_env pkexec_args
    pkexec_args+=("$DEPLOY_BIN")
    [[ "$FORCE_UPDATE"   == "yes" ]] && pkexec_args+=(--force)
    [[ "$DEPLOY_CHANNEL" != "$UPDATE_CHANNEL_DEFAULT" ]] && pkexec_args+=(--channel "$DEPLOY_CHANNEL")
    [[ "$VERBOSE_DEPLOY" == "yes" ]] && pkexec_args+=(--verbose)
    [[ "$DRY_RUN_DEPLOY" == "yes" ]] && pkexec_args+=(--dry-run)

    local -a terminal_args
    _build_terminal_args "$TERMINAL" "Shani OS Update" terminal_args "${pkexec_args[@]}"

    "${terminal_args[@]}"
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log "Update completed successfully — reboot-needed marker will surface restart dialog"
        # shani-deploy wrote /run/shanios/reboot-needed (tmpfs — auto-cleared on reboot).
        # On next startup or interactive run _check_reboot_needed will pick it up.
    else
        warn "Update failed or cancelled (exit code: $exit_code)"
        command -v notify-send &>/dev/null && \
            notify-send -u critical -i dialog-error \
                "Shani OS Update Failed" \
                "The update did not complete. Check $LOG_FILE." 2>/dev/null || true
        _cleanup_and_exit 1
    fi
}

#####################################
### Main                          ###
#####################################

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --startup)          MODE="startup";       shift ;;
            -r|--rollback)      MODE="rollback";      shift ;;
            -s|--storage-info)  MODE="storage-info";  shift ;;
            -i|--info)          MODE="info";           shift ;;
            --fix-security)     MODE="fix-security";  shift ;;
            -f|--force)         FORCE_UPDATE="yes";   shift ;;
            -t|--channel)       DEPLOY_CHANNEL="$2";  shift 2 ;;
            -v|--verbose)       VERBOSE_DEPLOY="yes"; shift ;;
            -d|--dry-run)       DRY_RUN_DEPLOY="yes"; shift ;;
            -h|--help)
                cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --startup           Run at login: fallback check → candidate check → update check
  -i, --info          Show system status (Secure Boot, encryption, slots, TPM2, services)
  --fix-security      Auto-fix security issues found by --info
  -r, --rollback      Roll back the inactive slot immediately
  -f, --force         Force deploy even if version matches or slot mismatch
  -t, --channel CHAN  Update channel: stable|latest  (default: $UPDATE_CHANNEL_DEFAULT)
  -v, --verbose       Verbose output from shani-deploy
  -d, --dry-run       Simulate deployment without changes
  -s, --storage-info  Show disk usage and storage analysis
  -h, --help          Show this help

Autostart:  Exec=shani-update --startup
EOF
                exit 0 ;;
            *) warn "Unknown option: $1"; shift ;;
        esac
    done

    log "shani-update v${SCRIPT_VERSION} mode=${MODE}"

    # storage-info / info / fix-security: no lock needed, just pass through to shani-deploy
    if [[ "$MODE" == "storage-info" ]]; then
        pkexec "$DEPLOY_BIN" --storage-info
        exit $?
    fi

    if [[ "$MODE" == "info" ]]; then
        pkexec "$DEPLOY_BIN" --info
        exit $?
    fi

    if [[ "$MODE" == "fix-security" ]]; then
        pkexec "$DEPLOY_BIN" --fix-security
        exit $?
    fi

    _validate_environment

    # ── Startup mode ─────────────────────────────────────────────────────────
    if [[ "$MODE" == "startup" ]]; then
        if [[ -z "${XDG_RUNTIME_DIR:-}" ]]; then
            log "XDG_RUNTIME_DIR not set — cannot run safely at startup"
            exit 0
        fi
        # Wait for polkit agent and desktop shell before acquiring the lock so
        # a concurrent manual invocation is not blocked during this delay.
        sleep 15
        if [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
            log "No display — skipping startup check"
            exit 0
        fi
    fi

    _acquire_lock
    trap '_cleanup_and_exit' EXIT INT TERM

    # ── Startup mode (continued after lock) ───────────────────────────────────
    if [[ "$MODE" == "startup" ]]; then

        log "=== Startup: checking reboot needed ==="
        if _check_reboot_needed; then
            _handle_reboot_needed
            _cleanup_and_exit 0
        fi

        log "=== Startup: checking fallback boot ==="
        if _check_fallback_boot; then
            _handle_fallback_boot
        fi

        log "=== Startup: checking candidate boot ==="
        if _check_candidate_boot; then
            _handle_candidate_boot
            # _handle_candidate_boot calls _cleanup_and_exit internally
        fi

        log "=== Startup: checking for updates ==="
        _run_update_check
        _cleanup_and_exit 0
    fi

    # ── Explicit rollback ─────────────────────────────────────────────────────
    if [[ "$MODE" == "rollback" ]]; then
        log "=== Manual rollback ==="
        BOOTED_SLOT=$(_get_booted_subvol)
        FAILED_SLOT=$(_other_slot "$BOOTED_SLOT")
        if _run_rollback "Shani OS — Rollback"; then
            log "Rollback succeeded"
            _post_rollback_dialog
            _cleanup_and_exit 0
        else
            log "ERROR: Rollback failed"
            _cleanup_and_exit 1
        fi
    fi

    # ── Interactive update mode ───────────────────────────────────────────────
    log "=== Interactive: checking reboot needed ==="
    if _check_reboot_needed; then
        _handle_reboot_needed
        _cleanup_and_exit 0
    fi

    log "=== Interactive: checking fallback boot ==="
    if _check_fallback_boot; then
        _handle_fallback_boot
    fi

    log "=== Interactive: checking candidate boot ==="
    if _check_candidate_boot; then
        _handle_candidate_boot
        # _handle_candidate_boot calls _cleanup_and_exit internally
    fi

    log "=== Interactive: checking for updates ==="
    _run_update_check
    _cleanup_and_exit 0
}

main "$@"
