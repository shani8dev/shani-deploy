#!/usr/bin/env bash
#
# startup-check: detect fallback boot and prompt user for rollback on Shani OS
#
# Run via .desktop autostart or systemd --user after login.
# Invokes shani-deploy --rollback via pkexec when a fallback boot is confirmed.

set -Eeuo pipefail
IFS=$'\n\t'

#####################################
### Global Configuration          ###
#####################################

readonly SCRIPT_VERSION="1.2"
readonly OS_NAME="shanios"
readonly LOG_DIR="${XDG_CACHE_HOME:-$HOME/.cache}"
readonly LOG_FILE="$LOG_DIR/shanios-startup-check.log"
readonly LOCK_FILE="${XDG_RUNTIME_DIR:-/tmp}/shanios-startup-check.lock"
readonly ROLLBACK_STATUS_FILE="${XDG_RUNTIME_DIR:-/tmp}/shanios-startup-check-status"
readonly CURRENT_SLOT_FILE="/data/current-slot"
readonly BOOT_FAILURE_FILE="/data/boot_failure"
readonly BOOT_HARD_FAILURE_FILE="/data/boot_hard_failure"
readonly BOOT_OK_FILE="/data/boot-ok"
readonly DEPLOY_BIN="/usr/local/bin/shani-deploy"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Global state
declare -g BOOTED_SLOT=""
declare -g CURRENT_SLOT=""
declare -g FAILED_SLOT=""
declare -g TERMINAL=""

#####################################
### Logging System                ###
#####################################

log() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*"
    echo "$msg" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    logger -t shanios-startup-check "$*" 2>/dev/null || true
}

log_success() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $*"
    echo -e "\033[0;32m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    logger -t shanios-startup-check "SUCCESS: $*" 2>/dev/null || true
}

log_warn() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $*"
    echo -e "\033[0;33m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    logger -t shanios-startup-check "WARNING: $*" 2>/dev/null || true
}

log_error() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*"
    echo -e "\033[0;31m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    logger -t shanios-startup-check "ERROR: $*" 2>/dev/null || true
}

die() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [FATAL] $*"
    echo -e "\033[1;31m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    logger -t shanios-startup-check "FATAL: $*" 2>/dev/null || true
    exit 1
}

log_section() {
    local line="=========================================="
    {
        echo ""
        echo "$line"
        echo "  $1"
        echo "$line"
    } >&2
    {
        echo ""
        echo "$line"
        echo "  $1"
        echo "$line"
    } >> "$LOG_FILE" 2>/dev/null || true
}

#####################################
### Lock                          ###
#####################################

acquire_lock() {
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        if [[ -f "$LOCK_FILE/pid" ]]; then
            local lock_pid
            lock_pid=$(cat "$LOCK_FILE/pid" 2>/dev/null || echo "")
            if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
                log_warn "Another instance is already running (PID: $lock_pid)"
                exit 1
            else
                log "Removing stale lock file"
                rm -rf "$LOCK_FILE"
                mkdir "$LOCK_FILE" || die "Failed to acquire lock"
            fi
        else
            die "Failed to acquire lock"
        fi
    fi
    echo $$ > "$LOCK_FILE/pid"
}

release_lock() {
    rm -rf "$LOCK_FILE" 2>/dev/null || true
}

#####################################
### Btrfs Helpers                 ###
#####################################

get_booted_subvol() {
    local subvol
    subvol=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | sed 's/.*subvol=@//;s/,.*//' || echo "")
    [[ -z "$subvol" ]] && subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    echo "${subvol:-blue}"
}

#####################################
### Fallback Detection            ###
#####################################

check_fallback_condition() {
    log_section "Boot Validation"

    BOOTED_SLOT=$(get_booted_subvol)

    if [[ -f "$BOOT_HARD_FAILURE_FILE" ]]; then
        log "Hard boot failure marker present — deferring to shani-deploy --rollback path"
        return 1
    fi

    if [[ -f "$BOOT_OK_FILE" ]] && [[ ! -f "$BOOT_FAILURE_FILE" ]]; then
        log "Boot-ok marker present, no failure file — clean boot on @${BOOTED_SLOT}"
        return 1
    fi

    CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | tr -d '[:space:]')

    if [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log_warn "Invalid or missing current-slot marker, using booted slot as reference"
        CURRENT_SLOT="$BOOTED_SLOT"
    fi

    log "Marker: @${CURRENT_SLOT}"
    log "Booted: @${BOOTED_SLOT}"

    if [[ "$BOOTED_SLOT" == "$CURRENT_SLOT" ]]; then
        log "Booted slot matches current-slot marker — no fallback detected"
        return 1
    fi

    if [[ ! -f "$BOOT_FAILURE_FILE" ]]; then
        log "Boot mismatch present but no failure file — nothing to act on"
        return 1
    fi

    FAILED_SLOT=$(cat "$BOOT_FAILURE_FILE" 2>/dev/null | tr -d '[:space:]')

    if [[ "$FAILED_SLOT" != "$CURRENT_SLOT" ]]; then
        log_warn "Recorded failure '@${FAILED_SLOT}' does not match expected current-slot '@${CURRENT_SLOT}' — ignoring"
        return 1
    fi

    log "Fallback detected: booted='@${BOOTED_SLOT}', failed='@${FAILED_SLOT}'"
    return 0
}

#####################################
### Terminal Detection            ###
#####################################

find_terminal() {
    for var in TERMINAL_EMULATOR COLORTERM TERM_PROGRAM; do
        local emu="${!var:-}"
        if [[ -n "$emu" ]] && command -v "$emu" &>/dev/null; then
            echo "$emu"
            return 0
        fi
    done

    local modern_terms=(alacritty kitty wezterm foot)
    for term in "${modern_terms[@]}"; do
        command -v "$term" &>/dev/null && echo "$term" && return 0
    done

    local desktop_terms=(
        gnome-terminal kgx tilix xfce4-terminal konsole lxterminal
        mate-terminal deepin-terminal terminator
    )
    for term in "${desktop_terms[@]}"; do
        command -v "$term" &>/dev/null && echo "$term" && return 0
    done

    local fallback_terms=(xterm urxvt st)
    for term in "${fallback_terms[@]}"; do
        command -v "$term" &>/dev/null && echo "$term" && return 0
    done

    return 1
}

#####################################
### Terminal Command Builder      ###
#####################################

build_terminal_cmd() {
    local terminal="$1"
    local command="$2"
    local escaped_cmd
    escaped_cmd=$(printf '%q' "$command")

    case "$terminal" in
        gnome-terminal|kgx|tilix|xfce4-terminal|lxterminal|mate-terminal|deepin-terminal)
            echo "$terminal --title='Shani OS Rollback' -- bash -c $escaped_cmd"
            ;;
        konsole)
            echo "$terminal --title 'Shani OS Rollback' -e bash -c $escaped_cmd"
            ;;
        alacritty)
            echo "$terminal --title 'Shani OS Rollback' -e bash -c $escaped_cmd"
            ;;
        kitty)
            echo "$terminal --title='Shani OS Rollback' bash -c $escaped_cmd"
            ;;
        wezterm)
            echo "$terminal start --class 'Shani OS Rollback' bash -c $escaped_cmd"
            ;;
        foot)
            echo "$terminal --title='Shani OS Rollback' bash -c $escaped_cmd"
            ;;
        terminator)
            echo "$terminal --title='Shani OS Rollback' -x bash -c $escaped_cmd"
            ;;
        xterm|urxvt|st)
            echo "$terminal -T 'Shani OS Rollback' -e bash -c $escaped_cmd"
            ;;
        *)
            echo "$terminal -e bash -c $escaped_cmd"
            ;;
    esac
}

#####################################
### Rollback Wrapper              ###
#####################################

create_rollback_wrapper() {
    local wrapper_script
    wrapper_script=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/shanios-rollback-wrapper.XXXXXX")

    cat > "$wrapper_script" << 'WRAPPER_EOF'
#!/bin/bash
readonly STATUS_FILE="$1"
readonly LOG_FILE="$2"

log_w() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*" >> "$LOG_FILE" 2>/dev/null || true
}

echo "RUNNING" > "$STATUS_FILE"
log_w "Rollback wrapper started"

if pkexec /usr/local/bin/shani-deploy --rollback; then
    echo "SUCCESS" > "$STATUS_FILE"
    log_w "Rollback completed successfully"
    echo ""
    echo "Rollback completed successfully!"
    echo "You can close this terminal. Please reboot when ready."
    echo ""
    echo "Press Enter to close..."
    read -r
else
    echo "FAILED" > "$STATUS_FILE"
    log_w "Rollback failed"
    echo ""
    echo "Rollback failed. Please check $LOG_FILE for details."
    echo ""
    echo "Press Enter to close..."
    read -r
fi
WRAPPER_EOF

    chmod +x "$wrapper_script"
    echo "$wrapper_script"
}

#####################################
### Wait for Rollback             ###
#####################################

wait_for_rollback_completion() {
    local max_wait_time=3600
    local check_interval=5
    local elapsed=0

    log "Monitoring rollback progress (this may take several minutes)..."

    while [[ $elapsed -lt $max_wait_time ]]; do
        if [[ -f "$ROLLBACK_STATUS_FILE" ]]; then
            local status
            status=$(cat "$ROLLBACK_STATUS_FILE" 2>/dev/null || echo "UNKNOWN")

            case "$status" in
                SUCCESS)
                    log_success "Rollback completed successfully!"
                    return 0
                    ;;
                FAILED)
                    log_error "Rollback failed"
                    return 1
                    ;;
                RUNNING|INITIALIZING)
                    ;;
                *)
                    log_warn "Unknown rollback status: $status"
                    ;;
            esac
        fi

        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))

        if [[ $((elapsed % 120)) -eq 0 ]]; then
            log "Rollback still in progress... ($((elapsed / 60)) minutes elapsed)"
        fi
    done

    log_warn "Rollback monitoring timed out after $((max_wait_time / 60)) minutes"
    return 1
}

#####################################
### GUI Dialog — Rollback Prompt  ###
#####################################

decide_rollback() {
    local failed_slot="$1"
    local booted_slot="$2"
    local message="Boot failure detected!\n\nSlot '@${failed_slot}' failed to boot.\nSystem fell back to '@${booted_slot}'.\n\nWould you like to rollback '@${failed_slot}' now so it boots correctly next time?"

    if command -v yad &>/dev/null; then
        if yad --title="Shani OS - Boot Failure Detected" \
               --width=480 --height=200 \
               --center --on-top \
               --text="$(echo -e "$message")" \
               --image="dialog-warning" \
               --button="Rollback Now:0" \
               --button="Ignore:1" \
               --timeout=120 2>/dev/null; then
            log "User chose to rollback (via yad)"
            return 0
        else
            log "User chose to ignore rollback (via yad)"
            return 1
        fi
    fi

    if command -v zenity &>/dev/null; then
        if zenity --question \
                  --title="Shani OS - Boot Failure Detected" \
                  --width=450 \
                  --text="$(echo -e "$message")" \
                  --ok-label="Rollback Now" \
                  --cancel-label="Ignore" \
                  --timeout=120 2>/dev/null; then
            log "User chose to rollback (via zenity)"
            return 0
        else
            log "User chose to ignore rollback (via zenity)"
            return 1
        fi
    fi

    if command -v kdialog &>/dev/null; then
        if kdialog --title "Shani OS - Boot Failure Detected" \
                   --yesno "$(echo -e "$message")" \
                   --yes-label "Rollback Now" \
                   --no-label "Ignore" 2>/dev/null; then
            log "User chose to rollback (via kdialog)"
            return 0
        else
            log "User chose to ignore rollback (via kdialog)"
            return 1
        fi
    fi

    if command -v notify-send &>/dev/null; then
        notify-send -u critical \
                   -i dialog-warning \
                   "Shani OS - Boot Failure Detected" \
                   "Slot '@${failed_slot}' failed to boot. System fell back to '@${booted_slot}'. Check your terminal to rollback." 2>/dev/null || true
    fi

    if [[ -t 0 ]] && [[ -t 1 ]]; then
        log "Using console interface for rollback decision"
        echo "" >&2
        echo "========================================" >&2
        echo "  Shani OS - Boot Failure Detected"      >&2
        echo "========================================" >&2
        echo "Failed slot:  @${failed_slot}"           >&2
        echo "Booted slot:  @${booted_slot}"           >&2
        echo ""                                        >&2
        read -rp "Rollback now? [y/N]: " -t 60 response || response="n"
        case "$response" in
            [Yy]*) log "User chose to rollback (via console)"; return 0 ;;
            *)     log "User chose to ignore rollback (via console)"; return 1 ;;
        esac
    fi

    log "No interactive interfaces available, defaulting to ignore"
    return 1
}

#####################################
### GUI Dialog — Post-Rollback    ###
#####################################

handle_post_rollback() {
    local reboot_message="Rollback completed successfully!\n\n'@${FAILED_SLOT}' has been restored to a working state.\n\nTo complete the rollback, please restart your computer now.\nThe system will boot back into '@${BOOTED_SLOT}'."
    local reboot_now=false

    if command -v yad &>/dev/null; then
        yad --title="Rollback Complete - Restart Recommended" \
               --width=450 --height=180 \
               --center --on-top \
               --text="$(echo -e "$reboot_message")" \
               --image="system-restart" \
               --button="Restart Now:0" \
               --button="Restart Later:1" \
               --timeout=300 2>/dev/null && reboot_now=true || reboot_now=false
    elif command -v zenity &>/dev/null; then
        zenity --question \
               --title="Rollback Complete - Restart Recommended" \
               --width=450 \
               --text="$(echo -e "$reboot_message")" \
               --ok-label="Restart Now" \
               --cancel-label="Restart Later" \
               --timeout=300 2>/dev/null && reboot_now=true || reboot_now=false
    elif command -v kdialog &>/dev/null; then
        kdialog --title "Rollback Complete - Restart Recommended" \
                --yesno "$(echo -e "$reboot_message")" \
                --yes-label "Restart Now" \
                --no-label "Restart Later" 2>/dev/null && reboot_now=true || reboot_now=false
    else
        if [[ -t 0 ]] && [[ -t 1 ]]; then
            echo "" >&2
            echo "✓ Rollback completed successfully!" >&2
            echo "" >&2
            read -rp "Restart now? [y/N]: " -t 60 response || response="n"
            case "$response" in
                [Yy]*) reboot_now=true ;;
                *)     reboot_now=false ;;
            esac
        else
            command -v notify-send &>/dev/null && \
                notify-send -u normal -i dialog-information \
                    "Shani OS Rollback Complete" \
                    "Rollback successful! Restart when convenient." 2>/dev/null || true
        fi
    fi

    if [[ "$reboot_now" == "true" ]]; then
        log "User requested immediate restart"
        pkexec systemctl reboot 2>/dev/null || \
        pkexec shutdown -r now 2>/dev/null || \
        log_warn "Automatic restart failed — please restart manually"
    else
        log "User chose to restart later — rollback complete"
        command -v notify-send &>/dev/null && \
            notify-send -u low -i dialog-information \
                "Shani OS Rollback Complete" \
                "Rollback successful. Remember to restart when convenient." 2>/dev/null || true
    fi
}

#####################################
### Main                          ###
#####################################

main() {
    log_section "Startup Boot Check"
    log "Shani OS startup-check starting (v$SCRIPT_VERSION)"

    # Wait for polkit agent and desktop to be fully ready.
    # This is essential whether launched via .desktop or systemd --user.
    sleep 15

    if [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        logger -t shanios-startup-check "No display available — skipping GUI startup check"
        exit 0
    fi

    acquire_lock
    trap 'release_lock' EXIT INT TERM

    if ! check_fallback_condition; then
        log_success "No rollback action required"
        exit 0
    fi

    if ! TERMINAL=$(find_terminal); then
        log_error "No suitable terminal emulator found. Please install: gnome-terminal, alacritty, kitty, or xterm"
        exit 1
    fi
    log "Terminal for rollback: $TERMINAL"

    if ! decide_rollback "$FAILED_SLOT" "$BOOTED_SLOT"; then
        log "User declined rollback — exiting"
        exit 0
    fi

    log_section "Rollback"
    log "User approved rollback — preparing to rollback '@${FAILED_SLOT}'"

    echo "INITIALIZING" > "$ROLLBACK_STATUS_FILE"

    local wrapper_script
    if ! wrapper_script=$(create_rollback_wrapper); then
        log_error "Unable to prepare rollback wrapper script"
        rm -f "$ROLLBACK_STATUS_FILE"
        exit 1
    fi

    local display_env="${DISPLAY:-:0}"
    local xauth_env="${XAUTHORITY:-$HOME/.Xauthority}"
    local wayland_display="${WAYLAND_DISPLAY:-}"

    local env_vars="DISPLAY='$display_env' XAUTHORITY='$xauth_env'"
    [[ -n "$wayland_display" ]] && env_vars="$env_vars WAYLAND_DISPLAY='$wayland_display'"

    local wrapper_cmd="$wrapper_script '$ROLLBACK_STATUS_FILE' '$LOG_FILE'"
    local pkexec_cmd="pkexec env $env_vars $wrapper_cmd"

    local terminal_cmd
    terminal_cmd=$(build_terminal_cmd "$TERMINAL" "$pkexec_cmd")

    log "Starting rollback in new terminal window..."
    eval "$terminal_cmd" &
    local terminal_pid=$!
    log "Rollback process launched (PID: $terminal_pid) — monitoring progress..."

    if wait_for_rollback_completion; then
        log_success "System rollback completed successfully!"
        rm -f "$wrapper_script" "$ROLLBACK_STATUS_FILE" 2>/dev/null || true
        handle_post_rollback
    else
        local wait_exit=$?
        log_warn "Rollback encountered an issue or timed out (code: $wait_exit)"
        kill -0 "$terminal_pid" 2>/dev/null && sleep 10
        rm -f "$wrapper_script" "$ROLLBACK_STATUS_FILE" 2>/dev/null || true
        exit 1
    fi

    log_success "Done"
    exit 0
}

main "$@"
