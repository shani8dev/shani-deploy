#!/usr/bin/env bash
#
# startup-check: detect fallback boot and prompt user for rollback on Shani OS
#
# Run as a per-user autostart (.desktop) after login.
# Invokes shani-deploy --rollback via pkexec when a fallback boot is confirmed.

set -Eeuo pipefail
IFS=$'\n\t'

#####################################
### Global Configuration          ###
#####################################

readonly SCRIPT_VERSION="1.1"
readonly OS_NAME="shanios"
readonly LOG_FILE="/var/log/shanios-startup-check.log"
readonly LOCK_FILE="/tmp/shanios-startup-check.lock"
readonly ROLLBACK_STATUS_FILE="/tmp/shanios-startup-check-status"
readonly CURRENT_SLOT_FILE="/data/current-slot"
readonly BOOT_FAILURE_FILE="/data/boot_failure"
readonly BOOT_HARD_FAILURE_FILE="/data/boot_hard_failure"
readonly BOOT_OK_FILE="/data/boot-ok"
readonly DEPLOY_BIN="/usr/local/bin/shani-deploy"

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
}

log_success() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $*"
    echo -e "\033[0;32m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_warn() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $*"
    echo -e "\033[0;33m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*"
    echo -e "\033[0;31m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

die() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [FATAL] $*"
    echo -e "\033[1;31m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
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

# Identical implementation to shani-deploy get_booted_subvol
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

    # Hard failure already written by dracut hook — shani-deploy --rollback handles it
    if [[ -f "$BOOT_HARD_FAILURE_FILE" ]]; then
        log "Hard boot failure marker present — deferring to shani-deploy --rollback path"
        return 1
    fi

    # Boot completed cleanly — nothing to do
    if [[ -f "$BOOT_OK_FILE" ]] && [[ ! -f "$BOOT_FAILURE_FILE" ]]; then
        log "Boot-ok marker present, no failure file — clean boot on @${BOOTED_SLOT}"
        return 1
    fi

    # Read current-slot marker (mirrors shani-deploy validate_boot logic)
    CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | tr -d '[:space:]')

    if [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log_warn "Invalid or missing current-slot marker, using booted slot as reference"
        CURRENT_SLOT="$BOOTED_SLOT"
    fi

    log "Marker: @${CURRENT_SLOT}"
    log "Booted: @${BOOTED_SLOT}"

    # No fallback if booted slot matches the expected current slot
    if [[ "$BOOTED_SLOT" == "$CURRENT_SLOT" ]]; then
        log "Booted slot matches current-slot marker — no fallback detected"
        return 1
    fi

    # Require boot_failure file written by check-boot-failure.sh / dracut hook
    if [[ ! -f "$BOOT_FAILURE_FILE" ]]; then
        log "Boot mismatch present but no failure file — nothing to act on"
        return 1
    fi

    FAILED_SLOT=$(cat "$BOOT_FAILURE_FILE" 2>/dev/null | tr -d '[:space:]')

    # The recorded failure must be the slot that was supposed to boot (CURRENT_SLOT)
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
    # Check environment variables first
    for var in TERMINAL_EMULATOR COLORTERM TERM_PROGRAM; do
        local emu="${!var:-}"
        if [[ -n "$emu" ]] && command -v "$emu" &>/dev/null; then
            echo "$emu"
            return 0
        fi
    done

    # Modern terminals (preferred)
    local modern_terms=(alacritty kitty wezterm foot)
    for term in "${modern_terms[@]}"; do
        command -v "$term" &>/dev/null && echo "$term" && return 0
    done

    # Desktop environment terminals
    local desktop_terms=(
        gnome-terminal kgx tilix xfce4-terminal konsole lxterminal
        mate-terminal deepin-terminal terminator
    )
    for term in "${desktop_terms[@]}"; do
        command -v "$term" &>/dev/null && echo "$term" && return 0
    done

    # Fallback terminals
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
    wrapper_script=$(mktemp /tmp/shanios-rollback-wrapper.XXXXXX)

    # Note: single-quoted heredoc so variables are NOT expanded here;
    # $1 and $2 are positional args passed at call time by the terminal command.
    cat > "$wrapper_script" << 'WRAPPER_EOF'
#!/bin/bash
# Wrapper: runs shani-deploy --rollback and reports status via STATUS_FILE

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
    echo "Rollback failed. Please check /var/log/shanios-deploy.log for details."
    echo ""
    echo "Press Enter to close..."
    read -r
fi
WRAPPER_EOF

    chmod +x "$wrapper_script"
    echo "$wrapper_script"
}

wait_for_rollback_completion() {
    local max_wait_time=3600   # 1 hour
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
                    log_error "Rollback encountered an error during installation"
                    return 1
                    ;;
                RUNNING|INITIALIZING)
                    # Still in progress — keep polling
                    ;;
                *)
                    log_warn "Rollback status unknown: $status"
                    ;;
            esac
        fi

        sleep "$check_interval"
        elapsed=$(( elapsed + check_interval ))

        # Log progress every 2 minutes to keep audit trail alive
        if [[ $(( elapsed % 120 )) -eq 0 ]]; then
            log "Rollback still in progress... ($((elapsed / 60)) minutes elapsed)"
        fi
    done

    log_warn "Rollback process timed out after $((max_wait_time / 60)) minutes — this may indicate a problem"
    return 1
}

#####################################
### GUI Dialog — Rollback Prompt  ###
#####################################

decide_rollback() {
    local failed_slot="$1"
    local booted_slot="$2"

    local message="Boot failure detected!\n\nSlot '@${failed_slot}' failed to boot completely.\nThe system automatically fell back to '@${booted_slot}'.\n\nWould you like to rollback now to restore '@${failed_slot}' to a working state?\n\nNote: The system will continue running on '@${booted_slot}' during the rollback."

    local session_type="${XDG_SESSION_TYPE:-unknown}"
    log "Desktop session: $session_type (${XDG_CURRENT_DESKTOP:-unknown})"
    log "GUI tools available: yad=$(command -v yad 2>/dev/null || echo 'not found'), zenity=$(command -v zenity 2>/dev/null || echo 'not found'), kdialog=$(command -v kdialog 2>/dev/null || echo 'not found')"

    # For Wayland sessions, prefer native Wayland dialogs
    if [[ "$session_type" == "wayland" ]]; then
        log "Using Wayland-native dialog system"

        if [[ "${XDG_CURRENT_DESKTOP,,}" =~ kde ]] && command -v kdialog &>/dev/null; then
            log "Showing KDE rollback dialog..."
            if kdialog --title "Shani OS - Boot Failure Detected" \
                       --yesno "$(echo -e "$message")" \
                       --yes-label "Rollback Now" \
                       --no-label "Ignore" 2>/dev/null; then
                log "User chose to rollback (via kdialog - wayland)"
                return 0
            else
                log "User chose to ignore rollback (via kdialog - wayland)"
                return 1
            fi
        elif [[ "${XDG_CURRENT_DESKTOP,,}" =~ gnome ]] && command -v zenity &>/dev/null; then
            log "Showing GNOME rollback dialog..."
            if zenity --question \
                      --title="Shani OS - Boot Failure Detected" \
                      --width=450 \
                      --text="$(echo -e "$message")" \
                      --ok-label="Rollback Now" \
                      --cancel-label="Ignore" \
                      --timeout=120 2>/dev/null; then
                log "User chose to rollback (via zenity - wayland)"
                return 0
            else
                log "User chose to ignore rollback or dialog timed out (via zenity - wayland)"
                return 1
            fi
        fi
        log "Falling back to alternative dialog systems..."
    fi

    # Try yad with explicit backend selection
    if command -v yad &>/dev/null; then
        log "Attempting yad rollback dialog..."

        local backends=("x11" "wayland" "")
        for backend in "${backends[@]}"; do
            local env_cmd=""
            if [[ -n "$backend" ]]; then
                env_cmd="GDK_BACKEND=$backend "
                log "Trying yad with $backend backend"
            else
                log "Trying yad with system default backend"
            fi

            if eval "${env_cmd}yad --title='Shani OS - Boot Failure Detected' \
                   --width=500 --height=220 \
                   --center \
                   --text='$(echo -e \"$message\")' \
                   --image='dialog-warning' \
                   --button='Rollback Now:0' \
                   --button='Ignore:1' \
                   --timeout=120" 2>/dev/null; then
                log "User chose to rollback (via yad - ${backend:-default})"
                return 0
            else
                local exit_code=$?
                log "yad dialog result: exit code $exit_code (backend: ${backend:-default})"
                if [[ $exit_code -eq 1 ]]; then
                    log "User chose to ignore rollback (via yad - ${backend:-default})"
                    return 1
                elif [[ $exit_code -eq 70 ]]; then
                    log "Rollback dialog timed out, treating as ignore"
                    return 1
                fi
                # Continue to try next backend
            fi
        done

        log "All yad backends failed, trying other dialog systems"
    fi

    # Try zenity
    if command -v zenity &>/dev/null; then
        log "Attempting zenity rollback dialog..."
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
            log "User chose to ignore rollback or dialog timed out (via zenity)"
            return 1
        fi
    fi

    # Try kdialog
    if command -v kdialog &>/dev/null; then
        log "Attempting kdialog rollback dialog..."
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

    # Fallback: notification + console
    log "No GUI dialogs available, trying notification with console fallback"
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
        echo "The system fell back after '@${failed_slot}' failed to boot." >&2
        echo ""                                        >&2
        read -rp "Rollback now? [y/N]: " -t 60 response || response="n"
        case "$response" in
            [Yy]*)
                log "User chose to rollback (via console)"
                return 0
                ;;
            *)
                log "User chose to ignore rollback (via console)"
                return 1
                ;;
        esac
    else
        log "No interactive interfaces available, defaulting to ignore"
    fi

    return 1
}

#####################################
### GUI Dialog — Post-Rollback    ###
#####################################

handle_post_rollback() {
    local reboot_message="Rollback completed successfully!\n\n'@${FAILED_SLOT}' has been restored to a working state.\n\nTo complete the rollback, please restart your computer now.\nThe system will boot back into '@${BOOTED_SLOT}'."
    local reboot_now=false

    if command -v yad &>/dev/null; then
        if yad --title="Rollback Complete - Restart Recommended" \
               --width=450 --height=180 \
               --center --on-top \
               --text="$(echo -e "$reboot_message")" \
               --image="system-restart" \
               --button="Restart Now:0" \
               --button="Restart Later:1" \
               --timeout=300 2>/dev/null; then
            reboot_now=true
        else
            reboot_now=false
        fi
    elif command -v zenity &>/dev/null; then
        if zenity --question \
                  --title="Rollback Complete - Restart Recommended" \
                  --width=450 \
                  --text="$(echo -e "$reboot_message")" \
                  --ok-label="Restart Now" \
                  --cancel-label="Restart Later" \
                  --timeout=300 2>/dev/null; then
            reboot_now=true
        else
            reboot_now=false
        fi
    elif command -v kdialog &>/dev/null; then
        if kdialog --title "Rollback Complete - Restart Recommended" \
                   --yesno "$(echo -e "$reboot_message")" \
                   --yes-label "Restart Now" \
                   --no-label "Restart Later" 2>/dev/null; then
            reboot_now=true
        else
            reboot_now=false
        fi
    else
        # Console fallback
        if [[ -t 0 ]] && [[ -t 1 ]]; then
            echo "" >&2
            echo "✓ Rollback completed successfully!" >&2
            echo "" >&2
            echo "A restart is required to boot normally." >&2
            read -rp "Would you like to restart now? [y/N]: " -t 60 response || response="n"
            case "$response" in
                [Yy]*) reboot_now=true ;;
                *)     reboot_now=false ;;
            esac
        else
            if command -v notify-send &>/dev/null; then
                notify-send -u normal \
                           -i dialog-information \
                           "Shani OS Rollback Complete" \
                           "Rollback successful! Restart when convenient to activate all changes." 2>/dev/null || true
            fi
            reboot_now=false
        fi
    fi

    if [[ "$reboot_now" == "true" ]]; then
        log "User requested immediate restart to complete rollback"
        if pkexec systemctl reboot 2>/dev/null; then
            log "System restart initiated successfully"
        else
            log_warn "Unable to restart automatically — trying alternative method..."
            if pkexec shutdown -r now 2>/dev/null; then
                log "System restart initiated via shutdown command"
            else
                log_warn "Automatic restart failed — user will need to restart manually"
            fi
        fi
    else
        log "User chose to restart later — rollback complete"
        if command -v notify-send &>/dev/null; then
            notify-send -u low \
                       -i dialog-information \
                       "Shani OS Rollback Complete" \
                       "Rollback successful. Remember to restart when convenient." 2>/dev/null || true
        fi
    fi
}

#####################################
### Main                          ###
#####################################

main() {
    log_section "Startup Boot Check"
    log "Shani OS startup-check starting (v$SCRIPT_VERSION)"

    # Must have a display to show anything useful
    if [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        log "No display available — cannot show GUI. Exiting."
        exit 0
    fi

    acquire_lock
    trap 'release_lock' EXIT INT TERM

    # Detect fallback; exit cleanly if nothing to do
    if ! check_fallback_condition; then
        log_success "No rollback action required"
        exit 0
    fi

    # Find a terminal emulator for the rollback window
    if ! TERMINAL=$(find_terminal); then
        log_error "No suitable terminal emulator found. Please install: gnome-terminal, alacritty, kitty, or xterm"
        exit 1
    fi
    log "Terminal for rollback: $TERMINAL"

    # Ask the user
    if ! decide_rollback "$FAILED_SLOT" "$BOOTED_SLOT"; then
        log "User declined rollback — exiting"
        exit 0
    fi

    log_section "Rollback"
    log "User approved rollback — preparing to rollback '@${FAILED_SLOT}'"

    # Initialise status file before launching terminal
    echo "INITIALIZING" > "$ROLLBACK_STATUS_FILE"

    local wrapper_script
    if ! wrapper_script=$(create_rollback_wrapper); then
        log_error "Unable to prepare rollback wrapper script"
        rm -f "$ROLLBACK_STATUS_FILE"
        exit 1
    fi

    # Preserve GUI environment so pkexec can render dialogs inside the terminal
    local display_env="${DISPLAY:-:0}"
    local xauth_env="${XAUTHORITY:-$HOME/.Xauthority}"
    local wayland_display="${WAYLAND_DISPLAY:-}"

    local env_vars="DISPLAY='$display_env' XAUTHORITY='$xauth_env'"
    [[ -n "$wayland_display" ]] && env_vars="$env_vars WAYLAND_DISPLAY='$wayland_display'"

    # Wrapper is executable (+x) — invoke it directly; pkexec handles privilege elevation
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
        rm -f "$wrapper_script" 2>/dev/null || true
        rm -f "$ROLLBACK_STATUS_FILE" 2>/dev/null || true
        handle_post_rollback
    else
        local wait_exit=$?
        log_warn "Rollback encountered an issue or timed out (code: $wait_exit)"

        # Give user time to read any error output still visible in the terminal
        if kill -0 "$terminal_pid" 2>/dev/null; then
            log_warn "Rollback terminal still active — user may be reviewing error messages"
            sleep 10
        fi

        rm -f "$wrapper_script" 2>/dev/null || true
        rm -f "$ROLLBACK_STATUS_FILE" 2>/dev/null || true
        exit 1
    fi

    log_success "Done"
    exit 0
}

main "$@"
