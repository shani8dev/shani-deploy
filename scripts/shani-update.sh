#!/usr/bin/env bash
# shani-update: per-user update checker for Shani OS via systemd --user
# Fixed version - resolves early exit after comparison
set -Eeuo pipefail
IFS=$'\n\t'

# Constants
readonly SCRIPT_VERSION="2.2"
readonly DEFER_DELAY=300
readonly UPDATE_CHANNEL="stable"
readonly BASE_URL="https://sourceforge.net/projects/shanios/files"
readonly LOCAL_VERSION_FILE="/etc/shani-version"
readonly LOCAL_PROFILE_FILE="/etc/shani-profile"
readonly LOG_TAG="shani-update"
readonly LOG_DIR="${XDG_CACHE_HOME:-$HOME/.cache}"
readonly LOG_FILE="$LOG_DIR/shani-update.log"
readonly LOCK_FILE="$LOG_DIR/shani-update.lock"
readonly NETWORK_TIMEOUT=30
readonly CURL_RETRIES=3
readonly CURL_RETRY_DELAY=5

# Global variables
LOCAL_VERSION=""
LOCAL_PROFILE=""
REMOTE_VERSION=""
REMOTE_PROFILE=""
TERMINAL=""

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Lock mechanism to prevent multiple instances
acquire_lock() {
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        if [[ -f "$LOCK_FILE/pid" ]]; then
            local lock_pid
            lock_pid=$(cat "$LOCK_FILE/pid" 2>/dev/null || echo "")
            if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
                echo "ERROR: Another instance is already running (PID: $lock_pid)" >&2
                exit 1
            else
                log "Removing stale lock file"
                rm -rf "$LOCK_FILE"
                mkdir "$LOCK_FILE" || {
                    echo "ERROR: Failed to acquire lock" >&2
                    exit 1
                }
            fi
        else
            echo "ERROR: Failed to acquire lock" >&2
            exit 1
        fi
    fi
    echo $$ > "$LOCK_FILE/pid"
    trap 'cleanup_and_exit' EXIT INT TERM
}

cleanup_and_exit() {
    rm -rf "$LOCK_FILE" 2>/dev/null || true
    log "Exiting (script version $SCRIPT_VERSION)"
    exit "${1:-0}"
}

# Enhanced logging with log rotation
log() {
    local msg="$*"
    local timestamp
    timestamp=$(date '+%F %T')

    # Rotate log if it gets too large (>1MB)
    if [[ -f "$LOG_FILE" ]]; then
        local file_size=0
        if command -v stat >/dev/null 2>&1; then
            file_size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        fi
        if [[ $file_size -gt 1048576 ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
        fi
    fi

    # Write to log file and stderr
    echo "[$timestamp] $msg" >> "$LOG_FILE"
    echo "[$timestamp] $msg" >&2

    # Also log to systemd journal if available
    if command -v systemd-cat &>/dev/null; then
        echo "$msg" | systemd-cat -t "$LOG_TAG" 2>/dev/null || true
    elif command -v logger &>/dev/null; then
        logger -t "$LOG_TAG" "$msg" 2>/dev/null || true
    fi
}

err() {
    log "ERROR: $*"
    cleanup_and_exit 1
}

warn() {
    log "WARNING: $*"
}

# Validate environment
validate_environment() {
    if [[ ! -d /etc ]] || [[ ! -d /usr ]]; then
        err "Invalid system environment"
    fi

    local required_cmds=(curl bash mkdir rm)
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Required command not found: $cmd"
        fi
    done

    if ! systemctl --user status &>/dev/null; then
        warn "systemd user session not available, some features may not work"
    fi
}

# Enhanced terminal detection with fallback priorities
find_terminal() {
    # First check environment variables
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
        if command -v "$term" &>/dev/null; then
            echo "$term"
            return 0
        fi
    done

    # Desktop environment terminals
    local desktop_terms=(
        gnome-terminal kgx tilix xfce4-terminal konsole lxterminal
        mate-terminal deepin-terminal terminator
    )
    for term in "${desktop_terms[@]}"; do
        if command -v "$term" &>/dev/null; then
            echo "$term"
            return 0
        fi
    done

    # Fallback terminals
    local fallback_terms=(xterm urxvt st)
    for term in "${fallback_terms[@]}"; do
        if command -v "$term" &>/dev/null; then
            echo "$term"
            return 0
        fi
    done

    # Terminal multiplexers (last resort)
    for term in screen tmux; do
        if command -v "$term" &>/dev/null; then
            echo "$term"
            return 0
        fi
    done

    return 1
}

# Improved file reading with validation
read_file_or_default() {
    local file="$1" default="$2" filter="$3"

    if [[ ! -r "$file" ]]; then
        echo "$default"
        return 0
    fi

    local content
    content=$(head -n1 "$file" 2>/dev/null | tr -cd "$filter" | xargs echo)

    if [[ -z "$content" ]]; then
        warn "File $file exists but contains invalid data, using default: $default"
        echo "$default"
    else
        echo "$content"
    fi
}

# Enhanced network check
check_network() {
    local test_urls=("https://google.com" "https://github.com" "8.8.8.8")

    for url in "${test_urls[@]}"; do
        if curl -fsSL --connect-timeout 5 --max-time 10 "$url" &>/dev/null; then
            return 0
        fi
    done

    return 1
}

# Secure remote fetch with validation
fetch_remote_info() {
    local channel_url="$1"
    local temp_file
    temp_file=$(mktemp) || {
        log "ERROR: Failed to create temporary file"
        return 1
    }

    log "Fetching update information from: $channel_url"

    if ! curl -fsSL \
        --retry "$CURL_RETRIES" \
        --retry-delay "$CURL_RETRY_DELAY" \
        --max-time "$NETWORK_TIMEOUT" \
        --connect-timeout 10 \
        --user-agent "shani-update/$SCRIPT_VERSION" \
        --output "$temp_file" \
        "$channel_url" 2>/dev/null; then
        rm -f "$temp_file"
        log "ERROR: Failed to fetch from $channel_url"
        return 1
    fi

    # Validate file size (shouldn't be too large for a version string)
    local file_size=0
    if command -v stat >/dev/null 2>&1; then
        file_size=$(stat -f%z "$temp_file" 2>/dev/null || stat -c%s "$temp_file" 2>/dev/null || echo 0)
    fi
    if [[ $file_size -gt 1024 ]]; then
        rm -f "$temp_file"
        log "ERROR: Remote response too large: $file_size bytes"
        return 1
    fi

    local content
    content=$(head -n1 "$temp_file" 2>/dev/null | tr -cd 'A-Za-z0-9.-' | xargs echo)
    rm -f "$temp_file"

    if [[ -z "$content" ]]; then
        log "ERROR: Empty or invalid response from server"
        return 1
    fi

    echo "$content"
}

# FIXED: Validate date format version - prevent octal interpretation
validate_version_format() {
    local version="$1"

    if [[ ! "$version" =~ ^[0-9]{8}$ ]]; then
        return 1
    fi

    # Extract year, month, day
    local year="${version:0:4}"
    local month="${version:4:2}"
    local day="${version:6:2}"

    # FIXED: Use string comparisons to avoid octal interpretation issues
    if [[ "$year" < "2020" ]] || [[ "$year" > "2030" ]]; then
        return 1
    fi

    if [[ "$month" < "01" ]] || [[ "$month" > "12" ]]; then
        return 1
    fi

    if [[ "$day" < "01" ]] || [[ "$day" > "31" ]]; then
        return 1
    fi

    return 0
}

# Enhanced version comparison for date-based versions (YYYYMMDD format)
version_compare() {
    local v1="$1" v2="$2"

    # Ensure both versions are numeric and valid dates
    if [[ ! "$v1" =~ ^[0-9]{8}$ ]] || [[ ! "$v2" =~ ^[0-9]{8}$ ]]; then
        warn "Invalid version format for comparison: v1=$v1, v2=$v2"
        # Fallback to string comparison
        if [[ "$v1" == "$v2" ]]; then
            return 0
        elif [[ "$v1" < "$v2" ]]; then
            return 1
        else
            return 2
        fi
    fi

    # Simple string comparison works fine for YYYYMMDD format since it's lexicographically ordered
    if [[ "$v1" == "$v2" ]]; then
        return 0  # Equal
    elif [[ "$v1" < "$v2" ]]; then
        return 1  # v1 < v2 (update available)
    else
        return 2  # v1 > v2 (local is newer)
    fi
}

# GUI decision with timeout and accessibility - COMPLETELY FIXED
decide_action() {
    local current="v$LOCAL_VERSION-$LOCAL_PROFILE"
    local remote="v$REMOTE_VERSION-$REMOTE_PROFILE"
    local message="Update available!\nCurrent: $current\nNew: $remote\n\nWould you like to update now?"

    # Detect session type for better dialog selection
    local session_type="${XDG_SESSION_TYPE:-unknown}"
    log "Session type: $session_type, Desktop: ${XDG_CURRENT_DESKTOP:-unknown}"
    log "Available GUI tools: yad=$(command -v yad || echo 'not found'), zenity=$(command -v zenity || echo 'not found'), kdialog=$(command -v kdialog || echo 'not found')"

    # For Wayland sessions, prefer native Wayland dialogs
    if [[ "$session_type" == "wayland" ]]; then
        log "Detected Wayland session"
        # Try KDE dialog first on Wayland (most reliable for KDE Plasma)
        if [[ "${XDG_CURRENT_DESKTOP,,}" =~ kde ]] && command -v kdialog &>/dev/null; then
            log "Using kdialog for KDE Wayland session..."
            if kdialog --title "Shani OS Update" \
                       --yesno "$(echo -e "$message")" \
                       --yes-label "Update Now" \
                       --no-label "Remind Later" 2>/dev/null; then
                log "kdialog: user chose Update Now"
                return 0
            else
                log "kdialog: user chose Remind Later"
                return 1
            fi
        # Try GNOME dialog for GNOME Wayland
        elif [[ "${XDG_CURRENT_DESKTOP,,}" =~ gnome ]] && command -v zenity &>/dev/null; then
            log "Using zenity for GNOME Wayland session..."
            if zenity --question \
                      --title="Shani OS Update" \
                      --width=400 \
                      --text="$(echo -e "$message")" \
                      --ok-label="Update Now" \
                      --cancel-label="Remind Later" \
                      --timeout=120 2>/dev/null; then
                log "zenity dialog: user chose Update Now"
                return 0
            else
                log "zenity dialog: user chose Remind Later or timeout"
                return 1
            fi
        fi
        log "No native Wayland dialog available, trying yad with different backends..."
    fi

    # Try yad with explicit backend selection
    if command -v yad &>/dev/null; then
        log "Attempting to show yad dialog..."

        # Try different GDK backends for better compatibility
        local backends=("x11" "wayland" "")

        for backend in "${backends[@]}"; do
            local env_cmd=""
            if [[ -n "$backend" ]]; then
                env_cmd="GDK_BACKEND=$backend "
                log "Trying yad with GDK_BACKEND=$backend"
            else
                log "Trying yad with default backend"
            fi

            if eval "${env_cmd}yad --title='Shani OS Update' \
                   --width=450 --height=200 \
                   --center \
                   --text='$(echo -e \"$message\")' \
                   --image='software-update-available' \
                   --button='Update Now:0' \
                   --button='Remind Later:1' \
                   --timeout=120" 2>/dev/null; then
                log "yad dialog: user chose Update Now (backend: ${backend:-default})"
                return 0
            else
                local exit_code=$?
                log "yad with backend '${backend:-default}' failed with exit code: $exit_code"
                if [[ $exit_code -eq 1 ]]; then
                    log "yad dialog: user chose Remind Later (backend: ${backend:-default})"
                    return 1
                elif [[ $exit_code -eq 70 ]]; then
                    log "yad dialog timed out, treating as 'Remind Later'"
                    return 1
                fi
                # Continue to try next backend
            fi
        done

        log "All yad attempts failed, trying other dialog methods"
    fi

    # Try zenity if available
    if command -v zenity &>/dev/null; then
        log "Attempting to show zenity dialog..."
        if zenity --question \
                  --title="Shani OS Update" \
                  --width=400 \
                  --text="$(echo -e "$message")" \
                  --ok-label="Update Now" \
                  --cancel-label="Remind Later" \
                  --timeout=120 2>/dev/null; then
            log "zenity dialog: user chose Update Now"
            return 0
        else
            log "zenity dialog: user chose Remind Later or timeout"
            return 1
        fi
    fi

    # Try kdialog if available
    if command -v kdialog &>/dev/null; then
        log "Attempting to show kdialog..."
        if kdialog --title "Shani OS Update" \
                   --yesno "$(echo -e "$message")" \
                   --yes-label "Update Now" \
                   --no-label "Remind Later" 2>/dev/null; then
            log "kdialog: user chose Update Now"
            return 0
        else
            log "kdialog: user chose Remind Later"
            return 1
        fi
    fi

    # Fallback to notification + console
    log "No GUI dialog tools worked, trying fallback methods"
    if command -v notify-send &>/dev/null; then
        log "Sending notification..."
        notify-send -u critical \
                   -i software-update-available \
                   "Shani OS Update Available" \
                   "Current: $current → New: $remote. Check terminal for options." 2>/dev/null || true
    fi

    # Console fallback if no GUI available
    if [[ -t 0 ]] && [[ -t 1 ]]; then
        log "Using console fallback for user interaction"
        echo "=== Shani OS Update Available ===" >&2
        echo "Current: $current" >&2
        echo "New: $remote" >&2
        read -rp "Update now? [y/N]: " -t 60 response || response="n"
        case "$response" in
            [Yy]*)
                log "Console: user chose to update"
                return 0
                ;;
            *)
                log "Console: user chose not to update"
                return 1
                ;;
        esac
    else
        log "No interactive terminal available, defaulting to 'Remind Later'"
    fi

    return 1
}

# Enhanced terminal command builder with better escaping
build_terminal_cmd() {
    local terminal="$1"
    local command="$2"
    local escaped_cmd

    # Properly escape the command for shell execution
    escaped_cmd=$(printf '%q' "$command")

    case "$terminal" in
        gnome-terminal|kgx|tilix|xfce4-terminal|lxterminal|mate-terminal|deepin-terminal)
            echo "$terminal --title='Shani OS Update' --geometry=100x30 -- bash -c $escaped_cmd"
            ;;
        konsole)
            echo "$terminal --title 'Shani OS Update' -e bash -c $escaped_cmd"
            ;;
        alacritty)
            echo "$terminal --title 'Shani OS Update' -e bash -c $escaped_cmd"
            ;;
        kitty)
            echo "$terminal --title='Shani OS Update' bash -c $escaped_cmd"
            ;;
        wezterm)
            echo "$terminal start --class 'Shani OS Update' bash -c $escaped_cmd"
            ;;
        foot)
            echo "$terminal --title='Shani OS Update' bash -c $escaped_cmd"
            ;;
        terminator)
            echo "$terminal --title='Shani OS Update' -x bash -c $escaped_cmd"
            ;;
        xterm|urxvt|st)
            echo "$terminal -T 'Shani OS Update' -e bash -c $escaped_cmd"
            ;;
        screen)
            echo "screen -t 'Shani Update' bash -c $escaped_cmd"
            ;;
        tmux)
            echo "tmux new-session -d -s 'shani-update' bash -c $escaped_cmd"
            ;;
        *)
            # Generic fallback
            echo "$terminal -e bash -c $escaped_cmd"
            ;;
    esac
}

# Handle post-update actions
handle_post_update() {
    log "Handling post-update actions..."

    # Prompt for reboot
    local reboot_message="Update completed successfully!\n\nA system restart is recommended to ensure all changes take effect."
    local reboot_now=false

    if command -v yad &>/dev/null; then
        if yad --title="Update Complete" \
               --width=400 --height=150 \
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
                  --title="Update Complete" \
                  --text="$(echo -e "$reboot_message")" \
                  --ok-label="Restart Now" \
                  --cancel-label="Restart Later" \
                  --timeout=300 2>/dev/null; then
            reboot_now=true
        else
            reboot_now=false
        fi
    elif command -v kdialog &>/dev/null; then
        if kdialog --title "Update Complete" \
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
            echo "Update completed successfully!" >&2
            read -rp "Restart now to complete the update? [y/N]: " -t 60 response || response="n"
            case "$response" in
                [Yy]*) reboot_now=true ;;
                *) reboot_now=false ;;
            esac
        else
            if command -v notify-send &>/dev/null; then
                notify-send -u normal \
                           -i system-restart \
                           "Shani OS Update Complete" \
                           "System restart recommended to complete update" 2>/dev/null || true
            fi
            reboot_now=false
        fi
    fi

    if [[ "$reboot_now" == "true" ]]; then
        log "Initiating system restart..."
        if pkexec systemctl reboot 2>/dev/null; then
            log "Restart initiated successfully"
        else
            warn "Failed to initiate reboot via systemctl, trying shutdown command..."
            if pkexec shutdown -r now 2>/dev/null; then
                log "Restart initiated successfully via shutdown"
            else
                warn "Failed to initiate restart - user may need to restart manually"
            fi
        fi
    else
        log "User chose to restart later"
        if command -v notify-send &>/dev/null; then
            notify-send -u low \
                       -i software-update-available \
                       "Shani OS" \
                       "Remember to restart your system to complete the update" 2>/dev/null || true
        fi
    fi
}

# FIXED: Check if update is needed (separate function for clarity)
is_update_needed() {
    local local_ver="$1"
    local local_prof="$2"
    local remote_ver="$3"
    local remote_prof="$4"

    # Compare versions first
    version_compare "$local_ver" "$remote_ver"
    local comparison_result=$?

    case $comparison_result in
        0)
            # Versions are equal - check if profile changed
            if [[ "$local_prof" == "$remote_prof" ]]; then
                log "System is up-to-date (v$local_ver-$local_prof)"
                return 1  # No update needed
            else
                log "Profile change detected: $local_prof → $remote_prof (same version date)"
                return 0  # Update needed for profile change
            fi
            ;;
        1)
            log "Update available: v$local_ver → v$remote_ver (newer version found)"
            return 0  # Update needed
            ;;
        2)
            log "Local version v$local_ver is newer than remote v$remote_ver - no update needed"
            return 1  # No update needed
            ;;
        *)
            err "Version comparison failed with unexpected result: $comparison_result"
            ;;
    esac
}

# FIXED: Main execution flow with proper continuation
main() {
    log "Starting Shani OS update checker (version $SCRIPT_VERSION)"

    # Initialize
    acquire_lock
    validate_environment

    # Find terminal early
    if ! TERMINAL=$(find_terminal); then
        err "No suitable terminal emulator found. Please install: gnome-terminal, alacritty, kitty, or xterm"
    fi
    log "Using terminal: $TERMINAL"

    # Read local version info with validation
    LOCAL_VERSION=$(read_file_or_default "$LOCAL_VERSION_FILE" "19700101" "0-9")
    LOCAL_PROFILE=$(read_file_or_default "$LOCAL_PROFILE_FILE" "default" "A-Za-z")

    # Validate local version format
    if ! validate_version_format "$LOCAL_VERSION"; then
        warn "Invalid local version format: $LOCAL_VERSION, treating as very old version (19700101)"
        LOCAL_VERSION="19700101"
    fi

    log "Local version: v$LOCAL_VERSION-$LOCAL_PROFILE"

    # Check network connectivity
    if ! check_network; then
        err "No network connectivity available"
    fi

    # Fetch remote version info
    local channel_url="$BASE_URL/$LOCAL_PROFILE/$UPDATE_CHANNEL.txt"
    local remote_image

    if ! remote_image=$(fetch_remote_info "$channel_url"); then
        err "Failed to fetch update information from $channel_url"
    fi

    # Parse remote version with enhanced validation
    if [[ "$remote_image" =~ ^shanios-([0-9]{8})-([A-Za-z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"

        # Validate remote version format
        if ! validate_version_format "$REMOTE_VERSION"; then
            err "Invalid remote version format: $REMOTE_VERSION (not a valid date: YYYYMMDD)"
        fi
    else
        err "Invalid remote image format: '$remote_image' (expected: shanios-YYYYMMDD-PROFILE.zst)"
    fi

    log "Remote version: v$REMOTE_VERSION-$REMOTE_PROFILE"

    # Check if update is needed
    log "Checking if update is needed..."
    if ! is_update_needed "$LOCAL_VERSION" "$LOCAL_PROFILE" "$REMOTE_VERSION" "$REMOTE_PROFILE"; then
        log "No update needed, exiting"
        cleanup_and_exit 0
    fi

    log "Update is needed, proceeding to user decision..."

    # User decision - FIXED: Handle the decision properly without exiting early
    if ! decide_action; then
        log "Update deferred by user. Scheduling reminder in $DEFER_DELAY seconds..."

        if systemctl --user status &>/dev/null; then
            local defer_unit="$LOG_TAG-defer-$(date +%s)"
            if systemd-run --user \
                          --unit="$defer_unit" \
                          --description="Deferred Shani OS update reminder" \
                          --on-active="${DEFER_DELAY}s" \
                          "$0" 2>/dev/null; then
                log "Reminder scheduled successfully as unit: $defer_unit"
            else
                warn "Failed to schedule reminder"
            fi
        else
            warn "Cannot schedule reminder: systemd user session unavailable"
        fi

        cleanup_and_exit 0
    fi

    # Prepare for update
    log "User approved update to v$REMOTE_VERSION-$REMOTE_PROFILE"

    # Preserve GUI environment variables
    local display_env="${DISPLAY:-:0}"
    local xauth_env="${XAUTHORITY:-$HOME/.Xauthority}"
    local wayland_display="${WAYLAND_DISPLAY:-}"

    # Build update command with proper error handling
    local update_cmd='/usr/local/bin/shani-deploy'
    local inhibit_cmd="systemd-inhibit --what=shutdown:sleep:idle:handle-power-key:handle-suspend-key:handle-hibernate-key --who='Shani OS Update' --why='System update in progress'"

    # Create the complete command to run
    local complete_cmd="$inhibit_cmd bash -c '$update_cmd || (echo \"Update failed. Press Enter to continue...\"; read)'"

    # For pkexec, we need to preserve environment variables
    local env_vars="DISPLAY='$display_env' XAUTHORITY='$xauth_env'"
    if [[ -n "$wayland_display" ]]; then
        env_vars="$env_vars WAYLAND_DISPLAY='$wayland_display'"
    fi

    local pkexec_cmd="pkexec env $env_vars $complete_cmd"

    local terminal_cmd
    terminal_cmd=$(build_terminal_cmd "$TERMINAL" "$pkexec_cmd")

    log "Launching update in terminal..."
    log "Terminal command: $terminal_cmd"

    # Execute update
    if eval "$terminal_cmd" 2>/dev/null; then
        log "Update process completed successfully"

        # Post-update actions
        handle_post_update
    else
        local exit_code=$?
        warn "Update process failed or was cancelled (exit code: $exit_code)"

        # Clean up temp script if it exists
        if [[ -f "$LOG_DIR/temp_update_script" ]]; then
            local temp_script
            temp_script=$(cat "$LOG_DIR/temp_update_script" 2>/dev/null || echo "")
            if [[ -n "$temp_script" ]] && [[ -f "$temp_script" ]]; then
                rm -f "$temp_script" 2>/dev/null || true
            fi
            rm -f "$LOG_DIR/temp_update_script" 2>/dev/null || true
        fi

        cleanup_and_exit 1
    fi
}

# Run main function
main "$@"
