#!/usr/bin/env bash
# shani-update: per-user update checker for Shani OS via systemd --user
# Improved version with better error handling, security, and robustness
set -Eeuo pipefail
IFS=$'\n\t'

# Constants
readonly SCRIPT_VERSION="2.0"
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

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Lock mechanism to prevent multiple instances
acquire_lock() {
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        if [[ -f "$LOCK_FILE/pid" ]]; then
            local lock_pid
            lock_pid=$(cat "$LOCK_FILE/pid" 2>/dev/null || echo "")
            if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
                err "Another instance is already running (PID: $lock_pid)"
            else
                log "Removing stale lock file"
                rm -rf "$LOCK_FILE"
                mkdir "$LOCK_FILE" || err "Failed to acquire lock"
            fi
        else
            err "Failed to acquire lock"
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
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 1048576 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
    fi
    
    echo "[$timestamp] $msg" | tee -a "$LOG_FILE"
    
    # Also log to systemd journal if available
    if command -v systemd-cat &>/dev/null; then
        echo "$msg" | systemd-cat -t "$LOG_TAG"
    elif command -v logger &>/dev/null; then
        logger -t "$LOG_TAG" "$msg"
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
    # Check if we're running in a supported environment
    if [[ ! -d /etc ]] || [[ ! -d /usr ]]; then
        err "Invalid system environment"
    fi
    
    # Check for required commands
    local required_cmds=(curl bash mkdir rm)
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            err "Required command not found: $cmd"
        fi
    done
    
    # Validate systemd user session
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
    content=$(head -n1 "$file" 2>/dev/null | tr -cd "$filter")
    
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
    temp_file=$(mktemp) || err "Failed to create temporary file"
    
    # Ensure cleanup of temp file
    trap "rm -f '$temp_file'; cleanup_and_exit" EXIT INT TERM
    
    log "Fetching update information from: $channel_url"
    
    if ! curl -fsSL \
        --retry "$CURL_RETRIES" \
        --retry-delay "$CURL_RETRY_DELAY" \
        --max-time "$NETWORK_TIMEOUT" \
        --connect-timeout 10 \
        --user-agent "shani-update/$SCRIPT_VERSION" \
        --output "$temp_file" \
        "$channel_url"; then
        rm -f "$temp_file"
        return 1
    fi
    
    # Validate file size (shouldn't be too large for a version string)
    local file_size
    file_size=$(stat -f%z "$temp_file" 2>/dev/null || stat -c%s "$temp_file" 2>/dev/null || echo 0)
    if [[ "$file_size" -gt 1024 ]]; then
        rm -f "$temp_file"
        err "Remote response too large: $file_size bytes"
    fi
    
    local content
    content=$(head -n1 "$temp_file" | tr -cd 'A-Za-z0-9.-')
    rm -f "$temp_file"
    
    if [[ -z "$content" ]]; then
        return 1
    fi
    
    echo "$content"
}

# Enhanced version comparison
version_compare() {
    local v1="$1" v2="$2"
    
    # Simple numeric comparison for now
    if [[ "$v1" -eq "$v2" ]]; then
        return 0  # Equal
    elif [[ "$v1" -lt "$v2" ]]; then
        return 1  # v1 < v2 (update available)
    else
        return 2  # v1 > v2 (downgrade)
    fi
}

# GUI decision with timeout and accessibility
decide_action() {
    local current="v$LOCAL_VERSION-$LOCAL_PROFILE"
    local remote="v$REMOTE_VERSION-$REMOTE_PROFILE"
    local message="Update available!\nCurrent: $current\nNew: $remote\n\nWould you like to update now?"
    
    # Try modern dialog first
    if command -v yad &>/dev/null; then
        if yad --title="Shani OS Update" \
               --width=450 --height=200 \
               --center --on-top \
               --text="$message" \
               --image="software-update-available" \
               --button="Update Now!gtk-yes:0" \
               --button="Remind Later!gtk-cancel:1" \
               --timeout=120 \
               --timeout-label="Remind Later" \
               --no-escape; then
            return 0
        else
            return 1
        fi
    elif command -v zenity &>/dev/null; then
        if zenity --question \
                  --title="Shani OS Update" \
                  --width=400 \
                  --text="$message" \
                  --ok-label="Update Now" \
                  --cancel-label="Remind Later" \
                  --timeout=120; then
            return 0
        else
            return 1
        fi
    elif command -v kdialog &>/dev/null; then
        if kdialog --title "Shani OS Update" \
                   --yesno "$message" \
                   --yes-label "Update Now" \
                   --no-label "Remind Later"; then
            return 0
        else
            return 1
        fi
    else
        # Fallback to notification
        if command -v notify-send &>/dev/null; then
            notify-send -u critical \
                       -i software-update-available \
                       "Shani OS Update Available" \
                       "Current: $current → New: $remote\nClick to view update options"
        fi
        
        # Console fallback if no GUI available
        if [[ -t 0 ]] && [[ -t 1 ]]; then
            echo "=== Shani OS Update Available ==="
            echo "Current: $current"
            echo "New: $remote"
            read -rp "Update now? [y/N]: " -t 60 response || response="n"
            case "$response" in
                [Yy]*) return 0 ;;
                *) return 1 ;;
            esac
        fi
        
        return 1
    fi
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
            echo "$terminal --title 'Shani OS Update' --hold -e bash -c $escaped_cmd"
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

# Main execution flow
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
    LOCAL_VERSION=$(read_file_or_default "$LOCAL_VERSION_FILE" "0" "0-9")
    LOCAL_PROFILE=$(read_file_or_default "$LOCAL_PROFILE_FILE" "default" "A-Za-z")
    
    # Validate local version format
    if [[ ! "$LOCAL_VERSION" =~ ^[0-9]+$ ]]; then
        warn "Invalid local version format: $LOCAL_VERSION, treating as 0"
        LOCAL_VERSION="0"
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
    if [[ "$remote_image" =~ ^shanios-([0-9]+)-([A-Za-z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"
    else
        err "Invalid remote image format: '$remote_image' (expected: shanios-VERSION-PROFILE.zst)"
    fi
    
    log "Remote version: v$REMOTE_VERSION-$REMOTE_PROFILE"
    
    # Compare versions
    version_compare "$LOCAL_VERSION" "$REMOTE_VERSION"
    case $? in
        0)
            if [[ "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
                log "System is up-to-date (v$LOCAL_VERSION-$LOCAL_PROFILE)"
                exit 0
            else
                log "Profile change detected: $LOCAL_PROFILE → $REMOTE_PROFILE"
            fi
            ;;
        1)
            log "Update available: v$LOCAL_VERSION → v$REMOTE_VERSION"
            ;;
        2)
            warn "Remote version is older than local version (downgrade scenario)"
            ;;
    esac
    
    # User decision
    if ! decide_action; then
        log "Update deferred by user. Scheduling reminder in $DEFER_DELAY seconds..."
        
        if systemctl --user status &>/dev/null; then
            systemd-run --user \
                       --unit="$LOG_TAG-defer-$(date +%s)" \
                       --description="Deferred Shani OS update reminder" \
                       --on-active="${DEFER_DELAY}s" \
                       "$0" || warn "Failed to schedule reminder"
        else
            warn "Cannot schedule reminder: systemd user session unavailable"
        fi
        
        exit 0
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
    local env_cmd="env DISPLAY='$display_env' XAUTHORITY='$xauth_env'"
    
    if [[ -n "$wayland_display" ]]; then
        env_cmd="$env_cmd WAYLAND_DISPLAY='$wayland_display'"
    fi
    
    local full_cmd="$inhibit_cmd bash -c '$update_cmd || (echo \"Update failed. Press Enter to continue...\"; read)'"
    local pkexec_cmd="pkexec $env_cmd bash -c \"$full_cmd\""
    local terminal_cmd
    terminal_cmd=$(build_terminal_cmd "$TERMINAL" "$pkexec_cmd")
    
    log "Launching update in terminal..."
    log "Command: $terminal_cmd"
    
    # Execute update
    if bash -c "$terminal_cmd"; then
        log "Update process completed successfully"
        
        # Post-update actions
        handle_post_update
    else
        err "Update process failed or was cancelled"
    fi
}

# Handle post-update actions
handle_post_update() {
    log "Handling post-update actions..."
    
    # Prompt for reboot
    local reboot_message="Update completed successfully!\n\nA system restart is recommended to ensure all changes take effect."
    
    if command -v yad &>/dev/null; then
        if yad --title="Update Complete" \
               --width=400 --height=150 \
               --center --on-top \
               --text="$reboot_message" \
               --image="system-restart" \
               --button="Restart Now!gtk-yes:0" \
               --button="Restart Later!gtk-no:1" \
               --timeout=300 \
               --timeout-label="Restart Later"; then
            reboot_now=true
        else
            reboot_now=false
        fi
    elif command -v zenity &>/dev/null; then
        if zenity --question \
                  --title="Update Complete" \
                  --text="$reboot_message" \
                  --ok-label="Restart Now" \
                  --cancel-label="Restart Later" \
                  --timeout=300; then
            reboot_now=true
        else
            reboot_now=false
        fi
    else
        # Console fallback
        if [[ -t 0 ]] && [[ -t 1 ]]; then
            echo "Update completed successfully!"
            read -rp "Restart now to complete the update? [y/N]: " -t 60 response || response="n"
            case "$response" in
                [Yy]*) reboot_now=true ;;
                *) reboot_now=false ;;
            esac
        else
            notify-send -u normal \
                       -i system-restart \
                       "Shani OS Update Complete" \
                       "System restart recommended to complete update"
            reboot_now=false
        fi
    fi
    
    if [[ "$reboot_now" == "true" ]]; then
        log "Initiating system restart..."
        if pkexec shutdown -r now; then
            log "Restart initiated successfully"
        else
            warn "Failed to initiate restart - user may need to restart manually"
        fi
    else
        log "User chose to restart later"
        if command -v notify-send &>/dev/null; then
            notify-send -u low \
                       -i software-update-available \
                       "Shani OS" \
                       "Remember to restart your system to complete the update"
        fi
    fi
}

# Run main function
main "$@"
