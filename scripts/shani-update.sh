#!/usr/bin/env bash
# shani-update: per-user update checker for Shani OS via systemd --user
# Enhanced version with candidate slot detection and user-friendly messaging
set -Eeuo pipefail
IFS=$'\n\t'

# Constants
readonly SCRIPT_VERSION="2.4"
readonly DEFER_DELAY=300
readonly UPDATE_CHANNEL="stable"
readonly BASE_URL="https://sourceforge.net/projects/shanios/files"
readonly LOCAL_VERSION_FILE="/etc/shani-version"
readonly LOCAL_PROFILE_FILE="/etc/shani-profile"
readonly CURRENT_SLOT_FILE="/data/current-slot"
readonly LOG_TAG="shani-update"
readonly LOG_DIR="${XDG_CACHE_HOME:-$HOME/.cache}"
readonly LOG_FILE="$LOG_DIR/shani-update.log"
readonly LOCK_FILE="$LOG_DIR/shani-update.lock"
readonly NETWORK_TIMEOUT=30
readonly CURL_RETRIES=3
readonly CURL_RETRY_DELAY=5
readonly UPDATE_STATUS_FILE="$LOG_DIR/shani-update-status"

# Global variables
LOCAL_VERSION=""
LOCAL_PROFILE=""
REMOTE_VERSION=""
REMOTE_PROFILE=""
TERMINAL=""
CURRENT_SLOT=""
BOOTED_SLOT=""

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
    rm -f "$UPDATE_STATUS_FILE" 2>/dev/null || true
    log "Exiting (script version $SCRIPT_VERSION)"
    exit "${1:-0}"
}

# Logging function
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

# Get booted subvolume - adapted from shanios-deploy.sh
get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2-)
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    if [[ -z "$subvol" ]]; then
        subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    fi
    echo "${subvol:-blue}"
}

# Check if system is booted into candidate slot
check_boot_slot_validity() {
    # Read current slot from system state
    if [[ -r "$CURRENT_SLOT_FILE" ]]; then
        CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | xargs)
    fi
    
    # Default to blue if current slot is not set
    if [[ -z "$CURRENT_SLOT" ]]; then
        CURRENT_SLOT="blue"
        log "No active slot marker found, using default: blue"
    fi
    
    # Get the actual booted subvolume
    BOOTED_SLOT=$(get_booted_subvol)
    
    log "Boot validation: Active slot is '$CURRENT_SLOT', currently running from '$BOOTED_SLOT'"
    
    # Check if booted into candidate slot
    if [[ "$BOOTED_SLOT" != "$CURRENT_SLOT" ]]; then
        # Determine what the candidate slot would be
        local candidate_slot
        if [[ "$CURRENT_SLOT" == "blue" ]]; then
            candidate_slot="green"
        else
            candidate_slot="blue"
        fi
        
        # If booted into candidate slot, this is likely a test boot
        if [[ "$BOOTED_SLOT" == "$candidate_slot" ]]; then
            log "Candidate boot detected: Running from candidate subvol"
            log "Update checking temporarily disabled during system validation period"
            log "User should verify system stability before next update cycle"
            
            # Send user-friendly notification
            if command -v notify-send &>/dev/null; then
                notify-send -u normal \
                           -i software-update-available \
                           "Shani OS - System Testing" \
                           "You're running a newly updated system. Please test all your applications and restart when ready to make this version permanent." 2>/dev/null || true
            fi
            
            log "Exiting gracefully - system in post-update validation state"
            cleanup_and_exit 0
        else
            # Booted into some other slot - this shouldn't happen normally
            warn "Unexpected boot configuration detected"
            warn "Running from '$BOOTED_SLOT' but expected '$CURRENT_SLOT' or '$candidate_slot'"
            warn "System may need manual inspection - continuing with caution"
            
            # Still allow update checking but log the anomaly
            log "Proceeding with update check despite unusual boot state"
        fi
    else
        log "Boot validation successful: Running from expected system partition"
    fi
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
    
    # Check for btrfs command availability for slot detection
    if ! command -v btrfs &>/dev/null; then
        warn "btrfs command not available, slot detection may be limited"
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

# Enhanced network check with multiple methods
check_network() {
    log "Verifying internet connectivity for update check..."

    # Method 1: Try ping to common DNS servers (most reliable)
    local dns_servers=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    for dns in "${dns_servers[@]}"; do
        if ping -c 1 -W 5 "$dns" &>/dev/null; then
            log "Network connectivity confirmed via DNS server $dns"
            return 0
        fi
    done

    # Method 2: Try connecting to HTTP endpoints
    local test_urls=("https://www.google.com" "https://github.com" "https://httpbin.org/status/200")
    for url in "${test_urls[@]}"; do
        if curl -fsSL --connect-timeout 5 --max-time 10 --head "$url" &>/dev/null; then
            log "Network connectivity confirmed via web endpoint"
            return 0
        fi
    done

    # Method 3: Try DNS resolution
    if nslookup google.com &>/dev/null || dig +short google.com &>/dev/null || host google.com &>/dev/null; then
        log "Network connectivity confirmed via DNS resolution"
        return 0
    fi

    # Method 4: Check if we can reach the actual update server
    local channel_url="$BASE_URL/$LOCAL_PROFILE/$UPDATE_CHANNEL.txt"
    if curl -fsSL --connect-timeout 10 --max-time 20 --head "$channel_url" &>/dev/null; then
        log "Network connectivity confirmed - update server is reachable"
        return 0
    fi

    log "Unable to connect to the internet - all connectivity tests failed"
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

# Validate date format version - prevent octal interpretation
validate_version_format() {
    local version="$1"

    if [[ ! "$version" =~ ^[0-9]{8}$ ]]; then
        return 1
    fi

    # Extract year, month, day
    local year="${version:0:4}"
    local month="${version:4:2}"
    local day="${version:6:2}"

    # Use string comparisons to avoid octal interpretation issues
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

# GUI decision with timeout and accessibility
decide_action() {
    local current="v$LOCAL_VERSION-$LOCAL_PROFILE"
    local remote="v$REMOTE_VERSION-$REMOTE_PROFILE"
    local message="A new system update is available!\n\nCurrent version: $current\nNew version: $remote\n\nWould you like to install the update now?\n\nNote: The system will download and install in the background. You can continue working during the update process."

    # Detect session type for better dialog selection
    local session_type="${XDG_SESSION_TYPE:-unknown}"
    log "Desktop session: $session_type (${XDG_CURRENT_DESKTOP:-unknown})"
    log "GUI tools available: yad=$(command -v yad || echo 'not found'), zenity=$(command -v zenity || echo 'not found'), kdialog=$(command -v kdialog || echo 'not found')"

    # For Wayland sessions, prefer native Wayland dialogs
    if [[ "$session_type" == "wayland" ]]; then
        log "Using Wayland-native dialog system"
        # Try KDE dialog first on Wayland (most reliable for KDE Plasma)
        if [[ "${XDG_CURRENT_DESKTOP,,}" =~ kde ]] && command -v kdialog &>/dev/null; then
            log "Showing KDE update dialog..."
            if kdialog --title "Shani OS System Update" \
                       --yesno "$(echo -e "$message")" \
                       --yes-label "Install Update" \
                       --no-label "Remind Me Later" 2>/dev/null; then
                log "User chose to install update now"
                return 0
            else
                log "User chose to postpone update"
                return 1
            fi
        # Try GNOME dialog for GNOME Wayland
        elif [[ "${XDG_CURRENT_DESKTOP,,}" =~ gnome ]] && command -v zenity &>/dev/null; then
            log "Showing GNOME update dialog..."
            if zenity --question \
                      --title="Shani OS System Update" \
                      --width=450 \
                      --text="$(echo -e "$message")" \
                      --ok-label="Install Update" \
                      --cancel-label="Remind Me Later" \
                      --timeout=120 2>/dev/null; then
                log "User chose to install update now"
                return 0
            else
                log "User chose to postpone update or dialog timed out"
                return 1
            fi
        fi
        log "Falling back to alternative dialog systems..."
    fi

    # Try yad with explicit backend selection
    if command -v yad &>/dev/null; then
        log "Attempting yad update dialog..."

        # Try different GDK backends for better compatibility
        local backends=("x11" "wayland" "")

        for backend in "${backends[@]}"; do
            local env_cmd=""
            if [[ -n "$backend" ]]; then
                env_cmd="GDK_BACKEND=$backend "
                log "Trying yad with $backend backend"
            else
                log "Trying yad with system default backend"
            fi

            if eval "${env_cmd}yad --title='Shani OS System Update' \
                   --width=500 --height=220 \
                   --center \
                   --text='$(echo -e \"$message\")' \
                   --image='software-update-available' \
                   --button='Install Update:0' \
                   --button='Remind Me Later:1' \
                   --timeout=120" 2>/dev/null; then
                log "User chose to install update (via yad - ${backend:-default})"
                return 0
            else
                local exit_code=$?
                log "yad dialog result: exit code $exit_code (backend: ${backend:-default})"
                if [[ $exit_code -eq 1 ]]; then
                    log "User chose to postpone update (via yad - ${backend:-default})"
                    return 1
                elif [[ $exit_code -eq 70 ]]; then
                    log "Update dialog timed out, treating as postpone request"
                    return 1
                fi
                # Continue to try next backend
            fi
        done

        log "All yad backends failed, trying other dialog systems"
    fi

    # Try zenity if available
    if command -v zenity &>/dev/null; then
        log "Attempting zenity update dialog..."
        if zenity --question \
                  --title="Shani OS System Update" \
                  --width=450 \
                  --text="$(echo -e "$message")" \
                  --ok-label="Install Update" \
                  --cancel-label="Remind Me Later" \
                  --timeout=120 2>/dev/null; then
            log "User chose to install update (via zenity)"
            return 0
        else
            log "User chose to postpone update or zenity dialog timed out"
            return 1
        fi
    fi

    # Try kdialog if available
    if command -v kdialog &>/dev/null; then
        log "Attempting kdialog update dialog..."
        if kdialog --title "Shani OS System Update" \
                   --yesno "$(echo -e "$message")" \
                   --yes-label "Install Update" \
                   --no-label "Remind Me Later" 2>/dev/null; then
            log "User chose to install update (via kdialog)"
            return 0
        else
            log "User chose to postpone update (via kdialog)"
            return 1
        fi
    fi

    # Fallback to notification + console
    log "No GUI dialogs available, trying notification with console fallback"
    if command -v notify-send &>/dev/null; then
        log "Sending update notification to user..."
        notify-send -u critical \
                   -i software-update-available \
                   "Shani OS Update Available" \
                   "System update ready: $current → $remote\nCheck your terminal for installation options." 2>/dev/null || true
    fi

    # Console fallback if no GUI available
    if [[ -t 0 ]] && [[ -t 1 ]]; then
        log "Using console interface for update decision"
        echo "" >&2
        echo "========================================" >&2
        echo "    Shani OS System Update Available" >&2
        echo "========================================" >&2
        echo "Current version: $current" >&2
        echo "New version:     $remote" >&2
        echo "" >&2
        echo "This update will download and install in the background." >&2
        echo "You can continue using your system during the process." >&2
        echo "" >&2
        read -rp "Install update now? [y/N]: " -t 60 response || response="n"
        case "$response" in
            [Yy]*)
                log "User chose to install update (via console)"
                return 0
                ;;
            *)
                log "User chose to postpone update (via console)"
                return 1
                ;;
        esac
    else
        log "No interactive interfaces available, defaulting to postpone update"
    fi

    return 1
}

# Create wrapper script that signals completion
create_update_wrapper() {
    local wrapper_script
    wrapper_script=$(mktemp)

    cat > "$wrapper_script" << 'EOF'
#!/bin/bash
# Wrapper script to track shani-deploy completion

readonly STATUS_FILE="$1"
readonly LOG_FILE="$2"

# Function to log messages
log_message() {
    echo "[$(date '+%F %T')] $*" >> "$LOG_FILE"
}

# Signal that update is starting
echo "RUNNING" > "$STATUS_FILE"
log_message "Update started"

# Run the actual update command with systemd-inhibit
if systemd-inhibit --what=shutdown:sleep:idle:handle-power-key:handle-suspend-key:handle-hibernate-key \
                   --who='Shani OS Update' \
                   --why='System update in progress' \
                   /usr/local/bin/shani-deploy; then
    echo "SUCCESS" > "$STATUS_FILE"
    log_message "Update completed successfully"
    echo "Update completed successfully! You can now close this terminal."
    echo "Press Enter to continue..."
    read
else
    echo "FAILED" > "$STATUS_FILE"
    log_message "Update failed"
    echo "Update failed. Please check the logs."
    echo "Press Enter to continue..."
    read
fi
EOF

    chmod +x "$wrapper_script"
    echo "$wrapper_script"
}

# Wait for update completion by monitoring the status file
wait_for_update_completion() {
    local max_wait_time=7200  # 2 hours maximum wait time
    local check_interval=5    # Check every 5 seconds
    local elapsed=0

    log "Monitoring system update progress (this may take 10-30 minutes)..."
    
    while [[ $elapsed -lt $max_wait_time ]]; do
        if [[ -f "$UPDATE_STATUS_FILE" ]]; then
            local status
            status=$(cat "$UPDATE_STATUS_FILE" 2>/dev/null || echo "UNKNOWN")
            
            case "$status" in
                "SUCCESS")
                    log "System update completed successfully!"
                    return 0
                    ;;
                "FAILED")
                    log "System update encountered an error during installation"
                    return 1
                    ;;
                "RUNNING")
                    # Still running, continue waiting silently
                    ;;
                *)
                    log "Update status unknown: $status"
                    ;;
            esac
        fi
        
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
        
        # Log progress every 2 minutes to keep user informed
        if [[ $((elapsed % 120)) -eq 0 ]]; then
            local minutes=$((elapsed / 60))
            log "Update still in progress... ($minutes minutes elapsed)"
        fi
    done
    
    warn "Update process timed out after $((max_wait_time / 60)) minutes - this may indicate a problem"
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
            echo "$terminal --title='Shani OS Update' -- bash -c $escaped_cmd"
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
    log "System update installation completed - handling post-update tasks..."

    # Prompt for reboot
    local reboot_message="Congratulations! Your system has been successfully updated.\n\nTo complete the update and ensure all new features work properly, we recommend restarting your computer now.\n\nYou can also restart later, but some improvements may not be active until you do."
    local reboot_now=false

    if command -v yad &>/dev/null; then
        if yad --title="Update Complete - Restart Recommended" \
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
                  --title="Update Complete - Restart Recommended" \
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
        if kdialog --title "Update Complete - Restart Recommended" \
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
            echo "✓ System update completed successfully!" >&2
            echo "" >&2
            echo "To activate all new features, a restart is recommended." >&2
            read -rp "Would you like to restart now? [y/N]: " -t 60 response || response="n"
            case "$response" in
                [Yy]*) reboot_now=true ;;
                *) reboot_now=false ;;
            esac
        else
            if command -v notify-send &>/dev/null; then
                notify-send -u normal \
                           -i software-update-available \
                           "Shani OS Update Complete" \
                           "System successfully updated! Restart when convenient to activate all new features." 2>/dev/null || true
            fi
            reboot_now=false
        fi
    fi

    if [[ "$reboot_now" == "true" ]]; then
        log "User requested immediate restart to complete update"
        if pkexec systemctl reboot 2>/dev/null; then
            log "System restart initiated successfully"
        else
            warn "Unable to restart automatically - trying alternative method..."
            if pkexec shutdown -r now 2>/dev/null; then
                log "System restart initiated via shutdown command"
            else
                warn "Automatic restart failed - user will need to restart manually"
            fi
        fi
    else
        log "User chose to restart later - update installation complete"
        if command -v notify-send &>/dev/null; then
            notify-send -u low \
                       -i dialog-information \
                       "Shani OS Update Complete" \
                       "Your system has been updated successfully. Remember to restart when convenient to activate all new features." 2>/dev/null || true
        fi
    fi
}

# Check if update is needed
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
                log "Your system is current - no updates available (v$local_ver-$local_prof)"
                return 1  # No update needed
            else
                log "Profile update available: switching from '$local_prof' to '$remote_prof' profile (same version date)"
                return 0  # Update needed for profile change
            fi
            ;;
        1)
            log "System update available: v$local_ver → v$remote_ver (newer version found)"
            return 0  # Update needed
            ;;
        2)
            log "Your system is ahead of the available release (v$local_ver vs v$remote_ver)"
            return 1  # No update needed
            ;;
        *)
            err "Unable to compare versions properly (comparison result: $comparison_result)"
            ;;
    esac
}

# Main execution flow with proper continuation and process waiting
main() {
    log "Shani OS Update Checker starting (v$SCRIPT_VERSION)"

    # Initialize
    acquire_lock
    validate_environment
    
    # Check boot slot validity early - exit if booted into candidate slot
    check_boot_slot_validity

    # Find terminal early
    if ! TERMINAL=$(find_terminal); then
        err "No suitable terminal emulator found. Please install: gnome-terminal, alacritty, kitty, or xterm"
    fi
    log "Terminal for updates: $TERMINAL"

    # Read local version info with validation
    LOCAL_VERSION=$(read_file_or_default "$LOCAL_VERSION_FILE" "19700101" "0-9")
    LOCAL_PROFILE=$(read_file_or_default "$LOCAL_PROFILE_FILE" "default" "A-Za-z")

    # Validate local version format
    if ! validate_version_format "$LOCAL_VERSION"; then
        warn "System version format appears corrupted, treating as outdated (fallback: 19700101)"
        LOCAL_VERSION="19700101"
    fi

    log "Current system: v$LOCAL_VERSION-$LOCAL_PROFILE"

    # Check network connectivity
    if ! check_network; then
        warn "Internet connection not available - retrying in 30 seconds..."
        sleep 30
        if ! check_network; then
            err "Unable to connect to the internet after retry - update check cannot proceed"
        else
            log "Connection restored - continuing with update check"
        fi
    else
        log "Internet connection confirmed"
    fi

    # Fetch remote version info
    local channel_url="$BASE_URL/$LOCAL_PROFILE/$UPDATE_CHANNEL.txt"
    local remote_image

    log "Checking for available updates from Shani OS servers..."
    if ! remote_image=$(fetch_remote_info "$channel_url"); then
        err "Unable to retrieve update information from server"
    fi

    # Parse remote version with enhanced validation
    if [[ "$remote_image" =~ ^shanios-([0-9]{8})-([A-Za-z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"

        # Validate remote version format
        if ! validate_version_format "$REMOTE_VERSION"; then
            err "Server provided invalid version information: $REMOTE_VERSION (expected format: YYYYMMDD)"
        fi
    else
        err "Server response format error: '$remote_image' (contact support if this persists)"
    fi

    log "Latest available: v$REMOTE_VERSION-$REMOTE_PROFILE"

    # Check if update is needed
    log "Comparing your system version with available updates..."
    if ! is_update_needed "$LOCAL_VERSION" "$LOCAL_PROFILE" "$REMOTE_VERSION" "$REMOTE_PROFILE"; then
        log "Update check complete - your system is current"
        cleanup_and_exit 0
    fi

    log "Update is recommended - asking for user confirmation..."

    # User decision
    if ! decide_action; then
        log "Update postponed by user request - setting reminder for later"

        if systemctl --user status &>/dev/null; then
            local defer_unit="$LOG_TAG-defer-$(date +%s)"
            if systemd-run --user \
                          --unit="$defer_unit" \
                          --description="Deferred Shani OS update reminder" \
                          --on-active="${DEFER_DELAY}s" \
                          "$0" 2>/dev/null; then
                log "Update reminder scheduled successfully in $DEFER_DELAY seconds"
            else
                warn "Could not schedule automatic reminder"
            fi
        else
            warn "Reminder scheduling unavailable - please run update check manually later"
        fi

        cleanup_and_exit 0
    fi

    # Prepare for update
    log "User approved update - preparing to install v$REMOTE_VERSION-$REMOTE_PROFILE"

    # Initialize status file
    echo "INITIALIZING" > "$UPDATE_STATUS_FILE"

    # Create wrapper script for the update process
    local wrapper_script
    if ! wrapper_script=$(create_update_wrapper); then
        err "Unable to prepare update process"
    fi

    # Preserve GUI environment variables
    local display_env="${DISPLAY:-:0}"
    local xauth_env="${XAUTHORITY:-$HOME/.Xauthority}"
    local wayland_display="${WAYLAND_DISPLAY:-}"

    # Build the command to run the wrapper script
    local wrapper_cmd="$wrapper_script '$UPDATE_STATUS_FILE' '$LOG_FILE'"

    # For pkexec, we need to preserve environment variables
    local env_vars="DISPLAY='$display_env' XAUTHORITY='$xauth_env'"
    if [[ -n "$wayland_display" ]]; then
        env_vars="$env_vars WAYLAND_DISPLAY='$wayland_display'"
    fi

    local pkexec_cmd="pkexec env $env_vars $wrapper_cmd"

    local terminal_cmd
    terminal_cmd=$(build_terminal_cmd "$TERMINAL" "$pkexec_cmd")

    log "Starting system update in new terminal window..."

    # Execute update in background and get PID
    eval "$terminal_cmd" &
    local terminal_pid=$!

    log "Update process launched (PID: $terminal_pid) - monitoring progress..."

    # Wait for the update process to complete by monitoring the status file
    if wait_for_update_completion; then
        log "System update completed successfully!"

        # Clean up wrapper script
        rm -f "$wrapper_script" 2>/dev/null || true

        # Post-update actions
        handle_post_update
    else
        local wait_exit_code=$?
        warn "System update encountered an issue or timed out (code: $wait_exit_code)"

        # Check if terminal process is still running
        if kill -0 "$terminal_pid" 2>/dev/null; then
            warn "Update terminal still active - user may be reviewing error messages"
            # Give user some more time to see any error messages
            sleep 10
        fi

        # Clean up wrapper script
        rm -f "$wrapper_script" 2>/dev/null || true

        cleanup_and_exit 1
    fi
}

# Run main function
main "$@"
