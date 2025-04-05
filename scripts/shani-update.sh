#!/bin/bash
# shani-update: Robust update check for Shani OS with persistent log display,
# suspend and event inhibition, and safe terminal toggling.
#
# Functionality:
#  • Checks local and remote version info.
#  • If an update is available, displays a dialog with three buttons:
#         "Update", "Toggle Terminal", and "Remind Me Later".
#  • "Update" launches the update process (shani-deploy) using systemd-inhibit
#    to block events (shutdown, sleep, idle, lid-switch, power-key, suspend-key,
#    and hibernate-key) so that the update is uninterrupted. Its output is
#    redirected to a log file.
#  • "Toggle Terminal" toggles the log window (opening it if closed, or closing
#    it if open) without starting a new update.
#  • "Remind Me Later" defers the update prompt via systemd-run.
#
# Dependencies: curl, yad, systemd-run, systemd-inhibit, pkexec, nohup, mktemp, pgrep

### Configuration
DEFER_DELAY=300                       # Defer delay in seconds (5 minutes)
UPDATE_CHANNEL="stable"
BASE_URL="https://sourceforge.net/projects/shanios/files"
LOCAL_VERSION_FILE="/etc/shani-version"
LOCAL_PROFILE_FILE="/etc/shani-profile"
TMP_LOG="/tmp/shani_update_log"         # Log file for update output
TMP_PID="/tmp/shani_update_terminal.pid"  # File to store log window PID

### Dependency Check
for cmd in curl yad systemd-run systemd-inhibit pkexec nohup mktemp pgrep; do
    command -v "$cmd" >/dev/null || { echo "ERROR: $cmd is not installed. Exiting." >&2; exit 1; }
done

### Ensure DISPLAY is set
[ -z "$DISPLAY" ] && export DISPLAY=:0

### Read Local Version and Profile
LOCAL_VERSION=$( (cat "$LOCAL_VERSION_FILE" 2>/dev/null || echo "0") | tr -d '[:space:]' )
LOCAL_PROFILE=$( (cat "$LOCAL_PROFILE_FILE" 2>/dev/null || echo "default") | tr -d '[:space:]' )

### Fetch Remote Update Info
CHANNEL_URL="$BASE_URL/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
# Added -L flag to follow redirects from SourceForge
REMOTE_IMAGE=$(curl -L --fail --silent --max-time 30 "$CHANNEL_URL" | tr -d '[:space:]')
if [ -z "$REMOTE_IMAGE" ]; then
    echo "ERROR: Failed to retrieve update info from $CHANNEL_URL" >&2
    exit 1
fi

if [[ "$REMOTE_IMAGE" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]]; then
    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"
else
    echo "ERROR: Unexpected update info format: $REMOTE_IMAGE" >&2
    exit 1
fi

### Exit Silently if Up-To-Date
if [ "$LOCAL_VERSION" -eq "$REMOTE_VERSION" ] && [ "$LOCAL_PROFILE" = "$REMOTE_PROFILE" ]; then
    exit 0
fi

### Functions

# Check if the update process (shani-deploy) is already running.
is_update_running() {
    pgrep -f "shani-deploy" >/dev/null 2>&1
}

# Start the update process using systemd-inhibit (blocking shutdown, sleep, idle,
# lid-switch, power-key, suspend-key, and hibernate-key events). It uses the
# SYSTEMD_INHIBITED environment variable to ensure the inhibitor is applied only once.
start_update() {
    if is_update_running; then
        return
    fi
    : > "$TMP_LOG"  # Clear or create the log file.
    if [ -z "${SYSTEMD_INHIBITED:-}" ]; then
        export SYSTEMD_INHIBITED=1
    fi
    nohup systemd-inhibit --what=shutdown:sleep:idle:handle-lid-switch:handle-power-key:handle-suspend-key:handle-hibernate-key \
         --who="Shani OS Update" --why="Running system update" \
         pkexec /usr/local/bin/shani-deploy >>"$TMP_LOG" 2>&1 &
}

# Open the persistent log window if not already open.
open_log_window() {
    yad --text-info --title="Update Progress (v$REMOTE_VERSION)" \
        --filename="$TMP_LOG" --follow --undecorated --width=600 --height=400 &
    echo $! > "$TMP_PID"
}

# Close the log window if it is open and running.
close_log_window() {
    if [ -f "$TMP_PID" ]; then
        TERM_PID=$(cat "$TMP_PID")
        if kill -0 "$TERM_PID" 2>/dev/null; then
            kill "$TERM_PID" 2>/dev/null
        fi
        rm -f "$TMP_PID"
    fi
}

# Toggle the log window ONLY if an update is running.
toggle_terminal() {
    # Clean up stale PID file.
    if [ -f "$TMP_PID" ] && ! kill -0 "$(cat "$TMP_PID")" 2>/dev/null; then
        rm -f "$TMP_PID"
    fi
    if is_update_running; then
        if [ -f "$TMP_PID" ]; then
            close_log_window
        else
            open_log_window
        fi
    else
        yad --info --title="No Update Running" \
            --text="There is no update currently running." --width=300
    fi
}

# Defer the update prompt.
defer_update() {
    systemd-run --user --on-active="$DEFER_DELAY" "$0"
}

# Wait until the update process finishes.
wait_for_update() {
    while is_update_running; do
        sleep 1
    done
}

# Show a modal completion dialog.
show_completion_dialog() {
    yad --info --title="Update Complete" \
        --text="The update has completed. Click OK to close the log window." \
        --button="OK":0
}

### Main Dialog
ACTION=$(yad --title="Shani OS Update" --width=400 --center \
         --text="New update available (v$REMOTE_VERSION).\n\nChoose an action:" \
         --button="Update":0 --button="Toggle Terminal":1 --button="Remind Me Later":2)

case $? in
    0)
        # "Update" pressed.
        start_update
        open_log_window
        wait_for_update
        show_completion_dialog
        close_log_window
        ;;
    1)
        # "Toggle Terminal" pressed.
        toggle_terminal
        ;;
    *)
        # "Remind Me Later" pressed.
        defer_update
        ;;
esac

exit 0

