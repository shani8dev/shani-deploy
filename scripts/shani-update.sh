#!/bin/bash
# shani-update.sh
# This script checks for new updates and uses YAD to prompt the user.
# If a new update is available, it runs the core shani-deploy script via pkexec.

# Read local version and profile
LOCAL_VERSION=$(cat /etc/shani-version 2>/dev/null || echo "0")
LOCAL_PROFILE=$(cat /etc/shani-profile 2>/dev/null || echo "default")
UPDATE_CHANNEL="stable"  # Change if needed

# Construct the URL for update information
CHANNEL_URL="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"

# Fetch remote update info (expected format: shanios-<version>-<profile>.zst)
REMOTE_IMAGE=$(wget -qO- "$CHANNEL_URL" | tr -d '[:space:]') || {
    yad --error --title="Update Check" --text="Failed to fetch update info." --width=400
    exit 1
}

if [[ "$REMOTE_IMAGE" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]]; then
    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"
else
    yad --error --title="Update Check" --text="Unexpected update info format: $REMOTE_IMAGE" --width=400
    exit 1
fi

# Compare local and remote versions
if [ "$LOCAL_VERSION" -eq "$REMOTE_VERSION" ] && [ "$LOCAL_PROFILE" = "$REMOTE_PROFILE" ]; then
    yad --info --title="Update Check" --text="Your system is already up-to-date (v$LOCAL_VERSION)." --width=400
    exit 0
else
    yad --question --title="Update Available" \
        --text="A new update is available (v$REMOTE_VERSION).
Do you want to update?" --width=400
    if [ $? -eq 0 ]; then
        # User accepted; run shani-deploy via pkexec
        pkexec /usr/local/bin/shani-deploy.sh
    else
        yad --info --title="Update Cancelled" --text="Update cancelled." --width=400
    fi
fi
