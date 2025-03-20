#!/bin/bash
# startup-check.sh – Check if booted from fallback slot and prompt user for rollback.

CURRENT_SLOT_FILE="/data/current-slot"
CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null || echo "blue")

# Extract the booted slot from kernel parameters.
BOOTED_SLOT=$(grep -o 'subvol=[^, ]*' /proc/cmdline | cut -d= -f2)
BOOTED_SLOT="${BOOTED_SLOT#@}"
[ -z "$BOOTED_SLOT" ] && BOOTED_SLOT="$CURRENT_SLOT"

# Check if boot failure was detected
if [ -f /data/boot_failure ]; then
    FAILED_SLOT=$(cat /data/boot_failure)
    if [ "$FAILED_SLOT" != "$BOOTED_SLOT" ]; then
        logger -t startup-check "Boot failure recorded for slot '$FAILED_SLOT', but system booted into '$BOOTED_SLOT'. No rollback needed."
        exit 0
    fi

    # Log boot failure detection
    logger -t startup-check "System booted from fallback slot '$BOOTED_SLOT' (expected: '$CURRENT_SLOT'). Prompting user for rollback."

    # Create a temporary logfile for rollback progress
    LOGFILE=$(mktemp /tmp/rollback.log.XXXXXX)

    # Prepare rollback prompt message
    PROMPT_MSG="The system booted from fallback slot ($BOOTED_SLOT) instead of the expected slot ($CURRENT_SLOT).
Do you want to rollback to the previous version?

(You can switch to the 'Terminal Output' tab for live progress.)"

    # Launch YAD UI with a rollback prompt
    CHOICE=$(yad --notebook \
        --notebook-tab="Rollback Prompt" \
        --form --field=" " "$PROMPT_MSG" \
        --button="Rollback:0" --button="Cancel:1" \
        --notebook-tab="Terminal Output" \
        --text-info --tail --filename="$LOGFILE" \
        --width=600 --height=400)
    RET=$?

    if [ $RET -eq 0 ]; then
        logger -t startup-check "User confirmed rollback. Executing rollback process."
        pkexec /usr/local/bin/shani-deploy --rollback >> "$LOGFILE" 2>&1
        yad --info --title="Rollback Completed" --text="Rollback process completed." --width=400
    else
        logger -t startup-check "User canceled rollback. Boot failure remains unresolved."
        yad --info --title="Rollback Cancelled" --text="Rollback was cancelled. Please investigate the boot issue." --width=400
    fi
fi

