#!/bin/bash
# check-boot-failure.sh – Record boot failure if boot-success marker is missing.
# Extract the booted slot from the kernel command line.
BOOTED_SLOT=$(grep -o 'subvol=[^, ]*' /proc/cmdline | cut -d= -f2)
BOOTED_SLOT="${BOOTED_SLOT#@}"
[ -z "$BOOTED_SLOT" ] && BOOTED_SLOT="unknown"


# Hard failure already written by dracut hook — nothing more to do
if [ -f /data/boot_hard_failure ]; then
    logger -t check-boot-failure "Hard failure already recorded for slot '$BOOTED_SLOT', skipping."
    exit 0
fi
# Boot failed if still "in progress" and never marked ok
if [ -f /data/boot_in_progress ] && [ ! -f /data/boot-ok ]; then
    if [ ! -f /data/boot_failure ]; then
        echo "$BOOTED_SLOT" > /data/boot_failure
        logger -t check-boot-failure \
          "Boot failure detected: slot '$BOOTED_SLOT' did not complete boot."
    fi
fi
