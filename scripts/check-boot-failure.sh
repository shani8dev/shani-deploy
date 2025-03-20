#!/bin/bash
# check-boot-failure.sh – Record boot failure if boot-success marker is missing.
# Extract the booted slot from the kernel command line.
BOOTED_SLOT=$(grep -o 'subvol=[^, ]*' /proc/cmdline | cut -d= -f2)
BOOTED_SLOT="${BOOTED_SLOT#@}"
[ -z "$BOOTED_SLOT" ] && BOOTED_SLOT="unknown"

# If boot-success marker (/data/boot-ok) is missing, record the failed slot.
if [ ! -f /data/boot-ok ]; then
    echo "$BOOTED_SLOT" > /data/boot_failure
    logger -t check-boot-failure "Boot failure detected: /data/boot-ok missing. Failed slot recorded as '$BOOTED_SLOT'."
fi

