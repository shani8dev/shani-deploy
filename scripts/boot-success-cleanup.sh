#!/bin/bash
# boot-success-cleanup — clear a stale boot-failure marker after recovery.
#
# Extracted from mark-boot-success.service's inline ExecStart: systemd unit
# files cannot carry this shell verbatim (backslash continuations and \$ in
# awk are flagged as "unknown escape sequences" and silently mangled, which
# left the stale-marker cleanup dead on real boots).
set -uo pipefail

DATA_DIR="/data"

BOOTED_SLOT=$(grep -o 'rootflags=[^ ]*' /proc/cmdline 2>/dev/null \
    | cut -d= -f2- \
    | awk -F'subvol=' '{print $2}' \
    | cut -d, -f1 \
    | sed 's/^@//')

FAILED_SLOT=$(cat "${DATA_DIR}/boot_failure" 2>/dev/null | tr -cd 'a-z')

if [[ -n "$FAILED_SLOT" && "$BOOTED_SLOT" == "$FAILED_SLOT" ]]; then
    rm -f "${DATA_DIR}/boot_failure" "${DATA_DIR}/boot_failure.acked"
    logger -t boot-success \
        "Recovered slot '@${BOOTED_SLOT}' booted successfully — cleared stale failure marker."
fi

exit 0
