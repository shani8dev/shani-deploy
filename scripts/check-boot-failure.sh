#!/bin/bash
# check-boot-failure.sh – Check if boot-success marker exists; if not, create boot failure marker.
if [ ! -f /data/boot-ok ]; then
    touch /data/boot_failure
    logger -t check-boot-failure "Boot failure detected: /data/boot-ok missing. /data/boot_failure created."
fi
