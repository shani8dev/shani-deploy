#!/bin/bash
# check-boot-failure.sh – Record boot failure if boot-success marker is missing.

# The slot that actually booted (the fallback, working slot).
# Uses the same rootflags= parsing as shani-deploy and shani-update for consistency.
_rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2- 2>/dev/null || echo "")
BOOTED_SLOT=$(awk -F'subvol=' '{print $2}' <<< "$_rootflags" | cut -d, -f1)
BOOTED_SLOT="${BOOTED_SLOT#@}"
[ -z "$BOOTED_SLOT" ] && \
    BOOTED_SLOT=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
if [ -z "$BOOTED_SLOT" ]; then
    logger -t check-boot-failure "Cannot detect booted subvolume — skipping failure check."
    exit 0
fi

# The slot that was *supposed* to boot (the one that failed).
# shani-update._check_fallback_boot() expects boot_failure to contain
# this value so it can match it against /data/current-slot.
FAILED_SLOT=$(cat /data/current-slot 2>/dev/null | tr -cd 'a-z')
[ -z "$FAILED_SLOT" ] && FAILED_SLOT="$BOOTED_SLOT"

# Sanity-check: current-slot must be a valid slot name and must differ from
# the booted slot (we are on the fallback, so current-slot should name the
# slot that failed, not the one we are running). If they match or the value
# is invalid, derive the failed slot from the booted slot instead to avoid
# recording the wrong slot as having failed.
if [ "$FAILED_SLOT" = "$BOOTED_SLOT" ] || \
   { [ "$FAILED_SLOT" != "blue" ] && [ "$FAILED_SLOT" != "green" ]; }; then
    if [ "$BOOTED_SLOT" = "blue" ]; then
        FAILED_SLOT="green"
    elif [ "$BOOTED_SLOT" = "green" ]; then
        FAILED_SLOT="blue"
    else
        logger -t check-boot-failure \
          "Cannot derive failed slot from booted slot '$BOOTED_SLOT' — skipping."
        exit 0
    fi
    logger -t check-boot-failure \
      "current-slot invalid or matches booted slot — derived failed slot as '@${FAILED_SLOT}'."
fi

# Hard failure already written by dracut hook — nothing more to do
if [ -f /data/boot_hard_failure ]; then
    logger -t check-boot-failure "Hard failure already recorded for slot '$FAILED_SLOT', skipping."
    exit 0
fi

# If system already recovered and booted the same slot successfully,
# any existing failure marker is stale and should be removed.
if [ -f /data/boot-ok ] && [ -f /data/boot_failure ]; then
    RECORDED_FAILED=$(cat /data/boot_failure | tr -cd 'a-z')
    if [ "$BOOTED_SLOT" = "$RECORDED_FAILED" ]; then
        rm -f /data/boot_failure /data/boot_failure.acked
        logger -t check-boot-failure \
          "Recovered slot '@${BOOTED_SLOT}' booted successfully — clearing stale failure marker."
    fi
fi

# Boot failed if still "in progress" and never marked ok
if [ -f /data/boot_in_progress ] && [ ! -f /data/boot-ok ]; then
    if [ ! -f /data/boot_failure ] && [ ! -f /data/boot_failure.acked ]; then
        echo "$FAILED_SLOT" > /data/boot_failure
        logger -t check-boot-failure \
          "Boot failure: slot '@${FAILED_SLOT}' failed to boot, system fell back to '@${BOOTED_SLOT}'."
    fi
fi
