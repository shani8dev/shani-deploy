#!/bin/bash
# shani-desktop-health — a TRIAL boot only counts as good once the login screen
# (or an automatic sign-in) is up and stays up.
#
# A trial boot is one systemd-boot is counting: the first boots of a freshly
# deployed slot, whose loader entry still carries its +N-M tries counter. Only
# then does systemd-boot set LoaderBootCountPath, and only then does this unit
# run (ConditionPathExists= in shani-desktop-health.service). On every other
# boot it is skipped, so a steady-state machine is never judged by it.
#
# mark-boot-success.service Requires= this unit, so a failure here means the
# boot is never marked good and never blessed: /data/boot_in_progress stays,
# check-boot-failure records the slot at 15 min, and shani-auto-rollback at
# 16 min switches the default to the sibling slot (switch_to_sibling_slot:
# loader.conf only, no data touched). The person is told to reboot.
#
# It does NOT reboot by itself, unlike Ananta OS. Measured 2026-11-19
# (shani-testbed boot-probes/boot-counting.sh, broken display manager): a
# reboot here looped forever - loader.conf names the entry explicitly
# (`default shanios-blue.conf`), so systemd-boot keeps choosing it even with no
# tries left (Ananta writes `default ananta-*`, where an exhausted entry sorts
# last). Rebooting would only be safe once the default can fall through.
#
# Not a failure, ever (this exits 0):
#   - the default target is not graphical.target (server, headless)
#   - there is no display manager (display-manager.service not loaded)
#   - no display is connected (a monitor that is off or unplugged)
#
# The idea and its shape come from Ananta OS's ananta-health (GPL-3.0-or-later,
# github.com/BVMDebuDev/ananta-os): login screen on seat0, up for 15 s without
# restarting, plus the core bus services.
set -u

STABLE_SECS="${SHANI_DESKTOP_HEALTH_STABLE:-15}"
WAIT_SECS="${SHANI_DESKTOP_HEALTH_WAIT:-90}"
RECORD=/data/boot_desktop_failure

log() { logger -t shani-desktop-health -- "$*"; echo "shani-desktop-health: $*" >&2; }

fail() {
    log "FAIL: $1"
    printf '%s %s\n' "$(date -Iseconds)" "$1" > "$RECORD" 2>/dev/null || true
    log "this boot is not marked good; the boot-failure check switches to the other slot at 15 min"
    exit 1
}

pass() { log "PASS: $1"; rm -f "$RECORD" 2>/dev/null || true; exit 0; }

wait_for() {  # SECONDS COMMAND...
    local i
    for (( i = 0; i < $1; i++ )); do
        "${@:2}" >/dev/null 2>&1 && return 0
        sleep 1
    done
    "${@:2}" >/dev/null 2>&1
}

# A display is connected when any DRM connector reports it.
display_connected() {
    local s
    for s in /sys/class/drm/card*-*/status; do
        [[ -r $s ]] && [[ $(<"$s") == connected ]] && return 0
    done
    return 1
}

# seat0 has an active session (the greeter, or the person after an automatic
# sign-in). Its Type is not checked: greetd's greeter session is not always
# registered as wayland.
seat_session() {
    local id
    id=$(loginctl show-seat seat0 -P ActiveSession 2>/dev/null) && [[ -n $id ]] || return 1
    [[ $(loginctl show-session "$id" -P State 2>/dev/null) == active ]]
}

[[ $(systemctl get-default 2>/dev/null) == graphical.target ]] \
    || pass "not a graphical system ($(systemctl get-default 2>/dev/null)) - nothing to check"
[[ $(systemctl show -P LoadState display-manager.service 2>/dev/null) == loaded ]] \
    || pass "no display manager - nothing to check"
display_connected || pass "no display connected - not counted as a failure"

wait_for "$WAIT_SECS" systemctl -q is-active display-manager.service \
    || fail "the login screen did not start (display-manager.service is $(systemctl is-active display-manager.service 2>/dev/null))"
wait_for "$WAIT_SECS" seat_session \
    || fail "the login screen did not appear (no active session on seat0)"

restarts=$(systemctl show -P NRestarts display-manager.service 2>/dev/null)
sleep "$STABLE_SECS"
systemctl -q is-active display-manager.service \
    || fail "the login screen stopped within ${STABLE_SECS}s"
[[ $(systemctl show -P NRestarts display-manager.service 2>/dev/null) == "$restarts" ]] \
    || fail "the login screen restarted within ${STABLE_SECS}s"
wait_for 10 seat_session || fail "the login screen did not stay up"

for u in dbus.service systemd-logind.service polkit.service systemd-journald.service; do
    ! systemctl -q is-failed "$u" || fail "$u failed"
done

pass "the login screen is up and stayed up for ${STABLE_SECS}s"
