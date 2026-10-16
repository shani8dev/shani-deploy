#!/bin/bash
# shani-first-boot — make sure this machine is not stranded with no way in.
#
# Run at every boot, before the display manager. It is a no-op on a healthy
# system and the difference between a recoverable and an unrecoverable machine
# on one that is not.
#
# THE STRANDING THIS EXISTS TO PREVENT
#
# `os-installer-config/config.yaml` sets `skip_user: yes`, so Shanios installs
# no account at all: os-installer's user page never renders, and
# `configure.sh`'s `useradd` block is skipped twice over (by the flag, and by
# its own `OSI_USER_NAME` guard). The first account is created at first boot by
# the desktop's wizard — `plasma-setup.service` on the plasma profile,
# `gnome-initial-setup` otherwise.
#
# `shani-reset` wipes the /etc overlay UPPER layer, which is where /etc/passwd
# and /etc/shadow live. So after a reset EVERY account is gone — including the
# root password set at install time — while /home survives untouched, because
# @home is a separate subvolume. Nothing can then be logged into: not the
# desktop, and not a TTY, because root's password went with the rest of /etc.
# The only way back is the wizard.
#
# On Plasma that works by itself. `plasma-setup.service` guards on
# `ConditionPathExists=!/etc/plasma-setup-done`, and that flag is written at
# RUNTIME into the overlay upper — the exact layer the reset deletes — so the
# guard re-arms and the wizard runs again.
#
# On GNOME it does NOT, and that is this script's whole reason to exist.
# `gnome-initial-setup` is not a system service; it runs inside a user session
# and records that it has already run in that user's dconf database, as
# `org.gnome.desktop.firstuse.gnome-initial-setup`. That database lives in
# `~/.config/dconf/user`, inside @home, which the reset does not touch. So
# after a plain `shani-reset` on the gnome profile the machine has no account
# AND gnome-initial-setup still believes it has done its job: nothing prompts,
# and there is no user to log in as to fix it. Recovery means booting the
# installation media.
#
# WHAT THIS DOES
#
# When — and only when — no regular account exists, this clears that one dconf
# subtree for every home directory that has no matching /etc/passwd entry. The
# two conditions together are precise: a working system has a passwd entry for
# every home, so on a healthy machine this loop never runs and this script
# changes nothing at all.
#
# SCOPE, deliberately narrow. Only `/org/gnome/desktop/firstuse/` is reset.
# Every other setting the user has — theme, wallpaper, keybindings, the lot —
# survives, because they live elsewhere in the same database and reset is
# supposed to preserve a user's configuration. Verified against a real GVDB
# database, not assumed: the firstuse key goes, `/org/gnome/desktop/interface/
# color-scheme` written in the same breath is still there afterwards.
#
# It is also not the only safety net, and deliberately not the last one. If the
# wizard still does not appear, the operator needs to know that from the
# console rather than from a blank screen, so every path here also writes a
# loud, timestamped line to the journal, the console, and /dev/kmsg.

set -uo pipefail   # -e intentionally omitted: one bad home must not abort the rest

LOG_TAG=shani-first-boot
RUNTIME_ROOT=/run/shani-first-boot

log()  { logger -t "$LOG_TAG" -p user.info "$*" 2>/dev/null || true
         printf '[shani-first-boot] %s\n' "$*" >&2
         printf '\x1b[32m%s\x1b[0m' "$*" > /dev/kmsg 2>/dev/null || true; }
warn() { logger -t "$LOG_TAG" -p user.warning "$*" 2>/dev/null || true
         printf '[shani-first-boot] WARNING: %s\n' "$*" >&2
         printf '\x1b[1;33m%s\x1b[0m' "$*" > /dev/kmsg 2>/dev/null || true; }

DRY_RUN=${DRY_RUN:-0}
run() {
    if [[ "$DRY_RUN" == "1" ]]; then
        log "[DRY-RUN] $*"
    else
        "$@"
    fi
}

# ── Root guard ───────────────────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
    echo "shani-first-boot: must run as root" >&2
    exit 1
fi

# ── Does anybody exist who could log in? ─────────────────────────────────────
# The same definition shani-user-setup.sh uses: a regular UID, with a shell
# that is not one of the non-login ones. A system account with a high UID and
# /usr/sbin/nologin is not somebody who can reach a desktop, and treating it
# as one would declare a healthy machine stranded.
has_regular_account() {
    getent passwd | awk -F: '
        $3 >= 1000 && $3 < 60000 {
            shell = $7
            if (shell ~ /\/nologin$|\/false$|\/sync$|\/halt$|\/shutdown$/) next
            found = 1
            exit
        }
        END { exit(found ? 0 : 1) }'
}

if has_regular_account; then
    log "an account exists — nothing to do"
    exit 0
fi

# ── No account. This is the state a reset leaves, and it needs saying. ───────
PROFILE=$(cat /etc/shani-profile 2>/dev/null || echo "")
warn "NO USER ACCOUNT EXISTS on this machine."
warn "  A factory reset deletes every account, including root's password, because"
warn "  /etc/passwd and /etc/shadow live in the same /etc overlay it wipes."
warn "  Nothing can be logged into until the first-boot wizard creates one."

# ── Find homes whose owner has no passwd entry ──────────────────────────────
# These are exactly the homes a reset orphaned: the directory survived in
# @home, the account that owned it did not.
declare -a orphaned=()
for d in /home/*; do
    [[ -d "$d" ]] || continue
    [[ "$(basename "$d")" == "lost+found" ]] && continue
    _uid=$(stat -c %u "$d" 2>/dev/null) || continue
    _gid=$(stat -c %g "$d" 2>/dev/null) || _gid="$_uid"
    if getent passwd "$_uid" >/dev/null 2>&1; then
        continue                      # owner exists after all — not orphaned
    fi
    orphaned+=("${d}:${_uid}:${_gid}")
done

if [[ ${#orphaned[@]} -eq 0 ]]; then
    # Either a genuinely fresh machine, or a --home reset that took the homes
    # too. Either way there is no dconf database anywhere, so gnome-initial-
    # setup has nothing to believe and will run on its own.
    log "no orphaned home directories — gnome-initial-setup has no first-run"
    log "  marker to be stale, so it will run on its own"
    exit 0
fi

warn "found ${#orphaned[@]} home director$([[ ${#orphaned[@]} -eq 1 ]] && echo y || echo ies) with no matching account"

# ── Re-arm gnome-initial-setup in each one ──────────────────────────────────
# The tools are checked once, up front, and their absence is reported rather
# than swallowed: "nothing happened" and "nothing could be tried" are different
# states and the operator needs to be able to tell them apart from the console.
for tool in dconf dbus-run-session setpriv; do
    if ! command -v "$tool" &>/dev/null; then
        warn "'$tool' is not installed — cannot re-arm the GNOME first-boot wizard."
        warn "  Boot the installation media to recover this machine."
        exit 0
    fi
done

rearmed=0
failed=0
for entry in "${orphaned[@]}"; do
    home="${entry%%:*}"
    rest="${entry#*:}"
    uid="${rest%%:*}"
    gid="${rest#*:}"

    # dconf needs a runtime dir it owns, and it is reached as the home's owner
    # by NUMERIC id: there is no passwd entry to name, which is the entire
    # reason this loop exists.
    runtime="${RUNTIME_ROOT}/${uid}"
    if [[ "$DRY_RUN" == "1" ]]; then
        log "[DRY-RUN] re-arming gnome-initial-setup in ${home} (uid ${uid})"
        continue
    fi
    install -d -m 0700 -o "$uid" -g "$gid" "$runtime" 2>/dev/null || {
        warn "could not create a runtime directory for uid ${uid}"; failed=$((failed + 1)); continue; }

    # --clear-groups needs CAP_SETGID, which root has.
    if setpriv --reuid="$uid" --regid="$gid" --clear-groups \
        env HOME="$home" XDG_RUNTIME_DIR="$runtime" USER="$home" \
        dbus-run-session -- dconf reset -f /org/gnome/desktop/firstuse/ \
        >/dev/null 2>&1; then
        log "re-armed the GNOME first-boot wizard in ${home} (uid ${uid})"
        rearmed=$((rearmed + 1))
    else
        warn "could not re-arm gnome-initial-setup in ${home} (uid ${uid})"
        failed=$((failed + 1))
    fi
    rm -rf "$runtime" 2>/dev/null || true
done

if [[ "$rearmed" -gt 0 ]]; then
    log "first-boot wizard re-armed in ${rearmed} home(s)."
    if [[ "$PROFILE" == "plasma" ]]; then
        log "  (plasma profile: plasma-setup re-arms on its own via"
        log "   /etc/plasma-setup-done, so this was belt-and-braces)"
    fi
fi
if [[ "$failed" -gt 0 ]]; then
    warn "${failed} home(s) could not be re-armed."
    warn "  If no setup wizard appears, boot the installation media — there is no"
    warn "  password to fall back on, because the reset took root's too."
fi

# ── Tell the operator what to expect, and what to do if it does not happen ──
case "$PROFILE" in
    plasma) expect="plasma-setup.service" ;;
    cosmic) expect="cosmic-initial-setup" ;;
    *)      expect="gnome-initial-setup" ;;
esac
log "on the next graphical login, ${expect} should offer to create an account."
log "  Use the SAME username as before to get your files back from ${home:-/home}."
log "  A different username will not see them."

exit 0
