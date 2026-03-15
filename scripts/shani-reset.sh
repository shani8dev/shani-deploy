#!/bin/bash
# shani-reset — ShaniOS factory reset
#
# Wipes all persistent system state stored in /data and reboots.
# On the next boot, systemd-tmpfiles recreates the /data structure from
# shanios-data-structure.conf, the /etc overlay starts fresh from the
# read-only root, and all services start as if first-run.
#
# What is wiped:
#   /data/overlay/etc/upper/   — ALL /etc modifications, including:
#                                  user accounts (/etc/passwd, /etc/shadow, /etc/group)
#                                  hostname, locale, sshd config, enabled units, etc.
#                                  subuid/subgid ranges (/etc/subuid, /etc/subgid)
#   /data/overlay/var/upper/   — all /var overlay changes (if used)
#   /data/varlib/*/            — all persistent service state
#     (NetworkManager, bluetooth, tailscale, TPM2, cups, etc.)
#   /data/varspool/*/          — all job scheduler spools
#   /data/downloads/           — cached OS images (optional, --keep-downloads)
#   /data/boot_*               — all boot state markers
#   /data/deployment_pending   — any in-flight deployment flag
#
# What is NOT wiped:
#   /home                      — user files (@home subvolume, separate)
#   /root                      — root home (@root subvolume, separate)
#   @blue / @green             — OS root subvolumes (untouched)
#   ESP / UKI boot images      — system still boots the same slot
#   /data/current-slot         — preserved so system boots correct slot
#
# Usage:
#   shani-reset [--hard] [--keep-downloads] [--home] [--dry-run] [--yes]
#
#   --hard            Also wipe /data entirely then let tmpfiles recreate.
#                     Identical end result but cleaner (removes unknown files).
#   --keep-downloads  Preserve /data/downloads (large cached images)
#   --home            Also wipe /home (asks for confirmation)
#   --dry-run         Show what would be deleted, make no changes
#   --yes             Skip confirmation prompt (for scripted use)
#
# Install: /usr/local/bin/shani-reset
# Polkit:  see 99-shani.rules (AUTH_SELF, wheel required)

set -Eeuo pipefail
IFS=$'\n\t'

##############################################################################
### Constants
##############################################################################

readonly SCRIPT_VERSION="1.0"
readonly OS_NAME="shanios"
readonly LOG_TAG="shani-reset"
readonly DATA_DIR="/data"
readonly ROOT_DEV="/dev/disk/by-label/shani_root"

##############################################################################
### Logging
##############################################################################

log()     { echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]    $*" >&2; logger -t "$LOG_TAG" "$*" 2>/dev/null || true; }
log_warn(){ echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $*" >&2; logger -t "$LOG_TAG" "WARNING: $*" 2>/dev/null || true; }
log_ok()  { echo -e "$(date '+%Y-%m-%d %H:%M:%S') \033[0;32m[OK]\033[0m      $*" >&2; }
die()     { echo -e "$(date '+%Y-%m-%d %H:%M:%S') \033[1;31m[FATAL]\033[0m   $*" >&2; exit 1; }

section() {
    echo "" >&2
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
    echo "  $*" >&2
    echo "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
}

##############################################################################
### Options
##############################################################################

DRY_RUN="no"
HARD_WIPE="no"
KEEP_DOWNLOADS="no"
WIPE_HOME="no"
SKIP_CONFIRM="no"

usage() {
    cat >&2 <<EOF

Usage: $(basename "$0") [OPTIONS]

  Factory reset ShaniOS by wiping all persistent state in /data.
  The system reboots automatically after the reset.

Options:
  --hard             Wipe /data entirely instead of selectively.
                     Both modes produce the same end state; --hard also
                     removes any unknown files that accumulated in /data.
  --keep-downloads   Preserve /data/downloads (cached OS images, can be GBs)
  --home             Also wipe /home (user files — irreversible, asks twice)
  --dry-run          Print what would be deleted without making changes
  --yes              Skip the confirmation prompt
  -h, --help         Show this help

What survives:
  /home  /root       User home directories (separate Btrfs subvolumes, NOT wiped)
  @blue  @green      OS root slots (system still boots normally after reset)
  ESP / UKIs         Boot images and entries (untouched)

IMPORTANT: User ACCOUNTS (/etc/passwd entries) are part of the /etc overlay and
  ARE wiped. Home directory FILES in /home survive, but the accounts that own
  them must be re-created after reboot.

  On a desktop system: the KDE (plasma-welcome) or GNOME (gnome-initial-setup)
  first-run wizard starts automatically and creates a new user account.
  The adduser/useradd wrappers ensure correct group membership, and
  shani-user-setup then provisions shell, skel, and container namespaces.
  Files in /home for the re-created username are immediately accessible again.

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hard)             HARD_WIPE="yes";       shift ;;
        --keep-downloads)   KEEP_DOWNLOADS="yes";  shift ;;
        --home)             WIPE_HOME="yes";        shift ;;
        --dry-run)          DRY_RUN="yes";          shift ;;
        --yes|-y)           SKIP_CONFIRM="yes";     shift ;;
        -h|--help)          usage; exit 0 ;;
        *) die "Unknown option: $1. Run with --help for usage." ;;
    esac
done

##############################################################################
### Privilege escalation
##############################################################################

if [[ $(id -u) -ne 0 ]]; then
    self=$(readlink -f "$0")
    if command -v pkexec &>/dev/null; then
        exec pkexec "$self" "$@"
    elif command -v sudo &>/dev/null; then
        exec sudo "$self" "$@"
    else
        die "Must run as root."
    fi
fi

##############################################################################
### Dry-run wrapper
##############################################################################

run() {
    if [[ "$DRY_RUN" == "yes" ]]; then
        echo "  [DRY-RUN] $*" >&2
    else
        "$@"
    fi
}

##############################################################################
### Pre-flight checks
##############################################################################

section "ShaniOS Factory Reset v${SCRIPT_VERSION}"

[[ "$DRY_RUN" == "yes" ]] && log_warn "DRY-RUN mode — no changes will be made"

# Must have /data mounted
mountpoint -q "$DATA_DIR" 2>/dev/null || \
    die "/data is not mounted. Cannot perform reset. Is the @data subvolume present?"

# Detect current booted slot — we must preserve this so the system boots back correctly
_rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2- || echo "")
BOOTED_SLOT=$(awk -F'subvol=' '{print $2}' <<< "$_rootflags" | cut -d, -f1)
BOOTED_SLOT="${BOOTED_SLOT#@}"
[[ -z "$BOOTED_SLOT" ]] && \
    BOOTED_SLOT=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}' || echo "")
[[ -z "$BOOTED_SLOT" || ! "$BOOTED_SLOT" =~ ^(blue|green)$ ]] && \
    die "Cannot detect booted slot from /proc/cmdline or btrfs get-default. Aborting."

log "Booted slot: @${BOOTED_SLOT}"

##############################################################################
### Confirmation
##############################################################################

echo "" >&2
echo "  This will PERMANENTLY wipe:" >&2
echo "" >&2
echo "    • All /etc modifications (hostname, locale, sshd config, enabled units…)" >&2
echo "    • ALL USER ACCOUNTS created after install (stored in /etc overlay)" >&2
echo "      Users must be re-created after reboot — home directories in /home survive" >&2
echo "    • All service state (WiFi passwords, Bluetooth pairings, Tailscale key…)" >&2
echo "    • All job spools (cron, at, postfix queue…)" >&2
[[ "$KEEP_DOWNLOADS" == "no" ]] && \
    echo "    • Cached OS downloads in /data/downloads" >&2
[[ "$WIPE_HOME" == "yes" ]] && \
    echo "    • ALL USER FILES in /home  ← THIS IS IRREVERSIBLE" >&2
echo "" >&2
echo "  What is preserved:" >&2
echo "    • /home and /root (user files)" >&2
[[ "$WIPE_HOME" == "yes" ]] && \
    echo "    • (except /home — you asked to wipe it)" >&2
echo "    • @blue and @green OS root subvolumes" >&2
echo "    • Boot images and entries (ESP)" >&2
echo "" >&2
echo "  The system will REBOOT automatically after the reset." >&2
echo "" >&2

if [[ "$SKIP_CONFIRM" != "yes" ]]; then
    read -r -p "  Type 'reset' to confirm: " confirm
    [[ "$confirm" == "reset" ]] || { echo "  Aborted." >&2; exit 0; }
fi

# Extra confirmation for --home
if [[ "$WIPE_HOME" == "yes" && "$SKIP_CONFIRM" != "yes" ]]; then
    echo "" >&2
    echo "  ┌──────────────────────────────────────────────────┐" >&2
    echo "  │  WARNING: --home will delete all files in /home  │" >&2
    echo "  │  This includes documents, photos, dotfiles, etc. │" >&2
    echo "  │  THIS CANNOT BE UNDONE.                          │" >&2
    echo "  └──────────────────────────────────────────────────┘" >&2
    echo "" >&2
    read -r -p "  Type 'wipe home' to confirm: " confirm_home
    [[ "$confirm_home" == "wipe home" ]] || { echo "  Home wipe aborted. Continuing without --home." >&2; WIPE_HOME="no"; }
fi

##############################################################################
### Reset
##############################################################################

section "Performing reset"

if [[ "$HARD_WIPE" == "yes" ]]; then
    # ── Hard wipe: remove everything under /data, preserve mount point ────────
    # We cannot unmount /data (live overlay + bind mounts depend on it).
    # Strategy: delete all contents in-place. tmpfiles recreates on next boot.
    log "Hard wipe: removing all contents of /data..."

    # Preserve the mount point itself and nothing else.
    # Use find -mindepth 1 so we never touch /data itself.
    if [[ "$KEEP_DOWNLOADS" == "yes" ]]; then
        # Preserve downloads dir but wipe everything else
        run find "$DATA_DIR" -mindepth 1 -maxdepth 1 \
            ! -name "downloads" \
            -exec rm -rf {} + 2>/dev/null || true
        log "  Preserved /data/downloads (--keep-downloads)"
    else
        run find "$DATA_DIR" -mindepth 1 -maxdepth 1 \
            -exec rm -rf {} + 2>/dev/null || true
    fi

    log_ok "Hard wipe complete"

else
    # ── Soft wipe: selectively clear state directories ─────────────────────────

    log "Wiping /etc overlay upper layer..."
    run rm -rf "${DATA_DIR}/overlay/etc/upper"
    run rm -rf "${DATA_DIR}/overlay/etc/work"
    run mkdir -p "${DATA_DIR}/overlay/etc/upper" "${DATA_DIR}/overlay/etc/work" 2>/dev/null || true
    log_ok "  /data/overlay/etc cleared"

    log "Wiping /var overlay upper layer (if used)..."
    run rm -rf "${DATA_DIR}/overlay/var/upper"
    run rm -rf "${DATA_DIR}/overlay/var/work"
    run mkdir -p "${DATA_DIR}/overlay/var/upper" "${DATA_DIR}/overlay/var/work" 2>/dev/null || true
    log_ok "  /data/overlay/var cleared"

    log "Wiping persistent service state (/data/varlib)..."
    if [[ -d "${DATA_DIR}/varlib" ]]; then
        run find "${DATA_DIR}/varlib" -mindepth 2 -delete 2>/dev/null || true
        log_ok "  /data/varlib/* cleared (directories preserved for bind mounts)"
    fi

    log "Wiping job scheduler spools (/data/varspool)..."
    if [[ -d "${DATA_DIR}/varspool" ]]; then
        run find "${DATA_DIR}/varspool" -mindepth 2 -delete 2>/dev/null || true
        log_ok "  /data/varspool/* cleared"
    fi

    log "Wiping boot state markers..."
    run rm -f \
        "${DATA_DIR}/boot_in_progress" \
        "${DATA_DIR}/boot-ok" \
        "${DATA_DIR}/boot_failure" \
        "${DATA_DIR}/boot_failure.acked" \
        "${DATA_DIR}/boot_hard_failure" \
        "${DATA_DIR}/deployment_pending"
    log_ok "  Boot markers cleared"

    if [[ "$KEEP_DOWNLOADS" == "no" ]]; then
        log "Wiping cached downloads (/data/downloads)..."
        run rm -rf "${DATA_DIR}/downloads"
        run mkdir -p "${DATA_DIR}/downloads" 2>/dev/null || true
        log_ok "  /data/downloads cleared"
    else
        log "  Skipping /data/downloads (--keep-downloads)"
    fi
fi

# ── Restore correct current-slot marker ────────────────────────────────────────
# tmpfiles will create current-slot=blue if missing, but the system may be
# booted from @green. Write the correct value now so the NEXT boot is correct.
log "Writing slot markers for @${BOOTED_SLOT}..."
if [[ "$BOOTED_SLOT" == "blue" ]]; then
    INACTIVE_SLOT="green"
else
    INACTIVE_SLOT="blue"
fi
if [[ "$DRY_RUN" == "yes" ]]; then
    echo "  [DRY-RUN] Would write: /data/current-slot=${BOOTED_SLOT}" >&2
    echo "  [DRY-RUN] Would write: /data/previous-slot=${INACTIVE_SLOT}" >&2
else
    echo "$BOOTED_SLOT"  > "${DATA_DIR}/current-slot"
    echo "$INACTIVE_SLOT" > "${DATA_DIR}/previous-slot"
    log_ok "  current-slot=${BOOTED_SLOT}, previous-slot=${INACTIVE_SLOT}"
fi

# ── Optional: wipe /home ───────────────────────────────────────────────────────
if [[ "$WIPE_HOME" == "yes" ]]; then
    section "Wiping /home"
    log_warn "Removing all files in /home..."
    # Wipe contents but keep the /home directory and the mount point
    run find /home -mindepth 1 -delete 2>/dev/null || true
    log_ok "/home wiped"
fi

##############################################################################
### Post-reset: regenerate UKI cmdline
##############################################################################
# The /etc overlay upper is now empty, so any cached cmdline files that lived
# in the overlay (/etc/kernel/install_cmdline_<slot>) are gone.
# gen-efi will regenerate them on the next shani-deploy run.
# We do NOT run gen-efi here — the current UKIs are still valid (they embed
# the cmdline at build time). The next deploy will refresh them.

section "Reset complete"
echo "" >&2
log_ok "All persistent state wiped."
log "On next boot:"
log "  • systemd-tmpfiles recreates /data structure"
log "  • /etc starts fresh from @${BOOTED_SLOT} read-only root"
log "  • All services start in initial state (re-run first-time setup)"
log "  • System boots into @${BOOTED_SLOT} (unchanged)"
log "After login:"
log "  • The desktop setup wizard (plasma-welcome / gnome-initial-setup)"
log "    runs automatically and creates a new user account"
log "  • Home directory files in /home are intact and accessible once"
log "    the account is re-created with the same username"
log "  • Run 'shani-update' to ensure latest OS version"
echo "" >&2

##############################################################################
### Reboot
##############################################################################

if [[ "$DRY_RUN" == "yes" ]]; then
    log "[DRY-RUN] Would reboot now."
    exit 0
fi

log "Rebooting in 3 seconds... (Ctrl-C to abort)"
sleep 3
systemctl reboot
