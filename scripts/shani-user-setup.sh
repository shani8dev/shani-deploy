#!/bin/bash
# shani-user-setup — provision groups, shell, skel, and container namespaces
# for every regular user (UID 1000–59999).
# Runs as root via shani-user-setup.service (triggered by shani-user-setup.path).
#
# Extra groups are read from /etc/shani-extra-groups (one comma-separated line).
# This is the single source of truth shared with the adduser/useradd wrappers.
# Falls back to the built-in default if the file is missing.

set -uo pipefail   # -e intentionally omitted: one bad user must not abort the rest

EXTRA_GROUPS_FILE="/etc/shani-extra-groups"

EXTRA_GROUPS=""
if [[ -f "$EXTRA_GROUPS_FILE" ]]; then
    EXTRA_GROUPS=$(head -n1 "$EXTRA_GROUPS_FILE" 2>/dev/null | tr -d '[:space:]')
fi

log()  { logger -t shani-user-setup -p user.info    "$*"; }
warn() { logger -t shani-user-setup -p user.warning "$*"; }

# ── Root guard ────────────────────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
    echo "shani-user-setup: must run as root" >&2
    exit 1
fi

# ── Dry-run support ───────────────────────────────────────────────────────────
# Set DRY_RUN=1 in the environment to audit without making changes.
DRY_RUN=${DRY_RUN:-0}
run() {
    if [[ "$DRY_RUN" == "1" ]]; then
        log "DRY-RUN: $*"
    else
        "$@"
    fi
}

# Parse wanted groups once, outside the loop (empty if file was absent)
WANTED_GROUPS=()
if [[ -n "$EXTRA_GROUPS" ]]; then
    IFS=',' read -ra WANTED_GROUPS <<< "$EXTRA_GROUPS"
fi

# Hoist constant tool lookups — no point re-running these per user.
# Real paths: since the /usr/sbin merge, /bin/zsh, /usr/sbin/zsh and
# /usr/bin/zsh are one binary, and which name `command -v` returns depends
# on the caller's PATH. Comparing names rewrote every user's shell to the
# other spelling on each run; each rewrite of passwd re-triggered
# shani-user-setup.path until its trigger limit killed it (found by
# shani-testbed's gate, 2026-09-24).
ZSH_PATH=$(realpath -e "$(command -v zsh 2>/dev/null)" 2>/dev/null || true)
BASH_PATH=$(realpath -e "$(command -v bash 2>/dev/null)" 2>/dev/null || true)
HAS_FLATPAK=$(command -v flatpak          &>/dev/null && echo 1 || echo 0)
HAS_NIX=$(command -v nix-channel          &>/dev/null && echo 1 || echo 0)
HAS_PODMAN=$(command -v podman            &>/dev/null && echo 1 || echo 0)
HAS_LXC=$(command -v lxc                  &>/dev/null && echo 1 || echo 0)
HAS_LXD=$(command -v lxd                  &>/dev/null && echo 1 || echo 0)
SCRIPT_MTIME=$(stat -c %Y "$0" 2>/dev/null || echo 0)

# Under 'set -u', "${arr[*]}" on an empty array is an unbound-variable error.
# Use the ${arr[@]+"${arr[@]}"} expansion idiom instead when referencing them.
processed=()
skipped=()
failed=()

# Use getent to enumerate users — safer on an OverlayFS /etc and also picks
# up LDAP/sssd users.
while IFS=: read -r username _ uid gid _ home shell; do
    [[ -z "$username" || -z "$home" ]] && continue

    # ── Skip non-interactive accounts ────────────────────────────────────────
    case "$shell" in
        */nologin|*/false|*/sync|*/halt|*/shutdown)
            log "skipping $username (non-interactive shell: $shell)"
            skipped+=("$username")
            continue
            ;;
    esac

    log "processing $username (uid=$uid home=$home)"

    user_ok=1

    # ── Stamp-file fast-path ──────────────────────────────────────────────────
    # We write a stamp encoding the script's mtime and extra-groups list.
    # If it matches, skip the one-time bootstrap steps. Set FORCE_SETUP=1 to bypass.
    _stamp_dir="${home}/.cache/shani"
    _stamp="${_stamp_dir}/user-setup.stamp"
    _stamp_val="${SCRIPT_MTIME}:${EXTRA_GROUPS}"
    _stamp_ok=0
    if [[ "${FORCE_SETUP:-0}" != "1" && -f "$_stamp" ]]; then
        if [[ "$(cat "$_stamp" 2>/dev/null)" == "$_stamp_val" ]]; then
            _stamp_ok=1
        fi
    fi

    # ── Group membership ──────────────────────────────────────────────────────
    missing=()
    for group in "${WANTED_GROUPS[@]+"${WANTED_GROUPS[@]}"}"; do
        getent group "$group" &>/dev/null || continue
        id -nG "$username" 2>/dev/null | tr ' ' '\n' | grep -qx "$group" || missing+=("$group")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        joined=$(printf '%s,' "${missing[@]+"${missing[@]}"}")
        joined="${joined%,}"
        log "adding $username to: $joined"
        run usermod -aG "$joined" "$username" || { warn "usermod -aG failed for $username"; user_ok=0; }
    else
        log "$username already has all groups"
    fi

    # ── Shell ─────────────────────────────────────────────────────────────────
    # A user's shell is theirs: new installs start on zsh (configure.sh's
    # useradd -s /bin/zsh), and whatever a user picks later with chsh - or
    # was created with - stays. Only a shell that no longer exists (its
    # binary gone after a slot switch, so they could not log in) is replaced,
    # by zsh or else bash. Paths compare by realpath: since the /usr/sbin
    # merge /bin/zsh, /usr/sbin/zsh and /usr/bin/zsh are one binary.
    current_shell=$(getent passwd "$username" | cut -d: -f7)
    if [[ -n "$current_shell" && ! -x "$(realpath -e "$current_shell" 2>/dev/null)" ]]; then
        if [[ -n "$ZSH_PATH" && -x "$ZSH_PATH" ]]; then
            log "shell ${current_shell} of $username is missing - setting zsh ($ZSH_PATH)"
            run usermod -s "$ZSH_PATH" "$username" || { warn "usermod -s zsh failed for $username"; user_ok=0; }
        elif [[ -n "$BASH_PATH" && -x "$BASH_PATH" ]]; then
            log "shell ${current_shell} of $username is missing - setting bash ($BASH_PATH)"
            run usermod -s "$BASH_PATH" "$username" || { warn "usermod -s bash failed for $username"; user_ok=0; }
        fi
    fi

    # Warn if user is currently logged in — group/shell changes won't take
    # effect until they re-login.
    if command -v loginctl &>/dev/null; then
        if loginctl list-users --no-legend 2>/dev/null | awk '{print $2}' | grep -qx "$username"; then
            log "note: $username is currently logged in — group/shell changes require re-login"
        fi
    fi

    # ── One-time bootstrap (stamp-guarded) ───────────────────────────────────
    # Flatpak/nix/subuid/podman bootstrap are expensive to probe and
    # only ever needed once per user. Skip when stamp matches.
    if [[ "$_stamp_ok" -ne 1 ]]; then

    # ── Flatpak user remote ───────────────────────────────────────────────────
    if [[ "$HAS_FLATPAK" -eq 1 ]]; then
        if ! runuser -u "$username" -- flatpak remote-list --user 2>/dev/null \
                | grep -q flathub; then
            run runuser -u "$username" -- flatpak remote-add --user --if-not-exists flathub \
                https://dl.flathub.org/repo/flathub.flatpakrepo 2>/dev/null \
                || warn "flatpak remote-add failed for $username"
            log "added flathub remote for $username"
        fi
    fi

    # ── Nix user channel ──────────────────────────────────────────────────────
    # Only bootstrap a default channel if the user has none named nixpkgs.
    # Never overwrite an existing nixpkgs channel — the user may have
    # deliberately chosen a different URL.
    # Requires a functional system Nix (nix-daemon.socket active, /nix/store
    # populated). Without it, `nix-channel --add` vacuously "succeeds"
    # (it only writes ~/.nix-channels) while every real nix operation fails
    # — so refuse to stamp success and retry on the next run instead.
    if [[ "$HAS_NIX" -eq 1 ]]; then
        if ! systemctl is-active --quiet nix-daemon.socket 2>/dev/null; then
            warn "system Nix not ready (nix-daemon.socket inactive, /nix/store likely unpopulated) — skipping nixpkgs channel bootstrap for $username, will retry next run"
            user_ok=0
        elif ! runuser -u "$username" -- nix-channel --list 2>/dev/null \
                | grep -q "^nixpkgs "; then
            if run runuser -u "$username" -- nix-channel --add \
                https://nixos.org/channels/nixpkgs-unstable nixpkgs 2>/dev/null; then
                log "added nixpkgs channel for $username"
            else
                warn "nix-channel add failed for $username"
                user_ok=0
            fi
        fi
    fi

    # ── subuid/subgid (rootless podman / lxc / lxd) ──────────────────────────
    # Serialize range allocation with flock: two concurrent invocations could
    # otherwise read the same 'last' value and hand out overlapping ranges
    # (classic TOCTOU between read of /etc/subuid and usermod's write).
    if [[ "$HAS_PODMAN" -eq 1 || "$HAS_LXC" -eq 1 || "$HAS_LXD" -eq 1 ]]; then
        exec 9>/run/shani-user-setup-subid.lock
        if ! flock -w 30 9; then
            warn "could not acquire subid allocation lock within 30s — skipping subuid/subgid setup"
            user_ok=0
        else
        if ! grep -q "^${username}:" /etc/subuid 2>/dev/null; then
            # Find the highest end of any existing range to avoid collisions.
            # If /etc/subuid is missing or empty, start at 100000.
            last=100000
            if [[ -s /etc/subuid ]]; then
                last=$(awk -F: '
                    /^[^#]/ {
                        end = $2 + $3
                        if (end > max) max = end
                    }
                    END { print (max > 0 ? max : 100000) }
                ' /etc/subuid 2>/dev/null || echo 100000)
            fi
            run usermod --add-subuids "${last}-$((last + 65535))" "$username" \
                || { warn "subuid setup failed for $username"; user_ok=0; }
            log "added subuid range for $username (${last}-$((last + 65535)))"
        fi
        if ! grep -q "^${username}:" /etc/subgid 2>/dev/null; then
            last=100000
            if [[ -s /etc/subgid ]]; then
                last=$(awk -F: '
                    /^[^#]/ {
                        end = $2 + $3
                        if (end > max) max = end
                    }
                    END { print (max > 0 ? max : 100000) }
                ' /etc/subgid 2>/dev/null || echo 100000)
            fi
            run usermod --add-subgids "${last}-$((last + 65535))" "$username" \
                || { warn "subgid setup failed for $username"; user_ok=0; }
            log "added subgid range for $username (${last}-$((last + 65535)))"
        fi
        exec 9>&-   # release lock
        fi
    fi

    # ── Podman storage migration ──────────────────────────────────────────────
    # Guard with mountpoint check — /var is a volatile tmpfs on this system and
    # @containers is a separate Btrfs subvolume. Running migrate before it is
    # mounted would reinitialise the storage graph against an empty tmpfs.
    if [[ "$HAS_PODMAN" -eq 1 ]]; then
        if mountpoint -q /var/lib/containers 2>/dev/null; then
            run runuser -u "$username" -- podman system migrate 2>/dev/null \
                || warn "podman system migrate failed for $username"
        else
            warn "skipping podman system migrate for $username: /var/lib/containers not mounted"
        fi
    fi

    fi  # end stamp-guarded bootstrap

    if [[ "$user_ok" -eq 1 ]]; then
        processed+=("$username")
        # Write stamp so next run skips the slow steps.
        if [[ "$DRY_RUN" != "1" && -d "$home" ]]; then
            mkdir -p "$_stamp_dir" 2>/dev/null \
                && chown "$uid:$gid" "$_stamp_dir" 2>/dev/null \
                && printf '%s' "$_stamp_val" > "$_stamp" 2>/dev/null \
                && chown "$uid:$gid" "$_stamp" 2>/dev/null \
                || warn "could not write stamp for $username (non-fatal)"
        fi
    else
        failed+=("$username")
    fi

done < <(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print}')

log "done — processed ${#processed[@]} user(s): ${processed[*]:-}"
[[ ${#skipped[@]}  -gt 0 ]] && log "skipped  ${#skipped[@]}  user(s): ${skipped[*]:-}"
[[ ${#failed[@]}   -gt 0 ]] && warn "FAILED   ${#failed[@]}  user(s): ${failed[*]:-}"

[[ ${#failed[@]} -eq 0 ]]
