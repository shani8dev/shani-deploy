#!/bin/bash
# shani-user-setup — provision groups, shell, skel, and container namespaces
# for every regular user (UID 1000–59999).
# Runs as root via shani-user-setup.service (triggered by shani-user-setup.path).
#
# Extra groups are read from /etc/shani-extra-groups (one comma-separated line).
# This is the single source of truth shared with the adduser/useradd wrappers.
# Falls back to the built-in default if the file is missing.

set -uo pipefail   # -e intentionally omitted: one bad user must not abort the rest

SKEL_DIR="/etc/skel"
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
ZSH_PATH=$(command -v zsh  2>/dev/null || true)
BASH_PATH=$(command -v bash 2>/dev/null || true)
HAS_RSYNC=$(command -v rsync              &>/dev/null && echo 1 || echo 0)
HAS_XDG=$(command -v xdg-user-dirs-update &>/dev/null && echo 1 || echo 0)
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
    for group in "${WANTED_GROUPS[@]}"; do
        getent group "$group" &>/dev/null || continue
        id -nG "$username" 2>/dev/null | tr ' ' '\n' | grep -qx "$group" || missing+=("$group")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        joined=$(printf '%s,' "${missing[@]}")
        joined="${joined%,}"
        log "adding $username to: $joined"
        run usermod -aG "$joined" "$username" || { warn "usermod -aG failed for $username"; user_ok=0; }
    else
        log "$username already has all groups"
    fi

    # ── Default shell ─────────────────────────────────────────────────────────
    # Re-read from getent — $shell is stale if usermod changed it earlier.
    current_shell=$(getent passwd "$username" | cut -d: -f7)

    if [[ -n "$ZSH_PATH" && -x "$ZSH_PATH" && "$current_shell" != "$ZSH_PATH" ]]; then
        log "setting shell to zsh ($ZSH_PATH) for $username"
        run usermod -s "$ZSH_PATH" "$username" || { warn "usermod -s zsh failed for $username"; user_ok=0; }
    elif [[ -z "$ZSH_PATH" && -n "$BASH_PATH" && -x "$BASH_PATH" && "$current_shell" != "$BASH_PATH" ]]; then
        log "zsh not found, setting shell to bash ($BASH_PATH) for $username"
        run usermod -s "$BASH_PATH" "$username" || { warn "usermod -s bash failed for $username"; user_ok=0; }
    fi

    # Warn if user is currently logged in — group/shell changes won't take
    # effect until they re-login.
    if command -v loginctl &>/dev/null; then
        if loginctl list-users --no-legend 2>/dev/null | awk '{print $2}' | grep -qx "$username"; then
            log "note: $username is currently logged in — group/shell changes require re-login"
        fi
    fi

    # ── Home directory ────────────────────────────────────────────────────────
    # Note: install -d -m does NOT change permissions on an already-existing dir,
    # so we always check and fix mode explicitly after ensuring the dir exists.
    if [[ ! -d "$home" ]]; then
        log "creating home directory $home for $username"
        run mkdir -p "$home" \
            || { warn "failed to create $home"; user_ok=0; }
    fi
    if [[ -d "$home" ]]; then
        current_mode=$(stat -c %a "$home" 2>/dev/null)
        if [[ "$current_mode" != "700" ]]; then
            run chmod 700 "$home" || { warn "chmod failed for $home"; user_ok=0; }
        fi
    fi

    # ── Skel sync ─────────────────────────────────────────────────────────────
    # Always run — skel files may be updated by packages and should propagate.
    # --update skips dest files newer than the source (user-modified copies),
    # so only genuinely new or updated skel files are written.
    # Ownership is fixed after copy — skel files are root-owned and the user
    # must be able to modify or delete their own copies.
    if [[ -d "$home" && -d "$SKEL_DIR" ]]; then
        if [[ "$HAS_RSYNC" -eq 1 ]]; then
            run rsync -a --update --chown="$uid:$gid" --exclude='.gitkeep' "$SKEL_DIR/" "$home/" \
                || warn "rsync skel failed for $username"
        else
            # Fallback: recurse manually, mirroring rsync --update semantics.
            while IFS= read -r item; do
                [[ "$(basename "$item")" == ".gitkeep" ]] && continue
                rel="${item#"$SKEL_DIR"/}"
                dest="$home/$rel"
                if [[ -d "$item" ]]; then
                    if [[ ! -d "$dest" ]]; then
                        run mkdir -p "$dest" \
                            && run chown "$uid:$gid" "$dest" \
                            || warn "mkdir skel dir $dest failed for $username"
                    fi
                else
                    # Copy if missing or skel is newer; skip if dest is newer (user-modified).
                    if [[ -e "$dest" ]]; then
                        [[ "$item" -nt "$dest" ]] || continue
                    fi
                    run cp -a "$item" "$dest" \
                        && run chown "$uid:$gid" "$dest" \
                        || warn "cp skel $item failed for $username"
                fi
            done < <(find "$SKEL_DIR" -mindepth 1 ! -name '.gitkeep')
        fi
    fi

    # ── One-time bootstrap (stamp-guarded) ───────────────────────────────────
    # XDG dirs, flatpak/nix/subuid/podman bootstrap are expensive to probe and
    # only ever needed once per user. Skip when stamp matches.
    if [[ "$_stamp_ok" -ne 1 ]]; then

    # ── XDG user dirs ─────────────────────────────────────────────────────────
    if [[ "$HAS_XDG" -eq 1 ]]; then
        run runuser -u "$username" -- xdg-user-dirs-update 2>/dev/null \
            || warn "xdg-user-dirs-update failed for $username"
    fi

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
    if [[ "$HAS_NIX" -eq 1 ]]; then
        if ! runuser -u "$username" -- nix-channel --list 2>/dev/null \
                | grep -q "^nixpkgs "; then
            run runuser -u "$username" -- nix-channel --add \
                https://nixos.org/channels/nixpkgs-unstable nixpkgs 2>/dev/null \
                || warn "nix-channel add failed for $username"
            log "added nixpkgs channel for $username"
        fi
    fi

    # ── subuid/subgid (rootless podman / lxc / lxd) ──────────────────────────
    if [[ "$HAS_PODMAN" -eq 1 || "$HAS_LXC" -eq 1 || "$HAS_LXD" -eq 1 ]]; then
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

    # ── Skel dir permissions ──────────────────────────────────────────────────
    # Always run — user may have inadvertently changed modes on sensitive dirs.
    for d in .ssh .gnupg .config/systemd/user .local/share/keyrings .local/share/zsh; do
        [[ -d "$home/$d" ]] || continue
        _cur=$(stat -c '%a %u %g' "$home/$d" 2>/dev/null)
        [[ "$_cur" == "700 $uid $gid" ]] && continue
        run chmod 700 "$home/$d" && run chown "$uid:$gid" "$home/$d" \
            || warn "failed to fix permissions on $home/$d"
    done

    # ── SSH key permissions ───────────────────────────────────────────────────
    # Always run — user may have copied keys with wrong modes.
    if [[ -d "$home/.ssh" ]]; then
        _fix_file() {
            local f="$1" want_mode="$2"
            local cur_mode cur_owner cur_group
            cur_mode=$(stat -c %a "$f" 2>/dev/null)
            cur_owner=$(stat -c %u "$f" 2>/dev/null)
            cur_group=$(stat -c %g "$f" 2>/dev/null)
            [[ "$cur_mode"  != "$want_mode" ]] && { run chmod "$want_mode" "$f" || warn "chmod $want_mode $f failed"; }
            [[ "$cur_owner" != "$uid" || "$cur_group" != "$gid" ]] && { run chown "$uid:$gid" "$f" || warn "chown $f failed"; }
        }

        # Private keys — 600
        while IFS= read -r keyfile; do
            _fix_file "$keyfile" 600
        done < <(find "$home/.ssh" -maxdepth 1 -type f \
            ! -name "*.pub" \
            ! -name "authorized_keys" \
            ! -name "known_hosts" \
            ! -name "config" \
            ! -name ".gitkeep")

        # Public keys — 644
        while IFS= read -r pubfile; do
            _fix_file "$pubfile" 644
        done < <(find "$home/.ssh" -maxdepth 1 -type f -name "*.pub")

        [[ -f "$home/.ssh/authorized_keys" ]] && _fix_file "$home/.ssh/authorized_keys" 600
        [[ -f "$home/.ssh/known_hosts"     ]] && _fix_file "$home/.ssh/known_hosts"     644
        [[ -f "$home/.ssh/config"          ]] && _fix_file "$home/.ssh/config"          600
    fi

    # ── GnuPG key permissions ─────────────────────────────────────────────────
    # Always run — user may have imported new keys or changed modes.
    if [[ -d "$home/.gnupg" ]]; then
        while IFS= read -r f; do
            [[ "$(basename "$f")" == ".gitkeep" ]] && continue
            _fix_file "$f" 600
        done < <(find "$home/.gnupg" -maxdepth 1 -type f)

        while IFS= read -r d; do
            _cur=$(stat -c '%a %u %g' "$d" 2>/dev/null)
            [[ "$_cur" == "700 $uid $gid" ]] || {
                run chmod 700 "$d" && run chown "$uid:$gid" "$d" \
                    || warn "failed to fix permissions on $d"
            }
        done < <(find "$home/.gnupg" -mindepth 1 -maxdepth 1 -type d)

        if [[ -d "$home/.gnupg/private-keys-v1.d" ]]; then
            while IFS= read -r f; do
                _fix_file "$f" 600
            done < <(find "$home/.gnupg/private-keys-v1.d" -maxdepth 1 -type f)
        fi
    fi

    # ── Fix ownership ─────────────────────────────────────────────────────────
    # Only chown the home dir root itself — recursing into a large tree is
    # expensive and almost never needed. Specific files (keys, skel items) are
    # already chowned above where they're created or fixed.
    if [[ -d "$home" ]]; then
        current_owner=$(stat -c %u "$home" 2>/dev/null)
        current_group=$(stat -c %g "$home" 2>/dev/null)
        if [[ "$current_owner" != "$uid" || "$current_group" != "$gid" ]]; then
            log "fixing ownership of $home root (was $current_owner:$current_group, want $uid:$gid)"
            run chown "$uid:$gid" "$home" \
                || { warn "chown failed for $home"; user_ok=0; }
        fi
    fi

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

log "done — processed ${#processed[@]} user(s): ${processed[@]+"${processed[@]}"}"
[[ ${#skipped[@]}  -gt 0 ]] && log "skipped  ${#skipped[@]}  user(s): ${skipped[@]+"${skipped[@]}"}"
[[ ${#failed[@]}   -gt 0 ]] && warn "FAILED   ${#failed[@]}  user(s): ${failed[@]+"${failed[@]}"}"

[[ ${#failed[@]} -eq 0 ]]
