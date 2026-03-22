#!/bin/bash
# gen-efi.sh – Generate and update the Unified Kernel Image (UKI) for Secure Boot.
#
# Usage:
#   ./gen-efi.sh configure <target_slot>  — generate/update UKI for a slot
#   ./gen-efi.sh enroll-mok               — stage MOK enrollment without rebuilding UKI
#   ./gen-efi.sh enroll-tpm2              — enroll TPM2 for automatic LUKS unlock
#   ./gen-efi.sh cleanup-mok             — remove old MOK keys after new key is confirmed
#
# ENHANCED:
# - Validates target slot against booted slot
# - Auto-mounts/unmounts ESP
# - Safe for direct calls (only for current slot)
# - Safe for chroot calls (from shani-deploy)
#
# Must be run as root.

set -Eeuo pipefail

# Check for required dependencies.
REQUIRED_CMDS=("blkid" "dracut" "sbsign" "sbverify" "bootctl" "ls" "grep" "sort" "tail" "awk" "mkdir" "cat" "cryptsetup" "stat" "btrfs")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][ERROR] Required command '$cmd' not found. Please install it." >&2
        exit 1
    fi
done

if [[ $EUID -ne 0 ]]; then
    self=$(readlink -f "$0")
    if command -v pkexec &>/dev/null; then
        exec pkexec "$self" "$@"
    elif command -v sudo &>/dev/null; then
        exec sudo "$self" "$@"
    else
        echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][ERROR] Must run as root." >&2
        exit 1
    fi
fi

if [[ "${1:-}" != "configure" && "${1:-}" != "enroll-mok" && "${1:-}" != "enroll-tpm2" && "${1:-}" != "cleanup-mok" && "${1:-}" != "cleanup-tpm2" ]]; then
    echo "Usage:"
    echo "  $0 configure <target_slot>    — generate UKI for blue or green slot"
    echo "  $0 enroll-mok                — stage MOK enrollment (re-signs EFI binaries, no UKI rebuild)"
    echo "  $0 enroll-tpm2               — enroll TPM2 for automatic LUKS unlock"
    echo "  $0 cleanup-mok               — delete old MOK keys after new key is confirmed enrolled"
    echo "  $0 cleanup-tpm2              — remove stale TPM2 LUKS slots after re-enrolment"
    exit 1
fi

# TARGET_SLOT only required for configure
if [[ "${1:-}" == "configure" ]]; then
    if [[ -z "${2:-}" ]]; then
        echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][ERROR] Missing target slot. Usage: $0 configure <target_slot>" >&2
        exit 1
    fi
    TARGET_SLOT="$2"
    if [[ ! "$TARGET_SLOT" =~ ^(blue|green)$ ]]; then
        echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][ERROR] Invalid target slot '$TARGET_SLOT' — must be 'blue' or 'green'." >&2
        exit 1
    fi
    CMDLINE_FILE="/etc/kernel/install_cmdline_${TARGET_SLOT}"
else
    TARGET_SLOT=""
    CMDLINE_FILE=""
fi

# Configuration
readonly OS_NAME="shanios"
readonly ESP="/boot/efi"
readonly EFI_DIR="$ESP/EFI/${OS_NAME}"
readonly MOK_KEY="/etc/secureboot/keys/MOK.key"
readonly MOK_CRT="/etc/secureboot/keys/MOK.crt"
readonly ROOTLABEL="shani_root"

# Ensure MOK keys exist — they are normally placed by build-base-image.sh and
# verified by configure.sh at install time. If missing (e.g. custom image built
# without keys), generate a fresh set and set MOK_KEYS_GENERATED=1 so
# reenroll_mok_keys can re-sign existing EFI binaries and stage enrollment.
MOK_KEYS_GENERATED=0

ensure_mok_keys() {
    if [[ -f "$MOK_KEY" && -f "$MOK_CRT" ]]; then
        log "MOK keys present"
        # Validate MOK.der — regenerate from MOK.crt if missing or corrupt.
        # mokutil requires valid DER; a corrupt file produces:
        #   "Abort!!! ... is not a valid x509 certificate in DER format"
        local mok_der_path="/etc/secureboot/keys/MOK.der"
        local der_valid=0
        if [[ -f "$mok_der_path" ]]; then
            openssl x509 -in "$mok_der_path" -inform DER -noout &>/dev/null && der_valid=1
        fi
        if (( ! der_valid )); then
            log_warn "MOK.der missing or invalid — regenerating from MOK.crt"
            openssl x509 -in "$MOK_CRT" -outform DER \
                -out "$mok_der_path" \
                || error_exit "Failed to regenerate MOK.der from MOK.crt"
            log "MOK.der regenerated"
        fi
        return 0
    fi

    # MOK.der is the public cert only — the private key is never stored in the
    # EFI partition, so we cannot recover signing capability from MOK.der alone.
    if [[ -f /etc/secureboot/keys/MOK.der ]]; then
        log_warn "MOK.key or MOK.crt missing but MOK.der exists — keypair is partially corrupted"
        log_warn "The private key cannot be recovered from MOK.der"
    fi

    log_warn "Generating new MOK keypair"
    mkdir -p /etc/secureboot/keys
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$MOK_KEY" \
        -new -x509 -sha256 -days 3650 \
        -out "$MOK_CRT" \
        -subj "/CN=Shani OS Secure Boot Key/" \
        || error_exit "MOK key generation failed"

    openssl x509 -in "$MOK_CRT" -outform DER \
        -out /etc/secureboot/keys/MOK.der \
        || error_exit "MOK DER export failed"

    chmod 0600 "$MOK_KEY"
    MOK_KEYS_GENERATED=1
    log "MOK keys generated"
}

# Re-sign all existing EFI binaries with the newly generated keys and stage
# MOK enrollment. Called only when MOK_KEYS_GENERATED=1, after ESP is mounted.
reenroll_mok_keys() {
    log "Re-signing existing EFI binaries with new MOK keys"
    # Force-restore + re-sign bootloader binaries (grubx64.efi, shim)
    # then stage MOK enrollment via the shared helpers.
    update_bootloader force
    _stage_mok_enrollment || log_warn "MOK enrollment staging encountered an issue — EFI binaries were re-signed successfully"
}

_mokutil_hash_enroll() {
    local der_file="$1"
    local tmp_hash tmp_err
    tmp_hash=$(mktemp)
    tmp_err=$(mktemp)

    local hash_ok=0 import_ok=0
    if mokutil --generate-hash=shanios > "$tmp_hash" 2>"$tmp_err"; then
        hash_ok=1
    else
        log_warn "mokutil --generate-hash failed: $(cat "$tmp_err" 2>/dev/null)"
    fi

    if (( hash_ok )); then
        if mokutil --import "$der_file" --hash-file "$tmp_hash" >"$tmp_err" 2>&1; then
            import_ok=1
            log "MOK enrollment staged — confirm with password 'shanios' in MokManager on first boot"
        else
            log_warn "mokutil --import failed: $(cat "$tmp_err" 2>/dev/null)"
        fi
    fi

    if (( ! import_ok )); then
        log_warn "mokutil enrollment staging failed — MOK.der copied to ESP for manual enrollment"
        log_warn "Manual steps: reboot → select 'Enroll MOK' → 'Enroll key from disk' → EFI/BOOT/MOK.der"
    fi

    rm -f "$tmp_hash" "$tmp_err"
}

# Track if we mounted ESP
ESP_WAS_UNMOUNTED=0

log() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI] $*"
}

log_warn() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][WARN] $*"
}

error_exit() {
    log "ERROR: $*"
    # Only unmount ESP if we were the ones who mounted it
    if [[ ${ESP_WAS_UNMOUNTED:-0} -eq 1 ]]; then
        umount "$ESP" 2>/dev/null || true
        ESP_WAS_UNMOUNTED=0
    fi
    exit 1
}

# Detect if we're in chroot
in_chroot() {
    local root_id proc_id
    root_id=$(stat -c %d:%i / 2>/dev/null) || return 1
    proc_id=$(stat -c %d:%i /proc/1/root/. 2>/dev/null) || return 0
    [[ "$root_id" != "$proc_id" ]]
}

# Get currently booted slot — unified implementation matching shani-deploy/shani-update.
get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2- 2>/dev/null || echo "")
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    [[ -z "$subvol" ]] && subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    if [[ -z "$subvol" ]]; then
        error_exit "Cannot detect booted subvolume — /proc/cmdline has no subvol= and btrfs get-default returned nothing."
    fi
    echo "$subvol"
}

# Validate target slot
validate_target_slot() {
    local target="$1"

    # If in chroot, trust shani-deploy
    if in_chroot; then
        log "Running in chroot, proceeding..."
        return 0
    fi

    # Get booted slot
    local booted
    booted=$(get_booted_subvol)
    log "Booted slot: @${booted}"
    log "Target slot: @${target}"

    # Check if target matches booted
    if [[ "$target" != "$booted" ]]; then
        echo "" >&2
        log "ERROR: Cannot generate UKI for inactive slot from live system!"
        log "ERROR: You are booted in: @${booted}"
        log "ERROR: You are trying to generate for: @${target}"
        echo "" >&2
        log "ERROR: This would use @${booted}'s kernel for @${target}'s boot entry!"
        echo "" >&2
        log "ERROR: Solutions:"
        log "ERROR:   1. Run: gen-efi configure ${booted}  (regenerate current booted slot)"
        log "ERROR:      Or:  shani-deploy --fix-security  (auto-fixes booted slot UKI)"
        log "ERROR:   2. Use: shani-deploy  (handles @${target} via chroot on next deploy)"
        log "ERROR:      Or:  shani-deploy --rollback  (restores @${target} and regenerates its UKI)"
        echo "" >&2
        return 1
    fi

    log "Target matches booted slot, safe to proceed ✓"
    return 0
}

# Ensure ESP is mounted
ensure_esp_mounted() {
    if ! mountpoint -q "$ESP" 2>/dev/null; then
        log "ESP not mounted, mounting temporarily..."
        mount "$ESP" || error_exit "Failed to mount ESP"
        ESP_WAS_UNMOUNTED=1
    fi
}

# Unmount ESP if we mounted it
cleanup_esp() {
    if [[ $ESP_WAS_UNMOUNTED -eq 1 ]]; then
        log "Unmounting ESP..."
        umount "$ESP" 2>/dev/null || log "WARNING: Could not unmount ESP"
    fi
}

sign_efi_binary() {
    local file="$1"

    # Check if the binary is already validly signed with the current MOK.crt.
    # If so, skip signing — no need to re-sign or strip anything.
    if sbverify --cert "$MOK_CRT" "$file" &>/dev/null 2>&1; then
        log "$(basename "$file") already signed with current key — skipping"
        return 0
    fi

    # Not signed with our key — sign it now.
    # Use fixed .tmp names (not mktemp) so the EXIT trap and any manual cleanup
    # can find and remove them reliably. Only one root process runs at a time.
    local tmp_signed="${file}.signed.tmp"
    local tmp_backup="${file}.orig.tmp"
    rm -f "$tmp_signed" "$tmp_backup"
    cp "$file" "$tmp_backup" || { rm -f "$tmp_signed" "$tmp_backup"; error_exit "Failed to backup ${file} before signing"; }
    if sbsign --key "$MOK_KEY" --cert "$MOK_CRT" --output "$tmp_signed" "$file"; then
        mv "$tmp_signed" "$file"
    else
        rm -f "$tmp_signed" "$tmp_backup"
        error_exit "sbsign failed for $file"
    fi
    if ! sbverify --cert "$MOK_CRT" "$file" &>/dev/null 2>&1; then
        log_warn "sbverify failed for $file — restoring original"
        mv "$tmp_backup" "$file"
        error_exit "sbverify failed for $file — original restored"
    fi
    rm -f "$tmp_backup"
}

get_kernel_version() {
    local kernel_ver
    kernel_ver=$(find /usr/lib/modules/ -maxdepth 1 -mindepth 1 -type d \
        2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^/]*$' | sort -V | tail -n 1)
    if [[ -z "$kernel_ver" ]]; then
        error_exit "No valid kernel version found in /usr/lib/modules/"
    fi
    echo "$kernel_ver"
}

generate_cmdline() {
    local slot="$1"
    # Always regenerate — never reuse a cached file. The generation is fast
    # (one blkid call) and a stale file (e.g. after LUKS UUID change, swap
    # recreate, or keymap change) would silently produce a broken UKI.
    if [[ -f "$CMDLINE_FILE" ]]; then
        log "Regenerating cmdline for ${slot} (replacing existing ${CMDLINE_FILE})"
    fi

    local fs_uuid
    fs_uuid=$(blkid -s UUID -o value /dev/disk/by-label/"${ROOTLABEL}" 2>/dev/null || true)
    if [[ -z "$fs_uuid" ]]; then
        if [[ -f "$CMDLINE_FILE" ]]; then
            log_warn "Failed to retrieve filesystem UUID for label ${ROOTLABEL} — keeping existing cmdline file unchanged"
            return 2
        fi
        error_exit "Failed to retrieve filesystem UUID for label ${ROOTLABEL} and no existing cmdline to fall back to"
    fi

    local rootdev encryption_params resume_uuid

    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        local underlying
        underlying=$(cryptsetup status /dev/mapper/"${ROOTLABEL}" 2>/dev/null | sed -n 's/^ *device: //p' | tr -d '\n')
        if [[ -z "$underlying" ]]; then
            if [[ -f "$CMDLINE_FILE" ]]; then
                log_warn "Could not determine underlying block device for /dev/mapper/${ROOTLABEL} — keeping existing cmdline file unchanged"
                return 2
            fi
            error_exit "Could not determine underlying block device for /dev/mapper/${ROOTLABEL} and no existing cmdline to fall back to"
        fi
        local luks_uuid
        luks_uuid=$(cryptsetup luksUUID "$underlying" 2>/dev/null || true)
        if [[ -z "$luks_uuid" ]]; then
            if [[ -f "$CMDLINE_FILE" ]]; then
                log_warn "Failed to retrieve LUKS UUID from ${underlying} — keeping existing cmdline file unchanged"
                return 2
            fi
            error_exit "Failed to retrieve LUKS UUID from underlying device ${underlying} and no existing cmdline to fall back to"
        fi
        rootdev="/dev/mapper/${ROOTLABEL}"
        encryption_params=" rd.luks.uuid=${luks_uuid} rd.luks.name=${luks_uuid}=${ROOTLABEL} rd.luks.options=${luks_uuid}=tpm2-device=auto"
        resume_uuid="${luks_uuid}"
    else
        rootdev="UUID=${fs_uuid}"
        encryption_params=""
        resume_uuid="${fs_uuid}"
    fi

    local cmdline="quiet splash systemd.volatile=state ro lsm=landlock,lockdown,yama,integrity,apparmor,bpf rootfstype=btrfs rootflags=subvol=@${slot},ro,noatime,compress=zstd,space_cache=v2,autodefrag${encryption_params} root=${rootdev}"

    if [[ -f /etc/vconsole.conf ]]; then
        local keymap
        keymap=$(grep -E '^KEYMAP=' /etc/vconsole.conf 2>/dev/null | cut -d= -f2 || true)
        # Sanitize: keyboard layout names are alphanumeric with hyphens, dots, underscores only
        keymap=$(printf '%s' "$keymap" | tr -cd 'A-Za-z0-9._-')
        if [[ -n "$keymap" && ${#keymap} -le 64 ]]; then
            cmdline+=" rd.vconsole.keymap=$keymap"
        fi
    fi

    if [[ -f /swap/swapfile ]]; then
        local swap_offset btrfs_out

        # Get raw output (supports both old and new btrfs-progs)
        btrfs_out=$(btrfs inspect-internal map-swapfile -r /swap/swapfile 2>/dev/null || echo "")

        # Try parsing "resume_offset: <num>" first, fallback to last numeric field
        swap_offset=$(
            echo "$btrfs_out" \
            | awk -F'[: \t]+' '/resume_offset/ {print $2; found=1} END {if (!found) exit 1}' 2>/dev/null \
            || echo "$btrfs_out" | awk 'NF {last=$NF} END {print last+0}' 2>/dev/null \
            || echo ""
        )

        if [[ -n "$swap_offset" && "$swap_offset" != "0" ]]; then
            cmdline+=" resume=UUID=${resume_uuid} resume_offset=${swap_offset}"
        else
            log "WARNING: Swap file exists but failed to determine valid swap offset."
        fi
    fi

    # Write atomically: write to a fixed-name .tmp sibling then rename into
    # place. Using a fixed name (not mktemp) is fine — only one root process
    # runs this at a time and it avoids leaving random tmp files on failure.
    # The rename(2) is atomic on the same filesystem so the live file is never
    # partially overwritten.
    local tmp_cmdline="${CMDLINE_FILE}.tmp"
    mkdir -p "$(dirname "$CMDLINE_FILE")" || {
        if [[ -f "$CMDLINE_FILE" ]]; then
            log_warn "Could not create cmdline directory — keeping existing cmdline file unchanged"
            return 2
        fi
        error_exit "Could not create cmdline directory and no existing cmdline to fall back to"
    }
    printf '%s\n' "$cmdline" > "$tmp_cmdline" || {
        rm -f "$tmp_cmdline"
        if [[ -f "$CMDLINE_FILE" ]]; then
            log_warn "Failed to write cmdline — keeping existing cmdline file unchanged"
            return 2
        fi
        error_exit "Failed to write cmdline and no existing cmdline to fall back to"
    }
    chmod 0644 "$tmp_cmdline"
    if ! mv "$tmp_cmdline" "$CMDLINE_FILE"; then
        rm -f "$tmp_cmdline"
        if [[ -f "$CMDLINE_FILE" ]]; then
            log_warn "Failed to rename cmdline into place — keeping existing cmdline file unchanged"
            return 2
        fi
        error_exit "Failed to rename cmdline and no existing cmdline to fall back to"
    fi
    log "Kernel cmdline generated for ${slot} (saved in ${CMDLINE_FILE})"
}

ensure_crypttab() {
    local underlying
    underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
        | sed -n 's/^ *device: //p' | tr -d '\n')
    [[ -z "$underlying" ]] && error_exit "Could not determine underlying device for /dev/mapper/${ROOTLABEL}"

    local luks_uuid
    luks_uuid=$(cryptsetup luksUUID "$underlying" 2>/dev/null || true)
    [[ -z "$luks_uuid" ]] && error_exit "Could not retrieve LUKS UUID from $underlying"

    local keyfile_dest="/etc/cryptsetup-keys.d/${ROOTLABEL}.bin"
    local keyfile_opt="none"

    # /etc/crypttab — validate UUID matches live device even if file exists.
    # Rewrite only the UUID field if stale; preserve keyfile and options columns.
    # If the file exists but has no entry for ROOTLABEL (e.g. installed for a
    # different label), treat it as missing and append a correct entry.
    if [[ -f /etc/crypttab ]]; then
        local recorded_uuid
        recorded_uuid=$(awk -v label="${ROOTLABEL}" '$1==label {print $2}' /etc/crypttab \
            | sed 's/UUID=//' 2>/dev/null || true)
        if [[ -z "$recorded_uuid" ]]; then
            # No entry for our label — append one rather than rewriting the file
            log_warn "/etc/crypttab has no entry for ${ROOTLABEL} — appending"
            printf '%s\n' "${ROOTLABEL} UUID=${luks_uuid} none luks,discard" >> /etc/crypttab
            log "/etc/crypttab entry appended"
        elif [[ "$recorded_uuid" == "$luks_uuid" ]]; then
            log "/etc/crypttab UUID matches live device — ok"
        else
            log_warn "/etc/crypttab has stale UUID (${recorded_uuid}) — updating to ${luks_uuid}"
            local stale_keyfile stale_opts
            stale_keyfile=$(awk -v label="${ROOTLABEL}" '$1==label {print $3}' /etc/crypttab 2>/dev/null || echo "none")
            stale_opts=$(awk -v label="${ROOTLABEL}" '$1==label {print $4}' /etc/crypttab 2>/dev/null || echo "luks,discard")
            # Use defaults if fields were empty
            [[ -z "$stale_keyfile" ]] && stale_keyfile="none"
            [[ -z "$stale_opts" ]] && stale_opts="luks,discard"
            printf '%s\n' "${ROOTLABEL} UUID=${luks_uuid} ${stale_keyfile} ${stale_opts}" > /etc/crypttab
            log "/etc/crypttab UUID corrected"
        fi
        # Read keyfile field (post any correction) for dracut conf consistency below
        local existing_keyfile
        existing_keyfile=$(awk -v label="${ROOTLABEL}" '$1==label {print $3}' /etc/crypttab 2>/dev/null || true)
        if [[ -n "$existing_keyfile" && "$existing_keyfile" != "none" ]]; then
            keyfile_opt="$existing_keyfile"
        fi
    else
        # Detect keyfile from disk — keyfile systems vs PIN/passphrase systems
        if [[ -f "$keyfile_dest" ]]; then
            log "Keyfile present at ${keyfile_dest}"
            keyfile_opt="$keyfile_dest"
        elif [[ -f "${ESP}/crypto_keyfile.bin" ]]; then
            log "Recovering keyfile from ESP"
            mkdir -p "$(dirname "$keyfile_dest")"
            cp "${ESP}/crypto_keyfile.bin" "$keyfile_dest"
            chmod 0400 "$keyfile_dest"
            if cryptsetup open --test-passphrase --key-file="$keyfile_dest" "$underlying" &>/dev/null; then
                keyfile_opt="$keyfile_dest"
                log "Keyfile recovered and verified against LUKS volume"
            else
                log_warn "Recovered keyfile from ESP does NOT unlock ${underlying} — discarding, falling back to passphrase"
                rm -f "$keyfile_dest"
                keyfile_opt="none"
            fi
        else
            log "No keyfile found — PIN/passphrase system, crypttab will use 'none'"
        fi

        local entry="${ROOTLABEL} UUID=${luks_uuid} ${keyfile_opt} luks,discard"
        printf '%s\n' "$entry" > /etc/crypttab
        chmod 0644 /etc/crypttab
        log "/etc/crypttab written: ${entry}"
    fi

    # /etc/dracut.conf.d/99-crypt-key.conf — always rewrite to stay in sync
    # with the current keyfile_opt. A one-time write risks drift if the system
    # migrates between keyfile and PIN/passphrase configurations.
    mkdir -p /etc/dracut.conf.d
    local install_items="/etc/crypttab"
    [[ "$keyfile_opt" != "none" ]] && install_items+=" ${keyfile_opt}"
    local expected_conf
    expected_conf="install_items+=\" ${install_items} \""
    local current_conf=""
    [[ -f /etc/dracut.conf.d/99-crypt-key.conf ]] && \
        current_conf=$(cat /etc/dracut.conf.d/99-crypt-key.conf 2>/dev/null | tr -s ' ' | tr -d '\n')
    # Normalise expected the same way so trailing newline from printf does not
    # cause a false mismatch on every run.
    local expected_conf_norm
    expected_conf_norm=$(printf '%s' "$expected_conf" | tr -s ' ' | tr -d '\n')
    if [[ "$current_conf" != "$expected_conf_norm" ]]; then
        printf '%s\n' "$expected_conf" > /etc/dracut.conf.d/99-crypt-key.conf
        log "dracut crypt config updated (install_items: ${install_items})"
    else
        log "dracut crypt config up to date"
    fi
}


# _get_mok_fingerprint <der_file>
# Print the lowercase no-colon SHA1 fingerprint of a DER certificate.
_get_mok_fingerprint() {
    openssl x509 -in "$1" -inform DER -noout -fingerprint -sha1 2>/dev/null \
        | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' || echo ""
}

# _current_key_enrolled — return 0 if MOK.der is enrolled in firmware.
# Uses mokutil --test-key which is the correct API for this check.
_current_key_enrolled() {
    local mok_der="$1"
    [[ ! -f "$mok_der" ]] && return 1
    mokutil --test-key "$mok_der" 2>/dev/null | grep -qi 'is already enrolled' || return 1
}

# _has_old_enrolled_keys — return 0 if any enrolled key does NOT match MOK.der.
_has_old_enrolled_keys() {
    local mok_der="$1"
    local local_fp
    local_fp=$(_get_mok_fingerprint "$mok_der") || local_fp=""
    [[ -z "$local_fp" ]] && return 1

    # Parse all SHA1 fingerprints from enrolled list
    local enrolled_fps
    enrolled_fps=$(mokutil --list-enrolled 2>/dev/null \
        | grep -i 'SHA1 Fingerprint' \
        | sed 's/.*: //' | tr -d ':' | tr '[:upper:]' '[:lower:]') || return 1

    while IFS= read -r fp; do
        [[ -z "$fp" ]] && continue
        [[ "$fp" != "$local_fp" ]] && return 0   # found a foreign key
    done <<< "$enrolled_fps"
    return 1
}

# _stage_mok_enrollment — stage MOK key enrollment via mokutil.
# Shared by reenroll_mok_keys, enroll_mok, and generate_uki (key rotation path).
#
# Behaviour:
#   - Current key already enrolled            → silent, nothing to do
#   - Current key not enrolled, none pending  → stage via mokutil --import
#   - Current key not enrolled, different key pending → clear pending, re-stage
#   - Current key not enrolled, same key pending      → already queued, skip
#
# Always warns if old (different) keys remain enrolled — user should run
# "gen-efi cleanup-mok" after confirming the new key.
_stage_mok_enrollment() {
    local mok_der="/etc/secureboot/keys/MOK.der"

    # Always copy DER to ESP — needed for MokManager manual fallback and TPM re-enroll
    cp "$mok_der" "$ESP/EFI/BOOT/MOK.der" || log_warn "Failed to copy MOK.der to ESP"

    # Current key already enrolled — nothing to do
    if _current_key_enrolled "$mok_der"; then
        log "MOK key already enrolled in firmware"
        # Warn if stale keys also exist (leftover from a previous rotation)
        if _has_old_enrolled_keys "$mok_der"; then
            log_warn "Old MOK keys detected in firmware — run: gen-efi cleanup-mok"
        fi
        return 0
    fi

    # Current key not enrolled — check pending queue
    local pending_fps
    pending_fps=$(mokutil --list-new 2>/dev/null \
        | grep -i 'SHA1 Fingerprint' \
        | sed 's/.*: //' | tr -d ':' | tr '[:upper:]' '[:lower:]') || pending_fps=""

    local local_fp
    local_fp=$(_get_mok_fingerprint "$mok_der") || local_fp=""

    if [[ -n "$local_fp" ]] && echo "$pending_fps" | grep -qx "$local_fp"; then
        # Correct key is already queued — just remind user
        log "MOK enrollment already pending for current key"
        log_warn "ACTION REQUIRED: reboot and confirm MOK enrollment in MokManager"
        return 0
    fi

    # A different key is pending — clear it and re-stage with current key
    if [[ -n "$pending_fps" ]]; then
        log_warn "Pending MOK enrollment is for a different key — clearing and re-staging"
        mokutil --revoke-import 2>/dev/null || log_warn "mokutil --revoke-import failed — proceeding anyway"
    fi

    # Stage enrollment
    _mokutil_hash_enroll "$mok_der"
    log_warn "ACTION REQUIRED: reboot and confirm MOK enrollment in MokManager"

    # Inform about old enrolled keys that will remain until cleanup
    if _has_old_enrolled_keys "$mok_der"; then
        log_warn "Old MOK keys remain enrolled — after reboot run: gen-efi cleanup-mok"
    fi
}

# cleanup_tpm2 — remove stale TPM2 LUKS keyslots left after re-enrolment.
#
# Each call to enroll-tpm2 adds a new TPM2 slot. The old slot is wiped
# automatically during enrol, but if that wipe failed (credential unavailable,
# older systemd) stale slots accumulate. This command finds all TPM2-type
# slots in the LUKS header and removes every one except the highest-numbered
# (most recently written), after confirming at least one healthy TPM2 slot
# exists so the system can still auto-unlock.
#
# Safe to run at any time after a successful enroll-tpm2.
cleanup_tpm2() {
    if in_chroot; then
        error_exit "cleanup-tpm2 must run on the live booted system, not inside a chroot"
    fi

    if [[ ! -e "/dev/mapper/${ROOTLABEL}" ]]; then
        error_exit "No LUKS mapper /dev/mapper/${ROOTLABEL} found — system does not appear to be encrypted"
    fi

    if ! command -v systemd-cryptenroll &>/dev/null; then
        error_exit "systemd-cryptenroll not found — install systemd"
    fi

    local underlying
    underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
        | sed -n 's/^ *device: //p' | tr -d '\n')
    [[ -z "$underlying" ]] && error_exit "Could not determine underlying LUKS device for /dev/mapper/${ROOTLABEL}"

    # Collect all TPM2 slot numbers from the LUKS header
    local -a tpm2_slots=()
    local slot_num
    while IFS= read -r slot_num; do
        [[ -n "$slot_num" ]] && tpm2_slots+=("$slot_num")
    done < <(cryptsetup luksDump "$underlying" 2>/dev/null \
        | awk '
            /^Tokens:/ { in_tokens=1 }
            in_tokens && /^[[:space:]]+[0-9]+:/ { current=gensub(/^[[:space:]]+([0-9]+):.*/, "\1", 1) }
            in_tokens && current && /systemd-tpm2|"type".*tpm2/ { print current; current="" }
        ' 2>/dev/null | sort -n || true)

    if [[ ${#tpm2_slots[@]} -eq 0 ]]; then
        log "No TPM2 slots found in LUKS header — nothing to clean up"
        return 0
    fi

    if [[ ${#tpm2_slots[@]} -eq 1 ]]; then
        log "Only one TPM2 slot present (slot ${tpm2_slots[0]}) — nothing to clean up"
        return 0
    fi

    log "Found ${#tpm2_slots[@]} TPM2 slots: ${tpm2_slots[*]}"

    # Keep the highest-numbered slot (most recently enrolled), wipe the rest
    local keep_slot="${tpm2_slots[-1]}"
    log "Keeping slot ${keep_slot} (most recent) — wiping ${#tpm2_slots[@]}-1 stale slot(s)"

    local keyfile="/etc/cryptsetup-keys.d/${ROOTLABEL}.bin"
    local wiped=0 failed=0

    for slot_num in "${tpm2_slots[@]}"; do
        [[ "$slot_num" == "$keep_slot" ]] && continue
        log "Wiping stale TPM2 slot ${slot_num}..."
        local wipe_ok=0
        if [[ -f "$keyfile" ]]; then
            cryptsetup luksKillSlot --key-file="$keyfile" "$underlying" "$slot_num" 2>/dev/null \
                && wipe_ok=1
        fi
        if (( ! wipe_ok )); then
            systemd-cryptenroll --wipe-slot="$slot_num" "$underlying" 2>/dev/null \
                && wipe_ok=1
        fi
        if (( wipe_ok )); then
            log "Slot ${slot_num} wiped"
            (( wiped++ ))
        else
            log_warn "Could not wipe slot ${slot_num} — remove manually:"
            log_warn "  cryptsetup luksKillSlot ${underlying} ${slot_num}"
            (( failed++ ))
        fi
    done

    if (( wiped > 0 )); then
        log "${wiped} stale TPM2 slot(s) removed"
    fi
    if (( failed > 0 )); then
        log_warn "${failed} slot(s) could not be removed automatically — see above for manual commands"
    fi
}

# cleanup_mok — delete enrolled MOK keys that don't match the current MOK.der.
#
# Safe to run only AFTER the new key has been confirmed enrolled in firmware.
# Deletes stale keys left over from a key rotation (e.g. image shipped with
# a new key replacing the old one).
#
# Each deletion is staged via mokutil --delete and confirmed in MokManager on
# the next reboot — same one-time prompt as enrollment.
cleanup_mok() {
    if in_chroot; then
        error_exit "cleanup-mok must run on the live booted system, not inside a chroot"
    fi

    local mok_der="/etc/secureboot/keys/MOK.der"
    [[ ! -f "$mok_der" ]] && error_exit "MOK.der not found at ${mok_der}"

    # Ensure current key is enrolled before deleting anything
    if ! _current_key_enrolled "$mok_der"; then
        error_exit "Current MOK key is not yet enrolled — enroll it first (reboot and confirm MokManager), then run cleanup-mok"
    fi

    if ! _has_old_enrolled_keys "$mok_der"; then
        log "No old MOK keys to clean up — firmware is up to date"
        return 0
    fi

    local local_fp
    local_fp=$(_get_mok_fingerprint "$mok_der") || local_fp=""

    local deleted=0

    # mokutil --export writes each enrolled cert as MoK-0001, MoK-0002 etc into CWD.
    # Work in a temp dir so exported files don't land in an unpredictable location.
    local export_dir
    export_dir=$(mktemp -d)
    # Run export in a known CWD so MoK-* files land predictably
    pushd "$export_dir" >/dev/null
    mokutil --export 2>/dev/null || true
    popd >/dev/null
    for cert_file in "$export_dir"/MoK-*; do  # files exported directly into export_dir
        [[ -f "$cert_file" ]] || continue
        local fp
        fp=$(openssl x509 -in "$cert_file" -inform DER -noout -fingerprint -sha1 2>/dev/null \
            | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' || echo "")
        if [[ -n "$fp" && "$fp" != "$local_fp" ]]; then
            log "Staging deletion of old key: ${fp}"
            local tmp_hash_del tmp_err_del
            tmp_hash_del=$(mktemp)
            tmp_err_del=$(mktemp)
            if mokutil --generate-hash=shanios > "$tmp_hash_del" 2>"$tmp_err_del" && \
               mokutil --delete "$cert_file" --hash-file "$tmp_hash_del" >"$tmp_err_del" 2>&1; then
                (( deleted++ ))
            else
                log_warn "Failed to stage deletion for ${fp}: $(cat "$tmp_err_del" 2>/dev/null)"
                log_warn "Manual removal: mokutil --delete <key.der>"
            fi
            rm -f "$tmp_hash_del" "$tmp_err_del"
        fi
    done
    rm -rf "$export_dir"

    if (( deleted > 0 )); then
        log_warn "ACTION REQUIRED: reboot and confirm MOK key deletion in MokManager (${deleted} old key(s) staged for removal)"
    else
        log_warn "Could not automatically stage old key deletion — remove manually via MokManager"
        log_warn "  List enrolled: mokutil --list-enrolled"
        log_warn "  Delete a key:  mokutil --delete <key.der>"
    fi
}


# update_bootloader — update shim and systemd-boot on the ESP if the source
# binaries are newer than what is currently installed. Re-signs after update.
# configure.sh installs these at install time; gen-efi.sh keeps them current
# on subsequent kernel/systemd updates since bootctl update would deploy
# an unsigned binary on this immutable signed system.
# _pe_valid — return 0 if file has a valid PE DOS header ("MZ" magic), 1 otherwise.
_pe_valid() {
    local magic
    magic=$(dd if="$1" bs=2 count=1 2>/dev/null | od -A n -t x1 | tr -d ' \n' || echo "")
    [[ "$magic" == "4d5a" ]]
}

# update_bootloader [force]
# Without "force": copy only when source is newer than destination.
# With    "force": also restore if destination is missing or has an invalid PE header
#                  (used by enroll_mok to recover from a corrupted binary).
update_bootloader() {
    local force="${1:-}"
    local shim_src="/usr/share/shim-signed/shimx64.efi"
    local shim_dst="${ESP}/EFI/BOOT/BOOTX64.EFI"
    local sdboot_src="/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
    local sdboot_dst="${ESP}/EFI/BOOT/grubx64.efi"
    local mmx64_src="/usr/share/shim-signed/mmx64.efi"
    local mmx64_dst="${ESP}/EFI/BOOT/mmx64.efi"
    local updated=0

    # shim (BOOTX64.EFI) — Microsoft-signed, never re-signed by us
    if [[ -f "$shim_src" ]]; then
        local shim_needs_copy=0
        [[ ! -f "$shim_dst" || "$shim_src" -nt "$shim_dst" ]] && shim_needs_copy=1
        [[ "$force" == "force" && -f "$shim_dst" ]] && ! _pe_valid "$shim_dst" && shim_needs_copy=1
        if (( shim_needs_copy )); then
            log "Updating shim: ${shim_dst}"
            cp "$shim_src" "$shim_dst" || error_exit "Failed to copy shim"
            updated=1
        else
            log "shim is up to date"
        fi
    else
        log_warn "shim source not found at ${shim_src} — skipping shim update"
    fi

    # MokManager (mmx64.efi) — not signed, shim verifies via its own hash
    if [[ -f "$mmx64_src" ]]; then
        local mmx64_needs_copy=0
        [[ ! -f "$mmx64_dst" || "$mmx64_src" -nt "$mmx64_dst" ]] && mmx64_needs_copy=1
        [[ "$force" == "force" && -f "$mmx64_dst" ]] && ! _pe_valid "$mmx64_dst" && mmx64_needs_copy=1
        if (( mmx64_needs_copy )); then
            log "Updating MokManager: ${mmx64_dst}"
            cp "$mmx64_src" "$mmx64_dst" || error_exit "Failed to copy mmx64.efi"
            updated=1
        else
            log "MokManager is up to date"
        fi
    else
        log_warn "mmx64.efi source not found at ${mmx64_src} — skipping MokManager update"
    fi

    # systemd-boot (grubx64.efi — loaded by shim as second-stage bootloader)
    if [[ -f "$sdboot_src" ]]; then
        local sdboot_needs_copy=0
        [[ ! -f "$sdboot_dst" || "$sdboot_src" -nt "$sdboot_dst" ]] && sdboot_needs_copy=1
        if [[ "$force" == "force" && -f "$sdboot_dst" ]] && ! _pe_valid "$sdboot_dst"; then
            log_warn "grubx64.efi has invalid PE header — restoring from source"
            sdboot_needs_copy=1
        fi
        if (( sdboot_needs_copy )); then
            log "Updating systemd-boot: ${sdboot_dst}"
            cp "$sdboot_src" "$sdboot_dst" || error_exit "Failed to copy systemd-boot"
            sign_efi_binary "$sdboot_dst"
            updated=1
        else
            log "systemd-boot is up to date"
        fi
    else
        log_warn "systemd-boot source not found at ${sdboot_src} — skipping bootloader update"
    fi

    [[ $updated -eq 1 ]] && log "Bootloader update complete" || log "All bootloader components up to date"
}

# generate_uki generates the UKI image for the given slot.
generate_uki() {
    local slot="$1"

    # VALIDATE target slot
    validate_target_slot "$slot" || error_exit "Slot validation failed"

    # Ensure keys exist — generate if missing
    ensure_mok_keys

    # Ensure ESP is mounted before we start
    ensure_esp_mounted
    mkdir -p "$EFI_DIR"

    # If keys were just generated, re-sign existing EFI binaries and stage enrollment
    # now that ESP is mounted. reenroll_mok_keys calls update_bootloader force
    # internally, so skip the regular update_bootloader call below in that case.
    if [[ $MOK_KEYS_GENERATED -eq 1 ]]; then
        reenroll_mok_keys
    else
        # Update shim and systemd-boot on the ESP if source binaries are newer.
        update_bootloader
    fi

    local kernel_ver
    kernel_ver=$(get_kernel_version)
    log "Using kernel: $kernel_ver"
    local uki_path="$EFI_DIR/${OS_NAME}-${slot}.efi"

    # Now that uki_path is defined, arm the EXIT trap to clean up tmp files
    # and unmount ESP if we mounted it.
    trap 'cleanup_esp; rm -f "${CMDLINE_FILE}.tmp" "${uki_path}.tmp" "${uki_path}.tmp.signed.tmp" "${uki_path}.tmp.orig.tmp"' EXIT

    # ensure_crypttab before generate_cmdline — crypttab must exist before
    # dracut runs, and setting it up first keeps the logical order clear.
    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        ensure_crypttab
    fi

    local cmdline_rc=0
    generate_cmdline "$slot" || cmdline_rc=$?
    if (( cmdline_rc == 2 )); then
        log_warn "Cmdline generation fell back to existing file — UKI will be built with previous cmdline"
    elif (( cmdline_rc != 0 )); then
        error_exit "generate_cmdline failed unexpectedly (rc=${cmdline_rc})"
    fi
    local kernel_cmdline
    kernel_cmdline=$(<"$CMDLINE_FILE")
    if [[ -z "$kernel_cmdline" ]]; then
        error_exit "Kernel command line is empty."
    fi

    dracut --force --uefi --kver "$kernel_ver" --kernel-cmdline "$kernel_cmdline" "${uki_path}.tmp" || error_exit "dracut failed"
    sign_efi_binary "${uki_path}.tmp"
    mv "${uki_path}.tmp" "$uki_path" || error_exit "Failed to move signed UKI into place"

    # Key rotation: if the current key is not yet enrolled in firmware, stage
    # enrollment automatically. Silent when already enrolled (common case).
    # Runs in chroot too — shani-deploy bind-mounts /sys so mokutil can reach
    # the live EFI variable store via /sys/firmware/efi/efivars.
    # Non-fatal: UKI is already built and signed at this point; a mokutil
    # failure (e.g. read-only efivars in chroot) must not fail the whole deploy.
    _stage_mok_enrollment || log_warn "MOK enrollment staging encountered an issue — UKI was built and signed successfully"

    # Clear the EXIT trap before returning — uki_path is local and would be
    # unbound when the trap fires on process exit. Call cleanup_esp explicitly
    # here so the ESP is still unmounted if we mounted it.
    trap - EXIT
    cleanup_esp
}


# enroll_mok — stage MOK enrollment without rebuilding the UKI.
#
# Use this when:
#   - The MOK key was regenerated (keypair changed) but UKIs are otherwise valid
#   - The enrolled MOK in firmware does not match the local MOK.der
#   - Secure Boot was enabled and the key needs enrolling for the first time
#
# What it does:
#   1. Ensures MOK keypair exists (generates one if missing)
#   2. Mounts ESP temporarily if needed
#   3. Re-signs all EFI binaries on the ESP with the current MOK key
#      (BOOTX64.EFI/shim is NOT re-signed — it is Microsoft-signed)
#   4. Copies MOK.der to the ESP so MokManager can present it at next boot
#   5. Stages enrollment via mokutil --import --hash-file
#
# After running: reboot and confirm MOK enrollment in the MokManager UEFI prompt.
# Note: does NOT rebuild UKIs — run 'gen-efi configure <slot>' if UKIs also need
# to be regenerated (e.g. after a full keypair replacement).
enroll_mok() {
    # Cannot run in chroot — needs live ESP and mokutil talking to real firmware
    if in_chroot; then
        error_exit "enroll-mok must run on the live booted system, not inside a chroot"
    fi

    # Keys must already exist — enroll-mok only enrolls, it does not generate.
    # Generating keys without rebuilding UKIs would enroll a key that does not
    # match the signatures on the existing ESP binaries, causing Secure Boot to
    # reject them at boot.
    # If keys are missing: run "gen-efi configure <slot>" first (generates keys
    # and rebuilds UKIs with them), then run "gen-efi enroll-mok".
    if [[ ! -f "$MOK_KEY" || ! -f "$MOK_CRT" ]]; then
        error_exit "MOK keys not found at ${MOK_KEY} / ${MOK_CRT}\n"\
"  Keys must exist before enrolling. Run: gen-efi configure <slot>\n"\
"  That will generate the keys and rebuild the UKIs. Then run: gen-efi enroll-mok"
    fi

    # Validate MOK.der — regenerate from MOK.crt if missing or corrupt.
    # Keys are confirmed present above so this only runs the DER check.
    ensure_mok_keys

    # Mount ESP if needed
    trap 'cleanup_esp' EXIT
    ensure_esp_mounted
    mkdir -p "$EFI_DIR"

    # Restore any corrupt bootloader binaries, update if source is newer,
    # then re-sign everything — all handled by update_bootloader force.
    update_bootloader force

    # Re-sign any UKIs already on the ESP (update_bootloader only covers grubx64.efi)
    for slot in blue green; do
        local uki="$EFI_DIR/${OS_NAME}-${slot}.efi"
        if [[ -f "$uki" ]]; then
            log "Re-signing ${uki}"
            ( sign_efi_binary "$uki" ) || log_warn "Failed to re-sign ${uki} — continuing"
        fi
    done

    # Stage MOK enrollment
    _stage_mok_enrollment || log_warn "MOK enrollment staging encountered an issue — EFI binaries were re-signed successfully"
}

# enroll_tpm2 — enroll the TPM2 chip into the LUKS2 volume for automatic unlock.
#
# Must run on the LIVE booted system (not in a chroot) — it talks to real TPM
# hardware and seals against current PCR values.
#
# PCR policy (matches wiki.shani.dev instructions):
#   With Secure Boot:    PCR 0+7
#     PCR 0 — firmware/BIOS measurements (detects firmware tampering)
#     PCR 7 — Secure Boot state (UEFI db/dbx/pk certificates)
#   Without Secure Boot: PCR 0 only
#
# The sealed key is released only if the firmware and Secure Boot state
# match exactly what was recorded at enrollment time. An attacker with a
# different boot chain cannot unseal the key.
#
# Your LUKS passphrase remains valid as a fallback at all times.
# Re-enroll after: firmware updates, enabling/disabling Secure Boot, MOK changes.
enroll_tpm2() {
    # Must run on live system — TPM hardware not accessible in chroot
    if in_chroot; then
        error_exit "enroll-tpm2 must run on the live booted system, not inside a chroot"
    fi

    # Encryption must be active
    if [[ ! -e "/dev/mapper/${ROOTLABEL}" ]]; then
        error_exit "No LUKS mapper /dev/mapper/${ROOTLABEL} found — system does not appear to be encrypted"
    fi

    # systemd-cryptenroll required
    if ! command -v systemd-cryptenroll &>/dev/null; then
        error_exit "systemd-cryptenroll not found — install systemd (tpm2-tss must also be installed)"
    fi

    # Verify TPM2 device is present
    log "Checking TPM2 device..."
    if ! { systemd-cryptenroll --tpm2-device=list 2>/dev/null || true; } | grep -q .; then
        error_exit "No TPM2 device found — ensure TPM 2.0 is enabled in BIOS/UEFI"
    fi

    # Derive the underlying LUKS block device
    local underlying
    underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
        | sed -n 's/^ *device: //p' | tr -d '\n')
    [[ -z "$underlying" ]] && error_exit "Could not determine underlying LUKS device for /dev/mapper/${ROOTLABEL}"
    log "LUKS device: ${underlying}"

    # Choose PCR policy based on Secure Boot state
    local pcrs
    local sb_state
    sb_state=$(mokutil --sb-state 2>/dev/null || true)
    if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then
        pcrs="0+7"
        log "Secure Boot is enabled — using PCR policy: ${pcrs} (firmware + Secure Boot state)"
    else
        pcrs="0"
        log_warn "Secure Boot is not enabled — using PCR policy: ${pcrs} (firmware only)"
        log_warn "Without Secure Boot, an attacker with physical access could replace the bootloader to steal the key"
        log_warn "Consider enabling Secure Boot for maximum protection"
    fi

    log "Enrolling TPM2..."
    local keyfile="/etc/cryptsetup-keys.d/${ROOTLABEL}.bin"
    if [[ -f "$keyfile" ]]; then
        # Keyfile-based system (no PIN set at install) — must unlock via keyfile
        # since no passphrase was set. The keyfile is the only non-TPM credential.
        log "Keyfile system detected — unlocking via ${keyfile}"
        systemd-cryptenroll \
            --tpm2-device=auto \
            --tpm2-pcrs="${pcrs}" \
            --unlock-key-file="$keyfile" \
            "$underlying" \
            || error_exit "TPM2 enrollment failed"
    else
        # PIN system — LUKS passphrase was set at install, prompt interactively.
        # Also ask whether to require a TPM2 PIN at boot. A PIN means the TPM
        # will not unseal without user input even when PCRs match, giving a
        # second factor. Without it, any boot on matching hardware auto-unlocks.
        # Default is yes — the user already chose interactive unlock at install.
        local tpm2_pin_flag=""
        local use_tpm2_pin
        read -r -p "Require a TPM2 PIN at boot? [y/N]: " use_tpm2_pin
        use_tpm2_pin="${use_tpm2_pin:-N}"
        if [[ "${use_tpm2_pin^^}" == "Y" ]]; then
            tpm2_pin_flag="--tpm2-with-pin=yes"
            log "TPM2 PIN will be required at boot"
        else
            log "TPM2 PIN not set — disk will unlock automatically on matching hardware"
        fi
        log "PIN system detected — you will be prompted for your LUKS passphrase"
        systemd-cryptenroll \
            --tpm2-device=auto \
            --tpm2-pcrs="${pcrs}" \
            ${tpm2_pin_flag:+"$tpm2_pin_flag"} \
            "$underlying" \
            || error_exit "TPM2 enrollment failed"
    fi

    log "TPM2 enrolled successfully with PCR policy: ${pcrs}"
    log "The disk will unlock automatically on next boot"
    log ""
    log "Important reminders:"
    log "  - Your LUKS passphrase remains valid as fallback"
    log "  - Re-enroll after firmware updates, Secure Boot changes, or MOK changes:"
    log "      gen-efi enroll-tpm2"
    log "  - If re-enrolling, clean up stale slots afterwards:"
    log "      gen-efi cleanup-tpm2"
    log "  - To remove TPM enrollment:"
    log "      systemd-cryptenroll --wipe-slot=tpm2 ${underlying}"
    log "  - Verify enrollment:"
    log "      cryptsetup luksDump ${underlying} | grep systemd-tpm2"
}

case "${1:-}" in
    configure)
        generate_uki "$TARGET_SLOT"
        log "UKI generated for ${TARGET_SLOT}"
        ;;
    enroll-mok)
        enroll_mok
        ;;
    enroll-tpm2)
        enroll_tpm2
        ;;
    cleanup-mok)
        cleanup_mok
        ;;
    cleanup-tpm2)
        cleanup_tpm2
        ;;
    *)
        echo "Usage:"
        echo "  $0 configure <target_slot>"
        echo "  $0 enroll-mok"
        echo "  $0 enroll-tpm2"
        echo "  $0 cleanup-mok"
        echo "  $0 cleanup-tpm2"
        exit 1
        ;;
esac
