#!/usr/bin/env bash
# gen-efi.sh – Generate and update the Unified Kernel Image (UKI) for Secure Boot.
#
# Usage: ./gen-efi.sh configure <target_slot>
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

if [[ "${1:-}" != "configure" ]]; then
    echo "Usage: $0 configure <target_slot>"
    exit 1
fi

if [[ -z "${2:-}" ]]; then
    echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][ERROR] Missing target slot. Usage: $0 configure <target_slot>" >&2
    exit 1
fi

TARGET_SLOT="$2"
if [[ ! "$TARGET_SLOT" =~ ^(blue|green)$ ]]; then
    echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][ERROR] Invalid target slot '$TARGET_SLOT' — must be 'blue' or 'green'." >&2
    exit 1
fi

# Configuration
OS_NAME="shanios"
ESP="/boot/efi"
EFI_DIR="$ESP/EFI/${OS_NAME}"
CMDLINE_FILE="/etc/kernel/install_cmdline_${TARGET_SLOT}"
MOK_KEY="/etc/secureboot/keys/MOK.key"
MOK_CRT="/etc/secureboot/keys/MOK.crt"
ROOTLABEL="shani_root"

# Ensure MOK keys exist — they are normally placed by build-base-image.sh and
# verified by configure.sh at install time. If missing (e.g. custom image built
# without keys), generate a fresh set and set MOK_KEYS_GENERATED=1 so
# reenroll_mok_keys can re-sign existing EFI binaries and stage enrollment.
MOK_KEYS_GENERATED=0

ensure_mok_keys() {
    if [[ -f "$MOK_KEY" && -f "$MOK_CRT" ]]; then
        log "MOK keys present"
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

    # Re-sign shim and systemd-boot (grubx64.efi) — these were signed with the
    # old keys and must be updated before the next boot.
    local efi_bins=(
        "$ESP/EFI/BOOT/BOOTX64.EFI"
        "$ESP/EFI/BOOT/grubx64.efi"
    )
    for bin in "${efi_bins[@]}"; do
        if [[ -f "$bin" ]]; then
            log "Re-signing ${bin}"
            sign_efi_binary "$bin" || log_warn "Failed to re-sign ${bin} — continuing"
        else
            log_warn "EFI binary not found, skipping: ${bin}"
        fi
    done

    # Copy updated DER to EFI partition so MokManager can offer enrollment
    cp /etc/secureboot/keys/MOK.der "$ESP/EFI/BOOT/MOK.der" \
        || log_warn "Failed to copy MOK.der to ESP — manual enrollment may be required"

    # Stage MOK enrollment — use --root-pw if root has a password, otherwise
    # use --hash-file with a generated hash.
    local mok_der="/etc/secureboot/keys/MOK.der"
    if [[ -s /etc/shadow ]] && awk -F: '$1=="root" && $2!="" && $2!="*" && $2!="!" {found=1} END{exit !found}' /etc/shadow 2>/dev/null; then
        log "Staging MOK enrollment via --root-pw"
        if ! mokutil --import "$mok_der" --root-pw >/dev/null 2>&1; then
            log_warn "mokutil --root-pw failed — falling back to hash-file method"
            _mokutil_hash_enroll "$mok_der"
        fi
    else
        log "No root password set — staging MOK enrollment via password hash"
        _mokutil_hash_enroll "$mok_der"
    fi

    log_warn "SYSTEM REBOOT REQUIRED — confirm MOK enrollment in MokManager on next boot"
}

_mokutil_hash_enroll() {
    local der_file="$1"
    local tmp_hash
    tmp_hash=$(mktemp)
    if mokutil --generate-hash=shanios > "$tmp_hash" 2>/dev/null \
        && mokutil --import "$der_file" --hash-file "$tmp_hash" >/dev/null 2>&1; then
        log "MOK enrollment staged — confirm with password 'shanios' in MokManager on first boot"
    else
        log_warn "mokutil enrollment staging failed — MOK.der is in ESP for manual enrollment"
    fi
    rm -f "$tmp_hash"
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
get_booted_slot() {
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
    local booted=$(get_booted_slot)
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
        log "ERROR:   1. Run: gen-efi configure ${booted}  (generate for current slot)"
        log "ERROR:   2. Use: shani-deploy  (it chroots correctly)"
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
    sbsign --key "$MOK_KEY" --cert "$MOK_CRT" --output "$file" "$file" || error_exit "sbsign failed for $file"
    sbverify --cert "$MOK_CRT" "$file" || error_exit "sbverify failed for $file"
}

get_kernel_version() {
    local kernel_ver
    kernel_ver=$(ls -1 /usr/lib/modules/ 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' 2>/dev/null || true)
    kernel_ver=$(echo "$kernel_ver" | sort -V | tail -n 1)
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
        error_exit "Failed to retrieve filesystem UUID for label ${ROOTLABEL}"
    fi

    local rootdev encryption_params resume_uuid

    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        local underlying
        underlying=$(cryptsetup status /dev/mapper/"${ROOTLABEL}" 2>/dev/null | sed -n 's/^ *device: //p' || true)
        local luks_uuid
        luks_uuid=$(cryptsetup luksUUID "$underlying" 2>/dev/null || true)
        if [[ -z "$luks_uuid" ]]; then
            error_exit "Failed to retrieve LUKS UUID from underlying device $underlying"
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
        local swap_offset
        swap_offset=$(btrfs inspect-internal map-swapfile -r /swap/swapfile | awk '{print $NF}' 2>/dev/null || true)
        if [[ -n "$swap_offset" ]]; then
            cmdline+=" resume=UUID=${resume_uuid} resume_offset=${swap_offset}"
        else
            log "WARNING: Swap file exists but failed to determine swap offset."
        fi
    fi

    echo "$cmdline" > "$CMDLINE_FILE"
    chmod 0644 "$CMDLINE_FILE"
    log "Kernel cmdline generated for ${slot} (saved in ${CMDLINE_FILE})"
}

# ensure_crypttab — create /etc/crypttab and /etc/dracut.conf.d/99-crypt-key.conf
# if either is missing. Both are checked independently.
#
# Handles two install configurations:
#   PIN/passphrase (OSI_ENCRYPTION_PIN set at install):
#     crypttab keyfile field = "none" → dracut conf has no keyfile in install_items
#   Keyfile (no OSI_ENCRYPTION_PIN at install):
#     keyfile at /etc/cryptsetup-keys.d/shani_root.bin → dracut conf includes it
#
# Keyfile recovery order when crypttab is missing:
#   1. Already present at /etc/cryptsetup-keys.d/shani_root.bin → use as-is
#   2. Present on ESP at /boot/efi/crypto_keyfile.bin → copy into place
#   3. Neither found → "none" (PIN/passphrase at boot)
ensure_crypttab() {
    local underlying
    underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
        | sed -n 's/^ *device: //p' || true)
    [[ -z "$underlying" ]] && error_exit "Could not determine underlying device for /dev/mapper/${ROOTLABEL}"

    local luks_uuid
    luks_uuid=$(cryptsetup luksUUID "$underlying" 2>/dev/null || true)
    [[ -z "$luks_uuid" ]] && error_exit "Could not retrieve LUKS UUID from $underlying"

    local keyfile_dest="/etc/cryptsetup-keys.d/${ROOTLABEL}.bin"
    local keyfile_opt="none"

    # /etc/crypttab — checked first so we can read keyfile_opt from it if present
    if [[ -f /etc/crypttab ]]; then
        log "/etc/crypttab already present — skipping"
        # Read keyfile field from existing crypttab (field 3) so dracut conf
        # is consistent with it — avoids adding a keyfile that crypttab doesn't use.
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
            keyfile_opt="$keyfile_dest"
            log "Keyfile recovered to ${keyfile_dest}"
        else
            log "No keyfile found — PIN/passphrase system, crypttab will use 'none'"
        fi

        local entry="${ROOTLABEL} UUID=${luks_uuid} ${keyfile_opt} luks,discard"
        printf '%s\n' "$entry" > /etc/crypttab
        chmod 0644 /etc/crypttab
        log "/etc/crypttab written: ${entry}"
    fi

    # /etc/dracut.conf.d/99-crypt-key.conf — checked independently
    # Must be consistent with crypttab: include keyfile in install_items only
    # if crypttab actually references it. PIN systems use "none" — no keyfile
    # needed in the initrd.
    if [[ ! -f /etc/dracut.conf.d/99-crypt-key.conf ]]; then
        log "/etc/dracut.conf.d/99-crypt-key.conf missing — generating"
        mkdir -p /etc/dracut.conf.d
        local install_items="/etc/crypttab"
        [[ "$keyfile_opt" != "none" ]] && install_items+=" ${keyfile_opt}"
        printf 'install_items+=" %s "\n' "$install_items" \
            > /etc/dracut.conf.d/99-crypt-key.conf
        log "dracut crypt config written (install_items: ${install_items})"
    else
        log "/etc/dracut.conf.d/99-crypt-key.conf already present — skipping"
    fi
}

# update_bootloader — update shim and systemd-boot on the ESP if the source
# binaries are newer than what is currently installed. Re-signs after update.
# configure.sh installs these at install time; gen-efi.sh keeps them current
# on subsequent kernel/systemd updates since bootctl update would deploy
# an unsigned binary on this immutable signed system.
update_bootloader() {
    local shim_src="/usr/share/shim-signed/shimx64.efi"
    local shim_dst="${ESP}/EFI/BOOT/BOOTX64.EFI"
    local sdboot_src="/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
    local sdboot_dst="${ESP}/EFI/BOOT/grubx64.efi"
    local mmx64_src="/usr/share/shim-signed/mmx64.efi"
    local mmx64_dst="${ESP}/EFI/BOOT/mmx64.efi"
    local updated=0

    # shim (BOOTX64.EFI)
    if [[ -f "$shim_src" ]]; then
        if [[ ! -f "$shim_dst" ]] || [[ "$shim_src" -nt "$shim_dst" ]]; then
            log "Updating shim: ${shim_dst}"
            cp "$shim_src" "$shim_dst" || error_exit "Failed to copy shim"
            sign_efi_binary "$shim_dst"
            updated=1
        else
            log "shim is up to date"
        fi
    else
        log_warn "shim source not found at ${shim_src} — skipping shim update"
    fi

    # MokManager (mmx64.efi) — not signed, shim verifies it via its own hash
    if [[ -f "$mmx64_src" ]]; then
        if [[ ! -f "$mmx64_dst" ]] || [[ "$mmx64_src" -nt "$mmx64_dst" ]]; then
            log "Updating MokManager: ${mmx64_dst}"
            cp "$mmx64_src" "$mmx64_dst" || error_exit "Failed to copy mmx64.efi"
            updated=1
        else
            log "MokManager is up to date"
        fi
    else
        log_warn "mmx64.efi source not found at ${mmx64_src} — skipping MokManager update"
    fi

    # systemd-boot (grubx64.efi — loaded by shim as the second-stage bootloader)
    if [[ -f "$sdboot_src" ]]; then
        if [[ ! -f "$sdboot_dst" ]] || [[ "$sdboot_src" -nt "$sdboot_dst" ]]; then
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

    # Ensure ESP is unmounted on any exit from this point
    trap 'cleanup_esp' EXIT

    # Ensure ESP is mounted before we start
    ensure_esp_mounted
    mkdir -p "$EFI_DIR"

    # If keys were just generated, re-sign existing EFI binaries and stage enrollment
    # now that ESP is mounted.
    if [[ $MOK_KEYS_GENERATED -eq 1 ]]; then
        reenroll_mok_keys
    fi

    # Update shim and systemd-boot on the ESP if source binaries are newer.
    # Must run after reenroll_mok_keys (which may have just installed new keys)
    # so the sign step uses the correct current keys.
    update_bootloader

    local kernel_ver
    kernel_ver=$(get_kernel_version)
    log "Using kernel: $kernel_ver"
    local uki_path="$EFI_DIR/${OS_NAME}-${slot}.efi"
    generate_cmdline "$slot"
    local kernel_cmdline
    kernel_cmdline=$(<"$CMDLINE_FILE")
    if [[ -z "$kernel_cmdline" ]]; then
        error_exit "Kernel command line is empty."
    fi
    # If the root device is encrypted, ensure /etc/crypttab exists before dracut.
    # Without it dracut builds a UKI with no LUKS unlock support.
    # We derive everything from the live mapping — no external service needed.
    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        ensure_crypttab
    fi

    dracut --force --uefi --kver "$kernel_ver" --kernel-cmdline "$kernel_cmdline" "$uki_path" || error_exit "dracut failed"
    sign_efi_binary "$uki_path"



case "${1:-}" in
    configure)
        generate_uki "$TARGET_SLOT"
        log "UKI generated for ${TARGET_SLOT}"
        ;;
    *)
        echo "Usage: $0 configure <target_slot>"
        exit 1
        ;;
esac
