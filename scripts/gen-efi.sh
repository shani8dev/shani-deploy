#!/bin/bash
# gen-efi.sh – Generate and update the Unified Kernel Image (UKI) for Secure Boot.
#
# Usage:
#   ./gen-efi.sh configure <target_slot>  — generate/update UKI for a slot
#   ./gen-efi.sh enroll-mok               — stage MOK enrollment without rebuilding UKI
#   ./gen-efi.sh enroll-tpm2              — enroll TPM2 for automatic LUKS unlock
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

if [[ "${1:-}" != "configure" && "${1:-}" != "enroll-mok" && "${1:-}" != "enroll-tpm2" ]]; then
    echo "Usage:"
    echo "  $0 configure <target_slot>    — generate UKI for blue or green slot"
    echo "  $0 enroll-mok                — stage MOK enrollment (re-signs EFI binaries, no UKI rebuild)"
    echo "  $0 enroll-tpm2               — enroll TPM2 for automatic LUKS unlock"
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
    _stage_mok_enrollment
}

_mokutil_hash_enroll() {
    local der_file="$1"
    local tmp_hash tmp_err
    tmp_hash=$(mktemp)
    tmp_err=$(mktemp)

    # Check if this key is already pending enrollment (queued but not yet confirmed)
    if mokutil --list-new 2>/dev/null | grep -q .; then
        log "MOK enrollment already pending — reboot and confirm in MokManager"
        rm -f "$tmp_hash" "$tmp_err"
        return 0
    fi

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
    local tmp_signed
    tmp_signed=$(mktemp "${file}.signed.XXXXXX")
    if sbsign --key "$MOK_KEY" --cert "$MOK_CRT" --output "$tmp_signed" "$file"; then
        mv "$tmp_signed" "$file"
    else
        rm -f "$tmp_signed"
        error_exit "sbsign failed for $file"
    fi
    sbverify --cert "$MOK_CRT" "$file" || { error_exit "sbverify failed for $file"; }
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
        error_exit "Failed to retrieve filesystem UUID for label ${ROOTLABEL}"
    fi

    local rootdev encryption_params resume_uuid

    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        local underlying
        underlying=$(cryptsetup status /dev/mapper/"${ROOTLABEL}" 2>/dev/null | sed -n 's/^ *device: //p' | tr -d '\n')
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
        | sed -n 's/^ *device: //p' | tr -d '\n')
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


# _stage_mok_enrollment — stage MOK key enrollment via mokutil.
# Shared by reenroll_mok_keys and enroll_mok.
#
# If the key is already enrolled in firmware, nothing more is needed.
# If not, stages it via mokutil --import so MokManager presents it on next boot.
# The user must confirm enrollment in MokManager once — this is a firmware
# security gate and cannot be bypassed from a running OS.
_stage_mok_enrollment() {
    local mok_der="/etc/secureboot/keys/MOK.der"

    # Always copy DER to ESP and stage enrollment regardless of whether Secure Boot
    # is currently enabled. If SB is off now but the user enables it later, the key
    # must already be enrolled — otherwise the system will not boot.
    cp "$mok_der" "$ESP/EFI/BOOT/MOK.der"         || log_warn "Failed to copy MOK.der to ESP"

    # Check if this exact key is already enrolled in firmware — nothing to do
    local local_fp
    local_fp=$(openssl x509 -in "$mok_der" -inform DER -noout -fingerprint -sha1         2>/dev/null | sed 's/.*=//' | tr -d ':' | tr '[:upper:]' '[:lower:]' || echo "")
    if [[ -n "$local_fp" ]] &&        mokutil --list-enrolled 2>/dev/null | tr -d ': ' | tr '[:upper:]' '[:lower:]'        | grep -q "$local_fp"; then
        log "MOK key already enrolled in firmware — no action needed"
        return 0
    fi

    # Key not yet enrolled — stage it via mokutil --import --hash-file.
    # MokManager will prompt the user to confirm on next boot (one-time only).
    _mokutil_hash_enroll "$mok_der"

    log_warn "ACTION REQUIRED: reboot and confirm MOK enrollment in the MokManager prompt"
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
            sign_efi_binary "$uki" || log_warn "Failed to re-sign ${uki} — continuing"
        fi
    done

    # Stage MOK enrollment
    _stage_mok_enrollment
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
    if ! systemd-cryptenroll --tpm2-device=list 2>/dev/null | grep -q .; then
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

    # Check if TPM2 is already enrolled — wipe old slot before re-enrolling
    local wipe_flag=""
    if systemd-cryptenroll "$underlying" 2>/dev/null | grep -q tpm2; then
        log_warn "TPM2 slot already enrolled — wiping old slot before re-enrolling"
        wipe_flag="--wipe-slot=tpm2"
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
            ${wipe_flag:+"$wipe_flag"} \
            --unlock-key-file="$keyfile" \
            "$underlying" \
            || error_exit "TPM2 enrollment failed"
    else
        # PIN system — LUKS passphrase was set at install, prompt interactively
        log "PIN system detected — you will be prompted for your LUKS passphrase"
        systemd-cryptenroll \
            --tpm2-device=auto \
            --tpm2-pcrs="${pcrs}" \
            ${wipe_flag:+"$wipe_flag"} \
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
    *)
        echo "Usage:"
        echo "  $0 configure <target_slot>"
        echo "  $0 enroll-mok"
        echo "  $0 enroll-tpm2"
        exit 1
        ;;
esac
