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
    echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI][ERROR] Must run as root." >&2
    exit 1
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

# Configuration
OS_NAME="shanios"
ESP="/boot/efi"
EFI_DIR="$ESP/EFI/${OS_NAME}"
BOOT_ENTRIES="$ESP/loader/entries"
CMDLINE_FILE="/etc/kernel/install_cmdline_${TARGET_SLOT}"
MOK_KEY="/etc/secureboot/keys/MOK.key"
MOK_CRT="/etc/secureboot/keys/MOK.crt"
ROOTLABEL="shani_root"

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
    # Unmount ESP if we mounted it
    [[ $ESP_WAS_UNMOUNTED -eq 1 ]] && umount "$ESP" 2>/dev/null || true
    exit 1
}

# Detect if we're in chroot
in_chroot() {
    local root_id proc_id
    root_id=$(stat -c %d:%i / 2>/dev/null) || return 1
    proc_id=$(stat -c %d:%i /proc/1/root/. 2>/dev/null) || return 0
    [[ "$root_id" != "$proc_id" ]]
}

# Get currently booted slot
get_booted_slot() {
    # From kernel cmdline
    local slot=$(grep -o 'rootflags=[^ ]*' /proc/cmdline 2>/dev/null | sed 's/.*subvol=@//;s/,.*//' || echo "")
    
    # Fallback to btrfs
    [[ -z "$slot" ]] && slot=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    
    echo "${slot:-blue}"
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
    kernel_ver=$(ls -1 /usr/lib/modules/ 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -n 1)
    if [[ -z "$kernel_ver" ]]; then
        error_exit "No valid kernel version found in /usr/lib/modules/"
    fi
    echo "$kernel_ver"
}

generate_cmdline() {
    local slot="$1"
    if [[ -f "$CMDLINE_FILE" ]]; then
        log "Removing stale cmdline, regenerating..."
        rm -f "$CMDLINE_FILE"
    fi

    local fs_uuid
    fs_uuid=$(blkid -s UUID -o value /dev/disk/by-label/"${ROOTLABEL}" 2>/dev/null || true)
    if [[ -z "$fs_uuid" ]]; then
        error_exit "Failed to retrieve filesystem UUID for label ${ROOTLABEL}"
    fi

    local rootdev encryption_params resume_uuid

    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        local underlying
        underlying=$(cryptsetup status /dev/mapper/"${ROOTLABEL}" | sed -n 's/^ *device: //p')
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
        keymap=$(grep -E '^KEYMAP=' /etc/vconsole.conf | cut -d= -f2)
        if [[ -n "$keymap" ]]; then
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

# update_slot_conf updates the boot entry configuration for a given slot.
update_slot_conf() {
    local slot="$1" target_slot="$2"
    local suffix=""
    if [[ "$slot" == "$target_slot" ]]; then
        suffix=" (Active)"
    else
        suffix=" (Candidate)"
    fi
    local conf_file="$BOOT_ENTRIES/${OS_NAME}-${slot}.conf"
    cat > "$conf_file" <<EOF
title   ${OS_NAME}-${slot}${suffix}
efi     /EFI/${OS_NAME}/${OS_NAME}-${slot}.efi
EOF
    log "Updated boot entry: $conf_file"
}

# generate_uki generates the UKI image and then updates the boot entries for both slots.
generate_uki() {
    local slot="$1"
    
    # VALIDATE target slot
    validate_target_slot "$slot" || error_exit "Slot validation failed"
    
    # Ensure ESP is mounted before we start
    ensure_esp_mounted
    mkdir -p "$EFI_DIR" "$BOOT_ENTRIES"

    local kernel_ver
    kernel_ver=$(get_kernel_version)
    local uki_path="$EFI_DIR/${OS_NAME}-${slot}.efi"
    generate_cmdline "$slot"
    local kernel_cmdline
    kernel_cmdline=$(<"$CMDLINE_FILE")
    if [[ -z "$kernel_cmdline" ]]; then
        error_exit "Kernel command line is empty."
    fi
    dracut --force --uefi --kver "$kernel_ver" --kernel-cmdline "$kernel_cmdline" "$uki_path" || error_exit "dracut failed"
    sign_efi_binary "$uki_path"

    # Update both slots' boot entries.
    update_slot_conf "$slot" "$slot"
    local other_slot=$([[ "$slot" == "blue" ]] && echo "green" || echo "blue")
    update_slot_conf "$other_slot" "$slot"

	bootctl set-default "${OS_NAME}-${slot}.conf" || error_exit "bootctl set-default failed"
    
    # Unmount ESP if we mounted it
    cleanup_esp
}

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
