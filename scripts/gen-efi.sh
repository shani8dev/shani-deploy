#!/usr/bin/env bash
# gen-efi.sh – Generate and update the Unified Kernel Image (UKI) for Secure Boot.
#
# Usage: ./gen-efi.sh configure <target_slot>
#
# This script creates (or reuses) a kernel command-line file and uses dracut
# to generate a new UKI image, signing it for Secure Boot.
# The command line includes "rootflags=subvol=@<target_slot>".
#
# It then updates the boot menu configuration for both slots:
# the active slot (from /data/current-slot) is labeled " (Active)"
# while the other is labeled " (Candidate)". The active boot entry is set as default.
#
# Must be run as root.

set -Eeuo pipefail

# Check for required dependencies.
REQUIRED_CMDS=("blkid" "dracut" "sbsign" "sbverify" "bootctl" "ls" "grep" "sort" "tail" "awk" "mkdir" "cat" "cryptsetup")
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

mkdir -p "$EFI_DIR" "$BOOT_ENTRIES"

log() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") [GENEFI] $*"
}

error_exit() {
    log "ERROR: $*"
    exit 1
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
    if [ -f "$CMDLINE_FILE" ]; then
        log "Reusing existing kernel cmdline from $CMDLINE_FILE"
    else
        local fs_uuid
        fs_uuid=$(blkid -s UUID -o value /dev/disk/by-label/"${ROOTLABEL}" 2>/dev/null || true)
        if [[ -z "$fs_uuid" ]]; then
            error_exit "Failed to retrieve filesystem UUID for label ${ROOTLABEL}"
        fi

        local rootdev encryption_params resume_uuid

        if [ -e "/dev/mapper/${ROOTLABEL}" ]; then
            local underlying
            underlying=$(cryptsetup status /dev/mapper/"${ROOTLABEL}" | sed -n 's/^ *device: //p')
            local luks_uuid
            luks_uuid=$(cryptsetup luksUUID "$underlying" 2>/dev/null || true)
            if [[ -z "$luks_uuid" ]]; then
                error_exit "Failed to retrieve LUKS UUID from underlying device $underlying"
            fi
            rootdev="/dev/mapper/${ROOTLABEL}"
            encryption_params=" rd.luks.uuid=${luks_uuid} rd.luks.name=${luks_uuid}=${ROOTLABEL} rd.luks.options=discard"
            resume_uuid="${luks_uuid}"
        else
            rootdev="UUID=${fs_uuid}"
            encryption_params=""
            resume_uuid="${fs_uuid}"
        fi

        local cmdline="quiet splash systemd.volatile=state ro lsm=landlock,lockdown,yama,integrity,apparmor,bpf rootfstype=btrfs rootflags=subvol=@${slot},ro,noatime,compress=zstd,space_cache=v2,autodefrag${encryption_params} root=${rootdev}"

		# Append keyboard mapping parameter from /etc/vconsole.conf if available
		if [[ -f /etc/vconsole.conf ]]; then
			local keymap
			keymap=$(grep -E '^KEYMAP=' /etc/vconsole.conf | cut -d= -f2)
			if [[ -n "$keymap" ]]; then
				cmdline+=" rd.vconsole.keymap=$keymap"
			fi
		fi

        if [ -f /swap/swapfile ]; then
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
    fi
}

# update_slot_conf updates the boot entry configuration for a given slot.
update_slot_conf() {
    local slot="$1"
    local active_slot=""
    if [ -f /data/current-slot ]; then
        active_slot=$(cat /data/current-slot)
    fi
    local suffix=""
    if [[ "$slot" == "$active_slot" ]]; then
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
    update_slot_conf "$slot"
    local other_slot=$([[ "$slot" == "blue" ]] && echo "green" || echo "blue")
    update_slot_conf "$other_slot"

    # Set the active slot (from /data/current-slot, if available) as default.
    local active
    if [ -f /data/current-slot ]; then
        active=$(cat /data/current-slot)
    else
        active="$slot"
    fi
    bootctl set-default "${OS_NAME}-${active}.conf" || error_exit "bootctl set-default failed"
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

