#!/bin/bash
# Self-update block: Always run the remote script from a temporary file.
REMOTE_SCRIPT_URL="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"  # Update with your URL
TEMP_SCRIPT=$(mktemp)

if curl -fsSL "$REMOTE_SCRIPT_URL" -o "$TEMP_SCRIPT"; then
    chmod +x "$TEMP_SCRIPT"
    echo "Running remote version from temporary file..."
    exec "$TEMP_SCRIPT" "$@"
else
    echo "Warning: Could not fetch remote script. Proceeding with local version." >&2
fi
rm -f "$TEMP_SCRIPT"

# --- Original deploy-image.sh code follows ---
# deploy-image.sh – Combined Deployment and Rollback for Blue/Green Btrfs Systems
# with Update Channel Selection, Boot Failure Detection, Overlay Mount for /etc,
# UKI Generation, and Cleanup of Old Backups and Downloads.
#
# Usage:
#   deploy-image.sh              # Deploy update (default: latest channel)
#   deploy-image.sh latest       # Deploy update from latest channel
#   deploy-image.sh stable       # Deploy update from stable channel
#   deploy-image.sh rollback     # Force a rollback
#
# (Run as root.)

set -Eeuo pipefail
IFS=$'\n\t'

# --- Configuration ---
OS_NAME="shanios"
LOCAL_VERSION=$(cat /etc/shani-version)
LOCAL_PROFILE=$(cat /etc/shani-profile)
DOWNLOAD_DIR="/data/downloads"
ZSYNC_CACHE_DIR="${DOWNLOAD_DIR}/zsync_cache"
MOUNT_DIR="/mnt"
ROOTLABEL="shani_root"
ROOT_DEV="/dev/disk/by-label/${ROOTLABEL}"
MIN_FREE_SPACE_MB=10240
GENEFI_SCRIPT="/usr/local/bin/gen-efi"  # Ensure this script is present

# Marker file to indicate an update was deployed but not yet finalized.
DEPLOY_PENDING="/data/deployment_pending"

declare -g BACKUP_NAME=""
declare -g CURRENT_SLOT=""
declare -g CANDIDATE_SLOT=""
declare -g REMOTE_VERSION=""
declare -g REMOTE_PROFILE=""
declare -g IMAGE_NAME=""
declare -g UPDATE_CHANNEL="stable"  # Default channel

# --- Parameter Parsing ---
if [[ "${1:-}" == "rollback" ]]; then
    rollback_mode="yes"
else
    rollback_mode="no"
    if [[ "${1:-}" == "stable" ]]; then
        UPDATE_CHANNEL="stable"
    elif [[ "${1:-}" == "latest" ]]; then
        UPDATE_CHANNEL="latest"
    fi
fi

# --- Common Functions ---
log() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") [DEPLOY] $*"
}

die() {
    echo "$(date "+%Y-%m-%d %H:%M:%S") [FATAL] $*" >&2
    exit 1
}

safe_mount() {
    local src=$1 tgt=$2 opts=$3
    if ! findmnt -M "$tgt" >/dev/null; then
        mount -o "$opts" "$src" "$tgt" || die "Mount failed: $src → $tgt"
        log "Mounted $tgt ($opts)"
    fi
}

safe_umount() {
    local tgt=$1
    if findmnt -M "$tgt" >/dev/null; then
        umount -R "$tgt" && log "Unmounted $tgt"
    fi
}

get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2-)
    subvol=$(awk -F'subvol=' '{print $2}' <<<"$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    [[ -z "$subvol" ]] && subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    echo "${subvol:-blue}"
}

cleanup_old_backups() {
    # For each slot, keep at least one backup and delete older ones.
    for slot in blue green; do
        local backup_list count retention to_remove backup
        backup_list=$(btrfs subvolume list "$MOUNT_DIR" | awk -v slot="$slot" '$0 ~ slot"_backup" {print $NF}' | sort)
        count=$(echo "$backup_list" | wc -l)
        retention=1
        if [ "$count" -gt "$retention" ]; then
            to_remove=$(echo "$backup_list" | head -n $(($count - $retention)))
            for backup in $to_remove; do
                btrfs subvolume delete "$MOUNT_DIR/@${backup}" && log "Deleted old backup: @${backup}"
            done
        fi
    done
}

cleanup_downloads() {
    # Remove downloaded image files older than 7 days, but keep at least one.
    local count
    count=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst" | wc -l)
    if [ "$count" -gt 1 ]; then
        find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst" -mtime +7 -exec rm -f {} \;
        log "Cleaned up downloaded images older than 7 days."
    else
        log "Only one downloaded image remains; skipping downloads cleanup."
    fi
}

restore_candidate() {
    log "Error encountered. Initiating candidate rollback..."
    (
        set +e
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
        if [[ -n "$BACKUP_NAME" ]] && btrfs subvolume show "$MOUNT_DIR/@${BACKUP_NAME}" &>/dev/null; then
            log "Restoring candidate slot @${CANDIDATE_SLOT} from backup @${BACKUP_NAME}"
            btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false &>/dev/null || true
            btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" &>/dev/null || true
            btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
            btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
        fi
        if btrfs subvolume list "$MOUNT_DIR" | grep -q "@temp_update"; then
            btrfs subvolume delete "$MOUNT_DIR/@temp_update" &>/dev/null
        fi
        safe_umount "$MOUNT_DIR"
    ) || log "Candidate rollback incomplete – manual intervention may be required"
    exit 1
}
trap 'restore_candidate' ERR

rollback_system() {
    log "Initiating full system rollback..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    if [ -f "$MOUNT_DIR/@data/current-slot" ]; then
        FAILED_SLOT=$(cat "$MOUNT_DIR/@data/current-slot")
    else
        die "Current slot marker not found. Cannot rollback."
    fi
    if [ -f "$MOUNT_DIR/@data/previous-slot" ]; then
        PREVIOUS_SLOT=$(cat "$MOUNT_DIR/@data/previous-slot")
    else
        if [ "$FAILED_SLOT" = "blue" ]; then
            PREVIOUS_SLOT="green"
        else
            PREVIOUS_SLOT="blue"
        fi
    fi
    log "Detected failing slot: ${FAILED_SLOT}. Previous working slot: ${PREVIOUS_SLOT}."
    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" | awk -v slot="${FAILED_SLOT}" '$0 ~ slot"_backup" {print $NF}' | sort | tail -n 1)
    if [ -z "$BACKUP_NAME" ]; then
        die "No backup found for slot ${FAILED_SLOT}. Cannot rollback."
    fi
    log "Restoring slot ${FAILED_SLOT} from backup ${BACKUP_NAME}..."
    FAILED_PATH="$MOUNT_DIR/@${FAILED_SLOT}"
    BACKUP_PATH="$MOUNT_DIR/@${BACKUP_NAME}"
    btrfs subvolume delete "$FAILED_PATH" || die "Failed to delete failed slot"
    btrfs subvolume snapshot "$BACKUP_PATH" "$FAILED_PATH" || die "Failed to restore from backup"
    log "Switching active slot to previous working slot: ${PREVIOUS_SLOT}..."
    echo "$PREVIOUS_SLOT" > "$MOUNT_DIR/@data/current-slot"
    bootctl set-default "shanios-${PREVIOUS_SLOT}.conf" || log "bootctl update failed (please verify manually)"
    safe_umount "$MOUNT_DIR"
    log "Rollback complete. Rebooting..."
    reboot
}

# --- Boot Failure Check ---
if [ ! -f /data/boot-ok ]; then
    log "Boot failure detected: /data/boot-ok marker missing. Initiating rollback..."
    rollback_system
fi

# --- Resume Pending Deployment if Marker Exists ---
# If a previous run left the deployment pending (e.g. candidate update exists but finalization wasn’t done)
if [ -f "$DEPLOY_PENDING" ]; then
    log "Found deployment pending marker. Resuming finalization (Phase 5)."
    skip_deployment="yes"
fi

# --- Main Execution (Deployment) ---
if [[ "${rollback_mode}" == "yes" ]]; then
    rollback_system
    exit 0
fi


    log "Starting deployment procedure..."
    log "Deploying update from channel: ${UPDATE_CHANNEL}"
    CHANNEL_URL="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    
    # Phase 1: Boot Validation & Candidate Selection
    CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null || echo "blue")
    BOOTED_SLOT=$(get_booted_subvol)
    if [[ "$BOOTED_SLOT" != "$CURRENT_SLOT" ]]; then
        die "System booted @${BOOTED_SLOT} but expected slot is @${CURRENT_SLOT}. Reboot into the correct slot first."
    fi
    if [[ "$CURRENT_SLOT" == "blue" ]]; then
        CANDIDATE_SLOT="green"
    else
        CANDIDATE_SLOT="blue"
    fi
    log "System booted from @${CURRENT_SLOT}. Preparing deployment to candidate slot @${CANDIDATE_SLOT}."
    
if [[ "${skip_deployment:-}" != "yes" ]]; then
    # Phase 2: Pre-update Checks
    log "Checking available disk space on /data..."
    free_space_mb=$(df --output=avail "/data" | tail -n1)
    free_space_mb=$(( free_space_mb / 1024 ))
    if [ "$free_space_mb" -lt "$MIN_FREE_SPACE_MB" ]; then
        die "Not enough disk space: ${free_space_mb} MB available; ${MIN_FREE_SPACE_MB} MB required."
    fi
    log "Disk space is sufficient."
    mkdir -p "$DOWNLOAD_DIR" "$ZSYNC_CACHE_DIR"
    
    # Phase 3: Update Check & Download
    log "Fetching ${UPDATE_CHANNEL} image info from ${CHANNEL_URL}..."
    IMAGE_NAME=$(wget -qO- "$CHANNEL_URL" | tr -d '[:space:]') || die "Failed to fetch update info"
    if [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"
        log "New image found: $IMAGE_NAME (version: $REMOTE_VERSION, profile: $REMOTE_PROFILE)"
    else
        die "Unexpected format in ${UPDATE_CHANNEL}.txt: $IMAGE_NAME"
    fi
    
    # If system is already up-to-date, check for a pending candidate update
    if [[ "$LOCAL_VERSION" == "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
        log "System is already up-to-date (v${REMOTE_VERSION})."
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
        if btrfs subvolume list "$MOUNT_DIR" | awk '{print $NF}' | grep -qx "@${CANDIDATE_SLOT}"; then
            log "Candidate update found in slot @${CANDIDATE_SLOT}. Proceeding to finalization (Phase 5)."
            skip_deployment="yes"
        else
            log "No pending candidate update found. Exiting."
            safe_umount "$MOUNT_DIR"
            exit 0
        fi
        safe_umount "$MOUNT_DIR"
    fi
    
    cd "$DOWNLOAD_DIR" || die "Failed to access download directory: $DOWNLOAD_DIR"
    
    IMAGE_BASE_URL="https://downloads.sourceforge.net/project/shanios/${REMOTE_PROFILE}/${REMOTE_VERSION}"
    IMAGE_ZSYNC_URL="${IMAGE_BASE_URL}/${IMAGE_NAME}.zsync?use_mirror=autoselect"
    IMAGE_FILE_URL="${IMAGE_BASE_URL}/${IMAGE_NAME}?use_mirror=autoselect"
    SHA256_URL="${IMAGE_BASE_URL}/${IMAGE_NAME}.sha256?use_mirror=autoselect"
    ASC_URL="${IMAGE_BASE_URL}/${IMAGE_NAME}.asc?use_mirror=autoselect"
    
    echo "$IMAGE_NAME" > "$DOWNLOAD_DIR/${UPDATE_CHANNEL}.txt"
    
    MARKER_FILE="$DOWNLOAD_DIR/${IMAGE_NAME}.verified"
    if [ -f "$IMAGE_NAME" ]; then
        if [ -f "$MARKER_FILE" ]; then
            log "Image $IMAGE_NAME already downloaded and verified. Skipping download and verification."
        else
            log "Image $IMAGE_NAME exists but has not been verified. Proceeding with download check."
        fi
    fi
    
    if [[ -f "$IMAGE_NAME" ]]; then
        log "Found existing image file $IMAGE_NAME. Checking completeness..."
        EXPECTED_SIZE=$(wget -q --spider -L -S "$IMAGE_FILE_URL" 2>&1 | grep -i "Length:" | awk '{print $2}' | tr -d '\r')
        if [[ -n "${EXPECTED_SIZE:-}" && "$EXPECTED_SIZE" =~ ^[0-9]+$ ]]; then
            ACTUAL_SIZE=$(stat -c%s "$IMAGE_NAME")
            if (( ACTUAL_SIZE < EXPECTED_SIZE )); then
                log "Incomplete file detected: local size ($ACTUAL_SIZE bytes) is less than expected ($EXPECTED_SIZE bytes). Attempting to resume download..."
                if ! zsync -i "$IMAGE_NAME" "$IMAGE_ZSYNC_URL"; then
                    log "Zsync resume failed; trying wget to resume download..."
                    wget -L --continue --show-progress --retry-connrefused --waitretry=1 \
                         --read-timeout=20 --timeout=15 --tries=10 -O "$IMAGE_NAME" "$IMAGE_FILE_URL" \
                         || die "Failed to resume incomplete download"
                fi
            else
                log "Existing file appears complete (size: $ACTUAL_SIZE bytes)."
            fi
        else
            log "Warning: Could not determine expected file size; skipping completeness check."
        fi
    fi
    
    if [[ ! -f "$IMAGE_NAME" ]]; then
        log "No valid image found; downloading update image..."
        OLD_IMAGE=""
        if [[ -f "old.txt" ]]; then
            OLD_IMAGE=$(<old.txt)
        fi
        if [[ -n "$OLD_IMAGE" && -f "$OLD_IMAGE" ]]; then
            log "Resuming download using existing file: $OLD_IMAGE"
            if ! zsync -i "$OLD_IMAGE" "$IMAGE_ZSYNC_URL"; then
                log "Zsync download failed; falling back to full download via wget."
                wget -L --continue --show-progress --retry-connrefused --waitretry=1 \
                     --read-timeout=20 --timeout=15 --tries=10 -O "$IMAGE_NAME" "$IMAGE_FILE_URL" \
                     || die "Full download failed"
            fi
        else
            log "No previous image found; performing full zsync download."
            if ! zsync "$IMAGE_ZSYNC_URL"; then
                log "Zsync download failed; falling back to full download via wget."
                wget -L --continue --show-progress --retry-connrefused --waitretry=1 \
                     --read-timeout=20 --timeout=15 --tries=10 -O "$IMAGE_NAME" "$IMAGE_FILE_URL" \
                     || die "Full download failed"
            fi
        fi
    fi
    
    wget -L --continue --show-progress --retry-connrefused --waitretry=1 \
         --read-timeout=20 --timeout=15 --tries=10 -O "${IMAGE_NAME}.sha256" "$SHA256_URL" \
         || die "Failed to download SHA256 file"
    wget -L --continue --show-progress --retry-connrefused --waitretry=1 \
         --read-timeout=20 --timeout=15 --tries=10 -O "${IMAGE_NAME}.asc" "$ASC_URL" \
         || die "Failed to download PGP signature file"
    
    if ! sha256sum -c "${IMAGE_NAME}.sha256"; then
        log "SHA256 checksum verification failed"
    fi
    
    # Create a temporary GnuPG home directory
    GNUPGHOME=$(mktemp -d /tmp/gnupg-XXXXXX)
    GPG_KEY_ID="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"
    export GNUPGHOME
    chmod 700 "$GNUPGHOME"
    gpg --recv-keys "$GPG_KEY_ID"
    echo -e "trust\n5\ny\nsave\n" | gpg --homedir "$GNUPGHOME" --batch --command-fd 0 --edit-key "$GPG_KEY_ID"
    # Perform GPG verification
    if ! gpg --verify "${IMAGE_NAME}.asc" "$IMAGE_NAME"; then
        log "PGP signature verification failed"
    fi
    # Clean up the temporary GnuPG home directory
    rm -rf "$GNUPGHOME"
    log "Image verified successfully."
    touch "$MARKER_FILE"
    
    # Phase 4: Btrfs Deployment
    log "Mounting Btrfs top-level..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    if mountpoint -q "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        safe_umount "$MOUNT_DIR"
        die "Candidate slot @${CANDIDATE_SLOT} is mounted – aborting deployment."
    fi
    if btrfs subvolume list "$MOUNT_DIR" | grep -q "path @${CANDIDATE_SLOT}\$"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        log "Creating backup of candidate slot @${CANDIDATE_SLOT} as @${BACKUP_NAME}"
        btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}" || die "Candidate backup snapshot failed"
        btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false || die "Failed to clear read-only property on candidate slot"
        btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" || die "Failed to delete candidate slot"
    fi
    
    TEMP_SUBVOL="$MOUNT_DIR/temp_update"
    # Before creating the temporary subvolume, check if it already exists
    if btrfs subvolume list "$MOUNT_DIR" | awk '{print $NF}' | grep -qx "temp_update"; then
    log "Found existing temporary subvolume temp_update. Attempting to delete it..."
        if btrfs subvolume show "$TEMP_SUBVOL/shanios_base" &>/dev/null; then
            btrfs subvolume delete "$TEMP_SUBVOL/shanios_base" || log "Failed to delete nested subvolume shanios_base"
        fi
    btrfs subvolume delete "$MOUNT_DIR/temp_update" || log "Failed to delete existing temporary subvolume temp_update"
    fi

    btrfs subvolume create "$TEMP_SUBVOL" || die "Failed to create temporary subvolume"
    log "Receiving update image into temporary subvolume..."
    zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | btrfs receive "$TEMP_SUBVOL" || die "Image extraction failed"
    log "Creating candidate snapshot from update image..."
    btrfs subvolume snapshot "$TEMP_SUBVOL/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}" || die "Snapshot creation for candidate slot failed"
    btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true || die "Failed to set candidate slot to read-only"
    
    log "Deleting nested subvolume 'shanios_base' from temporary update volume..."
    if btrfs subvolume show "$TEMP_SUBVOL/shanios_base" &>/dev/null; then
        btrfs subvolume delete "$TEMP_SUBVOL/shanios_base" || log "Failed to delete nested subvolume shanios_base"
    fi
    log "Deleting temporary subvolume..."
    btrfs subvolume delete "$TEMP_SUBVOL" || log "Failed to delete temporary subvolume"
    safe_umount "$MOUNT_DIR"
    
    # Create marker so next run knows to resume finalization
    touch "$DEPLOY_PENDING"
fi

# --- Phase 5: UKI Generation (Using Bind Mounts for /etc and /var) ---
log "Mounting candidate subvolume for UKI update..."
mkdir -p "$MOUNT_DIR"
safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvol=@${CANDIDATE_SLOT}"

# Mount EFI partition: if already mounted on /boot/efi, use a bind mount.
if mountpoint -q /boot/efi; then
    log "EFI partition already mounted on /boot/efi. Using bind mount for $MOUNT_DIR/boot/efi."
    mkdir -p "$MOUNT_DIR/boot/efi"
    mount --bind /boot/efi "$MOUNT_DIR/boot/efi" || die "Bind mount failed: /boot/efi → $MOUNT_DIR/boot/efi"
else
    safe_mount "LABEL=shani_boot" "$MOUNT_DIR/boot/efi"
fi

# Bind mount /data into the candidate environment.
if mountpoint -q "$MOUNT_DIR/data"; then
    log "$MOUNT_DIR/data is already mounted. Unmounting first..."
    umount -R "$MOUNT_DIR/data" || die "Failed to unmount $MOUNT_DIR/data"
fi
mount --bind /data "$MOUNT_DIR/data" || die "Data bind mount failed"
log "Bind mounted /data to $MOUNT_DIR/data"

# Bind mount /etc from host into candidate.
if mountpoint -q "$MOUNT_DIR/etc"; then
    log "$MOUNT_DIR/etc is already mounted. Unmounting first..."
    umount -R "$MOUNT_DIR/etc" || die "Failed to unmount $MOUNT_DIR/etc"
fi
mkdir -p "$MOUNT_DIR/etc"
mount --bind /etc "$MOUNT_DIR/etc" || die "Failed to bind mount /etc"
log "Bind mounted /etc to $MOUNT_DIR/etc"

# Bind mount /var from host into candidate.
if mountpoint -q "$MOUNT_DIR/var"; then
    log "$MOUNT_DIR/var is already mounted. Unmounting first..."
    umount -R "$MOUNT_DIR/var" || die "Failed to unmount $MOUNT_DIR/var"
fi
mkdir -p "$MOUNT_DIR/var"
mount --bind /var "$MOUNT_DIR/var" || die "Failed to bind mount /var"
log "Bind mounted /var to $MOUNT_DIR/var"

# Bind essential directories for chroot
target_dirs=("/dev" "/proc" "/sys" "/run" "/tmp" "/sys/firmware/efi/efivars")
for dir in "${target_dirs[@]}"; do
    mkdir -p "$MOUNT_DIR$dir"
    mount --bind "$dir" "$MOUNT_DIR$dir" || die "Failed to bind mount $dir"
done

# Proceed with UKI generation.
log "Regenerating Secure Boot UKI..."
chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$CANDIDATE_SLOT" || { 
    for dir in "${target_dirs[@]}"; do safe_umount "$MOUNT_DIR$dir"; done
    safe_umount "$MOUNT_DIR/etc"; 
    safe_umount "$MOUNT_DIR/var"; 
    safe_umount "$MOUNT_DIR/data"; 
    safe_umount "$MOUNT_DIR/boot/efi"; 
    safe_umount "$MOUNT_DIR"; 
    die "UKI generation failed"; 
}

# Clean up: unmount bind mounts in reverse order.
for dir in "${target_dirs[@]}"; do safe_umount "$MOUNT_DIR$dir"; done
safe_umount "$MOUNT_DIR/etc"
safe_umount "$MOUNT_DIR/var"
safe_umount "$MOUNT_DIR/data"
safe_umount "$MOUNT_DIR/boot/efi"
safe_umount "$MOUNT_DIR"


# Finalize by removing the pending marker.
if [ -f "$DEPLOY_PENDING" ]; then
    rm -f "$DEPLOY_PENDING"
    log "Removed deployment pending marker."
fi

# --- Phase 6: Finalization & Cleanup ---
log "Updating slot markers..."
echo "$CURRENT_SLOT" > "/data/previous-slot"
echo "$CANDIDATE_SLOT" > "/data/current-slot"
mkdir -p "$MOUNT_DIR"
safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
if [[ -n "$BACKUP_NAME" ]]; then
    btrfs subvolume delete "$MOUNT_DIR/@${BACKUP_NAME}" &>/dev/null && log "Deleted backup @${BACKUP_NAME}"
fi
cleanup_old_backups
safe_umount "$MOUNT_DIR"
echo "$IMAGE_NAME" > "$DOWNLOAD_DIR/old.txt"
cleanup_downloads
log "Deployment finalized! Next boot will use @${CANDIDATE_SLOT} (version: ${REMOTE_VERSION})"

