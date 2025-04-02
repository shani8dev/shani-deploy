#!/bin/bash
################################################################################
# shanios-deploy.sh
#
# Improved Blue/Green Btrfs Deployment Script for shanios
# Performs self‑update with complete state persistence (including arrays)
# so that nothing is missed during the update.
#
# Usage: ./shanios-deploy.sh [OPTIONS]
#
# Options:
#   -h, --help             Show this help message.
#   -r, --rollback         Force a full rollback.
#   -c, --cleanup          Run manual cleanup.
#   -t, --channel <chan>   Specify update channel: latest or stable (default: stable).
#   -d, --dry-run          Dry run (simulate actions without making changes).
################################################################################

#####################################
### State Restoration (if needed) ###
#####################################

if [ -n "$SHANIOS_DEPLOY_STATE_FILE" ] && [ -f "$SHANIOS_DEPLOY_STATE_FILE" ]; then
    # Restore all persisted variables (scalars and arrays)
    source "$SHANIOS_DEPLOY_STATE_FILE"
    rm -f "$SHANIOS_DEPLOY_STATE_FILE"
fi

#####################################
### State Persistence Function    ###
#####################################
# Create a temporary directory for state files
STATE_DIR=$(mktemp -d /tmp/shanios-deploy-state.XXXXXX)
export STATE_DIR

# Cleanup trap to remove the state directory on exit
cleanup() {
    if [[ -n "${STATE_DIR}" && -d "${STATE_DIR}" ]]; then
        rm -rf "${STATE_DIR}"
    fi
}
trap cleanup EXIT

persist_state() {
    local state_file
    state_file=$(mktemp /tmp/shanios_deploy_state.XXXX)
    {
        # Persist scalar variables using printf %q to handle quoting
        echo "export OS_NAME=$(printf '%q' "$OS_NAME")"
        echo "export DOWNLOAD_DIR=$(printf '%q' "$DOWNLOAD_DIR")"
        echo "export ZSYNC_CACHE_DIR=$(printf '%q' "$ZSYNC_CACHE_DIR")"
        echo "export MOUNT_DIR=$(printf '%q' "$MOUNT_DIR")"
        echo "export ROOTLABEL=$(printf '%q' "$ROOTLABEL")"
        echo "export ROOT_DEV=$(printf '%q' "$ROOT_DEV")"
        echo "export MIN_FREE_SPACE_MB=$(printf '%q' "$MIN_FREE_SPACE_MB")"
        echo "export GENEFI_SCRIPT=$(printf '%q' "$GENEFI_SCRIPT")"
        echo "export DEPLOY_PENDING=$(printf '%q' "$DEPLOY_PENDING")"
        echo "export GPG_KEY_ID=$(printf '%q' "$GPG_KEY_ID")"
        echo "export WGET_OPTS=$(printf '%q' "$WGET_OPTS")"
        echo "export LOCAL_VERSION=$(printf '%q' "$LOCAL_VERSION")"
        echo "export LOCAL_PROFILE=$(printf '%q' "$LOCAL_PROFILE")"
        echo "export BACKUP_NAME=$(printf '%q' "$BACKUP_NAME")"
        echo "export CURRENT_SLOT=$(printf '%q' "$CURRENT_SLOT")"
        echo "export CANDIDATE_SLOT=$(printf '%q' "$CANDIDATE_SLOT")"
        echo "export REMOTE_VERSION=$(printf '%q' "$REMOTE_VERSION")"
        echo "export REMOTE_PROFILE=$(printf '%q' "$REMOTE_PROFILE")"
        echo "export IMAGE_NAME=$(printf '%q' "$IMAGE_NAME")"
        echo "export STATE_DIR=$(printf '%q' "${STATE_DIR}")" >> "$state_file"
        echo "export MARKER_FILE=$(printf '%q' "$MARKER_FILE")"
        # Persist arrays using declare -p
        declare -p CHROOT_BIND_DIRS
        declare -p CHROOT_STATIC_DIRS
    } > "$state_file"
    export SHANIOS_DEPLOY_STATE_FILE="$state_file"
}

#####################################
### Global Configuration          ###
#####################################

readonly OS_NAME="shanios"
readonly DOWNLOAD_DIR="/data/downloads"
readonly ZSYNC_CACHE_DIR="${DOWNLOAD_DIR}/zsync_cache"
readonly MOUNT_DIR="/mnt"
readonly ROOTLABEL="shani_root"
readonly ROOT_DEV="/dev/disk/by-label/${ROOTLABEL}"
readonly MIN_FREE_SPACE_MB=10240
readonly GENEFI_SCRIPT="/usr/local/bin/gen-efi"  # External script for UKI generation
readonly DEPLOY_PENDING="/data/deployment_pending"
readonly GPG_KEY_ID="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"

# Common wget options for downloads
readonly WGET_OPTS="--trust-server-names --content-disposition --continue --show-progress --retry-connrefused --waitretry=1 --read-timeout=20 --timeout=15 --tries=10"

# Global state variables
declare -g LOCAL_VERSION
declare -g LOCAL_PROFILE
declare -g BACKUP_NAME=""
declare -g CURRENT_SLOT=""
declare -g CANDIDATE_SLOT=""
declare -g REMOTE_VERSION=""
declare -g REMOTE_PROFILE=""
declare -g IMAGE_NAME=""
MARKER_FILE=""

# Arrays for chroot bind mounts (persisted via declare -p)
CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp /sys/firmware/efi/efivars)
CHROOT_STATIC_DIRS=(data etc var)

#####################################
### Preliminary & Environment     ###
#####################################

check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "Error: Must be run as root (use sudo)." >&2
        exit 1
    fi
}

check_internet() {
    if ! ping -c1 -W2 google.com &>/dev/null; then
        echo "Error: No internet connection. Please check your network." >&2
        exit 1
    fi
}

set_environment() {
    set -Eeuo pipefail
    IFS=$'\n\t'
    LOCAL_VERSION=$(< /etc/shani-version)
    LOCAL_PROFILE=$(< /etc/shani-profile)
}

#####################################
### Systemd Inhibit Function      ###
#####################################

inhibit_system() {
    if [ -z "${SYSTEMD_INHIBITED:-}" ]; then
        export SYSTEMD_INHIBITED=1
        log "Inhibiting all system interruptions during update..."
        exec systemd-inhibit --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" --why="Updating system" "$0" "$@"
    fi
}

#####################################
### Self-Update Section           ###
#####################################

ORIGINAL_ARGS=("$@")

self_update() {
    if [[ -z "${SELF_UPDATE_DONE:-}" ]]; then
        export SELF_UPDATE_DONE=1
        # Persist state before updating
        persist_state

        local remote_url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
        local temp_script
        temp_script=$(mktemp)

        if curl -fsSL "$remote_url" -o "$temp_script"; then
            chmod +x "$temp_script"
            log "Self-update: Running updated script (state preserved via $SHANIOS_DEPLOY_STATE_FILE)..."
            exec /bin/bash "$temp_script" "${ORIGINAL_ARGS[@]}"
        else
            log "Warning: Unable to fetch remote script; continuing with local version." >&2
        fi
        rm -f "$temp_script"
    fi
}

#####################################
### Logging & Helper Functions    ###
#####################################

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [DEPLOY] $*"
}

die() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] $*" >&2
    exit 1
}

run_cmd() {
    if [[ "${dry_run:-no}" == "yes" ]]; then
        log "[Dry Run] $*"
    else
        log "Executing: $*"
        eval "$@" || die "Command failed: $*"
    fi
}

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    if ! findmnt -M "$tgt" &>/dev/null; then
        mount -o "$opts" "$src" "$tgt" || die "Mount failed: $src -> $tgt"
        log "Mounted $tgt with options ($opts)"
    fi
}

safe_umount() {
    local tgt="$1"
    if findmnt -M "$tgt" &>/dev/null; then
        umount -R "$tgt" && log "Unmounted $tgt"
    fi
}

get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2-)
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    if [[ -z "$subvol" ]]; then
        subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    fi
    echo "${subvol:-blue}"
}

#####################################
### Backup & Cleanup Functions    ###
#####################################

cleanup_old_backups() {
    for slot in blue green; do
        local backups count backup
        backups=$(btrfs subvolume list "$MOUNT_DIR" | awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' | sort -r)
        count=$(echo "$backups" | wc -l)
        if (( count > 1 )); then
            echo "$backups" | tail -n +2 | while read -r backup; do
                if btrfs subvolume delete "$MOUNT_DIR/@${backup}"; then
                    log "Deleted old backup: @${backup}"
                else
                    log "Failed to delete backup: @${backup}"
                fi
            done
        else
            log "Only the latest backup exists for slot $slot; no cleanup needed."
        fi
    done
}

cleanup_downloads() {
    local files latest_file count
    files=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst" -mtime +7 -printf "%T@ %p\n" | sort -n)
    count=$(echo "$files" | wc -l)
    if (( count > 1 )); then
        latest_file=$(echo "$files" | tail -n 1 | cut -d' ' -f2-)
        echo "$files" | while read -r line; do
            local file
            file=$(echo "$line" | cut -d' ' -f2-)
            if [[ "$file" != "$latest_file" ]]; then
                if rm -f "$file"; then
                    log "Deleted old download: $file"
                else
                    log "Failed to delete old download: $file"
                fi
            fi
        done
    else
        log "No old downloads to clean up."
    fi
}

#####################################
### Chroot Environment Functions  ###
#####################################

prepare_chroot_env() {
    local slot="$1"
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvol=@${slot}"
    if mountpoint -q /boot/efi; then
        log "EFI partition already mounted; binding /boot/efi..."
        mkdir -p "$MOUNT_DIR/boot/efi"
        run_cmd "mount --bind /boot/efi $MOUNT_DIR/boot/efi"
    else
        safe_mount "LABEL=shani_boot" "$MOUNT_DIR/boot/efi"
    fi
    for dir in "${CHROOT_STATIC_DIRS[@]}"; do
        mkdir -p "$MOUNT_DIR/$dir"
        run_cmd "mount --bind /$dir $MOUNT_DIR/$dir"
    done
    for d in "${CHROOT_BIND_DIRS[@]}"; do
        mkdir -p "$MOUNT_DIR$d"
        run_cmd "mount --bind $d $MOUNT_DIR$d"
    done
}

cleanup_chroot_env() {
    for d in "${CHROOT_BIND_DIRS[@]}"; do
        safe_umount "$MOUNT_DIR$d"
    done
    for dir in "${CHROOT_STATIC_DIRS[@]}"; do
        safe_umount "$MOUNT_DIR/$dir"
    done
    safe_umount "$MOUNT_DIR/boot/efi"
    safe_umount "$MOUNT_DIR"
}

generate_uki_common() {
    local slot="$1"
    prepare_chroot_env "$slot"
    log "Generating Secure Boot UKI for slot ${slot} using external gen-efi script..."
    chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$slot" || {
        cleanup_chroot_env
        die "UKI generation failed for slot ${slot}"
    }
    cleanup_chroot_env
    log "UKI generation for slot ${slot} completed."
}

#####################################
### Rollback & Restore Functions  ###
#####################################

restore_candidate() {
    log "Error encountered. Initiating candidate rollback..."
    {
        set +e
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
        if [[ -n "$BACKUP_NAME" ]] && btrfs subvolume show "$MOUNT_DIR/@${BACKUP_NAME}" &>/dev/null; then
            log "Restoring candidate slot @${CANDIDATE_SLOT} from backup @${BACKUP_NAME}"
            btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false &>/dev/null || true
            btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" &>/dev/null || true
            btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
            btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
        fi
        [[ -d "$MOUNT_DIR/temp_update" ]] && btrfs subvolume delete "$MOUNT_DIR/temp_update" &>/dev/null
        safe_umount "$MOUNT_DIR"
    } || log "Candidate restore incomplete – manual intervention may be required"
    exit 1
}
trap 'restore_candidate' ERR

rollback_system() {
    log "Initiating full system rollback..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    local failed_slot previous_slot
    if [[ -f "$MOUNT_DIR/@data/current-slot" ]]; then
        failed_slot=$(< "$MOUNT_DIR/@data/current-slot")
    else
        die "Current slot marker missing. Cannot rollback."
    fi
    if [[ -f "$MOUNT_DIR/@data/previous-slot" ]]; then
        previous_slot=$(< "$MOUNT_DIR/@data/previous-slot")
    else
        previous_slot=$([[ "$failed_slot" == "blue" ]] && echo "green" || echo "blue")
    fi
    log "Detected failing slot: ${failed_slot}. Rolling back to previous slot: ${previous_slot}."
    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" | awk -v slot="${failed_slot}" '$0 ~ slot"_backup" {print $NF}' | sort | tail -n 1)
    if [[ -z "$BACKUP_NAME" ]]; then
        die "No backup found for slot ${failed_slot}. Rollback aborted."
    fi
    log "Restoring slot ${failed_slot} from backup ${BACKUP_NAME}..."
    local failed_path backup_path
    failed_path="$MOUNT_DIR/@${failed_slot}"
    backup_path="$MOUNT_DIR/@${BACKUP_NAME}"
    btrfs property set -ts "$failed_path" ro false &>/dev/null || true
    btrfs subvolume delete "$failed_path" || die "Failed to delete slot ${failed_slot}"
    btrfs subvolume snapshot "$backup_path" "$failed_path" || die "Failed to restore slot ${failed_slot}"
    btrfs property set -ts "$failed_path" ro true
    log "Updating active slot marker to previous slot: ${previous_slot}..."
    echo "$previous_slot" > "$MOUNT_DIR/@data/current-slot"
    safe_umount "$MOUNT_DIR"
    generate_uki_common "$previous_slot"
    log "Rollback complete. Rebooting system..."
    reboot
}

#####################################
### Deployment Phase Functions    ###
#####################################

boot_validation_and_candidate_selection() {
    CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null)
    CURRENT_SLOT=$(echo "$CURRENT_SLOT" | xargs)
    if [[ -z "$CURRENT_SLOT" ]]; then
        CURRENT_SLOT="blue"
    fi

    local booted
    booted=$(get_booted_subvol)
    if [[ "$booted" != "$CURRENT_SLOT" ]]; then
        die "System booted from @$booted but expected @$CURRENT_SLOT. Reboot into the correct slot first."
    fi

    if [[ "$CURRENT_SLOT" == "blue" ]]; then
        CANDIDATE_SLOT="green"
    else
        CANDIDATE_SLOT="blue"
    fi

    log "System booted from @$CURRENT_SLOT. Preparing deployment to candidate slot @${CANDIDATE_SLOT}."
}

pre_update_checks() {
    local free_space_mb
    free_space_mb=$(df --output=avail "/data" | tail -n1)
    free_space_mb=$(( free_space_mb / 1024 ))
    if (( free_space_mb < MIN_FREE_SPACE_MB )); then
        die "Not enough disk space: ${free_space_mb} MB available; ${MIN_FREE_SPACE_MB} MB required."
    fi
    log "Disk space is sufficient."
    mkdir -p "$DOWNLOAD_DIR" "$ZSYNC_CACHE_DIR"
}

fetch_update_info() {
    local channel_url
    channel_url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    
    log "Checking for updates from: ${channel_url}..."
    
    # Fetch and validate update information
    IMAGE_NAME=$(wget -qO- "$channel_url" | tr -d '[:space:]') || die "Failed to fetch update info"
    
    # Parse image name components
    if [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"
        log "Update available: ${IMAGE_NAME} (v${REMOTE_VERSION}, ${REMOTE_PROFILE})"
    else
        die "Invalid update format in ${UPDATE_CHANNEL}.txt: '${IMAGE_NAME}'"
    fi

    # Check if update is needed
    if [[ "$LOCAL_VERSION" == "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
        log "System is up-to-date (v${REMOTE_VERSION}, ${REMOTE_PROFILE}). Checking candidate slot..."
        
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"

        # Verify candidate slot status
        if btrfs subvolume list "$MOUNT_DIR" | awk '{print $NF}' | grep -qx "@${CANDIDATE_SLOT}"; then
            CANDIDATE_RELEASE_FILE="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-version"
            CANDIDATE_PROFILE_FILE="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-profile"

            if [[ -f "$CANDIDATE_RELEASE_FILE" && -f "$CANDIDATE_PROFILE_FILE" ]]; then
                CANDIDATE_VERSION=$(cat "$CANDIDATE_RELEASE_FILE")
                CANDIDATE_PROFILE=$(cat "$CANDIDATE_PROFILE_FILE")

                if [[ "$CANDIDATE_VERSION" == "$REMOTE_VERSION" && "$CANDIDATE_PROFILE" == "$REMOTE_PROFILE" ]]; then
                    log "Candidate update matches. Proceeding to finalization."
                    touch "${STATE_DIR}/skip-deployment"
                else
                    log "Candidate mismatch (Found: v${CANDIDATE_VERSION}, ${CANDIDATE_PROFILE}). Deploying new update."
                fi
            else
                log "Candidate slot missing version/profile info. Deploying new update."
            fi
        else
            log "No candidate update found. Exiting."
            safe_umount "$MOUNT_DIR"
            exit 0
        fi
        safe_umount "$MOUNT_DIR"
    fi
}

download_update() {
    log "Downloading update: ${IMAGE_NAME}"
    cd "$DOWNLOAD_DIR" || die "Failed to access download directory: ${DOWNLOAD_DIR}"
    
    # Construct download URLs
    local base_url="https://downloads.sourceforge.net/project/shanios/${REMOTE_PROFILE}/${REMOTE_VERSION}"
    IMAGE_ZSYNC_URL="${base_url}/${IMAGE_NAME}.zsync?use_mirror=autoselect"
    IMAGE_FILE_URL="${base_url}/${IMAGE_NAME}?use_mirror=autoselect"
    SHA256_URL="${base_url}/${IMAGE_NAME}.sha256?use_mirror=autoselect"
    ASC_URL="${base_url}/${IMAGE_NAME}.asc?use_mirror=autoselect"

    # Write channel file
    echo "$IMAGE_NAME" > "$DOWNLOAD_DIR/${UPDATE_CHANNEL}.txt"
    MARKER_FILE="$DOWNLOAD_DIR/${IMAGE_NAME}.verified"
    
    # Start download process
    download_and_verify
}

download_update_image() {
    local expected_size actual_size download_file zsync_url_clean
    download_file="$IMAGE_NAME"

    expected_size=$(wget -q --spider -L -S "$IMAGE_FILE_URL" 2>&1 | awk '/Length:/ {print $2}' | tr -d '\r')
    if [[ -z "$expected_size" || ! "$expected_size" =~ ^[0-9]+$ ]]; then
        die "Could not determine a valid expected file size from server."
    fi

    if [[ -f "$download_file" ]]; then
        actual_size=$(stat -c%s "$download_file")
        if (( actual_size >= expected_size )); then
            log "Existing file $download_file is complete (size: $actual_size bytes); skipping download."
            return 0
        else
            log "Incomplete file detected ($actual_size vs expected $expected_size bytes); resuming download."
        fi
    fi

    zsync_url_clean="${IMAGE_ZSYNC_URL%%\?*}"
    if command -v zsync &>/dev/null && [[ -n "$zsync_url_clean" ]]; then
        if ! zsync -i "$download_file" "$zsync_url_clean"; then
            log "zsync resume failed; falling back to wget."
            fallback_download "$download_file"
        fi
    else
        log "zsync not available or URL missing; using wget."
        fallback_download "$download_file"
    fi

    actual_size=$(stat -c%s "$download_file" 2>/dev/null || echo 0)
    if (( actual_size >= expected_size )); then
        log "Download completed successfully: $download_file (size: $actual_size bytes)"
    else
        die "Download incomplete: $download_file ($actual_size bytes) vs expected ($expected_size bytes)"
    fi
}

fallback_download() {
    local target_file="$1" downloaded
    if [[ -f "$target_file" ]]; then
        log "Resuming download with wget for $target_file..."
        run_cmd "wget -c $WGET_OPTS '$IMAGE_FILE_URL'"
    else
        log "Starting fresh download with wget for $target_file..."
        run_cmd "wget $WGET_OPTS '$IMAGE_FILE_URL'"
    fi

    downloaded=$(basename "$IMAGE_FILE_URL")
    downloaded="${downloaded%%\?*}"
    
    if [[ "$downloaded" != "$(basename "$target_file")" ]]; then
        if [[ -f "$downloaded" ]]; then
            log "Renaming downloaded file from $downloaded to $target_file"
            mv "$downloaded" "$target_file"
        fi
    else
        log "Downloaded file name matches target file name; no renaming required."
    fi
}

download_and_verify() {
    download_update_image

    for file in "sha256" "asc"; do
        local url target_name downloaded_file
        if [[ "$file" == "sha256" ]]; then
            url="$SHA256_URL"
            target_name="${IMAGE_NAME}.sha256"
        else
            url="$ASC_URL"
            target_name="${IMAGE_NAME}.asc"
        fi
        run_cmd "wget -L $WGET_OPTS '$url'"
        downloaded_file=$(basename "$url")
        downloaded_file="${downloaded_file%%\?*}"
        if [[ -f "$downloaded_file" ]]; then
            if [[ "$downloaded_file" != "$(basename "$target_name")" ]]; then
                log "Renaming downloaded file from $downloaded_file to $target_name"
                mv "$downloaded_file" "$target_name"
            else
                log "Downloaded file name ($downloaded_file) matches target name; no renaming required."
            fi
        else
            die "Download failed for ${file} file."
        fi
    done

    if ! sha256sum -c "${IMAGE_NAME}.sha256"; then
        die "SHA256 checksum verification failed for $IMAGE_NAME"
    fi

    local gnupg_home
	gnupg_home=$(mktemp -d /tmp/gnupg-XXXXXX)
	export GNUPGHOME="$gnupg_home"
	chmod 700 "$GNUPGHOME"

	gpg --quiet --no-tty --recv-keys "$GPG_KEY_ID" >/dev/null 2>&1 || die "Failed to import key"
	echo -e "trust\n5\ny\nsave\n" | gpg --batch --command-fd 0 --no-tty --quiet --edit-key "$GPG_KEY_ID" >/dev/null 2>&1

	gpg --verify "${IMAGE_NAME}.asc" "$IMAGE_NAME" || die "Signature verification failed"

	rm -rf "$gnupg_home"

    log "Image verified successfully."
    touch "$MARKER_FILE"
}

deploy_btrfs_update() {
    log "Deploying update via Btrfs..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    if mountpoint -q "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        safe_umount "$MOUNT_DIR"
        die "Candidate slot @${CANDIDATE_SLOT} is currently mounted. Aborting deployment."
    fi
    if btrfs subvolume list "$MOUNT_DIR" | grep -q "path @${CANDIDATE_SLOT}\$"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        log "Creating backup of candidate slot @${CANDIDATE_SLOT} as @${BACKUP_NAME}..."
        btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}" || die "Backup snapshot failed"
        btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false || die "Failed to clear read-only property"
        btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" || die "Failed to delete candidate slot"
    fi
    local temp_subvol="$MOUNT_DIR/temp_update"
    if btrfs subvolume list "$MOUNT_DIR" | awk '{print $NF}' | grep -qx "temp_update"; then
        log "Deleting existing temporary subvolume temp_update..."
        [[ -d "$temp_subvol/shanios_base" ]] && btrfs subvolume delete "$temp_subvol/shanios_base" || log "Failed to delete nested subvolume shanios_base"
        btrfs subvolume delete "$temp_subvol" || log "Failed to delete temporary subvolume temp_update"
    fi
    btrfs subvolume create "$temp_subvol" || die "Failed to create temporary subvolume"
    log "Receiving update image into temporary subvolume..."
    run_cmd "zstd -d --long=31 -T0 '$DOWNLOAD_DIR/$IMAGE_NAME' -c | btrfs receive '$temp_subvol'" || die "Image extraction failed"
    log "Creating candidate snapshot from temporary update..."
    btrfs subvolume snapshot "$temp_subvol/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}" || die "Snapshot creation failed"
    btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true || die "Failed to set candidate slot to read-only"
    log "Deleting temporary subvolume..."
    [[ -d "$temp_subvol/shanios_base" ]] && btrfs subvolume delete "$temp_subvol/shanios_base" || log "Failed to delete nested subvolume shanios_base"
    btrfs subvolume delete "$temp_subvol" || log "Failed to delete temporary subvolume"
    safe_umount "$MOUNT_DIR"
    touch "$DEPLOY_PENDING"
}

generate_uki_update() {
    log "Generating Secure Boot UKI for new deployment..."
    generate_uki_common "$CANDIDATE_SLOT"
    [[ -f "$DEPLOY_PENDING" ]] && { rm -f "$DEPLOY_PENDING"; log "Removed deployment pending marker."; }
}

finalize_update() {
    log "Finalizing deployment..."
    echo "$CURRENT_SLOT" > /data/previous-slot
    echo "$CANDIDATE_SLOT" > /data/current-slot
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    [[ -n "$BACKUP_NAME" ]] && { btrfs subvolume delete "$MOUNT_DIR/@${BACKUP_NAME}" &>/dev/null && log "Deleted backup @${BACKUP_NAME}"; }
    cleanup_old_backups
    safe_umount "$MOUNT_DIR"
    echo "$IMAGE_NAME" > "$DOWNLOAD_DIR/old.txt"
    cleanup_downloads
    log "Deployment finalized. Next boot will use @${CANDIDATE_SLOT} (version: ${REMOTE_VERSION})"
}

#####################################
### Usage & Parameter Parsing     ###
#####################################

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -h, --help             Show this help message.
  -r, --rollback         Force a full rollback.
  -c, --cleanup          Run manual cleanup.
  -t, --channel <chan>   Specify update channel: latest or stable (default: stable).
  -d, --dry-run          Dry run (simulate actions without making changes).
EOF
}

args=$(getopt -o hrct:d --long help,rollback,cleanup,channel:,dry-run -n "$0" -- "$@") || { usage; exit 1; }
eval set -- "$args"

while true; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -r|--rollback)
            touch "${STATE_DIR}/rollback"
            shift
            ;;
        -c|--cleanup)
            touch "${STATE_DIR}/cleanup"
            shift
            ;;
        -t|--channel)
            echo "$2" > "${STATE_DIR}/channel"
            shift 2
            ;;
        -d|--dry-run)
            touch "${STATE_DIR}/dry-run"
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Invalid option: $1"
            usage
            exit 1
            ;;
    esac
done

#####################################
### Main Execution Flow           ###
#####################################

main() {
    check_root
    check_internet
    set_environment
    
	dry_run=$([[ -f "${STATE_DIR}/dry-run" ]] && echo "yes" || echo "no")
    
	if [[ -f "${STATE_DIR}/channel" ]]; then
		UPDATE_CHANNEL=$(cat "${STATE_DIR}/channel")
	else
		UPDATE_CHANNEL="stable"
	fi
	
    inhibit_system "$@"
    self_update "$@"

	if [[ -f "${STATE_DIR}/cleanup" ]]; then
		log "Initiating manual cleanup..."
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" || die "Failed to mount for cleanup"
        cleanup_old_backups
        safe_umount "$MOUNT_DIR" || true
        cleanup_downloads
        exit 0
	fi

    if [[ ! -f /data/boot-ok ]]; then
        log "Boot failure detected: /data/boot-ok missing. Initiating rollback..."
        rollback_system
    fi
    
	if [[ -f "${STATE_DIR}/rollback" ]]; then
		rollback_system
		exit 0
	fi

	if [[ -f "${DEPLOY_PENDING}" ]]; then
		log "Deployment pending marker found. Resuming finalization."
		touch "${STATE_DIR}/skip-deployment"
	fi

    boot_validation_and_candidate_selection
    pre_update_checks
    fetch_update_info
    
	if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
		log "Skipping download/deployment; resuming finalization."
	else
		download_update
        deploy_btrfs_update
    fi

    generate_uki_update
    finalize_update
}

main "$@"

