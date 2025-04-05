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
        log "Checking for old backups in slot '${slot}'..."
        # Gather backups whose names contain the slot and follow the naming pattern
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" | \
            awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' | sort -r)
        
        if [ ${#backups[@]} -gt 0 ]; then
            log "Found backups for slot '${slot}': ${backups[*]}"
        else
            log "No backups found for slot '${slot}'."
            continue
        fi
        
        backup_count=${#backups[@]}
        if (( backup_count > 1 )); then
            log "Keeping the most recent backup and deleting the older $((backup_count-1)) backup(s) for slot '${slot}'."
            # Loop over all but the first (most recent) backup
            for (( i=1; i<backup_count; i++ )); do
                backup="${backups[i]}"
                # Validate backup name against expected pattern: e.g., blue_backup_202304271530
                if [[ "$backup" =~ ^(blue|green)_backup_[0-9]{12}$ ]]; then
                    if btrfs subvolume delete "$MOUNT_DIR/@${backup}"; then
                        log "Deleted old backup: @${backup}"
                    else
                        log "Failed to delete backup: @${backup}"
                    fi
                else
                    log "Skipping deletion for backup with unexpected name format: ${backup}"
                fi
            done
        else
            log "Only the latest backup exists for slot '${slot}'; no cleanup needed."
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
    
    log "Initiating update check: retrieving update info from ${channel_url}..."
    
    # Fetch and validate update information
    IMAGE_NAME=$(wget -qO- "$channel_url" | tr -d '[:space:]') || die "Error: Unable to fetch update info from ${channel_url}"
    log "Fetched update info: '${IMAGE_NAME}'"
    
    # Parse image name components
    if [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"
        log "parsed update info: version v${REMOTE_VERSION}, profile '${REMOTE_PROFILE}'"
    else
        die "Error: Invalid update format in ${UPDATE_CHANNEL}.txt. Received: '${IMAGE_NAME}'"
    fi

    # Check if update is needed
    if [[ "$LOCAL_VERSION" == "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
        log "Local system is up-to-date (v${REMOTE_VERSION}, ${REMOTE_PROFILE}). Proceeding to verify candidate update slot..."
        
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
                    log "Candidate slot is up-to-date (${CANDIDATE_VERSION}, ${CANDIDATE_PROFILE}). Skipping deployment."
                    touch "${STATE_DIR}/skip-deployment"
                else
                    log "Mismatch detected in candidate slot: found ${CANDIDATE_VERSION} (${CANDIDATE_PROFILE}) vs expected ${REMOTE_VERSION} (${REMOTE_PROFILE}). Deploying new update."
                fi
            else
                log "Candidate slot missing version/profile details. Deploying new update."
            fi
        else
            log "No candidate subvolume '@${CANDIDATE_SLOT}' found. Exiting update process."
            safe_umount "$MOUNT_DIR"
            exit 0
        fi
        safe_umount "$MOUNT_DIR"
    else
        log "Local system version (${LOCAL_VERSION}, ${LOCAL_PROFILE}) differs from remote update (${REMOTE_VERSION}, ${REMOTE_PROFILE}). Initiating update process."
    fi
}

download_update() {
    log "INFO" "Starting download process for ${IMAGE_NAME}"

    # Check essential commands
    for cmd in wget sha256sum gpg; do
        if ! command -v "$cmd" &> /dev/null; then
            log "ERROR" "Required command not found: $cmd"
            return 1
        fi
    done

    # Validate and switch to download directory
    mkdir -p "${DOWNLOAD_DIR}" || { log "ERROR" "Could not create download directory"; return 1; }
    cd "${DOWNLOAD_DIR}" || { log "ERROR" "Could not access download directory: ${DOWNLOAD_DIR}"; return 1; }

    # Configuration for wget options
    local WGET_OPTS=(
        --retry-connrefused
        --waitretry=30
        --read-timeout=60
        --timeout=60
        --tries=999999
        --no-verbose
        --dns-timeout=30
        --connect-timeout=30
        --prefer-family=IPv4
        --continue
    )
    [[ -t 2 ]] && WGET_OPTS+=(--show-progress)

    local SOURCEFORGE_BASE="https://sourceforge.net/projects/shanios/files"
    local MIRROR_FILE="${DOWNLOAD_DIR}/mirror.url"
    local MAX_ATTEMPTS=10
    local RETRY_BASE_DELAY=5
    local RETRY_MAX_DELAY=120
    local GPG_KEYSERVERS=("hkps://keys.openpgp.org" "keyserver.ubuntu.com")

    # File paths for tracking and verification
    local UPDATE_CHANNEL_FILE="${DOWNLOAD_DIR}/${UPDATE_CHANNEL}.channel"
    local MARKER_FILE="${DOWNLOAD_DIR}/${IMAGE_NAME}.verified"
    local image_file="${DOWNLOAD_DIR}/${IMAGE_NAME}"
    local image_file_part="${image_file}.part"
    local sha_file="${DOWNLOAD_DIR}/${IMAGE_NAME}.sha256"
    local asc_file="${DOWNLOAD_DIR}/${IMAGE_NAME}.asc"

    # Skip download if already verified and exists
    if [[ -f "${MARKER_FILE}" && -f "${image_file}" ]]; then
        log "INFO" "Found existing verified download: ${IMAGE_NAME}"
        return 0
    fi

    # Discover and store mirror URL if not already present
    if [[ ! -f "${MIRROR_FILE}" ]]; then
        log "INFO" "Performing initial mirror discovery"
        local initial_url="${SOURCEFORGE_BASE}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}/download"
        local spider_output
        spider_output=$(wget --max-redirect=20 --spider -S "${initial_url}" 2>&1)
        # Extract the effective mirror URL using the Location header
        local final_url
        final_url=$(echo "$spider_output" | grep -i '^ *Location: ' | tail -1 | awk '{print $2}' | tr -d '\r')
        if [[ -n "${final_url}" ]]; then
            echo "${final_url}" > "${MIRROR_FILE}"
            log "INFO" "Stored mirror URL: ${final_url}"
        else
            log "ERROR" "Failed to discover mirror URL"
            return 1
        fi
    fi

    # Retrieve stored mirror URL
    local mirror_url
    mirror_url=$(cat "${MIRROR_FILE}")
    log "INFO" "Using mirror URL: ${mirror_url}"

    # Verify remote file size
    log "INFO" "Checking remote file size"
    local expected_size
    expected_size=$(wget -q --spider -S "${mirror_url}" 2>&1 | awk '/Content-Length:/ {print $2}' | tail -1 | tr -d '\r')
    if [[ ! "${expected_size}" =~ ^[0-9]+$ ]] || (( expected_size <= 0 )); then
        log "ERROR" "Invalid remote file size: ${expected_size}"
        return 1
    fi
    log "INFO" "Expected file size: ${expected_size} bytes"

    # Update channel tracking
    echo "${IMAGE_NAME}" > "${UPDATE_CHANNEL_FILE}" || { log "ERROR" "Failed to write channel file"; return 1; }

    # Download loop with resume and exponential backoff
    local attempt=0
    local current_size=0
    while (( attempt++ < MAX_ATTEMPTS )); do
        log "INFO" "Download attempt ${attempt}/${MAX_ATTEMPTS}"

        # Resume download if partial file exists
        if [[ -f "${image_file_part}" ]]; then
            current_size=$(stat -c%s "${image_file_part}" 2>/dev/null || echo 0)
            log "INFO" "Resuming download from ${current_size}/${expected_size} bytes"
        fi

        wget "${WGET_OPTS[@]}" -O "${image_file_part}" "${mirror_url}"

        current_size=$(stat -c%s "${image_file_part}" 2>/dev/null || echo 0)
        if (( current_size == expected_size )); then
            log "INFO" "Download completed successfully"
            if ! mv "${image_file_part}" "${image_file}"; then
                log "ERROR" "File rename failed"
                return 1
            fi
            break
        else
            log "WARN" "Download incomplete (${current_size}/${expected_size})"
        fi

        # Calculate delay with exponential backoff and a slight random offset
        if (( attempt < MAX_ATTEMPTS )); then
            local delay=$(( RETRY_BASE_DELAY * (2 ** (attempt - 1)) ))
            (( delay = delay > RETRY_MAX_DELAY ? RETRY_MAX_DELAY : delay ))
            delay=$(( delay + (RANDOM % 10 - 5) ))
            (( delay < 1 )) && delay=1
            log "WARN" "Retrying in ${delay}s"
            sleep "${delay}"
        fi
    done

    if (( current_size != expected_size )); then
        log "ERROR" "Failed to complete download after ${MAX_ATTEMPTS} attempts"
        return 1
    fi

    # Fetch verification files from the original source
    log "INFO" "Fetching verification files"
    local sha_url="${SOURCEFORGE_BASE}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.sha256/download"
    local asc_url="${SOURCEFORGE_BASE}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.asc/download"
    if ! wget "${WGET_OPTS[@]}" -O "${sha_file}" "${sha_url}"; then
        log "ERROR" "SHA256 fetch failed"
        return 1
    fi
    if ! wget "${WGET_OPTS[@]}" -O "${asc_file}" "${asc_url}"; then
        log "ERROR" "ASC fetch failed"
        return 1
    fi

    # Validate SHA256 checksum
    log "INFO" "Verifying SHA256 checksum"
    if ! sha256sum -c "${sha_file}" --status; then
        log "ERROR" "Checksum validation failed"
        return 1
    fi

    # GPG verification using a temporary GNUPGHOME
    local gpg_temp
    gpg_temp=$(mktemp -d) || { log "ERROR" "Failed to create GPG temp dir"; return 1; }
    # Save previous GNUPGHOME to restore later (if needed)
    local old_gnupghome="${GNUPGHOME:-}"
    export GNUPGHOME="${gpg_temp}"
    chmod 700 "${gpg_temp}"
    # Set a trap to clean up the temporary directory
    trap 'rm -rf "${gpg_temp}"' EXIT

    log "INFO" "Importing GPG key ${GPG_KEY_ID}"
    local key_imported=0
    for keyserver in "${GPG_KEYSERVERS[@]}"; do
        if gpg --batch --quiet --keyserver "${keyserver}" --recv-keys "${GPG_KEY_ID}"; then
            log "INFO" "Imported key from ${keyserver}"
            key_imported=1
            break
        fi
    done
    if [[ ${key_imported} -ne 1 ]]; then
        log "ERROR" "Failed to import GPG key ${GPG_KEY_ID} from all keyservers"
        return 1
    fi

    log "INFO" "Verifying GPG signature"
    if ! gpg --batch --verify "${asc_file}" "${image_file}"; then
        log "ERROR" "GPG signature verification failed"
        return 1
    fi

    # Clear the GPG cleanup trap now that we're done with GPG operations
    trap - EXIT
    rm -rf "${gpg_temp}"
    # Optionally restore previous GNUPGHOME if needed
    export GNUPGHOME="${old_gnupghome}"

    # Final cleanup on success: remove mirror reference and mark download as verified
    log "INFO" "Removing mirror reference after successful verification"
    rm -f "${MIRROR_FILE}"

    if ! touch "${MARKER_FILE}"; then
        log "ERROR" "Failed to create verification marker"
        return 1
    fi

    log "INFO" "Download and verification successful"
    return 0
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
        # Create backup using the expected naming pattern
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

finalize_update() {
    log "Finalizing deployment..."

    # Update slot metadata
    echo "$CURRENT_SLOT" > /data/previous-slot
    echo "$CANDIDATE_SLOT" > /data/current-slot

    # Generate UKI for the new deployment
    log "Generating Secure Boot UKI for new deployment..."
    generate_uki_common "$CANDIDATE_SLOT"
    [[ -f "$DEPLOY_PENDING" ]] && { rm -f "$DEPLOY_PENDING"; log "Removed deployment pending marker."; }

    # Cleanup backup and downloads
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    [[ -n "$BACKUP_NAME" ]] && {
        btrfs subvolume delete "$MOUNT_DIR/@${BACKUP_NAME}" &>/dev/null
        log "Deleted backup @${BACKUP_NAME}"
    }
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

    boot_validation_and_candidate_selection
    pre_update_checks
    fetch_update_info
    
	if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
		log "Skipping download and deployment (system is up-to-date)."
	else
		log "System deployment is outdated. Starting download and deployment..."
		download_update || die "Download update failed."
		deploy_btrfs_update || die "Deployment of update failed."
	fi

	if [[ -f "${DEPLOY_PENDING}" ]]; then
		log "Deployment pending marker found. Resuming finalization..."
		finalize_update || die "Finalization of update failed."
	fi

}

main "$@"

