#!/bin/bash
################################################################################
# shanios-deploy.sh
#
# Enhanced Blue/Green Btrfs Deployment Script for shanios
# With native Btrfs deduplication and swapfile hibernation support
#
# Usage: ./shanios-deploy.sh [OPTIONS]
#
# Options:
#   -h, --help             Show this help message.
#   -r, --rollback         Force a full rollback.
#   -c, --cleanup          Run manual cleanup.
#   -s, --storage-info     Show storage usage analysis.
#   -t, --channel <chan>   Specify update channel: latest or stable (default: stable).
#   -d, --dry-run          Dry run (simulate actions without making changes).
################################################################################

#####################################
### State Restoration (if needed) ###
#####################################

if [ -n "$SHANIOS_DEPLOY_STATE_FILE" ] && [ -f "$SHANIOS_DEPLOY_STATE_FILE" ]; then
    source "$SHANIOS_DEPLOY_STATE_FILE"
    rm -f "$SHANIOS_DEPLOY_STATE_FILE"
fi

#####################################
### State Persistence Function    ###
#####################################

STATE_DIR=$(mktemp -d /tmp/shanios-deploy-state.XXXXXX)
export STATE_DIR

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
        [[ -v OS_NAME ]] && echo "export OS_NAME=$(printf '%q' "$OS_NAME")"
        [[ -v DOWNLOAD_DIR ]] && echo "export DOWNLOAD_DIR=$(printf '%q' "$DOWNLOAD_DIR")"
        [[ -v ZSYNC_CACHE_DIR ]] && echo "export ZSYNC_CACHE_DIR=$(printf '%q' "$ZSYNC_CACHE_DIR")"
        [[ -v MOUNT_DIR ]] && echo "export MOUNT_DIR=$(printf '%q' "$MOUNT_DIR")"
        [[ -v ROOTLABEL ]] && echo "export ROOTLABEL=$(printf '%q' "$ROOTLABEL")"
        [[ -v ROOT_DEV ]] && echo "export ROOT_DEV=$(printf '%q' "$ROOT_DEV")"
        [[ -v MIN_FREE_SPACE_MB ]] && echo "export MIN_FREE_SPACE_MB=$(printf '%q' "$MIN_FREE_SPACE_MB")"
        [[ -v GENEFI_SCRIPT ]] && echo "export GENEFI_SCRIPT=$(printf '%q' "$GENEFI_SCRIPT")"
        [[ -v DEPLOY_PENDING ]] && echo "export DEPLOY_PENDING=$(printf '%q' "$DEPLOY_PENDING")"
        [[ -v GPG_KEY_ID ]] && echo "export GPG_KEY_ID=$(printf '%q' "$GPG_KEY_ID")"
        [[ -v LOCAL_VERSION ]] && echo "export LOCAL_VERSION=$(printf '%q' "$LOCAL_VERSION")"
        [[ -v LOCAL_PROFILE ]] && echo "export LOCAL_PROFILE=$(printf '%q' "$LOCAL_PROFILE")"
        [[ -v BACKUP_NAME ]] && echo "export BACKUP_NAME=$(printf '%q' "$BACKUP_NAME")"
        [[ -v CURRENT_SLOT ]] && echo "export CURRENT_SLOT=$(printf '%q' "$CURRENT_SLOT")"
        [[ -v CANDIDATE_SLOT ]] && echo "export CANDIDATE_SLOT=$(printf '%q' "$CANDIDATE_SLOT")"
        [[ -v REMOTE_VERSION ]] && echo "export REMOTE_VERSION=$(printf '%q' "$REMOTE_VERSION")"
        [[ -v REMOTE_PROFILE ]] && echo "export REMOTE_PROFILE=$(printf '%q' "$REMOTE_PROFILE")"
        [[ -v IMAGE_NAME ]] && echo "export IMAGE_NAME=$(printf '%q' "$IMAGE_NAME")"
        [[ -v STATE_DIR ]] && echo "export STATE_DIR=$(printf '%q' "${STATE_DIR}")"
        [[ -v MARKER_FILE ]] && echo "export MARKER_FILE=$(printf '%q' "$MARKER_FILE")"
        [[ -v UPDATE_CHANNEL ]] && echo "export UPDATE_CHANNEL=$(printf '%q' "$UPDATE_CHANNEL")"
        if [[ -v CHROOT_BIND_DIRS ]]; then
            echo "CHROOT_BIND_DIRS=()"
            for dir in "${CHROOT_BIND_DIRS[@]}"; do
                echo "CHROOT_BIND_DIRS+=($(printf '%q' "$dir"))"
            done
        fi
        if [[ -v CHROOT_STATIC_DIRS ]]; then
            echo "CHROOT_STATIC_DIRS=()"
            for dir in "${CHROOT_STATIC_DIRS[@]}"; do
                echo "CHROOT_STATIC_DIRS+=($(printf '%q' "$dir"))"
            done
        fi
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
readonly GENEFI_SCRIPT="/usr/local/bin/gen-efi"
readonly DEPLOY_PENDING="/data/deployment_pending"
readonly GPG_KEY_ID="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"

readonly MIRROR_DISCOVERY_TIMEOUT=15
readonly MIRROR_TEST_TIMEOUT=10
readonly MAX_MIRROR_DISCOVERIES=8
readonly MIN_MIRRORS_NEEDED=3
readonly MAX_INHIBIT_DEPTH=2

declare -g LOCAL_VERSION
declare -g LOCAL_PROFILE
declare -g BACKUP_NAME=""
declare -g CURRENT_SLOT=""
declare -g CANDIDATE_SLOT=""
declare -g REMOTE_VERSION=""
declare -g REMOTE_PROFILE=""
declare -g IMAGE_NAME=""
declare -g UPDATE_CHANNEL="stable"
declare -g DRY_RUN="no"
MARKER_FILE=""

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
    
    if [[ ! -f /etc/shani-version ]]; then
        die "Missing /etc/shani-version file"
    fi
    
    if [[ ! -f /etc/shani-profile ]]; then
        die "Missing /etc/shani-profile file"
    fi
    
    LOCAL_VERSION=$(< /etc/shani-version)
    LOCAL_PROFILE=$(< /etc/shani-profile)
    
    if [[ -z "$LOCAL_VERSION" ]]; then
        die "LOCAL_VERSION is empty"
    fi
    
    if [[ -z "$LOCAL_PROFILE" ]]; then
        die "LOCAL_PROFILE is empty"
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
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] $*"
        return 0
    else
        log "Executing: $*"
        "$@" || die "Command failed: $*"
    fi
}

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    
    if [[ -z "$src" || -z "$tgt" ]]; then
        die "safe_mount: Invalid arguments (src='$src', tgt='$tgt')"
    fi
    
    if ! findmnt -M "$tgt" &>/dev/null; then
        run_cmd mount -o "$opts" "$src" "$tgt"
        log "Mounted $tgt with options ($opts)"
    fi
}

safe_umount() {
    local tgt="$1"
    
    if [[ -z "$tgt" ]]; then
        log "WARNING: safe_umount called with empty target"
        return 1
    fi
    
    if findmnt -M "$tgt" &>/dev/null; then
        if [[ "${DRY_RUN}" == "yes" ]]; then
            log "[Dry Run] Would unmount $tgt"
            return 0
        fi
        
        if umount -R "$tgt"; then
            log "Unmounted $tgt"
            return 0
        else
            log "WARNING: Failed to unmount $tgt"
            return 1
        fi
    fi
    return 0
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
### Self-Update Section           ###
#####################################

ORIGINAL_ARGS=("$@")

self_update() {
    if [[ -z "${SELF_UPDATE_DONE:-}" ]]; then
        export SELF_UPDATE_DONE=1
        persist_state

        local remote_url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
        local temp_script
        temp_script=$(mktemp)

        if curl -fsSL "$remote_url" -o "$temp_script"; then
            chmod +x "$temp_script"
            log "Self-update: Running updated script..."
            exec /bin/bash "$temp_script" "${ORIGINAL_ARGS[@]}"
        else
            log "Warning: Unable to fetch remote script; continuing with local version." >&2
        fi
        rm -f "$temp_script"
    fi
}

#####################################
### Systemd Inhibit Function      ###
#####################################

inhibit_system() {
    local inhibit_depth="${SYSTEMD_INHIBIT_DEPTH:-0}"
    
    if (( inhibit_depth >= MAX_INHIBIT_DEPTH )); then
        log "WARNING: Maximum inhibit depth reached, continuing without inhibit"
        return 0
    fi
    
    if [ -z "${SYSTEMD_INHIBITED:-}" ]; then
        export SYSTEMD_INHIBITED=1
        export SYSTEMD_INHIBIT_DEPTH=$((inhibit_depth + 1))
        log "Inhibiting all system interruptions during update..."
        exec systemd-inhibit --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" --why="Updating system" "$0" "$@"
    fi
}

#####################################
### Backup & Cleanup Functions    ###
#####################################

cleanup_old_backups() {
    for slot in blue green; do
        log "Checking for old backups in slot '${slot}'..."
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" | \
            awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' | sort -r)
        
        if [ ${#backups[@]} -gt 0 ]; then
            log "Found backups for slot '${slot}': ${backups[*]}"
        else
            log "No backups found for slot '${slot}'."
            continue
        fi
        
        backup_count=${#backups[@]}
        if (( backup_count > 2 )); then
            log "Keeping the 2 most recent backups and deleting the older $((backup_count-2)) backup(s) for slot '${slot}'."
            for (( i=2; i<backup_count; i++ )); do
                backup="${backups[i]}"
                if [[ "$backup" =~ ^(blue|green)_backup_[0-9]{12}$ ]]; then
                    run_cmd btrfs subvolume delete "$MOUNT_DIR/@${backup}"
                    log "Deleted old backup: @${backup}"
                else
                    log "Skipping deletion for backup with unexpected name format: ${backup}"
                fi
            done
        else
            log "Only ${backup_count} backup(s) exist for slot '${slot}'; no cleanup needed."
        fi
    done
}

cleanup_downloads() {
    local files latest_file count
    files=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst*" -mtime +7 -printf "%T@ %p\n" | sort -n)
    count=$(echo "$files" | wc -l)
    
    if (( count > 1 )); then
        latest_file=$(echo "$files" | tail -n 1 | cut -d' ' -f2-)
        echo "$files" | while read -r line; do
            local file
            file=$(echo "$line" | cut -d' ' -f2-)
            if [[ "$file" != "$latest_file" ]]; then
                run_cmd rm -f "$file"
                log "Deleted old download: $file"
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
    
    if [[ -z "$slot" ]]; then
        die "prepare_chroot_env: slot parameter is empty"
    fi
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvol=@${slot}"
    
    if mountpoint -q /boot/efi; then
        log "EFI partition already mounted; binding /boot/efi..."
        mkdir -p "$MOUNT_DIR/boot/efi"
        run_cmd mount --bind /boot/efi "$MOUNT_DIR/boot/efi"
    else
        safe_mount "LABEL=shani_boot" "$MOUNT_DIR/boot/efi" "defaults"
    fi
    
    for dir in "${CHROOT_STATIC_DIRS[@]}"; do
        mkdir -p "$MOUNT_DIR/$dir"
        run_cmd mount --bind "/$dir" "$MOUNT_DIR/$dir"
    done
    
    for d in "${CHROOT_BIND_DIRS[@]}"; do
        mkdir -p "$MOUNT_DIR$d"
        run_cmd mount --bind "$d" "$MOUNT_DIR$d"
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
    
    if [[ -z "$slot" ]]; then
        die "generate_uki_common: slot parameter is empty"
    fi
    
    if [[ ! -x "$GENEFI_SCRIPT" ]]; then
        die "gen-efi script not found or not executable: $GENEFI_SCRIPT"
    fi
    
    prepare_chroot_env "$slot"
    log "Generating Secure Boot UKI for slot ${slot} using external gen-efi script..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would generate UKI for slot ${slot}"
    else
        if ! chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$slot"; then
            cleanup_chroot_env
            die "UKI generation failed for slot ${slot}"
        fi
    fi
    
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
        failed_slot="${failed_slot// /}"
    else
        log "WARNING: Current slot marker missing, using booted slot"
        failed_slot=$(get_booted_subvol)
    fi
    
    if [[ -f "$MOUNT_DIR/@data/previous-slot" ]]; then
        previous_slot=$(< "$MOUNT_DIR/@data/previous-slot")
        previous_slot="${previous_slot// /}"
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
    
    run_cmd btrfs property set -ts "$failed_path" ro false
    run_cmd btrfs subvolume delete "$failed_path"
    run_cmd btrfs subvolume snapshot "$backup_path" "$failed_path"
    run_cmd btrfs property set -ts "$failed_path" ro true
    
    log "Updating active slot marker to previous slot: ${previous_slot}..."
    echo "$previous_slot" > "$MOUNT_DIR/@data/current-slot"
    safe_umount "$MOUNT_DIR"
    
    generate_uki_common "$previous_slot"
    log "Rollback complete. Rebooting system..."
    [[ "${DRY_RUN}" == "yes" ]] || reboot
}

#####################################
### URL Validation Functions      ###
#####################################

validate_url() {
    local url="$1"
    
    [[ -n "$url" ]] || return 1
    [[ "$url" =~ ^https?:// ]] || return 1
    [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(/.*)?$ ]] || return 1
    
    return 0
}

is_valid_mirror() {
    local url="$1"
    
    validate_url "$url" || return 1
    [[ "$url" != *"sourceforge.net/projects/shanios/files"* ]] || return 1
    [[ "$url" == *"${IMAGE_NAME}"* ]] || [[ "$url" =~ /download$ ]] || return 1
    
    return 0
}

#####################################
### Effective URL Discovery       ###
#####################################

get_effective_url() {
    local url="$1"
    local method="${2:-auto}"
    local effective_url=""
    
    if [[ -z "$url" ]]; then
        log "ERROR: Empty URL passed to get_effective_url"
        return 1
    fi
    
    if ! validate_url "$url"; then
        log "ERROR: Invalid URL format: $url"
        return 1
    fi
    
    case "$method" in
        curl|auto)
            if command -v curl &>/dev/null; then
                effective_url=$(curl -sL -w '%{url_effective}' -o /dev/null \
                    --max-time "$MIRROR_DISCOVERY_TIMEOUT" \
                    --max-redirs 5 \
                    --retry 1 \
                    --retry-delay 2 \
                    "$url" 2>/dev/null || echo "")
                
                [[ -n "$effective_url" ]] && validate_url "$effective_url" && {
                    echo "$effective_url"
                    return 0
                }
            fi
            ;;&
            
        wget|auto)
            if command -v wget &>/dev/null; then
                effective_url=$(wget --max-redirect=5 \
                    --spider -S \
                    --timeout="$MIRROR_DISCOVERY_TIMEOUT" \
                    --tries=1 \
                    "$url" 2>&1 | \
                    grep -i '^ *Location: ' | \
                    tail -1 | \
                    awk '{print $2}' | \
                    tr -d '\r' || echo "")
                
                [[ -n "$effective_url" ]] && validate_url "$effective_url" && {
                    echo "$effective_url"
                    return 0
                }
            fi
            ;;
            
        *)
            log "ERROR: Unknown method '$method' in get_effective_url"
            return 1
            ;;
    esac
    
    return 1
}

#####################################
### Mirror Testing                ###
#####################################

test_mirror_response() {
    local mirror_url="$1"
    local timeout="${2:-$MIRROR_TEST_TIMEOUT}"
    
    if [[ -z "$mirror_url" ]]; then
        log "ERROR: Empty mirror_url in test_mirror_response"
        return 1
    fi
    
    if ! validate_url "$mirror_url"; then
        log "ERROR: Invalid mirror URL: $mirror_url"
        return 1
    fi
    
    if command -v curl &>/dev/null; then
        if curl -I \
            --max-time "$timeout" \
            --retry 1 \
            --silent \
            --fail \
            "$mirror_url" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    if command -v wget &>/dev/null; then
        if wget --spider \
            --timeout="$timeout" \
            --tries=1 \
            --quiet \
            "$mirror_url" 2>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

#####################################
### Mirror Discovery              ###
#####################################

discover_initial_mirror() {
    local base_url="$1"
    local MIRROR_FILE="${DOWNLOAD_DIR}/mirror.url"
    
    if [[ -z "$base_url" ]]; then
        log "ERROR: base_url is empty in discover_initial_mirror"
        return 1
    fi
    
    if ! validate_url "$base_url"; then
        log "ERROR: Invalid base_url format: $base_url"
        return 1
    fi
    
    log "Performing initial mirror discovery for: $base_url"
    
    local mirror_url=""
    local methods=("curl" "wget")
    
    for method in "${methods[@]}"; do
        log "Trying mirror discovery with $method..."
        mirror_url=$(get_effective_url "$base_url" "$method")
        
        if [[ -n "$mirror_url" ]] && is_valid_mirror "$mirror_url"; then
            if ! echo "$mirror_url" > "$MIRROR_FILE"; then
                log "ERROR: Failed to write mirror file: $MIRROR_FILE"
                return 1
            fi
            log "Discovered mirror: $mirror_url"
            return 0
        fi
    done
    
    log "WARNING: Could not discover mirror, using direct SourceForge URL"
    if ! echo "$base_url" > "$MIRROR_FILE"; then
        log "ERROR: Failed to write fallback mirror file"
        return 1
    fi
    return 0
}

find_fastest_mirror() {
    local base_url="$1"
    local MIRROR_FILE="${DOWNLOAD_DIR}/mirror.url"
    
    if [[ -z "$base_url" ]]; then
        log "ERROR: base_url is empty in find_fastest_mirror"
        return 1
    fi
    
    if ! validate_url "$base_url"; then
        log "ERROR: Invalid base_url: $base_url"
        return 1
    fi
    
    log "Finding fastest mirror for: $base_url"
    
    local -a discovered_mirrors=()
    local -A seen_domains=()
    local mirror_url domain
    local methods=("curl" "wget")
    local method_idx=0
    
    for ((i=0; i<MAX_MIRROR_DISCOVERIES; i++)); do
        local method="${methods[$method_idx]}"
        method_idx=$(( (method_idx + 1) % ${#methods[@]} ))
        
        mirror_url=$(get_effective_url "$base_url" "$method")
        
        if [[ -n "$mirror_url" ]] && is_valid_mirror "$mirror_url"; then
            domain=$(echo "$mirror_url" | sed -E 's|https?://([^/]+).*|\1|')
            
            if [[ -z "$domain" ]]; then
                log "WARNING: Could not extract domain from: $mirror_url"
                continue
            fi
            
            if [[ -z "${seen_domains[$domain]:-}" ]]; then
                seen_domains["$domain"]=1
                discovered_mirrors+=("$mirror_url")
                log "Discovered mirror: $domain"
            fi
        fi
        
        if [[ ${#discovered_mirrors[@]} -ge MIN_MIRRORS_NEEDED ]]; then
            break
        fi
        
        sleep 0.5
    done
    
    if [[ ${#discovered_mirrors[@]} -eq 0 ]]; then
        log "No mirrors discovered, using direct URL"
        if ! echo "$base_url" > "$MIRROR_FILE"; then
            log "ERROR: Failed to write mirror file"
            return 1
        fi
        return 0
    fi
    
    log "Testing ${#discovered_mirrors[@]} mirror(s) for responsiveness..."
    
    local selected_mirror=""
    
    for mirror in "${discovered_mirrors[@]}"; do
        log "Testing mirror: $(echo "$mirror" | sed -E 's|https?://([^/]+).*|\1|')"
        
        if test_mirror_response "$mirror"; then
            selected_mirror="$mirror"
            log "Selected responsive mirror: $(echo "$mirror" | sed -E 's|https?://([^/]+).*|\1|')"
            break
        else
            log "Mirror unresponsive: $(echo "$mirror" | sed -E 's|https?://([^/]+).*|\1|')"
        fi
    done
    
    if [[ -z "$selected_mirror" ]]; then
        selected_mirror="${discovered_mirrors[0]}"
        log "WARNING: All mirrors unresponsive, using first discovered: $selected_mirror"
    fi
    
    if ! echo "$selected_mirror" > "$MIRROR_FILE"; then
        log "ERROR: Failed to write selected mirror to file"
        return 1
    fi
    
    return 0
}

#####################################
### Storage Optimization          ###
#####################################

optimize_storage() {
    log "Optimizing storage (deduplicating blue/green slots)..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    if ! btrfs subvolume show "$MOUNT_DIR/@blue" &>/dev/null || \
       ! btrfs subvolume show "$MOUNT_DIR/@green" &>/dev/null; then
        log "Skipping optimization: both slots not present"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    if ! command -v duperemove &>/dev/null; then
        log "WARNING: duperemove not installed (add to package list for 50-70% space savings)"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    local before=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | tail -1 | awk '{print $1}')
    
    log "Running Btrfs extent deduplication (this may take a few minutes)..."
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would run duperemove on blue/green slots"
    else
        duperemove -dhr \
            --hashfile="$MOUNT_DIR/@data/.dedupe.db" \
            "$MOUNT_DIR/@blue" \
            "$MOUNT_DIR/@green" &>/dev/null
    fi
    
    local after=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | tail -1 | awk '{print $1}')
    
    if [[ -n "$before" ]] && [[ -n "$after" ]] && (( before > after )); then
        local saved=$((before - after))
        local percent=$((saved * 100 / before))
        log "Storage reclaimed: $(numfmt --to=iec $saved) (${percent}% reduction)"
    else
        log "Storage already optimized"
    fi
    
    safe_umount "$MOUNT_DIR"
}

#####################################
### Subvolume Verification        ###
#####################################

parse_candidate_fstab_subvolumes() {
    local fstab_file="$1"
    local -a subvols=()
    
    if [[ ! -f "$fstab_file" ]]; then
        log "WARNING: Cannot read fstab from candidate slot"
        return 1
    fi
    
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        
        if [[ "$line" =~ LABEL=shani_root ]] && [[ "$line" =~ subvol=@([a-zA-Z0-9_]+) ]]; then
            local subvol="${BASH_REMATCH[1]}"
            if [[ "$subvol" != "blue" && "$subvol" != "green" ]]; then
                subvols+=("$subvol")
            fi
        fi
    done < "$fstab_file"
    
    local -a unique_subvols=($(printf '%s\n' "${subvols[@]}" | sort -u))
    
    printf '%s\n' "${unique_subvols[@]}"
    return 0
}

verify_and_create_required_subvolumes() {
    log "Verifying required subvolumes exist for candidate slot..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    local candidate_fstab="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/fstab"
    
    if [[ ! -f "$candidate_fstab" ]]; then
        log "WARNING: fstab not found in candidate slot, cannot verify subvolumes"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    mapfile -t required_subvols < <(parse_candidate_fstab_subvolumes "$candidate_fstab")
    
    if [[ ${#required_subvols[@]} -eq 0 ]]; then
        log "No additional subvolumes required"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    log "Candidate slot requires ${#required_subvols[@]} subvolume(s): ${required_subvols[*]}"
    
    local -a missing_subvols=()
    for subvol in "${required_subvols[@]}"; do
        if ! btrfs subvolume show "$MOUNT_DIR/@${subvol}" &>/dev/null; then
            missing_subvols+=("$subvol")
        fi
    done
    
    if [[ ${#missing_subvols[@]} -gt 0 ]]; then
        log "Found ${#missing_subvols[@]} missing subvolume(s): ${missing_subvols[*]}"
        log "Creating missing subvolumes to prevent boot failure..."
        
        for subvol in "${missing_subvols[@]}"; do
            log "Creating @${subvol}..."
            
            run_cmd btrfs subvolume create "$MOUNT_DIR/@${subvol}"
            
            case "$subvol" in
                swap)
                    log "Setting up @swap subvolume for hibernation..."
                    
                    if [[ "${DRY_RUN}" == "yes" ]]; then
                        log "[Dry Run] Would disable CoW and create swapfile"
                    else
                        if chattr +C "$MOUNT_DIR/@${subvol}" 2>/dev/null; then
                            log "Disabled CoW on @swap subvolume"
                        else
                            log "WARNING: Failed to disable CoW on @swap"
                        fi
                        
                        local swapfile="$MOUNT_DIR/@${subvol}/swapfile"
                        if [[ ! -f "$swapfile" ]]; then
                            log "Creating swapfile..."
                            
                            local mem_mb
                            mem_mb=$(free -m | awk '/^Mem:/{print $2}')
                            
                            # Check available space on the filesystem
                            local available_mb
                            available_mb=$(df -BM "$MOUNT_DIR" | awk 'NR==2 {gsub(/M/,""); print $4}')
                            
                            # Need at least mem_mb + 2GB buffer for safety
                            local required_mb=$((mem_mb + 2048))
                            
                            if (( available_mb < required_mb )); then
                                log "WARNING: Insufficient space for full-size swapfile"
                                log "Available: ${available_mb}MB, Required: ${required_mb}MB"
                                
                                # Try to create smaller swapfile (50% of RAM if space allows)
                                local fallback_mb=$((mem_mb / 2))
                                local fallback_required=$((fallback_mb + 1024))
                                
                                if (( available_mb >= fallback_required )); then
                                    log "Creating reduced swapfile: ${fallback_mb}MB (50% of RAM)"
                                    mem_mb=$fallback_mb
                                else
                                    log "ERROR: Not enough space even for reduced swapfile. Skipping."
                                    continue
                                fi
                            fi
                            
                            if btrfs filesystem mkswapfile --size "${mem_mb}M" "$swapfile" 2>/dev/null; then
                                log "Created swapfile: ${mem_mb}M"
                                chmod 600 "$swapfile"
                            else
                                log "WARNING: btrfs mkswapfile unavailable, using fallback"
                                if dd if=/dev/zero of="$swapfile" bs=1M count="$mem_mb" status=none 2>/dev/null; then
                                    chmod 600 "$swapfile" 2>/dev/null
                                    mkswap "$swapfile" &>/dev/null || log "WARNING: Failed to format swapfile"
                                    log "Created swapfile using dd: ${mem_mb}M"
                                else
                                    log "ERROR: Failed to create swapfile"
                                    rm -f "$swapfile"
                                fi
                            fi
                        fi
                    fi
                    ;;
                    
                data)
                    log "Creating overlay structure in @data..."
                    if [[ "${DRY_RUN}" == "yes" ]]; then
                        log "[Dry Run] Would create @data overlay structure"
                    else
                        mkdir -p "$MOUNT_DIR/@data/overlay/etc/lower"
                        mkdir -p "$MOUNT_DIR/@data/overlay/etc/upper"
                        mkdir -p "$MOUNT_DIR/@data/overlay/etc/work"
                        mkdir -p "$MOUNT_DIR/@data/overlay/var/lower"
                        mkdir -p "$MOUNT_DIR/@data/overlay/var/upper"
                        mkdir -p "$MOUNT_DIR/@data/overlay/var/work"
                        mkdir -p "$MOUNT_DIR/@data/downloads"
                        
                        [[ ! -f "$MOUNT_DIR/@data/current-slot" ]] && \
                            echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot"
                        [[ ! -f "$MOUNT_DIR/@data/previous-slot" ]] && \
                            echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/previous-slot"
                    fi
                    ;;
            esac
        done
        
        log "All missing subvolumes created successfully"
    else
        log "All required subvolumes already exist"
    fi
    
    safe_umount "$MOUNT_DIR"
    return 0
}

analyze_storage_usage() {
    log "Analyzing storage usage..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    echo ""
    echo "=== Btrfs Storage Analysis ==="
    
    echo ""
    echo "1. Filesystem Overview:"
    btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/   /' || echo "   Unable to read filesystem info"
    
    echo ""
    echo "2. Individual Subvolume Sizes (uncompressed):"
    for subvol in blue green data; do
        if btrfs subvolume show "$MOUNT_DIR/@${subvol}" &>/dev/null; then
            local exclusive=$(btrfs filesystem du -s "$MOUNT_DIR/@${subvol}" 2>/dev/null | awk 'NR==2 {print $1}')
            local total=$(btrfs filesystem du -s "$MOUNT_DIR/@${subvol}" 2>/dev/null | awk 'NR==2 {print $2}')
            if [[ -n "$exclusive" ]] && [[ -n "$total" ]]; then
                echo "   @${subvol}: Exclusive=$(numfmt --to=iec $exclusive 2>/dev/null || echo $exclusive) Total=$(numfmt --to=iec $total 2>/dev/null || echo $total)"
            else
                echo "   @${subvol}: Present"
            fi
        else
            echo "   @${subvol}: Not found"
        fi
    done
    
    echo ""
    echo "3. Actual Space Used (after sharing/deduplication):"
    if btrfs subvolume show "$MOUNT_DIR/@blue" &>/dev/null && btrfs subvolume show "$MOUNT_DIR/@green" &>/dev/null; then
        local combined=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | tail -1 | awk '{print $1}')
        if [[ -n "$combined" ]]; then
            echo "   Blue + Green combined: $(numfmt --to=iec $combined 2>/dev/null || echo $combined)"
            
            local blue_size=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" 2>/dev/null | awk 'NR==2 {print $2}')
            local green_size=$(btrfs filesystem du -s "$MOUNT_DIR/@green" 2>/dev/null | awk 'NR==2 {print $2}')
            if [[ -n "$blue_size" ]] && [[ -n "$green_size" ]] && (( blue_size + green_size > 0 )); then
                local theoretical=$((blue_size + green_size))
                local saved=$((theoretical - combined))
                local percent=$((saved * 100 / theoretical))
                echo "   Saved via sharing: $(numfmt --to=iec $saved 2>/dev/null || echo $saved) (${percent}%)"
            fi
        else
            echo "   Unable to calculate combined size"
        fi
    else
        echo "   Both slots not present - cannot calculate"
    fi
    
    if command -v compsize &>/dev/null; then
        echo ""
        echo "4. Compression Statistics:"
        compsize "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | sed 's/^/   /' || \
            echo "   (unable to read compression stats)"
    else
        echo ""
        echo "4. Compression Statistics: (install 'compsize' for details)"
    fi
    
    if [[ -f "$MOUNT_DIR/@data/.dedupe.db" ]]; then
        local db_size=$(stat -c%s "$MOUNT_DIR/@data/.dedupe.db" 2>/dev/null || echo 0)
        echo ""
        echo "5. Deduplication Database: $(numfmt --to=iec $db_size 2>/dev/null || echo $db_size)"
    fi
    
    echo "=============================="
    echo ""
    
    safe_umount "$MOUNT_DIR"
}

#####################################
### Deployment Phase Functions    ###
#####################################

boot_validation_and_candidate_selection() {
    CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null || echo "")
    CURRENT_SLOT="${CURRENT_SLOT// /}"
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
    log "Disk space is sufficient: ${free_space_mb} MB available."
    run_cmd mkdir -p "$DOWNLOAD_DIR" "$ZSYNC_CACHE_DIR"
}

fetch_update_info() {
    local channel_url
    channel_url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    
    log "Initiating update check: retrieving update info from ${channel_url}..."
    
    IMAGE_NAME=$(wget -qO- "$channel_url" | tr -d '[:space:]') || die "Error: Unable to fetch update info from ${channel_url}"
    log "Fetched update info: '${IMAGE_NAME}'"
    
    if [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"
        log "Parsed update info: version v${REMOTE_VERSION}, profile '${REMOTE_PROFILE}'"
    else
        die "Error: Invalid update format in ${UPDATE_CHANNEL}.txt. Received: '${IMAGE_NAME}'"
    fi

    if [[ "$LOCAL_VERSION" == "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
        log "Local system is up-to-date (v${REMOTE_VERSION}, ${REMOTE_PROFILE}). Proceeding to verify candidate slot..."
        
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"

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
                    log "Mismatch in candidate slot: found ${CANDIDATE_VERSION} (${CANDIDATE_PROFILE}) vs expected ${REMOTE_VERSION} (${REMOTE_PROFILE}). Deploying update."
                fi
            else
                log "Candidate slot missing version/profile details. Deploying update."
            fi
        else
            log "No candidate subvolume '@${CANDIDATE_SLOT}' found. Exiting update process."
            safe_umount "$MOUNT_DIR"
            exit 0
        fi
        safe_umount "$MOUNT_DIR"
    else
        log "Local system version (${LOCAL_VERSION}, ${LOCAL_PROFILE}) differs from remote (${REMOTE_VERSION}, ${REMOTE_PROFILE}). Initiating update."
    fi
}

download_update() {
    log "Starting download process for ${IMAGE_NAME}"

    if [[ -z "${IMAGE_NAME}" || -z "${DOWNLOAD_DIR}" || -z "${REMOTE_PROFILE}" || -z "${REMOTE_VERSION}" ]]; then
        log "ERROR: Required variables not set"
        return 1
    fi

    local missing_cmds=()
    for cmd in wget sha256sum; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_cmds+=("$cmd")
        fi
    done
    
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        log "ERROR: Required commands not found: ${missing_cmds[*]}"
        return 1
    fi

    run_cmd mkdir -p "${DOWNLOAD_DIR}"
    
    if ! cd "${DOWNLOAD_DIR}"; then
        log "ERROR: Could not access download directory: ${DOWNLOAD_DIR}"
        return 1
    fi

    local WGET_OPTS=(
        --retry-connrefused
        --waitretry=30
        --read-timeout=60
        --timeout=60
        --tries=5
        --no-verbose
        --dns-timeout=30
        --connect-timeout=30
        --prefer-family=IPv4
        --continue
    )
    [[ -t 2 ]] && WGET_OPTS+=(--show-progress)

    local SOURCEFORGE_BASE="https://sourceforge.net/projects/shanios/files"
    local MIRROR_FILE="${DOWNLOAD_DIR}/mirror.url"
    local MAX_ATTEMPTS=5
    local RETRY_BASE_DELAY=5
    local RETRY_MAX_DELAY=60

    local UPDATE_CHANNEL_FILE="${DOWNLOAD_DIR}/${UPDATE_CHANNEL}.channel"
    local MARKER_FILE="${DOWNLOAD_DIR}/${IMAGE_NAME}.verified"
    local image_file="${DOWNLOAD_DIR}/${IMAGE_NAME}"
    local image_file_part="${image_file}.part"
    local sha_file="${DOWNLOAD_DIR}/${IMAGE_NAME}.sha256"
    local asc_file="${DOWNLOAD_DIR}/${IMAGE_NAME}.asc"

    if [[ -f "${MARKER_FILE}" && -f "${image_file}" ]]; then
        local existing_size
        existing_size=$(stat -c%s "${image_file}" 2>/dev/null || echo 0)
        if (( existing_size > 0 )); then
            log "Found existing verified download: ${IMAGE_NAME} (${existing_size} bytes)"
            return 0
        else
            log "WARNING: Marker exists but file is empty, re-downloading"
            rm -f "${MARKER_FILE}"
        fi
    fi

    local base_url="${SOURCEFORGE_BASE}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}/download"
    
    if ! validate_url "$base_url"; then
        log "ERROR: Constructed invalid base URL: $base_url"
        return 1
    fi

    local mirror_url=""
    mirror_url=$(cat "${MIRROR_FILE}" 2>/dev/null | head -1 | xargs || echo "")
    if [[ -n "$mirror_url" ]] && is_valid_mirror "$mirror_url"; then
        log "Using cached mirror: $(echo "$mirror_url" | sed -E 's|https?://([^/]+).*|\1|')"
    else
        log "Cached mirror invalid or missing, discovering new mirror..."
        rm -f "${MIRROR_FILE}"
        mirror_url=""
    fi
    
    if [[ -z "$mirror_url" ]]; then
        if ! find_fastest_mirror "$base_url"; then
            log "WARNING: Mirror discovery failed, attempting initial discovery..."
            if ! discover_initial_mirror "$base_url"; then
                log "ERROR: All mirror discovery attempts failed"
                return 1
            fi
        fi
        
        if [[ ! -f "${MIRROR_FILE}" ]]; then
            log "ERROR: Mirror file not created after discovery"
            return 1
        fi
        
        mirror_url=$(cat "${MIRROR_FILE}" 2>/dev/null | head -1 | xargs || echo "")
        
        if [[ -z "$mirror_url" ]]; then
            log "ERROR: No mirror URL available after discovery"
            return 1
        fi
    fi

    log "Checking remote file availability..."
    local expected_size
    expected_size=$(wget -q --spider -S "$mirror_url" 2>&1 | \
        awk '/Content-Length:/ {print $2}' | \
        tail -1 | \
        tr -d '\r' || echo "0")
    
    if [[ ! "$expected_size" =~ ^[0-9]+$ ]] || (( expected_size <= 0 )); then
        log "WARNING: Could not determine remote file size, proceeding anyway"
        expected_size=0
    else
        log "Expected file size: $((expected_size / 1024 / 1024)) MB"
    fi

    if ! echo "${IMAGE_NAME}" > "${UPDATE_CHANNEL_FILE}"; then
        log "ERROR: Failed to write channel file: ${UPDATE_CHANNEL_FILE}"
        return 1
    fi

    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would download ${IMAGE_NAME} from mirror"
        log "[Dry Run] Would verify SHA256 and GPG signature"
        return 0
    fi

    local attempt=0
    local current_size=0
    local download_success=0
    
    while (( attempt < MAX_ATTEMPTS )) && [[ $download_success -eq 0 ]]; do
        attempt=$((attempt + 1))
        log "Download attempt ${attempt}/${MAX_ATTEMPTS} from: $(echo "$mirror_url" | sed -E 's|https?://([^/]+).*|\1|')"

        if [[ -f "${image_file_part}" ]]; then
            current_size=$(stat -c%s "${image_file_part}" 2>/dev/null || echo 0)
            
            if (( expected_size > 0 && current_size > expected_size )); then
                log "Partial file larger than expected - deleting"
                rm -f "${image_file_part}"
                current_size=0
            elif (( current_size > 0 )); then
                log "Resuming download: $((current_size / 1024 / 1024)) MB / $((expected_size / 1024 / 1024)) MB"
            fi
        fi

        if wget "${WGET_OPTS[@]}" -O "${image_file_part}" "$mirror_url"; then
            current_size=$(stat -c%s "${image_file_part}" 2>/dev/null || echo 0)
            
            if (( expected_size == 0 )) || (( current_size == expected_size )); then
                download_success=1
                log "Download completed successfully"
                if ! mv "${image_file_part}" "${image_file}"; then
                    log "ERROR: File rename failed"
                    return 1
                fi
            else
                log "Download incomplete ($((current_size / 1024 / 1024)) MB / $((expected_size / 1024 / 1024)) MB)"
            fi
        else
            log "Download failed with current mirror"
            
            if (( attempt % 2 == 0 )); then
                log "Attempting to discover new mirror..."
                rm -f "${MIRROR_FILE}"
                if find_fastest_mirror "$base_url"; then
                    mirror_url=$(cat "${MIRROR_FILE}" 2>/dev/null | head -1 | xargs || echo "")
                    if [[ -n "$mirror_url" ]]; then
                        log "Switched to new mirror: $(echo "$mirror_url" | sed -E 's|https?://([^/]+).*|\1|')"
                    else
                        log "ERROR: New mirror URL is empty"
                    fi
                fi
            fi
        fi

        if [[ $download_success -eq 0 ]] && (( attempt < MAX_ATTEMPTS )); then
            local delay=$(( RETRY_BASE_DELAY * (2 ** (attempt - 1)) ))
            (( delay = delay > RETRY_MAX_DELAY ? RETRY_MAX_DELAY : delay ))
            log "Retrying in ${delay}s..."
            sleep "$delay"
        fi
    done

    if [[ $download_success -eq 0 ]]; then
        log "ERROR: Failed to download after ${MAX_ATTEMPTS} attempts"
        return 1
    fi

    if [[ ! -f "${image_file}" ]]; then
        log "ERROR: Downloaded file does not exist: ${image_file}"
        return 1
    fi
    
    current_size=$(stat -c%s "${image_file}" 2>/dev/null || echo 0)
    if (( current_size == 0 )); then
        log "ERROR: Downloaded file is empty"
        rm -f "${image_file}"
        return 1
    fi

    log "Download completed, proceeding with verification..."
    
    log "Fetching SHA256 checksum..."
    local sha_url="${SOURCEFORGE_BASE}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.sha256/download"
    if ! wget "${WGET_OPTS[@]}" -O "${sha_file}" "${sha_url}"; then
        log "ERROR: Failed to fetch SHA256 file"
        return 1
    fi
    
    log "Fetching GPG signature..."
    local asc_url="${SOURCEFORGE_BASE}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.asc/download"
    if ! wget "${WGET_OPTS[@]}" -O "${asc_file}" "${asc_url}"; then
        log "ERROR: Failed to fetch GPG signature file"
        return 1
    fi

    log "Verifying SHA256 checksum..."
    if ! sha256sum -c "${sha_file}" --status 2>/dev/null; then
        log "ERROR: SHA256 checksum verification failed"
        rm -f "${image_file}"
        return 1
    fi
    log "SHA256 checksum verified successfully"

    log "Verifying GPG signature..."
    local gpg_temp
    if ! gpg_temp=$(mktemp -d); then
        log "ERROR: Failed to create temporary GPG directory"
        return 1
    fi
    
    local old_gnupghome_set=false
    local old_gnupghome_value=""
    if [[ -v GNUPGHOME ]]; then
        old_gnupghome_set=true
        old_gnupghome_value="${GNUPGHOME}"
    fi
    
    export GNUPGHOME="${gpg_temp}"
    chmod 700 "${gpg_temp}"
    
    cleanup_gpg() {
        if [[ "${old_gnupghome_set}" == "true" ]]; then
            export GNUPGHOME="${old_gnupghome_value}"
        else
            unset GNUPGHOME
        fi
        rm -rf "${gpg_temp}"
    }
    trap cleanup_gpg RETURN

    log "Importing GPG key ${GPG_KEY_ID}..."
    local GPG_KEYSERVERS=("hkps://keys.openpgp.org" "keyserver.ubuntu.com")
    local key_imported=0
    
    for keyserver in "${GPG_KEYSERVERS[@]}"; do
        if gpg --batch --quiet --keyserver "${keyserver}" --recv-keys "${GPG_KEY_ID}" 2>/dev/null; then
            log "Successfully imported key from ${keyserver}"
            key_imported=1
            break
        else
            log "Failed to import key from ${keyserver}, trying next..."
        fi
    done
    
    if [[ ${key_imported} -ne 1 ]]; then
        log "ERROR: Failed to import GPG key from all keyservers"
        cleanup_gpg
        return 1
    fi

    if ! gpg --batch --verify "${asc_file}" "${image_file}" 2>/dev/null; then
        log "ERROR: GPG signature verification failed"
        rm -f "${image_file}"
        cleanup_gpg
        return 1
    fi
    log "GPG signature verified successfully"

    cleanup_gpg

    if ! touch "${MARKER_FILE}"; then
        log "ERROR: Failed to create verification marker"
        return 1
    fi

    log "Download and verification completed successfully"
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
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        log "Creating backup of candidate slot @${CANDIDATE_SLOT} as @${BACKUP_NAME}..."
        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}"
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    fi
    
    local temp_subvol="$MOUNT_DIR/temp_update"
    if btrfs subvolume list "$MOUNT_DIR" | awk '{print $NF}' | grep -qx "temp_update"; then
        log "Deleting existing temporary subvolume temp_update..."
        if [[ -d "$temp_subvol/shanios_base" ]]; then
            run_cmd btrfs subvolume delete "$temp_subvol/shanios_base"
        fi
        run_cmd btrfs subvolume delete "$temp_subvol"
    fi
    
    run_cmd btrfs subvolume create "$temp_subvol"
    log "Receiving update image into temporary subvolume..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would extract ${IMAGE_NAME} to temporary subvolume"
    else
        if ! zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | btrfs receive "$temp_subvol"; then
            die "Image extraction failed"
        fi
    fi
    
    log "Creating candidate snapshot from temporary update..."
    run_cmd btrfs subvolume snapshot "$temp_subvol/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
    
    log "Deleting temporary subvolume..."
    if [[ -d "$temp_subvol/shanios_base" ]]; then
        run_cmd btrfs subvolume delete "$temp_subvol/shanios_base"
    fi
    run_cmd btrfs subvolume delete "$temp_subvol"
    safe_umount "$MOUNT_DIR"
    
    if [[ "${DRY_RUN}" == "no" ]]; then
        touch "$DEPLOY_PENDING"
    fi
}

finalize_update() {
    log "Finalizing deployment..."

    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would finalize deployment and switch to slot ${CANDIDATE_SLOT}"
        return 0
    fi

    echo "$CURRENT_SLOT" > /data/previous-slot
    echo "$CANDIDATE_SLOT" > /data/current-slot

    verify_and_create_required_subvolumes || die "Failed to verify/create required subvolumes"

    log "Generating Secure Boot UKI for new deployment..."
    generate_uki_common "$CANDIDATE_SLOT"
    
    [[ -f "$DEPLOY_PENDING" ]] && { 
        rm -f "$DEPLOY_PENDING"
        log "Removed deployment pending marker."
    }

    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    [[ -n "$BACKUP_NAME" ]] && {
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${BACKUP_NAME}"
        log "Deleted backup @${BACKUP_NAME}"
    }
    cleanup_old_backups
    safe_umount "$MOUNT_DIR"

    echo "$IMAGE_NAME" > "$DOWNLOAD_DIR/old.txt"
    cleanup_downloads

    optimize_storage

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
  -s, --storage-info     Show storage usage analysis.
  -t, --channel <chan>   Specify update channel: latest or stable (default: stable).
  -d, --dry-run          Dry run (simulate actions without making changes).
EOF
}

args=$(getopt -o hrcst:d --long help,rollback,cleanup,storage-info,channel:,dry-run -n "$0" -- "$@") || { usage; exit 1; }
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
        -s|--storage-info)
            touch "${STATE_DIR}/storage-info"
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
    self_update "$@"
    inhibit_system "$@"
   
    DRY_RUN=$([[ -f "${STATE_DIR}/dry-run" ]] && echo "yes" || echo "no")
    
    if [[ -f "${STATE_DIR}/channel" ]]; then
        UPDATE_CHANNEL=$(cat "${STATE_DIR}/channel")
    else
        UPDATE_CHANNEL="stable"
    fi

    if [[ -f "${STATE_DIR}/storage-info" ]]; then
        log "Showing storage information..."
        analyze_storage_usage
        exit 0
    fi

    if [[ -f "${STATE_DIR}/cleanup" ]]; then
        log "Initiating manual cleanup..."
        mkdir -p "$MOUNT_DIR"
        if safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" 2>/dev/null; then
            cleanup_old_backups
            safe_umount "$MOUNT_DIR"
        fi
        cleanup_downloads
        if [[ -f "/data/.dedupe.db" ]]; then
            run_cmd rm -f "/data/.dedupe.db"
            log "Removed deduplication database"
        fi
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
        mkdir -p "$MOUNT_DIR"
        if safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" 2>/dev/null; then
            if btrfs subvolume show "$MOUNT_DIR/@blue" &>/dev/null && \
               btrfs subvolume show "$MOUNT_DIR/@green" &>/dev/null; then
                safe_umount "$MOUNT_DIR"
                log "Running storage optimization on existing slots..."
                optimize_storage
            else
                safe_umount "$MOUNT_DIR"
            fi
        fi
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
