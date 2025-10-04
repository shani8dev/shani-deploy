#!/bin/bash
################################################################################
# shanios-deploy.sh
#
# Enhanced Blue/Green Btrfs Deployment Script for shanios
# Refactored to eliminate redundancies
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

set -Eeuo pipefail
IFS=$'\n\t'

#####################################
### State Restoration             ###
#####################################

if [[ -n "${SHANIOS_DEPLOY_STATE_FILE:-}" ]] && [[ -f "$SHANIOS_DEPLOY_STATE_FILE" ]]; then
    source "$SHANIOS_DEPLOY_STATE_FILE"
    rm -f "$SHANIOS_DEPLOY_STATE_FILE"
fi

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

# Tool availability flags (check once at startup)
declare -g HAS_ARIA2C=0 HAS_WGET=0 HAS_CURL=0
command -v aria2c &>/dev/null && HAS_ARIA2C=1
command -v wget &>/dev/null && HAS_WGET=1
command -v curl &>/dev/null && HAS_CURL=1

declare -g LOCAL_VERSION LOCAL_PROFILE
declare -g BACKUP_NAME="" CURRENT_SLOT="" CANDIDATE_SLOT=""
declare -g REMOTE_VERSION="" REMOTE_PROFILE="" IMAGE_NAME=""
declare -g UPDATE_CHANNEL="stable" DRY_RUN="no"
declare -g MARKER_FILE=""

CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp /sys/firmware/efi/efivars)
CHROOT_STATIC_DIRS=(data etc var)

#####################################
### State Management              ###
#####################################

STATE_DIR=$(mktemp -d /tmp/shanios-deploy-state.XXXXXX)
export STATE_DIR

cleanup_state() {
    [[ -n "${STATE_DIR}" && -d "${STATE_DIR}" ]] && rm -rf "${STATE_DIR}"
}
trap cleanup_state EXIT

persist_state() {
    local state_file
    state_file=$(mktemp /tmp/shanios_deploy_state.XXXX)
    {
        declare -p OS_NAME DOWNLOAD_DIR ZSYNC_CACHE_DIR MOUNT_DIR ROOTLABEL ROOT_DEV 2>/dev/null || true
        declare -p MIN_FREE_SPACE_MB GENEFI_SCRIPT DEPLOY_PENDING GPG_KEY_ID 2>/dev/null || true
        declare -p LOCAL_VERSION LOCAL_PROFILE BACKUP_NAME CURRENT_SLOT CANDIDATE_SLOT 2>/dev/null || true
        declare -p REMOTE_VERSION REMOTE_PROFILE IMAGE_NAME STATE_DIR MARKER_FILE UPDATE_CHANNEL 2>/dev/null || true
        declare -p CHROOT_BIND_DIRS CHROOT_STATIC_DIRS 2>/dev/null || true
    } > "$state_file"
    export SHANIOS_DEPLOY_STATE_FILE="$state_file"
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
    fi
    log "Executing: $*"
    "$@" || die "Command failed: $*"
}

validate_nonempty() {
    local value="$1" name="$2"
    [[ -n "$value" ]] || die "$name is empty"
}

validate_url() {
    [[ "$1" =~ ^https?://[a-zA-Z0-9.-]+(/.*)?$ ]]
}

file_nonempty() {
    [[ -f "$1" ]] && (( $(stat -c%s "$1" 2>/dev/null || echo 0) > 0 ))
}

#####################################
### Mount Management              ###
#####################################

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    
    [[ -n "$src" && -n "$tgt" ]] || die "safe_mount: Invalid arguments (src='$src', tgt='$tgt')"
    
    if ! findmnt -M "$tgt" &>/dev/null; then
        run_cmd mount -o "$opts" "$src" "$tgt"
        log "Mounted $tgt"
    fi
}

safe_umount() {
    local tgt="$1"
    
    [[ -n "$tgt" ]] || { log "WARNING: safe_umount called with empty target"; return 1; }
    
    if findmnt -M "$tgt" &>/dev/null; then
        [[ "${DRY_RUN}" == "yes" ]] && { log "[Dry Run] Would unmount $tgt"; return 0; }
        umount -R "$tgt" && log "Unmounted $tgt" || { log "WARNING: Failed to unmount $tgt"; return 1; }
    fi
    return 0
}

#####################################
### Btrfs Helpers                 ###
#####################################

get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2- || echo "")
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    [[ -z "$subvol" ]] && subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    echo "${subvol:-blue}"
}

btrfs_subvol_exists() {
    local path="$1"
    btrfs subvolume show "$path" &>/dev/null
}

get_btrfs_available_mb() {
    local mount_point="$1"
    local available_bytes
    available_bytes=$(btrfs filesystem usage -b "$mount_point" 2>/dev/null | \
        awk '/Free \(estimated\):/ {gsub(/[^0-9]/,"",$3); print $3}')
    
    if [[ -z "$available_bytes" ]] || [[ "$available_bytes" -eq 0 ]]; then
        log "WARNING: Could not determine Btrfs available space"
        echo "0"
        return 1
    fi
    echo "$((available_bytes / 1024 / 1024))"
}

#####################################
### Universal Download Function   ###
#####################################

download_file() {
    local url="$1" output="$2"
    
    validate_url "$url" || return 1
    mkdir -p "$(dirname "$output")"
    
    # Try aria2c (fastest, multi-connection)
    if (( HAS_ARIA2C )); then
        aria2c --console-log-level=error --timeout=30 --max-tries=3 \
            --dir="$(dirname "$output")" --out="$(basename "$output")" \
            "$url" 2>/dev/null && return 0
    fi
    
    # Try wget (best SourceForge support, resume capability)
    if (( HAS_WGET )); then
        wget --timeout=30 --tries=3 --quiet --continue \
            -O "$output" "$url" 2>/dev/null && return 0
    fi
    
    # Try curl (last resort)
    if (( HAS_CURL )); then
        curl -fsSL --max-time 30 --retry 2 \
            -o "$output" "$url" 2>/dev/null && return 0
    fi
    
    log "ERROR: All download methods failed"
    return 1
}

download_with_retry() {
    local url="$1" output="$2" max_attempts="${3:-5}"
    local attempt=0 delay=5
    
    while (( attempt < max_attempts )); do
        ((attempt++))
        log "Download attempt ${attempt}/${max_attempts}..."
        
        download_file "$url" "$output" && file_nonempty "$output" && return 0
        
        (( attempt < max_attempts )) && {
            log "Retrying in ${delay}s..."
            sleep "$delay"
            delay=$(( delay < 60 ? delay * 2 : 60 ))
        }
    done
    
    return 1
}

#####################################
### Mirror Discovery & Testing    ###
#####################################

get_effective_url() {
    local url="$1" result=""
    
    validate_url "$url" || return 1
    
    # Use curl for redirect following
    if (( HAS_CURL )); then
        result=$(curl -sL -w '%{url_effective}' -o /dev/null \
            --max-time "$MIRROR_DISCOVERY_TIMEOUT" --max-redirs 5 "$url" 2>/dev/null)
        validate_url "$result" && { echo "$result"; return 0; }
    fi
    
    # Fallback to wget
    if (( HAS_WGET )); then
        result=$(wget --max-redirect=5 --spider -S \
            --timeout="$MIRROR_DISCOVERY_TIMEOUT" "$url" 2>&1 | \
            grep -i '^ *Location: ' | tail -1 | awk '{print $2}' | tr -d '\r')
        validate_url "$result" && { echo "$result"; return 0; }
    fi
    
    return 1
}

test_mirror_response() {
    local mirror_url="$1" timeout="${2:-$MIRROR_TEST_TIMEOUT}"
    
    validate_url "$mirror_url" || return 1
    
    # Try aria2c dry-run
    (( HAS_ARIA2C )) && aria2c --dry-run=true --timeout="$timeout" \
        --connect-timeout="$timeout" --max-tries=1 --console-log-level=error \
        "$mirror_url" &>/dev/null && return 0
    
    # Try wget spider
    (( HAS_WGET )) && wget --spider --timeout="$timeout" --tries=1 \
        --quiet "$mirror_url" 2>/dev/null && return 0
    
    # Try curl HEAD
    (( HAS_CURL )) && curl -I --max-time "$timeout" --retry 1 \
        --silent --fail "$mirror_url" &>/dev/null && return 0
    
    return 1
}

is_valid_mirror() {
    local url="$1"
    validate_url "$url" || return 1
    [[ "$url" != *"sourceforge.net/projects/shanios/files"* ]] || return 1
    [[ "$url" == *"${IMAGE_NAME}"* || "$url" =~ /download$ ]]
}

discover_mirrors() {
    local base_url="$1" MIRROR_FILE="${DOWNLOAD_DIR}/mirror.url"
    local -a discovered_mirrors=()
    local -A seen_domains=()
    
    validate_url "$base_url" || return 1
    
    log "Discovering mirrors for: $base_url"
    
    for ((i=0; i<MAX_MIRROR_DISCOVERIES; i++)); do
        local mirror_url domain
        mirror_url=$(get_effective_url "$base_url")
        
        if [[ -n "$mirror_url" ]] && is_valid_mirror "$mirror_url"; then
            domain=$(echo "$mirror_url" | sed -E 's|https?://([^/]+).*|\1|')
            [[ -n "$domain" ]] || continue
            
            [[ -z "${seen_domains[$domain]:-}" ]] && {
                seen_domains["$domain"]=1
                discovered_mirrors+=("$mirror_url")
                log "Discovered mirror: $domain"
            }
        fi
        
        [[ ${#discovered_mirrors[@]} -ge MIN_MIRRORS_NEEDED ]] && break
        sleep 0.5
    done
    
    if [[ ${#discovered_mirrors[@]} -eq 0 ]]; then
        log "No mirrors discovered, using direct URL"
        echo "$base_url" > "$MIRROR_FILE"
        return 0
    fi
    
    log "Testing ${#discovered_mirrors[@]} mirror(s)..."
    
    local selected_mirror=""
    for mirror in "${discovered_mirrors[@]}"; do
        if test_mirror_response "$mirror"; then
            selected_mirror="$mirror"
            log "Selected: $(echo "$mirror" | sed -E 's|https?://([^/]+).*|\1|')"
            break
        fi
    done
    
    [[ -z "$selected_mirror" ]] && selected_mirror="${discovered_mirrors[0]}"
    echo "$selected_mirror" > "$MIRROR_FILE"
}

#####################################
### Verification Functions        ###
#####################################

verify_sha256() {
    local file="$1" sha_file="$2"
    log "Verifying SHA256..."
    sha256sum -c "$sha_file" --status 2>/dev/null
}

verify_gpg() {
    local file="$1" sig_file="$2"
    local gpg_temp
    
    log "Verifying GPG signature..."
    gpg_temp=$(mktemp -d) || return 1
    
    (
        export GNUPGHOME="$gpg_temp"
        chmod 700 "$gpg_temp"
        
        log "Importing GPG key ${GPG_KEY_ID}..."
        for keyserver in keys.openpgp.org keyserver.ubuntu.com; do
            gpg --batch --quiet --keyserver "$keyserver" \
                --recv-keys "$GPG_KEY_ID" 2>/dev/null && break
        done || exit 1
        
        gpg --batch --verify "$sig_file" "$file" 2>/dev/null
    )
    local result=$?
    rm -rf "$gpg_temp"
    return $result
}

#####################################
### Preliminary Checks            ###
#####################################

check_root() {
    [[ $(id -u) -eq 0 ]] || die "Must be run as root (use sudo)"
}

check_internet() {
    ping -c1 -W2 8.8.8.8 &>/dev/null || die "No internet connection"
}

set_environment() {
    [[ -f /etc/shani-version ]] || die "Missing /etc/shani-version file"
    [[ -f /etc/shani-profile ]] || die "Missing /etc/shani-profile file"
    
    LOCAL_VERSION=$(< /etc/shani-version)
    LOCAL_PROFILE=$(< /etc/shani-profile)
    
    validate_nonempty "$LOCAL_VERSION" "LOCAL_VERSION"
    validate_nonempty "$LOCAL_PROFILE" "LOCAL_PROFILE"
}

#####################################
### Self-Update Section           ###
#####################################

ORIGINAL_ARGS=("$@")

self_update() {
    [[ -n "${SELF_UPDATE_DONE:-}" ]] && return 0
    
    export SELF_UPDATE_DONE=1
    persist_state

    local remote_url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
    local temp_script
    temp_script=$(mktemp)

    if download_file "$remote_url" "$temp_script"; then
        chmod +x "$temp_script"
        log "Self-update: Running updated script..."
        exec /bin/bash "$temp_script" "${ORIGINAL_ARGS[@]}"
    fi
    
    log "Warning: Unable to fetch remote script; continuing with local version."
    rm -f "$temp_script"
}

#####################################
### Systemd Inhibit Function      ###
#####################################

inhibit_system() {
    local inhibit_depth="${SYSTEMD_INHIBIT_DEPTH:-0}"
    
    (( inhibit_depth >= MAX_INHIBIT_DEPTH )) && {
        log "WARNING: Maximum inhibit depth reached, continuing without inhibit"
        return 0
    }
    
    [[ -z "${SYSTEMD_INHIBITED:-}" ]] || return 0
    
    export SYSTEMD_INHIBITED=1
    export SYSTEMD_INHIBIT_DEPTH=$((inhibit_depth + 1))
    log "Inhibiting all system interruptions during update..."
    exec systemd-inhibit \
        --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
        --who="shanios-deployment" \
        --why="Updating system" \
        "$0" "$@"
}

#####################################
### Cleanup Functions             ###
#####################################

cleanup_old_backups() {
    local slot backup backup_count exclude_backup="${1:-}"
    
    for slot in blue green; do
        log "Checking for old backups in slot '${slot}'..."
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" | \
            awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' | sort -r)
        
        backup_count=${#backups[@]}
        
        [[ $backup_count -eq 0 ]] && { log "No backups found for slot '${slot}'."; continue; }
        
        log "Found ${backup_count} backup(s) for slot '${slot}': ${backups[*]}"
        
        if (( backup_count > 2 )); then
            log "Keeping 2 most recent backups, deleting $((backup_count-2)) older backup(s)..."
            for (( i=2; i<backup_count; i++ )); do
                backup="${backups[i]}"
                [[ "$backup" =~ ^(blue|green)_backup_[0-9]{12}$ ]] || {
                    log "Skipping unexpected backup name: ${backup}"
                    continue
                }
                run_cmd btrfs subvolume delete "$MOUNT_DIR/@${backup}"
                log "Deleted old backup: @${backup}"
            done
        else
            log "Only ${backup_count} backup(s) exist; no cleanup needed."
        fi
    done
}

cleanup_downloads() {
    local files latest_file count
    files=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst*" -mtime +7 -printf "%T@ %p\n" 2>/dev/null | sort -n)
    count=$(echo "$files" | wc -l)
    
    (( count <= 1 )) && { log "No old downloads to clean up."; return 0; }
    
    latest_file=$(echo "$files" | tail -n 1 | cut -d' ' -f2-)
    echo "$files" | while read -r line; do
        local file
        file=$(echo "$line" | cut -d' ' -f2-)
        [[ "$file" != "$latest_file" ]] && {
            run_cmd rm -f "$file"
            log "Deleted old download: $file"
        }
    done
}

#####################################
### Chroot Environment            ###
#####################################

prepare_chroot_env() {
    local slot="$1"
    validate_nonempty "$slot" "slot parameter"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvol=@${slot}"
    
    mkdir -p "$MOUNT_DIR/boot/efi"
    if mountpoint -q /boot/efi; then
        log "EFI partition already mounted; binding /boot/efi..."
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
    local d dir
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
    validate_nonempty "$slot" "slot parameter"
    [[ -x "$GENEFI_SCRIPT" ]] || die "gen-efi script not found: $GENEFI_SCRIPT"
    
    prepare_chroot_env "$slot"
    log "Generating Secure Boot UKI for slot ${slot}..."
    
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
### Rollback Functions            ###
#####################################

restore_candidate() {
    log "Error encountered. Initiating candidate rollback..."
    {
        set +e
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
        
        if [[ -n "$BACKUP_NAME" ]] && btrfs_subvol_exists "$MOUNT_DIR/@${BACKUP_NAME}"; then
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
    
    log "Detected failing slot: ${failed_slot}. Rolling back to: ${previous_slot}."
    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" | \
        awk -v slot="${failed_slot}" '$0 ~ slot"_backup" {print $NF}' | sort | tail -n 1)
    
    [[ -n "$BACKUP_NAME" ]] || die "No backup found for slot ${failed_slot}"
    
    log "Restoring slot ${failed_slot} from backup ${BACKUP_NAME}..."
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro false
    run_cmd btrfs subvolume delete "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro true
    
    log "Updating active slot marker to: ${previous_slot}..."
    echo "$previous_slot" > "$MOUNT_DIR/@data/current-slot"
    safe_umount "$MOUNT_DIR"
    
    generate_uki_common "$previous_slot"
    log "Rollback complete. Rebooting system..."
    [[ "${DRY_RUN}" == "yes" ]] || reboot
}

#####################################
### Storage Optimization          ###
#####################################

optimize_storage() {
    log "Optimizing storage (deduplicating blue/green slots)..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    if ! btrfs_subvol_exists "$MOUNT_DIR/@blue" || ! btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        log "Skipping optimization: both slots not present"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    if ! command -v duperemove &>/dev/null; then
        log "WARNING: duperemove not installed (50-70% space savings possible)"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    local -a dedupe_targets=("$MOUNT_DIR/@blue" "$MOUNT_DIR/@green")
    
    while IFS= read -r backup; do
        [[ -n "$backup" ]] && dedupe_targets+=("$MOUNT_DIR/@${backup}")
    done < <(btrfs subvolume list "$MOUNT_DIR" | awk '/_backup_/ {print $NF}')
    
    [[ ${#dedupe_targets[@]} -gt 2 ]] && \
        log "Including ${#dedupe_targets[@]} subvolumes (with backups) in deduplication"
    
    local before after saved percent
    before=$(btrfs filesystem du -s "${dedupe_targets[@]}" 2>/dev/null | tail -1 | awk '{print $1}')
    
    log "Running Btrfs extent deduplication (may take several minutes)..."
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would run duperemove on ${#dedupe_targets[@]} subvolumes"
    else
        duperemove -Adhr \
            --skip-zeroes \
            --dedupe-options=same \
            --lookup-extents=yes \
            -b 128K \
            --threads=$(nproc) \
            --io-threads=$(nproc) \
            --hashfile="$MOUNT_DIR/@data/.dedupe.db" \
            --hashfile-threads=$(nproc) \
            "${dedupe_targets[@]}" > /dev/null
    fi
    
    after=$(btrfs filesystem du -s "${dedupe_targets[@]}" 2>/dev/null | tail -1 | awk '{print $1}')
    
    if [[ -n "$before" && -n "$after" ]] && (( before > after )); then
        saved=$((before - after))
        percent=$((saved * 100 / before))
        log "Storage reclaimed: $(numfmt --to=iec $saved) (${percent}% reduction)"
    else
        log "Storage already optimized"
    fi
    
    safe_umount "$MOUNT_DIR"
}

#####################################
### Subvolume Management          ###
#####################################

parse_fstab_subvolumes() {
    local fstab_file="$1"
    [[ -f "$fstab_file" ]] || { log "WARNING: Cannot read fstab"; return 1; }
    
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]] && continue
        
        if [[ "$line" =~ LABEL=shani_root.*subvol=@([a-zA-Z0-9_]+) ]]; then
            local subvol="${BASH_REMATCH[1]}"
            [[ "$subvol" != "blue" && "$subvol" != "green" ]] && echo "$subvol"
        fi
    done < "$fstab_file" | sort -u
}

create_swapfile() {
    local swapfile="$1" mem_mb="$2" available_mb="$3"
    
    if (( available_mb < mem_mb )); then
        log "WARNING: Insufficient space for hibernation swapfile"
        log "Available: ${available_mb}MB, Required: ${mem_mb}MB"
        log "Skipping swapfile creation. System will use zram for swap."
        return 1
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
            return 1
        fi
    fi
    return 0
}

verify_and_create_required_subvolumes() {
    log "Verifying required subvolumes for candidate slot..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    local candidate_fstab="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/fstab"
    [[ -f "$candidate_fstab" ]] || {
        log "WARNING: fstab not found in candidate slot"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    mapfile -t required_subvols < <(parse_fstab_subvolumes "$candidate_fstab")
    
    [[ ${#required_subvols[@]} -eq 0 ]] && {
        log "No additional subvolumes required"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    log "Candidate requires ${#required_subvols[@]} subvolume(s): ${required_subvols[*]}"
    
    local -a missing_subvols=()
    for subvol in "${required_subvols[@]}"; do
        btrfs_subvol_exists "$MOUNT_DIR/@${subvol}" || missing_subvols+=("$subvol")
    done
    
    [[ ${#missing_subvols[@]} -eq 0 ]] && {
        log "All required subvolumes exist"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    log "Creating ${#missing_subvols[@]} missing subvolume(s): ${missing_subvols[*]}"
    
    for subvol in "${missing_subvols[@]}"; do
        log "Creating @${subvol}..."
        run_cmd btrfs subvolume create "$MOUNT_DIR/@${subvol}"
        
        case "$subvol" in
            swap)
                log "Setting up @swap for hibernation..."
                [[ "${DRY_RUN}" == "yes" ]] && {
                    log "[Dry Run] Would disable CoW and create swapfile"
                    continue
                }
                
                chattr +C "$MOUNT_DIR/@${subvol}" 2>/dev/null && log "Disabled CoW on @swap" || \
                    log "WARNING: Failed to disable CoW on @swap"
                
                local swapfile="$MOUNT_DIR/@${subvol}/swapfile"
                [[ -f "$swapfile" ]] && continue
                
                local mem_mb available_mb
                mem_mb=$(free -m | awk '/^Mem:/{print $2}')
                available_mb=$(get_btrfs_available_mb "$MOUNT_DIR")
                
                [[ "$available_mb" -eq 0 ]] && {
                    log "WARNING: Could not determine space, skipping swapfile"
                    continue
                }
                
                create_swapfile "$swapfile" "$mem_mb" "$available_mb"
                ;;
                
            data)
                log "Creating overlay structure in @data..."
                [[ "${DRY_RUN}" == "yes" ]] && {
                    log "[Dry Run] Would create @data overlay structure"
                    continue
                }
                
                mkdir -p "$MOUNT_DIR/@data/overlay/"{etc,var}/{lower,upper,work}
                mkdir -p "$MOUNT_DIR/@data/downloads"
                
                [[ ! -f "$MOUNT_DIR/@data/current-slot" ]] && \
                    echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot"
                [[ ! -f "$MOUNT_DIR/@data/previous-slot" ]] && \
                    echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/previous-slot"
                ;;
        esac
    done
    
    log "All missing subvolumes created successfully"
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
        if btrfs_subvol_exists "$MOUNT_DIR/@${subvol}"; then
            local exclusive total
            exclusive=$(btrfs filesystem du -s "$MOUNT_DIR/@${subvol}" 2>/dev/null | awk 'NR==2 {print $1}')
            total=$(btrfs filesystem du -s "$MOUNT_DIR/@${subvol}" 2>/dev/null | awk 'NR==2 {print $2}')
            if [[ -n "$exclusive" && -n "$total" ]]; then
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
    if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        local combined blue_size green_size theoretical saved percent
        combined=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | tail -1 | awk '{print $1}')
        if [[ -n "$combined" ]]; then
            echo "   Blue + Green combined: $(numfmt --to=iec $combined 2>/dev/null || echo $combined)"
            
            blue_size=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" 2>/dev/null | awk 'NR==2 {print $2}')
            green_size=$(btrfs filesystem du -s "$MOUNT_DIR/@green" 2>/dev/null | awk 'NR==2 {print $2}')
            if [[ -n "$blue_size" && -n "$green_size" ]] && (( blue_size + green_size > 0 )); then
                theoretical=$((blue_size + green_size))
                saved=$((theoretical - combined))
                percent=$((saved * 100 / theoretical))
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
        local db_size
        db_size=$(stat -c%s "$MOUNT_DIR/@data/.dedupe.db" 2>/dev/null || echo 0)
        echo ""
        echo "5. Deduplication Database: $(numfmt --to=iec $db_size 2>/dev/null || echo $db_size)"
    fi
    
    echo "=============================="
    echo ""
    
    safe_umount "$MOUNT_DIR"
}

#####################################
### Deployment Functions          ###
#####################################

boot_validation_and_candidate_selection() {
    CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null || echo "blue")
    CURRENT_SLOT="${CURRENT_SLOT// /}"
    [[ -z "$CURRENT_SLOT" ]] && CURRENT_SLOT="blue"

    local booted
    booted=$(get_booted_subvol)
    [[ "$booted" == "$CURRENT_SLOT" ]] || \
        die "System booted from @$booted but expected @$CURRENT_SLOT. Reboot into correct slot first."

    CANDIDATE_SLOT=$([[ "$CURRENT_SLOT" == "blue" ]] && echo "green" || echo "blue")
    log "System booted from @$CURRENT_SLOT. Deploying to candidate slot @${CANDIDATE_SLOT}."
}

pre_update_checks() {
    local free_space_mb
    free_space_mb=$(df --output=avail "/data" | tail -n1)
    free_space_mb=$(( free_space_mb / 1024 ))
    (( free_space_mb >= MIN_FREE_SPACE_MB )) || \
        die "Not enough disk space: ${free_space_mb}MB available; ${MIN_FREE_SPACE_MB}MB required"
    log "Disk space sufficient: ${free_space_mb}MB available."
    run_cmd mkdir -p "$DOWNLOAD_DIR" "$ZSYNC_CACHE_DIR"
}

fetch_update_info() {
    local channel_url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    
    log "Checking for updates from ${channel_url}..."
    
    local temp_file
    temp_file=$(mktemp)
    
    if download_file "$channel_url" "$temp_file"; then
        IMAGE_NAME=$(tr -d '[:space:]' < "$temp_file")
        rm -f "$temp_file"
    else
        rm -f "$temp_file"
        die "Unable to fetch update info from ${channel_url}"
    fi
    
    log "Fetched update info: '${IMAGE_NAME}'"
    
    [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]] || \
        die "Invalid update format in ${UPDATE_CHANNEL}.txt: '${IMAGE_NAME}'"
    
    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"
    log "Remote update: version v${REMOTE_VERSION}, profile '${REMOTE_PROFILE}'"

    if [[ "$LOCAL_VERSION" == "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
        log "Local system up-to-date (v${REMOTE_VERSION}, ${REMOTE_PROFILE}). Verifying candidate slot..."
        
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"

        if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
            local CANDIDATE_RELEASE_FILE="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-version"
            local CANDIDATE_PROFILE_FILE="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-profile"

            if [[ -f "$CANDIDATE_RELEASE_FILE" && -f "$CANDIDATE_PROFILE_FILE" ]]; then
                local CANDIDATE_VERSION CANDIDATE_PROFILE
                CANDIDATE_VERSION=$(cat "$CANDIDATE_RELEASE_FILE")
                CANDIDATE_PROFILE=$(cat "$CANDIDATE_PROFILE_FILE")

                if [[ "$CANDIDATE_VERSION" == "$REMOTE_VERSION" && "$CANDIDATE_PROFILE" == "$REMOTE_PROFILE" ]]; then
                    log "Candidate slot up-to-date (${CANDIDATE_VERSION}, ${CANDIDATE_PROFILE}). Skipping deployment."
                    touch "${STATE_DIR}/skip-deployment"
                else
                    log "Candidate mismatch: ${CANDIDATE_VERSION} (${CANDIDATE_PROFILE}) vs ${REMOTE_VERSION} (${REMOTE_PROFILE}). Deploying."
                fi
            else
                log "Candidate missing version/profile. Deploying update."
            fi
        else
            log "No candidate subvolume '@${CANDIDATE_SLOT}' found. Exiting."
            safe_umount "$MOUNT_DIR"
            exit 0
        fi
        safe_umount "$MOUNT_DIR"
    else
        log "Local (${LOCAL_VERSION}, ${LOCAL_PROFILE}) differs from remote (${REMOTE_VERSION}, ${REMOTE_PROFILE}). Updating."
    fi
}

download_update() {
    log "Downloading ${IMAGE_NAME}..."
    
    local image="${DOWNLOAD_DIR}/${IMAGE_NAME}"
    local marker="${image}.verified"
    
    # Use cached if available
    [[ -f "$marker" ]] && file_nonempty "$image" && {
        log "Using cached verified image"
        return 0
    }
    
    [[ "${DRY_RUN}" == "yes" ]] && { log "[Dry Run] Would download and verify"; return 0; }
    
    local base_url="https://sourceforge.net/projects/shanios/files/${REMOTE_PROFILE}/${REMOTE_VERSION}"
    local mirror_file="${DOWNLOAD_DIR}/mirror.url"
    
    # Get mirror
    local mirror
    mirror=$(cat "$mirror_file" 2>/dev/null | head -1 | xargs) || {
        discover_mirrors "${base_url}/${IMAGE_NAME}/download"
        mirror=$(cat "$mirror_file" 2>/dev/null | head -1 | xargs)
    }
    
    validate_nonempty "$mirror" "mirror URL"
    
    # Download main file with retry
    download_with_retry "$mirror" "$image" || die "Download failed after retries"
    
    # Download verification files
    local sha="${image}.sha256"
    local asc="${image}.asc"
    
    download_file "${base_url}/${IMAGE_NAME}.sha256/download" "$sha" || die "Failed to fetch SHA256"
    download_file "${base_url}/${IMAGE_NAME}.asc/download" "$asc" || die "Failed to fetch signature"
    
    # Verify
    verify_sha256 "$image" "$sha" || die "SHA256 verification failed"
    verify_gpg "$image" "$asc" || die "GPG verification failed"
    
    touch "$marker"
    log "Download and verification completed"
}

deploy_btrfs_update() {
    log "Deploying update via Btrfs..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    mountpoint -q "$MOUNT_DIR/@${CANDIDATE_SLOT}" && {
        safe_umount "$MOUNT_DIR"
        die "Candidate slot @${CANDIDATE_SLOT} is mounted. Aborting."
    }
    
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        log "Backing up @${CANDIDATE_SLOT} as @${BACKUP_NAME}..."
        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}"
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    fi
    
    local temp_subvol="$MOUNT_DIR/temp_update"
    if btrfs_subvol_exists "$temp_subvol"; then
        log "Deleting existing temp_update..."
        [[ -d "$temp_subvol/shanios_base" ]] && run_cmd btrfs subvolume delete "$temp_subvol/shanios_base"
        run_cmd btrfs subvolume delete "$temp_subvol"
    fi
    
    run_cmd btrfs subvolume create "$temp_subvol"
    log "Extracting update image..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would extract ${IMAGE_NAME}"
    else
        zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | btrfs receive "$temp_subvol" || \
            die "Image extraction failed"
    fi
    
    log "Creating candidate snapshot..."
    run_cmd btrfs subvolume snapshot "$temp_subvol/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
    
    log "Cleaning up temporary subvolume..."
    [[ -d "$temp_subvol/shanios_base" ]] && run_cmd btrfs subvolume delete "$temp_subvol/shanios_base"
    run_cmd btrfs subvolume delete "$temp_subvol"
    safe_umount "$MOUNT_DIR"
    
    [[ "${DRY_RUN}" == "no" ]] && touch "$DEPLOY_PENDING"
}

finalize_update() {
    log "Finalizing deployment..."

    [[ "${DRY_RUN}" == "yes" ]] && {
        log "[Dry Run] Would finalize and switch to ${CANDIDATE_SLOT}"
        return 0
    }

    echo "$CURRENT_SLOT" > /data/previous-slot
    echo "$CANDIDATE_SLOT" > /data/current-slot

    verify_and_create_required_subvolumes || die "Failed to verify/create subvolumes"

    log "Generating Secure Boot UKI..."
    generate_uki_common "$CANDIDATE_SLOT"
    
    [[ -f "$DEPLOY_PENDING" ]] && rm -f "$DEPLOY_PENDING"

    log "Running post-deployment cleanup and optimization..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    cleanup_old_backups
    safe_umount "$MOUNT_DIR"

    echo "$IMAGE_NAME" > "$DOWNLOAD_DIR/old.txt"
    cleanup_downloads
    optimize_storage

    log "Deployment complete. Next boot: @${CANDIDATE_SLOT} (v${REMOTE_VERSION})"
}

#####################################
### Usage & Main                  ###
#####################################

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -h, --help             Show this help message
  -r, --rollback         Force full rollback
  -c, --cleanup          Run manual cleanup
  -s, --storage-info     Show storage analysis
  -t, --channel <chan>   Update channel: latest or stable (default: stable)
  -d, --dry-run          Simulate without making changes
EOF
}

# Parse arguments
args=$(getopt -o hrcst:d --long help,rollback,cleanup,storage-info,channel:,dry-run -n "$0" -- "$@") || {
    usage
    exit 1
}
eval set -- "$args"

while true; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -r|--rollback) touch "${STATE_DIR}/rollback"; shift ;;
        -c|--cleanup) touch "${STATE_DIR}/cleanup"; shift ;;
        -s|--storage-info) touch "${STATE_DIR}/storage-info"; shift ;;
        -t|--channel) echo "$2" > "${STATE_DIR}/channel"; shift 2 ;;
        -d|--dry-run) touch "${STATE_DIR}/dry-run"; shift ;;
        --) shift; break ;;
        *) echo "Invalid option: $1"; usage; exit 1 ;;
    esac
done

main() {
    check_root
    check_internet
    set_environment
    self_update "$@"
    inhibit_system "$@"
   
    DRY_RUN=$([[ -f "${STATE_DIR}/dry-run" ]] && echo "yes" || echo "no")
    UPDATE_CHANNEL=$(cat "${STATE_DIR}/channel" 2>/dev/null || echo "stable")

    # Handle special modes
    [[ -f "${STATE_DIR}/storage-info" ]] && { analyze_storage_usage; exit 0; }

    if [[ -f "${STATE_DIR}/cleanup" ]]; then
        log "Running manual cleanup..."
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" 2>/dev/null && {
            cleanup_old_backups
            safe_umount "$MOUNT_DIR"
        }
        cleanup_downloads
        [[ -f "/data/.dedupe.db" ]] && run_cmd rm -f "/data/.dedupe.db"
        exit 0
    fi

    [[ -f /data/boot-ok ]] || { log "Boot failure detected. Initiating rollback..."; rollback_system; }
    [[ -f "${STATE_DIR}/rollback" ]] && { rollback_system; exit 0; }

    boot_validation_and_candidate_selection
    pre_update_checks
    fetch_update_info
    
    if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
        log "System up-to-date. Running optimization check..."
        mkdir -p "$MOUNT_DIR"
        if safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" 2>/dev/null; then
            btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green" && {
                safe_umount "$MOUNT_DIR"
                optimize_storage
            } || safe_umount "$MOUNT_DIR"
        fi
    else
        log "Deployment required. Starting update..."
        download_update || die "Download failed"
        deploy_btrfs_update || die "Deployment failed"
    fi

    [[ -f "${DEPLOY_PENDING}" ]] && {
        log "Resuming finalization..."
        finalize_update || die "Finalization failed"
    }
}

main "$@"
