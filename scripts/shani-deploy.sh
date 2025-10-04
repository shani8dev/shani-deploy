#!/bin/bash
################################################################################
# shanios-deploy.sh - Optimized Blue/Green Btrfs Deployment Script
#
# Usage: ./shanios-deploy.sh [OPTIONS]
#
# Options:
#   -h, --help             Show this help message
#   -r, --rollback         Force full rollback
#   -c, --cleanup          Run manual cleanup
#   -s, --storage-info     Show storage analysis
#   -t, --channel <chan>   Update channel: latest or stable (default: stable)
#   -d, --dry-run          Simulate without making changes
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

readonly MIRROR_TEST_TIMEOUT=8
readonly MAX_INHIBIT_DEPTH=2

# Tool availability
declare -g HAS_ARIA2C=0 HAS_WGET=0 HAS_CURL=0
command -v aria2c &>/dev/null && HAS_ARIA2C=1
command -v wget &>/dev/null && HAS_WGET=1
command -v curl &>/dev/null && HAS_CURL=1

declare -g LOCAL_VERSION LOCAL_PROFILE
declare -g BACKUP_NAME="" CURRENT_SLOT="" CANDIDATE_SLOT=""
declare -g REMOTE_VERSION="" REMOTE_PROFILE="" IMAGE_NAME=""
declare -g UPDATE_CHANNEL="stable" DRY_RUN="no"

CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp /sys/firmware/efi/efivars)
CHROOT_STATIC_DIRS=(data etc var)

# Curated SourceForge mirrors (fast, reliable)
readonly -a SF_MIRRORS=(
    "https://master.dl.sourceforge.net"
    "https://netix.dl.sourceforge.net"
    "https://liquidtelecom.dl.sourceforge.net"
    "https://phoenixnap.dl.sourceforge.net"
    "https://gigenet.dl.sourceforge.net"
    "https://downloads.sourceforge.net"
)

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
        declare -p OS_NAME DOWNLOAD_DIR MOUNT_DIR ROOT_DEV GENEFI_SCRIPT 2>/dev/null || true
        declare -p LOCAL_VERSION LOCAL_PROFILE BACKUP_NAME CURRENT_SLOT CANDIDATE_SLOT 2>/dev/null || true
        declare -p REMOTE_VERSION REMOTE_PROFILE IMAGE_NAME STATE_DIR UPDATE_CHANNEL 2>/dev/null || true
        declare -p CHROOT_BIND_DIRS CHROOT_STATIC_DIRS 2>/dev/null || true
    } > "$state_file"
    export SHANIOS_DEPLOY_STATE_FILE="$state_file"
}

#####################################
### Logging & Helpers             ###
#####################################

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [DEPLOY] $*"; }
die() { echo "$(date '+%Y-%m-%d %H:%M:%S') [FATAL] $*" >&2; exit 1; }

run_cmd() {
    [[ "${DRY_RUN}" == "yes" ]] && { log "[Dry Run] $*"; return 0; }
    log "Executing: $*"
    "$@" || die "Command failed: $*"
}

validate_nonempty() { [[ -n "$1" ]] || die "$2 is empty"; }
validate_url() { [[ "$1" =~ ^https?://[a-zA-Z0-9.-]+(/.*)?$ ]]; }
file_nonempty() { [[ -f "$1" ]] && (( $(stat -c%s "$1" 2>/dev/null || echo 0) > 0 )); }

#####################################
### Mount Management              ###
#####################################

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    [[ -n "$src" && -n "$tgt" ]] || die "safe_mount: Invalid arguments"
    findmnt -M "$tgt" &>/dev/null || run_cmd mount -o "$opts" "$src" "$tgt"
}

safe_umount() {
    local tgt="$1"
    [[ -n "$tgt" ]] || return 1
    if findmnt -M "$tgt" &>/dev/null; then
        [[ "${DRY_RUN}" == "yes" ]] && { log "[Dry Run] Would unmount $tgt"; return 0; }
        umount -R "$tgt" 2>/dev/null || log "WARNING: Failed to unmount $tgt"
    fi
}

#####################################
### Btrfs Helpers                 ###
#####################################

get_booted_subvol() {
    local subvol
    subvol=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | sed 's/.*subvol=@//;s/,.*//' || echo "")
    [[ -z "$subvol" ]] && subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    echo "${subvol:-blue}"
}

btrfs_subvol_exists() { btrfs subvolume show "$1" &>/dev/null; }

get_btrfs_available_mb() {
    local bytes
    bytes=$(btrfs filesystem usage -b "$1" 2>/dev/null | awk '/Free \(estimated\):/ {gsub(/[^0-9]/,"",$3); print $3}')
    [[ -n "$bytes" && "$bytes" -gt 0 ]] && echo "$((bytes / 1024 / 1024))" || echo "0"
}

#####################################
### Download System               ###
#####################################

download_file() {
    local url="$1" output="$2" is_small="${3:-0}"
    
    validate_url "$url" || return 1
    mkdir -p "$(dirname "$output")"
    
    # For small text files, prefer wget/curl (aria2c has issues with redirects)
    if (( is_small )); then
        (( HAS_WGET )) && wget -q --timeout=20 --tries=2 -O "$output" "$url" 2>/dev/null && return 0
        (( HAS_CURL )) && curl -fsSL --max-time 20 --retry 1 -o "$output" "$url" 2>/dev/null && return 0
        return 1
    fi
    
    # For large files: aria2c (multi-connection) > wget (resume) > curl
    if (( HAS_ARIA2C )); then
        aria2c --console-log-level=error --timeout=30 --max-tries=3 \
            --max-connection-per-server=8 --split=8 --min-split-size=1M \
            --continue=true --allow-overwrite=true --auto-file-renaming=false \
            --dir="$(dirname "$output")" --out="$(basename "$output")" \
            "$url" 2>/dev/null && return 0
    fi
    
    if (( HAS_WGET )); then
        wget --timeout=30 --tries=3 --continue --progress=dot:giga \
            -O "$output" "$url" 2>&1 | grep -v "^$" && return 0
    fi
    
    if (( HAS_CURL )); then
        curl -fL --max-time 30 --retry 2 --continue-at - \
            -o "$output" "$url" 2>/dev/null && return 0
    fi
    
    return 1
}

download_with_retry() {
    local url="$1" output="$2" max_attempts="${3:-5}" is_small="${4:-0}"
    local attempt=0 delay=5 last_size=0
    
    while (( attempt < max_attempts )); do
        ((attempt++))
        
        local current_size=0
        [[ -f "$output" ]] && current_size=$(stat -c%s "$output" 2>/dev/null || echo 0)
        
        if (( current_size > 0 && current_size > last_size )); then
            log "Attempt ${attempt}/${max_attempts} (resuming from $(numfmt --to=iec $current_size 2>/dev/null || echo ${current_size}B))..."
        else
            log "Attempt ${attempt}/${max_attempts}..."
        fi
        
        if download_file "$url" "$output" "$is_small"; then
            file_nonempty "$output" && return 0
            log "Downloaded file is empty, retrying..."
            rm -f "$output"
        fi
        
        last_size=$current_size
        
        if (( attempt < max_attempts )); then
            local new_size=0
            [[ -f "$output" ]] && new_size=$(stat -c%s "$output" 2>/dev/null || echo 0)
            
            if (( new_size > last_size )); then
                log "Progress: +$(( (new_size - last_size) / 1024 / 1024 ))MB, retrying in ${delay}s..."
            else
                log "No progress, retrying in ${delay}s..."
                rm -f "$output"
            fi
            
            sleep "$delay"
            delay=$(( delay < 60 ? delay * 2 : 60 ))
        fi
    done
    
    return 1
}

#####################################
### Mirror Selection              ###
#####################################

test_mirror() {
    local url="$1"
    validate_url "$url" || return 1
    
    # Quick HTTP HEAD check
    if (( HAS_CURL )); then
        local code
        code=$(curl -I --max-time "$MIRROR_TEST_TIMEOUT" --retry 1 \
            -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
        [[ "$code" =~ ^(200|302)$ ]] && return 0
    fi
    
    if (( HAS_WGET )); then
        wget --spider --timeout="$MIRROR_TEST_TIMEOUT" --tries=1 \
            -q "$url" 2>/dev/null && return 0
    fi
    
    return 1
}

select_mirror() {
    local project="$1" filepath="$2" filename="$3"
    
    log "Selecting best mirror for: $filename"
    
    for mirror_base in "${SF_MIRRORS[@]}"; do
        local mirror_url="${mirror_base}/project/${project}/${filepath}/${filename}"
        local mirror_name
        mirror_name=$(echo "$mirror_url" | sed -E 's|https://([^/]+).*|\1|')
        
        log "Testing: $mirror_name"
        
        if test_mirror "$mirror_url"; then
            log "Selected: $mirror_name"
            echo "$mirror_url"
            return 0
        fi
    done
    
    # Fallback to direct URL
    log "No fast mirror found, using direct download"
    echo "https://sourceforge.net/projects/${project}/files/${filepath}/${filename}/download"
}

#####################################
### Verification                  ###
#####################################

verify_sha256() {
    log "Verifying SHA256..."
    sha256sum -c "$2" --status 2>/dev/null
}

verify_gpg() {
    local file="$1" sig="$2"
    log "Verifying GPG signature..."
    
    local gpg_temp
    gpg_temp=$(mktemp -d) || return 1
    
    (
        export GNUPGHOME="$gpg_temp"
        chmod 700 "$gpg_temp"
        
        for keyserver in keys.openpgp.org keyserver.ubuntu.com; do
            gpg --batch --quiet --keyserver "$keyserver" --recv-keys "$GPG_KEY_ID" 2>/dev/null && break
        done || exit 1
        
        gpg --batch --verify "$sig" "$file" 2>/dev/null
    )
    local result=$?
    rm -rf "$gpg_temp"
    return $result
}

#####################################
### System Checks                 ###
#####################################

check_root() { [[ $(id -u) -eq 0 ]] || die "Must run as root"; }
check_internet() { ping -c1 -W2 8.8.8.8 &>/dev/null || die "No internet connection"; }

set_environment() {
    [[ -f /etc/shani-version && -f /etc/shani-profile ]] || die "Missing version/profile files"
    LOCAL_VERSION=$(< /etc/shani-version)
    LOCAL_PROFILE=$(< /etc/shani-profile)
    validate_nonempty "$LOCAL_VERSION" "LOCAL_VERSION"
    validate_nonempty "$LOCAL_PROFILE" "LOCAL_PROFILE"
}

#####################################
### Self-Update                   ###
#####################################

ORIGINAL_ARGS=("$@")

self_update() {
    [[ -n "${SELF_UPDATE_DONE:-}" ]] && return 0
    export SELF_UPDATE_DONE=1
    persist_state

    local url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
    local temp
    temp=$(mktemp)

    if download_file "$url" "$temp" 1; then
        chmod +x "$temp"
        log "Running updated script..."
        exec /bin/bash "$temp" "${ORIGINAL_ARGS[@]}"
    fi
    
    log "Self-update unavailable, continuing..."
    rm -f "$temp"
}

#####################################
### System Inhibit                ###
#####################################

inhibit_system() {
    local depth="${SYSTEMD_INHIBIT_DEPTH:-0}"
    (( depth >= MAX_INHIBIT_DEPTH )) && { log "Max inhibit depth reached"; return 0; }
    [[ -n "${SYSTEMD_INHIBITED:-}" ]] && return 0
    
    export SYSTEMD_INHIBITED=1
    export SYSTEMD_INHIBIT_DEPTH=$((depth + 1))
    log "Inhibiting system interruptions..."
    exec systemd-inhibit \
        --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
        --who="shanios-deployment" --why="System update in progress" \
        "$0" "$@"
}

#####################################
### Cleanup Functions             ###
#####################################

cleanup_old_backups() {
    for slot in blue green; do
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" | \
            awk -v s="${slot}" '$0 ~ s"_backup_" {print $NF}' | sort -r)
        
        (( ${#backups[@]} <= 2 )) && continue
        
        log "Cleaning ${slot}: keeping 2 of ${#backups[@]} backups"
        for (( i=2; i<${#backups[@]}; i++ )); do
            [[ "${backups[i]}" =~ ^(blue|green)_backup_[0-9]{12}$ ]] || continue
            run_cmd btrfs subvolume delete "$MOUNT_DIR/@${backups[i]}"
        done
    done
}

cleanup_downloads() {
    find "$DOWNLOAD_DIR" -maxdepth 1 -name "shanios-*.zst*" -mtime +7 -type f | \
    sort -r | tail -n +2 | while read -r f; do
        run_cmd rm -f "$f"
        log "Deleted old download: $(basename "$f")"
    done
}

#####################################
### Chroot Environment            ###
#####################################

prepare_chroot_env() {
    local slot="$1"
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvol=@${slot}"
    
    mkdir -p "$MOUNT_DIR/boot/efi"
    if mountpoint -q /boot/efi; then
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
    for d in "${CHROOT_BIND_DIRS[@]}"; do safe_umount "$MOUNT_DIR$d"; done
    for d in "${CHROOT_STATIC_DIRS[@]}"; do safe_umount "$MOUNT_DIR/$d"; done
    safe_umount "$MOUNT_DIR/boot/efi"
    safe_umount "$MOUNT_DIR"
}

generate_uki_common() {
    local slot="$1"
    [[ -x "$GENEFI_SCRIPT" ]] || die "gen-efi script missing"
    
    prepare_chroot_env "$slot"
    log "Generating UKI for ${slot}..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would generate UKI"
    else
        chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$slot" || {
            cleanup_chroot_env
            die "UKI generation failed"
        }
    fi
    
    cleanup_chroot_env
}

#####################################
### Rollback                      ###
#####################################

restore_candidate() {
    log "Error: Rolling back candidate..."
    set +e
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    if [[ -n "$BACKUP_NAME" ]] && btrfs_subvol_exists "$MOUNT_DIR/@${BACKUP_NAME}"; then
        btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false &>/dev/null
        btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" &>/dev/null
        btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
        btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
    fi
    
    [[ -d "$MOUNT_DIR/temp_update" ]] && btrfs subvolume delete "$MOUNT_DIR/temp_update" &>/dev/null
    safe_umount "$MOUNT_DIR"
    exit 1
}
trap 'restore_candidate' ERR

rollback_system() {
    log "Full system rollback..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    local failed_slot previous_slot
    failed_slot=$(cat "$MOUNT_DIR/@data/current-slot" 2>/dev/null | tr -d ' ' || get_booted_subvol)
    previous_slot=$(cat "$MOUNT_DIR/@data/previous-slot" 2>/dev/null | tr -d ' ' || \
        { [[ "$failed_slot" == "blue" ]] && echo "green" || echo "blue"; })
    
    log "Rolling back ${failed_slot} → ${previous_slot}"
    
    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" | \
        awk -v s="${failed_slot}" '$0 ~ s"_backup" {print $NF}' | sort | tail -1)
    [[ -n "$BACKUP_NAME" ]] || die "No backup found"
    
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro false
    run_cmd btrfs subvolume delete "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro true
    
    echo "$previous_slot" > "$MOUNT_DIR/@data/current-slot"
    safe_umount "$MOUNT_DIR"
    
    generate_uki_common "$previous_slot"
    log "Rollback complete. Rebooting..."
    [[ "${DRY_RUN}" == "yes" ]] || reboot
}

#####################################
### Storage Optimization          ###
#####################################

optimize_storage() {
    log "Optimizing storage..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    if ! btrfs_subvol_exists "$MOUNT_DIR/@blue" || ! btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    command -v duperemove &>/dev/null || {
        log "Install duperemove for 50-70% space savings"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    local -a targets=("$MOUNT_DIR/@blue" "$MOUNT_DIR/@green")
    while IFS= read -r b; do
        [[ -n "$b" ]] && targets+=("$MOUNT_DIR/@${b}")
    done < <(btrfs subvolume list "$MOUNT_DIR" | awk '/_backup_/ {print $NF}')
    
    log "Deduplicating ${#targets[@]} subvolumes..."
    [[ "${DRY_RUN}" == "yes" ]] && { log "[Dry Run] Would dedupe"; safe_umount "$MOUNT_DIR"; return 0; }
    
    duperemove -Adhr --skip-zeroes --dedupe-options=same --lookup-extents=yes \
        -b 128K --threads=$(nproc) --io-threads=$(nproc) \
        --hashfile="$MOUNT_DIR/@data/.dedupe.db" --hashfile-threads=$(nproc) \
        "${targets[@]}" &>/dev/null || true
    
    safe_umount "$MOUNT_DIR"
}

#####################################
### Subvolume Management          ###
#####################################

parse_fstab_subvolumes() {
    [[ -f "$1" ]] || return 1
    awk '/LABEL=shani_root.*subvol=@/ && !/^[[:space:]]*#/ {
        match($0, /subvol=@([a-zA-Z0-9_]+)/, a); 
        if (a[1] != "blue" && a[1] != "green") print a[1]
    }' "$1" | sort -u
}

create_swapfile() {
    local file="$1" size_mb="$2" avail_mb="$3"
    
    (( avail_mb < size_mb )) && {
        log "Insufficient space for ${size_mb}MB swapfile (${avail_mb}MB available)"
        return 1
    }
    
    if btrfs filesystem mkswapfile --size "${size_mb}M" "$file" 2>/dev/null; then
        chmod 600 "$file"
        return 0
    fi
    
    # Fallback
    dd if=/dev/zero of="$file" bs=1M count="$size_mb" status=none && \
        chmod 600 "$file" && mkswap "$file" &>/dev/null
}

verify_and_create_required_subvolumes() {
    log "Verifying required subvolumes..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    local fstab="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/fstab"
    [[ -f "$fstab" ]] || { safe_umount "$MOUNT_DIR"; return 0; }
    
    mapfile -t required < <(parse_fstab_subvolumes "$fstab")
    [[ ${#required[@]} -eq 0 ]] && { safe_umount "$MOUNT_DIR"; return 0; }
    
    local -a missing=()
    for sub in "${required[@]}"; do
        btrfs_subvol_exists "$MOUNT_DIR/@${sub}" || missing+=("$sub")
    done
    
    [[ ${#missing[@]} -eq 0 ]] && { safe_umount "$MOUNT_DIR"; return 0; }
    
    log "Creating ${#missing[@]} subvolume(s): ${missing[*]}"
    
    for sub in "${missing[@]}"; do
        run_cmd btrfs subvolume create "$MOUNT_DIR/@${sub}"
        
        case "$sub" in
            swap)
                [[ "${DRY_RUN}" == "yes" ]] && continue
                chattr +C "$MOUNT_DIR/@${sub}" 2>/dev/null
                local mem avail
                mem=$(free -m | awk '/^Mem:/{print $2}')
                avail=$(get_btrfs_available_mb "$MOUNT_DIR")
                create_swapfile "$MOUNT_DIR/@${sub}/swapfile" "$mem" "$avail" || true
                ;;
            data)
                [[ "${DRY_RUN}" == "yes" ]] && continue
                mkdir -p "$MOUNT_DIR/@data/overlay/"{etc,var}/{lower,upper,work}
                mkdir -p "$MOUNT_DIR/@data/downloads"
                [[ -f "$MOUNT_DIR/@data/current-slot" ]] || echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot"
                [[ -f "$MOUNT_DIR/@data/previous-slot" ]] || echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/previous-slot"
                ;;
        esac
    done
    
    safe_umount "$MOUNT_DIR"
}

analyze_storage_usage() {
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    echo -e "\n=== Btrfs Storage Analysis ===\n"
    echo "Filesystem:"
    btrfs filesystem df "$MOUNT_DIR" | sed 's/^/  /'
    
    echo -e "\nSubvolumes:"
    for s in blue green data; do
        if btrfs_subvol_exists "$MOUNT_DIR/@${s}"; then
            local info
            info=$(btrfs filesystem du -s "$MOUNT_DIR/@${s}" 2>/dev/null | awk 'NR==2')
            echo "  @${s}: $info"
        fi
    done
    
    if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        echo -e "\nShared data:"
        local combined
        combined=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | tail -1)
        echo "  $combined"
    fi
    
    echo -e "==============================\n"
    safe_umount "$MOUNT_DIR"
}

#####################################
### Deployment                    ###
#####################################

boot_validation_and_candidate_selection() {
    CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null | tr -d ' ')
    [[ -z "$CURRENT_SLOT" ]] && CURRENT_SLOT="blue"
    
    local booted
    booted=$(get_booted_subvol)
    [[ "$booted" == "$CURRENT_SLOT" ]] || die "Booted from @$booted, expected @$CURRENT_SLOT"
    
    CANDIDATE_SLOT=$([[ "$CURRENT_SLOT" == "blue" ]] && echo "green" || echo "blue")
    log "Current: @$CURRENT_SLOT, Candidate: @${CANDIDATE_SLOT}"
}

pre_update_checks() {
    local free_mb
    free_mb=$(df --output=avail "/data" | tail -1)
    free_mb=$(( free_mb / 1024 ))
    (( free_mb >= MIN_FREE_SPACE_MB )) || die "Insufficient space: ${free_mb}MB < ${MIN_FREE_SPACE_MB}MB"
    log "Available space: ${free_mb}MB"
    run_cmd mkdir -p "$DOWNLOAD_DIR" "$ZSYNC_CACHE_DIR"
}

fetch_update_info() {
    local url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    
    log "Checking for updates..."
    local temp
    temp=$(mktemp)
    
    if download_file "$url" "$temp" 1; then
        IMAGE_NAME=$(tr -d '[:space:]' < "$temp")
        rm -f "$temp"
    else
        rm -f "$temp"
        die "Failed to fetch update info"
    fi
    
    [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]] || \
        die "Invalid image format: $IMAGE_NAME"
    
    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"
    log "Remote: v${REMOTE_VERSION} (${REMOTE_PROFILE})"
    
    if [[ "$LOCAL_VERSION" == "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
        log "System up-to-date, checking candidate..."
        
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
        
        if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
            local cand_ver cand_prof
            cand_ver=$(cat "$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-version" 2>/dev/null || echo "")
            cand_prof=$(cat "$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-profile" 2>/dev/null || echo "")
            
            if [[ "$cand_ver" == "$REMOTE_VERSION" && "$cand_prof" == "$REMOTE_PROFILE" ]]; then
                log "Candidate up-to-date, skipping deployment"
                touch "${STATE_DIR}/skip-deployment"
            else
                log "Candidate outdated: $cand_ver ($cand_prof), will update"
            fi
        fi
        
        safe_umount "$MOUNT_DIR"
    fi
}

download_update() {
    log "Downloading ${IMAGE_NAME}..."
    
    local image="${DOWNLOAD_DIR}/${IMAGE_NAME}"
    local marker="${image}.verified"
    
    # Use cached if verified
    [[ -f "$marker" ]] && file_nonempty "$image" && {
        log "Using cached verified image"
        return 0
    }
    
    [[ "${DRY_RUN}" == "yes" ]] && { log "[Dry Run] Would download"; return 0; }
    
    # Select mirror
    local mirror
    mirror=$(select_mirror "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
    
    log "Downloading from: $(echo "$mirror" | sed -E 's|https://([^/]+).*|\1|')"
    
    # Download main file
    download_with_retry "$mirror" "$image" 5 0 || die "Download failed"
    
    # Download verification files
    local base_url="https://sourceforge.net/projects/shanios/files/${REMOTE_PROFILE}/${REMOTE_VERSION}"
    local sha="${image}.sha256"
    local asc="${image}.asc"
    
    download_file "${base_url}/${IMAGE_NAME}.sha256/download" "$sha" 1 || die "SHA256 download failed"
    download_file "${base_url}/${IMAGE_NAME}.asc/download" "$asc" 1 || die "Signature download failed"
    
    # Verify
    verify_sha256 "$image" "$sha" || die "SHA256 verification failed"
    verify_gpg "$image" "$asc" || die "GPG verification failed"
    
    touch "$marker"
    log "Download verified successfully"
}

deploy_btrfs_update() {
    log "Deploying update..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    mountpoint -q "$MOUNT_DIR/@${CANDIDATE_SLOT}" && {
        safe_umount "$MOUNT_DIR"
        die "Candidate slot mounted, aborting"
    }
    
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        log "Backing up to @${BACKUP_NAME}..."
        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}"
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    fi
    
    local temp="$MOUNT_DIR/temp_update"
    if btrfs_subvol_exists "$temp"; then
        [[ -d "$temp/shanios_base" ]] && run_cmd btrfs subvolume delete "$temp/shanios_base"
        run_cmd btrfs subvolume delete "$temp"
    fi
    
    run_cmd btrfs subvolume create "$temp"
    log "Extracting image..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[Dry Run] Would extract image"
    else
        zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | btrfs receive "$temp" || \
            die "Extraction failed"
    fi
    
    log "Creating snapshot..."
    run_cmd btrfs subvolume snapshot "$temp/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
    
    log "Cleaning up..."
    [[ -d "$temp/shanios_base" ]] && run_cmd btrfs subvolume delete "$temp/shanios_base"
    run_cmd btrfs subvolume delete "$temp"
    safe_umount "$MOUNT_DIR"
    
    [[ "${DRY_RUN}" == "no" ]] && touch "$DEPLOY_PENDING"
}

finalize_update() {
    log "Finalizing..."
    [[ "${DRY_RUN}" == "yes" ]] && { log "[Dry Run] Would finalize"; return 0; }
    
    echo "$CURRENT_SLOT" > /data/previous-slot
    echo "$CANDIDATE_SLOT" > /data/current-slot
    
    verify_and_create_required_subvolumes || die "Subvolume setup failed"
    
    generate_uki_common "$CANDIDATE_SLOT"
    
    [[ -f "$DEPLOY_PENDING" ]] && rm -f "$DEPLOY_PENDING"
    
    log "Post-deployment cleanup..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    cleanup_old_backups
    safe_umount "$MOUNT_DIR"
    
    echo "$IMAGE_NAME" > "$DOWNLOAD_DIR/old.txt"
    cleanup_downloads
    optimize_storage
    
    log "Deployment complete! Next boot: @${CANDIDATE_SLOT} v${REMOTE_VERSION}"
}

#####################################
### Main                          ###
#####################################

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -h, --help           Show help
  -r, --rollback       Force rollback
  -c, --cleanup        Manual cleanup
  -s, --storage-info   Storage analysis
  -t, --channel <ch>   Channel: latest|stable (default: stable)
  -d, --dry-run        Simulate only
EOF
}

# Parse args
args=$(getopt -o hrcst:d --long help,rollback,cleanup,storage-info,channel:,dry-run -n "$0" -- "$@") || {
    usage; exit 1
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
        *) die "Invalid option: $1" ;;
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
    
    # Special modes
    [[ -f "${STATE_DIR}/storage-info" ]] && { analyze_storage_usage; exit 0; }
    
    if [[ -f "${STATE_DIR}/cleanup" ]]; then
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" && {
            cleanup_old_backups
            safe_umount "$MOUNT_DIR"
        }
        cleanup_downloads
        [[ -f "/data/.dedupe.db" ]] && run_cmd rm -f "/data/.dedupe.db"
        exit 0
    fi
    
    [[ -f /data/boot-ok ]] || { log "Boot failure detected"; rollback_system; }
    [[ -f "${STATE_DIR}/rollback" ]] && { rollback_system; exit 0; }
    
    boot_validation_and_candidate_selection
    pre_update_checks
    fetch_update_info
    
    if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
        log "System current, optimizing..."
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" && {
            btrfs_subvol_exists "$MOUNT_DIR/@blue" && \
            btrfs_subvol_exists "$MOUNT_DIR/@green" && {
                safe_umount "$MOUNT_DIR"
                optimize_storage
            } || safe_umount "$MOUNT_DIR"
        }
    else
        download_update || die "Download failed"
        deploy_btrfs_update || die "Deployment failed"
    fi
    
    [[ -f "${DEPLOY_PENDING}" ]] && finalize_update
}

main "$@"
