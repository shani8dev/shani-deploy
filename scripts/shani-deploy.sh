#!/bin/bash
################################################################################
# shanios-deploy.sh - Production Blue/Green Btrfs Deployment System
#
# Optimized for reliability, performance, and maintainability
#
# Usage: ./shanios-deploy.sh [OPTIONS]
#
# Options:
#   -h, --help              Show help
#   -r, --rollback          Force system rollback
#   -c, --cleanup           Manual cleanup (backups, downloads)
#   -s, --storage-info      Display storage analysis
#   -t, --channel <chan>    Update channel: latest|stable (default: stable)
#   -d, --dry-run           Simulate without changes
#   -v, --verbose           Detailed output
#   --skip-self-update      Skip script auto-update
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
readonly LOG_FILE="/var/log/shanios-deploy.log"

readonly MIRROR_TEST_TIMEOUT=8
readonly MIRROR_CACHE_TTL=3600
readonly MAX_INHIBIT_DEPTH=2
readonly MAX_DOWNLOAD_ATTEMPTS=5
readonly EXTRACTION_TIMEOUT=1800
readonly STALL_THRESHOLD=3
readonly MIN_DOWNLOAD_SIZE=104857600

# Tool availability
declare -g HAS_ARIA2C=0 HAS_WGET=0 HAS_CURL=0 HAS_PV=0
command -v aria2c &>/dev/null && HAS_ARIA2C=1
command -v wget &>/dev/null && HAS_WGET=1
command -v curl &>/dev/null && HAS_CURL=1
command -v pv &>/dev/null && HAS_PV=1

declare -g LOCAL_VERSION LOCAL_PROFILE
declare -g BACKUP_NAME="" CURRENT_SLOT="" CANDIDATE_SLOT=""
declare -g REMOTE_VERSION="" REMOTE_PROFILE="" IMAGE_NAME=""
declare -g UPDATE_CHANNEL="stable" DRY_RUN="no" VERBOSE="no"
declare -g DEPLOYMENT_START_TIME="" SKIP_SELF_UPDATE="no"

readonly CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp)
readonly CHROOT_STATIC_DIRS=(data etc var)

readonly -a SF_MIRRORS=(
    "https://master.dl.sourceforge.net"
    "https://downloads.sourceforge.net"
    "https://netix.dl.sourceforge.net"
    "https://phoenixnap.dl.sourceforge.net"
    "https://liquidtelecom.dl.sourceforge.net"
    "https://gigenet.dl.sourceforge.net"
)

readonly E_SUCCESS=0
readonly E_GENERAL=1
readonly E_NETWORK=2
readonly E_DOWNLOAD=3
readonly E_VERIFY=4
readonly E_DEPLOY=5

#####################################
### State & Lock Management       ###
#####################################

STATE_DIR=$(mktemp -d /tmp/shanios-deploy-state.XXXXXX)
export STATE_DIR

cleanup_state() {
    [[ -n "${STATE_DIR:-}" && -d "${STATE_DIR}" ]] && rm -rf "${STATE_DIR}"
}
trap cleanup_state EXIT

persist_state() {
    local state_file
    state_file=$(mktemp /tmp/shanios_deploy_state.XXXX)
    {
        declare -p OS_NAME DOWNLOAD_DIR MOUNT_DIR ROOT_DEV GENEFI_SCRIPT 2>/dev/null || true
        declare -p LOCAL_VERSION LOCAL_PROFILE BACKUP_NAME CURRENT_SLOT CANDIDATE_SLOT 2>/dev/null || true
        declare -p REMOTE_VERSION REMOTE_PROFILE IMAGE_NAME UPDATE_CHANNEL 2>/dev/null || true
        declare -p VERBOSE DRY_RUN SKIP_SELF_UPDATE DEPLOYMENT_START_TIME 2>/dev/null || true
        declare -p STATE_DIR LOG_FILE DEPLOY_PENDING GPG_KEY_ID 2>/dev/null || true
        declare -p CHROOT_BIND_DIRS CHROOT_STATIC_DIRS HAS_ARIA2C HAS_WGET HAS_CURL HAS_PV 2>/dev/null || true
    } > "$state_file"
    export SHANIOS_DEPLOY_STATE_FILE="$state_file"
}

#####################################
### Logging System                ###
#####################################

log() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_verbose() {
    [[ "${VERBOSE}" == "yes" ]] || return 0
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $*"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $*"
    echo -e "\033[0;32m${msg}\033[0m"
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_warn() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $*"
    echo -e "\033[0;33m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_error() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*"
    echo -e "\033[0;31m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

die() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [FATAL] $*"
    echo -e "\033[1;31m${msg}\033[0m" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    exit 1
}

log_section() {
    local line="=========================================="
    echo ""
    echo "$line"
    echo "  $1"
    echo "$line"
    {
        echo ""
        echo "$line"
        echo "  $1"
        echo "$line"
    } >> "$LOG_FILE" 2>/dev/null || true
}

#####################################
### Helper Functions              ###
#####################################

run_cmd() {
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] $*"
        return 0
    fi
    log_verbose "Executing: $*"
    "$@" || { log_error "Command failed: $*"; return 1; }
}

validate_nonempty() {
    [[ -n "$1" ]] || die "$2 is empty"
}

validate_url() {
    local url="$1"
    [[ -n "$url" ]] || return 1
    [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(/.*)?$ ]]
}

is_valid_mirror() {
    local url="$1"
    validate_url "$url" || return 1
    # Exclude SourceForge project URLs (we want actual CDN mirrors)
    [[ "$url" != *"sourceforge.net/projects/shanios/files"* ]] || return 1
    # URL should contain the image filename or end with /download
    [[ "$url" == *"${IMAGE_NAME}"* || "$url" =~ /download$ ]]
}

file_nonempty() {
    [[ -f "$1" ]] && (( $(stat -c%s "$1" 2>/dev/null || echo 0) > 0 ))
}

format_bytes() {
    numfmt --to=iec "$1" 2>/dev/null || echo "${1}B"
}

#####################################
### Mount Management              ###
#####################################

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    [[ -n "$src" && -n "$tgt" ]] || die "safe_mount: Invalid arguments"
    
    findmnt -M "$tgt" &>/dev/null && return 0
    
    log_verbose "Mounting: $src -> $tgt"
    run_cmd mount -o "$opts" "$src" "$tgt" || die "Failed to mount $tgt"
}

safe_umount() {
    local tgt="$1"
    [[ -n "$tgt" ]] || return 1
    
    findmnt -M "$tgt" &>/dev/null || return 0
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] Would unmount: $tgt"
        return 0
    fi
    
    umount -R "$tgt" 2>/dev/null || {
        log_warn "Failed to unmount: $tgt"
        return 1
    }
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

btrfs_subvol_exists() {
    btrfs subvolume show "$1" &>/dev/null
}

get_btrfs_available_mb() {
    local bytes
    bytes=$(btrfs filesystem usage -b "$1" 2>/dev/null | awk '/Free \(estimated\):/ {gsub(/[^0-9]/,"",$3); print $3}')
    [[ -n "$bytes" && "$bytes" -gt 0 ]] && echo "$((bytes / 1024 / 1024))" || echo "0"
}

#####################################
### Mirror Selection & Discovery  ###
#####################################

test_mirror() {
    local url="$1"
    validate_url "$url" || return 1
    
    if (( HAS_CURL )); then
        local code
        code=$(curl -I --max-time "$MIRROR_TEST_TIMEOUT" -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
        [[ "$code" =~ ^(200|302)$ ]] && return 0
    fi
    
    (( HAS_WGET )) && wget --spider --timeout="$MIRROR_TEST_TIMEOUT" --tries=1 -q "$url" 2>/dev/null && return 0
    
    return 1
}

discover_mirror_from_redirect() {
    local base_url="$1"
    
    validate_url "$base_url" || return 1
    
    log_verbose "Discovering mirror via redirect..."
    
    if (( HAS_CURL )); then
        local effective_url
        effective_url=$(curl -sL -w '%{url_effective}' -o /dev/null --max-time 10 --max-redirs 5 "$base_url" 2>/dev/null)
        
        if [[ -n "$effective_url" ]] && validate_url "$effective_url" && [[ "$effective_url" != "$base_url" ]]; then
            # Verify discovered mirror is not a SourceForge project URL
            if [[ "$effective_url" != *"/projects/shanios/files"* ]]; then
                log_verbose "Discovered: $(echo "$effective_url" | sed -E 's|https://([^/]+).*|\1|')"
                echo "$effective_url"
                return 0
            fi
        fi
    fi
    
    if (( HAS_WGET )); then
        local effective_url
        effective_url=$(wget --max-redirect=5 --spider -S --timeout=10 --tries=1 "$base_url" 2>&1 | \
            grep -i '^ *Location: ' | tail -1 | awk '{print $2}' | tr -d '\r')
        
        if [[ -n "$effective_url" ]] && validate_url "$effective_url" && [[ "$effective_url" != "$base_url" ]]; then
            if [[ "$effective_url" != *"/projects/shanios/files"* ]]; then
                log_verbose "Discovered: $(echo "$effective_url" | sed -E 's|https://([^/]+).*|\1|')"
                echo "$effective_url"
                return 0
            fi
        fi
    fi
    
    return 1
}

select_mirror() {
    local project="$1" filepath="$2" filename="$3"
    
    validate_nonempty "$project" "project name"
    validate_nonempty "$filepath" "file path"
    validate_nonempty "$filename" "filename"
    
    # Check cache first
    local cache_file="$DOWNLOAD_DIR/.mirror_cache"
    if [[ -f "$cache_file" ]]; then
        local cached_mirror cached_time
        if read -r cached_mirror cached_time < "$cache_file" 2>/dev/null; then
            if (( $(date +%s) - cached_time < MIRROR_CACHE_TTL )); then
                if test_mirror "$cached_mirror"; then
                    log_verbose "Using cached mirror"
                    echo "$cached_mirror"
                    return 0
                fi
            fi
        fi
        rm -f "$cache_file"
    fi
    
    # Test static mirrors first (fast, predictable)
    local tested=0 max_tests=3
    
    for mirror_base in "${SF_MIRRORS[@]}"; do
        ((tested++))
        (( tested > max_tests )) && break
        
        local mirror_url="${mirror_base}/project/${project}/${filepath}/${filename}"
        
        log_verbose "Testing mirror: $(echo "$mirror_url" | sed -E 's|https://([^/]+).*|\1|')"
        
        if test_mirror "$mirror_url"; then
            log_success "Selected mirror: $(echo "$mirror_url" | sed -E 's|https://([^/]+).*|\1|')"
            echo "$mirror_url $(date +%s)" > "$cache_file"
            echo "$mirror_url"
            return 0
        fi
    done
    
    # Fallback: Use SourceForge's dynamic redirect
    log_warn "Static mirrors unresponsive, trying dynamic discovery"
    local sf_url="https://sourceforge.net/projects/${project}/files/${filepath}/${filename}/download"
    
    local discovered
    if discovered=$(discover_mirror_from_redirect "$sf_url"); then
        log_success "Dynamic mirror: $(echo "$discovered" | sed -E 's|https://([^/]+).*|\1|')"
        echo "$discovered $(date +%s)" > "$cache_file"
        echo "$discovered"
        return 0
    fi
    
    # Final fallback: direct URL (SourceForge will redirect)
    log_warn "Dynamic discovery failed, using direct URL"
    echo "$sf_url"
}

#####################################
### Download System               ###
#####################################

validate_download() {
    local file="$1" expected_min_size="${2:-$MIN_DOWNLOAD_SIZE}"
    
    [[ -f "$file" ]] || { log_error "File does not exist: $file"; return 1; }
    
    local size
    size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    
    if (( size < expected_min_size )); then
        log_error "File too small: $(format_bytes $size) < $(format_bytes $expected_min_size)"
        return 1
    fi
    
    # Check for HTML error pages
    if file "$file" 2>/dev/null | grep -qi "html\|xml"; then
        log_error "Downloaded file appears to be HTML/XML (error page)"
        return 1
    fi
    
    # Verify zstd format
    if ! file "$file" 2>/dev/null | grep -qi "zstandard"; then
        log_warn "File may not be zstd compressed (check format)"
    fi
    
    log_verbose "Download validation passed: $(format_bytes $size)"
    return 0
}

download_file() {
    local url="$1" output="$2" is_small="${3:-0}"
    
    validate_url "$url" || { log_error "Invalid URL: $url"; return 1; }
    mkdir -p "$(dirname "$output")"
    
    if (( is_small )); then
        (( HAS_WGET )) && wget -q --timeout=15 --tries=2 -O "$output" "$url" 2>/dev/null && return 0
        (( HAS_CURL )) && curl -fsSL --max-time 15 --retry 1 -o "$output" "$url" 2>/dev/null && return 0
        return 1
    fi
    
    if (( HAS_ARIA2C )); then
        aria2c --console-log-level=error --timeout=30 --max-tries=3 \
            --max-connection-per-server=8 --split=8 --continue=true \
            --allow-overwrite=true --auto-file-renaming=false \
            --dir="$(dirname "$output")" --out="$(basename "$output")" \
            "$url" 2>/dev/null && return 0
    fi
    
    if (( HAS_WGET )); then
        wget --timeout=30 --tries=3 --continue -q --show-progress \
            -O "$output" "$url" 2>&1 | grep --line-buffered -v "^$" && return 0
    fi
    
    (( HAS_CURL )) && curl -fL --max-time 30 --retry 2 --continue-at - \
        -o "$output" "$url" 2>/dev/null && return 0
    
    return 1
}

download_with_retry() {
    local url="$1" output="$2" max_attempts="${3:-$MAX_DOWNLOAD_ATTEMPTS}"
    local attempt=0 delay=5 last_size=0 stall_count=0
    
    while (( attempt < max_attempts )); do
        ((attempt++))
        
        local current_size=0
        [[ -f "$output" ]] && current_size=$(stat -c%s "$output" 2>/dev/null || echo 0)
        
        if (( current_size > last_size )); then
            log "Attempt ${attempt}/${max_attempts} - Resuming from $(format_bytes $current_size)"
            stall_count=0
        else
            if (( current_size > 0 && current_size == last_size )); then
                ((stall_count++))
                if (( stall_count >= STALL_THRESHOLD )); then
                    log_warn "Download stalled $STALL_THRESHOLD times, restarting"
                    rm -f "$output"
                    current_size=0
                    last_size=0
                    stall_count=0
                fi
            fi
        fi
        
        if download_file "$url" "$output" 0; then
            if validate_download "$output"; then
                log_success "Download complete - $(format_bytes $(stat -c%s "$output"))"
                return 0
            else
                log_warn "Download validation failed, retrying"
                last_size=$current_size
            fi
        fi
        
        if (( attempt < max_attempts )); then
            log "Retrying in ${delay}s..."
            sleep "$delay"
            delay=$(( delay < 60 ? delay * 2 : 60 ))
        fi
    done
    
    log_error "Download failed after $max_attempts attempts"
    rm -f "$output"
    return 1
}

#####################################
### Verification                  ###
#####################################

verify_sha256() {
    local file="$1" sha_file="$2"
    log_verbose "Verifying SHA256 checksum"
    
    sha256sum -c "$sha_file" --status 2>/dev/null || {
        log_error "SHA256 verification failed"
        log_error "Expected: $(cat "$sha_file")"
        log_error "Actual: $(sha256sum "$file")"
        return 1
    }
    
    log_success "SHA256 verified"
}

verify_gpg() {
    local file="$1" sig="$2"
    local gpg_temp
    
    log_verbose "Verifying GPG signature"
    
    gpg_temp=$(mktemp -d) || return 1
    
    (
        export GNUPGHOME="$gpg_temp"
        chmod 700 "$gpg_temp"
        
        log_verbose "Importing GPG key: $GPG_KEY_ID"
        
        local imported=0
        for keyserver in keys.openpgp.org keyserver.ubuntu.com pgp.mit.edu; do
            if gpg --batch --quiet --keyserver "$keyserver" --recv-keys "$GPG_KEY_ID" 2>/dev/null; then
                imported=1
                log_verbose "Key imported from: $keyserver"
                break
            fi
        done
        
        [[ $imported -eq 0 ]] && { log_error "Failed to import GPG key"; exit 1; }
        
        local fp
        fp=$(gpg --batch --with-colons --fingerprint "$GPG_KEY_ID" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
        if [[ "$fp" != "$GPG_KEY_ID" ]]; then
            log_error "Key fingerprint mismatch!"
            exit 1
        fi
        
        gpg --batch --verify "$sig" "$file" 2>/dev/null
    )
    local result=$?
    rm -rf "$gpg_temp"
    
    [[ $result -eq 0 ]] && log_success "GPG signature verified" || log_error "GPG verification failed"
    return $result
}

#####################################
### System Checks                 ###
#####################################

check_root() {
    [[ $(id -u) -eq 0 ]] || die "Must run as root (use sudo)"
}

check_internet() {
    log_verbose "Checking internet connectivity"
    ping -c1 -W2 8.8.8.8 &>/dev/null || die "No internet connection"
    log_verbose "Internet connectivity OK"
}

check_tools() {
    log_verbose "Checking tool availability"
    
    local tools=""
    (( HAS_ARIA2C )) && tools+="aria2c " || tools+="(aria2c missing) "
    (( HAS_WGET )) && tools+="wget " || tools+="(wget missing) "
    (( HAS_CURL )) && tools+="curl " || tools+="(curl missing) "
    (( HAS_PV )) && tools+="pv" || tools+="(pv missing)"
    
    log_verbose "Tools: $tools"
    
    (( HAS_ARIA2C || HAS_WGET || HAS_CURL )) || die "No download tools available (need aria2c, wget, or curl)"
}

set_environment() {
    [[ -f /etc/shani-version && -f /etc/shani-profile ]] || \
        die "Missing system files: /etc/shani-version or /etc/shani-profile"
    
    LOCAL_VERSION=$(< /etc/shani-version)
    LOCAL_PROFILE=$(< /etc/shani-profile)
    
    validate_nonempty "$LOCAL_VERSION" "LOCAL_VERSION"
    validate_nonempty "$LOCAL_PROFILE" "LOCAL_PROFILE"
    
    log "System: v${LOCAL_VERSION} (${LOCAL_PROFILE})"
    log "Channel: ${UPDATE_CHANNEL}"
}

#####################################
### Self-Update                   ###
#####################################

ORIGINAL_ARGS=("$@")

self_update() {
    [[ -n "${SELF_UPDATE_DONE:-}" || "${SKIP_SELF_UPDATE}" == "yes" ]] && return 0
    
    if [[ -f "$DEPLOY_PENDING" ]]; then
        log_warn "Deployment pending, skipping self-update"
        return 0
    fi
    
    export SELF_UPDATE_DONE=1
    persist_state

    local url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
    local temp
    temp=$(mktemp)

    log_verbose "Checking for script updates..."
    
    if download_file "$url" "$temp" 1; then
        if grep -q "#!/bin/bash" "$temp" && grep -q "shanios-deploy" "$temp"; then
            if ! cmp -s "$0" "$temp"; then
                chmod +x "$temp"
                log_success "Updated script available, re-executing..."
                exec /bin/bash "$temp" "${ORIGINAL_ARGS[@]}"
            else
                log_verbose "Script already up-to-date"
            fi
        else
            log_warn "Downloaded script failed validation"
        fi
    else
        log_verbose "Could not check for updates, continuing with current version"
    fi
    
    rm -f "$temp"
}

#####################################
### System Inhibit                ###
#####################################

inhibit_system() {
    local depth="${SYSTEMD_INHIBIT_DEPTH:-0}"
    
    (( depth >= MAX_INHIBIT_DEPTH )) && {
        log_verbose "Maximum inhibit depth reached"
        return 0
    }
    [[ -n "${SYSTEMD_INHIBITED:-}" ]] && return 0
    
    export SYSTEMD_INHIBITED=1
    export SYSTEMD_INHIBIT_DEPTH=$((depth + 1))
    
    log "Inhibiting system power events during deployment"
    
    exec systemd-inhibit \
        --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
        --who="shanios-deployment" \
        --why="System update in progress" \
        "$0" "$@"
}

#####################################
### Cleanup & Optimization        ###
#####################################

cleanup_old_backups() {
    log_verbose "Checking for old backups to clean"
    
    findmnt -M "$MOUNT_DIR" &>/dev/null || {
        log_error "Mount point not available for cleanup"
        return 1
    }
    
    for slot in blue green; do
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
            awk -v s="${slot}" '$0 ~ s"_backup_" {print $NF}' | sort -r)
        
        (( ${#backups[@]} == 0 )) && continue
        
        log_verbose "Found ${#backups[@]} backup(s) for ${slot}"
        
        if (( ${#backups[@]} <= 2 )); then
            log_verbose "Keeping all ${#backups[@]} backup(s)"
            continue
        fi
        
        log "Keeping 2 most recent backups for ${slot}, deleting $((${#backups[@]}-2))"
        
        for (( i=2; i<${#backups[@]}; i++ )); do
            if [[ ! "${backups[i]}" =~ ^(blue|green)_backup_[0-9]{12}$ ]]; then
                log_warn "Skipping invalid backup name: ${backups[i]}"
                continue
            fi
            
            if [[ "${backups[i]}" == "$CURRENT_SLOT" ]] || [[ "${backups[i]}" == "$CANDIDATE_SLOT" ]]; then
                log_error "SAFETY: Refusing to delete active slot: ${backups[i]}"
                continue
            fi
            
            log_verbose "Deleting old backup: @${backups[i]}"
            if run_cmd btrfs subvolume delete "$MOUNT_DIR/@${backups[i]}"; then
                log_success "Deleted: @${backups[i]}"
            else
                log_warn "Failed to delete: @${backups[i]}"
            fi
        done
    done
}

cleanup_downloads() {
    log_verbose "Cleaning old downloads"
    
    local count=0
    while IFS= read -r f; do
        ((count++))
        run_cmd rm -f "$f"
        log_verbose "Deleted: $f"
    done < <(find "$DOWNLOAD_DIR" -maxdepth 1 -name "shanios-*.zst*" -mtime +7 -type f 2>/dev/null | sort -r | tail -n +2)
    
    (( count > 0 )) && log "Cleaned $count old download(s)" || log_verbose "No old downloads to clean"
}

optimize_storage() {
    log_section "Storage Optimization"
    
    [[ -f "$DEPLOY_PENDING" ]] && {
        log_warn "Deployment pending, skipping optimization"
        return 0
    }
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" || {
        log_error "Could not mount for optimization"
        return 1
    }
    
    if ! btrfs_subvol_exists "$MOUNT_DIR/@blue" || ! btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        log_verbose "Both slots not present, skipping optimization"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    if ! command -v duperemove &>/dev/null; then
        log_warn "duperemove not installed"
        log "Install duperemove for 50-70% space savings: sudo apt install duperemove"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    local -a targets=("$MOUNT_DIR/@blue" "$MOUNT_DIR/@green")
    while IFS= read -r b; do
        [[ -n "$b" ]] && targets+=("$MOUNT_DIR/@${b}")
    done < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | awk '/_backup_/ {print $NF}')
    
    log "Deduplicating ${#targets[@]} subvolume(s)"
    
    [[ "${DRY_RUN}" == "yes" ]] && {
        log "[DRY-RUN] Would deduplicate ${#targets[@]} subvolumes"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    local before
    before=$(btrfs filesystem du -s "${targets[@]}" 2>/dev/null | tail -1 | awk '{print $1}')
    
    if [[ -z "$before" ]]; then
        log_warn "Could not determine space usage"
        safe_umount "$MOUNT_DIR"
        return 1
    fi
    
    log "Running extent-based deduplication (may take several minutes)..."
    log_verbose "Space before: $(format_bytes $before)"
    
    local dedupe_log
    dedupe_log=$(mktemp)
    
    if duperemove -Adhr --skip-zeroes --dedupe-options=same --lookup-extents=yes \
        -b 128K --threads=$(nproc) --io-threads=$(nproc) \
        --hashfile="$MOUNT_DIR/@data/.dedupe.db" --hashfile-threads=$(nproc) \
        "${targets[@]}" > "$dedupe_log" 2>&1; then
        
        local after
        after=$(btrfs filesystem du -s "${targets[@]}" 2>/dev/null | tail -1 | awk '{print $1}')
        
        if [[ -n "$after" ]] && (( before > after )); then
            local saved=$((before - after))
            local percent=$((saved * 100 / before))
            log_success "Deduplication complete"
            log "Space reclaimed: $(format_bytes $saved) (${percent}% reduction)"
        elif [[ -n "$after" ]] && (( before == after )); then
            log "No additional space to reclaim (already optimized)"
        else
            log_warn "Could not measure space savings"
        fi
    else
        log_warn "Deduplication completed with errors"
        log_verbose "Check log for details: $dedupe_log"
    fi
    
    rm -f "$dedupe_log"
    safe_umount "$MOUNT_DIR"
}

#####################################
### Chroot Environment            ###
#####################################

prepare_chroot_env() {
    local slot="$1"
    
    validate_nonempty "$slot" "slot parameter"
    
    log_verbose "Preparing chroot for @${slot}"
    
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
    
    if [[ -d /sys/firmware/efi/efivars ]]; then
        mkdir -p "$MOUNT_DIR/sys/firmware/efi/efivars"
        run_cmd mount --bind /sys/firmware/efi/efivars "$MOUNT_DIR/sys/firmware/efi/efivars"
    fi
    
    log_verbose "Chroot environment ready"
}

cleanup_chroot_env() {
    log_verbose "Cleaning up chroot environment"
    
    [[ -d "$MOUNT_DIR/sys/firmware/efi/efivars" ]] && safe_umount "$MOUNT_DIR/sys/firmware/efi/efivars"
    
    for d in "${CHROOT_BIND_DIRS[@]}"; do 
        safe_umount "$MOUNT_DIR$d"
    done
    for d in "${CHROOT_STATIC_DIRS[@]}"; do 
        safe_umount "$MOUNT_DIR/$d"
    done
    safe_umount "$MOUNT_DIR/boot/efi"
    safe_umount "$MOUNT_DIR"
}

generate_uki() {
    local slot="$1"
    
    log_section "UKI Generation"
    
    [[ -x "$GENEFI_SCRIPT" ]] || die "gen-efi not found: $GENEFI_SCRIPT"
    
    prepare_chroot_env "$slot"
    
    [[ "${DRY_RUN}" == "yes" ]] && {
        log "[DRY-RUN] Would generate UKI for @${slot}"
        cleanup_chroot_env
        return 0
    }
    
    log "Generating Unified Kernel Image for @${slot}..."
    
    if chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$slot"; then
        log_success "UKI generation complete"
    else
        cleanup_chroot_env
        die "UKI generation failed"
    fi
    
    cleanup_chroot_env
}

#####################################
### Rollback System               ###
#####################################

restore_candidate() {
    log_error "Critical error detected - initiating automatic rollback"
    
    trap - ERR
    set +e
    
    mkdir -p "$MOUNT_DIR" 2>/dev/null
    mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null || true
    
    if [[ -n "$BACKUP_NAME" ]] && btrfs_subvol_exists "$MOUNT_DIR/@${BACKUP_NAME}"; then
        log "Restoring @${CANDIDATE_SLOT} from @${BACKUP_NAME}"
        
        btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false 2>/dev/null
        btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null
        
        if btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null; then
            btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true 2>/dev/null
            log_success "Candidate restored from backup"
        else
            log_error "Failed to restore from backup - manual intervention required"
        fi
    else
        log_warn "No backup available for restoration"
    fi
    
    if [[ -d "$MOUNT_DIR/temp_update" ]]; then
        log "Cleaning up temporary subvolume"
        [[ -d "$MOUNT_DIR/temp_update/shanios_base" ]] && \
            btrfs subvolume delete "$MOUNT_DIR/temp_update/shanios_base" 2>/dev/null
        btrfs subvolume delete "$MOUNT_DIR/temp_update" 2>/dev/null
    fi
    
    umount -R "$MOUNT_DIR" 2>/dev/null
    rm -f "$DEPLOY_PENDING" 2>/dev/null
    
    log_error "Deployment failed - system remains on @${CURRENT_SLOT}"
    log "Check logs at: $LOG_FILE"
    exit 1
}
trap 'restore_candidate' ERR

rollback_system() {
    log_section "System Rollback"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    local failed_slot previous_slot
    
    failed_slot=$(cat "$MOUNT_DIR/@data/current-slot" 2>/dev/null | tr -d '[:space:]')
    [[ -z "$failed_slot" ]] && failed_slot=$(get_booted_subvol)
    
    previous_slot=$(cat "$MOUNT_DIR/@data/previous-slot" 2>/dev/null | tr -d '[:space:]')
    [[ -z "$previous_slot" ]] && previous_slot=$([[ "$failed_slot" == "blue" ]] && echo "green" || echo "blue")
    
    log "Rolling back: ${failed_slot} → ${previous_slot}"
    
    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
        awk -v s="${failed_slot}" '$0 ~ s"_backup" {print $NF}' | sort | tail -1)
    
    [[ -z "$BACKUP_NAME" ]] && die "No backup found for ${failed_slot}"
    
    log "Using backup: @${BACKUP_NAME}"
    
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro false
    run_cmd btrfs subvolume delete "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro true
    
    echo "$previous_slot" > "$MOUNT_DIR/@data/current-slot"
    
    safe_umount "$MOUNT_DIR"
    
    generate_uki "$previous_slot"
    
    log_success "Rollback complete"
    log "Rebooting to @${previous_slot}..."
    
    [[ "${DRY_RUN}" == "yes" ]] || reboot
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
        log_warn "Insufficient space for ${size_mb}MB swapfile (available: ${avail_mb}MB)"
        log "System will use zram for swap"
        return 1
    }
    
    log "Creating ${size_mb}MB swapfile"
    
    if btrfs filesystem mkswapfile --size "${size_mb}M" "$file" 2>/dev/null; then
        chmod 600 "$file"
        log_success "Swapfile created (btrfs native method)"
        return 0
    fi
    
    if truncate -s "${size_mb}M" "$file" 2>/dev/null && \
       chmod 600 "$file" && \
       chattr +C "$file" 2>/dev/null && \
       mkswap "$file" &>/dev/null; then
        log_success "Swapfile created (truncate method)"
        return 0
    fi
    
    if dd if=/dev/zero of="$file" bs=1M count="$size_mb" status=none 2>/dev/null && \
       chmod 600 "$file" && \
       mkswap "$file" &>/dev/null; then
        log_success "Swapfile created (dd method)"
        return 0
    fi
    
    log_error "All swapfile creation methods failed"
    rm -f "$file"
    return 1
}

verify_and_create_subvolumes() {
    log_section "Subvolume Verification"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    local fstab="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/fstab"
    [[ -f "$fstab" ]] || {
        log_verbose "No fstab found in candidate slot"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    mapfile -t required < <(parse_fstab_subvolumes "$fstab")
    
    [[ ${#required[@]} -eq 0 ]] && {
        log_verbose "No additional subvolumes required"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    log "Required subvolumes: ${required[*]}"
    
    local -a missing=()
    for sub in "${required[@]}"; do
        btrfs_subvol_exists "$MOUNT_DIR/@${sub}" || missing+=("$sub")
    done
    
    [[ ${#missing[@]} -eq 0 ]] && {
        log_success "All required subvolumes exist"
        safe_umount "$MOUNT_DIR"
        return 0
    }
    
    log "Creating ${#missing[@]} missing subvolume(s): ${missing[*]}"
    
    for sub in "${missing[@]}"; do
        log "Creating @${sub}..."
        run_cmd btrfs subvolume create "$MOUNT_DIR/@${sub}"
        
        case "$sub" in
            swap)
                [[ "${DRY_RUN}" == "yes" ]] && continue
                
                chattr +C "$MOUNT_DIR/@${sub}" 2>/dev/null && \
                    log_verbose "Disabled CoW on @swap" || \
                    log_warn "Failed to disable CoW on @swap"
                
                local swapfile="$MOUNT_DIR/@${sub}/swapfile"
                if [[ -f "$swapfile" ]]; then
                    log_verbose "Swapfile already exists, skipping creation"
                else
                    local mem avail
                    mem=$(free -m | awk '/^Mem:/{print $2}')
                    avail=$(get_btrfs_available_mb "$MOUNT_DIR")
                    
                    create_swapfile "$swapfile" "$mem" "$avail" || true
                fi
                ;;
                
            data)
                [[ "${DRY_RUN}" == "yes" ]] && continue
                
                mkdir -p "$MOUNT_DIR/@data/overlay/"{etc,var}/{lower,upper,work}
                mkdir -p "$MOUNT_DIR/@data/downloads"
                
                [[ ! -f "$MOUNT_DIR/@data/current-slot" ]] && \
                    echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot"
                [[ ! -f "$MOUNT_DIR/@data/previous-slot" ]] && \
                    echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/previous-slot"
                ;;
        esac
        
        log_success "Created: @${sub}"
    done
    
    safe_umount "$MOUNT_DIR"
}

analyze_storage() {
    log_section "Storage Analysis"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    echo ""
    echo "Filesystem Usage:"
    btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /' || echo "  Unable to read filesystem info"
    
    echo ""
    echo "Subvolumes:"
    for s in blue green data swap; do
        if btrfs_subvol_exists "$MOUNT_DIR/@${s}"; then
            local info
            info=$(btrfs filesystem du -s "$MOUNT_DIR/@${s}" 2>/dev/null | awk 'NR==2')
            echo "  @${s}: ${info:-Present}"
        else
            echo "  @${s}: Not found"
        fi
    done
    
    if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        echo ""
        echo "Deduplication Savings:"
        local combined blue green excl
        combined=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | tail -1)
        if [[ -n "$combined" ]]; then
            echo "  Combined: $combined"
            
            blue=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" 2>/dev/null | awk 'NR==2 {print $2}')
            green=$(btrfs filesystem du -s "$MOUNT_DIR/@green" 2>/dev/null | awk 'NR==2 {print $2}')
            excl=$(echo "$combined" | awk '{print $1}')
            
            if [[ -n "$blue" && -n "$green" && -n "$excl" ]] && (( blue + green > 0 )); then
                local saved=$(( blue + green - excl ))
                local percent=$(( saved * 100 / (blue + green) ))
                echo "  Saved: $(format_bytes $saved) (${percent}%)"
            fi
        fi
    fi
    
    echo ""
    
    safe_umount "$MOUNT_DIR"
}

#####################################
### Deployment Logic              ###
#####################################

validate_boot() {
    log_section "Boot Validation"
    
    if [[ -f /data/current-slot ]]; then
        CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null | tr -d '[:space:]')
    fi
    
    if [[ -z "$CURRENT_SLOT" ]] || [[ "$CURRENT_SLOT" != "blue" && "$CURRENT_SLOT" != "green" ]]; then
        log_warn "Invalid or missing slot marker, detecting from boot"
        CURRENT_SLOT=$(get_booted_subvol)
        
        if [[ "$CURRENT_SLOT" != "blue" && "$CURRENT_SLOT" != "green" ]]; then
            log_warn "Could not determine valid slot, defaulting to 'blue'"
            CURRENT_SLOT="blue"
        fi
        
        echo "$CURRENT_SLOT" > /data/current-slot
        log "Corrected slot marker to: $CURRENT_SLOT"
    fi
    
    local booted
    booted=$(get_booted_subvol)
    
    log "Slot marker: @${CURRENT_SLOT}"
    log "Booted from: @${booted}"
    
    if [[ "$booted" != "$CURRENT_SLOT" ]]; then
        log_error "BOOT MISMATCH DETECTED!"
        log_error "System booted from @${booted} but marker says @${CURRENT_SLOT}"
        die "Boot validation failed - reboot into correct slot required"
    fi
    
    log_success "Boot validation passed"
    
    CANDIDATE_SLOT=$([[ "$CURRENT_SLOT" == "blue" ]] && echo "green" || echo "blue")
    
    log "Active: @${CURRENT_SLOT} | Candidate: @${CANDIDATE_SLOT}"
}

check_space() {
    log_section "Space Check"
    
    local free_mb
    free_mb=$(( $(df --output=avail "/data" | tail -1) / 1024 ))
    
    log "Available: ${free_mb}MB | Required: ${MIN_FREE_SPACE_MB}MB"
    
    (( free_mb >= MIN_FREE_SPACE_MB )) || \
        die "Insufficient space: ${free_mb}MB < ${MIN_FREE_SPACE_MB}MB"
    
    log_success "Disk space sufficient"
    
    run_cmd mkdir -p "$DOWNLOAD_DIR" "$ZSYNC_CACHE_DIR"
}

fetch_update() {
    log_section "Update Check"
    
    local url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    local temp
    temp=$(mktemp)
    
    log "Checking ${UPDATE_CHANNEL} channel..."
    
    download_file "$url" "$temp" 1 || {
        rm -f "$temp"
        die "Failed to fetch update manifest"
    }
    
    IMAGE_NAME=$(tr -d '[:space:]' < "$temp")
    rm -f "$temp"
    
    [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]] || \
        die "Invalid manifest format: $IMAGE_NAME"
    
    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"
    
    log "Remote: v${REMOTE_VERSION} (${REMOTE_PROFILE})"
    log "Local:  v${LOCAL_VERSION} (${LOCAL_PROFILE})"
    
    if [[ "$LOCAL_VERSION" == "$REMOTE_VERSION" && "$LOCAL_PROFILE" == "$REMOTE_PROFILE" ]]; then
        log "Current slot up-to-date"
        
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
        
        if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
            local cand_ver cand_prof
            cand_ver=$(cat "$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-version" 2>/dev/null || echo "")
            cand_prof=$(cat "$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/shani-profile" 2>/dev/null || echo "")
            
            if [[ "$cand_ver" == "$REMOTE_VERSION" && "$cand_prof" == "$REMOTE_PROFILE" ]]; then
                log_success "Candidate also up-to-date"
                touch "${STATE_DIR}/skip-deployment"
            else
                log "Candidate needs update"
            fi
        fi
        
        safe_umount "$MOUNT_DIR"
    else
        log "Update available: v${LOCAL_VERSION} → v${REMOTE_VERSION}"
    fi
}

download_update() {
    log_section "Download Phase"
    
    local image="${DOWNLOAD_DIR}/${IMAGE_NAME}"
    local marker="${image}.verified"
    
    if [[ -f "$marker" ]] && validate_download "$image"; then
        local sha="${image}.sha256"
        if [[ -f "$sha" ]] && sha256sum -c "$sha" --status 2>/dev/null; then
            log_success "Using cached verified image: $(format_bytes $(stat -c%s "$image"))"
            return 0
        else
            log_warn "Cached file verification failed, re-downloading"
            rm -f "$marker" "$image"
        fi
    fi
    
    [[ "${DRY_RUN}" == "yes" ]] && {
        log "[DRY-RUN] Would download: $IMAGE_NAME"
        return 0
    }
    
    local mirror
    mirror=$(select_mirror "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME") || \
        die "Failed to select download mirror"
    
    log "Downloading from: $(echo "$mirror" | sed -E 's|https://([^/]+).*|\1|')"
    
    download_with_retry "$mirror" "$image" || die "Download failed after all retries"
    
    local base_url="https://sourceforge.net/projects/shanios/files/${REMOTE_PROFILE}/${REMOTE_VERSION}"
    local sha="${image}.sha256"
    local asc="${image}.asc"
    
    log "Downloading verification files..."
    download_file "${base_url}/${IMAGE_NAME}.sha256/download" "$sha" 1 || die "SHA256 download failed"
    download_file "${base_url}/${IMAGE_NAME}.asc/download" "$asc" 1 || die "Signature download failed"
    
    verify_sha256 "$image" "$sha" || die "SHA256 verification failed"
    verify_gpg "$image" "$asc" || die "GPG verification failed"
    
    touch "$marker"
    log_success "Download and verification complete"
}

deploy_update() {
    log_section "Deployment Phase"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    mountpoint -q "$MOUNT_DIR/@${CANDIDATE_SLOT}" && {
        safe_umount "$MOUNT_DIR"
        die "Candidate slot @${CANDIDATE_SLOT} is mounted - cannot deploy safely"
    }
    
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        
        log "Creating backup: @${BACKUP_NAME}"
        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}" || {
            safe_umount "$MOUNT_DIR"
            die "Failed to create backup snapshot"
        }
        log_success "Backup created"
        
        log "Removing old candidate..."
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false || {
            safe_umount "$MOUNT_DIR"
            die "Failed to make candidate writable"
        }
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" || {
            safe_umount "$MOUNT_DIR"
            die "Failed to delete old candidate"
        }
    else
        log_verbose "No existing candidate to backup"
    fi
    
    local temp="$MOUNT_DIR/temp_update"
    if btrfs_subvol_exists "$temp"; then
        log_verbose "Cleaning existing temp_update"
        [[ -d "$temp/shanios_base" ]] && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
        btrfs subvolume delete "$temp" 2>/dev/null || log_warn "Failed to clean temp_update"
    fi
    
    log "Creating extraction subvolume..."
    run_cmd btrfs subvolume create "$temp" || {
        safe_umount "$MOUNT_DIR"
        die "Failed to create temp subvolume"
    }
    
    log "Extracting OS image (this may take several minutes)..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] Would extract $(format_bytes $(stat -c%s "$DOWNLOAD_DIR/$IMAGE_NAME" 2>/dev/null || echo 0))"
    else
        local start=$(date +%s)
        local extract_failed=0
        
        if (( HAS_PV )); then
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                pv -p -t -e -r -b | \
                btrfs receive "$temp" || extract_failed=1
        else
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                btrfs receive "$temp" || extract_failed=1
        fi
        
        if (( extract_failed )); then
            log_error "Extraction failed or timed out"
            btrfs subvolume delete "$temp" 2>/dev/null
            safe_umount "$MOUNT_DIR"
            die "Image extraction failed"
        fi
        
        local elapsed=$(($(date +%s) - start))
        log_success "Extraction complete in ${elapsed}s"
    fi
    
    log "Creating candidate snapshot..."
    run_cmd btrfs subvolume snapshot "$temp/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}" || {
        safe_umount "$MOUNT_DIR"
        die "Failed to create candidate snapshot"
    }
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
    
    log "Cleaning up temporary subvolume..."
    [[ -d "$temp/shanios_base" ]] && run_cmd btrfs subvolume delete "$temp/shanios_base"
    run_cmd btrfs subvolume delete "$temp"
    safe_umount "$MOUNT_DIR"
    
    [[ "${DRY_RUN}" == "no" ]] && touch "$DEPLOY_PENDING"
    log_success "Deployment phase complete"
}

finalize_update() {
    log_section "Finalization"
    
    [[ "${DRY_RUN}" == "yes" ]] && {
        log "[DRY-RUN] Would finalize and switch to ${CANDIDATE_SLOT}"
        return 0
    }
    
    echo "$CURRENT_SLOT" > /data/previous-slot
    echo "$CANDIDATE_SLOT" > /data/current-slot
    
    verify_and_create_subvolumes || die "Failed to verify/create subvolumes"
    
    log "Generating Secure Boot UKI..."
    generate_uki "$CANDIDATE_SLOT"
    
    [[ -f "$DEPLOY_PENDING" ]] && rm -f "$DEPLOY_PENDING"
    
    log "Running post-deployment cleanup and optimization..."
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    cleanup_old_backups
    safe_umount "$MOUNT_DIR"
    
    cleanup_downloads
    optimize_storage
    
    log_success "Deployment complete"
    log "Next boot: @${CANDIDATE_SLOT} (v${REMOTE_VERSION})"
}

#####################################
### Main Entry Point              ###
#####################################

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -h, --help              Show help
  -r, --rollback          Force system rollback
  -c, --cleanup           Manual cleanup
  -s, --storage-info      Storage analysis
  -t, --channel <chan>    Update channel: latest|stable (default: stable)
  -d, --dry-run           Simulate without changes
  -v, --verbose           Verbose output
  --skip-self-update      Skip script auto-update
EOF
}

main() {
    local ROLLBACK="no" CLEANUP="no" STORAGE_INFO="no"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            -r|--rollback) ROLLBACK="yes"; shift ;;
            -c|--cleanup) CLEANUP="yes"; shift ;;
            -s|--storage-info) STORAGE_INFO="yes"; shift ;;
            -t|--channel) UPDATE_CHANNEL="$2"; shift 2 ;;
            -d|--dry-run) DRY_RUN="yes"; shift ;;
            -v|--verbose) VERBOSE="yes"; shift ;;
            --skip-self-update) SKIP_SELF_UPDATE="yes"; shift ;;
            --) shift; break ;;
            *) echo "Invalid option: $1" >&2; usage; exit 1 ;;
        esac
    done
    
    DEPLOYMENT_START_TIME=$(date +%s)
    
    check_root
    check_internet
    check_tools
    set_environment
    self_update "$@"
    inhibit_system "$@"
    
    [[ "$STORAGE_INFO" == "yes" ]] && { analyze_storage; exit 0; }
    
    if [[ "$CLEANUP" == "yes" ]]; then
        log "Running manual cleanup..."
        mkdir -p "$MOUNT_DIR"
        safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" 2>/dev/null && {
            cleanup_old_backups
            safe_umount "$MOUNT_DIR"
        }
        cleanup_downloads
        exit 0
    fi
    
    [[ -f /data/boot-ok ]] || {
        log_error "Boot failure detected (missing /data/boot-ok)"
        rollback_system
    }
    
    [[ "$ROLLBACK" == "yes" ]] && { rollback_system; exit 0; }
    
    validate_boot
    check_space
    fetch_update
    
    if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
        log "System up-to-date, running optimization check..."
        mkdir -p "$MOUNT_DIR"
        if safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" 2>/dev/null; then
            if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
                safe_umount "$MOUNT_DIR"
                optimize_storage
            else
                safe_umount "$MOUNT_DIR"
            fi
        fi
    else
        log "Deployment required, starting update process..."
        download_update || die "Download phase failed"
        deploy_update || die "Deployment phase failed"
    fi
    
    [[ -f "$DEPLOY_PENDING" ]] && {
        log "Resuming finalization..."
        finalize_update || die "Finalization phase failed"
    }
    
    log_success "All operations complete"
}

main "$@"
