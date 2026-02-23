#!/bin/bash
################################################################################
# shanios-deploy.sh - Production Blue/Green Btrfs Deployment System
#
# Usage: ./shanios-deploy.sh [OPTIONS]
#
# Options:
#   -h, --help              Show help
#   -r, --rollback          Force system rollback
#   -c, --cleanup           Manual cleanup (backups, downloads)
#   -s, --storage-info      Display storage analysis
#   -o, --optimize          Run manual deduplication (maintenance only; bees handles continuous dedup)
#   -t, --channel <chan>    Update channel: latest|stable (default: stable)
#   -f, --force             Deploy even if version matches or boot mismatch
#   -d, --dry-run           Simulate without changes
#   -v, --verbose           Detailed output
#   --skip-self-update      Skip script auto-update
################################################################################

set -Eeuo pipefail
IFS=$'\n\t'

declare -a ORIGINAL_ARGS=("$@")
declare DEPLOYMENT_START_TIME=$(date +%s)
export ORIGINAL_ARGS DEPLOYMENT_START_TIME

#####################################
### State Restoration             ###
#####################################
if [[ -n "${SHANIOS_DEPLOY_STATE_FILE:-}" ]] && [[ -f "$SHANIOS_DEPLOY_STATE_FILE" ]]; then
    set +e
    state_content=$(cat "$SHANIOS_DEPLOY_STATE_FILE" 2>/dev/null)
    rm -f "$SHANIOS_DEPLOY_STATE_FILE"
    
    if [[ -n "$state_content" ]]; then
        state_content=$(echo "$state_content" | grep -v "declare.*OS_NAME\|declare.*DOWNLOAD_DIR\|declare.*MOUNT_DIR\|declare.*ROOT_DEV\|declare.*GENEFI_SCRIPT\|declare.*LOG_FILE\|declare.*DEPLOY_PENDING\|declare.*GPG_KEY_ID\|declare.*CHROOT_BIND_DIRS\|declare.*CHROOT_STATIC_DIRS\|declare.*CHANNEL_FILE" || true)
        [[ -n "$state_content" ]] && eval "$state_content" 2>/dev/null || true
    fi
    set -e
fi

#####################################
### Global Configuration          ###
#####################################

readonly OS_NAME="shanios"
readonly DOWNLOAD_DIR="/data/downloads"
readonly MOUNT_DIR="/mnt"
readonly ROOT_DEV="/dev/disk/by-label/shani_root"
readonly MIN_FREE_SPACE_MB=10240
readonly MIN_FILE_SIZE=10485760
readonly GENEFI_SCRIPT="/usr/local/bin/gen-efi"
readonly DEPLOY_PENDING="/data/deployment_pending"
readonly GPG_KEY_ID="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"
readonly LOG_FILE="/var/log/shanios-deploy.log"
readonly CHANNEL_FILE="/etc/shani-channel"
readonly ESP="/boot/efi"
readonly R2_BASE_URL="https://downloads.shani.dev"

readonly MAX_INHIBIT_DEPTH=2
readonly MAX_DOWNLOAD_ATTEMPTS=5
readonly EXTRACTION_TIMEOUT=1800

declare -g HAS_ARIA2C=0 HAS_WGET=0 HAS_CURL=0 HAS_PV=0
command -v aria2c &>/dev/null && HAS_ARIA2C=1
command -v wget &>/dev/null && HAS_WGET=1
command -v curl &>/dev/null && HAS_CURL=1
command -v pv &>/dev/null && HAS_PV=1

declare -g LOCAL_VERSION LOCAL_PROFILE
declare -g CHROOT_ESP_BIND=0
declare -g BACKUP_NAME="" CURRENT_SLOT="" CANDIDATE_SLOT=""
declare -g REMOTE_VERSION="" REMOTE_PROFILE="" IMAGE_NAME=""
declare -g UPDATE_CHANNEL="" UPDATE_CHANNEL_SOURCE="" DRY_RUN="no" VERBOSE="no"
declare -g DEPLOYMENT_START_TIME="" SKIP_SELF_UPDATE="no" SELF_UPDATE_DONE=""
declare -g FORCE_UPDATE="no"

readonly CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp)
readonly CHROOT_STATIC_DIRS=(data etc var swap)

#####################################
### State Management              ###
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
        declare -p LOCAL_VERSION LOCAL_PROFILE BACKUP_NAME CURRENT_SLOT CANDIDATE_SLOT 2>/dev/null || true
        declare -p REMOTE_VERSION REMOTE_PROFILE IMAGE_NAME UPDATE_CHANNEL UPDATE_CHANNEL_SOURCE 2>/dev/null || true
        declare -p VERBOSE DRY_RUN SKIP_SELF_UPDATE STATE_DIR 2>/dev/null || true
        declare -p HAS_ARIA2C HAS_WGET HAS_CURL HAS_PV SELF_UPDATE_DONE 2>/dev/null || true
        declare -p FORCE_UPDATE 2>/dev/null || true
        declare -p ORIGINAL_ARGS DEPLOYMENT_START_TIME 2>/dev/null || true
    } > "$state_file"
    export SHANIOS_DEPLOY_STATE_FILE="$state_file"
}

#####################################
### Logging System                ###
#####################################

log() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [INFO] $*"
    echo "$msg" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_verbose() {
    [[ "${VERBOSE}" == "yes" ]] || return 0
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [DEBUG] $*"
    echo "$msg" >&2
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

log_success() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $*"
    echo -e "\033[0;32m${msg}\033[0m" >&2
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
    {
        echo ""
        echo "$line"
        echo "  $1"
        echo "$line"
    } >&2
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

format_bytes() {
    numfmt --to=iec "$1" 2>/dev/null || echo "${1}B"
}

get_file_size() {
    stat -c%s "$1" 2>/dev/null || echo 0
}

#####################################
### Channel Management            ###
#####################################

read_channel_from_file() {
    local channel=""
    if [[ -f "$CHANNEL_FILE" ]]; then
        channel=$(cat "$CHANNEL_FILE" 2>/dev/null | tr -d '[:space:]' | head -1)
        if [[ -n "$channel" ]] && [[ "$channel" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            channel=$(echo "$channel" | tr '[:upper:]' '[:lower:]')
            case "$channel" in
                stable|latest)
                    log_verbose "Channel from file: $channel"
                    echo "$channel"
                    return 0
                    ;;
                *)
                    log_warn "Invalid channel in $CHANNEL_FILE: $channel"
                    ;;
            esac
        fi
    fi
    echo ""
}

set_update_channel() {
    local channel_arg="${1:-}"
    if [[ -n "$channel_arg" ]]; then
        UPDATE_CHANNEL="$channel_arg"
        UPDATE_CHANNEL_SOURCE="command-line"
        log_verbose "Channel source: command-line (-t $channel_arg)"
        return 0
    fi
    
    local file_channel
    file_channel=$(read_channel_from_file)
    if [[ -n "$file_channel" ]]; then
        UPDATE_CHANNEL="$file_channel"
        UPDATE_CHANNEL_SOURCE="$CHANNEL_FILE"
        log_verbose "Channel source: $CHANNEL_FILE"
        return 0
    fi
    
    UPDATE_CHANNEL="stable"
    UPDATE_CHANNEL_SOURCE="default"
    log_verbose "Channel source: default (stable)"
}

#####################################
### Mount Management              ###
#####################################

is_mounted() {
    findmnt -M "$1" &>/dev/null
}

safe_umount() {
    local tgt="$1"
    [[ -n "$tgt" ]] || return 1
    
    is_mounted "$tgt" || return 0
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] Would unmount: $tgt"
        return 0
    fi
    
    umount -R "$tgt" 2>/dev/null || \
    umount -R -l "$tgt" 2>/dev/null || {
        log_warn "Failed to unmount: $tgt"
        return 1
    }
}

force_umount_all() {
    local base_dir="$1"
    [[ -n "$base_dir" ]] || return 1
    
    is_mounted "$base_dir" || return 0
    
    log_verbose "Force unmounting all under: $base_dir"
    
    local -a mounts
    mapfile -t mounts < <(findmnt -R -o TARGET -n "$base_dir" 2>/dev/null | sort -r || true)
    
    if [[ ${#mounts[@]} -eq 0 ]]; then
        is_mounted "$base_dir" || return 0
        mounts=("$base_dir")
    fi
    
    for mount in "${mounts[@]}"; do
        [[ -n "$mount" ]] && safe_umount "$mount"
    done
    
    is_mounted "$base_dir" || return 0
    
    umount -fl "$base_dir" 2>/dev/null
    sleep 0.5
    
    is_mounted "$base_dir" && { log_warn "Mount persists: $base_dir"; return 1; }
    return 0
}

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    [[ -n "$src" && -n "$tgt" ]] || die "safe_mount: Invalid arguments"
    
    if is_mounted "$tgt"; then
        log_verbose "Already mounted: $tgt — unmounting before remount"
        safe_umount "$tgt" || force_umount_all "$tgt" || { log_warn "Could not unmount $tgt before remount"; return 1; }
    fi
    
    log_verbose "Mounting: $src -> $tgt (opts: $opts)"
    run_cmd mount -o "$opts" "$src" "$tgt" || die "Failed to mount $tgt"
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
### Mirror Discovery              ###
#####################################


get_remote_file_size() {
    local url="$1"
    local size=0
    
    if (( HAS_CURL )); then
        # Use -L to follow redirects, increase max redirects and timeouts
        size=$(timeout 30 curl -sIL \
            --connect-timeout 10 \
            --max-time 25 \
            --max-redirs 20 \
            "$url" 2>/dev/null | \
            grep -i "^content-length:" | \
            tail -1 | \
            awk '{print $2}' | \
            tr -d '\r\n ' || echo "0")
        
        # If we got a small size, it might be a redirect page - try with range request
        if [[ "$size" =~ ^[0-9]+$ ]] && (( size == 0 || (size > 0 && size < 1048576) )); then
            log_verbose "Got small size ($size), retrying with range request..."
            local range_size
            range_size=$(timeout 30 curl -sI \
                --connect-timeout 10 \
                --max-time 25 \
                --max-redirs 20 \
                --location \
                -r 0-0 \
                "$url" 2>/dev/null | \
                grep -i "^content-range:" | \
                awk -F'/' '{print $2}' | \
                tr -d '\r\n ' || echo "0")
            
            if [[ "$range_size" =~ ^[0-9]+$ ]] && (( range_size > size )); then
                log_verbose "Range request got better size: $range_size"
                size="$range_size"
            fi
        fi
        
    elif (( HAS_WGET )); then
        # wget follows redirects by default, increase max redirects
        size=$(timeout 30 wget -q --spider -S \
            --max-redirect=20 \
            --timeout=20 \
            --tries=1 \
            "$url" 2>&1 | \
            grep -i "^  Content-Length:" | \
            tail -1 | \
            awk '{print $2}' | \
            tr -d '\r\n ' || echo "0")
        
        # Try range request if size seems wrong
        if [[ "$size" =~ ^[0-9]+$ ]] && (( size == 0 || (size > 0 && size < 1048576) )); then
            log_verbose "Got small size ($size), retrying with range request..."
            local range_output
            range_output=$(timeout 30 wget -q --spider -S \
                --max-redirect=20 \
                --timeout=20 \
                --tries=1 \
                --header="Range: bytes=0-0" \
                "$url" 2>&1 || echo "")
            
            local range_size
            range_size=$(echo "$range_output" | \
                grep -i "^  Content-Range:" | \
                awk -F'/' '{print $2}' | \
                tr -d '\r\n ' || echo "0")
            
            if [[ "$range_size" =~ ^[0-9]+$ ]] && (( range_size > size )); then
                log_verbose "Range request got better size: $range_size"
                size="$range_size"
            fi
        fi
    fi
    
    # Validate size is numeric and positive
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size > 0 )); then
        echo "$size"
    else
        echo "0"
    fi
}

download_from_r2() {
    local filepath="$1" output="$2" is_small="${3:-0}"
    
    [[ -z "${R2_BASE_URL:-}" ]] && return 1
    
    local url="${R2_BASE_URL}/${filepath}"
    log_verbose "Trying R2: $url"
    
    if (( is_small )); then
        local temp_output="${output}.tmp"
        if (( HAS_WGET )); then
            timeout 20 wget -q --timeout=15 --tries=2 -O "$temp_output" "$url" 2>/dev/null && \
                [[ -f "$temp_output" && -s "$temp_output" ]] && \
                mv "$temp_output" "$output" && return 0
            rm -f "$temp_output"
        fi
        if (( HAS_CURL )); then
            timeout 20 curl -fsSL --max-time 15 --retry 1 -o "$temp_output" "$url" 2>/dev/null && \
                [[ -f "$temp_output" && -s "$temp_output" ]] && \
                mv "$temp_output" "$output" && return 0
            rm -f "$temp_output"
        fi
        return 1
    fi
    
    download_with_tool "${HAS_ARIA2C:+aria2c}" "$url" "$output" 2>/dev/null || \
    download_with_tool "${HAS_WGET:+wget}" "$url" "$output" 2>/dev/null || \
    download_with_tool "${HAS_CURL:+curl}" "$url" "$output" 2>/dev/null || \
    return 1
}

discover_mirror() {
    local sf_url="$1"
       
    if (( HAS_CURL )); then
        log_verbose "Attempting curl discovery"
        local discovered
        discovered=$(timeout 30 curl -sL -w '%{url_effective}' \
            --max-redirs 20 \
            --connect-timeout 10 \
            --max-time 25 \
            -o /dev/null \
            "$sf_url" 2>/dev/null | \
            grep -E '^https?://' | \
            tail -1 | \
            tr -d '\r\n' | \
            xargs)
        
        log_verbose "Curl extracted: ${discovered:-none}"
        
        if [[ -n "$discovered" ]] && [[ "$discovered" =~ ^https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*/.+ ]]; then
            local base_url
            base_url=$(dirname "$discovered")
            log_verbose "Curl discovered: $base_url"
            echo "$base_url"
            return 0
        fi
    fi
	
    if (( HAS_WGET )); then
        log_verbose "Attempting wget discovery"
        
        local spider_output
        spider_output=$(timeout 30 wget --max-redirect=20 --spider -S "$sf_url" 2>&1 | \
            grep -E '^ +(HTTP|Location):' || echo "")
        
        if [[ "${VERBOSE}" == "yes" ]]; then
            log_verbose "Spider output (first 20 lines):"
            echo "$spider_output" | head -20 >&2
        fi
        
        # Extract final Location header
        local final_url
        final_url=$(echo "$spider_output" | \
            grep -i '^  Location: ' | \
            tail -1 | \
            sed 's/^  Location: //' | \
            tr -d '\r\n' | \
            xargs)
        
        log_verbose "Extracted URL: ${final_url:-none}"
        
        if [[ -n "$final_url" ]] && [[ "$final_url" =~ ^https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*/.+ ]]; then
            local base_url
            base_url=$(dirname "$final_url")
            log_verbose "Wget discovered: $base_url"
            echo "$base_url"
            return 0
        fi
    fi
    
    echo ""
}

validate_mirror() {
    local mirror_url="$1"
    
    [[ -z "$mirror_url" ]] && return 1
    
    log_verbose "Validating mirror: $mirror_url"
    
    # Quick check to verify mirror responds
    if (( HAS_WGET )); then
        local response
        response=$(timeout 20 wget -q --spider -S --timeout=15 --tries=1 \
            "$mirror_url" 2>&1 || echo "")
        
        log_verbose "Wget validation response: ${response:0:200}"
        
        if echo "$response" | grep -qi "HTTP/[12].[01] [23][0-9][0-9]\|Content-Length:"; then
            log_verbose "Mirror validation: PASS (wget)"
            return 0
        fi
    elif (( HAS_CURL )); then
        local response
        response=$(timeout 20 curl -sI --connect-timeout 8 --max-time 15 \
            "$mirror_url" 2>&1 || echo "")
        
        log_verbose "Curl validation response: ${response:0:200}"
        
        if echo "$response" | grep -qi "HTTP/[12].[01] [23][0-9][0-9]\|Content-Length:"; then
            log_verbose "Mirror validation: PASS (curl)"
            return 0
        fi
    fi
    
    log_verbose "Mirror validation: FAIL"
    return 1
}

get_mirror_url() {
    local project="$1" filepath="$2" filename="$3"
    local mirror_cache="$DOWNLOAD_DIR/mirror.url"
    
    # Check cached mirror and validate it
    if [[ -f "$mirror_cache" ]]; then
        local cached
        cached=$(cat "$mirror_cache" 2>/dev/null | head -1 | tr -d '\r\n' | xargs)
        if [[ -n "$cached" ]]; then
            # Reconstruct full URL from cached base
            local full_url="${cached}/${filename}"
            log_verbose "Testing cached mirror: $(echo "$cached" | sed -E 's|https://([^/]+).*|\1|')"
            
            if validate_mirror "$full_url"; then
                log_verbose "Cached mirror valid"
                echo "$full_url"
                return 0
            else
                log_verbose "Cached mirror failed validation, removing"
                rm -f "$mirror_cache"
            fi
        fi
    fi
    
    # Construct SourceForge URL with /download endpoint (critical for proper redirects)
    local sf_url="https://sourceforge.net/projects/${project}/files/${filepath}/${filename}/download"
    
    log "Discovering mirror from SourceForge..."
    
    local base_url
    base_url=$(discover_mirror "$sf_url")
    
    # Clean and validate discovered mirror
    if [[ -n "$base_url" ]]; then
        # Sanitize the base_url
        base_url=$(echo "$base_url" | tr -d '\r\n' | xargs)
        
        log_verbose "Discovered base URL: $base_url"
        
        # Validate it's a proper URL
        if [[ ! "$base_url" =~ ^https?://[a-zA-Z0-9] ]]; then
            log_warn "Discovered base_url has invalid format: ${base_url:0:100}"
            base_url=""
        fi
    else
        log_verbose "No base URL discovered"
    fi
    
    # Validate discovered mirror
    if [[ -n "$base_url" ]]; then
        local full_url="${base_url}/${filename}"
        log_verbose "Testing mirror: $full_url"
        
        if validate_mirror "$full_url"; then
            local mirror_host=$(echo "$base_url" | sed -E 's|https?://([^/]+).*|\1|')
            log_success "Mirror validated: $mirror_host"
            mkdir -p "$DOWNLOAD_DIR"
            echo "$base_url" > "$mirror_cache"
            echo "$full_url"
            return 0
        else
            log_warn "Discovered mirror failed validation"
        fi
    fi
    
    # Ultimate fallback: use SourceForge direct download URL (slower but reliable)
    log_warn "Mirror discovery failed, using SourceForge direct"
    local fallback_url="https://sourceforge.net/projects/${project}/files/${filepath}/${filename}/download"
    
    # Don't cache the fallback URL as it will redirect on each use
    echo "$fallback_url"
    return 0
}

#####################################
### Download System               ###
#####################################

validate_download() {
    local file="$1" expected_size="${2:-0}" is_final="${3:-1}"
    
    [[ -f "$file" ]] || { log_error "File not found: $file"; return 1; }
    
    local size
    size=$(get_file_size "$file")
    
    # Check minimum size threshold
    local min_size="$MIN_FILE_SIZE"
    if (( expected_size > 0 )); then
        min_size="$expected_size"
    fi
    
    if (( size < min_size )); then
        log_error "File too small: $(format_bytes $size) < $(format_bytes $min_size)"
        return 1
    fi
    
    # Get actual disk usage
    local disk_usage
    disk_usage=$(du -b "$file" 2>/dev/null | awk '{print $1}')
    
    if (( disk_usage > 0 && size > 0 )); then
        local usage_ratio=$((disk_usage * 100 / size))
        log_verbose "Disk usage: $(format_bytes $disk_usage) / $(format_bytes $size) (${usage_ratio}%)"
        
        # ONLY check for sparse files if this is a final validation
        # (i.e., download tool claims to be done)
        if (( is_final )); then
            # Only flag as preallocated if disk usage is extremely low (< 5%)
            # — btrfs transparent compression can legitimately yield 40-60% ratios
            if (( expected_size > 0 && size == expected_size && usage_ratio < 5 )); then
                log_error "File appears preallocated but incomplete: $(format_bytes $disk_usage) actual vs $(format_bytes $size) apparent"
                return 1
            fi
        fi
    else
        # Zero disk usage = completely preallocated
        if (( size > 0 )); then
            log_error "File is completely preallocated (0 bytes written)"
            return 1
        fi
    fi
    
    # Check for aria2c control files (indicates incomplete download)
    if [[ -f "${file}.aria2" ]]; then
        log_error "aria2c control file exists - download incomplete"
        return 1
    fi
    
    # Detect HTML/XML error pages
    if file "$file" 2>/dev/null | grep -qi "html\|xml"; then
        log_error "File appears to be error page (HTML/XML)"
        return 1
    fi
    
    # Validate zstd files - ONLY run full integrity check if final validation
    if [[ "$file" == *.zst ]]; then
        if ! file "$file" 2>/dev/null | grep -qiE "zstandard|zst compressed"; then
            log_warn "File extension .zst but wrong content type"
            return 1
        fi
    fi
    
    log_verbose "Validation passed: $(format_bytes $size)"
    return 0
}

download_with_tool() {
    local tool="$1" url="$2" output="$3"
    
    # Sanitize URL
    url=$(echo "$url" | tr -d '\r\n' | xargs)
    
    # Validate URL format
    if [[ ! "$url" =~ ^https?://[a-zA-Z0-9] ]]; then
        log_error "Invalid URL format: ${url:0:100}"
        return 1
    fi
    
    local wget_base_opts=(
        --retry-connrefused
        --waitretry=30
        --read-timeout=60
        --timeout=60
        --tries=3
        --dns-timeout=30
        --connect-timeout=30
        --prefer-family=IPv4
    )
    [[ -t 2 ]] && wget_base_opts+=(--show-progress --progress=bar:force)

    local curl_base_opts=(
        --fail
        --location
        --max-time 600
        --retry 5
        --retry-delay 5
        --retry-connrefused
        --connect-timeout 30
        --progress-bar
        --remote-time
    )
    [[ ! -t 2 ]] && curl_base_opts+=(--silent)

    local aria2c_base_opts=(
        --allow-overwrite=true
        --auto-file-renaming=false
        --conditional-get=false
        --remote-time=true
        --file-allocation=none
        --timeout=60
        --max-tries=5
        --retry-wait=5
        --console-log-level=error
        --summary-interval=0
        --max-resume-failure-tries=10
        --connect-timeout=30
    )

    case "$tool" in
        aria2c)
            if [[ "$url" == *"downloads.shani.dev"* ]]; then
                # R2: resume supported, use multiple connections
                local _connections=4
                aria2c "${aria2c_base_opts[@]}" \
                    --continue=true \
                    --max-connection-per-server="${_connections}" \
                    --split="${_connections}" \
                    --dir="$(dirname "$output")" \
                    --out="$(basename "$output")" \
                    "$url"
            else
                # SourceForge: no resume, no multi-connection, start fresh
                rm -f "$output" "${output}.aria2"
                aria2c "${aria2c_base_opts[@]}" \
                    --continue=false \
                    --max-connection-per-server=1 \
                    --split=1 \
                    --dir="$(dirname "$output")" \
                    --out="$(basename "$output")" \
                    "$url"
            fi
            ;;
        wget)
            if [[ "$url" == *"downloads.shani.dev"* ]]; then
                wget "${wget_base_opts[@]}" --continue -O "$output" "$url"
            else
                rm -f "$output"
                wget "${wget_base_opts[@]}" -O "$output" "$url"
            fi
            ;;
        curl)
            if [[ "$url" == *"downloads.shani.dev"* ]]; then
                curl "${curl_base_opts[@]}" --continue-at - --output "$output" "$url"
            else
                rm -f "$output"
                curl "${curl_base_opts[@]}" --output "$output" "$url"
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

download_file() {
    local url="$1" output="$2" is_small="${3:-0}" expected_size="${4:-0}"
    
    mkdir -p "$(dirname "$output")"
    
    # Small files - simplified approach
    if (( is_small )); then
        local temp_output="${output}.tmp"
        
        if (( HAS_WGET )); then
            if timeout 20 wget -q --timeout=15 --tries=2 -O "$temp_output" "$url" 2>/dev/null; then
                if [[ -f "$temp_output" ]] && [[ -s "$temp_output" ]]; then
                    mv "$temp_output" "$output" 2>/dev/null && return 0
                fi
            fi
            rm -f "$temp_output"
        fi
        
        if (( HAS_CURL )); then
            if timeout 20 curl -fsSL --max-time 15 --retry 1 -o "$temp_output" "$url" 2>/dev/null; then
                if [[ -f "$temp_output" ]] && [[ -s "$temp_output" ]]; then
                    mv "$temp_output" "$output" 2>/dev/null && return 0
                fi
            fi
            rm -f "$temp_output"
        fi
        
        return 1
    fi
    
    # Large files - intelligent retry with resume
    local -a downloaders=()
    (( HAS_ARIA2C )) && downloaders+=(aria2c)
    (( HAS_WGET )) && downloaders+=(wget)
    (( HAS_CURL )) && downloaders+=(curl)
    
    if [[ ${#downloaders[@]} -eq 0 ]]; then
        log_error "No download tools available"
        return 1
    fi
    
    # Try each tool multiple times before giving up
    local max_tool_attempts=3
    
    for tool in "${downloaders[@]}"; do
        local attempt=0
        
        while (( attempt < max_tool_attempts )); do
            ((attempt++))
            log_verbose "Attempting $tool (try ${attempt}/${max_tool_attempts})..."
            
            # Check existing file state before download
            if [[ -f "$output" ]]; then
                local current_size=$(get_file_size "$output")
                local disk_usage=$(du -b "$output" 2>/dev/null | awk '{print $1}')
                
                if (( current_size > 0 && disk_usage == 0 )); then
                    # Completely preallocated, no real data
                    log_verbose "Removing completely preallocated file"
                    rm -f "$output" "${output}.aria2"
                elif (( current_size > 0 )); then
                    local usage_ratio=$((disk_usage * 100 / current_size))
                    log_verbose "Found partial: $(format_bytes $disk_usage) actual / $(format_bytes $current_size) apparent (${usage_ratio}%)"
                    
                    # ANY real data is worth keeping for resume
                    # Don't delete partial downloads just because they're sparse
                fi
            fi
            
            if download_with_tool "$tool" "$url" "$output"; then
                if [[ -f "$output" ]] && [[ -s "$output" ]]; then
                    # Check if download tool actually completed or just preallocated
                    local final_size=$(get_file_size "$output")
                    local final_usage=$(du -b "$output" 2>/dev/null | awk '{print $1}')
                    
                    if (( final_usage > 0 )); then
                        local final_ratio=$((final_usage * 100 / final_size))
                        
                        # If tool claims done but file is mostly empty, it's preallocated
                        if (( expected_size > 0 && final_ratio < 5 )); then
                            log_verbose "$tool preallocated file but didn't complete (${final_ratio}%), retrying..."
                            # Don't delete - it might have written some data
                            sleep 3
                            continue
                        fi
                    fi
                    
                    log_verbose "$tool succeeded"
                    # Clean up control files on success
                    rm -f "${output}.aria2" "${output}.tmp"
                    return 0
                else
                    log_verbose "$tool completed but no valid output"
                fi
            fi
            
            # Check if we made actual progress
            if [[ -f "$output" ]]; then
                local new_size=$(get_file_size "$output")
                local new_usage=$(du -b "$output" 2>/dev/null | awk '{print $1}')
                
                if (( new_usage > 0 )); then
                    log_verbose "Progress: $(format_bytes $new_usage) actual data written"
                    # If we have real partial data, retry with same tool
                    if (( attempt < max_tool_attempts )); then
                        log_verbose "Retrying with $tool to resume..."
                        sleep 3
                        continue
                    fi
                fi
            fi
            
            # If no progress and more attempts left, try again
            if (( attempt < max_tool_attempts )); then
                log_verbose "$tool attempt ${attempt} failed, retrying..."
                sleep 5
            fi
        done
        
        log_verbose "$tool exhausted all attempts, trying next tool"
    done
    
    # All tools failed
    log_error "All download tools failed"
    return 1
}

#####################################
### Verification                  ###
#####################################

verify_sha256() {
    local file="$1" sha_file="$2"
    log_verbose "Verifying SHA256"
    
    local expected=$(awk '{print $1}' "$sha_file" 2>/dev/null | head -1 | tr -d '[:space:]')
    local actual=$(sha256sum "$file" 2>/dev/null | awk '{print $1}' | tr -d '[:space:]')
    
    [[ -z "$expected" || -z "$actual" ]] && { log_error "Missing checksums"; return 1; }
    
    if [[ "$expected" != "$actual" ]]; then
        log_error "SHA256 mismatch"
        log_error "Expected: $expected"
        log_error "Got: $actual"
        return 1
    fi
    
    log_success "SHA256 verified"
    return 0
}

verify_gpg() {
    local file="$1" sig="$2"
    log_verbose "Verifying GPG signature"
    
    local gpg_temp=$(mktemp -d)
    local old_gnupghome="${GNUPGHOME:-}"
    export GNUPGHOME="$gpg_temp"
    chmod 700 "$gpg_temp"
    
    local result=1
    local keyservers=(keys.openpgp.org keyserver.ubuntu.com pgp.mit.edu)
    
    local key_imported=0
    for keyserver in "${keyservers[@]}"; do
        if gpg --batch --quiet --keyserver "$keyserver" --recv-keys "$GPG_KEY_ID" 2>/dev/null; then
            log_verbose "Key imported from: $keyserver"
            key_imported=1
            break
        fi
    done
    (( key_imported )) || log_warn "Could not import GPG key from any keyserver"

    local fp=$(gpg --batch --with-colons --fingerprint "$GPG_KEY_ID" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
    if [[ "$fp" == "$GPG_KEY_ID" ]] && gpg --batch --verify "$sig" "$file" 2>/dev/null; then
        log_success "GPG signature verified"
        result=0
    else
        log_error "GPG verification failed"
    fi
    
    rm -rf "$gpg_temp"
    [[ -n "$old_gnupghome" ]] && export GNUPGHOME="$old_gnupghome" || unset GNUPGHOME
    return $result
}

#####################################
### System Checks                 ###
#####################################

check_root() {
    [[ $(id -u) -eq 0 ]] || die "Must run as root"
}

check_internet() {
    log_verbose "Checking connectivity"
    ping -c1 -W2 8.8.8.8 &>/dev/null || die "No internet"
}

check_tools() {
    log_verbose "Checking tools"
    (( HAS_ARIA2C || HAS_WGET || HAS_CURL )) || die "No download tools available"
}

set_environment() {
    [[ -f /etc/shani-version && -f /etc/shani-profile ]] || \
        die "Missing: /etc/shani-version or /etc/shani-profile"
    
    LOCAL_VERSION=$(< /etc/shani-version)
    LOCAL_PROFILE=$(< /etc/shani-profile)
    
    validate_nonempty "$LOCAL_VERSION" "LOCAL_VERSION"
    validate_nonempty "$LOCAL_PROFILE" "LOCAL_PROFILE"
    
    log "System: v${LOCAL_VERSION} (${LOCAL_PROFILE})"
    log "Channel: ${UPDATE_CHANNEL} (source: ${UPDATE_CHANNEL_SOURCE})"
}

#####################################
### Self-Update                   ###
#####################################

self_update() {
    [[ -n "${SELF_UPDATE_DONE:-}" || "${SKIP_SELF_UPDATE}" == "yes" || -f "$DEPLOY_PENDING" ]] && return 0
    
    export SELF_UPDATE_DONE=1
    persist_state

    local url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
    local temp=$(mktemp)

    log_verbose "Checking for updates..."
    
    if download_file "$url" "$temp" 1; then
        if grep -q "#!/bin/bash" "$temp" && grep -q "shanios-deploy" "$temp"; then
            if ! cmp -s "$0" "$temp"; then
                chmod +x "$temp"
                log_success "Updated, re-executing..."
                [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]] && exec /bin/bash "$temp" "${ORIGINAL_ARGS[@]}" || exec /bin/bash "$temp"
            fi
        fi
    fi
    
    rm -f "$temp"
}

#####################################
### System Inhibit                ###
#####################################

inhibit_system() {
    local depth="${SYSTEMD_INHIBIT_DEPTH:-0}"
    (( depth >= MAX_INHIBIT_DEPTH )) && return 0
    [[ -n "${SYSTEMD_INHIBITED:-}" ]] && return 0
    
    export SYSTEMD_INHIBITED=1
    export SYSTEMD_INHIBIT_DEPTH=$((depth + 1))
    log "Inhibiting power events"
    
    local script_path
    script_path=$(readlink -f "$0")

    [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]] && \
        exec systemd-inhibit --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" --why="System update in progress" "$script_path" "${ORIGINAL_ARGS[@]}" || \
        exec systemd-inhibit --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" --why="System update in progress" "$script_path"
}

#####################################
### Cleanup Functions             ###
#####################################

cleanup_old_backups() {
    log_verbose "Cleaning backups"
    set +e
    
    is_mounted "$MOUNT_DIR" || { log_verbose "Mount unavailable"; set -e; return 1; }

    for slot in blue green; do
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
            awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' | sort -r)

        local backup_count=${#backups[@]}
        (( backup_count == 0 )) && continue
        
        log_verbose "Found ${backup_count} backup(s) for slot '${slot}'"

        if (( backup_count > 1 )); then
            log "Keeping latest, deleting $((backup_count-1)) older backup(s) for '${slot}'"
            for (( i=1; i<backup_count; i++ )); do
                local backup="${backups[i]}"
                local clean_backup="${backup#@}"
                
                # Validate backup name format (10-12 digit timestamp)
                [[ ! "$clean_backup" =~ ^(blue|green)_backup_[0-9]{10,12}$ ]] && {
                    log_warn "Skipping invalid backup name: ${backup}"
                    continue
                }
                
                [[ -n "${BACKUP_NAME:-}" && "$backup" == "@${BACKUP_NAME}" ]] && continue
                
                [[ "${DRY_RUN}" == "yes" ]] && { log "[DRY-RUN] Would delete: ${backup}"; continue; }
                btrfs subvolume delete "$MOUNT_DIR/${backup}" &>/dev/null && \
                    log_success "Deleted: ${backup}" || log_warn "Failed to delete: ${backup}"
            done
        fi
    done

    set -e
    return 0
}

cleanup_downloads() {
    log_verbose "Cleaning downloads"
    [[ ! -d "$DOWNLOAD_DIR" ]] && return 0
    
    local latest_image=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst" \
        -printf "%T@ %p\n" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
    
    local count=0 protected=0
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        
        if [[ -n "$latest_image" ]]; then
            local basename=$(basename "$file")
            local latest_basename=$(basename "$latest_image")
            
            if [[ "$basename" == "$latest_basename" ]] || \
               [[ "$basename" == "${latest_basename}.sha256" ]] || \
               [[ "$basename" == "${latest_basename}.asc" ]] || \
               [[ "$basename" == "${latest_basename}.verified" ]]; then
                ((protected++))
                continue
            fi
        fi
        
        if [[ "${DRY_RUN}" == "yes" ]]; then
            log "[DRY-RUN] Would delete: $(basename "$file")"
            ((count++))
        elif rm -f "$file" 2>/dev/null; then
            log_verbose "Deleted: $(basename "$file")"
            ((count++))
        fi
    done < <(find "$DOWNLOAD_DIR" -maxdepth 1 -type f \
        \( -name "shanios-*.zst*" -o -name "*.aria2" -o -name "*.part" -o -name "*.tmp" \) \
        -mtime +7 2>/dev/null)
    
    (( count > 0 )) && log "Cleaned $count old download(s)"
    (( protected > 0 )) && log_verbose "Protected $protected current file(s)"
}

analyze_storage() {
    log_section "Storage Analysis"

    if is_mounted "$MOUNT_DIR"; then
        log_verbose "Cleaning up existing mount before storage analysis"
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
    fi

    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" || { log_error "Mount failed"; return 1; }
    trap 'safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true' RETURN

    local -a check_subvols=(blue green data swap)

    echo ""
    log "=== Filesystem Usage ==="
    echo ""
    btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /' || log_warn "Failed to get usage"

    echo ""
    log "=== Subvolume Compression Analysis ==="
    for subvol in "${check_subvols[@]}"; do
        local path="$MOUNT_DIR/@${subvol}"
        [[ -d "$path" ]] || continue
        echo ""
        log "@${subvol}:"
        if command -v compsize &>/dev/null; then
            compsize -x "$path" || log_warn "compsize failed"
        else
            btrfs filesystem du -s "$path" || log_warn "btrfs du failed"
        fi
    done

    echo ""
    log "=== Subvolume List ==="
    btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /' || log_warn "Failed to list subvolumes"

    echo ""
    return 0
}

optimize_storage() {
    set +e
    log_section "Storage Optimization (Deduplication)"

    [[ -f "$DEPLOY_PENDING" ]] && { log_warn "Deployment pending, skipping"; set -e; return 0; }

    if is_mounted "$MOUNT_DIR"; then
        log_verbose "Cleaning up existing mount before optimization"
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
    fi

    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" || { log_error "Mount failed"; set -e; return 1; }
    trap 'safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true' RETURN

    btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green" || {
        log_warn "Skipping deduplication (missing blue/green subvolumes)"
        set -e
        return 0
    }

    local -a targets=("$MOUNT_DIR/@blue" "$MOUNT_DIR/@green")
    while IFS= read -r backup; do
        [[ -n "$backup" ]] && targets+=("$MOUNT_DIR/${backup}")
    done < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | awk '$NF ~ /_backup_/ {print $NF}')

    echo ""
    log "=== Running Deduplication ==="
    log "Targets: ${targets[*]}"
    log "This may take several minutes..."
    echo ""

    if ! btrfs_subvol_exists "$MOUNT_DIR/@data"; then
        log_warn "@data subvolume missing — skipping hashfile, deduplication will proceed without cache"
    fi
    local dedupe_start=$(date +%s)

    local dedupe_hashfile_opts=()
    btrfs_subvol_exists "$MOUNT_DIR/@data" && \
        dedupe_hashfile_opts=(--hashfile="$MOUNT_DIR/@data/.dedupe.db")

    duperemove -dhr --skip-zeroes --dedupe-options=same,partial -b 128K --batchsize=256 \
        --io-threads="$(nproc)" --cpu-threads="$(nproc)" \
        "${dedupe_hashfile_opts[@]}" "${targets[@]}"

    local dedupe_status=$?
    local dedupe_duration=$(( $(date +%s) - dedupe_start ))

    echo ""
    [[ $dedupe_status -eq 0 ]] && log_success "Deduplication completed in ${dedupe_duration}s" || \
        log_warn "Deduplication completed with warnings (exit: $dedupe_status)"

    echo ""
    log "=== Post-Deduplication Results ==="
    local -a check_subvols=(blue green data swap)
    for subvol in "${check_subvols[@]}"; do
        local path="$MOUNT_DIR/@${subvol}"
        [[ -d "$path" ]] || continue
        echo ""
        log "@${subvol}:"
        if command -v compsize &>/dev/null; then
            compsize -x "$path" || log_warn "compsize failed"
        else
            btrfs filesystem du -s "$path" || log_warn "btrfs du failed"
        fi
    done

    echo ""
    log "Final Filesystem Usage:"
    btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /' || log_warn "Failed to get usage"

    echo ""
    set -e
    return 0
}

#####################################
### Chroot Management             ###
#####################################

prepare_chroot() {
    local slot="$1"
    validate_nonempty "$slot" "slot"
    log_verbose "Preparing chroot: @${slot}"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvol=@${slot}"
    
    mkdir -p "$MOUNT_DIR/boot/efi"
    if mountpoint -q /boot/efi; then
        run_cmd mount --bind /boot/efi "$MOUNT_DIR/boot/efi"
        # Record that we did a bind-mount (not a fresh label mount) so cleanup
        # knows it should NOT try to unmount the host's /boot/efi itself.
        CHROOT_ESP_BIND=1
    else
        safe_mount "LABEL=shani_boot" "$MOUNT_DIR/boot/efi" "defaults"
        CHROOT_ESP_BIND=0
    fi
    
    for dir in "${CHROOT_STATIC_DIRS[@]}"; do
        mkdir -p "$MOUNT_DIR/$dir"
        run_cmd mount --bind "/$dir" "$MOUNT_DIR/$dir"
    done
    
    for d in "${CHROOT_BIND_DIRS[@]}"; do
        mkdir -p "$MOUNT_DIR$d"
        run_cmd mount --rbind "$d" "$MOUNT_DIR$d"
    done
    
    if [[ -d /sys/firmware/efi/efivars ]]; then
        mkdir -p "$MOUNT_DIR/sys/firmware/efi/efivars"
        run_cmd mount --rbind /sys/firmware/efi/efivars "$MOUNT_DIR/sys/firmware/efi/efivars"
    fi
}

cleanup_chroot() {
    log_verbose "Cleaning chroot"
    set +e

    [[ -d "$MOUNT_DIR/sys/firmware/efi/efivars" ]] && safe_umount "$MOUNT_DIR/sys/firmware/efi/efivars"
    # Unmount bind dirs in reverse order to handle nested mounts correctly
    local -a bind_reversed=()
    for d in "${CHROOT_BIND_DIRS[@]}"; do bind_reversed=("$d" "${bind_reversed[@]}"); done
    for d in "${bind_reversed[@]}"; do safe_umount "$MOUNT_DIR$d" || umount -R -l "$MOUNT_DIR$d" 2>/dev/null || true; done
    # Unmount static dirs in reverse order
    local -a static_reversed=()
    for d in "${CHROOT_STATIC_DIRS[@]}"; do static_reversed=("$d" "${static_reversed[@]}"); done
    for d in "${static_reversed[@]}"; do safe_umount "$MOUNT_DIR/$d"; done
    safe_umount "$MOUNT_DIR/boot/efi"
    safe_umount "$MOUNT_DIR"

    set -e
    return 0
}

generate_uki() {
    local slot="$1"
    log_section "UKI Generation"
    [[ -x "$GENEFI_SCRIPT" ]] || die "gen-efi not found"
    
    prepare_chroot "$slot"
    trap 'cleanup_chroot' RETURN

    [[ "${DRY_RUN}" == "yes" ]] && return 0

    log "Generating UKI for @${slot}..."
    local result=0
    chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$slot" && \
        log_success "UKI complete" || { log_error "UKI generation failed"; result=1; }

    return $result
}

finalize_boot_entries() {
    local active_slot="$1"
    local candidate_slot="$2"
    local esp_mounted=0

    if ! mountpoint -q "$ESP" 2>/dev/null; then
        log "ESP not mounted, mounting temporarily..."
        if mount LABEL=shani_boot "$ESP" 2>/dev/null; then
            esp_mounted=1
        else
            log_warn "Could not mount ESP — boot entries not updated"
            return 1
        fi
    fi

    mkdir -p "$ESP/loader/entries"

    local active_conf="$ESP/loader/entries/${OS_NAME}-${active_slot}.conf"
    local candidate_conf="$ESP/loader/entries/${OS_NAME}-${candidate_slot}.conf"

    cat > "$active_conf" <<EOF
title   ${OS_NAME}-${active_slot} (Active)
efi     /EFI/${OS_NAME}/${OS_NAME}-${active_slot}.efi
EOF

    cat > "$candidate_conf" <<EOF
title   ${OS_NAME}-${candidate_slot} (Candidate)
efi     /EFI/${OS_NAME}/${OS_NAME}-${candidate_slot}.efi
EOF

    bootctl set-default "${OS_NAME}-${active_slot}.conf" || \
        log_warn "bootctl set-default failed"

    if [[ $esp_mounted -eq 1 ]]; then
        umount "$ESP" 2>/dev/null || log_warn "Could not unmount ESP"
    fi
}

#####################################
### Rollback                      ###
#####################################

restore_candidate() {
    trap - ERR
    trap - ERR EXIT
    set +e

    # Guard: if /dev is gone we're in a broken chroot or degraded environment.
    # btrfs and mount will fail — bail immediately to prevent further damage.
    if [[ ! -c /dev/null ]]; then
        echo "[FATAL] restore_candidate: environment degraded (/dev unavailable), aborting" >&2
        exit 1
    fi

    log_error "Initiating rollback"

    if [[ -z "${CANDIDATE_SLOT:-}" ]]; then
        log_warn "CANDIDATE_SLOT unknown, skipping subvolume restore"
        umount -R "$MOUNT_DIR" 2>/dev/null || umount -R -l "$MOUNT_DIR" 2>/dev/null || true
        rm -f "$DEPLOY_PENDING" 2>/dev/null
        log_error "Rollback incomplete - manual intervention required"
        exit 1
    fi

    mkdir -p "$MOUNT_DIR" 2>/dev/null
    umount -R "$MOUNT_DIR" 2>/dev/null || umount -R -l "$MOUNT_DIR" 2>/dev/null || true
    mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null || \
        log_warn "Failed to mount subvolid=5 — slot file writes may fail"

    # If BACKUP_NAME not set, search disk for most recent backup
    if [[ -z "${BACKUP_NAME:-}" ]]; then
        local found
        found=$(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
            awk -v s="${CANDIDATE_SLOT}_backup_" '$NF ~ s {print $NF}' | sort | tail -1)
        BACKUP_NAME="${found#@}"
        [[ -n "$BACKUP_NAME" ]] && log "Found backup on disk: @${BACKUP_NAME}" || \
            log_warn "No backup found on disk for @${CANDIDATE_SLOT}"
    fi

    if [[ -n "$BACKUP_NAME" ]] && btrfs_subvol_exists "$MOUNT_DIR/@${BACKUP_NAME}"; then
        log "Restoring from @${BACKUP_NAME}"

        local rc_booted
        rc_booted=$(get_booted_subvol)

        if [[ "$CANDIDATE_SLOT" == "$rc_booted" ]]; then
            log_warn "Refusing to touch @${CANDIDATE_SLOT} — it is the currently booted slot"
            log_warn "Skipping subvolume restore, booted system is intact"
        else
            if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
                btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false 2>/dev/null
                btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null
            else
                log_warn "@${CANDIDATE_SLOT} does not exist, restoring directly from backup without delete"
            fi
            btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null
            btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true 2>/dev/null
        fi

        local _rc_slot="${CURRENT_SLOT:-$(get_booted_subvol)}"
        echo "$_rc_slot" > "$MOUNT_DIR/@data/current-slot" 2>/dev/null || \
            log_warn "Failed to write current-slot"
        echo "$CANDIDATE_SLOT" > "$MOUNT_DIR/@data/previous-slot" 2>/dev/null || \
            log_warn "Failed to write previous-slot"
    else
        log_error "No backup available for @${CANDIDATE_SLOT} — snapshotting @${CURRENT_SLOT} as fallback"
        local nb_booted
        nb_booted=$(get_booted_subvol)
        if [[ -n "${CURRENT_SLOT:-}" && "$CANDIDATE_SLOT" != "$nb_booted" ]] && \
           btrfs_subvol_exists "$MOUNT_DIR/@${CURRENT_SLOT}"; then
            if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
                btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false 2>/dev/null
                btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null || true
            fi
            btrfs subvolume snapshot "$MOUNT_DIR/@${CURRENT_SLOT}" "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null && \
                btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true 2>/dev/null && \
                log "Snapshotted @${CURRENT_SLOT} → @${CANDIDATE_SLOT}" || \
                log_warn "Snapshot failed — @${CANDIDATE_SLOT} may be inconsistent"

            local _rc_slot="${CURRENT_SLOT:-$(get_booted_subvol)}"
            echo "$_rc_slot" > "$MOUNT_DIR/@data/current-slot" 2>/dev/null || \
                log_warn "Failed to write current-slot"
            echo "$CANDIDATE_SLOT" > "$MOUNT_DIR/@data/previous-slot" 2>/dev/null || \
                log_warn "Failed to write previous-slot"

            # Unmount before chroot for UKI generation
            umount -R "$MOUNT_DIR" 2>/dev/null || umount -R -l "$MOUNT_DIR" 2>/dev/null || true
            generate_uki "$CANDIDATE_SLOT" && {
                log "UKI generated for @${CANDIDATE_SLOT} — both slots consistent"
            } || {
                log_warn "UKI generation failed — copying @${CURRENT_SLOT} UKI as fallback"
                cp "$ESP/EFI/${OS_NAME}/${OS_NAME}-${CURRENT_SLOT}.efi" \
                   "$ESP/EFI/${OS_NAME}/${OS_NAME}-${CANDIDATE_SLOT}.efi" 2>/dev/null || true
            }
        else
            log_warn "Cannot restore @${CANDIDATE_SLOT} — system remains on @${CURRENT_SLOT:-booted slot}"
        fi
    fi

    btrfs_subvol_exists "$MOUNT_DIR/temp_update/shanios_base" && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update/shanios_base" 2>/dev/null
    btrfs_subvol_exists "$MOUNT_DIR/temp_update" && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update" 2>/dev/null

    umount -R "$MOUNT_DIR" 2>/dev/null || umount -R -l "$MOUNT_DIR" 2>/dev/null || true
    rm -f "$DEPLOY_PENDING" 2>/dev/null

    finalize_boot_entries "${CURRENT_SLOT:-$(get_booted_subvol)}" "$CANDIDATE_SLOT" 2>/dev/null || \
        log_warn "Could not update boot entries"

    log_error "Rollback complete - system remains on @${CURRENT_SLOT:-$(get_booted_subvol)}"
    log_error "Please reboot to ensure clean state"
    exit 1
}
trap 'restore_candidate' ERR

rollback_system() {
    log_section "System Rollback"
    # Disable the restore_candidate ERR trap while we're already doing a rollback.
    # Without this, any error inside rollback_system would re-trigger restore_candidate
    # causing infinite recursion.
    trap - ERR

    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"

    # The failed slot is always the NON-booted slot
    # (the one that was supposed to be next but failed)
    local booted
    booted=$(get_booted_subvol)
    [[ ! "$booted" =~ ^(blue|green)$ ]] && die "Cannot determine booted slot"

    local failed_slot=$([[ "$booted" == "blue" ]] && echo "green" || echo "blue")

    CURRENT_SLOT="$booted"
    CANDIDATE_SLOT="$failed_slot"

    log "Booted: @${booted} | Restoring: @${failed_slot}"

    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
        awk -v s="${failed_slot}_backup_" '$NF ~ s {print $NF}' | sort | tail -1)
    BACKUP_NAME="${BACKUP_NAME#@}"

	if [[ -z "$BACKUP_NAME" ]]; then
        log_warn "No backup found for @${failed_slot} — snapshotting @${booted} as fallback"

        if btrfs_subvol_exists "$MOUNT_DIR/@${failed_slot}"; then
            local _nb_pre_delete
            _nb_pre_delete=$(get_booted_subvol)
            if [[ "$failed_slot" == "$_nb_pre_delete" ]]; then
                safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
                die "SAFETY ABORT: @${failed_slot} is the currently booted slot — refusing to touch it"
            fi
            btrfs property set -f -ts "$MOUNT_DIR/@${failed_slot}" ro false 2>/dev/null
            btrfs subvolume delete "$MOUNT_DIR/@${failed_slot}" 2>/dev/null || true
        fi

        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${booted}" "$MOUNT_DIR/@${failed_slot}"
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${failed_slot}" ro true

        echo "$booted"       > "$MOUNT_DIR/@data/current-slot"
        echo "$failed_slot"  > "$MOUNT_DIR/@data/previous-slot"

        btrfs_subvol_exists "$MOUNT_DIR/temp_update/shanios_base" && \
            btrfs subvolume delete "$MOUNT_DIR/temp_update/shanios_base" 2>/dev/null || true
        btrfs_subvol_exists "$MOUNT_DIR/temp_update" && \
            btrfs subvolume delete "$MOUNT_DIR/temp_update" 2>/dev/null || true

        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true

        # Generate UKI from within failed_slot chroot (snapshot of booted, so kernel is identical)
        generate_uki "$failed_slot" || {
            log_warn "UKI generation failed — copying @${booted} UKI as fallback"
            cp "$ESP/EFI/${OS_NAME}/${OS_NAME}-${booted}.efi" \
               "$ESP/EFI/${OS_NAME}/${OS_NAME}-${failed_slot}.efi" 2>/dev/null || true
        }
        finalize_boot_entries "$booted" "$failed_slot"
        log_success "Fallback slot ready"
        log "Please reboot to boot into @${booted}"
        return
    fi

    log "Restoring @${failed_slot} from @${BACKUP_NAME}"

    # SAFETY: re-read booted slot immediately before any destructive operation.
    # Must never touch the booted slot regardless of what variables say.
    local pre_delete_booted
    pre_delete_booted=$(get_booted_subvol)
    if [[ "$failed_slot" == "$pre_delete_booted" ]]; then
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
        die "SAFETY ABORT: @${failed_slot} is the currently booted slot — refusing to touch it"
    fi

    if btrfs_subvol_exists "$MOUNT_DIR/@${failed_slot}"; then
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${failed_slot}" ro false
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${failed_slot}"
    else
        log_warn "@${failed_slot} does not exist — restoring directly from backup without delete"
    fi
    run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${failed_slot}" ro true

    btrfs_subvol_exists "$MOUNT_DIR/temp_update/shanios_base" && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update/shanios_base" 2>/dev/null || true
    btrfs_subvol_exists "$MOUNT_DIR/temp_update" && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update" 2>/dev/null || true

    # Write slot markers before unmount.
    echo "$booted"      > "$MOUNT_DIR/@data/current-slot"
    echo "$failed_slot" > "$MOUNT_DIR/@data/previous-slot"

    safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || umount -R -l "$MOUNT_DIR" 2>/dev/null || die "Cannot unmount before UKI generation"

    # Generate UKI for restored slot — booted slot UKI is already valid.
    generate_uki "$failed_slot" || {
        log_warn "UKI generation failed — copying @${booted} UKI as fallback"
        cp "$ESP/EFI/${OS_NAME}/${OS_NAME}-${booted}.efi" \
           "$ESP/EFI/${OS_NAME}/${OS_NAME}-${failed_slot}.efi" 2>/dev/null || true
    }
    finalize_boot_entries "$booted" "$failed_slot"

    log_success "Rollback complete"
    log "Please reboot to boot into @${booted}"
    trap 'restore_candidate' ERR
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
    (( avail_mb < size_mb )) && { log_warn "Insufficient space"; return 1; }
    
    log "Creating ${size_mb}MB swapfile"
    
    if btrfs filesystem mkswapfile --size "${size_mb}M" "$file" 2>/dev/null; then
        chmod 600 "$file"
        log_success "Swapfile created (btrfs)"
        return 0
    fi
    
    if truncate -s "${size_mb}M" "$file" 2>/dev/null && chmod 600 "$file" && \
       chattr +C "$file" 2>/dev/null && mkswap "$file" &>/dev/null; then
        log_success "Swapfile created (truncate)"
        return 0
    fi
    
    if dd if=/dev/zero of="$file" bs=1M count="$size_mb" status=none 2>/dev/null && \
       chmod 600 "$file" && mkswap "$file" &>/dev/null; then
        log_success "Swapfile created (dd)"
        return 0
    fi
    
    rm -f "$file"
    return 1
}

parse_fstab_bind_dirs() {
    [[ -f "$1" ]] || return 1
    awk '/[[:space:]]bind[,[:space:]]/ && !/^[[:space:]]*#/ {
        if ($4 ~ /bind/ && $1 ~ /^\/data\//) print $1
    }' "$1" | sort -u
}

verify_and_create_subvolumes() {
    log_section "Filesystem Structure Verification"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    trap 'safe_umount "$MOUNT_DIR" 2>/dev/null || force_umount_all "$MOUNT_DIR" || true' RETURN
    
    local fstab="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/fstab"
    if [[ ! -f "$fstab" ]]; then
        log_verbose "No fstab found, skipping verification"
        return 0
    fi
    
    # Check subvolumes from fstab
    mapfile -t required < <(parse_fstab_subvolumes "$fstab")
    
    if [[ ${#required[@]} -eq 0 ]]; then
        log_verbose "No additional subvolumes required"
    else
        log "Required subvolumes: ${required[*]}"
        
        local -a missing=()
        for sub in "${required[@]}"; do
            btrfs_subvol_exists "$MOUNT_DIR/@${sub}" || missing+=("$sub")
        done
        
        if [[ ${#missing[@]} -eq 0 ]]; then
            log_success "All subvolumes exist"
        else
            log "Creating ${#missing[@]} missing subvolume(s)"
            
            for sub in "${missing[@]}"; do
                run_cmd btrfs subvolume create "$MOUNT_DIR/@${sub}"
                
                case "$sub" in
                    swap)
                        [[ "${DRY_RUN}" == "yes" ]] && continue
                        chattr +C "$MOUNT_DIR/@${sub}" 2>/dev/null || \
                            log_warn "Could not set no-COW on @${sub}"
                        
                        local swapfile="$MOUNT_DIR/@${sub}/swapfile"
                        if [[ ! -f "$swapfile" ]]; then
                            local mem=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo "2048")
                            local avail=$(get_btrfs_available_mb "$MOUNT_DIR")
                            create_swapfile "$swapfile" "$mem" "$avail" || \
                                log_warn "Swapfile creation failed"
                        fi
                        ;;
                        
                    data)
					    [[ "${DRY_RUN}" == "yes" ]] && continue
					    mkdir -p "$MOUNT_DIR/@data/overlay/"{etc,var}/{upper,work} 2>/dev/null || \
					        log_warn "Could not create overlay directories"
					    mkdir -p "$MOUNT_DIR/@data/downloads" 2>/dev/null || \
					        log_warn "Could not create downloads directory"
					    
					    # Create varlib and varspool directories for bind mounts
					    mkdir -p "$MOUNT_DIR/@data/varlib" 2>/dev/null || \
					        log_warn "Could not create varlib directory"
					    mkdir -p "$MOUNT_DIR/@data/varspool" 2>/dev/null || \
					        log_warn "Could not create varspool directory"
					    
					    if [[ ! -f "$MOUNT_DIR/@data/current-slot" ]]; then
					        echo "${CURRENT_SLOT:-blue}" > "$MOUNT_DIR/@data/current-slot" 2>/dev/null || \
					            log_warn "Could not create current-slot marker"
					    fi
					    if [[ ! -f "$MOUNT_DIR/@data/previous-slot" ]]; then
					        echo "${CANDIDATE_SLOT:-green}" > "$MOUNT_DIR/@data/previous-slot" 2>/dev/null || \
					            log_warn "Could not create previous-slot marker"
					    fi
					    ;;
                esac
                
                log_success "Created: @${sub}"
            done
        fi
    fi
    
    # Check bind mount directories from fstab
    mapfile -t bind_dirs < <(parse_fstab_bind_dirs "$fstab")
    
    if [[ ${#bind_dirs[@]} -gt 0 ]]; then
        log "Checking ${#bind_dirs[@]} bind mount director(ies)"
        
        local created=0
        for dir in "${bind_dirs[@]}"; do
            local full_path="$MOUNT_DIR/${dir#/}"
            
            if [[ -d "$full_path" ]]; then
                log_verbose "Exists: $dir"
                continue
            fi
            
            if [[ "${DRY_RUN}" == "yes" ]]; then
                log "[DRY-RUN] Would create: $dir"
                ((created++))
            else
                if mkdir -p "$full_path" 2>/dev/null; then
                    log_verbose "Created: $dir"
                    ((created++))
                else
                    log_warn "Failed to create: $dir (non-critical)"
                fi
            fi
        done
        
        if (( created > 0 )); then
            log_success "Created ${created} bind director(ies)"
        fi
    fi
    
    log_success "Filesystem structure verified"
}
#####################################
### Deployment Logic              ###
#####################################
validate_boot() {
    log_section "Boot Validation"
    
    local booted
    booted=$(get_booted_subvol)

    CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null | tr -d '[:space:]')
    
    if [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log_warn "Invalid marker, detecting..."
        CURRENT_SLOT="$booted"
        [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]] && CURRENT_SLOT="blue"
        mkdir -p /data
        echo "$CURRENT_SLOT" > /data/current-slot
        log "Corrected: $CURRENT_SLOT"
    fi
    
    log "Marker: @${CURRENT_SLOT}"
    log "Booted: @${booted}"
    
    if [[ "$booted" != "$CURRENT_SLOT" ]]; then
        if [[ "${FORCE_UPDATE:-no}" == "yes" ]]; then
            log_warn "Boot mismatch: booted=@${booted} marker=@${CURRENT_SLOT} — correcting"
            CURRENT_SLOT="$booted"
            mkdir -p /data
            echo "$CURRENT_SLOT" > /data/current-slot
        else
            if [[ ! -f "$DEPLOY_PENDING" ]]; then
                log_warn "SLOT MISMATCH: marker says @${CURRENT_SLOT} but running @${booted}"
                log_warn "Possible causes:"
                log_warn "  1. Update was deployed but system not yet rebooted — please reboot"
                log_warn "  2. Last update was unbootable and bootloader fell back — run --rollback"
                log_warn "  3. System was booted manually into wrong slot — reboot into @${CURRENT_SLOT} or run --rollback"
                log_warn "To force update from currently running @${booted} regardless: run --force"
                exit 0
            else
                log_error "SLOT MISMATCH: marker says @${CURRENT_SLOT} but running @${booted}"
                log_error "DEPLOY_PENDING flag exists — previous deploy may be incomplete"
                die "Run --rollback to restore, or --force to override and update from @${booted}"
            fi
        fi
    fi
    
    log_success "Validated"
    CANDIDATE_SLOT=$([[ "$CURRENT_SLOT" == "blue" ]] && echo "green" || echo "blue")
    log "Active: @${CURRENT_SLOT} | Candidate: @${CANDIDATE_SLOT}"
}

check_space() {
    log_section "Space Check"
    
    local free_mb=$(( $(df --output=avail "/data" | tail -1) / 1024 ))
    log "Available: ${free_mb}MB | Required: ${MIN_FREE_SPACE_MB}MB"
    
    (( free_mb >= MIN_FREE_SPACE_MB )) || \
        die "Insufficient: ${free_mb}MB < ${MIN_FREE_SPACE_MB}MB"
    
    log_success "Sufficient"
    run_cmd mkdir -p "$DOWNLOAD_DIR"
}

fetch_update() {
    log_section "Update Check"
    
    local sf_url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    local r2_path="${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    local temp=$(mktemp)
    
    log "Checking ${UPDATE_CHANNEL}..."
    download_from_r2 "$r2_path" "$temp" 1 || \
        download_file "$sf_url" "$temp" 1 || { rm -f "$temp"; die "Manifest fetch failed"; }
    
    IMAGE_NAME=$(tr -d '[:space:]' < "$temp")
    rm -f "$temp"
    
    [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]] || die "Invalid manifest"
    
    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"
    
    log "Remote: v${REMOTE_VERSION} (${REMOTE_PROFILE})"
    log "Local:  v${LOCAL_VERSION} (${LOCAL_PROFILE})"

	if (( REMOTE_VERSION < LOCAL_VERSION )); then
        log_warn "Remote older (${REMOTE_VERSION} < ${LOCAL_VERSION})"
        if [[ "${FORCE_UPDATE:-no}" != "yes" ]]; then
            log_success "No update needed"
            touch "${STATE_DIR}/skip-deployment"
            return 0
        fi
        log "Force update requested, downgrading to v${REMOTE_VERSION}"
    fi
    
    (( REMOTE_VERSION > LOCAL_VERSION )) && { log "Update available"; return 0; }
    
    log "Versions match (v${REMOTE_VERSION})"
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    trap 'safe_umount "$MOUNT_DIR" 2>/dev/null || force_umount_all "$MOUNT_DIR" || true' RETURN

    if ! btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        log "Candidate @${CANDIDATE_SLOT} missing — will deploy from remote to recreate"
        return 0
    fi

    if [[ "${FORCE_UPDATE:-no}" == "yes" ]]; then
        log "Force update requested, redeploying v${REMOTE_VERSION}"
        return 0
    fi
    log_success "System up-to-date"
    touch "${STATE_DIR}/skip-deployment"
    return 0
}

download_update() {
    log_section "Download Phase"
    
    validate_nonempty "$IMAGE_NAME" "IMAGE_NAME"
    validate_nonempty "$REMOTE_PROFILE" "REMOTE_PROFILE"
    validate_nonempty "$REMOTE_VERSION" "REMOTE_VERSION"
    
    local image="${DOWNLOAD_DIR}/${IMAGE_NAME}"
    local marker="${image}.verified"
    local sha="${image}.sha256"
    local asc="${image}.asc"
    
    # Check cache
    if [[ -f "$marker" && -f "$image" ]]; then
        local existing_size=$(get_file_size "$image")
        if (( existing_size > 0 )); then
            log_success "Using verified cache: $(format_bytes $existing_size)"
            return 0
        fi
        rm -f "$marker" "$image" "$sha" "$asc" "${image}.aria2"
    fi
    
    # Keep control files for resume - only clean orphaned temp files
    rm -f "${image}.tmp"
    
    [[ "${DRY_RUN}" == "yes" ]] && return 0
    
    # URLs
    local sf_base="https://sourceforge.net/projects/shanios/files"
    local sha_url="${sf_base}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.sha256/download"
    local asc_url="${sf_base}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.asc/download"
    
    # Try R2 first, fall back to SourceForge mirror
    local r2_image_path="${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}"
    local r2_image_url="${R2_BASE_URL}/${r2_image_path}"
    local use_r2=0
    
    if [[ -n "${R2_BASE_URL:-}" ]]; then
        log "Checking R2 availability..."
        local r2_size
        r2_size=$(get_remote_file_size "$r2_image_url")
        if (( r2_size > MIN_FILE_SIZE )); then
            log_success "R2 available ($(format_bytes $r2_size)), using R2"
            use_r2=1
        else
            log_verbose "R2 unavailable or too small, falling back to SourceForge"
        fi
    fi
    
    # Mirror discovery (SourceForge fallback)
    local mirror_url=""
    if (( use_r2 == 0 )); then
        log "Discovering SourceForge mirror..."
        mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
        mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
        [[ -z "$mirror_url" || ! "$mirror_url" =~ ^https?://[a-zA-Z0-9] ]] && die "Mirror discovery failed"
    fi
    
    # Get expected size
    log "Checking remote size..."
    local active_url expected_size
    if (( use_r2 )); then
        active_url="$r2_image_url"
    else
        active_url="$mirror_url"
    fi
    expected_size=$(get_remote_file_size "$active_url")
    (( expected_size > 0 )) && log "Expected: $(format_bytes $expected_size)"
    
    # Check for existing partial download
    if [[ -f "$image" ]]; then
        local current_size=$(get_file_size "$image")
        if (( current_size > 0 )); then
            log "Found partial download: $(format_bytes $current_size)"
            if (( expected_size > 0 )); then
                if (( current_size >= expected_size )); then
                    log "Partial download complete or larger, will verify"
                elif (( current_size < expected_size )); then
                    log "Will resume from $(format_bytes $current_size)"
                fi
            else
                log "Cannot determine expected size, will attempt resume"
            fi
        fi
    fi
    
    local download_success=0
    local global_attempt=0
    local max_global_attempts=5
    local current_mirror="$mirror_url"

    while (( download_success == 0 && global_attempt < max_global_attempts )); do
        ((global_attempt++))
        log "Download attempt ${global_attempt}/${max_global_attempts}"

        local dl_url
        (( use_r2 )) && dl_url="$r2_image_url" || dl_url="$mirror_url"

        # SourceForge doesn't reliably support resume — clear partial before each attempt
        if [[ "$dl_url" != *"downloads.shani.dev"* ]]; then
            [[ -f "$image" ]] && {
                log_verbose "Clearing partial SF download (no resume support)"
                rm -f "$image" "${image}.aria2"
            }
        fi

        if download_file "$dl_url" "$image" 0 "$expected_size"; then
            if [[ ! -f "$image" ]] || [[ ! -s "$image" ]]; then
                log_warn "Download produced no file"
                sleep 5
                continue
            fi
            
            local current_size=$(get_file_size "$image")
            log_verbose "Downloaded: $(format_bytes $current_size)"
            
            # Check if download is complete
            if (( expected_size > 0 )); then
                if (( current_size < expected_size )); then
                    log_warn "Download incomplete: $(format_bytes $current_size) / $(format_bytes $expected_size)"
                    log "Will retry to resume..."
                    sleep 5
                    continue
                elif (( current_size > expected_size )); then
                    log_error "Download too large: $(format_bytes $current_size) > $(format_bytes $expected_size)"
                    rm -f "$image" "${image}.aria2"
                    sleep 5
                    continue
                fi
            fi
            
            download_success=1
            log_success "Downloaded: $(format_bytes $current_size)"
            break
        fi
        
        log_warn "Download attempt ${global_attempt} failed"
        
        # Try mirror rediscovery every 2 failures
        if (( global_attempt % 2 == 0 && global_attempt < max_global_attempts )); then
            # If R2 was failing, fall back to SourceForge
            if (( use_r2 )); then
                log "R2 failing, switching to SourceForge mirror..."
                use_r2=0
                rm -f "$DOWNLOAD_DIR/mirror.url"
                mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
                mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
                continue
            fi
            log "Rediscovering mirror..."
            rm -f "$DOWNLOAD_DIR/mirror.url"
            
            local new_mirror
            new_mirror=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
            new_mirror=$(echo "$new_mirror" | tail -1 | tr -d '\r\n' | xargs)
            
            if [[ -n "$new_mirror" && "$new_mirror" =~ ^https?://[a-zA-Z0-9] ]]; then
                if [[ "$new_mirror" != "$current_mirror" ]]; then
                    log "Switched to new mirror"
                    current_mirror="$new_mirror"
                fi
                mirror_url="$new_mirror"
                expected_size=$(get_remote_file_size "$mirror_url")
            else
                log_warn "Mirror rediscovery failed, using current"
            fi
        fi
        
        if (( global_attempt < max_global_attempts )); then
            local delay=$((5 + global_attempt * 5))
            log "Retrying in ${delay}s..."
            sleep "$delay"
        fi
    done
    
    if [[ $download_success -eq 0 ]]; then
        rm -f "$image" "${image}.aria2"
        die "Download failed after $max_global_attempts attempts"
    fi
    
    validate_download "$image" "$expected_size" || { 
        rm -f "$image" "${image}.aria2"
        die "Validation failed"
    }
    
    log "Downloading verification files..."
    download_from_r2 "${r2_image_path}.sha256" "$sha" 1 || \
        download_file "$sha_url" "$sha" 1 || { 
            rm -f "$image" "${image}.aria2"
            die "SHA256 download failed"
        }
    download_from_r2 "${r2_image_path}.asc" "$asc" 1 || \
        download_file "$asc_url" "$asc" 1 || { 
            rm -f "$image" "$sha" "${image}.aria2"
            die "GPG signature download failed"
        }
    
    verify_sha256 "$image" "$sha" && verify_gpg "$image" "$asc" || { 
        rm -f "$image" "$sha" "$asc" "${image}.aria2"
        die "Verification failed"
    }
    
    # Clean up all control files on successful verification
    rm -f "$DOWNLOAD_DIR/mirror.url" "${image}.aria2"
    touch "$marker"
    log_success "Download and verification complete"
}

deploy_update() {
    log_section "Deployment Phase"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    trap 'safe_umount "$MOUNT_DIR" 2>/dev/null || force_umount_all "$MOUNT_DIR" || true' RETURN
    
	if findmnt -S "$ROOT_DEV" -o TARGET,OPTIONS | grep -qE "subvol=/@${CANDIDATE_SLOT}([^a-zA-Z]|$)"; then
        die "Candidate subvolume is currently mounted"
    fi

    # SAFETY: confirm candidate is not the booted slot before any destructive operation.
    local deploy_booted
    deploy_booted=$(get_booted_subvol)
    if [[ "$CANDIDATE_SLOT" == "$deploy_booted" ]]; then
        safe_umount "$MOUNT_DIR"
        die "SAFETY ABORT: @${CANDIDATE_SLOT} is the currently booted slot — refusing to touch it"
    fi

    # Backup only — do NOT delete candidate yet. Deletion happens after extraction
    # succeeds so power failure during extraction leaves @CANDIDATE_SLOT intact.
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        log "Backup: @${BACKUP_NAME}"
        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}" || \
            { safe_umount "$MOUNT_DIR"; die "Backup failed"; }
    fi

    local temp="$MOUNT_DIR/temp_update"
    if btrfs_subvol_exists "$temp"; then
        btrfs_subvol_exists "$temp/shanios_base" && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
        btrfs subvolume delete "$temp" 2>/dev/null
    fi

    log "Creating extraction subvolume..."
    run_cmd btrfs subvolume create "$temp"

    log "Extracting image..."
    [[ "${DRY_RUN}" == "yes" ]] && { log "[DRY-RUN] Would extract"; } || {
        local start=$(date +%s)
        if (( HAS_PV )); then
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                pv -p -t -e -r -b | btrfs receive "$temp" || {
                btrfs_subvol_exists "$temp/shanios_base" && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
                btrfs subvolume delete "$temp" 2>/dev/null
                safe_umount "$MOUNT_DIR"
                die "Extraction failed"
            }
        else
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                btrfs receive "$temp" || {
                btrfs_subvol_exists "$temp/shanios_base" && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
                btrfs subvolume delete "$temp" 2>/dev/null
                safe_umount "$MOUNT_DIR"
                die "Extraction failed"
            }
        fi
        log_success "Extracted in $(($(date +%s) - start))s"
    }

    # Extraction succeeded — now safe to replace candidate.
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    fi

    log "Snapshotting..."
    run_cmd btrfs subvolume snapshot "$temp/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true

    btrfs_subvol_exists "$temp/shanios_base" && run_cmd btrfs subvolume delete "$temp/shanios_base"
    run_cmd btrfs subvolume delete "$temp"
    
    [[ "${DRY_RUN}" == "no" ]] && touch "$DEPLOY_PENDING"
    log_success "Deployed"
}

finalize_update() {
    log_section "Finalization"
    [[ "${DRY_RUN}" == "yes" ]] && return 0

    verify_and_create_subvolumes || die "Subvolume verification failed"
    generate_uki "$CANDIDATE_SLOT" || die "UKI generation failed"
    finalize_boot_entries "$CANDIDATE_SLOT" "$CURRENT_SLOT"

    mkdir -p /data
    echo "$CURRENT_SLOT" > /data/previous-slot || die "Failed to write previous-slot"
    echo "$CANDIDATE_SLOT" > /data/current-slot || die "Failed to write current-slot"

    rm -f "$DEPLOY_PENDING" || log_warn "Failed to remove deployment pending flag"
    log_success "Deployment complete"
    
    trap - ERR
    set +e
    
    # Ensure clean mount state before maintenance
    if is_mounted "$MOUNT_DIR"; then
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
    fi
    
    mkdir -p "$MOUNT_DIR"
    if mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null; then
        cleanup_old_backups || log_verbose "Backup cleanup warnings"
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
    else
        log_verbose "Could not mount for maintenance"
    fi
    
    cleanup_downloads || log_verbose "Download cleanup warnings"
    
    # Storage info shown after deployment so user can see current state
    analyze_storage || log_verbose "Storage analysis warnings"
    
    set -e
    trap 'restore_candidate' ERR
    
    log_success "Complete"
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
  -r, --rollback          Force rollback
  -c, --cleanup           Manual cleanup
  -s, --storage-info      Storage analysis (read-only)
  -o, --optimize          Run manual deduplication (maintenance only; bees handles continuous dedup)
  -t, --channel <chan>    Update channel (latest|stable)
  -f, --force             Deploy even if version matches or boot mismatch
  -d, --dry-run           Simulate
  -v, --verbose           Verbose output
  --skip-self-update      Skip auto-update
EOF
}

main() {
    local ROLLBACK="no" CLEANUP="no" STORAGE_INFO="no" STORAGE_OPTIMIZE="no"
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            -r|--rollback) ROLLBACK="yes"; shift ;;
            -c|--cleanup) CLEANUP="yes"; shift ;;
            -s|--storage-info) STORAGE_INFO="yes"; shift ;;
            -o|--optimize) STORAGE_OPTIMIZE="yes"; shift ;;
            -t|--channel) UPDATE_CHANNEL="$2"; shift 2 ;;
            -f|--force) FORCE_UPDATE="yes"; shift ;;
            -d|--dry-run) DRY_RUN="yes"; shift ;;
            -v|--verbose) VERBOSE="yes"; shift ;;
            --skip-self-update) SKIP_SELF_UPDATE="yes"; shift ;;
            --) shift; break ;;
            *) die "Invalid option: $1" ;;
        esac
    done
       
    check_root
    check_tools
    set_update_channel "${UPDATE_CHANNEL:-}"
    set_environment
    [[ "$ROLLBACK" == "yes" ]] && { rollback_system; exit 0; }

    if [[ "$CLEANUP" == "yes" ]]; then
        trap - ERR
        set +e

        if is_mounted "$MOUNT_DIR"; then
            log_verbose "Cleaning up existing mount before cleanup"
            safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
        fi

        mkdir -p "$MOUNT_DIR"
        if mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null; then
            cleanup_old_backups
            safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
        else
            log_verbose "Could not mount for cleanup"
        fi
        cleanup_downloads
        analyze_storage || log_verbose "Storage analysis warnings"

        log_success "Manual cleanup complete"
        exit 0
    fi

    if [[ "$STORAGE_INFO" == "yes" ]]; then
        analyze_storage
        exit 0
    fi
	
    if [[ "$STORAGE_OPTIMIZE" == "yes" ]]; then
        optimize_storage
        exit 0
    fi

	check_internet
    self_update
    persist_state
    inhibit_system
	validate_boot
    check_space
    fetch_update
    
    if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
        log "No deployment needed, running maintenance"
        
        trap - ERR
        set +e
        
        # Ensure clean mount state
        if is_mounted "$MOUNT_DIR"; then
            log_verbose "Cleaning up existing mount before maintenance"
            safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
        fi
        
        mkdir -p "$MOUNT_DIR"
        if mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null; then
            if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
                cleanup_old_backups || log_verbose "Backup cleanup warnings"
            fi
            safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
        else
            log_verbose "Could not mount for maintenance"
        fi

        cleanup_downloads || log_verbose "Download cleanup warnings"
        analyze_storage || log_verbose "Storage analysis warnings"
        
        log_success "Maintenance complete"
        exit 0
    fi
    
    download_update || die "Download failed"
    deploy_update || die "Deployment failed"
    [[ -f "$DEPLOY_PENDING" ]] && finalize_update
    
    log_success "Done"
}

main "$@"
