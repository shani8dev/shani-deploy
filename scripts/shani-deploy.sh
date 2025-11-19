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
#   -t, --channel <chan>    Update channel: latest|stable (default: stable)
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
        
        if [[ -n "$state_content" ]]; then
            eval "$state_content" 2>/dev/null || true
        fi
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

readonly MAX_INHIBIT_DEPTH=2
readonly MAX_DOWNLOAD_ATTEMPTS=5
readonly EXTRACTION_TIMEOUT=1800

declare -g HAS_ARIA2C=0 HAS_WGET=0 HAS_CURL=0 HAS_PV=0
command -v aria2c &>/dev/null && HAS_ARIA2C=1
command -v wget &>/dev/null && HAS_WGET=1
command -v curl &>/dev/null && HAS_CURL=1
command -v pv &>/dev/null && HAS_PV=1

declare -g LOCAL_VERSION LOCAL_PROFILE
declare -g BACKUP_NAME="" CURRENT_SLOT="" CANDIDATE_SLOT=""
declare -g REMOTE_VERSION="" REMOTE_PROFILE="" IMAGE_NAME=""
declare -g UPDATE_CHANNEL="" UPDATE_CHANNEL_SOURCE="" SELF_UPDATE_DONE=""
declare -g DRY_RUN="no" VERBOSE="no" SKIP_SELF_UPDATE="no"

readonly CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp)
readonly CHROOT_STATIC_DIRS=(data etc var)

#####################################
### State Management              ###
#####################################

STATE_DIR=$(mktemp -d /tmp/shanios-deploy-state.XXXXXX)
export STATE_DIR

cleanup_state() {
    local state_dir="${STATE_DIR:-}"
    if [[ -n "$state_dir" && -d "$state_dir" ]]; then
        rm -rf "$state_dir" 2>/dev/null || true
    fi
}
trap cleanup_state EXIT

persist_state() {
    local state_file
    state_file=$(mktemp /tmp/shanios_deploy_state.XXXX)
    {
        declare -p LOCAL_VERSION LOCAL_PROFILE BACKUP_NAME CURRENT_SLOT CANDIDATE_SLOT 2>/dev/null || true
        declare -p REMOTE_VERSION REMOTE_PROFILE IMAGE_NAME UPDATE_CHANNEL UPDATE_CHANNEL_SOURCE 2>/dev/null || true
        declare -p VERBOSE DRY_RUN SKIP_SELF_UPDATE 2>/dev/null || true
        declare -p STATE_DIR 2>/dev/null || true
        declare -p HAS_ARIA2C HAS_WGET HAS_CURL HAS_PV 2>/dev/null || true
        declare -p SELF_UPDATE_DONE 2>/dev/null || true
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
        else
            log_verbose "Empty or invalid channel file format"
        fi
    else
        log_verbose "Channel file not found: $CHANNEL_FILE"
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
    local target="$1"
    [[ -n "$target" ]] || return 1
    findmnt -M "$target" &>/dev/null
}

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    [[ -n "$src" && -n "$tgt" ]] || die "safe_mount: Invalid arguments"
    
    is_mounted "$tgt" && return 0
    
    log_verbose "Mounting: $src -> $tgt (opts: $opts)"
    run_cmd mount -o "$opts" "$src" "$tgt" || die "Failed to mount $tgt"
}

safe_umount() {
    local tgt="$1"
    [[ -n "$tgt" ]] || return 1
    
    is_mounted "$tgt" || return 0
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] Would unmount: $tgt"
        return 0
    fi
    
    local attempt=0
    local max_attempts=3
    
    while (( attempt < max_attempts )); do
        ((attempt++))
        
        if umount -R "$tgt" 2>/dev/null; then
            log_verbose "Unmounted: $tgt (attempt $attempt)"
            return 0
        fi
        
        if ! is_mounted "$tgt"; then
            log_verbose "Mount disappeared: $tgt"
            return 0
        fi
        
        if (( attempt < max_attempts )); then
            log_verbose "Unmount retry $attempt/$max_attempts: $tgt"
            sleep 1
        fi
    done
    
    if umount -l "$tgt" 2>/dev/null; then
        log_warn "Lazy unmount used: $tgt"
        return 0
    fi
    
    log_warn "Failed to unmount: $tgt"
    return 1
}

force_umount_all() {
    local base_dir="$1"
    [[ -n "$base_dir" ]] || return 1
    
    log_verbose "Force unmounting all under: $base_dir"
    
    local -a mounts
    mapfile -t mounts < <(
        findmnt -R -o TARGET -n "$base_dir" 2>/dev/null | sort -r || true
    )
    
    if [[ ${#mounts[@]} -eq 0 ]]; then
        log_verbose "No mounts found under: $base_dir"
        return 0
    fi
    
    for mount in "${mounts[@]}"; do
        [[ -n "$mount" ]] || continue
        safe_umount "$mount" || log_verbose "Could not unmount: $mount"
    done
    
    if is_mounted "$base_dir"; then
        log_warn "Base mount still exists after cleanup: $base_dir"
        umount -fl "$base_dir" 2>/dev/null || true
        return 1
    fi
    
    return 0
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
    
    if (( HAS_WGET )); then
        size=$(timeout 20 wget -q --spider -S \
            --timeout=15 \
            --tries=1 \
            "$url" 2>&1 | \
            awk '/Content-Length:/ {print $2}' | \
            tail -1 | \
            tr -d '\r' || echo "0")
    elif (( HAS_CURL )); then
        size=$(timeout 20 curl -sI \
            --connect-timeout 8 \
            --max-time 15 \
            "$url" 2>/dev/null | \
            grep -i "content-length:" | \
            tail -1 | \
            awk '{print $2}' | \
            tr -d '\r' || echo "0")
    fi
    
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size > 0 )); then
        echo "$size"
    else
        echo "0"
    fi
}

discover_mirror() {
    local sf_url="$1"
    
    if (( HAS_WGET )); then
        log_verbose "Attempting wget discovery with redirect chain"
        
        local spider_output
        spider_output=$(timeout 30 wget --max-redirect=20 --spider -S "$sf_url" 2>&1 >/dev/null | \
            grep -E '^ +(HTTP|Location):' || echo "")
        
        if [[ "${VERBOSE}" == "yes" ]]; then
            log_verbose "Spider output:"
            echo "$spider_output" | head -20 >&2
        fi
        
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
        else
            log_verbose "URL validation failed or empty"
        fi
    fi
    
    if (( HAS_CURL )); then
        log_verbose "Attempting curl discovery"
        local discovered
        discovered=$(timeout 30 curl -sL -w '%{url_effective}' \
            --max-redirs 20 \
            --connect-timeout 10 \
            --max-time 25 \
            -o /dev/null \
            "$sf_url" 2>/dev/null | \
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
    
    echo ""
}

validate_mirror() {
    local mirror_url="$1"
    
    [[ -z "$mirror_url" ]] && return 1
    
    log_verbose "Validating mirror: $mirror_url"
    
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
    
    if [[ -f "$mirror_cache" ]]; then
        local cached
        cached=$(cat "$mirror_cache" 2>/dev/null | head -1 | tr -d '\r\n' | xargs)
        if [[ -n "$cached" ]]; then
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
    
    local sf_url="https://sourceforge.net/projects/${project}/files/${filepath}/${filename}/download"
    
    log "Discovering mirror from SourceForge..."
    
    local base_url
    base_url=$(discover_mirror "$sf_url")
    
    if [[ -n "$base_url" ]]; then
        base_url=$(echo "$base_url" | tr -d '\r\n' | xargs)
        
        log_verbose "Discovered base URL: $base_url"
        
        if [[ ! "$base_url" =~ ^https?://[a-zA-Z0-9] ]]; then
            log_warn "Discovered base_url has invalid format: ${base_url:0:100}"
            base_url=""
        fi
    else
        log_verbose "No base URL discovered"
    fi
    
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
    
    log_warn "Mirror discovery failed, using SourceForge direct"
    local fallback_url="https://sourceforge.net/projects/${project}/files/${filepath}/${filename}/download"
    
    echo "$fallback_url"
    return 0
}

#####################################
### Download System               ###
#####################################

validate_download() {
    local file="$1" expected_size="${2:-0}"
    
    [[ -f "$file" ]] || { log_error "File not found: $file"; return 1; }
    
    local size
    size=$(get_file_size "$file")
    
    local min_size="$MIN_FILE_SIZE"
    if (( expected_size > 0 )); then
        min_size="$expected_size"
    fi
    
    if (( size < min_size )); then
        log_error "File too small: $(format_bytes $size) < $(format_bytes $min_size)"
        return 1
    fi
    
    if file "$file" 2>/dev/null | grep -qi "html\|xml"; then
        log_error "File appears to be error page (HTML/XML)"
        return 1
    fi
    
    if [[ "$file" == *.zst ]] && ! file "$file" 2>/dev/null | grep -qi "zstandard"; then
        log_warn "File extension .zst but wrong content type"
        return 1
    fi
    
    log_verbose "Validation passed: $(format_bytes $size)"
    return 0
}

download_with_tool() {
    local tool="$1" url="$2" output="$3"
    
    url=$(echo "$url" | tr -d '\r\n' | xargs)
    
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
    
    local resume_supported=0
    if [[ -f "$output" ]] && [[ -s "$output" ]]; then
        local partial_size=$(get_file_size "$output")
        
        if (( partial_size > 0 )); then
            log_verbose "Found partial download: $(format_bytes $partial_size)"
            
            if timeout 10 wget --spider -S "$url" 2>&1 | grep -qi "Accept-Ranges.*bytes"; then
                log_verbose "Server supports resume"
                resume_supported=1
            else
                log_verbose "Server doesn't support resume, will restart download"
                rm -f "$output"
            fi
        fi
    fi
    
    case "$tool" in
        aria2c)
            aria2c \
                --max-connection-per-server=1 --split=1 \
                --continue=true --allow-overwrite=true --auto-file-renaming=false \
                --conditional-get=true --remote-time=true \
                --timeout=30 --max-tries=3 --retry-wait=3 \
                --console-log-level=error --summary-interval=0 \
                --truncate-console-readout=true \
                --dir="$(dirname "$output")" --out="$(basename "$output")" \
                "$url"
            ;;
        wget)
            if (( resume_supported )); then
                wget "${wget_base_opts[@]}" --continue -O "$output" "$url"
            else
                wget "${wget_base_opts[@]}" -O "$output" "$url"
            fi
            ;;
        curl)
            curl --fail --location --max-time 300 --retry 3 --retry-delay 3 \
                --continue-at - --create-dirs --output "$output" \
                --progress-bar --remote-time "$url"
            ;;
        *)
            return 1
            ;;
    esac
}

download_file() {
    local url="$1" output="$2" is_small="${3:-0}"
    
    mkdir -p "$(dirname "$output")"
    
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
    
    local -a downloaders=()
    (( HAS_ARIA2C )) && downloaders+=(aria2c)
    (( HAS_WGET )) && downloaders+=(wget)
    (( HAS_CURL )) && downloaders+=(curl)
    
    if [[ ${#downloaders[@]} -eq 0 ]]; then
        log_error "No download tools available"
        return 1
    fi
    
    for tool in "${downloaders[@]}"; do
        log_verbose "Trying $tool..."
        if download_with_tool "$tool" "$url" "$output"; then
            if [[ -f "$output" ]] && [[ -s "$output" ]]; then
                return 0
            else
                log_verbose "$tool completed but no output file"
                rm -f "$output"
            fi
        fi
        log_verbose "$tool failed"
    done
    
    return 1
}

#####################################
### Verification                  ###
#####################################

verify_sha256() {
    local file="$1" sha_file="$2"
    log_verbose "Verifying SHA256"
    
    local expected actual
    expected=$(awk '{print $1}' "$sha_file" 2>/dev/null | head -1 | tr -d '[:space:]')
    actual=$(sha256sum "$file" 2>/dev/null | awk '{print $1}' | tr -d '[:space:]')
    
    if [[ -z "$expected" || -z "$actual" ]]; then
        log_error "SHA256 verification failed: missing checksums"
        return 1
    fi
    
    log_verbose "Expected: $expected"
    log_verbose "Actual: $actual"
    
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
    
    local gpg_temp
    gpg_temp=$(mktemp -d) || { log_error "Failed to create GPG temp dir"; return 1; }
    
    local old_gnupghome="${GNUPGHOME:-}"
    export GNUPGHOME="$gpg_temp"
    chmod 700 "$gpg_temp"
    
    local result=1
    local keyservers=(keys.openpgp.org keyserver.ubuntu.com pgp.mit.edu)
    
    local imported=0
    for keyserver in "${keyservers[@]}"; do
        if gpg --batch --quiet --keyserver "$keyserver" --recv-keys "$GPG_KEY_ID" 2>/dev/null; then
            imported=1
            log_verbose "Key imported from: $keyserver"
            break
        fi
    done
    
    if [[ $imported -eq 0 ]]; then
        log_error "Failed to import GPG key from all keyservers"
        rm -rf "$gpg_temp"
        [[ -n "$old_gnupghome" ]] && export GNUPGHOME="$old_gnupghome" || unset GNUPGHOME
        return 1
    fi
    
    local fp
    fp=$(gpg --batch --with-colons --fingerprint "$GPG_KEY_ID" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
    if [[ "$fp" != "$GPG_KEY_ID" ]]; then
        log_error "GPG fingerprint mismatch"
        log_error "Expected: $GPG_KEY_ID"
        log_error "Got: ${fp:-none}"
        rm -rf "$gpg_temp"
        [[ -n "$old_gnupghome" ]] && export GNUPGHOME="$old_gnupghome" || unset GNUPGHOME
        return 1
    fi
    
    if gpg --batch --verify "$sig" "$file" 2>/dev/null; then
        log_success "GPG signature verified"
        result=0
    else
        log_error "GPG signature verification failed"
        result=1
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
    if [[ -n "${SELF_UPDATE_DONE:-}" ]] || \
       [[ "${SKIP_SELF_UPDATE}" == "yes" ]] || \
       [[ -f "$DEPLOY_PENDING" ]]; then
        return 0
    fi
    
    export SELF_UPDATE_DONE=1
    persist_state

    local url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
    local temp
    temp=$(mktemp)

    log_verbose "Checking for updates..."
    
    if download_file "$url" "$temp" 1; then
        if grep -q "#!/bin/bash" "$temp" && grep -q "shanios-deploy" "$temp"; then
            if ! cmp -s "$0" "$temp"; then
                chmod +x "$temp"
                log_success "Updated, re-executing..."
                if [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]]; then
                    exec /bin/bash "$temp" "${ORIGINAL_ARGS[@]}"
                else
                    exec /bin/bash "$temp"
                fi
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
    
    if [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]]; then
        exec systemd-inhibit \
            --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" \
            --why="System update in progress" \
            "$0" "${ORIGINAL_ARGS[@]}"
    else
        exec systemd-inhibit \
            --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" \
            --why="System update in progress" \
            "$0"
    fi
}

#####################################
### Cleanup Functions             ###
#####################################

cleanup_old_backups() {
    log_verbose "Cleaning backups"

    set +e
    
    if ! is_mounted "$MOUNT_DIR"; then
        log_verbose "Mount point not available, skipping backup cleanup"
        set -e
        return 0
    fi

    for slot in blue green; do
        log_verbose "Checking for old backups in slot '${slot}'..."

        mapfile -t backups < <(
            btrfs subvolume list "$MOUNT_DIR" 2>/dev/null |
            awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' |
            sort -r
        )

        local backup_count=${#backups[@]}

        if (( backup_count == 0 )); then
            log_verbose "No backups found for slot '${slot}'"
            continue
        fi

        log_verbose "Found ${backup_count} backup(s) for slot '${slot}'"

        if (( backup_count > 1 )); then
            log "Keeping the most recent backup and deleting $((backup_count-1)) older backup(s) for slot '${slot}'"

            for (( i=1; i<backup_count; i++ )); do
                local backup="${backups[i]}"
                local clean_backup="${backup#@}"

                if [[ ! "$clean_backup" =~ ^(blue|green)_backup_[0-9]{10,12}$ ]]; then
                    log_warn "Skipping deletion for backup with unexpected name format: ${backup}"
                    continue
                fi

                if [[ -n "${BACKUP_NAME:-}" ]] && [[ "$backup" == "@${BACKUP_NAME}" ]]; then
                    log_verbose "Skipping current backup: ${backup}"
                    continue
                fi

                if [[ "${DRY_RUN}" == "yes" ]]; then
                    log "[DRY-RUN] Would delete old backup: ${backup}"
                elif btrfs subvolume delete "$MOUNT_DIR/${backup}" &>/dev/null; then
                    log_success "Deleted old backup: ${backup}"
                else
                    log_warn "Failed to delete backup: ${backup}"
                fi
            done
        else
            log_verbose "Only the latest backup exists for slot '${slot}'; no cleanup needed"
        fi
    done

    set -e
    return 0
}

cleanup_downloads() {
    log_verbose "Cleaning downloads"
    
    [[ ! -d "$DOWNLOAD_DIR" ]] && return 0
    
    local latest_image
    latest_image=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst" -printf "%T@ %p\n" 2>/dev/null | \
        sort -rn | head -1 | cut -d' ' -f2-)
    
    local count=0 protected=0
    
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        
        if [[ -n "$latest_image" ]]; then
            local basename
            basename=$(basename "$file")
            local latest_basename
            latest_basename=$(basename "$latest_image")
            
            if [[ "$basename" == "$latest_basename" ]] || \
               [[ "$basename" == "${latest_basename}.sha256" ]] || \
               [[ "$basename" == "${latest_basename}.asc" ]] || \
               [[ "$basename" == "${latest_basename}.verified" ]]; then
                log_verbose "Protecting: $basename"
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
        else
            log_warn "Failed to delete: $(basename "$file")"
        fi
    done < <(find "$DOWNLOAD_DIR" -maxdepth 1 -type f \
        \( -name "shanios-*.zst*" -o -name "*.aria2" -o -name "*.part" -o -name "*.tmp" \) \
        -mtime +7 2>/dev/null)
    
    if (( count > 0 )); then
        log "Cleaned $count old download(s)"
    fi
    
    if (( protected > 0 )); then
        log_verbose "Protected $protected current file(s)"
    fi
    
    return 0
}

# Consolidated mount_for_operation function
mount_for_operation() {
    local operation="$1"
    
    if is_mounted "$MOUNT_DIR"; then
        log_verbose "Already mounted for $operation"
        return 0
    fi
    
    mkdir -p "$MOUNT_DIR" || { log_error "Cannot create mount directory"; return 1; }
    
    if ! mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null; then
        log_error "Cannot mount for $operation"
        return 1
    fi
    
    if ! is_mounted "$MOUNT_DIR"; then
        log_error "Mount verification failed for $operation"
        return 1
    fi
    
    log_verbose "Mounted for $operation"
    return 0
}

analyze_storage() {
    set +e
    
    log_section "Storage Analysis"

    if [[ -f "$DEPLOY_PENDING" ]]; then
        log_warn "Deployment pending, skipping storage analysis"
        set -e
        return 0
    fi

    if ! mount_for_operation "storage analysis"; then
        set -e
        return 1
    fi
    
    trap 'force_umount_all "$MOUNT_DIR" 2>/dev/null || true' RETURN

    local -a check_subvols=(blue green data swap)

    echo ""
    log "=== Pre-Deduplication State ==="
    echo ""

    log "Filesystem Usage:"
    if ! btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /'; then
        log_warn "Failed to retrieve filesystem usage"
    fi

    echo ""
    log "Subvolume Compression Analysis:"
    for subvol in "${check_subvols[@]}"; do
        local path="$MOUNT_DIR/@${subvol}"
        if [[ -d "$path" ]]; then
            echo ""
            log "@${subvol}:"
            if command -v compsize &>/dev/null; then
                compsize -x "$path" 2>/dev/null || log_verbose "compsize unavailable for @${subvol}"
            else
                btrfs filesystem du -s "$path" 2>/dev/null || log_verbose "btrfs du unavailable for @${subvol}"
            fi
        else
            log_verbose "@${subvol}: Missing"
        fi
    done

    if ! btrfs subvolume show "$MOUNT_DIR/@blue" &>/dev/null || \
       ! btrfs subvolume show "$MOUNT_DIR/@green" &>/dev/null; then
        log_verbose "Skipping deduplication (missing required subvolumes)"
        echo ""
        set -e
        return 0
    fi

    local -a targets=("$MOUNT_DIR/@blue" "$MOUNT_DIR/@green")
    local backup_count=0
    
    while IFS= read -r backup; do
        if [[ -n "$backup" ]]; then
            targets+=("$MOUNT_DIR/${backup}")
            ((backup_count++))
        fi
    done < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | awk '$NF ~ /_backup_/ {print $NF}')

    echo ""
    log "=== Running Deduplication ==="
    log "This may take several minutes depending on data size..."
    echo ""

    mkdir -p "$MOUNT_DIR/@data" 2>/dev/null || true

    local dedupe_start
    dedupe_start=$(date +%s)

    local dedupe_status=0
    duperemove -dhr --skip-zeroes \
        --dedupe-options=same,partial \
        -b 128K \
        --batchsize=256 \
        --io-threads="$(nproc)" \
        --cpu-threads="$(nproc)" \
        --hashfile="$MOUNT_DIR/@data/.dedupe.db" \
        "${targets[@]}" 2>&1 || dedupe_status=$?

    local dedupe_duration=$(( $(date +%s) - dedupe_start ))

    echo ""
    if [[ $dedupe_status -eq 0 ]]; then
        log_success "Deduplication completed in ${dedupe_duration}s"
    else
        log_warn "Deduplication completed with warnings (exit code: $dedupe_status, duration: ${dedupe_duration}s)"
    fi

    echo ""
    log "=== Post-Deduplication Results ==="
    echo ""

    for subvol in "${check_subvols[@]}"; do
        local path="$MOUNT_DIR/@${subvol}"
        if [[ -d "$path" ]]; then
            echo ""
            log "@${subvol}:"
            if command -v compsize &>/dev/null; then
                compsize -x "$path" 2>/dev/null || log_verbose "compsize unavailable for @${subvol}"
            else
                btrfs filesystem du -s "$path" 2>/dev/null || log_verbose "btrfs du unavailable for @${subvol}"
            fi
        fi
    done

    echo ""
    log "Final Filesystem Usage:"
    btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /' || true

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
}

cleanup_chroot() {
    log_verbose "Cleaning chroot"
    
    set +e
    
    force_umount_all "$MOUNT_DIR"
    
    set -e
}

generate_uki() {
    local slot="$1"
    
    log_section "UKI Generation"
    [[ -x "$GENEFI_SCRIPT" ]] || die "gen-efi not found"
    
    force_umount_all "$MOUNT_DIR" 2>/dev/null || true
    
    prepare_chroot "$slot"
    
    [[ "${DRY_RUN}" == "yes" ]] && {
        cleanup_chroot
        return 0
    }
    
    log "Generating UKI for @${slot}..."
    
    local result=0
    if chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$slot"; then
        log_success "UKI complete"
        result=0
    else
        log_error "UKI generation failed"
        result=1
    fi
    
    cleanup_chroot
    return $result
}

#####################################
### Rollback                      ###
#####################################

restore_candidate() {
    log_error "Initiating rollback"
    
    trap - ERR EXIT
    set +e
    
    force_umount_all "$MOUNT_DIR" 2>/dev/null || true
    
    if ! mount_for_operation "rollback"; then
        log_error "Cannot mount for rollback"
        rm -f "$DEPLOY_PENDING" 2>/dev/null
        exit 1
    fi
    
    if [[ -n "$BACKUP_NAME" ]] && btrfs_subvol_exists "$MOUNT_DIR/@${BACKUP_NAME}"; then
        log "Restoring from @${BACKUP_NAME}"
        btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false 2>/dev/null
        btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null
        btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null
        btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true 2>/dev/null
        
        log "Restoring slot markers..."
        echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot" 2>/dev/null || \
            log_warn "Failed to restore current-slot marker"
        
        local prev_slot
        prev_slot=$(cat "$MOUNT_DIR/@data/previous-slot" 2>/dev/null | tr -d '[:space:]')
        
        if [[ "$prev_slot" == "$CANDIDATE_SLOT" ]] || [[ -z "$prev_slot" ]]; then
            echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/previous-slot" 2>/dev/null || \
                log_warn "Failed to restore previous-slot marker"
            log_verbose "Restored previous-slot: $CURRENT_SLOT"
        else
            log_verbose "Preserved previous-slot: $prev_slot"
        fi
    fi
    
    [[ -d "$MOUNT_DIR/temp_update/shanios_base" ]] && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update/shanios_base" 2>/dev/null
    [[ -d "$MOUNT_DIR/temp_update" ]] && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update" 2>/dev/null
    
    force_umount_all "$MOUNT_DIR" 2>/dev/null || true
    rm -f "$DEPLOY_PENDING" 2>/dev/null
    
    log_error "Rollback complete - system remains on @${CURRENT_SLOT}"
    exit 1
}
trap 'restore_candidate' ERR

rollback_system() {
    log_section "System Rollback"
    
    force_umount_all "$MOUNT_DIR" 2>/dev/null || true
    
    if ! mount_for_operation "rollback"; then
        die "Cannot mount for rollback"
    fi
    
    local failed_slot previous_slot
    
    failed_slot=$(cat "$MOUNT_DIR/@data/current-slot" 2>/dev/null | tr -d '[:space:]')
    [[ -z "$failed_slot" ]] && failed_slot=$(get_booted_subvol)
    
    previous_slot=$(cat "$MOUNT_DIR/@data/previous-slot" 2>/dev/null | tr -d '[:space:]')
    [[ -z "$previous_slot" ]] && previous_slot=$([[ "$failed_slot" == "blue" ]] && echo "green" || echo "blue")
    
    log "Rollback: ${failed_slot} → ${previous_slot}"
    
    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
        awk -v s="${failed_slot}" '$0 ~ s"_backup" {print $NF}' | sort | tail -1)
    
    [[ -z "$BACKUP_NAME" ]] && die "No backup found"
    
    log "Using: @${BACKUP_NAME}"
    
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro false
    run_cmd btrfs subvolume delete "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro true
    
    echo "$previous_slot" > "$MOUNT_DIR/@data/current-slot"
    
    safe_umount "$MOUNT_DIR"
    
    generate_uki "$previous_slot"
    
    log_success "Rollback complete"
    log "System will boot: @${previous_slot}"
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

parse_fstab_bind_dirs() {
    [[ -f "$1" ]] || return 1
    awk '/[[:space:]]bind[,[:space:]]/ && !/^[[:space:]]*#/ {
        if ($4 ~ /bind/ && $1 ~ /^\/data\//) print $1
    }' "$1" | sort -u
}

create_swapfile() {
    local file="$1" size_mb="$2" avail_mb="$3"
    
    (( avail_mb < size_mb )) && { log_warn "Insufficient space for swap"; return 1; }
    
    log "Creating ${size_mb}MB swapfile"
    
    if btrfs filesystem mkswapfile --size "${size_mb}M" "$file" 2>/dev/null; then
        chmod 600 "$file"
        log_success "Swapfile created (btrfs)"
        return 0
    fi
    
    if truncate -s "${size_mb}M" "$file" 2>/dev/null && \
       chmod 600 "$file" && chattr +C "$file" 2>/dev/null && mkswap "$file" &>/dev/null; then
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

verify_and_create_filesystem_structure() {
    log_section "Filesystem Structure Verification"
    
    force_umount_all "$MOUNT_DIR" 2>/dev/null || true
    
    if ! mount_for_operation "filesystem verification"; then
        return 0
    fi
    
    local fstab="$MOUNT_DIR/@${CANDIDATE_SLOT}/etc/fstab"
    if [[ ! -f "$fstab" ]]; then
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    mapfile -t required < <(parse_fstab_subvolumes "$fstab")
    
    if [[ ${#required[@]} -eq 0 ]]; then
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    log "Required: ${required[*]}"
    
    local -a missing=()
    for sub in "${required[@]}"; do
        btrfs_subvol_exists "$MOUNT_DIR/@${sub}" || missing+=("$sub")
    done
    
    if [[ ${#missing[@]} -eq 0 ]]; then
        log_success "All subvolumes exist"
    else
        log "Creating ${#missing[@]} subvolume(s)"
        
        for sub in "${missing[@]}"; do
            run_cmd btrfs subvolume create "$MOUNT_DIR/@${sub}"
            
            case "$sub" in
                swap)
                    [[ "${DRY_RUN}" == "yes" ]] && continue
                    chattr +C "$MOUNT_DIR/@${sub}" 2>/dev/null || true
                    
                    local swapfile="$MOUNT_DIR/@${sub}/swapfile"
                    if [[ ! -f "$swapfile" ]]; then
                        local mem=$(free -m | awk '/^Mem:/{print $2}')
                        local avail=$(get_btrfs_available_mb "$MOUNT_DIR")
                        create_swapfile "$swapfile" "$mem" "$avail" || true
                    fi
                    ;;
                    
                data)
                    [[ "${DRY_RUN}" == "yes" ]] && continue
                    mkdir -p "$MOUNT_DIR/@data/overlay/"{etc,var}/{upper,work}
                    mkdir -p "$MOUNT_DIR/@data/downloads"
                    
                    if [[ ! -f "$MOUNT_DIR/@data/current-slot" ]]; then
                        echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot"
                    fi
                    if [[ ! -f "$MOUNT_DIR/@data/previous-slot" ]]; then
                        echo "$CANDIDATE_SLOT" > "$MOUNT_DIR/@data/previous-slot"
                    fi
                    ;;
            esac
            
            log_success "Created: @${sub}"
        done
    fi
    
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
                    log_warn "Failed: $dir"
                fi
            fi
        done
        
        (( created > 0 )) && log_success "Created ${created} bind director(ies)"
    fi
    
    safe_umount "$MOUNT_DIR"
}

#####################################
### Deployment Logic              ###
#####################################

validate_boot() {
    log_section "Boot Validation"
    
    CURRENT_SLOT=$(cat /data/current-slot 2>/dev/null | tr -d '[:space:]')
    
    if [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log_warn "Invalid marker, detecting..."
        CURRENT_SLOT=$(get_booted_subvol)
        
        if [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
            CURRENT_SLOT="blue"
        fi
        
        mkdir -p /data
        echo "$CURRENT_SLOT" > /data/current-slot
        log "Corrected: $CURRENT_SLOT"
    fi
    
    local booted=$(get_booted_subvol)
    
    log "Marker: @${CURRENT_SLOT}"
    log "Booted: @${booted}"
    
    if [[ "$booted" != "$CURRENT_SLOT" ]]; then
        log_error "BOOT MISMATCH!"
        log_error "Expected to boot @${CURRENT_SLOT} but running @${booted}"
        die "Marker: @${CURRENT_SLOT}, Booted: @${booted}"
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
    
    local url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    local temp=$(mktemp)
    
    log "Checking ${UPDATE_CHANNEL}..."
    
    download_file "$url" "$temp" 1 || { rm -f "$temp"; die "Manifest fetch failed"; }
    
    IMAGE_NAME=$(tr -d '[:space:]' < "$temp")
    rm -f "$temp"
    
    [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]] || die "Invalid manifest"
    
    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"
    
    log "Remote: v${REMOTE_VERSION} (${REMOTE_PROFILE})"
    log "Local:  v${LOCAL_VERSION} (${LOCAL_PROFILE})"
    
    # Check for newer version
    if (( REMOTE_VERSION < LOCAL_VERSION )); then
        log_warn "Remote version older than local (${REMOTE_VERSION} < ${LOCAL_VERSION})"
        log_success "No update needed"
        touch "${STATE_DIR}/skip-deployment"
        return 0
    fi
    
    if (( REMOTE_VERSION > LOCAL_VERSION )); then
        log "Update available: v${LOCAL_VERSION} → v${REMOTE_VERSION}"
        return 0
    fi
    
    # REMOTE_VERSION == LOCAL_VERSION - check if candidate slot needs creation
    log "Current version matches latest (v${REMOTE_VERSION})"
    
    if ! mount_for_operation "version check"; then
        log_warn "Cannot check candidate slot, assuming update needed"
        return 0
    fi
    
    local needs_update=0
    if ! btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        log "Candidate slot missing, will create"
        needs_update=1
    fi
    
    safe_umount "$MOUNT_DIR"
    
    if (( needs_update == 0 )); then
        log_success "System up-to-date"
        touch "${STATE_DIR}/skip-deployment"
    fi
    
    return 0
}

download_update() {
    log_section "Download Phase"
    
    [[ -n "$IMAGE_NAME" ]] || die "IMAGE_NAME not set"
    [[ -n "$REMOTE_PROFILE" ]] || die "REMOTE_PROFILE not set"
    [[ -n "$REMOTE_VERSION" ]] || die "REMOTE_VERSION not set"
    
    local image="${DOWNLOAD_DIR}/${IMAGE_NAME}"
    local image_part="${image}.part"
    local marker="${image}.verified"
    local sha="${image}.sha256"
    local asc="${image}.asc"
    
    # Check existing verified download
    if [[ -f "$marker" && -f "$image" ]]; then
        local existing_size=$(get_file_size "$image")
        if (( existing_size >= MIN_FILE_SIZE )); then
            log_success "Using verified cache: $(format_bytes $existing_size)"
            return 0
        fi
        log_verbose "Cached file invalid, removing"
        rm -f "$marker" "$image" "$sha" "$asc"
    fi
    
    # Clean up aria2c control files from interrupted sessions
    rm -f "$image_part.aria2" "$image.aria2"
    
    [[ "${DRY_RUN}" == "yes" ]] && return 0
    
    # Construct SourceForge URLs for verification files
    local sf_base="https://sourceforge.net/projects/shanios/files"
    local sha_url="${sf_base}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.sha256/download"
    local asc_url="${sf_base}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.asc/download"
    
    # Get mirror URL for main image
    log "Discovering mirror..."
    local mirror_url
    mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
    mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
    
    [[ -z "$mirror_url" ]] && die "Mirror discovery failed"
    [[ ! "$mirror_url" =~ ^https?://[a-zA-Z0-9] ]] && die "Invalid mirror URL format"
    
    log_verbose "Mirror URL: $mirror_url"
    
    # Check remote file size
    log "Checking remote file size..."
    local expected_size
    expected_size=$(get_remote_file_size "$mirror_url")
    
    if (( expected_size > 0 )); then
        log "Expected size: $(format_bytes $expected_size)"
    else
        log_warn "Could not determine remote size"
    fi
    
    # Download main image with retry, resume, and validation
    local attempt=0 delay=5
    local download_success=0
    local mirror_failed=0
    
    while (( attempt < MAX_DOWNLOAD_ATTEMPTS )); do
        ((attempt++))
        log "Download attempt ${attempt}/${MAX_DOWNLOAD_ATTEMPTS}"
        
        # Validate partial file if it exists
        local current_size=0
        if [[ -f "$image_part" ]]; then
            current_size=$(get_file_size "$image_part")
            
            if (( current_size > 0 )); then
                # Size validation against expected size
                if (( expected_size > 0 )); then
                    if (( current_size > expected_size )); then
                        log_warn "Partial file oversized ($(format_bytes $current_size) > $(format_bytes $expected_size)), removing"
                        rm -f "$image_part" "$image_part.aria2"
                        current_size=0
                    elif (( current_size == expected_size )); then
                        log "Partial file appears complete ($(format_bytes $current_size)), validating..."
                        # Move to final location for validation
                        if mv "$image_part" "$image" 2>/dev/null; then
                            download_success=1
                            break
                        fi
                    else
                        local percent=$(( current_size * 100 / expected_size ))
                        log "Resuming from $(format_bytes $current_size) / $(format_bytes $expected_size) (${percent}%)"
                    fi
                else
                    # No expected size available, basic sanity check
                    if (( current_size < MIN_FILE_SIZE )); then
                        log_warn "Partial file too small ($(format_bytes $current_size)), removing"
                        rm -f "$image_part" "$image_part.aria2"
                        current_size=0
                    else
                        log "Resuming from $(format_bytes $current_size) (expected size unknown)"
                    fi
                fi
            fi
        fi
        
        # Attempt download
        if download_file "$mirror_url" "$image_part" 0; then
            # Verify file was created and has content
            if [[ ! -f "$image_part" ]] || [[ ! -s "$image_part" ]]; then
                log_warn "Download completed but no file produced"
                mirror_failed=1
            else
                current_size=$(get_file_size "$image_part")
                
                # Validate downloaded size
                if (( expected_size > 0 )); then
                    if (( current_size < expected_size )); then
                        log_warn "Download incomplete: $(format_bytes $current_size) / $(format_bytes $expected_size)"
                        # Keep partial file for resume on next attempt
                        continue
                    elif (( current_size > expected_size )); then
                        log_warn "Downloaded file larger than expected, may be corrupted"
                        rm -f "$image_part"
                        mirror_failed=1
                        continue
                    fi
                else
                    # No expected size, at least check minimum
                    if (( current_size < MIN_FILE_SIZE )); then
                        log_warn "Downloaded file too small ($(format_bytes $current_size))"
                        rm -f "$image_part"
                        mirror_failed=1
                        continue
                    fi
                fi
                
                # Move to final location
                if mv "$image_part" "$image" 2>/dev/null; then
                    download_success=1
                    log_success "Downloaded: $(format_bytes $current_size)"
                    break
                else
                    log_error "Failed to rename downloaded file"
                fi
            fi
        else
            log_warn "Download attempt failed"
            mirror_failed=1
        fi
        
        # Rediscover mirror on repeated failures
        if (( mirror_failed && attempt % 2 == 0 && attempt < MAX_DOWNLOAD_ATTEMPTS )); then
            log "Mirror appears broken, rediscovering..."
            rm -f "$DOWNLOAD_DIR/mirror.url"
            
            mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
            mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
            
            if [[ -z "$mirror_url" ]] || [[ ! "$mirror_url" =~ ^https?://[a-zA-Z0-9] ]]; then
                log_warn "Mirror rediscovery failed"
            else
                log_verbose "New mirror: $mirror_url"
                expected_size=$(get_remote_file_size "$mirror_url")
                mirror_failed=0
            fi
        fi
        
        # Retry delay with exponential backoff
        if (( attempt < MAX_DOWNLOAD_ATTEMPTS )); then
            log "Retrying in ${delay}s..."
            sleep "$delay"
            delay=$(( delay < 60 ? delay * 2 : 60 ))
        fi
    done
    
    # Final validation
    if [[ $download_success -eq 0 ]]; then
        rm -f "$image_part" "$image" "$image.aria2" "$image_part.aria2"
        die "Download failed after $MAX_DOWNLOAD_ATTEMPTS attempts"
    fi
    
    if ! validate_download "$image" "$expected_size"; then
        rm -f "$image"
        die "Downloaded file validation failed"
    fi
    
    # Download verification files
    log "Downloading verification files..."
    download_file "$sha_url" "$sha" 1 || { rm -f "$image"; die "SHA256 download failed"; }
    download_file "$asc_url" "$asc" 1 || { rm -f "$image" "$sha"; die "GPG signature download failed"; }
    
    # Verify integrity
    if ! verify_sha256 "$image" "$sha" || ! verify_gpg "$image" "$asc"; then
        rm -f "$image" "$sha" "$asc"
        die "Verification failed"
    fi
    
    # Mark as verified and clear mirror cache
    touch "$marker" || log_warn "Failed to create verification marker"
    rm -f "$DOWNLOAD_DIR/mirror.url"
    log_success "Download and verification complete"
}

deploy_update() {
    log_section "Deployment Phase"
    
    # Use mount_for_operation for consistency
    if ! mount_for_operation "deployment"; then
        die "Cannot mount for deployment"
    fi
    
    # Check if candidate is mounted (shouldn't be)
    if is_mounted "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        log_error "Candidate slot is mounted, cannot proceed"
        safe_umount "$MOUNT_DIR"
        die "Candidate mounted at $MOUNT_DIR/@${CANDIDATE_SLOT}"
    fi
    
    # Backup existing candidate if it exists
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        
        log "Creating backup: @${BACKUP_NAME}"
        if ! run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}"; then
            safe_umount "$MOUNT_DIR"
            die "Backup creation failed"
        fi
        
        log "Removing old candidate slot"
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false
        if ! run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
            safe_umount "$MOUNT_DIR"
            die "Failed to delete old candidate slot"
        fi
    fi
    
    # Clean temporary extraction subvolume
    local temp="$MOUNT_DIR/temp_update"
    if btrfs_subvol_exists "$temp"; then
        log_verbose "Cleaning existing temp_update subvolume"
        [[ -d "$temp/shanios_base" ]] && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
        btrfs subvolume delete "$temp" 2>/dev/null
    fi
    
    # Create extraction subvolume
    log "Creating extraction subvolume..."
    if ! run_cmd btrfs subvolume create "$temp"; then
        safe_umount "$MOUNT_DIR"
        die "Failed to create temp_update subvolume"
    fi
    
    # Extract image
    log "Extracting image (this may take several minutes)..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] Would extract $IMAGE_NAME to temp_update"
    else
        local start=$(date +%s)
        local extract_status=0
        
        if (( HAS_PV )); then
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                pv -p -t -e -r -b | btrfs receive "$temp" || extract_status=$?
        else
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                btrfs receive "$temp" || extract_status=$?
        fi
        
        if [[ $extract_status -ne 0 ]]; then
            log_error "Extraction failed with status $extract_status"
            [[ -d "$temp/shanios_base" ]] && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
            btrfs subvolume delete "$temp" 2>/dev/null
            safe_umount "$MOUNT_DIR"
            die "Image extraction failed"
        fi
        
        local duration=$(($(date +%s) - start))
        log_success "Extraction completed in ${duration}s"
    fi
    
    # Verify extracted subvolume exists
    if [[ ! -d "$temp/shanios_base" ]]; then
        log_error "Expected subvolume shanios_base not found after extraction"
        btrfs subvolume delete "$temp" 2>/dev/null
        safe_umount "$MOUNT_DIR"
        die "Extraction produced unexpected structure"
    fi
    
    # Create candidate from extracted base
    log "Creating candidate slot snapshot..."
    if ! run_cmd btrfs subvolume snapshot "$temp/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        [[ -d "$temp/shanios_base" ]] && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
        btrfs subvolume delete "$temp" 2>/dev/null
        safe_umount "$MOUNT_DIR"
        die "Failed to create candidate snapshot"
    fi
    
    # Set candidate as read-only
    if ! run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true; then
        log_warn "Failed to set candidate as read-only"
    fi
    
    # Cleanup temporary subvolumes
    log_verbose "Cleaning up temporary subvolumes"
    [[ -d "$temp/shanios_base" ]] && run_cmd btrfs subvolume delete "$temp/shanios_base"
    run_cmd btrfs subvolume delete "$temp"
    
    # Unmount cleanly
    safe_umount "$MOUNT_DIR"
    
    # Mark deployment as pending
    [[ "${DRY_RUN}" == "no" ]] && touch "$DEPLOY_PENDING"
    log_success "Deployment phase complete"
}

finalize_update() {
    log_section "Finalization"
    
    [[ "${DRY_RUN}" == "yes" ]] && {
        log "[DRY-RUN] Would finalize deployment"
        return 0
    }
    
    # Update slot markers FIRST (before any operations that might fail)
    mkdir -p /data
    if ! echo "$CURRENT_SLOT" > /data/previous-slot 2>/dev/null; then
        log_warn "Failed to write previous-slot marker"
    fi
    if ! echo "$CANDIDATE_SLOT" > /data/current-slot 2>/dev/null; then
        log_error "CRITICAL: Failed to write current-slot marker"
        die "Cannot update slot markers"
    fi
    log_verbose "Updated slot markers: previous=$CURRENT_SLOT, current=$CANDIDATE_SLOT"
    
    # Verify and create filesystem structure
    log "Verifying filesystem structure..."
    if ! verify_and_create_filesystem_structure; then
        die "Filesystem structure verification failed"
    fi
    
    # Generate UKI for new candidate slot
    log "Generating boot configuration..."
    if ! generate_uki "$CANDIDATE_SLOT"; then
        die "UKI generation failed"
    fi
    
    # Post-deployment cleanup (non-critical, use permissive error handling)
    log "Running post-deployment cleanup..."
    
    # Temporarily disable ERR trap and error exit for cleanup
    trap - ERR
    set +e
    
    # Cleanup old backups
    if mount_for_operation "backup cleanup"; then
        cleanup_old_backups
        local cleanup_status=$?
        [[ $cleanup_status -ne 0 ]] && log_verbose "Backup cleanup returned status $cleanup_status (non-critical)"
        
        # Ensure unmount
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR"
    else
        log_verbose "Could not mount for backup cleanup (skipping)"
    fi
    
    # Cleanup old downloads
    cleanup_downloads
    [[ $? -ne 0 ]] && log_verbose "Download cleanup had warnings (non-critical)"
    
    # Storage analysis and deduplication
    analyze_storage
    [[ $? -ne 0 ]] && log_verbose "Storage analysis had warnings (non-critical)"
    
    # Reset exit status and re-enable strict error handling
    true
    set -e
    trap 'restore_candidate' ERR
    
    # Clear deployment pending flag (CRITICAL - must succeed)
    if ! rm -f "$DEPLOY_PENDING" 2>/dev/null; then
        log_error "CRITICAL: Failed to remove deployment pending flag"
        die "Cannot clear deployment flag at $DEPLOY_PENDING"
    fi
    
    log_success "Finalization complete"
    log "System prepared for next boot into @${CANDIDATE_SLOT} (v${REMOTE_VERSION})"
    log "Current boot remains on @${CURRENT_SLOT} until reboot"
}

#####################################
### Main Entry Point (updated)    ###
#####################################

main() {
    local ROLLBACK="no" CLEANUP="no" STORAGE_INFO="no"
    
    # Parse arguments
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
            *) die "Invalid option: $1" ;;
        esac
    done
    
    # System checks
    check_root
    check_internet
    check_tools
    set_update_channel "${UPDATE_CHANNEL:-}"
    set_environment
    self_update
    inhibit_system
    
    # Handle special operations
    if [[ "$STORAGE_INFO" == "yes" ]]; then
        analyze_storage
        exit 0
    fi
    
    if [[ "$CLEANUP" == "yes" ]]; then
        # Use permissive error handling for manual cleanup
        trap - ERR
        set +e
        
        if mount_for_operation "manual cleanup"; then
            cleanup_old_backups
            safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR"
        fi
        cleanup_downloads
        
        set -e
        exit 0
    fi
    
    # Check boot-ok flag
    if [[ ! -f /data/boot-ok ]]; then
        log_error "boot-ok flag missing, previous boot may have failed"
        rollback_system
        exit 1
    fi
    
    # Handle manual rollback request
    if [[ "$ROLLBACK" == "yes" ]]; then
        rollback_system
        exit 0
    fi
    
    # Normal update flow
    validate_boot
    check_space
    fetch_update
    
    # Check if deployment can be skipped
    if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
        log "No deployment needed, running maintenance tasks"
        
        # Use permissive error handling for maintenance
        trap - ERR
        set +e
        
        if mount_for_operation "maintenance"; then
            if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
                cleanup_old_backups
            fi
            safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR"
        fi
        
        analyze_storage
        
        # Re-enable error handling
        set -e
        trap 'restore_candidate' ERR
        
        log_success "Maintenance complete"
        exit 0
    fi
    
    # Perform update
    download_update || die "Download phase failed"
    deploy_update || die "Deployment phase failed"
    
    # Finalize if deployment is pending
    if [[ -f "$DEPLOY_PENDING" ]]; then
        finalize_update || die "Finalization failed"
    fi
    
    log_success "Update process complete"
    log "Reboot to activate new system on @${CANDIDATE_SLOT}"
}

main "$@"
