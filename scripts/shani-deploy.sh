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

#####################################
### State Restoration             ###
#####################################
if [[ -n "${SHANIOS_DEPLOY_STATE_FILE:-}" ]] && [[ -f "$SHANIOS_DEPLOY_STATE_FILE" ]]; then
    set +e
    
    # Read state file content
    state_content=$(cat "$SHANIOS_DEPLOY_STATE_FILE" 2>/dev/null)
    
    # Remove the file immediately to prevent re-use
    rm -f "$SHANIOS_DEPLOY_STATE_FILE"
    
    # Now try to source it if we got content
    if [[ -n "$state_content" ]]; then
        # Filter out readonly variable declarations
        state_content=$(echo "$state_content" | grep -v "declare.*OS_NAME\|declare.*DOWNLOAD_DIR\|declare.*MOUNT_DIR\|declare.*ROOT_DEV\|declare.*GENEFI_SCRIPT\|declare.*LOG_FILE\|declare.*DEPLOY_PENDING\|declare.*GPG_KEY_ID\|declare.*CHROOT_BIND_DIRS\|declare.*CHROOT_STATIC_DIRS" || true)
        
        # Source the filtered content
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

readonly MAX_INHIBIT_DEPTH=2
readonly MAX_DOWNLOAD_ATTEMPTS=5
readonly EXTRACTION_TIMEOUT=1800

# Tool availability flags
declare -g HAS_ARIA2C=0 HAS_WGET=0 HAS_CURL=0 HAS_PV=0
command -v aria2c &>/dev/null && HAS_ARIA2C=1
command -v wget &>/dev/null && HAS_WGET=1
command -v curl &>/dev/null && HAS_CURL=1
command -v pv &>/dev/null && HAS_PV=1

# State variables
declare -g LOCAL_VERSION LOCAL_PROFILE
declare -g BACKUP_NAME="" CURRENT_SLOT="" CANDIDATE_SLOT=""
declare -g REMOTE_VERSION="" REMOTE_PROFILE="" IMAGE_NAME=""
declare -g UPDATE_CHANNEL="stable" DRY_RUN="no" VERBOSE="no"
declare -g DEPLOYMENT_START_TIME="" SKIP_SELF_UPDATE="no"

readonly CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp)
readonly CHROOT_STATIC_DIRS=(data etc var)

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
        # Only persist non-readonly variables
        declare -p LOCAL_VERSION LOCAL_PROFILE BACKUP_NAME CURRENT_SLOT CANDIDATE_SLOT 2>/dev/null || true
        declare -p REMOTE_VERSION REMOTE_PROFILE IMAGE_NAME UPDATE_CHANNEL 2>/dev/null || true
        declare -p VERBOSE DRY_RUN SKIP_SELF_UPDATE DEPLOYMENT_START_TIME 2>/dev/null || true
        declare -p STATE_DIR 2>/dev/null || true
        declare -p HAS_ARIA2C HAS_WGET HAS_CURL HAS_PV 2>/dev/null || true
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
### Mount Management              ###
#####################################

safe_mount() {
    local src="$1" tgt="$2" opts="$3"
    [[ -n "$src" && -n "$tgt" ]] || die "safe_mount: Invalid arguments"
    
    findmnt -M "$tgt" &>/dev/null && return 0
    
    log_verbose "Mounting: $src -> $tgt (opts: $opts)"
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
    
    # Validate size is numeric and positive
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
        
        # Capture only stderr from wget, filter to headers only
        local spider_output
        spider_output=$(timeout 30 wget --max-redirect=20 --spider -S "$sf_url" 2>&1 >/dev/null | \
            grep -E '^ +(HTTP|Location):' || echo "")
        
        # Debug: show what we captured
        if [[ "${VERBOSE}" == "yes" ]]; then
            log_verbose "Spider output:"
            echo "$spider_output" | head -20 >&2
        fi
        
        # Extract the final Location header after all redirects
        local final_url
        final_url=$(echo "$spider_output" | \
            grep -i '^  Location: ' | \
            tail -1 | \
            sed 's/^  Location: //' | \
            tr -d '\r\n' | \
            xargs)
        
        log_verbose "Extracted URL: ${final_url:-none}"
        
        # Strict validation: must be a proper HTTP(S) URL
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
    
    # Fallback to curl if wget unavailable or failed
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
        
        # Strict validation
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
    local file="$1" expected_size="${2:-0}"
    
    [[ -f "$file" ]] || { log_error "File not found: $file"; return 1; }
    
    local size
    size=$(get_file_size "$file")
    
    # Use server-provided size if available, otherwise use minimum threshold
    local min_size="$MIN_FILE_SIZE"
    if (( expected_size > 0 )); then
        min_size="$expected_size"
    fi
    
    if (( size < min_size )); then
        log_error "File too small: $(format_bytes $size) < $(format_bytes $min_size)"
        return 1
    fi
    
    # Detect HTML/XML error pages
    if file "$file" 2>/dev/null | grep -qi "html\|xml"; then
        log_error "File appears to be error page (HTML/XML)"
        return 1
    fi
    
    # Validate zstd files
    if [[ "$file" == *.zst ]] && ! file "$file" 2>/dev/null | grep -qi "zstandard"; then
        log_warn "File extension .zst but wrong content type"
        return 1
    fi
    
    log_verbose "Validation passed: $(format_bytes $size)"
    return 0
}

download_with_tool() {
    local tool="$1" url="$2" output="$3"
    
    # Sanitize URL - remove any whitespace and validate
    url=$(echo "$url" | tr -d '\r\n' | xargs)
    
    # Validate URL format
    if [[ ! "$url" =~ ^https?://[a-zA-Z0-9] ]]; then
        log_error "Invalid URL format: ${url:0:100}"
        return 1
    fi
    
    local wget_opts=(
        --retry-connrefused
        --waitretry=30
        --read-timeout=60
        --timeout=60
        --tries=3
        --no-verbose
        --dns-timeout=30
        --connect-timeout=30
        --prefer-family=IPv4
        --continue
    )
    [[ -t 2 ]] && wget_opts+=(--show-progress)
    
    case "$tool" in
        aria2c)
            # Redirect stderr to prevent log contamination
            aria2c \
              --console-log-level=warn \
              --summary-interval=1 \
              --download-result=hide \
              --timeout=30 --max-tries=3 --retry-wait=3 \
              --max-connection-per-server=8 --split=8 --min-split-size=1M \
              --continue=true --allow-overwrite=true --auto-file-renaming=false \
              --conditional-get=true --remote-time=true \
              --dir="$(dirname "$output")" --out="$(basename "$output")" \
              "$url"
            ;;
        wget)
            wget "${wget_opts[@]}" -O "$output" "$url" 2>&1 | grep -E "(saved|%)" || true
            ;;
        curl)
            curl --fail --location --max-time 300 --retry 3 --retry-delay 3 \
                --continue-at - --create-dirs --output "$output" \
                --progress-bar --remote-time "$url" 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

download_file() {
    local url="$1" output="$2" is_small="${3:-0}"
    
    mkdir -p "$(dirname "$output")"
    
    # Small files - quick download without complex resume logic
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
    
    # Large files - try downloaders with resume support
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
            # Verify download produced a file
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
    
    # Import key
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
    
    # Verify fingerprint
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
    
    # Verify signature
    if gpg --batch --verify "$sig" "$file" 2>/dev/null; then
        log_success "GPG signature verified"
        result=0
    else
        log_error "GPG signature verification failed"
        result=1
    fi
    
    # Cleanup
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
    log "Channel: ${UPDATE_CHANNEL}"
}

#####################################
### Self-Update                   ###
#####################################

ORIGINAL_ARGS=("$@")

self_update() {
    [[ -n "${SELF_UPDATE_DONE:-}" || "${SKIP_SELF_UPDATE}" == "yes" || -f "$DEPLOY_PENDING" ]] && return 0
    
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
                exec /bin/bash "$temp" "${ORIGINAL_ARGS[@]}"
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
    
    exec systemd-inhibit \
        --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
        --who="shanios-deployment" \
        --why="System update in progress" \
        "$0" "$@"
}

#####################################
### Cleanup Functions             ###
#####################################

cleanup_old_backups() {
    log_verbose "Cleaning backups"
    
    # Disable ERR trap for this function - cleanup is non-critical
    set +e
    
    if ! findmnt -M "$MOUNT_DIR" &>/dev/null; then
        log_verbose "Mount point not available, skipping backup cleanup"
        set -e
        return 1
    fi
    
    for slot in blue green; do
        log_verbose "Checking for old backups in slot '${slot}'..."
        
        # Gather backups for this slot, sorted by timestamp (newest first)
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
            awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' | sort -r)
        
        local backup_count=${#backups[@]}
        
        if (( backup_count == 0 )); then
            log_verbose "No backups found for slot '${slot}'"
            continue
        fi
        
        log_verbose "Found ${backup_count} backup(s) for slot '${slot}'"
        
        if (( backup_count > 1 )); then
            log "Keeping the most recent backup and deleting $((backup_count-1)) older backup(s) for slot '${slot}'"
            
            # Loop over all but the first (most recent) backup
            for (( i=1; i<backup_count; i++ )); do
                local backup="${backups[i]}"
                
                # Validate backup name against expected pattern
                if [[ ! "$backup" =~ ^(blue|green)_backup_[0-9]{10}$ ]]; then
                    log_warn "Skipping deletion for backup with unexpected name format: ${backup}"
                    continue
                fi
                
                # Extra safety: don't delete if it matches current backup being created
                if [[ -n "${BACKUP_NAME:-}" ]] && [[ "$backup" == "$BACKUP_NAME" ]]; then
                    log_verbose "Skipping current backup: @${backup}"
                    continue
                fi
                
                # Attempt deletion
                if [[ "${DRY_RUN}" == "yes" ]]; then
                    log "[DRY-RUN] Would delete old backup: @${backup}"
                elif btrfs subvolume delete "$MOUNT_DIR/@${backup}" &>/dev/null; then
                    log_success "Deleted old backup: @${backup}"
                else
                    log_warn "Failed to delete backup: @${backup}"
                fi
            done
        else
            log_verbose "Only the latest backup exists for slot '${slot}'; no cleanup needed"
        fi
    done
    
    # Restore error handling
    set -e
    return 0
}

cleanup_downloads() {
    log_verbose "Cleaning downloads"
    
    [[ ! -d "$DOWNLOAD_DIR" ]] && return 0
    
    # Find the most recent complete shanios image
    local latest_image
    latest_image=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst" -printf "%T@ %p\n" 2>/dev/null | \
        sort -rn | head -1 | cut -d' ' -f2-)
    
    local count=0 protected=0
    
    # Process each old file
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        
        # Protect the latest complete image and its verification files
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
        
        # Delete old file
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
}

analyze_storage() {
    set +e  # Disable strict error checking for analysis

    log_section "Storage Analysis"

    # Check for pending deployment
    if [[ -f "$DEPLOY_PENDING" ]]; then
        log_warn "Deployment pending, skipping storage analysis"
        set -e
        return 0
    fi

    # Prepare mount point
    mkdir -p "$MOUNT_DIR"
    if ! safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"; then
        log_error "Failed to mount $ROOT_DEV at $MOUNT_DIR"
        set -e
        return 1
    fi

    # Ensure cleanup on exit
    trap 'safe_umount "$MOUNT_DIR"' RETURN

    echo ""
    log "Filesystem Usage:"
    btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /' || log_warn "Failed to retrieve filesystem usage"

    echo ""
    log "Subvolume Size Analysis:"
    local -a check_subvols=(blue green data swap)
    for subvol in "${check_subvols[@]}"; do
        if btrfs_subvol_exists "$MOUNT_DIR/@${subvol}"; then
            local size
            size=$(btrfs filesystem du -sb "$MOUNT_DIR/@${subvol}" 2>/dev/null | awk 'NR==2 {print $2}')
            if [[ "$size" =~ ^[0-9]+$ ]]; then
                echo "  @${subvol}: $(format_bytes "$size")"
            else
                echo "  @${subvol}: size unavailable"
            fi
        else
            echo "  @${subvol}: Missing"
        fi
    done

    # Deduplication analysis requires both @blue and @green
    if ! btrfs_subvol_exists "$MOUNT_DIR/@blue" || ! btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        log_verbose "Skipping deduplication analysis (missing subvolumes)"
        echo ""
        set -e
        return 0
    fi

    # Build target list including backups
    local -a targets=("$MOUNT_DIR/@blue" "$MOUNT_DIR/@green")
    local backup_count=0
    while IFS= read -r backup; do
        [[ -n "$backup" ]] && { targets+=("$MOUNT_DIR/@${backup}"); ((backup_count++)); }
    done < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | awk '$NF ~ /_backup_/ {print $NF}')

    echo ""
    log "Deduplication Analysis:"
    log_verbose "Analyzing ${#targets[@]} subvolume(s) (${backup_count} backup(s))"

    # Calculate combined size before optimization
    before=0
    for target in "${targets[@]}"; do
        if [[ -d "$target" ]]; then
            size=$(btrfs filesystem du -sb "$target" 2>/dev/null | awk 'NR==2 {print $2}')
            if [[ "$size" =~ ^[0-9]+$ ]]; then
                before=$((before + size))
            fi
        fi
    done

    echo "  Combined Size: $(format_bytes "$before")"

    # Calculate already-saved space
    local blue_size green_size
    blue_size=$(btrfs filesystem du -sb "$MOUNT_DIR/@blue" 2>/dev/null | awk 'NR==2 {print $2}')
    green_size=$(btrfs filesystem du -sb "$MOUNT_DIR/@green" 2>/dev/null | awk 'NR==2 {print $2}')

    if [[ -n "$blue_size" && -n "$green_size" ]] && [[ "$blue_size" =~ ^[0-9]+$ ]] && [[ "$green_size" =~ ^[0-9]+$ ]]; then
        local total_unshared=$((blue_size + green_size))
        if (( total_unshared > before && before > 0 )); then
            local already_saved=$((total_unshared - before))
            local saved_pct=$((already_saved * 100 / total_unshared))
            echo "  Already Saved: $(format_bytes "$already_saved") (${saved_pct}%)"
        fi
    fi

    # Deduplication optimization
    if ! command -v duperemove &>/dev/null; then
        log_warn "duperemove not installed — skipping deduplication optimization"
        echo ""
        set -e
        return 0
    fi

    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] Would run deduplication on ${#targets[@]} subvolume(s)"
        echo ""
        set -e
        return 0
    fi

    echo ""
    log "Running deduplication optimization (this may take several minutes)..."
    mkdir -p "$MOUNT_DIR/@data"

    # Run duperemove with **no redirection**
    duperemove -dhr --skip-zeroes \
        --dedupe-options=same,partial \
        -b 128K \
        --batchsize=256 \
        --io-threads="$(nproc)" \
        --cpu-threads="$(nproc)" \
        --hashfile="$MOUNT_DIR/@data/.dedupe.db" \
        "${targets[@]}"

    if [[ $? -eq 0 ]]; then
        log_success "Deduplication completed successfully"
    else
        log_warn "Deduplication completed with warnings"
    fi

    # Post-optimization size calculation
    after=0
    for target in "${targets[@]}"; do
        if [[ -d "$target" ]]; then
            size=$(btrfs filesystem du -sb "$target" 2>/dev/null | awk 'NR==2 {print $2}')
            if [[ "$size" =~ ^[0-9]+$ ]]; then
                after=$((after + size))
            fi
        fi
    done

    echo ""
    log "Post-Optimization Results:"
    echo "  Combined Size: $(format_bytes "$after")"

    if (( after < before )); then
        saved=$((before - after))
        if (( before > 0 )); then
            percent=$((saved * 100 / before))
            echo "  Additional Savings: $(format_bytes "$saved") (${percent}%)"
            log_success "Deduplication saved $(format_bytes "$saved")"
        fi
    else
        echo "  Additional Savings: None"
        log_verbose "No additional space saved from deduplication"
    fi

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
    
    # Disable error exit for cleanup - we want to unmount as much as possible
    set +e
    
    [[ -d "$MOUNT_DIR/sys/firmware/efi/efivars" ]] && safe_umount "$MOUNT_DIR/sys/firmware/efi/efivars"
    for d in "${CHROOT_BIND_DIRS[@]}"; do safe_umount "$MOUNT_DIR$d"; done
    for d in "${CHROOT_STATIC_DIRS[@]}"; do safe_umount "$MOUNT_DIR/$d"; done
    safe_umount "$MOUNT_DIR/boot/efi"
    safe_umount "$MOUNT_DIR"
    
    # Re-enable error exit
    set -e
}

generate_uki() {
    local slot="$1"
    
    log_section "UKI Generation"
    [[ -x "$GENEFI_SCRIPT" ]] || die "gen-efi not found"
    
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
    
    # Disable all traps and error handling for recovery
    trap - ERR EXIT
    set +e
    
    mkdir -p "$MOUNT_DIR" 2>/dev/null
    mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null || true
    
    if [[ -n "$BACKUP_NAME" ]] && btrfs_subvol_exists "$MOUNT_DIR/@${BACKUP_NAME}"; then
        log "Restoring from @${BACKUP_NAME}"
        btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false 2>/dev/null
        btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null
        btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null
        btrfs property set -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true 2>/dev/null
        
        # CRITICAL FIX: Restore slot markers to reflect current booted state
        log "Restoring slot markers..."
        echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot" 2>/dev/null || \
            log_warn "Failed to restore current-slot marker"
        
        # If previous-slot was modified during failed deployment, restore it
        # Check if it was set to CANDIDATE_SLOT (which would be wrong after rollback)
        local prev_slot
        prev_slot=$(cat "$MOUNT_DIR/@data/previous-slot" 2>/dev/null | tr -d '[:space:]')
        
        if [[ "$prev_slot" == "$CANDIDATE_SLOT" ]] || [[ -z "$prev_slot" ]]; then
            # previous-slot was modified or missing, restore to current
            echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/previous-slot" 2>/dev/null || \
                log_warn "Failed to restore previous-slot marker"
            log_verbose "Restored previous-slot: $CURRENT_SLOT"
        else
            log_verbose "Preserved previous-slot: $prev_slot"
        fi
    fi
    
    # Cleanup temporary volumes
    [[ -d "$MOUNT_DIR/temp_update/shanios_base" ]] && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update/shanios_base" 2>/dev/null
    [[ -d "$MOUNT_DIR/temp_update" ]] && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update" 2>/dev/null
    
    umount -R "$MOUNT_DIR" 2>/dev/null
    rm -f "$DEPLOY_PENDING" 2>/dev/null
    
    log_error "Rollback complete - system remains on @${CURRENT_SLOT}"
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
    
    log "Rollback: ${failed_slot} → ${previous_slot}"
    
    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
        awk -v s="${failed_slot}" '$0 ~ s"_backup" {print $NF}' | sort | tail -1)
    
    [[ -z "$BACKUP_NAME" ]] && die "No backup found"
    
    log "Using: @${BACKUP_NAME}"
    
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro false
    run_cmd btrfs subvolume delete "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${failed_slot}"
    run_cmd btrfs property set -ts "$MOUNT_DIR/@${failed_slot}" ro true
    
    # Update slot markers - we're rolling back TO previous_slot
    echo "$previous_slot" > "$MOUNT_DIR/@data/current-slot"
    # Keep previous-slot unchanged (it already contains the right value)
    
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

create_swapfile() {
    local file="$1" size_mb="$2" avail_mb="$3"
    
    (( avail_mb < size_mb )) && { log_warn "Insufficient space for swap"; return 1; }
    
    log "Creating ${size_mb}MB swapfile"
    
    # Try btrfs native
    if btrfs filesystem mkswapfile --size "${size_mb}M" "$file" 2>/dev/null; then
        chmod 600 "$file"
        log_success "Swapfile created (btrfs)"
        return 0
    fi
    
    # Try truncate
    if truncate -s "${size_mb}M" "$file" 2>/dev/null && \
       chmod 600 "$file" && chattr +C "$file" 2>/dev/null && mkswap "$file" &>/dev/null; then
        log_success "Swapfile created (truncate)"
        return 0
    fi
    
    # Try dd
    if dd if=/dev/zero of="$file" bs=1M count="$size_mb" status=none 2>/dev/null && \
       chmod 600 "$file" && mkswap "$file" &>/dev/null; then
        log_success "Swapfile created (dd)"
        return 0
    fi
    
    rm -f "$file"
    return 1
}

verify_and_create_subvolumes() {
    log_section "Subvolume Verification"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
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
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
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
                mkdir -p "$MOUNT_DIR/@data/overlay/"{etc,var}/{lower,upper,work}
                mkdir -p "$MOUNT_DIR/@data/downloads"
                
                # Initialize slot markers if they don't exist
                if [[ ! -f "$MOUNT_DIR/@data/current-slot" ]]; then
                    echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/current-slot"
                fi
                if [[ ! -f "$MOUNT_DIR/@data/previous-slot" ]]; then
                    echo "$CURRENT_SLOT" > "$MOUNT_DIR/@data/previous-slot"
                fi
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
    btrfs filesystem df "$MOUNT_DIR" 2>/dev/null | sed 's/^/  /'
    
    echo ""
    echo "Subvolumes:"
    for s in blue green data swap; do
        if btrfs_subvol_exists "$MOUNT_DIR/@${s}"; then
            local info=$(btrfs filesystem du -s "$MOUNT_DIR/@${s}" 2>/dev/null | awk 'NR==2')
            echo "  @${s}: ${info:-Present}"
        else
            echo "  @${s}: Missing"
        fi
    done
    
    if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
        echo ""
        echo "Deduplication Analysis:"
        local combined=$(btrfs filesystem du -s "$MOUNT_DIR/@blue" "$MOUNT_DIR/@green" 2>/dev/null | tail -1)
        if [[ -n "$combined" ]]; then
            echo "  Combined: $combined"
            
            local blue=$(btrfs filesystem du -sb "$MOUNT_DIR/@blue" 2>/dev/null | awk 'NR==2 {print $2}')
            local green=$(btrfs filesystem du -sb "$MOUNT_DIR/@green" 2>/dev/null | awk 'NR==2 {print $2}')
            local excl=$(echo "$combined" | awk '{print $1}')
            
            if [[ -n "$blue" && -n "$green" && -n "$excl" ]] && (( blue + green > 0 )); then
                local saved=$(( blue + green - excl ))
                local percent=$(( saved * 100 / (blue + green) ))
                echo "  Potential: $(format_bytes $saved) (${percent}%)"
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
    
    # Read from persistent storage
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
    
    # REMOTE_VERSION == LOCAL_VERSION - only check if candidate is missing
    log "Current slot already at latest version (v${REMOTE_VERSION})"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    if ! btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        log "Candidate slot missing, will create"
        safe_umount "$MOUNT_DIR"
        return 0
    fi
    
    safe_umount "$MOUNT_DIR"
    log_success "System up-to-date"
    touch "${STATE_DIR}/skip-deployment"
    return 0
}

download_update() {
    log_section "Download Phase"
    
    # Validate prerequisites
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
        if (( existing_size > 0 )); then
            log_success "Using verified cache: $(format_bytes $existing_size)"
            return 0
        fi
        # Only delete when verification fails
        rm -f "$marker" "$image" "$sha" "$asc"
    fi
    
    # Clean up partial downloads from interrupted sessions
    [[ -f "$image_part.aria2" ]] && rm -f "$image_part.aria2"
    
    [[ "${DRY_RUN}" == "yes" ]] && return 0
    
    # Construct SourceForge URLs
    local sf_base="https://sourceforge.net/projects/shanios/files"
    local sha_url="${sf_base}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.sha256/download"
    local asc_url="${sf_base}/${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}.asc/download"
    
    # Get mirror URL for main image
    log "Discovering mirror..."
    local mirror_url
    mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
    
    # Critical sanitization - remove any contamination
    mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
    
    if [[ -z "$mirror_url" ]]; then
        log_error "Failed to get mirror URL"
        die "Mirror discovery failed"
    fi
    
    # Validate URL format before proceeding
    if [[ ! "$mirror_url" =~ ^https?://[a-zA-Z0-9] ]]; then
        log_error "Invalid mirror URL format"
        log_error "Got: ${mirror_url:0:200}"
        die "Mirror URL validation failed"
    fi
    
    log_verbose "Mirror URL: $mirror_url"
    
    # Check remote file size
    log "Checking remote file..."
    local expected_size
    expected_size=$(get_remote_file_size "$mirror_url")
    
    if (( expected_size > 0 )); then
        log "Expected size: $(format_bytes $expected_size)"
    else
        log_warn "Could not determine remote size"
    fi
    
    # Download main image with retry and resume
    local attempt=0 delay=5
    local download_success=0
    local mirror_failed=0
    
    while (( attempt < MAX_DOWNLOAD_ATTEMPTS )); do
        ((attempt++))
        
        log "Download attempt ${attempt}/${MAX_DOWNLOAD_ATTEMPTS}"
        
        # Check partial download
        local current_size=0
        if [[ -f "$image_part" ]]; then
            current_size=$(get_file_size "$image_part")
            
            # Validate partial file - only delete if corrupted
            if (( expected_size > 0 && current_size > expected_size )); then
                log_warn "Partial file larger than expected, corrupted"
                rm -f "$image_part" "$image_part.aria2"
                current_size=0
            elif (( current_size > 0 )); then
                log "Resuming from $(format_bytes $current_size)"
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
                
                # Check if complete
                if (( expected_size == 0 )) || (( current_size >= expected_size )); then
                    if mv "$image_part" "$image" 2>/dev/null; then
                        download_success=1
                        log_success "Downloaded: $(format_bytes $current_size)"
                        break
                    else
                        log_error "Failed to rename downloaded file"
                    fi
                else
                    log_warn "Incomplete: $(format_bytes $current_size) / $(format_bytes $expected_size)"
                fi
            fi
        else
            log_warn "Download attempt failed"
            mirror_failed=1
        fi
        
        # Clear mirror cache and rediscover on repeated failures
        if (( mirror_failed && attempt % 2 == 0 && attempt < MAX_DOWNLOAD_ATTEMPTS )); then
            log "Mirror appears broken, rediscovering..."
            rm -f "$DOWNLOAD_DIR/mirror.url"
            
            mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
            mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
            
            if [[ -z "$mirror_url" ]] || [[ ! "$mirror_url" =~ ^https?://[a-zA-Z0-9] ]]; then
                log_warn "Mirror rediscovery failed, will retry"
            else
                log_verbose "New mirror: $mirror_url"
                # Refresh expected size from new mirror
                expected_size=$(get_remote_file_size "$mirror_url")
                mirror_failed=0
            fi
        fi
        
        # Retry delay
        if (( attempt < MAX_DOWNLOAD_ATTEMPTS )); then
            log "Retrying in ${delay}s..."
            sleep "$delay"
            delay=$(( delay < 60 ? delay * 2 : 60 ))
        fi
    done
    
    if [[ $download_success -eq 0 ]]; then
        rm -f "$image_part" "$image" "$image.aria2"
        die "Download failed after $MAX_DOWNLOAD_ATTEMPTS attempts"
    fi
    
    # Validate downloaded file
    if ! validate_download "$image" "$expected_size"; then
        rm -f "$image"
        die "Downloaded file validation failed"
    fi
    
    # Download verification files (use SourceForge direct URLs)
    log "Downloading verification files..."
    download_file "$sha_url" "$sha" 1 || { rm -f "$image"; die "SHA256 download failed"; }
    download_file "$asc_url" "$asc" 1 || { rm -f "$image" "$sha"; die "GPG signature download failed"; }
    
    # Verify integrity - cleanup on any failure
    if ! verify_sha256 "$image" "$sha" || ! verify_gpg "$image" "$asc"; then
        rm -f "$image" "$sha" "$asc"
        die "Verification failed"
    fi
    
    # Clear mirror cache and mark as verified
    rm -f "$DOWNLOAD_DIR/mirror.url"
    touch "$marker" || log_warn "Failed to create verification marker"
    log_success "Download and verification complete"
}

deploy_update() {
    log_section "Deployment Phase"
    
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    
    mountpoint -q "$MOUNT_DIR/@${CANDIDATE_SLOT}" && {
        safe_umount "$MOUNT_DIR"
        die "Candidate mounted"
    }
    
    # Backup existing candidate
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M)"
        
        log "Backup: @${BACKUP_NAME}"
        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}" || {
            safe_umount "$MOUNT_DIR"
            die "Backup failed"
        }
        
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    fi
    
    # Clean temp
    local temp="$MOUNT_DIR/temp_update"
    if btrfs_subvol_exists "$temp"; then
        [[ -d "$temp/shanios_base" ]] && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
        btrfs subvolume delete "$temp" 2>/dev/null
    fi
    
    # Extract
    log "Creating extraction subvolume..."
    run_cmd btrfs subvolume create "$temp"
    
    log "Extracting image..."
    
    if [[ "${DRY_RUN}" == "yes" ]]; then
        log "[DRY-RUN] Would extract"
    else
        local start=$(date +%s)
        
        if (( HAS_PV )); then
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                pv -p -t -e -r -b | btrfs receive "$temp" || {
                btrfs subvolume delete "$temp" 2>/dev/null
                safe_umount "$MOUNT_DIR"
                die "Extraction failed"
            }
        else
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                btrfs receive "$temp" || {
                btrfs subvolume delete "$temp" 2>/dev/null
                safe_umount "$MOUNT_DIR"
                die "Extraction failed"
            }
        fi
        
        log_success "Extracted in $(($(date +%s) - start))s"
    fi
    
    # Create candidate
    log "Snapshotting..."
    run_cmd btrfs subvolume snapshot "$temp/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true
    
    # Cleanup
    [[ -d "$temp/shanios_base" ]] && run_cmd btrfs subvolume delete "$temp/shanios_base"
    run_cmd btrfs subvolume delete "$temp"
    safe_umount "$MOUNT_DIR"
    
    [[ "${DRY_RUN}" == "no" ]] && touch "$DEPLOY_PENDING"
    log_success "Deployed"
}

finalize_update() {
    log_section "Finalization"
    
    [[ "${DRY_RUN}" == "yes" ]] && return 0
    
    # Update slot markers BEFORE any operations that might fail
    mkdir -p /data
    echo "$CURRENT_SLOT" > /data/previous-slot || log_warn "Failed to write previous-slot"
    echo "$CANDIDATE_SLOT" > /data/current-slot || log_warn "Failed to write current-slot"
    
    verify_and_create_subvolumes || die "Subvolume verification failed"
    
    generate_uki "$CANDIDATE_SLOT" || die "UKI generation failed"
    
    # Cleanup operations (non-critical, don't fail on errors)
    # CRITICAL: Temporarily disable ERR trap for cleanup operations
    trap - ERR
    set +e
    
    mkdir -p "$MOUNT_DIR"
    if mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null; then
        cleanup_old_backups
        umount -R "$MOUNT_DIR" 2>/dev/null || true
    fi
    cleanup_downloads
    analyze_storage
    
    # Re-enable ERR trap
    trap 'restore_candidate' ERR
    set -e
    
    # Clear pending flag - deployment complete
    rm -f "$DEPLOY_PENDING" || log_warn "Failed to remove deployment pending flag"
    
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
  -s, --storage-info      Storage analysis
  -t, --channel <chan>    Update channel (latest|stable)
  -d, --dry-run           Simulate
  -v, --verbose           Verbose output
  --skip-self-update      Skip auto-update
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
            *) die "Invalid option: $1" ;;
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
        # Disable ERR trap for manual cleanup
        trap - ERR
        set +e
        
        mkdir -p "$MOUNT_DIR"
        if mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null; then
            cleanup_old_backups
            umount -R "$MOUNT_DIR" 2>/dev/null || true
        fi
        cleanup_downloads
        
        set -e
        exit 0
    fi
    
    [[ -f /data/boot-ok ]] || rollback_system
    
    [[ "$ROLLBACK" == "yes" ]] && { rollback_system; exit 0; }
    
    validate_boot
    check_space
    fetch_update
    
    if [[ -f "${STATE_DIR}/skip-deployment" ]]; then
        # Both slots already up-to-date, just optimize if possible
        # Disable ERR trap for non-critical optimization
        trap - ERR
        set +e
        
        mkdir -p "$MOUNT_DIR"
        if mount -o subvolid=5 "$ROOT_DEV" "$MOUNT_DIR" 2>/dev/null; then
            if btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green"; then
                umount -R "$MOUNT_DIR" 2>/dev/null || true
                analyze_storage
            else
                umount -R "$MOUNT_DIR" 2>/dev/null || true
            fi
        fi
        
        # Re-enable ERR trap
        trap 'restore_candidate' ERR
        set -e
    else
        download_update || die "Download failed"
        deploy_update || die "Deployment failed"
    fi
    
    [[ -f "$DEPLOY_PENDING" ]] && finalize_update
    
    log_success "Done"
}

main "$@"
