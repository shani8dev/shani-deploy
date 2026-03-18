#!/bin/bash
################################################################################
# shanios-deploy.sh - Production Blue/Green Btrfs Deployment System
#
# Usage: ./shanios-deploy.sh [OPTIONS]
#
# Options:
#   -h, --help              Show help
#   -r, --rollback          Roll back the non-booted slot. IMPORTANT: run this from the slot you want to KEEP.
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
    # Only trust state files we created ourselves under /run
    if [[ "$SHANIOS_DEPLOY_STATE_FILE" =~ ^/run/shanios_deploy_state\.[A-Za-z0-9]+$ ]]; then
        set +e
        state_content=$(cat "$SHANIOS_DEPLOY_STATE_FILE" 2>/dev/null)
        rm -f "$SHANIOS_DEPLOY_STATE_FILE"

        if [[ -n "$state_content" ]]; then
            state_content=$(echo "$state_content" | grep -v "declare.*OS_NAME\|declare.*DOWNLOAD_DIR\|declare.*MOUNT_DIR\|declare.*ROOT_DEV\|declare.*GENEFI_SCRIPT\|declare.*LOG_FILE\|declare.*DEPLOY_PENDING\|declare.*GPG_KEY_ID\|declare.*CHROOT_BIND_DIRS\|declare.*CHROOT_STATIC_DIRS\|declare.*CHANNEL_FILE\|declare.*STATE_DIR" || true)
            [[ -n "$state_content" ]] && eval "$state_content" 2>/dev/null || true
        fi
        set -e
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] Ignoring untrusted state file path: $SHANIOS_DEPLOY_STATE_FILE" >&2
        unset SHANIOS_DEPLOY_STATE_FILE
    fi
fi

#####################################
### Global Configuration          ###
#####################################

readonly OS_NAME="shanios"
readonly ROOTLABEL="shani_root"
readonly DOWNLOAD_DIR="/data/downloads"
readonly MOUNT_DIR="/mnt"
readonly ROOT_DEV="/dev/disk/by-label/shani_root"
readonly MIN_FREE_SPACE_MB=10240
readonly MIN_FILE_SIZE=10485760
readonly GENEFI_SCRIPT="/usr/local/bin/gen-efi"
readonly DEPLOY_PENDING="/data/deployment_pending"
# /run is tmpfs — cleared automatically on every reboot, so no manual cleanup needed.
# Written world-readable so shani-update (running as a normal user) can read it.
readonly REBOOT_NEEDED_FILE="/run/shanios/reboot-needed"
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
declare -g BACKUP_NAME="${BACKUP_NAME:-}" CURRENT_SLOT="${CURRENT_SLOT:-}" CANDIDATE_SLOT="${CANDIDATE_SLOT:-}"
declare -g REMOTE_VERSION="${REMOTE_VERSION:-}" REMOTE_PROFILE="${REMOTE_PROFILE:-}" IMAGE_NAME="${IMAGE_NAME:-}"
declare -g UPDATE_CHANNEL="${UPDATE_CHANNEL:-}" UPDATE_CHANNEL_SOURCE="${UPDATE_CHANNEL_SOURCE:-}"
# These must not overwrite values restored from state — the re-exec'd process
# needs to inherit DRY_RUN/VERBOSE/etc. exactly as the parent had them.
declare -g DRY_RUN="${DRY_RUN:-no}"
declare -g VERBOSE="${VERBOSE:-no}"
declare -g SKIP_SELF_UPDATE="${SKIP_SELF_UPDATE:-no}"
declare -g SELF_UPDATE_DONE="${SELF_UPDATE_DONE:-}"
declare -g FORCE_UPDATE="${FORCE_UPDATE:-no}"
declare -g DEPLOYMENT_START_TIME="${DEPLOYMENT_START_TIME:-}"

readonly CHROOT_BIND_DIRS=(/dev /proc /sys /run /tmp)
# CHROOT_STATIC_DIRS are bind-mounted from the live system into the candidate
# slot chroot so gen-efi can access:
#   data  — downloads dir and slot markers live here
#   etc   — /etc/secureboot/keys (MOK signing keys), /etc/vconsole.conf (keymap),
#            and /etc/kernel/install_cmdline_* (generated from live disk state)
#   var   — dracut cache and module state
#   swap  — swap subvolume so gen-efi can compute the resume_offset for the
#            swapfile that already exists on disk (correct: swap is shared state)
# Consequence: gen-efi inside the chroot sees the live /etc, not the new slot's
# /etc. This is intentional for keys and keymap (shared), but means if the new
# slot ships a different fstab or vconsole.conf those changes don't affect the
# UKI cmdline until the next deploy after rebooting into the new slot.
readonly CHROOT_STATIC_DIRS=(data etc var swap)

#####################################
### State Management              ###
#####################################

# STATE_DIR is created after check_root() ensures we are root
STATE_DIR=""

cleanup_state() {
    [[ -n "${STATE_DIR:-}" && -d "${STATE_DIR}" ]] && rm -rf "${STATE_DIR}"
}
trap cleanup_state EXIT

persist_state() {
    local state_file
    state_file=$(mktemp /run/shanios_deploy_state.XXXX)
    chmod 600 "$state_file"
    {
        declare -p LOCAL_VERSION LOCAL_PROFILE BACKUP_NAME CURRENT_SLOT CANDIDATE_SLOT 2>/dev/null || true
        declare -p REMOTE_VERSION REMOTE_PROFILE IMAGE_NAME UPDATE_CHANNEL UPDATE_CHANNEL_SOURCE 2>/dev/null || true
        declare -p VERBOSE DRY_RUN SKIP_SELF_UPDATE 2>/dev/null || true
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
        case "$channel_arg" in
            stable|latest) ;;
            *) die "Invalid channel '${channel_arg}' — must be 'stable' or 'latest'" ;;
        esac
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
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline | cut -d= -f2- 2>/dev/null || echo "")
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    [[ -z "$subvol" ]] && subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    if [[ -z "$subvol" ]]; then
        die "Cannot detect booted subvolume — /proc/cmdline has no subvol= and btrfs get-default returned nothing. Check that the system booted from a ShaniOS slot."
    fi
    echo "$subvol"
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

    (( HAS_ARIA2C )) && { download_with_tool aria2c "$url" "$output" 2>/dev/null && return 0; }
    (( HAS_WGET ))   && { download_with_tool wget   "$url" "$output" 2>/dev/null && return 0; }
    (( HAS_CURL ))   && { download_with_tool curl   "$url" "$output" 2>/dev/null && return 0; }
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
    log_verbose "Fallback URL: ${fallback_url}"

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
        log_error "File too small: $(basename "$file") is $(format_bytes $size), expected at least $(format_bytes $min_size)"
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
            log_error "File appears to be preallocated but contains no real data (0 bytes written) — download tool may have failed silently"
            return 1
        fi
    fi

    # Check for aria2c control files (indicates incomplete download)
    if [[ -f "${file}.aria2" ]]; then
        log_error "aria2c control file exists — download is incomplete and cannot be used"
        return 1
    fi

    # Detect HTML/XML error pages
    if file "$file" 2>/dev/null | grep -qi "html\|xml"; then
        log_error "Downloaded file appears to be an HTML/XML error page, not a valid image — the server may have returned an error"
        return 1
    fi

    # Validate zstd files - ONLY run full integrity check if final validation
    if [[ "$file" == *.zst ]]; then
        if ! file "$file" 2>/dev/null | grep -qiE "zstandard|zst compressed"; then
            log_warn "File has .zst extension but does not appear to be a valid zstandard archive — download may be corrupt"
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
            attempt=$((attempt + 1))
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
    log_verbose "Verifying SHA256 checksum..."

    local expected=$(awk '{print $1}' "$sha_file" 2>/dev/null | head -1 | tr -d '[:space:]')
    local actual=$(sha256sum "$file" 2>/dev/null | awk '{print $1}' | tr -d '[:space:]')

    [[ -z "$expected" || -z "$actual" ]] && { log_error "Could not read checksums for verification"; return 1; }

    if [[ "$expected" != "$actual" ]]; then
        log_error "SHA256 checksum mismatch — download may be corrupt"
        log_error "Expected: $expected"
        log_error "Got:      $actual"
        return 1
    fi

    log_success "SHA256 checksum verified"
    return 0
}

verify_gpg() {
    local file="$1" sig="$2"
    log_verbose "Verifying GPG signature..."

    local gpg_temp
    gpg_temp=$(mktemp -d /run/shanios-gpg.XXXXXX)
    local old_gnupghome="${GNUPGHOME:-}"
    export GNUPGHOME="$gpg_temp"
    chmod 700 "$gpg_temp"

    local result=1
    local key_imported=0

    # Prefer the bundled key — fast, offline, no keyserver dependency.
    local bundled_key="/etc/shani-keys/signing.asc"
    if [[ -f "$bundled_key" ]]; then
        if gpg --batch --quiet --import "$bundled_key" 2>/dev/null; then
            log_verbose "GPG key imported from bundled key: ${bundled_key}"
            key_imported=1
        else
            log_warn "Bundled key import failed — falling back to keyservers"
        fi
    fi

    # Keyserver fallback — only if bundled key is missing or failed to import.
    if (( ! key_imported )); then
        local keyservers=(keys.openpgp.org keyserver.ubuntu.com pgp.mit.edu)
        for keyserver in "${keyservers[@]}"; do
            if gpg --batch --quiet --keyserver "$keyserver" --recv-keys "$GPG_KEY_ID" 2>/dev/null; then
                log_verbose "GPG key imported from keyserver: $keyserver"
                key_imported=1
                break
            fi
        done
        (( key_imported )) || log_warn "Could not import GPG signing key — signature verification may fail"
    fi

    local fp
    fp=$(gpg --batch --with-colons --fingerprint "$GPG_KEY_ID" 2>/dev/null | awk -F: '/^fpr:/ {print $10; exit}')
    if [[ "$fp" == "$GPG_KEY_ID" ]] && gpg --batch --verify "$sig" "$file" 2>/dev/null; then
        log_success "GPG signature verified"
        result=0
    else
        log_error "GPG signature verification failed — image may be tampered with"
    fi

    rm -rf "$gpg_temp"
    [[ -n "$old_gnupghome" ]] && export GNUPGHOME="$old_gnupghome" || unset GNUPGHOME
    return $result
}

#####################################
### System Checks                 ###
#####################################

check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        local self
        self=$(readlink -f "$0")
        if command -v pkexec &>/dev/null; then
            exec pkexec "$self" "${ORIGINAL_ARGS[@]}"
        elif command -v sudo &>/dev/null; then
            exec sudo "$self" "${ORIGINAL_ARGS[@]}"
        else
            die "Must run as root — re-run with sudo or as root user"
        fi
    fi
    # Now confirmed root — safe to create state dir under /run
    STATE_DIR=$(mktemp -d /run/shanios-deploy-state.XXXXXX)
    export STATE_DIR
}

check_internet() {
    log "Checking internet connectivity..."
    # Try ICMP first (fastest), then fall back to HTTP HEAD for environments
    # where ICMP is blocked (corporate firewalls, VPNs, containers).
    if ping -c1 -W2 8.8.8.8 &>/dev/null; then
        log_verbose "Internet connectivity OK (ping)"
        return 0
    fi
    if (( HAS_CURL )) && timeout 10 curl -fsSL --max-time 8 --head https://downloads.shani.dev &>/dev/null; then
        log_verbose "Internet connectivity OK (curl)"
        return 0
    fi
    if (( HAS_WGET )) && timeout 10 wget -q --spider --timeout=8 https://downloads.shani.dev &>/dev/null; then
        log_verbose "Internet connectivity OK (wget)"
        return 0
    fi
    die "No internet connection — check your network and try again"
}

check_tools() {
    log_verbose "Checking required tools"
    (( HAS_ARIA2C || HAS_WGET || HAS_CURL )) || \
        die "No download tool found — install aria2c, wget, or curl and try again"
    log_verbose "Download tools available: ${HAS_ARIA2C:+aria2c }${HAS_WGET:+wget }${HAS_CURL:+curl}"
}

set_environment() {
    [[ -f /etc/shani-version && -f /etc/shani-profile ]] || \
        die "Missing system identity files (/etc/shani-version or /etc/shani-profile) — system may be corrupted"

    LOCAL_VERSION=$(< /etc/shani-version)
    LOCAL_PROFILE=$(< /etc/shani-profile)

    validate_nonempty "$LOCAL_VERSION" "LOCAL_VERSION"
    validate_nonempty "$LOCAL_PROFILE" "LOCAL_PROFILE"

    log "Running system: v${LOCAL_VERSION} profile=${LOCAL_PROFILE}"
    log "Update channel: ${UPDATE_CHANNEL} (source: ${UPDATE_CHANNEL_SOURCE})"
}

#####################################
### Self-Update                   ###
#####################################

self_update() {
    [[ -n "${SELF_UPDATE_DONE:-}" ]] && { log_verbose "Script self-update already done this session, skipping"; return 0; }
    if [[ "${SKIP_SELF_UPDATE}" == "yes" ]]; then
        log "Script self-update skipped (--skip-self-update)"
        return 0
    fi
    if [[ -f "$DEPLOY_PENDING" ]]; then
        log_warn "Script self-update skipped — a deployment is mid-flight (pending flag exists). Run --rollback if this is unexpected."
        return 0
    fi

    export SELF_UPDATE_DONE=1
    persist_state

    local script_path
    script_path=$(readlink -f "$0")
    local temp
    temp=$(mktemp /run/shanios-selfupdate.XXXXXX)

    log "Checking for script updates..."

    local self_update_url="https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh"
    if download_file "$self_update_url" "$temp" 1; then
        if grep -q "#!/bin/bash" "$temp" && grep -q "shanios-deploy" "$temp"; then
            if ! cmp -s "$script_path" "$temp"; then
                chmod +x "$temp"
                log_success "Script updated — re-executing with new version..."
                # Clean up STATE_DIR before exec — EXIT trap won't fire after exec
                cleanup_state
                [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]] && exec /bin/bash "$temp" "${ORIGINAL_ARGS[@]}" || exec /bin/bash "$temp"
            else
                log_verbose "Script is already up to date"
            fi
        else
            log_verbose "Downloaded script failed sanity check, keeping current version"
        fi
    else
        log_verbose "Could not check for script update, continuing with current version"
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
    log "Inhibiting system power events (sleep/shutdown/hibernate) during deployment..."

    local script_path
    script_path=$(readlink -f "$0")

    # Clean up STATE_DIR before exec — EXIT trap won't fire after exec
    cleanup_state

    # Explicitly pass SHANIOS_DEPLOY_STATE_FILE via env so it survives the
    # systemd-inhibit exec regardless of whether it preserves the environment
    local state_env=()
    [[ -n "${SHANIOS_DEPLOY_STATE_FILE:-}" ]] && \
        state_env=(env "SHANIOS_DEPLOY_STATE_FILE=$SHANIOS_DEPLOY_STATE_FILE")

    [[ ${#ORIGINAL_ARGS[@]} -gt 0 ]] && \
        exec "${state_env[@]}" systemd-inhibit \
            --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" --why="System update in progress" \
            "$script_path" "${ORIGINAL_ARGS[@]}" || \
        exec "${state_env[@]}" systemd-inhibit \
            --what=idle:sleep:shutdown:handle-power-key:handle-suspend-key:handle-hibernate-key:handle-lid-switch \
            --who="shanios-deployment" --why="System update in progress" \
            "$script_path"
}

#####################################
### Cleanup Functions             ###
#####################################

cleanup_old_backups() {
    log_verbose "Scanning for old backup subvolumes to clean up..."
    set +e

    is_mounted "$MOUNT_DIR" || { log_verbose "Skipping backup cleanup — root filesystem not mounted"; set -e; return 1; }

    for slot in blue green; do
        mapfile -t backups < <(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
            awk -v slot="${slot}" '$0 ~ slot"_backup_" {print $NF}' | sort -r)

        local backup_count=${#backups[@]}
        if (( backup_count == 0 )); then
            log_verbose "No backups found for @${slot}"
            continue
        fi

        log_verbose "Found ${backup_count} backup(s) for slot '${slot}'"

        if (( backup_count == 1 )); then
            log_verbose "Only one backup for @${slot} (${backups[0]}) — nothing to clean"
        elif (( backup_count > 1 )); then
            log "Keeping latest backup for @${slot} (${backups[0]}), deleting $((backup_count-1)) older backup(s)"
            for (( i=1; i<backup_count; i++ )); do
                local backup="${backups[i]}"
                local clean_backup="${backup#@}"

                # Validate backup name format: slot_backup_TIMESTAMP
                # Timestamp is 10-14 digits covering YYYYMMDDHHmm (12) and YYYYMMDDHHmmSS (14).
                [[ ! "$clean_backup" =~ ^(blue|green)_backup_[0-9]{10,14}$ ]] && {
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
    log_verbose "Scanning for old download files to clean up..."
    [[ ! -d "$DOWNLOAD_DIR" ]] && return 0

    # Identify the current image set — protect these regardless of age.
    local latest_image
    latest_image=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name "shanios-*.zst" \
        -printf "%T@ %p\n" 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)

    local count=0 protected=0
    while IFS= read -r file; do
        [[ -z "$file" ]] && continue

        if [[ -n "$latest_image" ]]; then
            local file_base
            file_base=$(basename "$file")
            local latest_base
            latest_base=$(basename "$latest_image")

            # Protect the current image and all its sidecar files.
            if [[ "$file_base" == "$latest_base" ]] || \
               [[ "$file_base" == "${latest_base}.sha256" ]] || \
               [[ "$file_base" == "${latest_base}.asc" ]] || \
               [[ "$file_base" == "${latest_base}.verified" ]]; then
                protected=$((protected + 1))
                continue
            fi
        fi

        if [[ "${DRY_RUN}" == "yes" ]]; then
            log "[DRY-RUN] Would delete: $(basename "$file")"
            count=$((count + 1))
        elif rm -f "$file" 2>/dev/null; then
            log_verbose "Deleted: $(basename "$file")"
            count=$((count + 1))
        fi
    done < <(find "$DOWNLOAD_DIR" -maxdepth 1 -type f \
        \( -name "shanios-*.zst*" -o -name "*.aria2" -o -name "*.part" -o -name "*.tmp" \) \
        2>/dev/null)

    (( count > 0 )) && log "Cleaned $count old download file(s) from ${DOWNLOAD_DIR}"
    (( count == 0 )) && log_verbose "No old downloads to clean in ${DOWNLOAD_DIR}"
    (( protected > 0 )) && log_verbose "Protected $protected current file(s)"
}

analyze_storage() {
    log_section "Storage Analysis"

    if is_mounted "$MOUNT_DIR"; then
        log_verbose "Cleaning up existing mount before storage analysis"
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
    fi

    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" || { log_error "Could not mount root filesystem for storage analysis — check ${ROOT_DEV}"; return 1; }
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

    [[ -f "$DEPLOY_PENDING" ]] && { log_warn "A deployment is currently pending — cannot optimize storage now. Complete or rollback the deployment first, then re-run --optimize"; set -e; return 0; }

    if is_mounted "$MOUNT_DIR"; then
        log_verbose "Cleaning up existing mount before optimization"
        safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true
    fi

    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5" || { log_error "Could not mount root filesystem for deduplication — check ${ROOT_DEV}"; set -e; return 1; }
    trap 'safe_umount "$MOUNT_DIR" || force_umount_all "$MOUNT_DIR" || true' RETURN

    btrfs_subvol_exists "$MOUNT_DIR/@blue" && btrfs_subvol_exists "$MOUNT_DIR/@green" || {
        log_warn "Skipping deduplication (missing blue/green subvolumes)"
        set -e
        return 0
    }

    command -v duperemove &>/dev/null || { log_error "duperemove not installed — install it to use --optimize"; set -e; return 1; }

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
        log_verbose "ESP already mounted — bind-mounting into chroot"
        run_cmd mount --bind /boot/efi "$MOUNT_DIR/boot/efi"
        # Record that we did a bind-mount (not a fresh label mount) so cleanup
        # knows it should NOT try to unmount the host's /boot/efi itself.
        CHROOT_ESP_BIND=1
    else
        log_verbose "Mounting ESP (LABEL=shani_boot) into chroot"
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
    [[ -x "$GENEFI_SCRIPT" ]] || die "gen-efi script not found at ${GENEFI_SCRIPT} — cannot generate boot image"

    log_verbose "Preparing chroot environment for @${slot}..."
    prepare_chroot "$slot"
    trap 'cleanup_chroot' RETURN

    [[ "${DRY_RUN}" == "yes" ]] && return 0

    log "Generating unified kernel image (UKI) for @${slot}..."
    local result=0
    chroot "$MOUNT_DIR" "$GENEFI_SCRIPT" configure "$slot" && \
        log_success "UKI generated successfully for @${slot}" || { log_error "UKI generation failed for @${slot}"; result=1; }

    return $result
}

finalize_boot_entries() {
    local active_slot="$1"
    local candidate_slot="$2"
    # Whether the candidate should get boot-counting tries.
    # Pass "no-tries" as third arg for rollback/restore paths where both
    # slots are already known-good and no automatic fallback is wanted.
    local use_tries="${3:-yes}"
    local esp_mounted=0

    if ! mountpoint -q "$ESP" 2>/dev/null; then
        log "ESP not mounted at ${ESP} — mounting temporarily to update boot entries..."
        if mount LABEL=shani_boot "$ESP" 2>/dev/null; then
            esp_mounted=1
        else
            log_error "Could not mount ESP — boot entries not updated. The system may not boot correctly after reboot."
            return 1
        fi
    fi

    mkdir -p "$ESP/loader/entries"

    # Remove all stale entries for both slots before writing new ones:
    # - tries-suffixed files (+3-0, +3-3 etc.) left by previous deploys
    #   or renamed by bless-boot/systemd-boot boot counting
    # - plain .conf files left when a slot transitions from no-tries to tries
    #   (e.g. shanios-blue.conf orphaned when blue becomes active and gets
    #   shanios-blue+3-0.conf on the next deploy)
    rm -f "$ESP/loader/entries/${OS_NAME}-${active_slot}"+*.conf 2>/dev/null || true
    rm -f "$ESP/loader/entries/${OS_NAME}-${candidate_slot}"+*.conf 2>/dev/null || true
    rm -f "$ESP/loader/entries/${OS_NAME}-${active_slot}.conf" 2>/dev/null || true
    rm -f "$ESP/loader/entries/${OS_NAME}-${candidate_slot}.conf" 2>/dev/null || true

    # Default slot — the new unproven slot being set as the next boot target.
    # Gets +3-0 boot-count tries on normal deploy so systemd-boot automatically
    # falls back to the fallback entry if it fails to reach multi-user.target.
    # bless-boot calls 'bootctl set-good' once the session is healthy, which
    # renames the file from +3-0 → +3-3 (done == left) and stops counting.
    # On rollback/restore both slots are known-good so no tries are needed.
    local active_filename active_conf
    if [[ "$use_tries" == "yes" ]]; then
        # +3-0: 3 tries allowed, 0 done. systemd-boot decrements tries-left on
        # each boot attempt; when it reaches 0 it boots the fallback entry instead.
        active_filename="${OS_NAME}-${active_slot}+3-0.conf"
    else
        active_filename="${OS_NAME}-${active_slot}.conf"
    fi
    active_conf="$ESP/loader/entries/${active_filename}"
    cat > "$active_conf" <<EOF
title   ${OS_NAME}-${active_slot} (Active)
efi     /EFI/${OS_NAME}/${OS_NAME}-${active_slot}.efi
EOF

    # Fallback slot — the old proven slot. No tries needed: if the new slot
    # exhausts its tries systemd-boot falls back to this entry unconditionally.
    local candidate_conf="$ESP/loader/entries/${OS_NAME}-${candidate_slot}.conf"
    cat > "$candidate_conf" <<EOF
title   ${OS_NAME}-${candidate_slot} (Candidate)
efi     /EFI/${OS_NAME}/${OS_NAME}-${candidate_slot}.efi
EOF

    # Use a glob pattern so the default keeps matching as systemd-boot's boot-counting
    # renames the file from +3-0 → +2-1 → +1-2 → +0-3 across successive boots.
    # A hardcoded +3-0 suffix would stop matching after the first successful boot.
    local loader_default="${OS_NAME}-${active_slot}+*.conf"
    local loader_conf="$ESP/loader/loader.conf"
    if [[ -f "$loader_conf" ]]; then
        grep -v "^default " "$loader_conf" > "${loader_conf}.tmp" || true
        echo "default ${loader_default}" >> "${loader_conf}.tmp"
        mv "${loader_conf}.tmp" "$loader_conf"
    else
        printf 'default %s\ntimeout 5\nconsole-mode max\neditor 0\nauto-entries 0\nbeep 0\n' \
            "${loader_default}" > "$loader_conf"
    fi
    log_verbose "loader.conf default set to ${loader_default}"
    log "Boot default set to: @${active_slot} (${loader_default}) | Fallback: @${candidate_slot}"

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

    log_error "An error occurred during deployment — initiating emergency rollback to restore a clean state"

    if [[ -z "${CANDIDATE_SLOT:-}" ]]; then
        log_warn "CANDIDATE_SLOT unknown — deriving from booted slot"
        local _booted
        _booted=$(get_booted_subvol)
        if [[ "$_booted" == "blue" ]]; then
            CANDIDATE_SLOT="green"
        elif [[ "$_booted" == "green" ]]; then
            CANDIDATE_SLOT="blue"
        else
            log_error "Cannot determine booted slot — aborting emergency rollback. Check btrfs subvolumes manually."
            umount -R "$MOUNT_DIR" 2>/dev/null || umount -R -l "$MOUNT_DIR" 2>/dev/null || true
            rm -f "$DEPLOY_PENDING" 2>/dev/null
            exit 1
        fi
        log "Derived candidate slot: @${CANDIDATE_SLOT}"
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
        log "Restoring @${CANDIDATE_SLOT} from backup @${BACKUP_NAME}..."

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
            btrfs subvolume snapshot "$MOUNT_DIR/@${BACKUP_NAME}" "$MOUNT_DIR/@${CANDIDATE_SLOT}" 2>/dev/null &&                 log_success "Restored @${CANDIDATE_SLOT} from @${BACKUP_NAME}"
            btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true 2>/dev/null
        fi

        local _rc_slot="${CURRENT_SLOT:-$(get_booted_subvol)}"
        echo "$_rc_slot" > "$MOUNT_DIR/@data/current-slot" 2>/dev/null ||             log_warn "Failed to write current-slot"
        echo "$CANDIDATE_SLOT" > "$MOUNT_DIR/@data/previous-slot" 2>/dev/null ||             log_warn "Failed to write previous-slot"
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
            log_error "Cannot restore @${CANDIDATE_SLOT} — no backup and cannot safely snapshot. System remains on @${CURRENT_SLOT:-booted slot}. Run --rollback after next reboot to clean up."
        fi
    fi

    btrfs_subvol_exists "$MOUNT_DIR/temp_update/shanios_base" && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update/shanios_base" 2>/dev/null
    btrfs_subvol_exists "$MOUNT_DIR/temp_update" && \
        btrfs subvolume delete "$MOUNT_DIR/temp_update" 2>/dev/null

    umount -R "$MOUNT_DIR" 2>/dev/null || umount -R -l "$MOUNT_DIR" 2>/dev/null || true
    rm -f "$DEPLOY_PENDING" 2>/dev/null
    # Clear the reboot-needed marker — the deployment that wrote it was just
    # rolled back, so showing a restart dialog for that version is misleading.
    rm -f "$REBOOT_NEEDED_FILE" 2>/dev/null || true

    finalize_boot_entries "${CURRENT_SLOT:-$(get_booted_subvol)}" "$CANDIDATE_SLOT" "no-tries" || \
        log_warn "Could not update boot entries — you may need to set the default boot slot manually"

    log_error "Emergency rollback complete — system remains on @${CURRENT_SLOT:-$(get_booted_subvol)}"
    log_error "Please reboot to ensure a clean system state"
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
    [[ ! "$booted" =~ ^(blue|green)$ ]] && die "Cannot determine booted slot (got: '${booted}') — check /proc/cmdline and btrfs subvolume get-default /"

    local failed_slot=$([[ "$booted" == "blue" ]] && echo "green" || echo "blue")

    # Cross-check against /data/boot_failure if it exists — it contains the slot
    # that actually failed. If it disagrees with our derivation (which should never
    # happen in practice), warn but proceed with the derived value since the user
    # is running from the working slot.
    if [[ -f /data/boot_failure ]]; then
        local recorded_fail
        recorded_fail=$(cat /data/boot_failure 2>/dev/null | tr -d '[:space:]' || true)
        if [[ -n "$recorded_fail" && "$recorded_fail" =~ ^(blue|green)$ && "$recorded_fail" != "$failed_slot" ]]; then
            log_warn "boot_failure records @${recorded_fail} but booted slot @${booted} implies @${failed_slot} failed"
            log_warn "Using @${failed_slot} (derived from booted slot) — boot_failure may be stale"
        fi
    fi

    CURRENT_SLOT="$booted"
    CANDIDATE_SLOT="$failed_slot"

    log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_warn "  ROLLBACK DIRECTION"
    log_warn "  You are currently booted into: @${booted}"
    log_warn "  @${booted} will remain the DEFAULT boot slot"
    log_warn "  @${failed_slot} will be restored from its backup"
    log_warn ""
    log_warn "  If this is NOT what you want, press Ctrl+C now"
    log_warn "  and reboot into @${failed_slot} before running rollback."
    log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    sleep 5

    log "Booted slot (keeping): @${booted} | Slot being restored: @${failed_slot}"

    BACKUP_NAME=$(btrfs subvolume list "$MOUNT_DIR" 2>/dev/null | \
        awk -v s="${failed_slot}_backup_" '$NF ~ s {print $NF}' | sort | tail -1)
    BACKUP_NAME="${BACKUP_NAME#@}"

    if [[ -z "$BACKUP_NAME" ]]; then
        log_warn "No backup snapshot found for @${failed_slot} — will create a fresh snapshot from @${booted} as fallback"

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
        finalize_boot_entries "$booted" "$failed_slot" "no-tries"
        rm -f "$REBOOT_NEEDED_FILE" 2>/dev/null || true
        log_success "Fallback slot ready"
        log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log "  Default boot slot: @${booted}"
        log "  Restored slot:     @${failed_slot} (snapshot of @${booted})"
        log "  Please reboot — the system will boot into @${booted}"
        log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
    log_success "Restored @${failed_slot} from @${BACKUP_NAME}"

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
    finalize_boot_entries "$booted" "$failed_slot" "no-tries"
    rm -f "$REBOOT_NEEDED_FILE" 2>/dev/null || true

    log_success "Rollback complete"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "  Default boot slot: @${booted}"
    log "  Restored slot:     @${failed_slot} (ready for next deploy)"
    log "  Please reboot — the system will boot into @${booted}"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
    (( avail_mb < size_mb )) && { log_warn "Insufficient space for swapfile: need ${size_mb}MB, have ${avail_mb}MB"; return 1; }

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

    log_error "All swapfile creation methods failed for: $file"
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
        log_verbose "No fstab found at ${fstab} — skipping subvolume and bind-dir verification"
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
                created=$((created + 1))
            else
                if mkdir -p "$full_path" 2>/dev/null; then
                    log_verbose "Created: $dir"
                    created=$((created + 1))
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
        log_warn "Slot marker is invalid or missing — using live boot slot @${booted}"
        CURRENT_SLOT="$booted"
        mkdir -p /data
        echo "$CURRENT_SLOT" > /data/current-slot
        log "Slot marker corrected to: @${CURRENT_SLOT}"
    fi

    log "Slot marker says: @${CURRENT_SLOT}"
    log "Actually booted:  @${booted}"

    if [[ "$booted" != "$CURRENT_SLOT" ]]; then
        if [[ "${FORCE_UPDATE:-no}" == "yes" ]]; then
            # If a reboot-needed marker exists the user deployed successfully and
            # just hasn't rebooted yet. Warn clearly before overwriting that slot.
            if [[ -f "$REBOOT_NEEDED_FILE" ]]; then
                local pending_ver
                pending_ver=$(cat "$REBOOT_NEEDED_FILE" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
                log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                log_warn "  WARNING: A deployment to v${pending_ver} is pending reboot"
                log_warn "  --force will OVERWRITE @${CURRENT_SLOT} and discard that deployment"
                log_warn "  To keep it: reboot first, then run shani-deploy again"
                log_warn "  Continuing in 10 seconds — press Ctrl+C to abort"
                log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                sleep 10
            fi
            log_warn "Slot mismatch detected (marker=@${CURRENT_SLOT}, booted=@${booted}) — correcting marker due to --force"
            CURRENT_SLOT="$booted"
            mkdir -p /data
            echo "$CURRENT_SLOT" > /data/current-slot
        else
            if [[ ! -f "$DEPLOY_PENDING" ]]; then
                log_warn "SLOT MISMATCH: marker says @${CURRENT_SLOT} but you are running @${booted}"
                log_warn "Possible causes:"
                log_warn "  1. Update was deployed but system not yet rebooted — please reboot to apply"
                log_warn "  2. Last update failed to boot and bootloader fell back — run --rollback to fix"
                log_warn "  3. System was manually booted into wrong slot — reboot into @${CURRENT_SLOT} or run --rollback"
                log_warn "To force update from currently running @${booted} regardless: run --force"
                exit 0
            else
                log_error "SLOT MISMATCH: marker says @${CURRENT_SLOT} but running @${booted}"
                log_error "A deployment_pending flag also exists — the previous deploy may be incomplete or interrupted"
                die "Run --rollback to restore a clean state, or --force to override and update from @${booted}"
            fi
        fi
    fi

    log_success "Boot slot validated: @${booted}"
    CANDIDATE_SLOT=$([[ "$CURRENT_SLOT" == "blue" ]] && echo "green" || echo "blue")
    log "Active slot: @${CURRENT_SLOT} | Update target (candidate): @${CANDIDATE_SLOT}"
}

check_space() {
    log_section "Disk Space Check"

    if ! mountpoint -q /data 2>/dev/null && ! [ -d /data ]; then
        die "/data is not available — cannot check disk space. Ensure the data subvolume is mounted."
    fi
    local free_mb=$(( $(df --output=avail "/data" | tail -1) / 1024 ))
    log "Available space: ${free_mb}MB | Required: ${MIN_FREE_SPACE_MB}MB"

    (( free_mb >= MIN_FREE_SPACE_MB )) || \
        die "Not enough disk space: ${free_mb}MB available, ${MIN_FREE_SPACE_MB}MB required. Run --cleanup to remove old downloads and backups, then try again."

    log_success "Sufficient disk space available"
    run_cmd mkdir -p "$DOWNLOAD_DIR"
}

fetch_update() {
    log_section "Update Check"

    local sf_url="https://sourceforge.net/projects/shanios/files/${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    local r2_path="${LOCAL_PROFILE}/${UPDATE_CHANNEL}.txt"
    local temp
    temp=$(mktemp /run/shanios-fetchupdate.XXXXXX)

    log "Fetching latest version info from ${UPDATE_CHANNEL} channel..."
    download_from_r2 "$r2_path" "$temp" 1 || \
        download_file "$sf_url" "$temp" 1 || { rm -f "$temp"; die "Failed to fetch version manifest — check your internet connection"; }

    IMAGE_NAME=$(tr -d '[:space:]' < "$temp")
    rm -f "$temp"

    [[ "$IMAGE_NAME" =~ ^shanios-([0-9]+)-([a-zA-Z]+)\.zst$ ]] || die "Version manifest has unexpected format: ${IMAGE_NAME}"

    REMOTE_VERSION="${BASH_REMATCH[1]}"
    REMOTE_PROFILE="${BASH_REMATCH[2]}"

    log "Remote version: v${REMOTE_VERSION} (${REMOTE_PROFILE})"
    log "Local  version: v${LOCAL_VERSION} (${LOCAL_PROFILE})"
    if [[ "$REMOTE_PROFILE" != "$LOCAL_PROFILE" ]]; then
        log_warn "Profile mismatch: local=${LOCAL_PROFILE}, remote=${REMOTE_PROFILE} — update may change system profile"
    fi

    if (( REMOTE_VERSION < LOCAL_VERSION )); then
        log_warn "Remote version (v${REMOTE_VERSION}) is older than local (v${LOCAL_VERSION})"
        if [[ "${FORCE_UPDATE:-no}" != "yes" ]]; then
            log_success "System is newer than remote — no update needed"
            touch "${STATE_DIR}/skip-deployment"
            return 0
        fi
        log_warn "Proceeding with downgrade to v${REMOTE_VERSION} due to --force"
    fi

    (( REMOTE_VERSION > LOCAL_VERSION )) && { log_success "Update available: v${LOCAL_VERSION} → v${REMOTE_VERSION}"; return 0; }

    log "Local and remote versions match (v${REMOTE_VERSION})"
    mkdir -p "$MOUNT_DIR"
    safe_mount "$ROOT_DEV" "$MOUNT_DIR" "subvolid=5"
    trap 'safe_umount "$MOUNT_DIR" 2>/dev/null || force_umount_all "$MOUNT_DIR" || true' RETURN

    if ! btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        log_warn "Candidate slot @${CANDIDATE_SLOT} is missing — will redeploy from remote to recreate it"
        return 0
    fi

    if [[ "${FORCE_UPDATE:-no}" == "yes" ]]; then
        log "Redeploying v${REMOTE_VERSION} due to --force"
        return 0
    fi
    log_success "System is up to date (v${LOCAL_VERSION})"
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
            log_success "Using verified cached image: ${IMAGE_NAME} ($(format_bytes $existing_size))"
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
        log "Checking primary download server (R2)..."
        local r2_size
        r2_size=$(get_remote_file_size "$r2_image_url")
        if (( r2_size > MIN_FILE_SIZE )); then
            log_success "Primary server available — image size: $(format_bytes $r2_size)"
            use_r2=1
        else
            log_verbose "Primary server unavailable or returned unexpected size, falling back to SourceForge mirror"
        fi
    fi

    # Mirror discovery (SourceForge fallback)
    local mirror_url=""
    if (( use_r2 == 0 )); then
        log "Discovering SourceForge mirror for download..."
        mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
        mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
        [[ -z "$mirror_url" || ! "$mirror_url" =~ ^https?://[a-zA-Z0-9] ]] && die "Could not find a valid download mirror — check your internet connection and try again"
        log "Using mirror: ${mirror_url}"
    fi

    # Get expected size
    log_verbose "Checking remote image size..."
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
                    log "Existing file matches expected size — skipping download, will verify integrity"
                elif (( current_size < expected_size )); then
                    log "Will resume from $(format_bytes $current_size)"
                fi
            else
                log_warn "Cannot determine expected image size from server — will attempt resume and validate after"
            fi
        fi
    fi

    local download_success=0
    local global_attempt=0
    local max_global_attempts=5
    local current_mirror="$mirror_url"

    while (( download_success == 0 && global_attempt < max_global_attempts )); do
        global_attempt=$((global_attempt + 1))
        log "Download attempt ${global_attempt}/${max_global_attempts}"

        local dl_url
        (( use_r2 )) && dl_url="$r2_image_url" || dl_url="$mirror_url"
        log_verbose "Downloading from: ${dl_url}"

        # SourceForge doesn't reliably support resume — clear partial before each attempt
        if [[ "$dl_url" != *"downloads.shani.dev"* ]]; then
            [[ -f "$image" ]] && {
                log_verbose "Clearing partial SF download (no resume support)"
                rm -f "$image" "${image}.aria2"
            }
        fi

        if download_file "$dl_url" "$image" 0 "$expected_size"; then
            if [[ ! -f "$image" ]] || [[ ! -s "$image" ]]; then
                log_warn "Download attempt ${global_attempt} produced no output file — server may have rejected the request"
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
                log_warn "Primary server failing after ${global_attempt} attempts — switching to SourceForge mirror..."
                use_r2=0
                rm -f "$DOWNLOAD_DIR/mirror.url"
                mirror_url=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
                mirror_url=$(echo "$mirror_url" | tail -1 | tr -d '\r\n' | xargs)
                continue
            fi
            log "Rediscovering download mirror (attempt ${global_attempt})..."
            rm -f "$DOWNLOAD_DIR/mirror.url"

            local new_mirror
            new_mirror=$(get_mirror_url "shanios" "${REMOTE_PROFILE}/${REMOTE_VERSION}" "$IMAGE_NAME")
            new_mirror=$(echo "$new_mirror" | tail -1 | tr -d '\r\n' | xargs)

            if [[ -n "$new_mirror" && "$new_mirror" =~ ^https?://[a-zA-Z0-9] ]]; then
                if [[ "$new_mirror" != "$current_mirror" ]]; then
                    log "Switched to new mirror: ${new_mirror}"
                    current_mirror="$new_mirror"
                fi
                mirror_url="$new_mirror"
                expected_size=$(get_remote_file_size "$mirror_url")
            else
                log_warn "Mirror rediscovery failed — continuing with current mirror: ${current_mirror}"
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
        die "Download failed after $max_global_attempts attempts — check your internet connection or try again later"
    fi

    validate_download "$image" "$expected_size" || {
        rm -f "$image" "${image}.aria2"
        die "Downloaded image failed validation — it may be incomplete or corrupt. Restarting will retry the download."
    }

    log "Downloading verification files (SHA256 + GPG signature)..."
    download_from_r2 "${r2_image_path}.sha256" "$sha" 1 || \
        download_file "$sha_url" "$sha" 1 || {
            rm -f "$image" "${image}.aria2"
            die "Failed to download SHA256 checksum file"
        }
    download_from_r2 "${r2_image_path}.asc" "$asc" 1 || \
        download_file "$asc_url" "$asc" 1 || {
            rm -f "$image" "$sha" "${image}.aria2"
            die "Failed to download GPG signature file"
        }

    log "Verifying image integrity..."
    verify_sha256 "$image" "$sha" && verify_gpg "$image" "$asc" || {
        rm -f "$image" "$sha" "$asc" "${image}.aria2"
        die "Image verification failed — the download may be corrupt or tampered with"
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
        die "Candidate slot @${CANDIDATE_SLOT} is currently mounted — cannot deploy to an active mount"
    fi

    # SAFETY: confirm candidate is not the booted slot before any destructive operation.
    local deploy_booted
    deploy_booted=$(get_booted_subvol)
    if [[ "$CANDIDATE_SLOT" == "$deploy_booted" ]]; then
        safe_umount "$MOUNT_DIR"
        die "SAFETY ABORT: @${CANDIDATE_SLOT} is the currently booted slot — refusing to overwrite a running system"
    fi

    # Backup only — do NOT delete candidate yet. Deletion happens after extraction
    # succeeds so power failure during extraction leaves @CANDIDATE_SLOT intact.
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        BACKUP_NAME="${CANDIDATE_SLOT}_backup_$(date +%Y%m%d%H%M%S)"
        log "Creating safety backup of @${CANDIDATE_SLOT} → @${BACKUP_NAME}"
        run_cmd btrfs subvolume snapshot "$MOUNT_DIR/@${CANDIDATE_SLOT}" "$MOUNT_DIR/@${BACKUP_NAME}" || \
            { safe_umount "$MOUNT_DIR"; die "Backup snapshot failed — aborting to protect your system"; }
    fi

    local temp="$MOUNT_DIR/temp_update"
    if btrfs_subvol_exists "$temp"; then
        log_verbose "Removing leftover temp_update subvolume from previous run..."
        btrfs_subvol_exists "$temp/shanios_base" && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
        btrfs subvolume delete "$temp" 2>/dev/null
    fi

    log "Creating extraction workspace..."
    run_cmd btrfs subvolume create "$temp"

    log "Extracting system image into @${CANDIDATE_SLOT} (this may take a few minutes)..."
    [[ "${DRY_RUN}" == "yes" ]] && { log "[DRY-RUN] Would extract"; } || {
        local start=$(date +%s)
        if (( HAS_PV )); then
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                pv -p -t -e -r -b | btrfs receive "$temp" || {
                btrfs_subvol_exists "$temp/shanios_base" && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
                btrfs subvolume delete "$temp" 2>/dev/null
                safe_umount "$MOUNT_DIR"
                die "Extraction failed or timed out (limit: ${EXTRACTION_TIMEOUT}s) — image may be corrupt, try re-downloading"
            }
        else
            timeout "$EXTRACTION_TIMEOUT" zstd -d --long=31 -T0 "$DOWNLOAD_DIR/$IMAGE_NAME" -c | \
                btrfs receive "$temp" || {
                btrfs_subvol_exists "$temp/shanios_base" && btrfs subvolume delete "$temp/shanios_base" 2>/dev/null
                btrfs subvolume delete "$temp" 2>/dev/null
                safe_umount "$MOUNT_DIR"
                die "Extraction failed or timed out (limit: ${EXTRACTION_TIMEOUT}s) — image may be corrupt, try re-downloading"
            }
        fi
        log_success "Extracted in $(($(date +%s) - start))s"
    }

    # Extraction succeeded — now safe to replace candidate.
    if btrfs_subvol_exists "$MOUNT_DIR/@${CANDIDATE_SLOT}"; then
        run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro false
        run_cmd btrfs subvolume delete "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    fi

    log_verbose "Replacing @${CANDIDATE_SLOT} with extracted snapshot..."
    run_cmd btrfs subvolume snapshot "$temp/shanios_base" "$MOUNT_DIR/@${CANDIDATE_SLOT}"
    run_cmd btrfs property set -f -ts "$MOUNT_DIR/@${CANDIDATE_SLOT}" ro true

    btrfs_subvol_exists "$temp/shanios_base" && run_cmd btrfs subvolume delete "$temp/shanios_base"
    run_cmd btrfs subvolume delete "$temp"

    [[ "${DRY_RUN}" == "no" ]] && touch "$DEPLOY_PENDING"
    log_success "Image deployed to @${CANDIDATE_SLOT} (v${REMOTE_VERSION}) — pending finalization"
}

finalize_update() {
    log_section "Finalization"
    [[ "${DRY_RUN}" == "yes" ]] && return 0

    verify_and_create_subvolumes || die "Subvolume verification failed"
    generate_uki "$CANDIDATE_SLOT" || die "UKI generation failed"
    finalize_boot_entries "$CANDIDATE_SLOT" "$CURRENT_SLOT" || die "Failed to update boot entries — ESP may not be accessible"

    mkdir -p /data
    echo "$CURRENT_SLOT" > /data/previous-slot || die "Failed to write previous-slot"
    echo "$CANDIDATE_SLOT" > /data/current-slot || die "Failed to write current-slot"
    log_verbose "Slot markers written: current=@${CANDIDATE_SLOT}, previous=@${CURRENT_SLOT}"

    rm -f "$DEPLOY_PENDING" && log_verbose "Deployment pending flag cleared" || log_warn "Failed to remove deployment pending flag"

    # Write reboot-needed marker so shani-update can surface the reboot dialog
    # to the desktop session. pkexec strips DISPLAY/WAYLAND_DISPLAY so we cannot
    # call notify-send here reliably. The marker stores the deployed version so
    # the dialog can show what was installed.
    # /run is tmpfs — the file is cleared automatically on the next reboot,
    # so no explicit cleanup is needed when the user reboots into the new slot.
    mkdir -p /run/shanios && chmod 755 /run/shanios
    echo "$REMOTE_VERSION" > "$REBOOT_NEEDED_FILE" && chmod 644 "$REBOOT_NEEDED_FILE" || log_warn "Failed to write reboot-needed marker"
    log_verbose "Reboot-needed marker written: ${REBOOT_NEEDED_FILE}"

    # Write persistent marker so shani-user-setup runs after reboot into the
    # new slot. The .path unit watches /etc/passwd and /etc/skel, but skel
    # lives on the read-only root — inotify will not fire after a slot switch.
    # This marker is checked by shani-user-setup.service on boot and cleared
    # after a successful run.
    mkdir -p /data
    touch /data/user-setup-needed && chmod 644 /data/user-setup-needed \
        || log_warn "Failed to write user-setup-needed marker"
    log_verbose "user-setup-needed marker written — shani-user-setup will run after reboot"

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
        log_verbose "Could not mount root filesystem for post-deploy maintenance — skipping backup cleanup"
    fi

    cleanup_downloads || log_verbose "Download cleanup warnings"

    set -e
    trap 'restore_candidate' ERR

    local total_time=$(( $(date +%s) - DEPLOYMENT_START_TIME ))
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "  Deployment successful!"
    log "  Next boot will load: @${CANDIDATE_SLOT} (v${REMOTE_VERSION})"
    log "  Current slot:        @${CURRENT_SLOT} (still running)"
    log "  Total time:          ${total_time}s"
    log "  Please reboot to switch to the updated slot"
    log "  Tip: run with --optimize to reclaim disk space via deduplication"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    # Desktop notification is handled by shani-update which reads the
    # reboot-needed marker above — pkexec strips DISPLAY so notify-send here
    # would silently fail.
}

_info_cleanup_esp() {
    (( _INFO_ESP_MOUNTED == 1 )) && umount /boot/efi 2>/dev/null || true
}

system_info() {
    # system_info is read-only — don't pollute the deploy log
    echo ""
    echo "  =========================================="
    echo "    System Information"
    echo "  =========================================="

    # Track if we mounted ESP — mount early so UKI checks can access it
    _INFO_ESP_MOUNTED=0
    trap '_info_cleanup_esp' RETURN
    if ! mountpoint -q /boot/efi 2>/dev/null; then
        mount /boot/efi 2>/dev/null && _INFO_ESP_MOUNTED=1
    fi

    # Collect actionable recommendations throughout — printed at the end
    local -a recommendations=()
    # Cross-section state shared between UKI check and hibernate check
    local uki_booted_bad=0          # set if the booted slot's UKI fails sbverify
    local hibernate_offset_stale=0  # set if resume_offset in cmdline doesn't match swapfile

    # Pre-compute hibernate offset state early so the UKI section can reference it
    # (UKI check runs before the Disk/Swap section in the output order).
    # Use swapon to find the real swapfile path — strip trailing whitespace from
    # swapon column-padded output before the -f test.
    if command -v btrfs &>/dev/null; then
        local _pre_swapfile=""
        while IFS= read -r _dev; do
            _dev="${_dev%%[[:space:]]*}"   # strip trailing column padding
            [[ -z "$_dev" ]] && continue
            [[ -f "$_dev" ]] && { _pre_swapfile="$_dev"; break; }
        done < <(swapon --show=NAME --noheadings 2>/dev/null | grep -v zram || true)
        if [[ -n "$_pre_swapfile" ]]; then
            local _pre_actual _pre_cmdline _pre_btrfs_out
            # btrfs inspect-internal map-swapfile output varies by btrfs-progs version:
            #   newer: "resume_offset: 1972357"
            #   older: bare number only e.g. "2236549"
            # Try parsing resume_offset key first, then fall back to last bare number.
            _pre_btrfs_out=$(btrfs inspect-internal map-swapfile -r "$_pre_swapfile" 2>/dev/null || echo "")
            _pre_actual=$(echo "$_pre_btrfs_out" \
                | awk -F'[: \t]+' '/resume_offset/ {print $2; found=1} END {if (!found) exit 1}' 2>/dev/null || \
                  echo "$_pre_btrfs_out" | awk 'NF {last=$NF} END {print last+0}' 2>/dev/null || echo "")
            _pre_cmdline=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline \
                | cut -d= -f2 2>/dev/null || echo "")
            [[ -n "$_pre_actual" && "$_pre_actual" != "0" && -n "$_pre_cmdline" \
                && "$_pre_actual" != "$_pre_cmdline" ]] && hibernate_offset_stale=1
        fi
    fi

    # ── OS Identity ───────────────────────────────────────────────────────────
    local version profile channel slot_current slot_previous
    version=$(cat /etc/shani-version 2>/dev/null || echo "unknown")
    profile=$(cat /etc/shani-profile 2>/dev/null || echo "unknown")
    channel=$(cat /etc/shani-channel 2>/dev/null || echo "unknown")
    slot_current=$(cat /data/current-slot 2>/dev/null | tr -d '[:space:]' || echo "unknown")
    slot_previous=$(cat /data/previous-slot 2>/dev/null | tr -d '[:space:]' || echo "unknown")
    local booted
    booted=$(get_booted_subvol 2>/dev/null || echo "unknown")

    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │           ShaniOS System Status             │"
    echo "  └─────────────────────────────────────────────┘"
    echo ""
    echo "  OS"
    echo "    Version   : ${version}"
    echo "    Profile   : ${profile}"
    echo "    Channel   : ${channel}"
    echo "    Kernel    : $(uname -r 2>/dev/null || echo "unknown")"
    echo "    Uptime    : $(uptime -p 2>/dev/null | sed 's/^up //' || echo "unknown")"
    echo ""
    echo "  Slots"
    printf "    Active    : @%-10s" "${slot_current}"
    [[ "$booted" == "$slot_current" ]] && echo " ✓ (booted)" || echo " ✗ (mismatch — reboot pending?)"
    echo "    Fallback  : @${slot_previous}"
    echo "    Booted    : @${booted}"

    # ── Hardware ──────────────────────────────────────────────────────────────
    echo ""
    echo "  Hardware"
    local cpu_model cpu_cores ram_total
    cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//' || echo "unknown")
    cpu_cores=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "?")
    ram_total=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}' || echo "unknown")
    echo "    CPU       : ${cpu_model} (${cpu_cores} cores)"
    echo "    RAM       : ${ram_total} total"

    # ── Boot health ───────────────────────────────────────────────────────────
    echo ""
    echo "  Boot Health"
    if [[ -f /data/boot-ok ]]; then
        local last_ok
        last_ok=$(stat -c '%y' /data/boot-ok 2>/dev/null | cut -d. -f1 || echo "unknown")
        echo "    Last boot : ✓ Successful (${last_ok})"
    else
        # Distinguish a fresh install (version file recent, no failure flag) from
        # a genuine missing-record situation that might indicate a boot issue.
        local install_age_days=0
        if [[ -f /etc/shani-version ]]; then
            local install_epoch now_epoch
            install_epoch=$(stat -c '%Y' /etc/shani-version 2>/dev/null || echo "0")
            now_epoch=$(date +%s)
            install_age_days=$(( (now_epoch - install_epoch) / 86400 ))
        fi
        if (( install_age_days <= 3 )) && [[ ! -f /data/boot_failure ]]; then
            echo "    Last boot : — No record yet (fresh install, bless-boot pending)"
        else
            echo "    Last boot : ⚠ No successful boot recorded"
            recommendations+=("No successful boot recorded in /data/boot-ok — check bless-boot / boot-success.service")
        fi
    fi
    if [[ -f /data/boot_hard_failure ]]; then
        local hard_fail_slot
        hard_fail_slot=$(cat /data/boot_hard_failure 2>/dev/null | tr -d '[:space:]' || echo "unknown")
        echo "    Hard fail : ✗ Root mount FAILED for @${hard_fail_slot} — manual intervention required"
        recommendations+=("HARD BOOT FAILURE: @${hard_fail_slot} failed to mount — run: shani-deploy --rollback")
    elif [[ -f /data/boot_failure ]]; then
        local fail_slot
        fail_slot=$(cat /data/boot_failure 2>/dev/null | tr -d '[:space:]' || echo "unknown")
        echo "    Failure   : ⚠ Boot failure recorded for @${fail_slot}"
        recommendations+=("Boot failure recorded for @${fail_slot} — run: shani-deploy --rollback (restores slot from backup and regenerates its UKI)")
    fi
    if [[ -f /data/boot_failure.acked ]]; then
        echo "    Acked     : ⚠ Failure acknowledged — rollback dialog was shown (run --rollback if not done)"
    fi

    # ── Immutability ─────────────────────────────────────────────────────────
    echo ""
    echo "  Immutability"
    local root_opts
    root_opts=$(findmnt -n -o OPTIONS / 2>/dev/null || true)
    if echo "$root_opts" | grep -qw 'ro'; then
        echo "    Root (/)  : ✓ Read-only"
    else
        echo "    Root (/)  : ✗ Writable — immutability may be compromised"
        recommendations+=("Root filesystem is writable — reboot may be required")
    fi

    # ── Kernel Security ───────────────────────────────────────────────────────
    echo ""
    echo "  Kernel Security"

    # Active LSMs
    local active_lsms
    active_lsms=$(cat /sys/kernel/security/lsm 2>/dev/null | tr ',' ' ' || echo "unknown")
    echo "    LSMs      : ${active_lsms}"

    # Determine whether integrity/IMA is a kernel build choice or a config error.
    # CONFIG_IMA=n means the integrity LSM never registers — the lsm= cmdline entry
    # is silently ignored. This is a deliberate build decision, not a misconfiguration.
    local ima_compiled=0
    zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_IMA=y' && ima_compiled=1

    # Check all expected LSMs are loaded — exclude 'integrity' when IMA is not compiled in
    local expected_lsms=(landlock lockdown yama integrity apparmor bpf)
    local missing_lsms=() missing_build=()
    for lsm in "${expected_lsms[@]}"; do
        if ! echo "$active_lsms" | grep -qw "$lsm"; then
            if [[ "$lsm" == "integrity" && $ima_compiled -eq 0 ]]; then
                missing_build+=("$lsm")
            else
                missing_lsms+=("$lsm")
            fi
        fi
    done

    local lsm_expected_count=6
    local lsm_active_count=$(( lsm_expected_count - ${#missing_lsms[@]} - ${#missing_build[@]} ))
    if [[ ${#missing_lsms[@]} -eq 0 && ${#missing_build[@]} -eq 0 ]]; then
        echo "    LSM check : ✓ All ${lsm_expected_count} LSMs active"
    elif [[ ${#missing_lsms[@]} -eq 0 && ${#missing_build[@]} -gt 0 ]]; then
        echo "    LSM check : — ${lsm_active_count}/${lsm_expected_count} active (${missing_build[*]} not compiled in — intentional)"
    else
        echo "    LSM check : ✗ Missing: ${missing_lsms[*]}"
        recommendations+=("Some LSMs not active: ${missing_lsms[*]} — check kernel cmdline lsm= parameter")
    fi

    # IMA — report accurately based on build config and runtime state
    if [[ -d /sys/kernel/security/ima ]]; then
        local ima_policy
        ima_policy=$(cat /sys/kernel/security/ima/policy 2>/dev/null | wc -l || echo "0")
        echo "    IMA       : ✓ Active (${ima_policy} policy rules)"
    elif echo "$active_lsms" | grep -qw 'integrity'; then
        echo "    IMA       : ✓ Active (integrity LSM loaded)"
    elif (( ima_compiled == 0 )); then
        echo "    IMA       : — Not compiled in (CONFIG_IMA=n)"
    else
        echo "    IMA       : ✗ Not active (CONFIG_IMA=y but LSM not loaded — check lsm= cmdline)"
        recommendations+=("IMA is compiled in but not active — ensure 'integrity' is in lsm= kernel cmdline parameter")
    fi

    # Lockdown mode — meaningful only when Secure Boot is active
    local lockdown_mode
    lockdown_mode=$(cat /sys/kernel/security/lockdown 2>/dev/null | grep -o '\[.*\]' | tr -d '[]' || echo "none")
    if [[ "$lockdown_mode" == "none" ]]; then
        # Check if SB is off — if so, lockdown=none is expected/harmless
        local _sb_check
        _sb_check=$(mokutil --sb-state 2>/dev/null || echo "")
        if [[ "$_sb_check" == *"SecureBoot enabled"* ]]; then
            echo "    Lockdown  : ⚠ none (Secure Boot active but lockdown not enforced)"
            recommendations+=("Kernel lockdown is 'none' despite Secure Boot being enabled — consider adding lockdown=confidentiality to cmdline")
        else
            echo "    Lockdown  : — none (expected without Secure Boot)"
        fi
    else
        echo "    Lockdown  : ✓ ${lockdown_mode}"
    fi

    # ── Secure Boot ───────────────────────────────────────────────────────────
    echo ""
    echo "  Secure Boot"
    if [[ ! -d /sys/firmware/efi ]]; then
        echo "    Status    : N/A (BIOS/Legacy boot)"
    else
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
        if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then
            echo "    Status    : ✓ Enabled"
        else
            echo "    Status    : ✗ Disabled"
            recommendations+=("Enable Secure Boot in BIOS/UEFI for full boot chain protection")
        fi

        # MOK enrollment in firmware
        local mok_enrolled_count
        mok_enrolled_count=$(mokutil --list-enrolled 2>/dev/null | grep -c 'SHA1 Fingerprint' || echo "0")
        if (( mok_enrolled_count > 0 )); then
            echo "    MOK Enrol : ✓ ${mok_enrolled_count} key(s) enrolled in firmware"
        else
            echo "    MOK Enrol : ✗ No MOK keys enrolled in firmware"
            recommendations+=("Enroll MOK key: reboot and confirm in MokManager, or run: mokutil --import /etc/secureboot/keys/MOK.der --root-pw")
        fi

        # MOK keys on disk
        local mok_key="/etc/secureboot/keys/MOK.key"
        local mok_crt="/etc/secureboot/keys/MOK.crt"
        local mok_der="/etc/secureboot/keys/MOK.der"
        local mok_ok=0
        if [[ -f "$mok_key" && -f "$mok_crt" && -f "$mok_der" ]]; then
            mok_ok=1
            local expiry
            expiry=$(openssl x509 -in "$mok_crt" -noout -enddate 2>/dev/null \
                | sed 's/notAfter=//' || echo "unknown")
            echo "    MOK Keys  : ✓ Present (expires: ${expiry})"
        else
            echo "    MOK Keys  : ✗ Missing"
            recommendations+=("MOK signing keys missing — run: gen-efi configure <slot>")
        fi

        # UKI signing status — only check if MOK cert is available
        if [[ $mok_ok -eq 1 ]]; then
            local uki_ok=0 uki_bad=0 uki_missing=0
            local uki_bad_slots=() uki_missing_slots=()
            # uki_booted_bad is function-scoped (declared at top of system_info)
            for slot in blue green; do
                local uki="/boot/efi/EFI/${OS_NAME}/${OS_NAME}-${slot}.efi"
                if [[ -f "$uki" ]]; then
                    if sbverify --cert "$mok_crt" "$uki" &>/dev/null 2>&1; then
                        uki_ok=$((uki_ok + 1))
                    else
                        uki_bad=$((uki_bad + 1))
                        uki_bad_slots+=("$slot")
                        [[ "$slot" == "$booted" ]] && uki_booted_bad=1
                    fi
                else
                    uki_missing=$((uki_missing + 1))
                    uki_missing_slots+=("$slot")
                fi
            done
            if (( uki_bad > 0 || uki_missing > 0 )); then
                echo "    UKI Sigs  : ✗ ${uki_ok}/2 valid, ${uki_bad} invalid, ${uki_missing} missing"
                # Check if the bad slot matches a recorded boot failure — if so,
                # --rollback is the right fix (it restores the slot AND regenerates its UKI).
                # gen-efi configure can only be run for the booted slot from the live system.
                local _boot_fail_slot
                _boot_fail_slot=$(cat /data/boot_failure 2>/dev/null | tr -d '[:space:]' || echo "")
                for _bad in "${uki_bad_slots[@]}" "${uki_missing_slots[@]}"; do
                    if [[ "$_bad" == "$booted" ]]; then
                        # hibernate_offset_stale is pre-computed before this section runs
                        local _uki_also_hibernate=""
                        (( hibernate_offset_stale )) && _uki_also_hibernate=" (also fixes stale hibernate offset)"
                        recommendations+=("UKI for @${_bad} (booted slot) is invalid — run: gen-efi configure ${_bad}${_uki_also_hibernate}  [AUTOMATABLE]")
                    elif [[ -n "$_boot_fail_slot" && "$_bad" == "$_boot_fail_slot" ]]; then
                        recommendations+=("UKI for @${_bad} is invalid (matches boot failure) — fixed automatically by: shani-deploy --rollback")
                    else
                        recommendations+=("UKI for @${_bad} is invalid — run: shani-deploy --rollback (regenerates UKI via chroot) or shani-deploy to trigger a fresh deploy")
                    fi
                done
            else
                echo "    UKI Sigs  : ✓ ${uki_ok}/2 valid"
            fi
        else
            echo "    UKI Sigs  : — Cannot verify (MOK cert missing)"
        fi
    fi

    # ── Encryption ────────────────────────────────────────────────────────────
    echo ""
    echo "  Encryption"
    if [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        echo "    LUKS      : ✓ Active (/dev/mapper/${ROOTLABEL})"

        local underlying
        underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
            | sed -n 's/^ *device: //p' || true)
        if [[ -n "$underlying" ]]; then
            local luks_uuid
            luks_uuid=$(cryptsetup luksUUID "$underlying" 2>/dev/null || echo "unknown")
            echo "    Device    : ${underlying}"
            echo "    UUID      : ${luks_uuid}"

            # Single luksDump call — reused for cipher, KDF
            local luks_dump
            luks_dump=$(cryptsetup luksDump "$underlying" 2>/dev/null || true)
            local luks_cipher luks_kdf
            luks_cipher=$(echo "$luks_dump" | awk '/cipher:/ {print $2; exit}' || echo "unknown")
            luks_kdf=$(echo "$luks_dump" | awk '/PBKDF:/ {print $2; exit}' || echo "unknown")
            echo "    Cipher    : ${luks_cipher}"
            if [[ "$luks_kdf" == "argon2id" ]]; then
                echo "    KDF       : ✓ ${luks_kdf} (strong)"
            else
                echo "    KDF       : ⚠ ${luks_kdf} (argon2id recommended)"
                recommendations+=("LUKS KDF is ${luks_kdf} — consider re-encrypting with argon2id for stronger brute-force protection")
            fi

            # Single systemd-cryptenroll call — reused for keyslot count and TPM2 check
            local enroll_out
            enroll_out=$(systemd-cryptenroll "$underlying" 2>/dev/null || true)
            # Subtract 1 for the header line (SLOT TYPE)
            local keyslot_count
            keyslot_count=$(echo "$enroll_out" | grep -c '.' || echo "1")
            keyslot_count=$(( keyslot_count > 0 ? keyslot_count - 1 : 0 ))
            echo "    Keyslots  : ${keyslot_count} active"

            if echo "$enroll_out" | grep -q "tpm2"; then
                echo "    TPM2      : ✓ Enrolled (auto-unlock active)"
            else
                echo "    TPM2      : ✗ Not enrolled"
                if [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
                    recommendations+=("TPM2 not enrolled — automate disk unlock: gen-efi enroll-tpm2  [AUTOMATABLE]")
                fi
            fi

            # Keyfile
            local keyfile="/etc/cryptsetup-keys.d/${ROOTLABEL}.bin"
            if [[ -f "$keyfile" ]]; then
                echo "    Keyfile   : ✓ Present (${keyfile})"
            else
                echo "    Keyfile   : — Not used (PIN/passphrase system)"
            fi
        fi
    else
        echo "    LUKS      : — Not encrypted"
        recommendations+=("Disk is not encrypted — re-install with LUKS2 encryption enabled for data protection")
    fi

    # ── TPM2 ─────────────────────────────────────────────────────────────────
    echo ""
    echo "  TPM2"
    if [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
        local tpm_info
        tpm_info=$(systemd-cryptenroll --tpm2-device=list 2>/dev/null | grep -v '^PATH' | tail -1 || true)
        echo "    Hardware  : ✓ Present"
        [[ -n "$tpm_info" ]] && echo "    Device    : ${tpm_info}"
    else
        echo "    Hardware  : ✗ Not found or not enabled in BIOS"
    fi

    # ── Security Services ─────────────────────────────────────────────────────
    echo ""
    echo "  Security Services"

    # AppArmor — redirect aa-status --enabled stdout so it doesn't pollute output
    if command -v aa-status &>/dev/null; then
        if aa-status --enabled >/dev/null 2>&1; then
            local aa_enforced
            aa_enforced=$(aa-status 2>/dev/null | awk '/profiles are in enforce mode/ {print $1}' || echo "?")
            echo "    AppArmor  : ✓ Active (${aa_enforced} profiles enforcing)"
        else
            echo "    AppArmor  : ✗ Not enforcing"
            recommendations+=("AppArmor not enforcing — run: systemctl enable --now apparmor  [AUTOMATABLE]")
        fi
    else
        echo "    AppArmor  : — aa-status not found"
    fi

    # Firewall
    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            local fw_default
            fw_default=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
            echo "    Firewall  : ✓ Active (default zone: ${fw_default})"
        else
            echo "    Firewall  : ✗ firewalld not running"
            recommendations+=("Firewall not active — run: systemctl enable --now firewalld  [AUTOMATABLE]")
        fi
    else
        echo "    Firewall  : — Not installed"
    fi

    # fail2ban
    if command -v fail2ban-client &>/dev/null; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            local jail_count
            jail_count=$(fail2ban-client status 2>/dev/null \
                | awk -F',' '/Jail list/{gsub(/[[:space:]]/,"",$0); print NF}' || echo "?")
            echo "    fail2ban  : ✓ Active (${jail_count} jail(s))"
        else
            echo "    fail2ban  : ✗ Not running"
            recommendations+=("fail2ban not active — run: systemctl enable --now fail2ban  [AUTOMATABLE]")
        fi
    else
        echo "    fail2ban  : — Not installed"
    fi

    # Root account
    local root_locked
    root_locked=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")
    if [[ "$root_locked" == "L" || "$root_locked" == "LK" ]]; then
        echo "    Root acct : ✓ Locked (sudo via wheel only)"
    elif [[ "$root_locked" == "P" ]]; then
        echo "    Root acct : ⚠ Has password (locked root recommended)"
        recommendations+=("Root account has a password set — consider locking it: passwd -l root  [AUTOMATABLE]")
    else
        echo "    Root acct : — Status unknown"
    fi

    # SSH root login
    if [[ -f /etc/ssh/sshd_config ]] || [[ -d /etc/ssh/sshd_config.d ]]; then
        local ssh_root_login
        ssh_root_login=$(grep -rh '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
            | tail -1 | awk '{print $2}' || echo "")
        # OpenSSH >= 8.x default is prohibit-password (key-only), not "yes".
        # Only warn when the value is explicitly set to something risky or truly unknown.
        if [[ -z "$ssh_root_login" ]]; then
            local ssh_ver
            ssh_ver=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+' | head -1 || echo "0")
            if (( ssh_ver >= 8 )); then
                echo "    SSH Root  : ✓ Default (OpenSSH ${ssh_ver}.x — key-only by default)"
            else
                echo "    SSH Root  : ⚠ Default (OpenSSH <8 — explicit PermitRootLogin no recommended)"
                recommendations+=("Set PermitRootLogin no explicitly in sshd_config (OpenSSH <8 default may allow root login)")
            fi
        else
            case "$ssh_root_login" in
                no)                       echo "    SSH Root  : ✓ Disabled" ;;
                prohibit-password|without-password)
                                          echo "    SSH Root  : ✓ Key-only (no password)" ;;
                yes)                      echo "    SSH Root  : ✗ Enabled (password login as root allowed)"
                                          recommendations+=("SSH root login enabled — set PermitRootLogin no in sshd_config  [AUTOMATABLE]") ;;
                *)                        echo "    SSH Root  : ⚠ Unknown value: ${ssh_root_login}" ;;
            esac
        fi

        # SSH port
        local ssh_port
        ssh_port=$(grep -rh '^Port ' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
            | tail -1 | awk '{print $2}' || echo "22")
        echo "    SSH Port  : ${ssh_port:-22}"
    fi

    # Blacklisted kernel modules — Intel ME and pcspkr should not be loaded
    local bad_modules=()
    for mod in mei mei_me pcspkr; do
        lsmod 2>/dev/null | grep -qw "$mod" && bad_modules+=("$mod")
    done
    if [[ ${#bad_modules[@]} -eq 0 ]]; then
        echo "    Blacklist : ✓ mei/mei_me/pcspkr not loaded"
    else
        echo "    Blacklist : ⚠ Loaded modules that should be blacklisted: ${bad_modules[*]}"
        recommendations+=("Modules ${bad_modules[*]} are loaded but should be blacklisted — check /etc/modprobe.d/")
    fi

    # /etc/shadow permissions — 640 root shadow or 600 root root are both acceptable
    local shadow_perms
    shadow_perms=$(stat -c '%a %U %G' /etc/shadow 2>/dev/null || echo "unknown")
    if [[ "$shadow_perms" =~ ^(640\ root\ shadow|600\ root\ root)$ ]]; then
        echo "    Shadow    : ✓ Permissions OK (${shadow_perms})"
    elif [[ "$shadow_perms" != "unknown" ]]; then
        echo "    Shadow    : ⚠ Unexpected permissions: ${shadow_perms} (expected 640 root shadow)"
        recommendations+=("/etc/shadow has unexpected permissions (${shadow_perms}) — expected 640 root shadow")
    fi

    # ── Kernel sysctl hardening ───────────────────────────────────────────────
    echo ""
    echo "  Kernel Hardening"
    # Flat array of tuples: key  target  cmp  label
    #   cmp=min  → actual must be >= target  (higher = stricter, e.g. kptr_restrict=2 is fine when target=1)
    #   cmp=max  → actual must be <= target  (lower  = stricter, e.g. accept_redirects=0)
    #   cmp=eq   → actual must equal target  exactly (e.g. dmesg_restrict, tcp_syncookies)
    # Keys absent from this kernel are silently skipped from the denominator.
    # Keys marked info=1 are advisory only — don't count against the score.
    local sysctl_keys=(
    #   key                                      target  cmp   label
        "kernel.kptr_restrict"                   "1"    "min"  "hide kernel pointers"
        "kernel.dmesg_restrict"                  "1"    "eq"   "restrict dmesg to root"
        "kernel.unprivileged_bpf_disabled"       "1"    "min"  "disable unprivileged BPF"
        "net.core.bpf_jit_harden"                "2"    "min"  "harden BPF JIT"
        "kernel.yama.ptrace_scope"               "1"    "min"  "restrict ptrace"
        "net.ipv4.conf.all.accept_redirects"     "0"    "max"  "ignore IPv4 ICMP redirects"
        "net.ipv6.conf.all.accept_redirects"     "0"    "max"  "ignore IPv6 ICMP redirects"
        "net.ipv4.tcp_syncookies"                "1"    "eq"   "TCP SYN cookies"
        "net.ipv4.conf.all.rp_filter"            "1"    "info" "reverse path filtering (may be 0 with NetworkManager)"
        "kernel.unprivileged_userns_clone"       "0"    "info" "restrict user namespaces (Arch: read-only)"
    )
    local sysctl_ok=0 sysctl_total=0 sysctl_warn=() sysctl_info=()
    local i=0
    while (( i < ${#sysctl_keys[@]} )); do
        local key="${sysctl_keys[$i]}"
        local target="${sysctl_keys[$((i+1))]}"
        local cmp="${sysctl_keys[$((i+2))]}"
        local label="${sysctl_keys[$((i+3))]}"
        i=$(( i + 4 ))

        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "")
        [[ -z "$actual" ]] && continue   # key absent on this kernel — skip entirely

        # info-only keys: show as advisory, never count against score
        if [[ "$cmp" == "info" ]]; then
            if [[ "$actual" != "$target" ]]; then
                sysctl_info+=("${key}=${actual} (recommended ${target} — ${label})")
            fi
            continue
        fi

        sysctl_total=$(( sysctl_total + 1 ))

        local ok=0
        case "$cmp" in
            min) [[ "$actual" =~ ^[0-9]+$ ]] && (( actual >= target )) && ok=1 ;;
            max) [[ "$actual" =~ ^[0-9]+$ ]] && (( actual <= target )) && ok=1 ;;
            eq)  [[ "$actual" == "$target" ]] && ok=1 ;;
        esac

        if (( ok )); then
            sysctl_ok=$(( sysctl_ok + 1 ))
        else
            case "$cmp" in
                min) sysctl_warn+=("${key}=${actual} (want >=${target} — ${label})") ;;
                max) sysctl_warn+=("${key}=${actual} (want ${target} — ${label})") ;;
                eq)  sysctl_warn+=("${key}=${actual} (want ${target} — ${label})") ;;
            esac
        fi
    done

    if [[ ${#sysctl_warn[@]} -eq 0 ]]; then
        echo "    Sysctl    : ✓ ${sysctl_ok}/${sysctl_total} hardening keys correct"
    else
        echo "    Sysctl    : ⚠ ${sysctl_ok}/${sysctl_total} correct — mismatches:"
        for w in "${sysctl_warn[@]}"; do
            printf "              ✗ %s\n" "$w"
        done
        recommendations+=("Some sysctl hardening keys are not at recommended values — check /etc/sysctl.d/")
    fi
    for info in "${sysctl_info[@]}"; do
        printf "              — %s\n" "$info"
    done

    # USB device authorisation — check if new USB devices require explicit auth
    local usb_auth
    usb_auth=$(cat /sys/bus/usb/devices/usbX/authorized_default 2>/dev/null \
        || find /sys/bus/usb/devices -name 'authorized_default' -maxdepth 2 \
            -exec cat {} \; 2>/dev/null | head -1 || echo "")
    if [[ "$usb_auth" == "0" ]]; then
        echo "    USB Auth  : ✓ New devices require explicit authorisation"
    elif [[ "$usb_auth" == "1" ]]; then
        echo "    USB Auth  : — All USB devices auto-authorised (default)"
    fi

    # ── Disk ─────────────────────────────────────────────────────────────────
    echo ""
    echo "  Disk"
    # Root disk device
    local root_disk
    root_disk=$(lsblk -no PKNAME "$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/\[.*//')" 2>/dev/null \
        | head -1 || true)
    if [[ -z "$root_disk" ]]; then
        root_disk=$(lsblk -no PKNAME "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null | head -1 || echo "unknown")
    fi
    if [[ -n "$root_disk" && "$root_disk" != "unknown" ]]; then
        local disk_model disk_size disk_type
        disk_model=$(lsblk -dno MODEL "/dev/${root_disk}" 2>/dev/null | sed 's/[[:space:]]*$//' || echo "unknown")
        disk_size=$(lsblk -dno SIZE "/dev/${root_disk}" 2>/dev/null || echo "unknown")
        disk_type=$(lsblk -dno ROTA "/dev/${root_disk}" 2>/dev/null || echo "?")
        [[ "$disk_type" == "0" ]] && disk_type="SSD/NVMe" || disk_type="HDD"
        echo "    Device    : /dev/${root_disk} — ${disk_model} (${disk_size}, ${disk_type})"

        # SMART health (brief — smartctl short form)
        if command -v smartctl &>/dev/null; then
            local smart_health
            smart_health=$(smartctl -H "/dev/${root_disk}" 2>/dev/null \
                | awk '/overall-health|result/ {print $NF}' | head -1 || echo "unknown")
            if [[ "$smart_health" == "PASSED" ]]; then
                echo "    SMART     : ✓ PASSED"
            elif [[ -n "$smart_health" && "$smart_health" != "unknown" ]]; then
                echo "    SMART     : ✗ ${smart_health}"
                recommendations+=("SMART health check failed for /dev/${root_disk} — backup data immediately")
            else
                echo "    SMART     : — Not available (NVMe may need nvme-cli)"
            fi
            # SSD wear / temperature — NVMe and SATA differ in attribute names
            local smart_json
            smart_json=$(smartctl -j -A "/dev/${root_disk}" 2>/dev/null || true)
            if [[ -n "$smart_json" ]]; then
                # NVMe: percentage_used and temperature
                local nvme_wear nvme_temp
                nvme_wear=$(echo "$smart_json" | grep -o '"percentage_used"[^,}]*' \
                    | grep -o '[0-9]*' | head -1 || echo "")
                nvme_temp=$(echo "$smart_json" | grep -o '"temperature"[^,}]*' \
                    | grep -o '[0-9]\{2,3\}' | head -1 || echo "")
                # SATA: wear_leveling_count (ID 177) and airflow_temperature (ID 190/194)
                local sata_wear sata_temp
                sata_wear=$(echo "$smart_json" | grep -A5 '"id" *: *177' \
                    | grep '"value"' | grep -o '[0-9]*' | head -1 || echo "")
                sata_temp=$(echo "$smart_json" | grep -A5 '"id" *: *19[04]' \
                    | grep '"value"' | grep -o '[0-9]*' | head -1 || echo "")
                local wear="${nvme_wear:-$sata_wear}" temp="${nvme_temp:-$sata_temp}"
                if [[ -n "$wear" ]]; then
                    if (( wear >= 90 )); then
                        echo "    SSD Wear  : ✗ ${wear}% used — replace soon"
                        recommendations+=("SSD wear at ${wear}% — plan replacement before failure")
                    elif (( wear >= 70 )); then
                        echo "    SSD Wear  : ⚠ ${wear}% used"
                    else
                        echo "    SSD Wear  : ✓ ${wear}% used"
                    fi
                fi
                if [[ -n "$temp" ]]; then
                    if (( temp >= 70 )); then
                        echo "    Disk Temp : ✗ ${temp}°C (critically hot)"
                        recommendations+=("Disk temperature is ${temp}°C — check cooling")
                    elif (( temp > 55 )); then
                        echo "    Disk Temp : ⚠ ${temp}°C (warm)"
                    else
                        echo "    Disk Temp : ✓ ${temp}°C"
                    fi
                fi
            fi
        else
            echo "    SMART     : — smartctl not installed"
        fi
    else
        echo "    Device    : — Could not detect root disk"
    fi

    # Swap — detect all active swap devices (zram + swapfile can coexist)
    local swap_total swap_used
    swap_total=$(free -h 2>/dev/null | awk '/^Swap:/ {print $2}' || echo "0")
    swap_used=$(free -h 2>/dev/null | awk '/^Swap:/ {print $3}' || echo "0")
    if [[ "$swap_total" == "0" || "$swap_total" == "0B" ]]; then
        echo "    Swap      : ⚠ No swap active (hibernate unavailable, memory pressure unmanaged)"
    else
        echo "    Swap      : ✓ ${swap_used} used / ${swap_total} total"

        local has_zram=0 has_swapfile=0 swapfile_path=""
        swapon --show=NAME --noheadings 2>/dev/null | grep -q zram && has_zram=1
        while IFS= read -r swapdev; do
            swapdev="${swapdev%%[[:space:]]*}"   # strip trailing column padding
            [[ -z "$swapdev" ]] && continue
            if [[ -f "$swapdev" ]]; then
                has_swapfile=1
                swapfile_path="$swapdev"
            fi
        done < <(swapon --show=NAME --noheadings 2>/dev/null | grep -v zram || true)

        if (( has_zram && has_swapfile )); then
            echo "    Swap type : zram (memory pressure) + swapfile (hibernate)"
        elif (( has_zram )); then
            echo "    Swap type : zram only (compressed RAM — hibernate not available)"
        elif (( has_swapfile )); then
            echo "    Swap type : swapfile ${swapfile_path}"
        fi

        # Hibernate readiness — validate resume= and resume_offset= are in the active cmdline
        if (( has_swapfile )); then
            local cmdline
            cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
            local resume_ok=0 offset_ok=0
            echo "$cmdline" | grep -q 'resume=' && resume_ok=1
            echo "$cmdline" | grep -q 'resume_offset=' && offset_ok=1

            if (( resume_ok && offset_ok )); then
                # Verify the resume_offset matches the actual physical swapfile offset.
                # btrfs inspect-internal map-swapfile is authoritative for Btrfs swapfiles.
                # filefrag is a fallback for non-Btrfs (ext4 etc).
                local actual_offset=""
                configured_offset=$(echo "$cmdline" \
                    | grep -o 'resume_offset=[^ ]*' | cut -d= -f2 || echo "")

                if command -v btrfs &>/dev/null; then
                    local _btrfs_out
                    _btrfs_out=$(btrfs inspect-internal map-swapfile -r "$swapfile_path" 2>/dev/null || echo "")
                    actual_offset=$(echo "$_btrfs_out" \
                        | awk -F'[: \t]+' '/resume_offset/ {print $2; found=1} END {if (!found) exit 1}' 2>/dev/null || \
                          echo "$_btrfs_out" | awk 'NF {last=$NF} END {if (last+0>0) print last+0}' 2>/dev/null || echo "")
                fi
                # Fallback: filefrag — parse the physical start of the first extent
                # Output format: "0:        0..    7 :    2236549..   2236556 : 8 : last,eof"
                # Field 4 after the second colon is the physical start block.
                if [[ -z "$actual_offset" ]] && command -v filefrag &>/dev/null; then
                    actual_offset=$(filefrag -v -e "$swapfile_path" 2>/dev/null \
                        | awk 'NR>3 && /^\s*0:/ {gsub(/\.+/,"",$4); print $4; exit}' || echo "")
                fi

                if [[ -n "$actual_offset" && -n "$configured_offset" \
                        && "$actual_offset" == "$configured_offset" ]]; then
                    echo "    Hibernate : ✓ resume= and resume_offset=${configured_offset} correct"
                elif [[ -n "$actual_offset" && -n "$configured_offset" ]]; then
                    hibernate_offset_stale=1
                    echo "    Hibernate : ✗ resume_offset stale — cmdline=${configured_offset}, swapfile=${actual_offset}"
                    echo "    Hibernate   (swapfile recreated — regenerate booted slot UKI before hibernating)"
                    # gen-efi can only regenerate the currently booted slot directly.
                    # The candidate slot UKI will be regenerated automatically by the
                    # next shani-deploy run (via chroot) or --rollback.
                    # Only add a separate hibernate rec if the booted UKI rec doesn't already
                    # cover this (it does when uki_booted_bad=1, since it mentions the fix).
                    if (( ! uki_booted_bad )); then
                        recommendations+=("Hibernate resume_offset stale (cmdline=${configured_offset}, actual=${actual_offset}) — run: gen-efi configure ${booted}  (candidate slot updated automatically on next deploy/rollback)  [AUTOMATABLE]")
                    fi
                else
                    echo "    Hibernate : ✓ resume= and resume_offset= present in cmdline (offset unverifiable)"
                fi
            elif (( has_swapfile && ! resume_ok )); then
                echo "    Hibernate : ✗ swapfile present but resume= missing from cmdline"
                recommendations+=("Swapfile exists but resume= not in kernel cmdline — hibernate will not work — run: gen-efi configure ${booted}  [AUTOMATABLE]")
            fi
        fi
    fi

    # OOM kills since last boot — check kernel log for oom_kill events
    local oom_count
    oom_count=$(journalctl -k -b 0 --no-pager -q 2>/dev/null \
        | grep -c 'Out of memory\|oom_kill_process\|Killed process' || echo "0")
    if [[ "$oom_count" =~ ^[0-9]+$ ]] && (( oom_count > 0 )); then
        echo "    OOM kills : ⚠ ${oom_count} OOM event(s) this boot — system under memory pressure"
        recommendations+=("${oom_count} OOM kill event(s) since last boot — consider adding more RAM or swap")
    else
        echo "    OOM kills : ✓ None this boot"
    fi

    # ── /etc Overlay health ───────────────────────────────────────────────────
    echo ""
    echo "  /etc Overlay"
    local overlay_upper="/data/overlay/etc/upper"
    if [[ -d "$overlay_upper" ]]; then
        local overlay_count
        overlay_count=$(find "$overlay_upper" -mindepth 1 2>/dev/null | wc -l || echo "0")
        echo "    Files     : ${overlay_count} modified/added file(s) vs base"
        if [[ "$overlay_count" =~ ^[0-9]+$ ]] && (( overlay_count > 200 )); then
            echo "    Size      : ⚠ Large overlay — significant config drift from base image"
            recommendations+=("Large /etc overlay (${overlay_count} files) — consider upstreaming config to base image")
        elif [[ "$overlay_count" =~ ^[0-9]+$ ]] && (( overlay_count > 0 )); then
            # Show top-level dirs with most changes for quick orientation
            local top_dirs
            top_dirs=$(find "$overlay_upper" -mindepth 2 -maxdepth 2 2>/dev/null \
                | sed "s|${overlay_upper}/||" | cut -d/ -f1 | sort | uniq -c | sort -rn \
                | head -5 | awk '{printf "%s(%s) ", $2, $1}' || echo "")
            [[ -n "$top_dirs" ]] && echo "    Top dirs  : ${top_dirs}"
        fi
        # Check if /etc is actually mounted as overlay
        if findmnt -n -t overlay /etc &>/dev/null; then
            echo "    Mount     : ✓ Overlay active"
        else
            echo "    Mount     : ✗ Overlay not mounted — /etc may be from read-only root"
            recommendations+=("/etc overlay not mounted — check etc-overlay.mount unit")
        fi
    else
        echo "    Upper     : ✗ ${overlay_upper} missing"
        recommendations+=("/etc overlay upper directory missing — run shanios-tmpfiles-data.service")
    fi

    # ── Background Services ───────────────────────────────────────────────────
    echo ""
    echo "  Background Services"

    # bees deduplication daemon — UUID from blkid matching beesd-setup method
    local bees_uuid bees_unit bees_state
    bees_uuid=$(blkid -s UUID -o value /dev/disk/by-label/${ROOTLABEL} 2>/dev/null || true)
    if [[ -z "$bees_uuid" ]] && [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        bees_uuid=$(blkid -s UUID -o value /dev/mapper/${ROOTLABEL} 2>/dev/null || true)
    fi
    if [[ -n "$bees_uuid" ]]; then
        bees_unit="beesd@${bees_uuid}"
        bees_state=$(systemctl is-active "$bees_unit" 2>/dev/null || echo "inactive")
        if [[ "$bees_state" == "active" ]]; then
            echo "    bees dedup: ✓ Running (${bees_unit})"
        else
            echo "    bees dedup: ✗ Not running (${bees_unit} is ${bees_state})"
            if [[ ! -f "/etc/bees/${bees_uuid}.conf" ]]; then
                recommendations+=("bees not configured — run beesd-setup first, then: systemctl enable --now ${bees_unit}  [AUTOMATABLE]")
            else
                recommendations+=("bees deduplication not running — run: systemctl enable --now ${bees_unit}  [AUTOMATABLE]")
            fi
        fi
    else
        echo "    bees dedup: — Could not determine Btrfs UUID"
    fi

    # fwupd
    if systemctl is-active --quiet fwupd 2>/dev/null; then
        echo "    fwupd     : ✓ Running"
    else
        echo "    fwupd     : — Not running (on-demand)"
    fi

    # NetworkManager
    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo "    Network   : ✓ NetworkManager active"
    else
        echo "    Network   : ⚠ NetworkManager not running"
    fi

    # Failed systemd units — catch any service that has crashed and not recovered
    local failed_units
    mapfile -t failed_units < <(systemctl list-units --state=failed --no-legend --no-pager \
        2>/dev/null | awk '{print $1}' || true)
    if [[ ${#failed_units[@]} -eq 0 ]]; then
        echo "    Units     : ✓ No failed systemd units"
    else
        echo "    Units     : ✗ ${#failed_units[@]} failed unit(s): ${failed_units[*]}"
        recommendations+=("Failed systemd units: ${failed_units[*]} — run: systemctl status <unit> to investigate")
    fi

    # ── Boot entries ─────────────────────────────────────────────────────────
    echo ""
    echo "  Boot"
    if ! mountpoint -q /boot/efi 2>/dev/null; then
        echo "    ESP       : ✗ Could not mount — boot entries unavailable"
    elif mountpoint -q /boot/efi 2>/dev/null; then
        local loader_default
        loader_default=$(grep '^default' /boot/efi/loader/loader.conf 2>/dev/null \
            | awk '{print $2}' || echo "unknown")
        echo "    Default   : ${loader_default}"
        local entries
        entries=$(ls /boot/efi/loader/entries/*.conf 2>/dev/null \
            | xargs -I{} basename {} .conf | tr '\n' '  ' || echo "none")
        echo "    Entries   : ${entries}"

        # Detect orphaned plain .conf entries that coexist with a tries-suffixed
        # version of the same slot — left behind by interrupted deploys or manual edits.
        local orphan_entries=()
        for slot in blue green; do
            local plain="$ESP/loader/entries/${OS_NAME}-${slot}.conf"
            local has_tries
            has_tries=$(ls "$ESP/loader/entries/${OS_NAME}-${slot}"+*.conf 2>/dev/null | head -1 || echo "")
            if [[ -f "$plain" && -n "$has_tries" ]]; then
                orphan_entries+=("${OS_NAME}-${slot}.conf")
            fi
        done
        if [[ ${#orphan_entries[@]} -gt 0 ]]; then
            echo "    Orphans   : ⚠ Stale entries alongside tries-suffixed versions: ${orphan_entries[*]}"
            recommendations+=("Orphaned boot entries found (${orphan_entries[*]}) — run: shani-deploy --fix-security or remove manually from ESP/loader/entries/")
        fi
        local editor_val
        editor_val=$(grep '^editor' /boot/efi/loader/loader.conf 2>/dev/null | awk '{print $2}' || echo "not set")
        if [[ "$editor_val" == "0" ]]; then
            echo "    Editor    : ✓ Disabled"
        else
            echo "    Editor    : ✗ Not disabled (cmdline editable at boot)"
            recommendations+=("systemd-boot editor not disabled — add 'editor 0' to loader.conf  [AUTOMATABLE]")
        fi
    fi

    # ── Firmware updates ─────────────────────────────────────────────────────
    echo ""
    echo "  Firmware"
    if command -v fwupdmgr &>/dev/null; then
        local fw_output
        fw_output=$(fwupdmgr get-updates --offline 2>/dev/null || true)
        if echo "$fw_output" | grep -q 'GUID\|Version'; then
            local fw_count
            fw_count=$(echo "$fw_output" | grep -c 'GUID' || echo "1")
            echo "    fwupd     : ⚠ ${fw_count} update(s) available (run: fwupdmgr update)"
            recommendations+=("${fw_count} firmware update(s) available — run: fwupdmgr update")
        else
            # --offline reads cached metadata only — check how stale the cache is
            local fw_cache_age=""
            local fw_cache_dir="/var/cache/fwupd"
            if [[ -d "$fw_cache_dir" ]]; then
                local fw_cache_epoch now_epoch fw_cache_days
                fw_cache_epoch=$(find "$fw_cache_dir" -name "*.gz" -o -name "*.xml" 2>/dev/null \
                    | xargs stat -c '%Y' 2>/dev/null | sort -rn | head -1 || echo "0")
                now_epoch=$(date +%s)
                fw_cache_days=$(( (now_epoch - fw_cache_epoch) / 86400 ))
                if (( fw_cache_epoch > 0 && fw_cache_days > 7 )); then
                    fw_cache_age=" — cache ${fw_cache_days}d old, run: fwupdmgr refresh"
                fi
            fi
            echo "    fwupd     : ✓ Up to date (cached${fw_cache_age})"
        fi
    else
        echo "    fwupd     : — Not available"
    fi

    # ── Storage ───────────────────────────────────────────────────────────────
    echo ""
    echo "  Storage"
    local free_mb_raw
    free_mb_raw=$(df --output=avail /data 2>/dev/null | tail -1 | tr -d '[:space:]')
    if [[ "$free_mb_raw" =~ ^[0-9]+$ ]]; then
        echo "    Free      : $(( free_mb_raw / 1024 )) MB"
    else
        echo "    Free      : — (/data not mounted)"
    fi
    local btrfs_usage
    btrfs_usage=$(btrfs filesystem usage -b / 2>/dev/null \
        | awk '/Free \(estimated\):/ {printf "%.1f GB", $3/1024/1024/1024}' || echo "unknown")
    echo "    Btrfs free: ${btrfs_usage}"

    local backup_count
    backup_count=$(btrfs subvolume list / 2>/dev/null \
        | grep -cE '(blue|green)_backup_' || echo "0")
    echo "    Backups   : ${backup_count} snapshot(s) on disk"

    # Btrfs scrub — managed by btrfs-scrub.timer (btrfsmaintenance)
    local scrub_timer_active
    scrub_timer_active=$(systemctl is-active btrfs-scrub.timer 2>/dev/null || echo "inactive")
    if [[ "$scrub_timer_active" == "active" ]]; then
        # Use systemctl show for machine-readable next trigger — avoids awk fragility
        # on localised or multi-line 'systemctl status' output.
        local scrub_timer_next
        scrub_timer_next=$(systemctl show btrfs-scrub.timer --property=NextElapseUSecRealtime \
            --value 2>/dev/null || echo "")
        if [[ -z "$scrub_timer_next" || "$scrub_timer_next" == "0" ]]; then
            # Monotonic timer (not calendar-based) — try that property instead
            scrub_timer_next=$(systemctl show btrfs-scrub.timer --property=NextElapseUSecMonotonic \
                --value 2>/dev/null || echo "")
        fi
        # Convert microseconds to human date if we got a number
        if [[ "$scrub_timer_next" =~ ^[0-9]+$ ]] && (( scrub_timer_next > 0 )); then
            scrub_timer_next=$(date -d "@$(( scrub_timer_next / 1000000 ))" '+%Y-%m-%d %H:%M' 2>/dev/null \
                || echo "${scrub_timer_next}")
        elif [[ -z "$scrub_timer_next" || "$scrub_timer_next" == "0" ]]; then
            scrub_timer_next="unknown"
        fi
        echo "    Scrub tmr : ✓ Active (next: ${scrub_timer_next})"
    else
        echo "    Scrub tmr : ✗ btrfs-scrub.timer not active"
        recommendations+=("btrfs-scrub.timer not active — run: systemctl enable --now btrfs-scrub.timer  [AUTOMATABLE]")
    fi

    # Last scrub result
    local scrub_status scrub_result
    scrub_status=$(btrfs scrub status / 2>/dev/null || true)
    scrub_result=$(echo "$scrub_status" | awk '/Status:/ {print $2}' | head -1 || echo "")
    if [[ "$scrub_result" == "finished" ]]; then
        # Check specific error counters — any non-zero means data corruption
        local read_err csum_err corr_err
        read_err=$(echo "$scrub_status" | awk '/read_errors:/ {print $2}' | head -1 || echo "0")
        csum_err=$(echo "$scrub_status" | awk '/csum_errors:/ {print $2}' | head -1 || echo "0")
        corr_err=$(echo "$scrub_status" | awk '/corrected_errors:/ {print $2}' | head -1 || echo "0")
        if [[ "${read_err:-0}" != "0" || "${csum_err:-0}" != "0" || "${corr_err:-0}" != "0" ]]; then
            echo "    Scrub     : ✗ Errors found (read:${read_err} csum:${csum_err} corrected:${corr_err})"
            recommendations+=("Btrfs scrub found errors — investigate: btrfs scrub status /")
        else
            echo "    Scrub     : ✓ Last run clean"
        fi
    elif [[ "$scrub_result" == "running" ]]; then
        echo "    Scrub     : ↻ In progress"
    elif [[ -z "$scrub_result" ]]; then
        echo "    Scrub     : — No scrub recorded yet (first run scheduled by timer)"
    else
        echo "    Scrub     : ⚠ Status: ${scrub_result}"
    fi

    # Other btrfsmaintenance timers
    local -A btrfs_timers=(
        [balance]="btrfs-balance.timer"
        [defrag]="btrfs-defrag.timer"
        [trim]="btrfs-trim.timer"
    )
    local timer_ok=() timer_bad=()
    for name in balance defrag trim; do
        local unit="${btrfs_timers[$name]}"
        if [[ "$(systemctl is-active "$unit" 2>/dev/null)" == "active" ]]; then
            timer_ok+=("$name")
        else
            timer_bad+=("$name")
        fi
    done
    local timer_ok_str timer_bad_str
    timer_ok_str=$(IFS=' '; echo "${timer_ok[*]}")
    timer_bad_str=$(IFS=' '; echo "${timer_bad[*]}")
    [[ ${#timer_ok[@]} -gt 0 ]] && echo "    Maint tmr : ✓ Active: ${timer_ok_str}"
    if [[ ${#timer_bad[@]} -gt 0 ]]; then
        echo "    Maint tmr : ✗ Inactive: ${timer_bad_str}"
        local timer_units
        timer_units=$(printf '%s.timer ' "${timer_bad[@]}")
        recommendations+=("Btrfs maintenance timers inactive (${timer_bad_str}) — run: systemctl enable --now ${timer_units% }  [AUTOMATABLE]")
    fi

    echo "    ↳ Full analysis: shani-deploy --storage-info"

    # ── Deployment status ─────────────────────────────────────────────────────
    echo ""
    echo "  Deployment"
    if [[ -f "$DEPLOY_PENDING" ]]; then
        echo "    State     : ⚠ Pending (interrupted deploy?) — run: shani-deploy --rollback"
    elif [[ -f "$REBOOT_NEEDED_FILE" ]]; then
        local pending_ver
        pending_ver=$(cat "$REBOOT_NEEDED_FILE" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
        echo "    State     : ⚠ Reboot required to activate v${pending_ver}"
    else
        echo "    State     : ✓ Clean"
    fi
    # Last successful update — timestamp of /etc/shani-version as proxy
    if [[ -f /etc/shani-version ]]; then
        local ver_ts
        ver_ts=$(stat -c '%y' /etc/shani-version 2>/dev/null | cut -d. -f1 || echo "unknown")
        echo "    Installed : v${version} (since ${ver_ts})"
    fi

    # ── Security Recommendations ──────────────────────────────────────────────
    echo ""
    if [[ ${#recommendations[@]} -eq 0 ]]; then
        echo "  Security   : ✓ No issues found"
    else
        echo "  Security Recommendations"
        local i=1
        for rec in "${recommendations[@]}"; do
            printf "    %2d. %s\n" "$i" "$rec"
            i=$((i + 1))
        done
        echo ""
        echo "  Items marked [AUTOMATABLE] can be fixed by shani-deploy --fix-security"
    fi

    echo ""
}

fix_security() {
    log_section "Security Hardening"
    local fixed=0 failed=0

    # AppArmor
    if command -v aa-status &>/dev/null && ! aa-status --enabled >/dev/null 2>&1; then
        log "Enabling AppArmor..."
        if systemctl enable --now apparmor 2>/dev/null; then
            log_success "AppArmor enabled"
            fixed=$((fixed + 1))
        else
            log_warn "Failed to enable AppArmor"
            failed=$((failed + 1))
        fi
    fi

    # Firewall
    if command -v firewall-cmd &>/dev/null && ! systemctl is-active --quiet firewalld 2>/dev/null; then
        log "Enabling firewalld..."
        if systemctl enable --now firewalld 2>/dev/null; then
            log_success "firewalld enabled"
            fixed=$((fixed + 1))
        else
            log_warn "Failed to enable firewalld"
            failed=$((failed + 1))
        fi
    fi

    # fail2ban
    if command -v fail2ban-client &>/dev/null && ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        log "Enabling fail2ban..."
        if systemctl enable --now fail2ban 2>/dev/null; then
            log_success "fail2ban enabled"
            fixed=$((fixed + 1))
        else
            log_warn "Failed to enable fail2ban"
            failed=$((failed + 1))
        fi
    fi

    # Lock root account
    local root_locked
    root_locked=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")
    if [[ "$root_locked" == "P" ]]; then
        log "Locking root account..."
        if passwd -l root 2>/dev/null; then
            log_success "Root account locked"
            fixed=$((fixed + 1))
        else
            log_warn "Failed to lock root account"
            failed=$((failed + 1))
        fi
    fi

    # Disable SSH root login
    if [[ -f /etc/ssh/sshd_config ]]; then
        local ssh_root_login
        ssh_root_login=$(grep -rh '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
            | tail -1 | awk '{print $2}' || echo "default")
        if [[ "$ssh_root_login" == "yes" ]]; then
            log "Disabling SSH root login..."
            if sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null \
                && systemctl reload sshd 2>/dev/null; then
                log_success "SSH root login disabled"
                fixed=$((fixed + 1))
            else
                log_warn "Failed to disable SSH root login"
                failed=$((failed + 1))
            fi
        fi
    fi

    # systemd-boot editor + orphaned boot entries
    local _fix_esp_mounted=0
    if ! mountpoint -q /boot/efi 2>/dev/null; then
        mount /boot/efi 2>/dev/null && _fix_esp_mounted=1
    fi
    if mountpoint -q /boot/efi 2>/dev/null; then
        local editor_val
        editor_val=$(grep '^editor' /boot/efi/loader/loader.conf 2>/dev/null | awk '{print $2}' || echo "not set")
        if [[ "$editor_val" != "0" ]]; then
            log "Disabling systemd-boot editor..."
            if grep -q '^editor' /boot/efi/loader/loader.conf 2>/dev/null; then
                sed -i 's/^editor .*/editor 0/' /boot/efi/loader/loader.conf
            else
                echo "editor 0" >> /boot/efi/loader/loader.conf
            fi
            log_success "systemd-boot editor disabled"
            fixed=$((fixed + 1))
        fi

        # Remove orphaned plain slot .conf files that coexist with tries-suffixed versions
        for slot in blue green; do
            local plain_entry="$ESP/loader/entries/${OS_NAME}-${slot}.conf"
            local tries_entry
            tries_entry=$(ls "$ESP/loader/entries/${OS_NAME}-${slot}"+*.conf 2>/dev/null | head -1 || echo "")
            if [[ -f "$plain_entry" && -n "$tries_entry" ]]; then
                log "Removing orphaned boot entry: $(basename "$plain_entry")"
                if rm -f "$plain_entry" 2>/dev/null; then
                    log_success "Removed orphaned entry: $(basename "$plain_entry")"
                    fixed=$((fixed + 1))
                else
                    log_warn "Failed to remove: $(basename "$plain_entry")"
                    failed=$((failed + 1))
                fi
            fi
        done

        [[ $_fix_esp_mounted -eq 1 ]] && umount /boot/efi 2>/dev/null || true
    fi

    # btrfsmaintenance timers
    for timer in btrfs-scrub.timer btrfs-balance.timer btrfs-defrag.timer btrfs-trim.timer; do
        if [[ "$(systemctl is-active "$timer" 2>/dev/null)" != "active" ]]; then
            log "Enabling ${timer}..."
            if systemctl enable --now "$timer" 2>/dev/null; then
                log_success "${timer} enabled"
                fixed=$((fixed + 1))
            else
                log_warn "Failed to enable ${timer}"
                failed=$((failed + 1))
            fi
        fi
    done

    # bees deduplication daemon
    local bees_uuid
    bees_uuid=$(blkid -s UUID -o value /dev/disk/by-label/${ROOTLABEL} 2>/dev/null || true)
    if [[ -z "$bees_uuid" ]] && [[ -e "/dev/mapper/${ROOTLABEL}" ]]; then
        bees_uuid=$(blkid -s UUID -o value /dev/mapper/${ROOTLABEL} 2>/dev/null || true)
    fi
    if [[ -n "$bees_uuid" ]]; then
        local bees_unit="beesd@${bees_uuid}"
        if [[ "$(systemctl is-active "$bees_unit" 2>/dev/null)" != "active" ]]; then
            if [[ ! -f "/etc/bees/${bees_uuid}.conf" ]]; then
                log_warn "bees not configured yet — run beesd-setup.service first"
                log_warn "  systemctl start beesd-setup.service"
                failed=$((failed + 1))
            else
                log "Enabling ${bees_unit}..."
                if systemctl enable --now "$bees_unit" 2>/dev/null; then
                    log_success "${bees_unit} enabled"
                    fixed=$((fixed + 1))
                else
                    log_warn "Failed to enable ${bees_unit}"
                    failed=$((failed + 1))
                fi
            fi
        fi
    fi

    # TPM2 enrollment — prompt user, cannot do silently
    if [[ -e "/dev/mapper/${ROOTLABEL}" ]] && [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
        if ! systemd-cryptenroll "$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
            | sed -n 's/^ *device: //p')" 2>/dev/null | grep -q "tpm2"; then
            log_warn "TPM2 not enrolled — cannot automate (requires credential input)"
            log_warn "Run manually: gen-efi enroll-tpm2"
        fi
    fi

    # Hibernate resume_offset — regenerate booted slot UKI if swapfile offset has drifted.
    # gen-efi can only be called for the currently booted slot from the live system.
    # The candidate slot UKI is handled automatically by the next deploy or rollback.
    if [[ -f /swap/swapfile ]] && command -v btrfs &>/dev/null; then
        local _fix_swapfile="/swap/swapfile"
        local _fix_actual_offset _fix_cmdline_offset
        _fix_actual_offset=$(btrfs inspect-internal map-swapfile -r "$_fix_swapfile" \
            2>/dev/null | awk -F'[: \t]+' '/resume_offset/ {print $2}' || echo "")
        _fix_cmdline_offset=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline \
            | cut -d= -f2 || echo "")
        if [[ -n "$_fix_actual_offset" && -n "$_fix_cmdline_offset" \
                && "$_fix_actual_offset" != "$_fix_cmdline_offset" ]]; then
            local _fix_booted
            _fix_booted=$(get_booted_subvol 2>/dev/null || echo "")
            if [[ -n "$_fix_booted" ]] && [[ -x "$GENEFI_SCRIPT" ]]; then
                log "Regenerating UKI for @${_fix_booted} to fix stale resume_offset (${_fix_cmdline_offset} → ${_fix_actual_offset})..."
                if "$GENEFI_SCRIPT" configure "$_fix_booted" 2>&1; then
                    log_success "UKI regenerated for @${_fix_booted} — hibernate resume_offset now correct"
                    log "Candidate slot @$([[ "$_fix_booted" == "blue" ]] && echo green || echo blue) will be updated on next deploy or rollback"
                    fixed=$((fixed + 1))
                else
                    log_warn "UKI regeneration failed — hibernate may not work correctly until next deploy"
                    failed=$((failed + 1))
                fi
            else
                log_warn "Cannot fix hibernate offset — gen-efi not found at ${GENEFI_SCRIPT} or booted slot unknown"
                failed=$((failed + 1))
            fi
        fi
    fi

    echo ""
    if (( fixed > 0 || failed > 0 )); then
        log "Fixed: ${fixed} | Failed: ${failed}"
    else
        log_success "Nothing to fix — system already hardened"
    fi
    echo ""
    log "Run 'shani-deploy --info' to verify current security status"
}

#####################################
### Main Entry Point              ###
#####################################

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -h, --help              Show help
  -i, --info              Show system status (Secure Boot, encryption, slots, TPM2)
  --fix-security          Auto-fix security issues found by --info (services, SSH, boot editor, hibernate offset)
  -r, --rollback          Roll back the non-booted slot. IMPORTANT: run from the slot you want to KEEP.
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
    local ROLLBACK="no" CLEANUP="no" STORAGE_INFO="no" STORAGE_OPTIMIZE="no" SYSTEM_INFO="no" FIX_SECURITY="no"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            -i|--info) SYSTEM_INFO="yes"; shift ;;
            --fix-security) FIX_SECURITY="yes"; shift ;;
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
    [[ "${DRY_RUN}" == "yes" ]] && log_warn "[DRY-RUN] Simulation mode active — no changes will be made to the system"

    if [[ "$SYSTEM_INFO" == "yes" ]]; then
        system_info
        exit 0
    fi

    if [[ "$FIX_SECURITY" == "yes" ]]; then
        fix_security
        exit 0
    fi
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
            log_verbose "Could not mount root filesystem for backup cleanup — skipping"
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
        log "System is up to date — skipping deployment, running post-update maintenance"

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
            log_verbose "Could not mount root filesystem for maintenance — skipping backup cleanup"
        fi

        cleanup_downloads || log_verbose "Download cleanup warnings"

        log_success "Maintenance complete"
        log "Tip: run with --optimize to reclaim disk space via deduplication"
        exit 0
    fi

    download_update || die "Download failed"
    deploy_update || die "Deployment failed"
    if [[ -f "$DEPLOY_PENDING" ]]; then
        finalize_update
    else
        log_warn "Deployment pipeline completed but no pending flag was found — state may be inconsistent"
    fi
}

main "$@"
