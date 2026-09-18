#!/usr/bin/env bash
# shani-upgrade-adviser — Pre-upgrade advisory for ShaniOS
#
# Checks the currently installed shani version against available versions
# in shani-repo, verifies the system is upgrade-ready (disk space,
# dependencies), and outputs a human-readable or JSON upgrade advisory.
#
# Usage:
#   shani-upgrade-adviser              Full advisory report
#   shani-upgrade-adviser --check-only  Dry-run: report without acting
#   shani-upgrade-adviser --json        Machine-readable JSON output
#
# Install: /usr/local/bin/shani-upgrade-adviser

set -euo pipefail

#####################################
### Defaults                      ###
#####################################

DRY_RUN=false
JSON_OUTPUT=false
REPO_DIR="/home/shrinivaskumbhar/Documents/shani/shani-repo"
INSTALLED_VERSION="0.0.0"
AVAILABLE_VERSION="0.0.0"

#####################################
### Flag parsing                  ###
#####################################

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check-only) DRY_RUN=true ;;
        --json)       JSON_OUTPUT=true ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

#####################################
### Version detection             ###
#####################################

if [[ -f /etc/shani/version ]]; then
    INSTALLED_VERSION=$(cat /etc/shani/version | tr -d '[:space:]')
fi

if [[ -f "$REPO_DIR/version" ]]; then
    AVAILABLE_VERSION=$(cat "$REPO_DIR/version" | tr -d '[:space:]')
fi

#####################################
### Version comparison            ###
#####################################

# Returns: 0=equal, 1=installed<available (upgrade available), 2=installed>available
_version_compare() {
    local v1="$1" v2="$2"
    [[ "$v1" == "$v2" ]] && return 0
    [[ "$v1" < "$v2"  ]] && return 1
    return 2
}

UPGRADE_AVAILABLE=false
_version_compare "$INSTALLED_VERSION" "$AVAILABLE_VERSION"
case $? in
    1) UPGRADE_AVAILABLE=true ;;
    0|2) UPGRADE_AVAILABLE=false ;;
esac

#####################################
### Upgrade-readiness checks      ###
#####################################

# --- Disk space check ---
DISK_AVAIL_KB=$(df / | tail -1 | awk '{print $4}')
DISK_AVAIL_MB=$(( DISK_AVAIL_KB / 1024 ))
DISK_OK=true
DISK_MSG="OK (${DISK_AVAIL_MB} MB free)"
if [[ "$DISK_AVAIL_MB" -lt 1024 ]]; then
    DISK_OK=false
    DISK_MSG="WARNING — only ${DISK_AVAIL_MB} MB free (1024 MB minimum recommended)"
fi

# --- Dependency check ---
REQUIRED_COMMANDS=(bash curl gzip tar)
MISSING_DEPS=()
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
        MISSING_DEPS+=("$cmd")
    fi
done

DEPS_OK=true
if [[ ${#MISSING_DEPS[@]} -eq 0 ]]; then
    DEPS_MSG="OK (${REQUIRED_COMMANDS[*]})"
else
    DEPS_OK=false
    DEPS_MSG="MISSING: ${MISSING_DEPS[*]}"
fi

UPGRADE_READY=true
if [[ "$DISK_OK" != "true" ]] || [[ "$DEPS_OK" != "true" ]]; then
    UPGRADE_READY=false
fi

#####################################
### Report output                 ###
#####################################

if [[ "$JSON_OUTPUT" == "true" ]]; then
    printf '%s\n' \
        "{\"installed_version\":\"$INSTALLED_VERSION\"," \
        "\"available_version\":\"$AVAILABLE_VERSION\"," \
        "\"upgrade_available\":$UPGRADE_AVAILABLE," \
        "\"dry_run\":$DRY_RUN," \
        "\"upgrade_ready\":$UPGRADE_READY," \
        "\"disk_space\":{\"available_mb\":$DISK_AVAIL_MB,\"ok\":$DISK_OK,\"message\":\"$DISK_MSG\"}," \
        "\"dependencies\":{\"ok\":$DEPS_OK,\"message\":\"$DEPS_MSG\"}," \
        "\"required_commands\":$(printf '%s\n' "${REQUIRED_COMMANDS[@]}" | jq -R . | jq -s .)}" \
        | jq .
else
    echo "=== Shani Upgrade Adviser ==="
    echo ""
    echo "Installed version:  $INSTALLED_VERSION"
    echo "Available version:  $AVAILABLE_VERSION"
    if [[ "$UPGRADE_AVAILABLE" == "true" ]]; then
        echo "Upgrade available:  YES  ($INSTALLED_VERSION → $AVAILABLE_VERSION)"
    else
        echo "Upgrade available:  NO"
    fi
    echo ""
    echo "--- Upgrade Readiness ---"
    echo "Disk space:         $DISK_MSG"
    echo "Dependencies:       $DEPS_MSG"
    if [[ "$UPGRADE_READY" == "true" ]]; then
        echo "System ready:       YES"
    else
        echo "System ready:       NO — resolve the issues above before upgrading"
    fi
    echo ""
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "Mode:               Check-only (dry run) — no changes will be made"
    fi
    echo "=== End of Report ==="
fi
