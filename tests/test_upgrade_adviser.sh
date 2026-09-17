#!/usr/bin/env bash
# test_upgrade_adviser.sh — Tests for shani-upgrade-adviser
#
# Tests the upgrade adviser with various version scenarios, flag options,
# and output formats. Cleans up all temporary files after testing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADVISER="$SCRIPT_DIR/../bin/shani-upgrade-adviser"
TEMP_DIR=$(mktemp -d)
TRAP_CLEANUP=false

cleanup() {
    if [[ "$TRAP_CLEANUP" == "true" ]]; then
        rm -rf "$TEMP_DIR"
        TRAP_CLEANUP=false
    fi
}
trap cleanup EXIT
TRAP_CLEANUP=true

PASS=0
FAIL=0

assert_pass() {
    local name="$1"
    if eval "$2" &>/dev/null; then
        echo "  ✓ $name"
        PASS=$((PASS + 1))
    else
        echo "  ✗ $name"
        FAIL=$((FAIL + 1))
    fi
}

assert_json_field() {
    local json="$1" field="$2" expected="$3"
    local actual
    actual=$(echo "$json" | jq -r ".$field" 2>/dev/null)
    [[ "$actual" == "$expected" ]]
}

echo "=== Upgrade Adviser Tests ==="
echo ""

#####################################
### Test: Flag options            ###
#####################################
echo "--- Flag Options ---"

assert_pass "--check-only runs without error" \
    "$ADVISER --check-only"

assert_pass "--json runs without error" \
    "$ADVISER --json"

assert_pass "default mode runs without error" \
    "$ADVISER"

assert_pass "unknown flag exits with error" \
    "! $ADVISER --unknown-flag 2>/dev/null"

#####################################
### Test: Version scenarios       ###
#####################################
echo ""
echo "--- Version Scenarios ---"

# Scenario 1: Installed version < Available version (upgrade available)
V1_DIR="$TEMP_DIR/v1"
mkdir -p "$V1_DIR/repo"
echo "1.0.0" > "$V1_DIR/etc_shani_version"
echo "2.0.0" > "$V1_DIR/repo/version"

RESULT1=$($ADVISER 2>/dev/null || true)
# When /etc/shani/version doesn't exist, INSTALLED_VERSION defaults to 0.0.0
# and when repo/version doesn't exist either, AVAILABLE_VERSION defaults to 0.0.0
# So we test with the actual file-based approach via env override is not possible
# without modifying the script. Instead, test the comparison logic indirectly.

# Test: default versions (no files) — should report no upgrade (both 0.0.0)
assert_pass "default: no upgrade when versions are equal" \
    "$ADVISER --json | jq -e '.upgrade_available == false'"

# Scenario 2: Test JSON output structure
echo ""
echo "--- JSON Output Structure ---"

JSON_OUT=$($ADVISER --json 2>/dev/null || echo "{}")
assert_pass "JSON has installed_version field" \
    "echo '$JSON_OUT' | jq -e 'has(\"installed_version\")'"

assert_pass "JSON has available_version field" \
    "echo '$JSON_OUT' | jq -e 'has(\"available_version\")'"

assert_pass "JSON has upgrade_available field" \
    "echo '$JSON_OUT' | jq -e 'has(\"upgrade_available\")'"

assert_pass "JSON has dry_run field" \
    "echo '$JSON_OUT' | jq -e 'has(\"dry_run\")'"

assert_pass "JSON dry_run is boolean" \
    "echo '$JSON_OUT' | jq -e '.dry_run | type == \"boolean\"'"

assert_pass "JSON upgrade_available is boolean" \
    "echo '$JSON_OUT' | jq -e '.upgrade_available | type == \"boolean\"'"

# Scenario 3: --check-only JSON mode
echo ""
echo "--- Check-Only JSON Mode ---"

CHECK_JSON=$($ADVISER --check-only --json 2>/dev/null || echo "{}")
assert_pass "--check-only --json includes dry_run:true" \
    "echo '$CHECK_JSON' | jq -e '.dry_run == true'"

# Scenario 4: Human-readable output contains expected sections
echo ""
echo "--- Human-Readable Output ---"

HUMAN_OUT=$($ADVISER 2>/dev/null || echo "")
assert_pass "human output contains 'Installed version'" \
    "echo '$HUMAN_OUT' | grep -q 'Installed version'"

assert_pass "human output contains 'Available version'" \
    "echo '$HUMAN_OUT' | grep -q 'Available version'"

assert_pass "human output contains 'Upgrade available'" \
    "echo '$HUMAN_OUT' | grep -q 'Upgrade available'"

assert_pass "human output contains 'Upgrade Adviser'" \
    "echo '$HUMAN_OUT' | grep -q 'Shani Upgrade Adviser'"

# Scenario 5: Disk space and dependency checks appear in output
echo ""
echo "--- Readiness Checks in Output ---"

assert_pass "human output contains 'Disk space'" \
    "echo '$HUMAN_OUT' | grep -q 'Disk space'"

assert_pass "human output contains 'Dependencies'" \
    "echo '$HUMAN_OUT' | grep -q 'Dependencies'"

# Scenario 6: JSON output has readiness fields
echo ""
echo "--- JSON Readiness Fields ---"

assert_pass "JSON has upgrade_ready field" \
    "echo '$JSON_OUT' | jq -e 'has(\"upgrade_ready\")'"

assert_pass "JSON has disk_space object" \
    "echo '$JSON_OUT' | jq -e '.disk_space | type == \"object\"'"

assert_pass "JSON has dependencies object" \
    "echo '$JSON_OUT' | jq -e '.dependencies | type == \"object\"'"

#####################################
### Results                       ###
#####################################
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi

echo "All upgrade adviser tests passed!"
