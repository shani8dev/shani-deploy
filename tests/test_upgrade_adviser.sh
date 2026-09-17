#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADVISER="/home/shrinivaskumbhar/Documents/shani/shani-deploy/bin/shani-upgrade-adviser"

echo "Test 1: --check-only flag..."
if "$ADVISER" --check-only > /dev/null 2>&1; then
    echo "  PASS"
else
    echo "  FAIL"
    exit 1
fi

echo "Test 2: --json flag..."
if "$ADVISER" --json > /dev/null 2>&1; then
    echo "  PASS"
else
    echo "  FAIL"
    exit 1
fi

echo "Test 3: Default mode..."
if "$ADVISER" > /dev/null 2>&1; then
    echo "  PASS"
else
    echo "  FAIL"
    exit 1
fi

echo "All upgrade adviser tests passed!"
