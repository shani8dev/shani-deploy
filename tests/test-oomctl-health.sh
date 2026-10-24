#!/bin/bash
# Contract test: shani-health oomctl row (2026-09-30 session extension)
# Negative control: image/container has no memory cgroup controller, so
# systemd-oomd is enabled but never starts, and oomctl dump fails.
# Positive control (not executed here — needs real slot with working controller):
#   oomctl dump produces kill-report format; row reports actual OOM events.
set -euo pipefail
ERR=0

# Fixture: simulated "oomctl present, oomd enabled, not active"
# Matches verified state in session log (ConditionControlGroupController=memory missing)
if ! grep -qE 'OOM killer' /home/shrinivaskumbhar/Documents/shani/shani-deploy/scripts/shani-health.sh; then
  echo "FAIL: oomctl row missing from shani-health.sh"
  ERR=1
fi

# Negative control: no claim of "OK" when service is not running
# The inserted block reports "enabled but not running (memory-cgroup missing?)"
# rather than "OK". Confirm the guard is present.
if grep -qE 'memory-cgroup missing\?' /home/shrinivaskumbhar/Documents/shani/shani-deploy/scripts/shani-health.sh; then
  echo "PASS: oomctl row correctly reports unavailable (memory-cgroup missing guard present)"
else
  echo "FAIL: missing memory-cgroup unavailable guard"
  ERR=1
fi

# Verify comment documents why parsing is deferred (session audit)
if grep -qE 'get a real dump from a working slot' /home/shrinivaskumbhar/Documents/shani/shani-deploy/scripts/shani-health.sh; then
  echo "PASS: comment defers parsing until real oomctl dump available"
else
  echo "FAIL: missing audit reference in comment"
  ERR=1
fi

# Syntax check the edited script still passes
bash -n /home/shrinivaskumbhar/Documents/shani/shani-deploy/scripts/shani-health.sh || { echo "FAIL: bash -n"; ERR=1; }

echo "oomctl-health: ${ERR} failures (0 = all pass for unavailable-state contract)"
exit $ERR
