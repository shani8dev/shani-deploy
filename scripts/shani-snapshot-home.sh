#!/bin/bash
# shani-snapshot-home — a snapshot of /home taken immediately before an update
#
# shani-deploy calls this from deploy_update(), before it mounts the disk or
# writes to the standby slot. The update itself only replaces @blue/@green;
# a release, a service that migrates its state in place, or a rollback can
# still cost somebody the day's work under /home, and this is the same-minute
# undo for that.
#
# It is done by the system, as root, on purpose:
#   * a btrfs snapshot needs root;
#   * an update started by a timer has no logged-in session, and an update
#     started by one person must still cover everybody else's home;
#   * it must not depend on anyone remembering to take it before pressing
#     "Update".
# The user's control is opt-out, not opt-in: deploy_home_snapshot=no in
# /etc/shani/shani.conf, or `shani-deploy --no-home-snapshot` for one run.
#
# Exit status, consumed by take_predeploy_home_snapshot() in shani-deploy.sh:
#   0   a snapshot was taken
#   10  deliberately skipped, with the reason on stdout
#   11  tried and failed, with the reason on stdout
# All three leave the update free to continue: a snapshot is insurance, not
# a precondition.
#
# The snapshots themselves live under /home/.snapshots and are pruned to the
# newest --keep (2 by default) of this kind only; daily and manual snapshots
# are shani-backup's business and are not touched here.

set -uo pipefail

KEEP="${SHANI_SNAPSHOT_KEEP:-2}"
MIN_FREE_PCT="${SHANI_SNAPSHOT_MIN_FREE_PCT:-5}"

usage() {
    cat <<EOF
Usage: $0 [--keep N]

  --keep N   Pre-deploy snapshots kept per home (default 2; 0 keeps all)

Environment: SHANI_SNAPSHOT_KEEP, SHANI_SNAPSHOT_MIN_FREE_PCT (default 5).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --keep)
            [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || {
                echo "--keep needs a non-negative number"
                exit 11
            }
            KEEP="$2"; shift 2 ;;
        *)
            echo "unknown option: $1"
            exit 11 ;;
    esac
done

# The caller runs as root, but say so plainly rather than let shani-backup
# explain it: the exit code is what the deploy reads.
if [[ "$(id -u)" -ne 0 ]]; then
    echo "a snapshot needs root"
    exit 10
fi

if ! command -v shani-backup >/dev/null 2>&1; then
    echo "shani-backup is not installed"
    exit 10
fi

if [[ ! -d /home ]]; then
    echo "/home is not a directory on this system"
    exit 10
fi

# A snapshot is cheap at creation but holds on to what is deleted afterwards,
# so on a nearly full disk taking one makes the next write fail sooner. The
# same reasoning as shani-backup's own retention: below a few percent free,
# say so and leave the disk alone.
free_pct=$(df -P --output=pcent /home 2>/dev/null | tail -1 | tr -cd '0-9')
if [[ -n "$free_pct" ]] && (( free_pct < MIN_FREE_PCT )); then
    echo "/home has ${free_pct}% free (a snapshot is skipped below ${MIN_FREE_PCT}%)"
    exit 10
fi

out=$(shani-backup home predeploy --keep "$KEEP" 2>&1)
rc=$?

printf '%s\n' "$out"

if (( rc != 0 )); then
    [[ -n "${out//[[:space:]]/}" ]] || echo "shani-backup home predeploy exited ${rc} without saying why"
    exit 11
fi

# Success with nothing to say means there were no home folders to snapshot;
# that is a skip, not a snapshot.
if [[ -z "${out//[[:space:]]/}" ]]; then
    echo "no home folders to snapshot"
    exit 10
fi

exit 0
