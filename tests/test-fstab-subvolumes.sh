#!/usr/bin/env bash
# test-fstab-subvolumes.sh - parse_fstab_subvolumes reads every subvolume the
# image's fstab names, hyphenated ones included. Before 2026-11-19 it read
# @shani-chronoa as "shani": verify_and_create_subvolumes then never created
# @shani-chronoa on an older install and made a stray @shani instead.
# Needs gawk (match() with an array), as the image has.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
command -v gawk >/dev/null || { echo "SKIP: gawk not installed"; exit 0; }
fn=$(mktemp); sed -n '/^parse_fstab_subvolumes() {/,/^}/p' "$here/scripts/shani-deploy.sh" > "$fn"
fstab=$(mktemp); cat > "$fstab" <<'F'
LABEL=shani_root /                     btrfs subvol=@blue,ro 0 0
LABEL=shani_root /var/lib/shani-chronoa btrfs nofail,subvol=@shani-chronoa,rw 0 0
LABEL=shani_root /var/lib/qemu         btrfs nofail,subvol=@qemu,rw 0 0
#LABEL=shani_root /var/old             btrfs subvol=@commented 0 0
/data/varlib/dbus /var/lib/dbus none bind 0 0
F
got=$(awk() { gawk "$@"; }; source "$fn"; parse_fstab_subvolumes "$fstab" | paste -sd' ')
want="qemu shani-chronoa"
[[ "$got" == "$want" ]] && { echo "  ok    $got"; exit 0; } || { echo "  FAIL  got [$got], want [$want]"; exit 1; }
