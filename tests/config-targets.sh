#!/usr/bin/env bash
# The three "no drop-in, no validator of its own" targets added to
# shani-cassini-save.sh: subject_mapping, pam_yubico and krb5_conf.
#
# WHY THIS FILE EXISTS. Those three pages were the last callers of
# config_io's `write_staged_privileged`, which runs `pkexec install` over a
# temp file the CALLER owns in a directory the CALLER owns — a
# wait-for-root-to-read-my-file window, with no polkit rule. Content on stdin
# closes it by removing the name.
#
# The cost is that these files have no external validator, so the helper checks
# them itself. **A self-written validator is exactly the kind of check that can
# pass while proving nothing**, so most of this file is about making it fail:
# wrong field counts, unclosed sections, settings outside a section, a
# flattened file, a file that would configure nothing.
#
# Run it:
#   tests/config-targets.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SAVE_SRC="$REPO_ROOT/scripts/shani-cassini-save.sh"
[[ -f "$SAVE_SRC" ]] || { echo "no helper at $SAVE_SRC" >&2; exit 1; }

exec docker run --rm --privileged \
    -v /dev:/dev -v /lib/modules:/lib/modules:ro \
    -v "$SAVE_SRC:/shani-cassini-save:ro" \
    -v "$SCRIPT_DIR/config-targets-inner.sh:/suite.sh:ro" \
    archlinux:base bash -c '
set -uo pipefail
pacman -Sy --noconfirm >/dev/null 2>&1
pacman -S --noconfirm --needed kmod sudo openssh >/dev/null 2>&1
bash /suite.sh
'