#!/usr/bin/env bash
# A check of the harness itself: the `modules_load` target added to
# shani-deploy/scripts/shani-cassini-save.sh, run as root in a container.
#
# WHY THIS FILE EXISTS. `shani-cassini/tabs/kvm.py` has called
# `pkexec shani-cassini-save --target modules_load` since it was written, and
# that target was **not in the helper's allowlist** - `target_path()` knew only
# sudoers, sshd_config and exports. Every load the KVM page attempted was
# therefore refused with "unknown target", and the page's own docstring described
# the call as if it worked. Nothing failed loudly enough to notice: the page
# reported the helper's own refusal, which read as a plausible message.
#
# The target exists now, with `modprobe --show-depends` as the validator -
# systemd-modules-load has no check mode, and modprobe is the only thing that
# knows whether a module resolves for the running kernel.
#
# WHAT IS REAL: kmod, the allowlist, the pre-commit validator, the live
# post-commit check, the rollback, the atomic install and the read-back are all
# the real script. A refused save is asserted to leave NO file behind, because
# "the validator rejected it" is only meaningful if nothing was installed.
#
# Run it:
#   tests/modules-load-target.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SAVE_SRC="$REPO_ROOT/../shani-deploy/scripts/shani-cassini-save.sh"

[[ -f "$SAVE_SRC" ]] || { echo "no helper at $SAVE_SRC" >&2; exit 1; }

exec docker run --rm --privileged \
    -v /dev:/dev -v /lib/modules:/lib/modules:ro \
    -v "$SAVE_SRC:/shani-cassini-save:ro" \
    -v "$SCRIPT_DIR/modules-load-target-inner.sh:/suite.sh:ro" \
    archlinux:base bash -c '
set -uo pipefail
pacman -Sy --noconfirm >/dev/null 2>&1
pacman -S --noconfirm --needed kmod sudo openssh >/dev/null 2>&1
bash /suite.sh
'