#!/bin/bash
# tests/verify-units.sh — run `systemd-analyze verify` over every unit this
# repo ships, against a REAL Arch systemd (not the CI host's own).
#
# Installs the units into /usr/lib/systemd/{system,user}/ and stubs only what
# ShaniOS itself provides at runtime: its /usr/local/bin scripts (the
# PKGBUILD's scripts/*.sh -> /usr/local/bin/<name> convention) and data.mount
# (generated from /etc/fstab on a real install). Everything else — systemd's
# own units and binaries, flatpak — must be the real packaged thing, so a
# unit pointing at a binary that doesn't exist is caught.
#
# Writes into /usr: only run inside a throwaway container, e.g.
#   docker run --rm -v "$PWD:/src:ro" archlinux:latest \
#     bash -c 'pacman -Sy --noconfirm flatpak >/dev/null && bash /src/tests/verify-units.sh /src'

set -euo pipefail

if [[ ! -f /.dockerenv && -z "${CI:-}" ]]; then
    echo "refusing: this writes into /usr/lib/systemd — run it in a throwaway container" >&2
    exit 2
fi

src="${1:-.}"

install -d /usr/lib/systemd/system /usr/lib/systemd/user /usr/local/bin
cp "$src"/systemd/system/* /usr/lib/systemd/system/
cp "$src"/systemd/user/*   /usr/lib/systemd/user/
for s in "$src"/scripts/*.sh; do
    install -m755 /dev/null "/usr/local/bin/$(basename "$s" .sh)"
done
if [[ ! -e /usr/lib/systemd/system/data.mount ]]; then
    printf '[Mount]\nWhat=tmpfs\nWhere=/data\nType=tmpfs\n' \
        > /usr/lib/systemd/system/data.mount
fi

# verify only exits non-zero for hard errors; an unknown key is reported
# ("..., ignoring.") but still exits 0. A silently-ignored directive is
# exactly what this gate exists to catch, so ANY output counts as failure.
fail=0
for scope in system user; do
    flag=()
    if [[ $scope == user ]]; then
        flag=(--user)
        # verify --user needs a runtime dir even though no user manager runs.
        export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-$(mktemp -d)}"
    fi
    units=()
    for f in "$src"/systemd/"$scope"/*; do
        units+=("/usr/lib/systemd/$scope/$(basename "$f")")
    done
    out=$(systemd-analyze verify "${flag[@]}" --man=no "${units[@]}" 2>&1) || fail=1
    if [[ -n "$out" ]]; then
        printf '%s\n' "$out"
        fail=1
    fi
    echo "verified ${#units[@]} $scope unit(s)"
done
exit "$fail"
