#!/usr/bin/env bash
# test-etc-changes-protected.sh - `shani-etc-changes restore` never queues the
# accounts or this computer's identity.
#
# A restore removes a file's copy from the /etc overlay's upper layer, so the
# image's factory version shows again. For passwd/shadow/group/gshadow that
# would delete every account made on this computer; subuid/subgid break their
# containers; machine-id, crypttab and the Secure Boot key are made once at
# install; the SSH host keys are this computer's identity to every client
# (protected since 2026-11-19 - before, a restore deleted them and every
# client warned that the host had changed). The initramfs hook in
# shani-install-media refuses the same names (tests/test-etc-restore-hook.sh
# there checks the two lists match).
#
# No root: SHANI_ETC_UPPER/LOWER/PENDING point the real script at scratch
# folders.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
X="$here/scripts/shani-etc-changes"
pass=0; fail=0
ok() { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no() { printf '  FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }

S=$(mktemp -d); trap 'rm -rf "$S"' EXIT
mkdir -p "$S/up/secureboot/keys" "$S/up/ssh" "$S/low/ssh"
for f in passwd shadow group gshadow subuid subgid machine-id crypttab hostname; do echo low > "$S/low/$f"; echo up > "$S/up/$f"; done
echo k > "$S/up/secureboot/keys/MOK.key"
echo h > "$S/up/ssh/ssh_host_ed25519_key"; echo h > "$S/up/ssh/ssh_host_ed25519_key.pub"
export SHANI_ETC_UPPER=$S/up SHANI_ETC_LOWER=$S/low SHANI_ETC_PENDING=$S/pending

for p in passwd shadow group gshadow subuid subgid machine-id crypttab /etc/passwd \
         secureboot/keys/MOK.key ssh/ssh_host_ed25519_key ssh/ssh_host_ed25519_key.pub; do
  out=$(python3 "$X" restore "$p" 2>&1)
  [[ $out == *"is not restored here"* ]] && ok "refused $p" || no "refused $p" "$out"
done
for p in ./passwd ../passwd; do
  out=$(python3 "$X" restore "$p" 2>&1)
  [[ $out == *"not a path under /etc"* ]] && ok "refused bad path $p" || no "bad path $p" "$out"
done
[[ ! -e $S/pending ]] && ok "nothing was queued" || no "queue" "$(cat "$S/pending")"

out=$(python3 "$X" restore hostname 2>&1)
[[ $out == *'"ok": true'* ]] && grep -qx hostname "$S/pending" && ok "an ordinary file is queued (hostname)" || no "hostname" "$out"

n=$(python3 "$X" list 2>&1 | grep -c '\[protected\]')
(( n == 11 )) && ok "list marks all 11 protected files" || no "list protected count" "$(python3 "$X" list 2>&1)"

echo; echo "  ${pass} passed, ${fail} failed"
(( fail == 0 ))
