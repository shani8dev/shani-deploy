#!/bin/bash
# gen-efi must never let a Secure Boot KEY ROTATION pass as a local repair.
#
# WHY THIS EXISTS. `ensure_mok_keys()` regenerates the MOK keypair when
# MOK.key and MOK.crt do not match (sbsign cannot use a mismatched pair - the
# check is correct), and it also generates one when the pair is simply absent.
# That is the right repair, but it is not a LOCAL one:
#
#   - every UKI on the ESP was signed with the key it replaces;
#   - generate_uki() `mv`s the newly signed UKI over the live one, so the old
#     UKI is gone the moment the new one is signed;
#   - the firmware must ENROL the new key, which means the user has to accept a
#     MokManager prompt at the next reboot;
#   - miss the prompt and Secure Boot refuses the new UKI.
#
# So a key rotation makes the machine unbootable until someone is physically at
# the console. The code logged it with `log_warn`, in the same register as "MOK
# key already enrolled in firmware" and "Old MOK keys detected" - messages that
# describe nothing being done. Read as a tidied-up detail, which is how a
# terminal-bus key mismatch becomes a machine that will not boot.
#
# Enrollment elsewhere in this file already says ACTION REQUIRED for exactly
# this class (see _stage_mok_enrollment and cleanup_mok). Rotation did not.
#
# The other half of the check: the keys gen-efi ships must all live in the ONE
# place. A signing key copied somewhere else is the class of thing this repo's
# audit already records as a live Critical finding (MOK private keys reachable
# in git history), so a path that is not /etc/secureboot/keys is worth failing
# on rather than noting.
#
#   shani-deploy/tests/test-gen-efi-mok-rotation.sh    (host-only, no root, no disks)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(dirname "$HERE")/.."
GENEFI="$HERE/../scripts/gen-efi.sh"
pass=0 fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; fail=$((fail + 1)); }

[[ -f $GENEFI ]] || { echo "gen-efi.sh not found at $GENEFI" >&2; exit 2; }
code=$(python3 -c '
import re,sys
src=open(sys.argv[1]).read()
# drop comments so a documented ROTATION cannot satisfy the assertion
src="\n".join(l for l in src.split("\n") if not l.strip().startswith("#"))
print(src)' "$GENEFI")

# Lift the two branches that regenerate, so the assertions are on the real code
# rather than on a paraphrase of it.
rotate_mismatch=$(printf '%s' "$code" | sed -n '/key_pub.*!=.*cert_pub/,/fi/p' | head -30)
rotate_missing=$(printf '%s' "$code" | sed -n '/Generating new MOK keypair/,/openssl req/p' | head -30)

echo "== a keypair mismatch is announced as a rotation, not a repair"
if [ -n "$rotate_mismatch" ]; then
  ok "the mismatched-keypair branch was located"
  grep -qi 'ACTION REQUIRED' <<<"$rotate_mismatch" \
    && ok "the mismatch branch says ACTION REQUIRED" \
    || no "the mismatch branch says ACTION REQUIRED" \
         "it only logs a warning: a rotation that bricks the next boot reads as a tidied-up detail"
  grep -qiE 'rotat' <<<"$rotate_mismatch" \
    && ok "the mismatch branch says the key is being ROTATED" \
    || no "the mismatch branch says the key is being ROTATED" "the word never appears"
  grep -qiE 'will (not|no longer)|stops? booting|refuse' <<<"$rotate_mismatch" \
    && ok "it states the consequence: existing UKIs stop booting" \
    || no "it states the consequence" "no line says what breaks"
else
  no "the mismatched-keypair branch was located" "sed found nothing - has the code moved?"
fi

echo
echo "== a missing keypair is announced too"
if [ -n "$rotate_missing" ]; then
  ok "the generate branch was located"
  grep -qi 'ACTION REQUIRED' <<<"$rotate_missing" \
    && ok "the generate branch says ACTION REQUIRED" \
    || no "the generate branch says ACTION REQUIRED" "generating a new signing key is silent"
else
  no "the generate branch was located" "sed found nothing"
fi

echo
echo "== the two branches agree"
# One warning level and one message, or the two paths read as different
# severities for the same outcome.
a=$(grep -ci 'ACTION REQUIRED' <<<"$rotate_mismatch")
b=$(grep -ci 'ACTION REQUIRED' <<<"$rotate_missing")
[[ ${a:-0} -gt 0 && ${b:-0} -gt 0 ]] \
  && ok "both rotation paths are announced" \
  || no "both rotation paths are announced" "mismatch=${a:-0} missing=${b:-0}"

echo
echo "== the PRIVATE key lives in exactly one directory"
# Only MOK.key and MOK.crt. MOK.der is the PUBLIC cert and is deliberately
# copied onto the ESP (EFI/BOOT/MOK.der) for the MokManager fallback - the
# first version of this assertion counted that as a second key directory and
# reported correct behaviour as a defect. Constrain it to the private key.
# A bare `MOK.key` match is the variable ASSIGNMENT (MOK_KEY=.../MOK.key), not
# a path, and dirname of that is "." - which the earlier version read as a
# second key directory. Filtered out by name below.
# Here-strings, not `printf ... | grep`: `grep -q` exits the moment it matches,
# the writer takes SIGPIPE, and under `set -o pipefail` the PIPELINE then
# reports failure - so an assertion on an 80 KB input can fail purely because
# the match was found early enough. That is not hypothetical: this file was
# green, then the rebase grew gen-efi.sh by a few lines and the same assertion
# went red with nothing changed. A pipe whose reader may exit early cannot be
# used as a boolean here.
keydirs=$(grep -oE '[A-Za-z0-9_./{}$-]*MOK\.(key|crt)' <<<"$code" \
          | grep -v 'EFI' \
          | grep -vE '^MOK\.(key|crt)$' \
          | xargs -r -n1 dirname | sort -u)
if [ "$(printf '%s\n' "$keydirs" | grep -c .)" -le 1 ] && [ -n "$keydirs" ]; then
  ok "MOK.key/MOK.crt resolve to one directory: $(printf '%s' "$keydirs" | tr '\n' ' ')"
else
  no "MOK.key/MOK.crt resolve to one directory" "found: $(printf '%s' "$keydirs" | tr '\n' ' ')"
fi
if printf '%s' "$keydirs" | grep -q '^/etc/secureboot/keys'; then
  ok "and it is /etc/secureboot/keys"
else
  no "and it is /etc/secureboot/keys" "found [$(printf '%s' "$keydirs" | tr '\n' ' ')]"
fi
# The public cert on the ESP is load-bearing: MokManager reads it to present a
# pending enrollment when the next reboot happens without a network/user.
grep -qE <<<"$code" 'EFI/BOOT/MOK\.der' \
  && ok "MOK.der is staged on the ESP for the MokManager fallback" \
  || no "MOK.der is staged on the ESP" "the manual-enrollment fallback is gone"

echo
echo "== a signing key must never be written outside it"
# cp/mv/install of a MOK.key anywhere else is a copy of a private key.
stray=$(grep -nE '(cp|mv|install)[^|]*MOK\.key' <<<"$code" | grep -v '/etc/secureboot/keys' || true)
if [ -z "$stray" ]; then
  ok "MOK.key is never copied or moved out of /etc/secureboot/keys"
else
  no "MOK.key is never copied out of /etc/secureboot/keys" "$(printf '%s' "$stray" | head -2)"
fi

echo
echo "${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]