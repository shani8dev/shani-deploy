#!/usr/bin/env bash
# test-boot-counting-gate.sh - the REAL finalize_boot_entries, on a scratch ESP.
#
# Boot counting ("uki" entry key) is turned on for a counted +3-0 entry only
# when the slot's image can bless a good boot (generate_uki sets
# BLESS_READY_SLOT); LoaderEntryDefault then names the fallback slot, so an
# exhausted entry falls back. Otherwise the entry is "efi" (not counted) and
# Default names the new slot - the behaviour before 2026-11-19. A counted entry
# whose image cannot bless would fall back after three GOOD boots: measured, a
# counted boot of a 2026-09 image failed systemd-bless-boot.service.
#
# No root, no disk: finalize_boot_entries, _uki_entry_key and _esp_sdboot_major
# are lifted out of scripts/shani-deploy.sh; bootctl, mountpoint and the log
# functions are stubs; the ESP is a directory.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$here/scripts/shani-deploy.sh"
pass=0; fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }

fns=$(mktemp)
for f in _esp_sdboot_major _uki_entry_key finalize_boot_entries; do
  sed -n "/^${f}() {/,/^}/p" "$SRC" >> "$fns"
  grep -q "^${f}() {" "$fns" || { echo "FAIL could not lift ${f} from ${SRC}"; exit 1; }
done

# run CASE SDBOOT_MAJOR ACTIVE CANDIDATE USE_TRIES BLESS_READY_SLOT
run() {
  local tmp; tmp=$(mktemp -d)
  mkdir -p "$tmp/esp/EFI/BOOT" "$tmp/esp/loader/entries" "$tmp/efivars"
  printf 'MZ #### LoaderInfo: systemd-boot %s-1 ####' "$2" > "$tmp/esp/EFI/BOOT/grubx64.efi"
  (
    set -Eeuo pipefail
    ESP="$tmp/esp" OS_NAME=shanios SHANIOS_EFIVARS_DIR="$tmp/efivars"
    BLESS_READY_SLOT="$6"
    log() { :; }; log_warn() { :; }; log_error() { echo "ERR $*" >&2; }; log_verbose() { :; }; log_success() { :; }
    mountpoint() { return 0; }
    bootctl() { echo "$*" >> "$tmp/bootctl"; return 0; }
    chattr() { :; }
    # shellcheck disable=SC1090
    source "$fns"
    if [[ "$5" == yes ]]; then finalize_boot_entries "$3" "$4"; else finalize_boot_entries "$3" "$4" no-tries; fi
  ) || echo "finalize rc=$?" >> "$tmp/bootctl"
  echo "$tmp"
}
key_of() { sed -n 's/^\(efi\|uki\)[[:space:]].*/\1/p' "$1" | head -1; }

echo "== a counted entry whose image can bless: counted, Default on the fallback"
t=$(run a 262 green blue yes green)
f="$t/esp/loader/entries/shanios-green+3-0.conf"
[[ -f $f && $(key_of "$f") == uki ]] && ok "shanios-green+3-0.conf uses uki" || no "counted uki entry" "$(ls "$t/esp/loader/entries"; cat "$f" 2>/dev/null)"
grep -qx 'set-preferred shanios-green.conf' "$t/bootctl" && ok "Preferred = the new slot" || no "set-preferred" "$(cat "$t/bootctl")"
grep -qx 'set-default shanios-blue.conf' "$t/bootctl" && ok "Default = the fallback slot" || no "set-default fallback" "$(cat "$t/bootctl")"

echo "== a counted entry whose image CANNOT bless: not counted (efi), Default on the new slot"
t=$(run b 262 green blue yes "")
f="$t/esp/loader/entries/shanios-green+3-0.conf"
[[ $(key_of "$f") == efi ]] && ok "shanios-green+3-0.conf uses efi" || no "uncounted efi entry" "$(cat "$f" 2>/dev/null)"
[[ $(key_of "$t/esp/loader/entries/shanios-blue.conf") == uki ]] && ok "the plain fallback entry may still use uki" || no "fallback key" "$(cat "$t/esp/loader/entries/shanios-blue.conf")"
grep -qx 'set-default shanios-green.conf' "$t/bootctl" && ok "Default = the new slot (nothing counts down)" || no "set-default new slot" "$(cat "$t/bootctl")"

echo "== a rollback (no tries): plain entries, Default on the target"
t=$(run c 262 blue green no "")
[[ -f "$t/esp/loader/entries/shanios-blue.conf" && ! -e "$t/esp/loader/entries/shanios-blue+3-0.conf" ]] && ok "no counter on a rollback" || no "rollback entries" "$(ls "$t/esp/loader/entries")"
grep -qx 'set-default shanios-blue.conf' "$t/bootctl" && ok "Default = the slot rolled back to" || no "rollback default" "$(cat "$t/bootctl")"

echo "== systemd-boot 257 on the ESP: efi everywhere, whatever the image"
t=$(run d 257 green blue yes green)
[[ $(key_of "$t/esp/loader/entries/shanios-green+3-0.conf") == efi && $(key_of "$t/esp/loader/entries/shanios-blue.conf") == efi ]] \
  && ok "both entries efi" || no "old sd-boot" "$(cat "$t"/esp/loader/entries/*)"
grep -qx 'set-default shanios-green.conf' "$t/bootctl" && ok "Default = the new slot (Preferred unknown to 257)" || no "257 default" "$(cat "$t/bootctl")"

echo
echo "  ${pass} passed, ${fail} failed"
(( fail == 0 ))
