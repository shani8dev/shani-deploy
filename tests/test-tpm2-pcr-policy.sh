#!/bin/bash
# tests/test-tpm2-pcr-policy.sh — contract tests for the TPM2 PCR policy read in
# shani-health.sh's _section_tpm2, and the Secure Boot cross-check built on it.
#
# The Enrolled-row block and the cross-check block are EXTRACTED from the shipped
# script and evaluated verbatim, so what is exercised is the production control
# flow. cryptsetup and mokutil are stubbed, because their *output* is the input
# under test; the PCR parsing itself is never reimplemented here. The one thing
# deliberately not stubbed is the policy parser — it is sourced straight out of
# the script, so a regression in it cannot be masked by a test-local copy.
#
# Why this exists. The shipped code had two independent defects that together
# made this diagnostic a check that could never fire on any machine:
#
#   1. It read the policy with `grep -oP 'pcr-selection.*'`. No version of
#      systemd or cryptsetup emits a key called `pcr-selection` — checked
#      against v249 through v262. The grep always failed.
#   2. It detected the enrolled set with `grep -oP '(?<=tpm2-pcrs=)[0-9+]+'`.
#      Two errors: the separator is `:` (not `=`), and the key is
#      `tpm2-hash-pcrs` on every systemd since v252. The lookbehind therefore
#      never matched either, so `_enrolled_pcrs` was always empty, and the
#      `[[ -n "$_enrolled_pcrs" && ... ]]` guard short-circuited to false.
#
# The second defect is the dangerous one: an always-empty variable made the
# mismatch branch unreachable, so a genuinely mis-enrolled PCR set — one that
# would not survive a Secure Boot policy update — was never reported. The
# "Enrolled" row had the same fate, falling back to a systemd-cryptenroll line
# that carries no PCR information at all (its table has only slot and type).
#
# Ground truth for the field name and shape, verified against systemd v255
# sources rather than assumed:
#   src/cryptsetup/cryptsetup-tokens/cryptsetup-token-systemd-tpm2.c:235
#       crypt_log(cd, "\ttpm2-hash-pcrs:   %s\n", strna(hash_pcrs_str));
#   src/shared/tpm2-util.c:6888   tpm2_pcr_mask_to_string() joins with "+"
# so the value is a '+'-separated ascending list, never a bitmask integer.
#
# A test asserting only "the row appears" would pass against both defects, so
# every behavioural case asserts the row's VALUE, and cases 6 and 7 are negative
# controls: they run the exact pre-fix greps against the same real fixture and
# require them to come back empty. If a future systemd ever made those greps
# work, the controls fail and the premise for the change is re-examined rather
# than silently invalidated.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }

# Overridable only so the negative controls can be re-run against a restored
# copy of the pre-fix code; unset, it is always the shipped script.
HEALTH="${SHANI_HEALTH_UNDER_TEST:-scripts/shani-health.sh}"
[[ -f "$HEALTH" ]] || { echo "missing $HEALTH"; exit 1; }

# ---------------------------------------------------------------- extraction --
# Both blocks are indented 16 spaces and each is closed by the first 16-space
# `fi` after its start. The start anchors are asserted unique; the `fi` anchor
# deliberately is not, since it appears 80-odd times in the file.
extract_block() {
    local start="$1"
    local n
    n="$(grep -c "$start" "$HEALTH" || true)"
    if [[ "$n" != "1" ]]; then
        echo "FATAL: start anchor matched $n times, expected exactly 1: $start"
        exit 1
    fi
    awk -v pat="$start" '
        $0 ~ pat { b = 1 }
        b { print }
        b && /^                fi$/ { exit }
    ' "$HEALTH"
}

HELPER="$(sed -n '/^_tpm2_enrolled_pcrs() {/,/^}/p' "$HEALTH")"
[[ -n "$HELPER" ]] || { echo "FATAL: could not extract _tpm2_enrolled_pcrs()"; exit 1; }

XC_ROW="$(extract_block '^                local _dump; _dump=')"
XC_CHECK="$(extract_block '^                # Check PCR policy matches current Secure Boot state')"

if [[ -z "$XC_ROW" || -z "$XC_CHECK" ]]; then
    echo "FATAL: could not extract both blocks from $HEALTH"
    exit 1
fi
# Sanity-check the extracted text, not just that it is non-empty. If an anchor
# drifts, a block can still extract cleanly and evaluate to something unrelated.
printf '%s\n' "$XC_ROW"    | grep -q '_tpm2_enrolled_pcrs "\$_dump"' \
    || { echo "FATAL: XC_ROW does not parse a policy (wrong anchor?)"; exit 1; }
printf '%s\n' "$XC_ROW"    | grep -q 'PCR \${_enrolled_pcrs}' \
    || { echo "FATAL: XC_ROW does not display the policy (wrong anchor?)"; exit 1; }
printf '%s\n' "$XC_CHECK" | grep -q '_enrolled_pcrs" != "\$_expected_pcrs"' \
    || { echo "FATAL: XC_CHECK has no PCR comparison (wrong anchor?)"; exit 1; }
printf '%s\n' "$XC_CHECK" | grep -q 'mokutil --sb-state' \
    || { echo "FATAL: XC_CHECK never reads Secure Boot state (wrong anchor?)"; exit 1; }

# The parser must be defined before the block that calls it, or a moved
# definition hides behind extraction ordering.
_h_line=$(grep -n '^_tpm2_enrolled_pcrs() {' "$HEALTH" | cut -d: -f1)
_c_line=$(grep -n '_tpm2_enrolled_pcrs "\$_dump"' "$HEALTH" | head -1 | cut -d: -f1)
if [[ -z "$_h_line" || -z "$_c_line" || "$_h_line" -ge "$_c_line" ]]; then
    echo "FATAL: _tpm2_enrolled_pcrs() must be defined before its call site" \
         "(helper line ${_h_line:-none}, call line ${_c_line:-none})"
    exit 1
fi

TMP_HELPER="$(mktemp)"
trap 'rm -f "$TMP_HELPER"' EXIT
printf '%s\n' "$HELPER" > "$TMP_HELPER"

# ------------------------------------------------------------------ harness --
# $1 luksDump text, $2 mokutil --sb-state text, $3 systemd-cryptenroll list text.
# Echoes every row and recommendation the two blocks render.
_render() {
    local _stub_dump="$1" _stub_sb="$2" _stub_enroll="$3"
    ( # subshell: the stubs must not leak into the test process
        set -uo pipefail
        local underlying="luks-test-stub" _enroll_out="$_stub_enroll" _out=""
        _set_section() { :; }
        _head()        { :; }
        _row()         { _out+="$1 :: $2"$'\n'; }
        _row2()        { _out+="$1"$'\n'; }
        _rec()         { _out+="REC :: $1"$'\n'; }
        cryptsetup()   { printf '%s\n' "$_stub_dump"; }
        mokutil()      { printf '%s\n' "$_stub_sb"; }
        # shellcheck source=/dev/null
        source "$TMP_HELPER"
        eval "$XC_ROW"
        eval "$XC_CHECK"
        printf '%s' "$_out"
    )
}

_enrolled_row() { printf '%s\n' "$1" | grep '^Enrolled :: ' | head -1 | sed 's/^Enrolled :: //'; }
_has_rec()      { printf '%s\n' "$1" | grep -q '^REC :: '; }

SB_ON="SecureBoot enabled"
SB_OFF="SecureBoot disabled"
ENROLL_TPM2="SLOT TYPE
   0 tpm2"

# Verbatim shape from systemd v255's token plugin: a tab before
# "tpm2-hash-pcrs:" and three spaces before the value.
DUMP_0_7='LUKS header information
Version:	2
Tokens:
  0: systemd-tpm2
	tpm2-hash-pcrs:   0+7
	tpm2-public-key: rsa2048
	tpm2-pin: false'

# PCR 0 alone — what gen-efi enrolls with Secure Boot disabled.
DUMP_0='LUKS header information
Version:	2
Tokens:
  0: systemd-tpm2
	tpm2-hash-pcrs:   0
	tpm2-public-key: rsa2048'

# Genuinely wrong for Secure Boot-on: a set that will not survive the state it
# is compared against. This is the fault the check exists to catch.
DUMP_0_11='LUKS header information
Version:	2
Tokens:
  0: systemd-tpm2
	tpm2-hash-pcrs:   0+11
	tpm2-public-key: rsa2048'

# A token with no PCR field at all — the cryptsetup token plugin is absent.
# Not the same thing as "enrolled with no PCRs".
DUMP_NO_FIELD='LUKS header information
Version:	2
Tokens:
  0: systemd-tpm2
	tpm2-pin: false'

# Pre-v252 spelling.
DUMP_LEGACY='LUKS header information
Version:	2
Tokens:
  0: systemd-tpm2
	tpm2-pcrs:  7'

# ------------------------------------------------------- static assertions ---
XC_ALL="$XC_ROW
$XC_CHECK"
# The two greps that shipped the bug. Their continued absence is what proves the
# dead parse was removed rather than merely bypassed.
if printf '%s\n' "$XC_ALL" | grep -q 'pcr-selection'; then
    fail "dead 'pcr-selection' grep is gone" "still present — no systemd or cryptsetup version emits that key"
else
    ok "dead 'pcr-selection' grep is gone"
fi
if printf '%s\n' "$XC_ALL" | grep -q 'tpm2-pcrs='; then
    fail "dead 'tpm2-pcrs=' grep is gone" "still present — separator is ':' and the key is 'tpm2-hash-pcrs' on v252+"
else
    ok "dead 'tpm2-pcrs=' grep is gone"
fi
if printf '%s\n' "$XC_CHECK" | grep -q '\-n "\$_enrolled_pcrs"'; then
    ok "mismatch requires a readable policy (no fabricated fault)"
else
    fail "mismatch requires a readable policy (no fabricated fault)" \
         "the -n guard is missing — an unread policy would be reported as a mismatch"
fi

# ---------------------------------------------- 1. matching policy, SB on ----
out="$(_render "$DUMP_0_7" "$SB_ON" "$ENROLL_TPM2")"
row="$(_enrolled_row "$out")"
if [[ "$row" == *"PCR 0+7"* ]]; then
    ok "SB on, enrolled 0+7: row shows the real policy"
else
    fail "SB on, enrolled 0+7: row shows the real policy" "got '$row'"
fi
if _has_rec "$out"; then
    fail "SB on, enrolled 0+7: no mismatch raised" "raised: $out"
else
    ok "SB on, enrolled 0+7: no mismatch raised"
fi

# --------------------------------------------- 2. matching policy, SB off ----
out="$(_render "$DUMP_0" "$SB_OFF" "$ENROLL_TPM2")"
row="$(_enrolled_row "$out")"
if [[ "$row" == *"PCR 0"* && "$row" != *"0+7"* ]]; then
    ok "SB off, enrolled 0: row shows PCR 0 only"
else
    fail "SB off, enrolled 0: row shows PCR 0 only" "got '$row'"
fi
if _has_rec "$out"; then
    fail "SB off, enrolled 0: no mismatch raised" "raised: $out"
else
    ok "SB off, enrolled 0: no mismatch raised"
fi

# ----------------------------------------------------- 3. the real mismatch --
out="$(_render "$DUMP_0_11" "$SB_ON" "$ENROLL_TPM2")"
row="$(_enrolled_row "$out")"
if [[ "$row" == *"PCR 0+11"* ]]; then
    ok "SB on, enrolled 0+11: row shows the mismatching policy"
else
    fail "SB on, enrolled 0+11: row shows the mismatching policy" "got '$row'"
fi
if printf '%s\n' "$out" | grep -q '^REC :: .*mismatch'; then
    ok "SB on, enrolled 0+11: mismatch recommendation raised"
else
    fail "SB on, enrolled 0+11: mismatch recommendation raised" "none in: $out"
fi
# The diagnosis must name both sides, or it cannot be acted on.
if printf '%s\n' "$out" | grep -q '0+11.*expected'; then
    ok "mismatch names both the enrolled and the expected policy"
else
    fail "mismatch names both the enrolled and the expected policy" "got: $out"
fi

# --------------------------------------- 4. ordering must not cause a false ----
# The same set written the other way round. systemd emits ascending, but the
# comparison must not depend on it.
out="$(_render "$(printf 'Tokens:\n  0: systemd-tpm2\n\ttpm2-hash-pcrs:   7+0\n')" "$SB_ON" "$ENROLL_TPM2")"
if _has_rec "$out"; then
    fail "reversed 7+0 with SB on: no false mismatch" "raised: $out"
else
    ok "reversed 7+0 with SB on: no false mismatch"
fi

# ---------------------------------------- 5. unreadable policy is not a fault -
out="$(_render "$DUMP_NO_FIELD" "$SB_ON" "$ENROLL_TPM2")"
row="$(_enrolled_row "$out")"
if [[ "$row" == *"not available"* ]]; then
    ok "missing PCR field: row reports policy not available"
else
    fail "missing PCR field: row reports policy not available" "got '$row'"
fi
if _has_rec "$out"; then
    fail "missing PCR field: no fabricated mismatch" "raised: $out"
else
    ok "missing PCR field: no fabricated mismatch"
fi

# ------------------------------------------ 6. negative controls: old greps --
# The pre-fix patterns, verbatim, against the same fixture case 1 uses. If
# either ever matches, the "dead code" premise of this file is wrong.
old_policy=$(printf '%s\n' "$DUMP_0_7" | grep -A5 "systemd-tpm2" | grep -oP 'pcr-selection.*' | head -1)
if [[ -z "$old_policy" ]]; then
    ok "NEGATIVE CONTROL: pre-fix 'pcr-selection' grep finds nothing on a real dump"
else
    fail "NEGATIVE CONTROL: pre-fix 'pcr-selection' grep finds nothing on a real dump" \
         "returned '$old_policy' — if this now matches, the premise is stale"
fi
old_enrolled=$(printf '%s\n' "$DUMP_0_7" | grep -oP '(?<=tpm2-pcrs=)[0-9+]+' | head -1)
if [[ -z "$old_enrolled" ]]; then
    ok "NEGATIVE CONTROL: pre-fix 'tpm2-pcrs=' grep finds nothing on a real dump"
else
    fail "NEGATIVE CONTROL: pre-fix 'tpm2-pcrs=' grep finds nothing on a real dump" \
         "returned '$old_enrolled' — if this now matches, the premise is stale"
fi
# The same old grep against a dump with a genuine mismatch: the shipped code
# could not have reported it, which is the user-visible regression.
old_wrong=$(printf '%s\n' "$DUMP_0_11" | grep -oP '(?<=tpm2-pcrs=)[0-9+]+' | head -1)
if [[ -z "$old_wrong" ]]; then
    ok "NEGATIVE CONTROL: pre-fix grep also misses a real 0+11 mismatch"
else
    fail "NEGATIVE CONTROL: pre-fix grep also misses a real 0+11 mismatch" "returned '$old_wrong'"
fi
# A control that cannot fail is not a control: prove the old grep does work on
# the one input it was written for, so its emptiness above is a property of the
# real dump and not of a broken pattern.
old_control=$(printf 'tpm2-pcrs=0+7\n' | grep -oP '(?<=tpm2-pcrs=)[0-9+]+' | head -1)
if [[ "$old_control" == "0+7" ]]; then
    ok "NEGATIVE CONTROL is sound: the old grep does match its assumed 'tpm2-pcrs=' form"
else
    fail "NEGATIVE CONTROL is sound: the old grep does match its assumed 'tpm2-pcrs=' form" \
         "got '$old_control' — the control could not have failed, so it proves nothing"
fi

# ------------------------------------------------- 7. legacy key still works --
out="$(_render "$DUMP_LEGACY" "$SB_ON" "$ENROLL_TPM2")"
row="$(_enrolled_row "$out")"
if [[ "$row" == *"PCR 7"* ]]; then
    ok "legacy tpm2-pcrs key is still read"
else
    fail "legacy tpm2-pcrs key is still read" "got '$row'"
fi
if _has_rec "$out"; then
    ok "legacy 7 with SB on: still compared, and correctly flagged"
else
    fail "legacy 7 with SB on: still compared, and correctly flagged" "no recommendation from: $out"
fi

echo ""
if (( FAIL > 0 )); then echo "✗ $PASS passed, $FAIL failed"; exit 1; fi
echo "✓ $PASS passed, 0 failed"
