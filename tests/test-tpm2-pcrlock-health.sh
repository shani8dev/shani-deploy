#!/bin/bash
# tests/test-tpm2-pcrlock-health.sh — contract tests for the pcrlock branch of
# shani-health.sh's _section_tpm2.
#
# The branch is EXTRACTED from the shipped script and evaluated verbatim, so the
# production control flow is what runs. cryptsetup, mokutil and the policy-path
# lookup are stubbed because their output is the input under test; the pcrlock
# detection and policy-hash parsing are sourced straight out of the script and
# never reimplemented, so a regression in them cannot be masked here.
#
# Why this exists. shani-health reported one fixed sentence for every enrolled
# TPM2 volume — "OK auto-unlock active (PCR policy not available)" — which was
# wrong in both directions for a pcrlock volume:
#
#   1. It claimed the policy was unavailable when a pcrlock policy was in fact
#      present at a known path, so the one diagnostic meant to reassure an
#      operator that auto-unlock is protected reported the opposite.
#   2. Worse, the Secure Boot cross-check ran on pcrlock tokens. systemd v255
#      renders tpm2-hash-pcrs unconditionally (tok255.c:235) from the token
#      JSON rather than from the sealed policy, so a correctly pcrlock-enrolled
#      volume whose header list was not exactly "0+7" was reported as
#      "PCR policy mismatch" and told to re-enroll — i.e. told to replace a
#      working pcrlock enrollment with a weaker literal PCR pin. The
#      recommendation actively downgraded the machine's security.
#
# Case 4 is the negative control for (2): it feeds a pcrlock token whose header
# PCR list deliberately DISAGREES with Secure Boot, and requires that no
# mismatch row and no re-enroll recommendation is emitted. A test that only
# asserted the pcrlock row appears would pass with the cross-check still live.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }

# assert_eq <label> <actual> <expected>
assert_eq() {
    if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "got: $2 (want: $3)"; fi
}
# assert_contains <label> <haystack> <needle>
assert_contains() {
    if [[ "$2" == *"$3"* ]]; then ok "$1"; else fail "$1" "missing: $3"; fi
}
# assert_not_contains <label> <haystack> <needle>
assert_not_contains() {
    if [[ "$2" == *"$3"* ]]; then fail "$1" "unexpectedly present: $3"; else ok "$1"; fi
}

HEALTH="${SHANI_HEALTH_UNDER_TEST:-scripts/shani-health.sh}"
[[ -f "$HEALTH" ]] || { echo "missing $HEALTH"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- extraction --
# The three pcrlock helpers, and the Enrolled-row block. The helpers are
# single functions with a unique `^name() {` anchor and a closing `^}$`, so a
# line range is exact. The Enrolled block is indented 12 spaces and closed by
# the first 12-space `fi`, so that anchor is used and its presence asserted.
for fn in _tpm2_enrolled_pcrs _tpm2_uses_pcrlock _tpm2_pcrlock_policy _tpm2_policy_hash; do
    n=$(grep -c "^${fn}() {$" "$HEALTH")
    assert_eq "helper ${fn} has exactly one definition" "$n" "1"
    awk "/^${fn}\\(\\) \\{\$/,/^}\$/" "$HEALTH" > "$WORK/$fn.sh"
    grep -q "() {" "$WORK/$fn.sh" || { echo "extraction failed: $fn"; exit 1; }
done

# The policy path is repointed at the work dir; the real paths are pinned by a
# static assertion so the repointing cannot hide a search-order regression.
sed -i "s#/run/systemd/pcrlock.json#$WORK/run/pcrlock.json#;
        s#/var/lib/systemd/pcrlock.json#$WORK/var/pcrlock.json#" \
    "$WORK/_tpm2_pcrlock_policy.sh"
if grep -qE 'for _c in /run/systemd/pcrlock.json /var/lib/systemd/pcrlock.json' "$HEALTH"; then
    ok "policy search order pinned: /run before /var/lib"
else
    fail "policy search order pinned" "not found in $HEALTH"
fi

# The Enrolled row plus the cross-check: from the luksDump read to the `fi`
# that closes the cross-check's own `if`. The END anchor is therefore the
# cross-check's if-line, NOT "the next 12-space fi" — the section continues with
# the not-enrolled/disk-not-encrypted `else` branches at the same indent, and
# taking a later `fi` splices their `else` in and leaves a dangling `else`.
# Both anchors are asserted so a structural change to the section is caught here
# rather than producing a silently-short or unparseable block.
start=$(grep -n 'local _dump; _dump=$(cryptsetup luksDump' "$HEALTH" | head -1 | cut -d: -f1)
[[ -n "$start" ]] || { fail "extraction: luksDump read found" "not found in $HEALTH"; exit 1; }
# The range is closed by the `fi` of the `if` that references _expected_pcrs, so
# the extraction stays valid whether or not the condition still carries the
# pcrlock term. Anchoring on the guard's own text instead would abort the suite
# for a mutant that drops it, and a suite that aborts before its behavioural
# cases is a check that cannot report the defect it exists to catch.
guard=$(grep -n '_expected_pcrs" \]\]' "$HEALTH" | head -1 | cut -d: -f1)
[[ -n "$guard" ]] || { fail "extraction: cross-check condition found" "no _expected_pcrs comparison in $HEALTH"; exit 1; }
(( guard > start )) || { fail "extraction: cross-check follows the dump read" "guard at $guard, read at $start"; exit 1; }
end=$(awk -v s="$guard" 'NR>s && /^                fi$/ { print NR; exit }' "$HEALTH")
[[ -n "$end" ]] || { echo "extraction failed: cross-check terminator not found"; exit 1; }
sed -n "${start},${end}p" "$HEALTH" > "$WORK/block_raw.sh"
# The block must reach the cross-check AND be syntactically loadable on its own;
# a short or spliced extraction otherwise fails later as a confusing syntax
# error instead of naming the real problem.
if ! grep -q '_expected_pcrs' "$WORK/block_raw.sh"; then
    echo "extraction failed: block does not reach the Secure Boot cross-check"; exit 1
fi
if ! bash -n "$WORK/block_raw.sh" 2>/dev/null; then
    echo "extraction failed: block is not a balanced statement range"; exit 1
fi
# Drive it by supplying only the inputs it reads: ROOTLABEL/underlying are not
# referenced below the luksDump read, so the block is sourced into this shell
# (not a subshell — a subshell would discard the rows it appends) and invoked
# with the dump on stdin-free globals.
{
  echo '_tpm2_report() {'
  cat "$WORK/block_raw.sh"
  echo '}'
} > "$WORK/block.sh"

# ------------------------------------------------------------------ driver ---
ROWS=""
RECS=""
# Signatures copied from shani-health.sh so the extracted block's calls bind the
# same way they do in production: _row takes (key, value), _row2 takes a single
# continuation line, and _rec joins its arguments.
_row()  { ROWS+="$1|$2"$'\n'; }
_row2() { ROWS+="$1"$'\n'; }
_rec()  { RECS+="$*"$'\n'; }

mkdir -p "$WORK/run" "$WORK/var"

# run_health <luksDump text> <secureboot:on|off> [policy file present: 0|1]
run_health() {
    local dump_text="$1" sb="$2" pol="${3:-1}"
    if [[ "$pol" == "1" ]]; then
        printf '{"pcrBank":"sha256"}\n' > "$WORK/run/pcrlock.json"
    else
        rm -f "$WORK/run/pcrlock.json" "$WORK/var/pcrlock.json"
    fi
    ROWS=""; RECS=""
    mokutil() { [[ "$sb" == "on" ]] && echo "SecureBoot enabled" || echo "SecureBoot disabled"; }
    cryptsetup() { printf '%s\n' "$dump_text"; }
    underlying="/dev/fixture0"
    ROOTLABEL="root"
    # shellcheck source=/dev/null
    . "$WORK/_tpm2_enrolled_pcrs.sh"
    # shellcheck source=/dev/null
    . "$WORK/_tpm2_uses_pcrlock.sh"
    # shellcheck source=/dev/null
    . "$WORK/_tpm2_pcrlock_policy.sh"
    # shellcheck source=/dev/null
    . "$WORK/_tpm2_policy_hash.sh"
    # shellcheck source=/dev/null
    . "$WORK/block.sh"
    _tpm2_report "$dump_text"
    printf '%s' "$ROWS"
    printf '%s' "$RECS" > "$WORK/recs"
}

# The extracted block is asserted to still contain the guard this test exists
# to prove, so a refactor that moves the logic out of it cannot silently make
# these cases pass by testing a driver instead of the shipped code.
assert_contains "shipped block guards the cross-check against pcrlock" "$(cat "$WORK/block.sh")" '-z "$_pcrlock"'
assert_contains "shipped block has the pcrlock branch" "$(cat "$WORK/block.sh")" 'pcrlock policy: ${_pol}'

# -- Case 1: pcrlock token, policy present -----------------------------------
# The header PCR list is deliberately "0" (not "0+7") so a literal-token reading
# would flag a mismatch here.
DUMP_PCRLOCK='LUKS header information
Version:	2

Tokens:
  1: systemd-tpm2
      tpm2-hash-pcrs:   0
      tpm2-pcr-bank:    sha256
      tpm2-pubkey:
0102ab
      tpm2-pubkey-pcrs: 7
      tpm2-policy-hash:
deadbeefcafe0102
      tpm2-pin:         false
      tpm2-pcrlock:     true
      tpm2-salt:        true
      tpm2-srk:         true'

out=$(run_health "$DUMP_PCRLOCK" on 1)
assert_contains "pcrlock token -> row names the pcrlock policy" "$out" "pcrlock policy: $WORK/run/pcrlock.json"
assert_not_contains "pcrlock token -> no longer claims the policy is unavailable" "$out" "PCR policy not available"
assert_contains "pcrlock token -> policy hash is shown" "$out" "policy hash: deadbeefcafe0102"

# -- Case 4 (negative control for the false mismatch): SB on, pcrlock, and a
# header PCR list that disagrees with the expected 0+7. Must be silent.
assert_not_contains "pcrlock token -> no mismatch row against Secure Boot" "$out" "PCR policy 0 but SB is on"
assert_not_contains "pcrlock token -> no re-enroll recommendation" "$(cat "$WORK/recs")" "re-enroll"

# -- Case 2: pcrlock token, policy file absent (/run is tmpfs) ---------------
out=$(run_health "$DUMP_PCRLOCK" on 0)
assert_contains "pcrlock token with no policy file -> says so plainly" "$out" "pcrlock policy not present on this boot"
assert_not_contains "pcrlock token with no policy file -> not the old sentence" "$out" "PCR policy not available"

# -- Case 3: a literal token keeps the existing behaviour and the check ------
DUMP_LITERAL='LUKS header information
Version:	2

Tokens:
  1: systemd-tpm2
      tpm2-hash-pcrs:   0+7
      tpm2-pcrlock:     false'

out=$(run_health "$DUMP_LITERAL" on 1)
assert_contains "literal token matching 0+7 -> renders the PCR list" "$out" "auto-unlock active  (PCR 0+7)"
assert_not_contains "literal token matching 0+7 -> no mismatch row" "$out" "PCR policy"

# -- Case 5: a literal token that genuinely disagrees still reports ----------
DUMP_LITERAL_BAD='LUKS header information
Version:	2

Tokens:
  1: systemd-tpm2
      tpm2-hash-pcrs:   0
      tpm2-pcrlock:     false'

out=$(run_health "$DUMP_LITERAL_BAD" on 1)
assert_contains "literal token disagreeing with SB -> still reports the mismatch" "$out" "PCR policy 0 but SB is on"
assert_contains "literal token disagreeing with SB -> still recommends re-enroll" "$(cat "$WORK/recs")" "re-enroll: gen-efi enroll-tpm2"

# -- Case 6: a token with no readable PCR field at all -----------------------
DUMP_BLANK='LUKS header information
Version:	2

Tokens:
  1: luks2'

out=$(run_health "$DUMP_BLANK" on 1)
assert_contains "no readable PCR field -> reports unavailable, not empty" "$out" "PCR policy not available"
assert_not_contains "no readable PCR field -> no fabricated mismatch" "$out" "PCR policy  but"

echo
echo "✓ $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
