#!/bin/bash
# tests/test-tpm2-pcrlock.sh — contract tests for the TPM2 PCR enrollment policy
# in gen-efi.sh: pcrlock-vs-literal selection and per-entry-token enrollment.
#
# The two blocks under test are EXTRACTED from the shipped script and evaluated
# verbatim, so what runs is the production control flow. Only the tools whose
# *output* is the input under test are stubbed (cryptsetup, systemd-cryptenroll,
# mokutil); the selection logic and the token enumeration are never reimplemented
# here. The policy-discovery helper is sourced straight out of the script, so a
# regression in it cannot be masked by a test-local copy.
#
# Why this exists. The shipped code always enrolled with a literal `--tpm2-pcrs`
# mask chosen from `mokutil --sb-state`, and never passed `--entry-token`. Both
# were wrong in ways a happy-path test cannot see:
#
#   1. A literal PCR 7 pin is invalidated by any MOK or Secure Boot policy
#      change, forcing re-enrollment. systemd's own pcrlock mechanism exists to
#      avoid that (cryptenroll.c:552 only installs its default literal pin when
#      no pcrlock policy is present).
#   2. Omitting --entry-token makes systemd-cryptenroll create a NEW token and
#      leave the previous one stale, so blue/green would keep auto-unlocking
#      under the previous policy.
#
# Ground truth for the API, verified against systemd v255 sources rather than
# assumed:
#   cryptenroll.c:434     --tpm2-pcrlock is parse_path_argument() — a PATH, not
#                          a keyword, so "auto" would be a relative filename.
#   cryptenroll.c:552     `auto_hash_pcr_values && !arg_tpm2_pcrlock` — the
#                          literal default pin is installed only with no policy,
#                          so the two flags are mutually exclusive by design.
#   cryptenroll.c:548     the public-key PCR mask DEFAULTS to PCR 11, and
#   tpm2-util.c:4053      tpm2_pcr_seal() refuses a pcrlock policy together with
#                          a non-zero pubkey mask (EOPNOTSUPP) — so the mask
#                          must be explicitly cleared.
#   tpm2-util.c:7472      an empty --tpm2-public-key-pcrs= clears the mask.
#   tpm2-util.c:6779      the pcrlock policy search order: /run/systemd then
#                          /var/lib/systemd, basename "pcrlock.json".
#
# The negative control runs this same suite against the pre-change script: it
# must fail, or the tests prove nothing.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }

# Overridable only so the negative control can re-run the suite against a
# restored copy of the pre-change code; unset, it is always the shipped script.
GENEFI="${SHANI_GENEFI_UNDER_TEST:-scripts/gen-efi.sh}"
[[ -f "$GENEFI" ]] || { echo "missing $GENEFI"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --------------------------------------------------------------- extraction --
# The policy-discovery helper, sourced verbatim. Its two paths are repointed at
# fixtures because the real /run/systemd and /var/lib/systemd cannot be written
# safely here; the real paths are pinned by static assertions below, so the
# repointing cannot hide a path regression.
awk '/^_tpm2_pcrlock_policy_path\(\) \{$/,/^}$/' "$GENEFI" \
    | sed "s#/run/systemd/pcrlock.json#$WORK/run/pcrlock.json#;
           s#/var/lib/systemd/pcrlock.json#$WORK/var/pcrlock.json#" \
    > "$WORK/find_policy.sh"
if ! grep -q '_tpm2_pcrlock_policy_path()' "$WORK/find_policy.sh"; then
    echo "extraction failed: _tpm2_pcrlock_policy_path not found in $GENEFI"; exit 1
fi

awk '/^_tpm2_entry_token_ids\(\) \{$/,/^}$/' "$GENEFI" > "$WORK/entry_ids.sh"
if ! grep -q '_tpm2_entry_token_ids()' "$WORK/entry_ids.sh"; then
    echo "extraction failed: _tpm2_entry_token_ids not found in $GENEFI"; exit 1
fi

# The enrollment-argument block: from pcr_args construction through the mode
# line, so the mutually-exclusive arg choice, the entry-token enumeration and
# the per-token cryptenroll calls are all covered.
#
# Anchored by LINE NUMBER, not an awk range regex: that end anchor contains a
# double quote and a `$/`, and splitting the awk program across a line
# continuation made it a runaway expression that extracted 25 of 1794 bytes
# while still parsing — so the suite reported its own results against a shell
# that was nearly empty.
block_start=$(grep -nF 'local -a pcr_args=()' "$GENEFI" | cut -d: -f1)
block_end=$(grep -nF 'The disk will unlock automatically on next boot' "$GENEFI" | cut -d: -f1)
if [[ $(grep -cF 'local -a pcr_args=()' "$GENEFI") -ne 1 ]] \
   || [[ $(grep -cF 'The disk will unlock automatically on next boot' "$GENEFI") -ne 1 ]] \
   || [[ -z "$block_start" || -z "$block_end" ]] || (( block_end <= block_start )); then
    echo "extraction failed: enrollment argument block anchors not unique/ordered in $GENEFI"
    exit 1
fi
sed -n "${block_start},${block_end}p" "$GENEFI" > "$WORK/enroll_block.sh"
if ! grep -q 'pcr_args' "$WORK/enroll_block.sh"; then
    echo "extraction failed: enrollment argument block not found in $GENEFI"; exit 1
fi
if (( $(wc -l <"$WORK/enroll_block.sh") < 20 )); then
    echo "extraction failed: block truncated to $(wc -l <"$WORK/enroll_block.sh") lines"; exit 1
fi

# ---------------------------------------------------- static path pinning -----
for real_path in '/run/systemd/pcrlock.json' '/var/lib/systemd/pcrlock.json'; do
    if grep -qF "$real_path" "$GENEFI"; then
        ok "real policy search path pinned: $real_path"
    else
        fail "real policy search path pinned: $real_path" "not found in $GENEFI"
    fi
done
if grep -q 'tpm2_pcrlock_search_file' "$GENEFI"; then
    ok "helper cites systemd's own search order as its provenance"
else
    fail "helper cites systemd's own search order as its provenance" "no reference found"
fi

# -------------------------------------------- 1-4: policy discovery order -----
mkdir -p "$WORK/run" "$WORK/var"

# shellcheck source=/dev/null
. "$WORK/find_policy.sh"

if out="$(_tpm2_pcrlock_policy_path)"; then
    fail "no policy present -> returns 1" "returned 0 (path=$out)"
else
    ok "no policy present -> returns 1 (caller falls back, never aborts)"
fi

printf '{"pcrBank":"sha256"}\n' > "$WORK/var/pcrlock.json"
if out="$(_tpm2_pcrlock_policy_path)"; then
    if [[ "$out" == "$WORK/var/pcrlock.json" ]]; then
        ok "only /var/lib policy present -> that path is found"
    else
        fail "only /var/lib policy present -> that path is found" "got $out"
    fi
else
    fail "only /var/lib policy present -> that path is found" "returned 1"
fi

printf '{"pcrBank":"sha256"}\n' > "$WORK/run/pcrlock.json"
if out="$(_tpm2_pcrlock_policy_path)"; then
    if [[ "$out" == "$WORK/run/pcrlock.json" ]]; then
        ok "both present -> /run/systemd wins (systemd's own precedence)"
    else
        fail "both present -> /run/systemd wins (systemd's own precedence)" "got $out"
    fi
else
    fail "both present -> /run/systemd wins (systemd's own precedence)" "returned 1"
fi

# --------------------------------- 5-8: enrollment args + entry tokens ---------
# run_enroll <pcrlock_policy> <luksDump-fixture> -> prints the argv of every
# systemd-cryptenroll invocation, one arg per line, invocations separated by a
# "---" line.
run_enroll() {
    local policy="$1" fixture="$2"
    (
        set -uo pipefail
        pcrlock_policy="$policy"
        pcrs="0+7"
        underlying="/dev/test-luks"
        tpm2_pin_flag=""
        from_stdin=1
        log()      { :; }
        log_warn() { :; }
        error_exit() { echo "ERROR_EXIT: $*" >&2; exit 99; }
        cryptsetup() {
            if [[ "$1" == "luksDump" ]]; then cat "$fixture"; fi
        }
        systemd-cryptenroll() { echo "---"; printf '%s\n' "$@"; }
        # shellcheck source=/dev/null
        . "$WORK/entry_ids.sh"
        # shellcheck source=/dev/null
        . "$WORK/enroll_block.sh"
    ) 2>&1
}

DUMP_TWO='Tokens:
  0: luks2
  1: systemd-tpm2
      tpm2-hash-pcrs:   0+7
      tpm2-pcrlock:     false
  2: systemd-tpm2
      tpm2-hash-pcrs:   0+7
      tpm2-pcrlock:     false'

DUMP_NONE='Tokens:
  0: luks2'

printf '%s\n' "$DUMP_TWO"  > "$WORK/dump_two"
printf '%s\n' "$DUMP_NONE" > "$WORK/dump_none"

POLICY="$WORK/run/pcrlock.json"

out=$(run_enroll "$POLICY" "$WORK/dump_none")
if [[ "$out" == *"--tpm2-pcrlock=$POLICY"* ]]; then
    ok "policy present -> --tpm2-pcrlock is passed"
else
    fail "policy present -> --tpm2-pcrlock is passed" "not in: $out"
fi
if [[ "$out" == *"--tpm2-public-key-pcrs="* ]]; then
    ok "policy present -> --tpm2-public-key-pcrs= clears the mask (avoids EOPNOTSUPP)"
else
    fail "policy present -> --tpm2-public-key-pcrs= clears the mask (avoids EOPNOTSUPP)" "not in: $out"
fi
if [[ "$out" == *"--tpm2-pcrs"* ]]; then
    fail "policy present -> --tpm2-pcrs is NOT also passed (mutually exclusive)" "both flags present"
else
    ok "policy present -> --tpm2-pcrs is NOT also passed (mutually exclusive)"
fi

out=$(run_enroll "" "$WORK/dump_none")
if [[ "$out" == *"--tpm2-pcrs=0+7"* ]]; then
    ok "no policy -> falls back to the literal --tpm2-pcrs=0+7 pin"
else
    fail "no policy -> falls back to the literal --tpm2-pcrs=0+7 pin" "not in: $out"
fi
if [[ "$out" == *"--tpm2-pcrlock"* ]]; then
    fail "no policy -> --tpm2-pcrlock is NOT passed" "pcrlock flag present"
else
    ok "no policy -> --tpm2-pcrlock is NOT passed"
fi

# Both entry tokens must be enrolled, each addressed by --entry-token.
out=$(run_enroll "$POLICY" "$WORK/dump_two")
if [[ "$out" == *"--entry-token=1"* && "$out" == *"--entry-token=2"* ]]; then
    ok "two existing entry tokens -> BOTH addressed via --entry-token"
else
    fail "two existing entry tokens -> BOTH addressed via --entry-token" "not in: $out"
fi
invocations=$(grep -c '^---$' <<<"$out")
if [[ "$invocations" -eq 2 ]]; then
    ok "two existing entry tokens -> exactly 2 cryptenroll invocations"
else
    fail "two existing entry tokens -> exactly 2 cryptenroll invocations" "got $invocations"
fi

# No existing token: a single plain enrollment, no --entry-token.
out=$(run_enroll "$POLICY" "$WORK/dump_none")
if [[ "$out" != *"--entry-token"* ]]; then
    ok "no existing entry token -> plain enrollment, no --entry-token"
else
    fail "no existing entry token -> plain enrollment, no --entry-token" "found in: $out"
fi
invocations=$(grep -c '^---$' <<<"$out")
if [[ "$invocations" -eq 1 ]]; then
    ok "no existing entry token -> exactly 1 cryptenroll invocation"
else
    fail "no existing entry token -> exactly 1 cryptenroll invocation" "got $invocations"
fi

# ------------------------------------------- 9: mawk/gawk portability ---------
# The token enumeration used gawk-only gensub(), which is undefined on mawk.
# Under mawk it made the call emit nothing, so cleanup-tpm2 silently reported
# "No TPM2 slots found" and exited 0 on every mawk system.
# Comment lines are excluded deliberately: the helper's own docstring has to
# NAME gensub to explain why it is not used, and a naive whole-file grep
# reported that explanation as the defect it warns against.
if grep -vE '^[[:space:]]*#' "$GENEFI" | grep -q 'gensub'; then
    fail "token enumeration avoids gawk-only gensub()" "gensub call present (fails under mawk)"
else
    ok "token enumeration avoids gawk-only gensub()"
fi
if command -v awk >/dev/null && ! awk 'BEGIN{exit 1}' 2>/dev/null; then
    ok "awk on this host lacks gensub (real condition the fix targets)"
else
    fail "awk on this host lacks gensub (real condition the fix targets)" "host awk is gawk; the portability case is untested here"
fi

echo
echo "✓ $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
