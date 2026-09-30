#!/bin/bash
# tests/test-tpm2-pcrlock-status.sh — contract tests for pcrlock_status_json()
# in gen-efi.sh, the read-only reporter for which PCR policy a volume is
# actually locked against.
#
# The function is EXTRACTED from the shipped script and evaluated verbatim;
# only cryptsetup is stubbed, because its dump text is the input under test.
# jq is the real binary, since the output contract is the JSON itself.
#
# Why this exists. This reporter shipped in its first version with three
# independent defects, all of which produced a well-formed document that
# confidently described the wrong thing:
#
#   1. It enumerated entry tokens with `cryptsetup token list`. That
#      subcommand DOES NOT EXIST in cryptsetup 2.7.0 — the token subcommands
#      are add|remove|import|export only (confirmed against `cryptsetup
#      --help`, not assumed). The call always failed, and because the failure
#      was swallowed by `|| true`, entry_tokens was reported as [] on every
#      machine, including ones with several enrolled tokens.
#   2. It parsed tpm2-policy-hash with a same-line field split. tok255.c:241
#      prints "\ttpm2-policy-hash:" CRYPT_DUMP_LINE_SEP "%s\n" — the value is
#      on the FOLLOWING line — so the split read the empty string after the
#      colon and the policy hash was always null.
#   3. enrolled_mode was passed with --arg as the literal string "true", so
#      the document claimed enrolled_mode: "true" rather than naming the mode,
#      and a literal-PCR token was never distinguished from an unknown one
#      (both collapsed to null).
#
# Each of those is a "check that cannot fail": the function returned a valid
# jq document every time, so no amount of eyeballing the output would have
# caught any of them. The negative control re-applies all three and requires
# this suite to go red.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }

# Every assertion goes through one of these, with its label written exactly
# once. An earlier revision spelled the label twice — once in the `ok` branch
# and once in the `fail` branch — and 13 of them had drifted apart, so a real
# failure was reported under a different name than the passing assertion. The
# negative control keys on the fail label, which made three correctly-caught
# mutants look like misses. Passing the label once makes that divergence
# unrepresentable.

# assert_eq <label> <actual> <expected>
assert_eq() {
    if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "got: $2 (want: $3)"; fi
}
# assert_jq <label> <document> <filter> <expected> — expected null means JSON null
assert_jq() {
    assert_eq "$1" "$(jq -r "$3" <<<"$2")" "$4"
}

GENEFI="${SHANI_GENEFI_UNDER_TEST:-scripts/gen-efi.sh}"
[[ -f "$GENEFI" ]] || { echo "missing $GENEFI"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --------------------------------------------------------------- extraction --
awk '/^pcrlock_status_json\(\) \{$/,/^}$/' "$GENEFI" > "$WORK/status_fn.sh"
if ! grep -q 'pcrlock_status_json()' "$WORK/status_fn.sh"; then
    echo "extraction failed: pcrlock_status_json not found in $GENEFI"; exit 1
fi
# The mapper-existence gate is a real /dev/mapper path that cannot be created
# unprivileged, so it is repointed at a fixture. The real path is pinned by a
# static assertion below so the repointing cannot hide a path regression.
sed -i "s#/dev/mapper/\${ROOTLABEL}#$WORK/mapper#g" "$WORK/status_fn.sh"

awk '/^_tpm2_entry_token_ids\(\) \{$/,/^}$/' "$GENEFI" > "$WORK/entry_ids.sh"
awk '/^_tpm2_pcrlock_policy_path\(\) \{$/,/^}$/' "$GENEFI" \
    | sed "s#/run/systemd/pcrlock.json#$WORK/run/pcrlock.json#;
           s#/var/lib/systemd/pcrlock.json#$WORK/var/pcrlock.json#" \
    > "$WORK/find_policy.sh"
for f in entry_ids find_policy; do
    grep -q "() {" "$WORK/$f.sh" || { echo "extraction failed: $f"; exit 1; }
done

# Defect 1's prevention: the nonexistent subcommand must never come back.
# Comment lines are excluded because the helper's docstring has to NAME the
# command to explain why it is not used, and a naive whole-file grep reported
# that explanation as the defect it warns against.
if grep -vE '^[[:space:]]*#' "$GENEFI" | grep -q 'cryptsetup token list'; then
    fail "does not call the nonexistent 'cryptsetup token list'" "call present in $GENEFI"
else
    ok "does not call the nonexistent 'cryptsetup token list'"
fi
if grep -qF '/dev/mapper/${ROOTLABEL}' "$GENEFI"; then
    ok "real mapper gate path pinned: /dev/mapper/\${ROOTLABEL}"
else
    fail "real mapper gate path pinned: /dev/mapper/\${ROOTLABEL}" "not found in $GENEFI"
fi

# Reachability. gen-efi.sh gates every subcommand behind a hand-written
# whitelist near the top of the file, SEPARATE from the `case` dispatcher at the
# bottom. A subcommand present in the dispatcher but absent from the whitelist is
# unreachable — the guard prints usage and exits 1 first. That is not theoretical:
# `pcrlock-status` shipped exactly that way. Every other assertion in this file
# extracts pcrlock_status_json and calls it directly, which bypasses the guard
# entirely, so the whole suite stayed green and only the real harness run caught
# it (`gen-efi pcrlock-status --json` -> rc=1, usage text). Asserting the
# function's behaviour can never catch this; the guard has to be checked.
whitelist=$(grep -m1 '^if \[\[ "\${1:-}" != "configure"' "$GENEFI")
if [[ -n "$whitelist" ]]; then
    ok "top-level whitelist guard located"
    # The literal '${1:-}' is spliced in as single-quoted text on purpose:
    # writing "${1:-}" inside double quotes would expand THIS script's $1 and
    # silently search for `" != "sub"` instead.
    needle() { printf '"${1:-}" != "%s"' "$1"; }
    for sub in pcrlock-status tpm2-status; do
        if grep -qF "$(needle "$sub")" <<<"$whitelist"; then
            ok "subcommand '$sub' is reachable: whitelisted before the dispatcher"
        else
            fail "subcommand '$sub' is reachable" "absent from the whitelist guard — exits 1 before reaching the dispatcher"
        fi
    done
    # The general form of the same check: every dispatcher arm must also be
    # whitelisted, so the NEXT subcommand someone adds cannot repeat this.
    while IFS= read -r arm; do
        if grep -qF "$(needle "$arm")" <<<"$whitelist"; then
            ok "dispatcher arm '$arm' is whitelisted"
        else
            fail "dispatcher arm '$arm' is whitelisted" "arm exists in the dispatcher but not in the guard"
        fi
    done < <(sed -n '/^case "\${1:-}" in$/,/^esac$/p' "$GENEFI" \
             | grep -oE '^    [a-z0-9|-]+\)' | sed 's/^ *//' \
             | tr '|' '\n' | sed 's/)$//' | sort -u)
else
    fail "top-level whitelist guard located" "not found in $GENEFI"
fi

# ------------------------------------------------------------------ driver ---
mkdir -p "$WORK/run" "$WORK/var"
touch "$WORK/mapper"

# run_status <luksDump text> -> the JSON document on stdout
run_status() {
    local dump_text="$1"
    (
        set -uo pipefail
        ROOTLABEL="root"
        cryptsetup() {
            case "$1" in
                status) printf '   device: /dev/fixture0\n' ;;
                luksDump) printf '%s\n' "$dump_text" ;;
            esac
        }
        # shellcheck source=/dev/null
        . "$WORK/find_policy.sh"
        # shellcheck source=/dev/null
        . "$WORK/entry_ids.sh"
        # shellcheck source=/dev/null
        . "$WORK/status_fn.sh"
        pcrlock_status_json
    ) 2>/dev/null
}

# -- Fixtures copied from a real systemd v255 luksDump, not invented ---------
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

DUMP_LITERAL='LUKS header information
Version:	2

Tokens:
  0: luks2
  1: systemd-tpm2
      tpm2-hash-pcrs:   0+7
      tpm2-pcr-bank:    sha256
      tpm2-policy-hash:
1122334455
      tpm2-pin:         false
      tpm2-pcrlock:     false
  2: systemd-tpm2
      tpm2-hash-pcrs:   0+7
      tpm2-pcrlock:     false'

DUMP_NO_TOKENS='LUKS header information
Version:	2

Keyslots:
  0: luks2'

out=$(run_status "$DUMP_PCRLOCK")
if jq -e . >/dev/null 2>&1 <<<"$out"; then
    ok "emits a jq-parseable document"
else
    fail "emits a jq-parseable document" "got: $out"
fi
assert_jq "pcrlock token -> enrolled_mode is the string \"pcrlock\"" "$out" '.enrolled_mode' "pcrlock"
# Defect 2: the value is on the line AFTER the label.
assert_jq "policy_hash is read from the line AFTER the label (tok255.c:241)" "$out" '.policy_hash' "deadbeefcafe0102"
# Defect 1: the token id comes from the luksDump Tokens block.
assert_jq "entry_tokens lists the token id from the luksDump Tokens block" "$out" '.entry_tokens | join(",")' "1"
assert_jq "literal_pcrs is reported for a pcrlock token" "$out" '.literal_pcrs' "0"

out=$(run_status "$DUMP_LITERAL")
assert_jq "literal token -> enrolled_mode is \"literal\", not null" "$out" '.enrolled_mode' "literal"
assert_jq "literal token -> literal_pcrs is 0+7" "$out" '.literal_pcrs' "0+7"
# Defect 1: with two enrolled tokens the list must not collapse to [].
assert_jq "two enrolled tokens -> entry_tokens is [1,2], not []" "$out" '.entry_tokens | join(",")' "1,2"

# -- No tokens ----------------------------------------------------------------
out=$(run_status "$DUMP_NO_TOKENS")
assert_jq "no TPM2 token -> entry_tokens is []" "$out" '.entry_tokens | length' "0"
assert_jq "no TPM2 token -> enrolled_mode is null (never a guess)" "$out" '.enrolled_mode' "null"

# -- Mapper resolves but the header cannot be read ----------------------------
out=$(run_status "")
assert_jq "mapper resolves but dump unreadable -> enrolled_mode is null" "$out" '.enrolled_mode' "null"
# The device is genuinely known here — cryptsetup status resolved it — so it is
# reported even though the header could not be read. Reporting it as null would
# be the over-correction; only genuinely unknown fields become null.
assert_jq "dump unreadable but mapper resolves -> luks_device still reported" "$out" '.luks_device' "/dev/fixture0"
assert_jq "pcrlock_policy_available is a real JSON boolean false" "$out" '.pcrlock_policy_available' "false"

# -- With no mapper there is no device to report, and that IS undetermined ----
rm -f "$WORK/mapper"
out=$(run_status "$DUMP_PCRLOCK")
assert_jq "no mapper -> luks_device is null, not an empty string" "$out" '.luks_device' "null"
assert_jq "no mapper -> entry_tokens is []" "$out" '.entry_tokens | length' "0"
touch "$WORK/mapper"

# -- Policy discovery is reported too -----------------------------------------
printf '{"pcrBank":"sha256"}\n' > "$WORK/run/pcrlock.json"
out=$(run_status "$DUMP_PCRLOCK")
assert_jq "policy file present -> pcrlock_policy_available is true" "$out" '.pcrlock_policy_available' "true"
assert_jq "policy file present -> its path is reported" "$out" '.pcrlock_policy_path' "$WORK/run/pcrlock.json"
rm -f "$WORK/run/pcrlock.json"

# -- A field nothing can determine must be null, never "" --------------------
out=$(run_status "$DUMP_PCRLOCK")
assert_jq "determined policy_hash is a string" "$out" '.policy_hash | type' "string"
out=$(run_status "$DUMP_NO_TOKENS")
assert_jq "undetermined policy_hash is null, not an empty string" "$out" '.policy_hash' "null"

echo
echo "✓ $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
