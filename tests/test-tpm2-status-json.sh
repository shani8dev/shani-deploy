#!/bin/bash
# tests/test-tpm2-status-json.sh — contract tests for `gen-efi tpm2-status --json`,
# the machine-readable encryption/TPM2 interface Shani Cassini's encryption page
# consumes.
#
# The real tpm2_status_json() is EXTRACTED from scripts/gen-efi.sh and run
# verbatim (never reimplemented here) under the script's own `set -Eeuo pipefail`,
# with only the environment-derived inputs stubbed: cryptsetup, mokutil and
# systemd-cryptenroll (all need a real LUKS device / UEFI / TPM). The
# `[[ -e /dev/mapper/$ROOTLABEL ]]` gate is satisfied for real: /dev/mapper
# exists and is traversable, and ROOTLABEL is given a ".." traversal back into
# the sandbox, so the function's own path expression runs unchanged.
#
# The dispatcher arm is also extracted and run, so the fd-3 stdout discipline
# (`exec 3>&1 1>&2; tpm2_status_json >&3`, because log() writes to stdout) and
# the `--json` requirement are exercised for real, not just grepped.

set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok() { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }
summary() {
    echo ""
    if (( FAIL > 0 )); then echo "✗ $PASS passed, $FAIL failed"; exit 1; fi
    echo "✓ $PASS passed, $FAIL failed"
}

command -v jq &>/dev/null || { echo "missing jq"; exit 1; }

GENEFI=../scripts/gen-efi.sh
[[ -f "$GENEFI" ]] || { echo "missing $GENEFI"; exit 1; }
FN=$(sed -n '/^tpm2_status_json() {/,/^}/p' "$GENEFI")
[[ -n "$FN" ]] || { echo "could not extract tpm2_status_json() from $GENEFI"; exit 1; }
ARM=$(sed -n '/^    tpm2-status)$/,/^[[:space:]]*;;$/p' "$GENEFI")
[[ -n "$ARM" ]] || { echo "could not extract the tpm2-status dispatcher arm from $GENEFI"; exit 1; }

# /dev/mapper must exist and be searchable for the real `-e` check to resolve.
if [[ ! -d /dev/mapper || ! -x /dev/mapper ]]; then
    printf 'SKIP: /dev/mapper is missing or not searchable. The real\n' >&2
    printf 'tpm2_status_json() gates on [[ -e /dev/mapper/ROOTLABEL ]] and\n' >&2
    printf 'cannot be exercised without it.\n' >&2
    exit 1
fi

SB=$(mktemp -d)
trap 'rm -rf "$SB"' EXIT
STUBS="$SB/stubs"
mkdir -p "$STUBS"

# ---- stubs: the three privileged reads tpm2_status_json() performs ----------
cat > "$STUBS/cryptsetup" <<'STUB'
#!/bin/bash
# Fixtures drive the response so a test only has to state machine state.
case "${1:-}" in
    status)
        # An inactive/not-activated mapping: real cryptsetup exits 4 and
        # prints nothing on stdout.
        [[ -f "$SB/cryptsetup_status_device" ]] || exit 4
        cat "$SB/cryptsetup_status_device"
        ;;
    luksDump)
        [[ -f "$SB/luksdump" ]] || { echo "Device is not a valid LUKS device." >&2; exit 1; }
        cat "$SB/luksdump"
        ;;
    *)
        exit 1
        ;;
esac
STUB
cat > "$STUBS/mokutil" <<'STUB'
#!/bin/bash
cat "$SB/mokutil_sb_state" 2>/dev/null || true
STUB

cat > "$STUBS/systemd-cryptenroll" <<'STUB'
#!/bin/bash
cat "$SB/cryptenroll_list" 2>/dev/null || true
STUB

chmod +x "$STUBS"/*

# ".." traversal from /dev/mapper back to the sandbox, so the real
# `/dev/mapper/${ROOTLABEL}` test resolves to a file we control.
RELABEL="../../..${SB}/mapper-root"
MAPPER="${SB}/mapper-root"

# ---- fixtures --------------------------------------------------------------
DUMP_LUKS2_ARGO2='LUKS header information
Version:	2
Epoch:	4
Metadata area:	16384 [bytes]
Keyslots area:	16744448 [bytes]
UUID:	6b1f4e2c-8a3d-4f7b-9c05-2e1a7d3b8f44
Label:	shanios-root
Flags:	(removed)
Priority:	normal
Data offset:	16744448
Metadata size:	4 [bytes]
Keyslots:
  0: luks2
	Cipher:	aes-xts-plain64
	PBKDF:	argon2id
	Memory:	65536
	Iterations:	4
	Parallelism:	4
  1: luks2
	Cipher:	aes-xts-plain64
	PBKDF:	argon2id
  2: luks2
	Cipher:	aes-xts-plain64
	PBKDF:	argon2id
Tokens:
  1: systemd-tpm2
	tpm2-pcrs:	7
	tpm2-public-key:	rsa2048
	tpm2-pin:	false
  2: systemd-tpm2
	tpm2-pcrs:	7
	tpm2-public-key:	rsa2048
	tpm2-pin:	false
Segments:
  1: crypt
Digests:
  0: sha256'

DUMP_LUKS2_PBKDF2='LUKS header information
Version:	2
Epoch:	4
UUID:	1a2b3c4d-0000-0000-0000-000000000000
Keyslots:
  0: luks2
	Cipher:	aes-xts-plain64
	PBKDF:	pbkdf2
Tokens:
  1: systemd-tpm2
	tpm2-pcrs:	7
	tpm2-pin:	true
Segments:
  1: crypt'

DUMP_LUKS1='LUKS header information
Version:	1
Cipher name:	xts-plain64
Cipher mode:	xts-plain64
Hash spec:	sha512
Payload offset:	4096
Key slots area:	8M [bytes]
Mode:	read/write
Keyslots:
  0: luks1
  1: luks1
'

# No LUKS header whatsoever: an unlocked-but-not-encrypted, or a failed dump.
DUMP_NO_HEADER='Device /dev/nvme0n1p3 is not a valid LUKS device.'

# A keyslot-looking entry under a section that is not Keyslots: must not be
# counted — a count that is not scoped to the section header invents a
# keyslot, which is the one thing this field must never do.
DUMP_KEYSLOT_AMBIGUOUS='LUKS header information
Version:	2
Keyslots:
  0: luks2
Tokens:
  0: luks1
Segments:
  1: crypt'

# ---- machine-state fixtures ------------------------------------------------
# Realistic `cryptsetup status` output: the function parses the
# "  device:  <path>" line out of it, so a bare path here would silently
# produce luks_device="" and make every LUKS assertion vacuous.
status_out() {
    printf '/dev/mapper/shanios-root is active and is in use.\n'
    printf '  type:    LUKS2\n'
    printf '  cipher:  aes-xts-plain64\n'
    printf '  keysize: 512 bits\n'
    printf '  device:  %s\n' "$1"
    printf '  sector size:  512\n'
    printf '  offset:  4096 sectors\n'
    printf '  mode:    read/write\n'
}

# machine <encrypted:0|1> <device|-> <dump|NONE> <sb-state> <cryptenroll-list>
machine() {
    rm -f "$MAPPER" "$SB/cryptsetup_status_device" "$SB/luksdump" \
          "$SB/mokutil_sb_state" "$SB/cryptenroll_list"
    if [[ "$1" == "1" ]]; then
        : > "$MAPPER"           # makes the real `[[ -e /dev/mapper/... ]]` true
        [[ "$2" == "-" ]] || status_out "$2" > "$SB/cryptsetup_status_device"
        if [[ "$3" != "NONE" ]]; then printf '%s\n' "$3" > "$SB/luksdump"; fi
    fi
    printf '%s' "$4" > "$SB/mokutil_sb_state"
    printf '%s' "$5" > "$SB/cryptenroll_list"
}

# Run the REAL function under the script's own shell options. stdout only:
# stderr is dropped unless TSJ_DEBUG=1, so any stray output on the JSON path
# shows up as a jq parse failure rather than being hidden.
ERRF="$SB/stderr"
emit() {
    (
        set -Eeuo pipefail
        export SB
        # Deliberate: these are set inside the subshell that runs the
        # extracted code, and nowhere else.
        # shellcheck disable=SC2030,SC2031
        PATH="$STUBS:$PATH"
        # shellcheck disable=SC2030,SC2031
        export ROOTLABEL="$RELABEL"
        eval "$FN"
        tpm2_status_json
    ) 2>"$ERRF"
    if [[ "${TSJ_DEBUG:-0}" == "1" && -s "$ERRF" ]]; then
        echo "  [stderr from tpm2_status_json]:" >&2
        sed 's/^/    /' "$ERRF" >&2
    fi
}

JSON=""; RC=0
run_status() { JSON=$(emit); RC=$?; }

# jq field read; "null" when the key is absent — the RED signal.
jqf() { printf '%s' "$1" | jq -r "$2" 2>/dev/null || echo "null"; }

echo "────────────────── tpm2-status --json contract tests ──────────────────"

# ---- 1. LUKS cipher / KDF / keyslot detail (the B2 change) -----------------
machine 1 /dev/nvme0n1p3 "$DUMP_LUKS2_ARGO2" "SecureBoot enabled" "/dev/sda"
run_status

# The new field: absent today, so jq answers null — this is the RED assertion.
got=$(jqf "$JSON" '.luks_cipher // "null"')
if [[ "$got" != "null" && -n "$got" ]]; then
    ok "luks_cipher is reported from the dump (got '$got')"
else
    fail "luks_cipher is reported from the dump" "expected a non-null .luks_cipher, got '$got' (full: $JSON)"
fi

got=$(jqf "$JSON" '.luks_kdf // "null"')
if [[ "$got" != "null" && -n "$got" ]]; then
    ok "luks_kdf is reported from the dump (got '$got')"
else
    fail "luks_kdf is reported from the dump" "expected a non-null .luks_kdf, got '$got' (full: $JSON)"
fi

got=$(jqf "$JSON" '.luks_keyslots_in_use // "null"')
if [[ "$got" != "null" && -n "$got" ]]; then
    ok "luks_keyslots_in_use is reported from the dump (got '$got')"
else
    fail "luks_keyslots_in_use is reported from the dump" "expected a non-null .luks_keyslots_in_use, got '$got' (full: $JSON)"
fi

# ---- 2. correct VALUES, not just presence ----------------------------------
if [[ $(jqf "$JSON" '.luks_cipher') == "aes-xts-plain64" ]]; then
    ok "luks_cipher == aes-xts-plain64 (LUKS2 'Cipher:' line)"
else
    fail "luks_cipher == aes-xts-plain64 (LUKS2 'Cipher:' line)" "got '$(jqf "$JSON" '.luks_cipher')'"
fi

# argon2 must be reported as argon2 — never relabelled PBKDF2.
kdf=$(jqf "$JSON" '.luks_kdf')
if [[ "$kdf" == "argon2id" ]]; then
    ok "luks_kdf == argon2id (LUKS2 'PBKDF:' line, verbatim)"
else
    fail "luks_kdf == argon2id (LUKS2 'PBKDF:' line, verbatim)" "got '$kdf'"
fi
if [[ "${kdf,,}" == *argon2* && "${kdf,,}" != *pbkdf2* ]]; then
    ok "argon2id is not mislabelled as PBKDF2"
else
    fail "argon2id is not mislabelled as PBKDF2" "got '$kdf'"
fi

if [[ $(jqf "$JSON" '.luks_keyslots_in_use') == "3" ]]; then
    ok "luks_keyslots_in_use == 3 (three 'N: luks2' entries, tokens not counted)"
else
    fail "luks_keyslots_in_use == 3" "got '$(jqf "$JSON" '.luks_keyslots_in_use')'"
fi

if [[ $(jqf "$JSON" '.luks_version') == "2" ]]; then
    ok "luks_version == 2"
else
    fail "luks_version == 2" "got '$(jqf "$JSON" '.luks_version')'"
fi

# ---- 3. pbkdf2 variant is reported as pbkdf2, not defaulted to argon2 ------
machine 1 /dev/nvme0n1p3 "$DUMP_LUKS2_PBKDF2" "" ""
run_status
if [[ $(jqf "$JSON" '.luks_kdf') == "pbkdf2" ]]; then
    ok "luks_kdf == pbkdf2 on a pbkdf2 dump (no hardcoded default)"
else
    fail "luks_kdf == pbkdf2 on a pbkdf2 dump" "got '$(jqf "$JSON" '.luks_kdf')'"
fi

# ---- 4. LUKS1 dump: legacy field names must still be understood ------------
machine 1 /dev/nvme0n1p3 "$DUMP_LUKS1" "" ""
run_status
if [[ $(jqf "$JSON" '.luks_cipher') == "xts-plain64" ]]; then
    ok "luks_cipher == xts-plain64 (LUKS1 'Cipher name:' line)"
else
    fail "luks_cipher == xts-plain64 (LUKS1 'Cipher name:' line)" "got '$(jqf "$JSON" '.luks_cipher')'"
fi
if [[ $(jqf "$JSON" '.luks_kdf') == "sha512" ]]; then
    ok "luks_kdf == sha512 (LUKS1 'Hash spec:' line)"
else
    fail "luks_kdf == sha512 (LUKS1 'Hash spec:' line)" "got '$(jqf "$JSON" '.luks_kdf')'"
fi
if [[ $(jqf "$JSON" '.luks_keyslots_in_use') == "2" ]]; then
    ok "luks_keyslots_in_use == 2 on a LUKS1 dump"
else
    fail "luks_keyslots_in_use == 2 on a LUKS1 dump" "got '$(jqf "$JSON" '.luks_keyslots_in_use')'"
fi

# ---- 4b. keyslot count is scoped to the Keyslots: section -----------------
machine 1 /dev/nvme0n1p3 "$DUMP_KEYSLOT_AMBIGUOUS" "" ""
run_status
if [[ $(jqf "$JSON" '.luks_keyslots_in_use') == "1" ]]; then
    ok "keyslot count ignores a luks1 entry under Tokens: (no phantom keyslot)"
else
    fail "keyslot count ignores a luks1 entry under Tokens: (no phantom keyslot)" \
         "got '$(jqf "$JSON" '.luks_keyslots_in_use')'"
fi

# ---- 5. NEGATIVE CONTROL: no LUKS header at all ---------------------------# Must still be one valid JSON object on rc 0, with the new fields empty/0 —
# never a crash, never a fabricated cipher or KDF.
machine 1 /dev/nvme0n1p3 "$DUMP_NO_HEADER" "" ""
run_status
if (( RC == 0 )) && printf '%s' "$JSON" | jq -e . &>/dev/null; then
    ok "headerless dump: rc 0 and valid JSON"
else
    fail "headerless dump: rc 0 and valid JSON" "rc=$RC out=$JSON"
fi
if [[ $(jqf "$JSON" '.luks_cipher') == "" && $(jqf "$JSON" '.luks_kdf') == "" \
   && $(jqf "$JSON" '.luks_version') == "" \
   && $(jqf "$JSON" '.luks_keyslots_in_use') == "0" ]]; then
    ok "headerless dump: new fields empty/0, nothing invented"
else
    fail "headerless dump: new fields empty/0, nothing invented" \
         "cipher='$(jqf "$JSON" '.luks_cipher')' kdf='$(jqf "$JSON" '.luks_kdf')' ver='$(jqf "$JSON" '.luks_version')' slots='$(jqf "$JSON" '.luks_keyslots_in_use')'"
fi

# ---- 6. NEGATIVE CONTROL: luksDump fails outright -------------------------
machine 1 /dev/nvme0n1p3 NONE "" ""
run_status
if (( RC == 0 )) && printf '%s' "$JSON" | jq -e . &>/dev/null \
   && [[ $(jqf "$JSON" '.luks_cipher') == "" && $(jqf "$JSON" '.luks_keyslots_in_use') == "0" ]]; then
    ok "failed luksDump: rc 0, valid JSON, empty new fields"
else
    fail "failed luksDump: rc 0, valid JSON, empty new fields" "rc=$RC out=$JSON"
fi

# ---- 7. NEGATIVE CONTROL: not encrypted at all ----------------------------
machine 0 - NONE "" ""
run_status
if (( RC == 0 )) && printf '%s' "$JSON" | jq -e . &>/dev/null; then
    ok "unencrypted root: rc 0 and valid JSON"
else
    fail "unencrypted root: rc 0 and valid JSON" "rc=$RC out=$JSON"
fi
if [[ $(jqf "$JSON" '.encrypted') == "false" && $(jqf "$JSON" '.luks_device') == "" \
   && $(jqf "$JSON" '.luks_cipher') == "" && $(jqf "$JSON" '.luks_kdf') == "" \
   && $(jqf "$JSON" '.luks_keyslots_in_use') == "0" ]]; then
    ok "unencrypted root: no LUKS field is invented"
else
    fail "unencrypted root: no LUKS field is invented" "out=$JSON"
fi

# ---- 8. the 7 original keys: present and unchanged in every case ---------
check_original_keys() {
    local label="$1" expect_slots="$2" expect_pin="$3" expect_enrolled="$4"
    local missing
    missing=$(printf '%s' "$JSON" | jq -r 'has("encrypted") and has("tpm2_present")
              and has("tpm2_enrolled") and has("tpm2_slots") and has("tpm2_pin")
              and has("secure_boot") and has("luks_device")' 2>/dev/null) || missing="jq-error"
    if [[ "$missing" == "true" ]]; then
        ok "original 7 keys present and typed ($label)"
    else
        fail "original 7 keys present and typed ($label)" "jq has() check: $missing"
    fi
    if [[ $(jqf "$JSON" '.tpm2_slots') == "$expect_slots" \
       && $(jqf "$JSON" '.tpm2_pin') == "$expect_pin" \
       && $(jqf "$JSON" '.tpm2_enrolled') == "$expect_enrolled" ]]; then
        ok "original tpm2_slots/pin/enrolled semantics unchanged ($label)"
    else
        fail "original tpm2_slots/pin/enrolled semantics unchanged ($label)" \
             "slots='$(jqf "$JSON" '.tpm2_slots')' (want $expect_slots) pin='$(jqf "$JSON" '.tpm2_pin')' (want $expect_pin) enrolled='$(jqf "$JSON" '.tpm2_enrolled')' (want $expect_enrolled)"
    fi
    if [[ $(jqf "$JSON" '.encrypted') == "true" && $(jqf "$JSON" '.luks_device') == "/dev/nvme0n1p3" ]]; then
        ok "original encrypted/luks_device semantics unchanged ($label)"
    else
        fail "original encrypted/luks_device semantics unchanged ($label)" \
             "encrypted='$(jqf "$JSON" '.encrypted')' luks_device='$(jqf "$JSON" '.luks_device')'"
    fi
}

machine 1 /dev/nvme0n1p3 "$DUMP_LUKS2_ARGO2" "SecureBoot enabled" "/dev/sda"
run_status; check_original_keys "LUKS2 argon2id" 2 false true
machine 1 /dev/nvme0n1p3 "$DUMP_LUKS2_PBKDF2" "SecureBoot disabled" ""
run_status; check_original_keys "LUKS2 pbkdf2, pin" 1 true true
machine 1 /dev/nvme0n1p3 "$DUMP_NO_HEADER" "" ""
run_status; check_original_keys "no LUKS header" 0 false false
machine 0 - NONE "" ""
run_status
if [[ $(jqf "$JSON" '.encrypted') == "false" && $(jqf "$JSON" '.tpm2_slots') == "0" \
   && $(jqf "$JSON" '.tpm2_enrolled') == "false" && $(jqf "$JSON" '.tpm2_pin') == "false" ]]; then
    ok "original 7 keys still correct when unencrypted"
else
    fail "original 7 keys still correct when unencrypted" "out=$JSON"
fi

# ---- 9. output discipline: one line, valid JSON, nothing on stdout --------
# cryptsetup's own free-form dump text must never leak into the document —
# this is what a printf-concatenated emitter would get wrong.
machine 1 /dev/nvme0n1p3 "$DUMP_LUKS2_ARGO2" "" ""
run_status
lines=$(printf '%s\n' "$JSON" | wc -l)
if (( lines == 1 )) && printf '%s' "$JSON" | jq -e . &>/dev/null; then
    ok "stdout is exactly one valid JSON line (no dump text leaked)"
else
    fail "stdout is exactly one valid JSON line (no dump text leaked)" "lines=$lines out=$JSON"
fi

# A dump with quotes, a tab and a backslash must still serialize cleanly.
printf 'LUKS header information\nVersion:\t2\nKeyslots:\n  0: luks2\n\tLabel:\twe"ird\\back\tslash\n' > "$SB/luksdump"
: > "$MAPPER"
status_out /dev/nvme0n1p3 > "$SB/cryptsetup_status_device"
run_status
if printf '%s' "$JSON" | jq -e . &>/dev/null; then
    ok "dump containing quotes/backslash/tab still yields parseable JSON"
else
    fail "dump containing quotes/backslash/tab still yields parseable JSON" "out=$JSON"
fi

# ---- 10. the JSON path must stay silent (no log* on stdout) --------------
if printf '%s' "$FN" | grep -qE '(^|[^_[:alnum:]])(log|log_warn|error_exit|die)[[:space:]]*\('; then
    fail "no log*/error_exit call inside tpm2_status_json()" \
         "$(printf '%s' "$FN" | grep -nE '(^|[^_[:alnum:]])(log|log_warn|error_exit|die)[[:space:]]*\(' | tr '\n' ' ')"
else
    ok "no log*/error_exit call inside tpm2_status_json()"
fi

# ---- 11. dispatcher: fd 3 keeps the JSON clean, --json still required ----
# The real `tpm2-status)` arm, re-wrapped in the `case` it came out of and run
# with a log() that writes to stdout exactly like the real one.
run_arm() {
    (
        set -Eeuo pipefail
        set -- "$@"        # the arm reads the dispatcher's own "$2"
        export SB
        # Deliberate: these are set inside the subshell that runs the
        # extracted code, and nowhere else.
        # shellcheck disable=SC2030,SC2031
        PATH="$STUBS:$PATH"
        # shellcheck disable=SC2030,SC2031
        export ROOTLABEL="$RELABEL"
        # shellcheck disable=SC2329  # invoked by the eval'd arm below
        log()      { echo "GENEFI noise on stdout"; }
        # shellcheck disable=SC2329  # invoked by the eval'd arm below
        log_warn() { echo "GENEFI noise on stdout"; }
        # shellcheck disable=SC2329  # invoked by the eval'd arm below
        error_exit() { echo "error_exit: $*" >&2; exit 1; }
        eval "$FN"
        eval "case tpm2-status in
$ARM
esac"
    ) 2>/dev/null
}

machine 1 /dev/nvme0n1p3 "$DUMP_LUKS2_ARGO2" "" ""
JSON=$(run_arm tpm2-status --json); RC=$?
if (( RC == 0 )) && printf '%s' "$JSON" | jq -e . &>/dev/null; then
    ok "dispatcher arm: --json emits clean JSON on the original stdout"
else
    fail "dispatcher arm: --json emits clean JSON on the original stdout" "rc=$RC out=$JSON"
fi

# The `--json` guard, checked on the arm directly: the real script cannot be
# invoked here because it self-elevates through pkexec/sudo before dispatch.
JSON=""; RC=0
JSON=$(run_arm tpm2-status) || RC=$?
if (( RC != 0 )) && [[ -z "$JSON" ]]; then
    ok "dispatcher arm: missing --json errors out and prints no JSON"
else
    fail "dispatcher arm: missing --json errors out and prints no JSON" "rc=$RC out=$JSON"
fi

summary
