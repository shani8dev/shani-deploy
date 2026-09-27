#!/bin/bash
# tests/test-config-validation.sh — contract tests for the shani.conf values
# that gen-efi.sh turns into a mount target and a device-mapper path.
#
# The real _load_ini_config() and _validate_config() are EXTRACTED from
# scripts/gen-efi.sh and run verbatim (never reimplemented here), so what is
# exercised is the shipped code. The only things stubbed are the two DEFAULT_
# values, which the file defines at column 0 next to the config load and which
# cannot be reached without running the whole script.
#
# Why this exists: the parser accepts any value. `printf -v '%s'` does not
# expand it, so there is no injection, but nothing downstream checked it either
# -- deploy_esp_path reaches `mount "$ESP"`, `umount "$ESP"`,
# `mkdir -p "$ESP/EFI/BOOT"` and a `cp` onto the ESP, and deploy_rootlabel is
# interpolated into /dev/mapper/<label> and handed to cryptsetup. A mistyped
# shani.conf could point any of those somewhere unintended.
#
# The negative half matters as much as the positive one. Every "must reject"
# case below asserts the default came back, so if the validation were deleted
# these fail rather than silently passing. And a value that is merely unusual
# but legitimate must survive, or the fix has broken a working machine.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }
summary() {
    echo ""
    if (( FAIL > 0 )); then echo "✗ $PASS passed, $FAIL failed"; exit 1; fi
    echo "✓ $PASS passed, 0 failed"
}

GENEFI=scripts/gen-efi.sh
[[ -f "$GENEFI" ]] || { echo "missing $GENEFI"; exit 1; }

eval "$(sed -n '/^_load_ini_config() {/,/^}/p;/^_validate_config() {/,/^}/p' "$GENEFI")"
declare -F _load_ini_config >/dev/null || { echo "could not extract _load_ini_config()"; exit 1; }
declare -F _validate_config  >/dev/null || { echo "could not extract _validate_config()"; exit 1; }

DEFAULT_deploy_esp_path="/boot/efi"
DEFAULT_deploy_rootlabel="shani_root"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Apply a config body through the real parser + validator, then report what the
# two consumed values ended up as. `set +u` because the parser only defines the
# variables a config happens to mention.
apply() {
    printf '%s\n' "$1" > "$TMP/shani.conf"
    (
        set +u
        unset deploy_esp_path deploy_rootlabel 2>/dev/null || true
        _load_ini_config "$TMP/shani.conf" 2>/dev/null
        _validate_config 2>/dev/null
        printf '%s|%s' "${deploy_esp_path-$DEFAULT_deploy_esp_path}" \
                       "${deploy_rootlabel-$DEFAULT_deploy_rootlabel}"
    )
}

# --- values that must survive ------------------------------------------------

check_kept() { # $1 = label, $2 = config, $3 = expected esp, $4 = expected label
    local got esp label
    got=$(apply "$2")
    esp="${got%%|*}"; label="${got##*|}"
    if [[ "$esp" == "$3" && "$label" == "$4" ]]; then
        ok "$1"
    else
        fail "$1" "esp=$esp (want $3), rootlabel=$label (want $4)"
    fi
}

check_kept "the shipped default ESP and rootlabel are kept" \
    '[deploy]
esp_path=/boot/efi
rootlabel=shani_root' "/boot/efi" "shani_root"

check_kept "/efi is a real alternative ESP on this image and is kept" \
    '[deploy]
esp_path=/efi' "/efi" "shani_root"

check_kept "a hyphen and underscore in a rootlabel are legal dm-name characters" \
    '[deploy]
rootlabel=shanios_root-2' "/boot/efi" "shanios_root-2"

check_kept "a trailing-slash ESP path is absolute and is kept" \
    '[deploy]
esp_path=/boot/efi/' "/boot/efi/" "shani_root"

# --- values that must be rejected --------------------------------------------

check_kept "a relative esp_path is rejected, not mounted relative to /" \
    '[deploy]
esp_path=boot/efi' "/boot/efi" "shani_root"

check_kept "esp_path=/ is rejected" \
    '[deploy]
esp_path=/' "/boot/efi" "shani_root"

check_kept "a '..' traversal in esp_path is rejected" \
    '[deploy]
esp_path=/boot/efi/../..' "/boot/efi" "shani_root"

check_kept "a traversal in rootlabel is rejected before it reaches /dev/mapper" \
    '[deploy]
rootlabel=../../etc/shadow' "/boot/efi" "shani_root"

check_kept "a quote in rootlabel is rejected" \
    '[deploy]
rootlabel=a"b' "/boot/efi" "shani_root"

check_kept "a space in rootlabel is rejected" \
    '[deploy]
rootlabel=shani root' "/boot/efi" "shani_root"

# --- the config file's own keys are still not gated --------------------------
#
# A key allowlist is deliberately NOT implemented: the shipped sample documents
# 34 keys while the scripts read 38, so an allowlist built from the sample would
# drop 12 keys that are live today. This asserts an undocumented-but-live key
# still parses, so that stays true if anyone later adds a gate.

check_kept "an undocumented but live key still parses (no allowlist)" \
    '[deploy]
esp_path=/boot/efi
genefi_bin=/usr/local/bin/gen-efi' "/boot/efi" "shani_root"

if [[ -n "$(apply '[deploy]
deploy_esp_path=/tmp/evil')" ]] && \
   apply '[deploy]
genefi_bin=/usr/local/bin/gen-efi' >/dev/null 2>&1; then
    ok "a key outside the sample config is still assigned, not dropped"
else
    fail "a key outside the sample config is still assigned, not dropped" "the parser stopped assigning keys"
fi

# --- the script must actually CALL the validator -----------------------------
#
# Everything above extracts the two functions and calls them from here, so it
# proves the validator works and says nothing about whether the shipped script
# uses it. Deleting the one call site would leave gen-efi validating nothing
# while this file still reported 12/12 -- verified: commenting the call out
# changed nothing here. That was found by running that negative control, not by
# reading the test.
#
# So assert the wiring, and its ORDER, because order is what makes it a
# protection: after the config is read, before the values are consumed.
CALL_LINE=$(grep -n '^_validate_config$' "$GENEFI" | head -1 | cut -d: -f1)
LAST_LOAD=$(grep -n '_load_ini_config "' "$GENEFI" | tail -1 | cut -d: -f1)
ESP_LINE=$(grep -n '^ESP=' "$GENEFI" | head -1 | cut -d: -f1)

if [[ -n "$CALL_LINE" ]]; then
    ok "the script calls _validate_config (not merely defining it)"
else
    fail "the script calls _validate_config (not merely defining it)" "no top-level _validate_config call"
fi

if [[ -n "$CALL_LINE" && -n "$LAST_LOAD" && -n "$ESP_LINE" && "$CALL_LINE" -gt "$LAST_LOAD" ]]; then
    ok "the call comes after the config is read (line $CALL_LINE > $LAST_LOAD)"
else
    fail "the call comes after the config is read" "call=$CALL_LINE last_load=$LAST_LOAD"
fi

if [[ -n "$CALL_LINE" && -n "$ESP_LINE" && "$CALL_LINE" -lt "$ESP_LINE" ]]; then
    ok "the call comes before \$ESP is assigned from it (line $CALL_LINE < $ESP_LINE)"
else
    fail "the call comes before \$ESP is assigned from it" "call=$CALL_LINE ESP=$ESP_LINE — validating after assignment is too late"
fi

# --- the same contract in shani-deploy.sh, which has more of it --------------
#
# shani-deploy.sh resolves the same config into 22 variables and feeds three
# more dangerous sinks than gen-efi does: MOUNT_DIR (mount/umount of the
# chroot root), GENEFI_SCRIPT (handed to `chroot` to run as root) and five
# thresholds that land in $(( )) / (( )). Its assignments are already
# DEFAULT_-resolved and are made readonly further down, so the validator has to
# run in between -- which the order assertions below pin.
#
# The wiring lesson from the gen-efi half applies here too and is why these
# exist: a test that extracts the functions and calls them itself says nothing
# about whether the shipped script calls them.

DEPLOY=scripts/shani-deploy.sh
[[ -f "$DEPLOY" ]] || { echo "missing $DEPLOY"; exit 1; }

eval "$(sed -n '/^_load_ini_config() {/,/^}/p;/^_vc_bad_path() {/,/^}/p;/^_vc_num() {/,/^}/p;/^_validate_config() {/,/^}/p' "$DEPLOY")"
declare -F _validate_config >/dev/null || { echo "could not extract _validate_config() from $DEPLOY"; exit 1; }

DEFAULT_deploy_esp_path="/boot/efi"
DEFAULT_deploy_mount_dir="/mnt"
DEFAULT_deploy_genefi_script="/usr/local/bin/gen-efi"
DEFAULT_deploy_rootlabel="shani_root"
DEFAULT_deploy_max_inhibit_depth="2"
DEFAULT_deploy_max_download_attempts="5"
DEFAULT_deploy_extraction_timeout="1800"
DEFAULT_deploy_min_free_space_mb="10240"
DEFAULT_deploy_min_file_size="10485760"

# Apply a config through the real parser, resolve the uppercase variables the
# way the script does, then validate. Reports the values that reach sinks.
apply_deploy() {
    printf '%s\n' "$1" > "$TMP/shani.conf"
    (
        set +u
        unset ESP MOUNT_DIR GENEFI_SCRIPT ROOTLABEL MAX_INHIBIT_DEPTH \
              MAX_DOWNLOAD_ATTEMPTS EXTRACTION_TIMEOUT MIN_FREE_SPACE_MB MIN_FILE_SIZE 2>/dev/null || true
        _load_ini_config "$TMP/shani.conf" 2>/dev/null
        ESP="${deploy_esp_path:-$DEFAULT_deploy_esp_path}"
        MOUNT_DIR="${deploy_mount_dir:-$DEFAULT_deploy_mount_dir}"
        GENEFI_SCRIPT="${deploy_genefi_script:-$DEFAULT_deploy_genefi_script}"
        ROOTLABEL="${deploy_rootlabel:-$DEFAULT_deploy_rootlabel}"
        MAX_INHIBIT_DEPTH="${deploy_max_inhibit_depth:-$DEFAULT_deploy_max_inhibit_depth}"
        MAX_DOWNLOAD_ATTEMPTS="${deploy_max_download_attempts:-$DEFAULT_deploy_max_download_attempts}"
        EXTRACTION_TIMEOUT="${deploy_extraction_timeout:-$DEFAULT_deploy_extraction_timeout}"
        MIN_FREE_SPACE_MB="${deploy_min_free_space_mb:-$DEFAULT_deploy_min_free_space_mb}"
        MIN_FILE_SIZE="${deploy_min_file_size:-$DEFAULT_deploy_min_file_size}"
        _validate_config 2>/dev/null
        printf '%s|%s|%s|%s|%s|%s|%s|%s' "$ESP" "$MOUNT_DIR" "$GENEFI_SCRIPT" "$ROOTLABEL" \
               "$MAX_INHIBIT_DEPTH" "$MAX_DOWNLOAD_ATTEMPTS" "$EXTRACTION_TIMEOUT" "$MIN_FREE_SPACE_MB"
    )
}

# $1=label  $2=config  $3..$10=expected esp,mnt,gen,label,depth,attempts,timeout,minspace
check_deploy() {
    local label="$1" cfg="$2"; shift 2
    local -a want=("$@")
    local -a got=()
    local IFS='|'
    read -r -a got <<< "$(apply_deploy "$cfg")"
    local bad=""
    local names=(ESP MOUNT_DIR GENEFI_SCRIPT ROOTLABEL MAX_INHIBIT_DEPTH \
                 MAX_DOWNLOAD_ATTEMPTS EXTRACTION_TIMEOUT MIN_FREE_SPACE_MB)
    local i
    for i in "${!want[@]}"; do
        [[ "${got[$i]}" == "${want[$i]}" ]] || bad+="${names[$i]}=${got[$i]}(want ${want[$i]}) "
    done
    if [[ -z "$bad" ]]; then ok "$label"; else fail "$label" "$bad"; fi
}

check_deploy "deploy: the shipped defaults survive untouched" \
    '[deploy]
esp_path=/boot/efi
mount_dir=/mnt
genefi_script=/usr/local/bin/gen-efi
rootlabel=shani_root' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: /efi is a real ESP and is kept" \
    '[deploy]
esp_path=/efi' \
    /efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: esp_path=/ is rejected" \
    '[deploy]
esp_path=/' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: a relative mount_dir is rejected" \
    '[deploy]
mount_dir=mnt' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: a relative genefi_script is rejected before chroot runs it" \
    '[deploy]
genefi_script=bin/gen-efi' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: a '..' in genefi_script is rejected" \
    '[deploy]
genefi_script=/usr/local/bin/../bin/gen-efi' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: a traversal in rootlabel is rejected" \
    '[deploy]
rootlabel=../etc/shadow' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: a non-numeric threshold falls back to the default, not into arithmetic" \
    '[deploy]
extraction_timeout=30m' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

check_deploy "deploy: a threshold below its floor is raised to the floor" \
    '[deploy]
extraction_timeout=5' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 60 10240

check_deploy "deploy: max_download_attempts=0 is raised to 1 (a zero retry loop is not a choice)" \
    '[deploy]
max_download_attempts=0' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 1 1800 10240

check_deploy "deploy: max_inhibit_depth=0 is a legitimate zero and is KEPT" \
    '[deploy]
max_inhibit_depth=0' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 0 5 1800 10240

check_deploy "deploy: an undocumented but live key still parses (no allowlist)" \
    '[deploy]
genefi_bin=/usr/local/bin/gen-efi' \
    /boot/efi /mnt /usr/local/bin/gen-efi shani_root 2 5 1800 10240

# --- and the wiring, which is the part the value assertions cannot see -------

D_CALL=$(grep -n '^_validate_config$' "$DEPLOY" | head -1 | cut -d: -f1)
D_LAST_ASSIGN=$(grep -n '^MAX_INHIBIT_DEPTH="' "$DEPLOY" | head -1 | cut -d: -f1)
D_READONLY=$(grep -n '^readonly ESP=' "$DEPLOY" | head -1 | cut -d: -f1)

if [[ -n "$D_CALL" ]]; then
    ok "deploy: the script calls _validate_config (not merely defining it)"
else
    fail "deploy: the script calls _validate_config (not merely defining it)" "no top-level call"
fi

if [[ -n "$D_CALL" && -n "$D_LAST_ASSIGN" && "$D_CALL" -gt "$D_LAST_ASSIGN" ]]; then
    ok "deploy: the call comes after every config assignment (line $D_CALL > $D_LAST_ASSIGN)"
else
    fail "deploy: the call comes after every config assignment" "call=$D_CALL last_assign=$D_LAST_ASSIGN"
fi

if [[ -n "$D_CALL" && -n "$D_READONLY" && "$D_CALL" -lt "$D_READONLY" ]]; then
    ok "deploy: the call comes before the readonly block (line $D_CALL < $D_READONLY)"
else
    fail "deploy: the call comes before the readonly block" "call=$D_CALL readonly=$D_READONLY — correcting a readonly value would fail outright"
fi

summary
