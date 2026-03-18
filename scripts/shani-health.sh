#!/bin/bash
# shani-health — ShaniOS system health, security, and diagnostics tool
#
# Standalone read-mostly companion to shani-deploy. Covers everything that
# is about inspecting and hardening the system, not about updating it.
#
# Usage:
#   shani-health                     Full system status report (default / --info)
#   shani-health --fix-security      Auto-fix all [AUTOMATABLE] issues
#   shani-health --verify            Deep integrity check: UKI sigs + Btrfs scrub
#   shani-health --history [N]       Last N deploy/rollback events (default: 50)
#   shani-health --storage-info      Btrfs storage analysis (delegates to shani-deploy)
#   shani-health --export-logs [DIR] Bundle logs + state for bug reports
#
# Install:  cp shani-health /usr/local/bin/shani-health && chmod +x $_
# Requires: root (auto-escalates via pkexec or sudo)
#
# Exit codes:
#   0  success / no issues
#   1  fatal error or (for --verify) integrity issues found

set -Eeuo pipefail
IFS=$'\n\t'

###############################################################################
### Constants                                                                ###
###############################################################################

readonly SCRIPT_VERSION="2.0"
readonly OS_NAME="shanios"
readonly ROOTLABEL="shani_root"
readonly ROOT_DEV="/dev/disk/by-label/shani_root"
readonly ESP="/boot/efi"
readonly GENEFI_BIN="/usr/local/bin/gen-efi"
readonly DEPLOY_BIN="/usr/local/bin/shani-deploy"
readonly DEPLOY_LOG="/var/log/shanios-deploy.log"
readonly CHANNEL_FILE="/etc/shani-channel"

# /data state markers
readonly DATA_BOOT_OK="/data/boot-ok"
readonly DATA_BOOT_FAIL="/data/boot_failure"
readonly DATA_BOOT_FAIL_ACKED="/data/boot_failure.acked"
readonly DATA_BOOT_HARD_FAIL="/data/boot_hard_failure"
readonly DATA_CURRENT_SLOT="/data/current-slot"
readonly DATA_PREV_SLOT="/data/previous-slot"
readonly DATA_DEPLOY_PENDING="/data/deployment_pending"
readonly DATA_REBOOT_NEEDED="/run/shanios/reboot-needed"

declare -a ORIGINAL_ARGS=("$@")
VERBOSE="no"

###############################################################################
### Privilege escalation                                                     ###
###############################################################################

_require_root() {
    [[ $(id -u) -eq 0 ]] && return 0
    local self; self=$(readlink -f "$0")
    if command -v pkexec &>/dev/null; then
        exec pkexec "$self" "${ORIGINAL_ARGS[@]}"
    elif command -v sudo &>/dev/null; then
        exec sudo "$self" "${ORIGINAL_ARGS[@]}"
    fi
    _die "Must run as root — re-run with sudo or as root"
}

###############################################################################
### Logging                                                                  ###
###############################################################################

_ts()         { date '+%Y-%m-%d %H:%M:%S'; }
_log()        { echo "$(_ts) [INFO]    $*" >&2; }
_log_ok()     { echo -e "$(_ts) \033[0;32m[OK]\033[0m      $*" >&2; }
_log_warn()   { echo -e "$(_ts) \033[0;33m[WARN]\033[0m    $*" >&2; }
_log_err()    { echo -e "$(_ts) \033[0;31m[ERROR]\033[0m   $*" >&2; }
_log_debug()  { [[ "$VERBOSE" == "yes" ]] && echo "$(_ts) [DEBUG]   $*" >&2 || true; }
_log_section(){ echo ""; \
                echo "  ================================================"; \
                echo "    $1"; \
                echo "  ================================================"; }
_die()        { echo -e "$(_ts) \033[1;31m[FATAL]\033[0m   $*" >&2; exit 1; }

# Report output helpers — write to stdout so callers can pipe/redirect
_row()   { printf "    %-10s: %s\n" "$1" "$2"; }   # key : value
_row2()  { printf "    %-10s  %s\n" "" "$1"; }     # continuation/indent
_head()  { echo ""; echo "  $1"; }                 # section heading

###############################################################################
### Shared helpers                                                           ###
###############################################################################

_is_mounted() { findmnt -M "$1" &>/dev/null; }

_get_booted_subvol() {
    local rootflags subvol
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2- || echo "")
    subvol=$(awk -F'subvol=' '{print $2}' <<< "$rootflags" | cut -d, -f1)
    subvol="${subvol#@}"
    [[ -z "$subvol" ]] && \
        subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    echo "${subvol:-unknown}"
}

# Mount ESP if not already mounted; sets _esp_mounted=1 if we did it ourselves.
# Callers must declare local _esp_mounted=0 before calling.
_esp_mount() {
    mountpoint -q "$ESP" 2>/dev/null && return 0
    mount "$ESP" 2>/dev/null && _esp_mounted=1 || true
}
_esp_umount() { (( _esp_mounted )) && umount "$ESP" 2>/dev/null || true; _esp_mounted=0; }

# Resolve the btrfs resume_offset for a swapfile; echoes offset or ""
_swapfile_offset() {
    local swapfile="$1"
    [[ -f "$swapfile" ]] || { echo ""; return; }
    local out; out=$(btrfs inspect-internal map-swapfile -r "$swapfile" 2>/dev/null || echo "")
    local offset
    offset=$(echo "$out" | \
        awk -F'[: \t]+' '/resume_offset/{print $2; found=1} END{if(!found)exit 1}' 2>/dev/null) \
        || offset=$(echo "$out" | awk 'NF{last=$NF} END{if(last+0>0)print last+0}' 2>/dev/null)
    echo "${offset:-}"
}

# Find the active non-zram swapfile; echoes path or ""
_find_swapfile() {
    local dev
    while IFS= read -r dev; do
        dev="${dev%%[[:space:]]*}"
        [[ -z "$dev" ]] && continue
        [[ -f "$dev" ]] && { echo "$dev"; return; }
    done < <(swapon --show=NAME --noheadings 2>/dev/null | grep -v zram || true)
    echo ""
}

# Global recommendations array — reset at the start of system_info
declare -a _RECS=()
_rec()        { _RECS+=("$*"); }
_recs_reset() { _RECS=(); }

###############################################################################
### Section helpers                                                          ###
###############################################################################

_section_os_slots() {
    local booted="$1"
    local version profile channel slot_current slot_previous
    version=$(     cat /etc/shani-version   2>/dev/null || echo "unknown")
    profile=$(     cat /etc/shani-profile   2>/dev/null || echo "unknown")
    channel=$(     cat "$CHANNEL_FILE"      2>/dev/null | tr -d '[:space:]' || echo "unknown")
    slot_current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
    slot_previous=$(cat "$DATA_PREV_SLOT"   2>/dev/null | tr -d '[:space:]' || echo "unknown")

    _head "OS"
    _row "Version"   "$version"
    _row "Profile"   "$profile"
    _row "Channel"   "$channel"
    _row "Kernel"    "$(uname -r 2>/dev/null || echo "unknown")"
    _row "Uptime"    "$(uptime -p 2>/dev/null | sed 's/^up //' || echo "unknown")"

    _head "Slots"
    if [[ "$booted" == "$slot_current" ]]; then
        _row "Active"    "@${slot_current}  (booted)"
    else
        _row "Active"    "@${slot_current}  !! mismatch — booted: @${booted}"
        if [[ -f "$DATA_REBOOT_NEEDED" ]]; then
            _rec "Slot mismatch: running @${booted} but current=@${slot_current} — reboot to activate"
        else
            _rec "Slot mismatch: running @${booted} but current=@${slot_current} — run: shani-deploy --rollback"
        fi
    fi
    _row "Fallback"  "@${slot_previous}"
}

_section_hardware() {
    local cpu_model cpu_cores ram_total
    cpu_model=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null \
        | cut -d: -f2 | sed 's/^ *//' || echo "unknown")
    cpu_cores=$(nproc 2>/dev/null || echo "?")
    ram_total=$(free -h 2>/dev/null | awk '/^Mem:/{print $2}' || echo "unknown")

    _head "Hardware"
    _row "CPU"   "${cpu_model} (${cpu_cores} cores)"
    _row "RAM"   "${ram_total} total"
}

_section_boot_health() {
    _head "Boot Health"

    if [[ -f "$DATA_BOOT_OK" ]]; then
        local last_ok; last_ok=$(stat -c '%y' "$DATA_BOOT_OK" 2>/dev/null | cut -d. -f1 || echo "?")
        _row "Last boot"  "OK  ${last_ok}"
    else
        local install_age=0
        if [[ -f /etc/shani-version ]]; then
            local epoch; epoch=$(stat -c '%Y' /etc/shani-version 2>/dev/null || echo "0")
            install_age=$(( ( $(date +%s) - epoch ) / 86400 ))
        fi
        if (( install_age <= 3 )) && [[ ! -f "$DATA_BOOT_FAIL" ]]; then
            _row "Last boot"  "--  no record yet (fresh install)"
        else
            _row "Last boot"  "!!  no successful boot recorded"
            _rec "No successful boot in ${DATA_BOOT_OK} — check bless-boot / boot-success.service"
        fi
    fi

    if [[ -f "$DATA_BOOT_HARD_FAIL" ]]; then
        local s; s=$(cat "$DATA_BOOT_HARD_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "?")
        _row "Hard fail"  "!!  @${s} failed to mount root — run: shani-deploy --rollback"
        _rec "HARD BOOT FAILURE: @${s} could not mount — run: shani-deploy --rollback"
    elif [[ -f "$DATA_BOOT_FAIL" ]]; then
        local s; s=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]' || echo "?")
        _row "Failure"    "!   boot failure recorded for @${s}"
        _rec "Boot failure for @${s} — run: shani-deploy --rollback"
    fi

    if [[ -f "$DATA_BOOT_FAIL_ACKED" ]]; then
        local s; s=$(cat "$DATA_BOOT_FAIL_ACKED" 2>/dev/null | tr -d '[:space:]' || echo "?")
        _row "Acked"      "!   failure acked for @${s} — rollback may not have run"
        _rec "Failure acked for @${s} but markers present — run: shani-deploy --rollback"
    fi
}

_section_deployment() {
    _head "Deployment"

    if [[ -f "$DATA_DEPLOY_PENDING" ]]; then
        _row "State"     "!   deploy pending (interrupted?) — run: shani-deploy --rollback"
    elif [[ -f "$DATA_REBOOT_NEEDED" ]]; then
        local ver; ver=$(cat "$DATA_REBOOT_NEEDED" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
        _row "State"     "!   reboot required to activate v${ver}"
    else
        _row "State"     "OK  clean"
    fi

    if [[ -f /etc/shani-version ]]; then
        local version ver_ts
        version=$(cat /etc/shani-version 2>/dev/null || echo "?")
        ver_ts=$(stat -c '%y' /etc/shani-version 2>/dev/null | cut -d. -f1 || echo "?")
        _row "Installed"  "v${version}  (since ${ver_ts})"
    fi
}

_section_immutability() {
    _head "Immutability"

    local opts; opts=$(findmnt -n -o OPTIONS / 2>/dev/null || true)
    if echo "$opts" | grep -qw ro; then
        _row "Root (/)"   "OK  read-only"
    else
        _row "Root (/)"   "!!  writable — immutability compromised"
        _rec "Root filesystem is writable — reboot may be required"
    fi

    local overlay_upper="/data/overlay/etc/upper"
    if [[ -d "$overlay_upper" ]]; then
        local count; count=$(find "$overlay_upper" -mindepth 1 2>/dev/null | wc -l || echo "0")
        if findmnt -n -t overlay /etc &>/dev/null; then
            _row "/etc"   "OK  overlay active (${count} file(s) modified vs base)"
        else
            _row "/etc"   "!!  overlay NOT mounted — /etc from read-only root"
            _rec "/etc overlay not mounted — check etc-overlay.mount unit"
        fi
        if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 200 )); then
            _row2         "!  large overlay (${count} files) — significant config drift"
            _rec "Large /etc overlay (${count} files) — consider upstreaming to base image"
        elif [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
            local top_dirs
            top_dirs=$(find "$overlay_upper" -mindepth 2 -maxdepth 2 2>/dev/null \
                | sed "s|${overlay_upper}/||" | cut -d/ -f1 \
                | sort | uniq -c | sort -rn | head -5 \
                | awk '{printf "%s(%s) ",$2,$1}')
            [[ -n "$top_dirs" ]] && _row2 "top dirs: ${top_dirs}"
        fi
    else
        _row "/etc"   "!!  overlay upper dir missing — run shanios-tmpfiles-data.service"
        _rec "/etc overlay upper dir missing — run shanios-tmpfiles-data.service"
    fi
}

# uki_booted_bad_ref and hibernate_stale are passed by name (printf -v trick)
_section_secureboot() {
    local booted="$1"
    local uki_booted_bad_ref="$2"
    local hibernate_stale="$3"

    _head "Secure Boot"

    if [[ ! -d /sys/firmware/efi ]]; then
        _row "Status"    "N/A  BIOS/legacy boot"
        return
    fi

    local sb_state; sb_state=$(mokutil --sb-state 2>/dev/null || echo "")
    if [[ "$sb_state" == *"SecureBoot enabled"* ]]; then
        _row "Status"    "OK  enabled"
    else
        _row "Status"    "!!  disabled"
        _rec "Enable Secure Boot in BIOS/UEFI for full boot chain protection"
    fi

    local mok_count
    mok_count=$(mokutil --list-enrolled 2>/dev/null | grep -c 'SHA1 Fingerprint' || echo "0")
    if (( mok_count > 0 )); then
        _row "MOK enrol" "OK  ${mok_count} key(s) enrolled"
    else
        _row "MOK enrol" "!!  no keys enrolled"
        _rec "Enroll MOK: mokutil --import /etc/secureboot/keys/MOK.der --root-pw, then reboot"
    fi

    local mok_key="/etc/secureboot/keys/MOK.key"
    local mok_crt="/etc/secureboot/keys/MOK.crt"
    local mok_der="/etc/secureboot/keys/MOK.der"
    local mok_ok=0
    if [[ -f "$mok_key" && -f "$mok_crt" && -f "$mok_der" ]]; then
        mok_ok=1
        local expiry
        expiry=$(openssl x509 -in "$mok_crt" -noout -enddate 2>/dev/null \
            | sed 's/notAfter=//' || echo "unknown")
        _row "MOK keys"  "OK  present (expires: ${expiry})"
    else
        _row "MOK keys"  "!!  missing"
        _rec "MOK signing keys missing — run: gen-efi configure <slot>"
    fi

    if (( mok_ok )); then
        local uki_ok=0 uki_bad=0 uki_miss=0
        local uki_bad_slots=() uki_miss_slots=()
        for slot in blue green; do
            local uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${slot}.efi"
            if [[ ! -f "$uki" ]]; then
                uki_miss=$(( uki_miss + 1 )); uki_miss_slots+=("$slot")
            elif sbverify --cert "$mok_crt" "$uki" &>/dev/null 2>&1; then
                uki_ok=$(( uki_ok + 1 ))
            else
                uki_bad=$(( uki_bad + 1 )); uki_bad_slots+=("$slot")
                [[ "$slot" == "$booted" ]] && printf -v "$uki_booted_bad_ref" '%s' "1"
            fi
        done

        if (( uki_bad > 0 || uki_miss > 0 )); then
            _row "UKI sigs"  "!!  ${uki_ok}/2 valid, ${uki_bad} invalid, ${uki_miss} missing"
            local fail_slot=""
            [[ -f "$DATA_BOOT_FAIL" ]] && \
                fail_slot=$(cat "$DATA_BOOT_FAIL" 2>/dev/null | tr -d '[:space:]')
            for bad in "${uki_bad_slots[@]}" "${uki_miss_slots[@]}"; do
                if [[ "$bad" == "$booted" ]]; then
                    local also=""
                    (( hibernate_stale )) && also=" (also fixes stale hibernate offset)"
                    _rec "UKI @${bad} (booted) invalid — run: gen-efi configure ${bad}${also}  [AUTOMATABLE]"
                elif [[ -n "$fail_slot" && "$bad" == "$fail_slot" ]]; then
                    _rec "UKI @${bad} invalid (matches boot failure) — fixed by: shani-deploy --rollback"
                else
                    _rec "UKI @${bad} invalid — run: shani-deploy --rollback or a fresh deploy"
                fi
            done
        else
            _row "UKI sigs"  "OK  ${uki_ok}/2 valid"
        fi
    else
        _row "UKI sigs"  "--  cannot verify (MOK cert missing)"
    fi
}

_section_kernel_security() {
    local sb_active="$1"   # "yes" if Secure Boot is enabled

    _head "Kernel Security"

    local active_lsms
    active_lsms=$(cat /sys/kernel/security/lsm 2>/dev/null | tr ',' ' ' || echo "unknown")
    _row "LSMs"     "$active_lsms"

    local ima_compiled=0
    zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_IMA=y' && ima_compiled=1

    local expected=(landlock lockdown yama integrity apparmor bpf)
    local missing_lsms=() missing_build=()
    for lsm in "${expected[@]}"; do
        if ! echo "$active_lsms" | grep -qw "$lsm"; then
            [[ "$lsm" == "integrity" && $ima_compiled -eq 0 ]] \
                && missing_build+=("$lsm") || missing_lsms+=("$lsm")
        fi
    done

    local total='6'
    local active=$(( ${total} - ${#missing_lsms[@]} - ${#missing_build[@]} ))
    if [[ ${#missing_lsms[@]} -eq 0 && ${#missing_build[@]} -eq 0 ]]; then
        _row "LSM check"  "OK  all ${total} LSMs active"
    elif [[ ${#missing_lsms[@]} -eq 0 ]]; then
        _row "LSM check"  "--  ${active}/${total} active (${missing_build[*]} not compiled in)"
    else
        _row "LSM check"  "!!  missing: ${missing_lsms[*]}"
        _rec "LSMs not active: ${missing_lsms[*]} — check kernel cmdline lsm= parameter"
    fi

    if [[ -d /sys/kernel/security/ima ]]; then
        local rules; rules=$(wc -l < /sys/kernel/security/ima/policy 2>/dev/null || echo "0")
        _row "IMA"       "OK  active (${rules} policy rules)"
    elif echo "$active_lsms" | grep -qw integrity; then
        _row "IMA"       "OK  active (integrity LSM loaded)"
    elif (( ima_compiled == 0 )); then
        _row "IMA"       "--  not compiled in (CONFIG_IMA=n)"
    else
        _row "IMA"       "!!  not active despite CONFIG_IMA=y — add 'integrity' to lsm= cmdline"
        _rec "IMA compiled in but not active — add 'integrity' to lsm= kernel cmdline"
    fi

    local lockdown
    lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null \
        | grep -o '\[.*\]' | tr -d '[]' || echo "none")
    if [[ "$lockdown" == "none" ]]; then
        if [[ "$sb_active" == "yes" ]]; then
            _row "Lockdown"  "!   none (Secure Boot active — consider lockdown=confidentiality)"
            _rec "Kernel lockdown is 'none' despite Secure Boot active"
        else
            _row "Lockdown"  "--  none (expected without Secure Boot)"
        fi
    else
        _row "Lockdown"  "OK  ${lockdown}"
    fi

    # Sysctl hardening table: key  target  cmp(min|max|eq|info)  label
    local sysctl_table=(
        "kernel.kptr_restrict"               "1"  "min"  "hide kernel pointers"
        "kernel.dmesg_restrict"              "1"  "eq"   "restrict dmesg to root"
        "kernel.unprivileged_bpf_disabled"   "1"  "min"  "disable unprivileged BPF"
        "net.core.bpf_jit_harden"            "2"  "min"  "harden BPF JIT"
        "kernel.yama.ptrace_scope"           "1"  "min"  "restrict ptrace"
        "net.ipv4.conf.all.accept_redirects" "0"  "max"  "ignore IPv4 ICMP redirects"
        "net.ipv6.conf.all.accept_redirects" "0"  "max"  "ignore IPv6 ICMP redirects"
        "net.ipv4.tcp_syncookies"            "1"  "eq"   "TCP SYN cookies"
        "net.ipv4.conf.all.rp_filter"        "1"  "info" "reverse path filter"
        "kernel.unprivileged_userns_clone"   "0"  "info" "restrict user namespaces"
    )
    local sc_ok=0 sc_total=0 sc_warn=() sc_info=()
    local i=0
    while (( i < ${#sysctl_table[@]} )); do
        local key="${sysctl_table[$i]}"       target="${sysctl_table[$((i+1))]}"
        local cmp="${sysctl_table[$((i+2))]}" label="${sysctl_table[$((i+3))]}"
        i=$(( i + 4 ))
        local actual; actual=$(sysctl -n "$key" 2>/dev/null || echo "")
        [[ -z "$actual" ]] && continue
        if [[ "$cmp" == "info" ]]; then
            [[ "$actual" != "$target" ]] && sc_info+=("${key}=${actual}  (recommended ${target} — ${label})")
            continue
        fi
        sc_total=$(( sc_total + 1 ))
        local pass=0
        case "$cmp" in
            min) [[ "$actual" =~ ^[0-9]+$ ]] && (( actual >= target )) && pass=1 ;;
            max) [[ "$actual" =~ ^[0-9]+$ ]] && (( actual <= target )) && pass=1 ;;
            eq)  [[ "$actual" == "$target" ]] && pass=1 ;;
        esac
        if (( pass )); then
            sc_ok=$(( sc_ok + 1 ))
        else
            sc_warn+=("${key}=${actual}  (want ${cmp} ${target} — ${label})")
        fi
    done
    if [[ ${#sc_warn[@]} -eq 0 ]]; then
        _row "Sysctl"    "OK  ${sc_ok}/${sc_total} hardening keys correct"
    else
        _row "Sysctl"    "!   ${sc_ok}/${sc_total} correct"
        for w in "${sc_warn[@]}"; do _row2 "!  $w"; done
        _rec "Sysctl hardening gaps — check /etc/sysctl.d/"
    fi
    for info in "${sc_info[@]}"; do _row2 "--  $info"; done

    local usb_auth
    usb_auth=$(find /sys/bus/usb/devices -name 'authorized_default' -maxdepth 2 \
        -exec cat {} \; 2>/dev/null | head -1 || echo "")
    if [[ "$usb_auth" == "0" ]]; then
        _row "USB auth"  "OK  new devices require authorisation"
    elif [[ "$usb_auth" == "1" ]]; then
        _row "USB auth"  "--  all USB devices auto-authorised (default)"
    fi

    local bad_mods=()
    for mod in mei mei_me pcspkr; do
        lsmod 2>/dev/null | grep -qw "$mod" && bad_mods+=("$mod")
    done
    if [[ ${#bad_mods[@]} -eq 0 ]]; then
        _row "Blacklist"  "OK  mei/mei_me/pcspkr not loaded"
    else
        _row "Blacklist"  "!   loaded but should be blacklisted: ${bad_mods[*]}"
        _rec "Modules ${bad_mods[*]} should be blacklisted — check /etc/modprobe.d/"
    fi

    local shadow_perms
    shadow_perms=$(stat -c '%a %U %G' /etc/shadow 2>/dev/null || echo "unknown")
    if [[ "$shadow_perms" =~ ^(640\ root\ shadow|600\ root\ root)$ ]]; then
        _row "Shadow"    "OK  ${shadow_perms}"
    elif [[ "$shadow_perms" != "unknown" ]]; then
        _row "Shadow"    "!   unexpected: ${shadow_perms}  (expected 640 root shadow)"
        _rec "/etc/shadow permissions ${shadow_perms} — expected 640 root shadow"
    fi
}

_section_encryption() {
    _head "Encryption"

    if [[ ! -e "/dev/mapper/${ROOTLABEL}" ]]; then
        _row "LUKS"      "--  not encrypted"
        _rec "Disk not encrypted — re-install with LUKS2 for data protection"
        return
    fi

    _row "LUKS"      "OK  active (/dev/mapper/${ROOTLABEL})"
    local underlying
    underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
        | sed -n 's/^ *device: //p' || true)
    [[ -z "$underlying" ]] && return

    local uuid; uuid=$(cryptsetup luksUUID "$underlying" 2>/dev/null || echo "unknown")
    _row "Device"    "$underlying"
    _row "UUID"      "$uuid"

    local dump; dump=$(cryptsetup luksDump "$underlying" 2>/dev/null || true)
    local cipher; cipher=$(echo "$dump" | awk '/cipher:/{print $2;exit}')
    local kdf;    kdf=$(   echo "$dump" | awk '/PBKDF:/{print $2;exit}')
    _row "Cipher"    "${cipher:-unknown}"
    if [[ "$kdf" == "argon2id" ]]; then
        _row "KDF"   "OK  ${kdf} (strong)"
    else
        _row "KDF"   "!   ${kdf:-unknown}  (argon2id recommended)"
        _rec "LUKS KDF is ${kdf:-unknown} — consider re-encrypting with argon2id"
    fi

    local enroll_out; enroll_out=$(systemd-cryptenroll "$underlying" 2>/dev/null || true)
    local slots; slots=$(echo "$enroll_out" | grep -c '.' || echo "1")
    slots=$(( slots > 0 ? slots - 1 : 0 ))
    _row "Keyslots"  "$slots active"

    _head "TPM2"
    if [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
        local tpm_info
        tpm_info=$(systemd-cryptenroll --tpm2-device=list 2>/dev/null \
            | grep -v '^PATH' | tail -1 || true)
        _row "Hardware"  "OK  present${tpm_info:+  (${tpm_info})}"
        if echo "$enroll_out" | grep -q "tpm2"; then
            _row "Enrolled"  "OK  auto-unlock active"
        else
            _row "Enrolled"  "!!  not enrolled"
            _rec "TPM2 not enrolled for auto-unlock — run: gen-efi enroll-tpm2  [AUTOMATABLE]"
        fi
    else
        _row "Hardware"  "!!  not found or disabled in BIOS"
    fi

    local keyfile="/etc/cryptsetup-keys.d/${ROOTLABEL}.bin"
    if [[ -f "$keyfile" ]]; then
        _row "Keyfile"   "OK  present (${keyfile})"
    else
        _row "Keyfile"   "--  not used (PIN/passphrase)"
    fi
}

_section_security_services() {
    _head "Security Services"

    if command -v aa-status &>/dev/null; then
        if aa-status --enabled >/dev/null 2>&1; then
            local n; n=$(aa-status 2>/dev/null | awk '/enforce mode/{print $1}' || echo "?")
            _row "AppArmor"   "OK  ${n} profiles enforcing"
        else
            _row "AppArmor"   "!!  not enforcing"
            _rec "AppArmor not enforcing — run: systemctl enable --now apparmor  [AUTOMATABLE]"
        fi
    else
        _row "AppArmor"   "--  aa-status not found"
    fi

    if command -v firewall-cmd &>/dev/null; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            local zone; zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
            _row "Firewall"   "OK  active (zone: ${zone})"
        else
            _row "Firewall"   "!!  firewalld not running"
            _rec "Firewall not active — run: systemctl enable --now firewalld  [AUTOMATABLE]"
        fi
    else
        _row "Firewall"   "--  not installed"
    fi

    if command -v fail2ban-client &>/dev/null; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            local jails
            jails=$(fail2ban-client status 2>/dev/null \
                | awk -F',' '/Jail list/{gsub(/[[:space:]]/,"",$0);print NF}' || echo "?")
            _row "fail2ban"   "OK  ${jails} jail(s) active"
        else
            _row "fail2ban"   "!!  not running"
            _rec "fail2ban not active — run: systemctl enable --now fail2ban  [AUTOMATABLE]"
        fi
    else
        _row "fail2ban"   "--  not installed"
    fi

    local root_st; root_st=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "unknown")
    case "$root_st" in
        L|LK) _row "Root acct"  "OK  locked" ;;
        P)    _row "Root acct"  "!   has a password (locked root recommended)"
              _rec "Root has a password — lock: passwd -l root  [AUTOMATABLE]" ;;
        *)    _row "Root acct"  "--  status unknown" ;;
    esac

    if [[ -f /etc/ssh/sshd_config ]] || [[ -d /etc/ssh/sshd_config.d ]]; then
        local ssh_root
        ssh_root=$(grep -rh '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ \
            2>/dev/null | tail -1 | awk '{print $2}' || echo "")
        if [[ -z "$ssh_root" ]]; then
            local ssh_ver; ssh_ver=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+' | head -1 || echo "0")
            if (( ssh_ver >= 8 )); then
                _row "SSH root"   "OK  default key-only (OpenSSH ${ssh_ver}.x)"
            else
                _row "SSH root"   "!   default may allow login (OpenSSH <8)"
                _rec "Set PermitRootLogin no in sshd_config (OpenSSH <8 default risky)"
            fi
        else
            case "$ssh_root" in
                no)                        _row "SSH root"  "OK  disabled" ;;
                prohibit-password|without-password) _row "SSH root"  "OK  key-only" ;;
                yes)                       _row "SSH root"  "!!  enabled (password login allowed)"
                                           _rec "SSH root password login enabled — disable in sshd_config  [AUTOMATABLE]" ;;
                *)                         _row "SSH root"  "!   unknown value: ${ssh_root}" ;;
            esac
        fi
        local ssh_port
        ssh_port=$(grep -rh '^Port ' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
            | tail -1 | awk '{print $2}' || echo "22")
        _row "SSH port"   "${ssh_port:-22}"
    fi
}

_section_disk() {
    local booted="$1"
    local hibernate_stale_ref="$2"
    local uki_booted_bad="$3"

    _head "Disk"

    local root_disk
    root_disk=$(lsblk -no PKNAME \
        "$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/\[.*//')" 2>/dev/null | head -1 || true)
    [[ -z "$root_disk" ]] && \
        root_disk=$(lsblk -no PKNAME "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null | head -1 || echo "")

    if [[ -n "$root_disk" ]]; then
        local disk_model disk_size disk_type
        disk_model=$(lsblk -dno MODEL "/dev/${root_disk}" 2>/dev/null \
            | sed 's/[[:space:]]*$//' || echo "?")
        disk_size=$(lsblk -dno SIZE  "/dev/${root_disk}" 2>/dev/null || echo "?")
        disk_type=$(lsblk -dno ROTA  "/dev/${root_disk}" 2>/dev/null || echo "1")
        [[ "$disk_type" == "0" ]] && disk_type="SSD/NVMe" || disk_type="HDD"
        _row "Device"    "/dev/${root_disk}  ${disk_model}  (${disk_size}, ${disk_type})"

        if command -v smartctl &>/dev/null; then
            local smart
            smart=$(smartctl -H "/dev/${root_disk}" 2>/dev/null \
                | awk '/overall-health|result/{print $NF}' | head -1 || echo "")
            if [[ "$smart" == "PASSED" ]]; then
                _row "SMART"     "OK  PASSED"
            elif [[ -n "$smart" ]]; then
                _row "SMART"     "!!  ${smart}"
                _rec "SMART health ${smart} for /dev/${root_disk} — back up data immediately"
            else
                _row "SMART"     "--  not available (NVMe may need nvme-cli)"
            fi
        else
            _row "SMART"     "--  smartctl not installed"
        fi
    else
        _row "Device"    "--  could not detect root disk"
    fi

    # Swap & hibernate
    local swap_total swap_used
    swap_total=$(free -h 2>/dev/null | awk '/^Swap:/{print $2}' || echo "0")
    swap_used=$(  free -h 2>/dev/null | awk '/^Swap:/{print $3}' || echo "0")

    if [[ "$swap_total" == "0" || "$swap_total" == "0B" ]]; then
        _row "Swap"      "!   none active (hibernate unavailable)"
    else
        _row "Swap"      "OK  ${swap_used} / ${swap_total}"
        local has_zram=0 swapfile=""
        swapon --show=NAME --noheadings 2>/dev/null | grep -q zram && has_zram=1
        swapfile=$(_find_swapfile)
        local has_swapfile=0; [[ -n "$swapfile" ]] && has_swapfile=1

        if (( has_zram && has_swapfile )); then
            _row2 "zram + swapfile (hibernate capable)"
        elif (( has_zram )); then
            _row2 "zram only — hibernate not available"
        elif (( has_swapfile )); then
            _row2 "swapfile: $swapfile"
        fi

        if (( has_swapfile )); then
            local cmdline; cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
            local resume_ok=0 offset_ok=0
            echo "$cmdline" | grep -q 'resume='        && resume_ok=1
            echo "$cmdline" | grep -q 'resume_offset=' && offset_ok=1

            if (( resume_ok && offset_ok )); then
                local configured; configured=$(echo "$cmdline" \
                    | grep -o 'resume_offset=[^ ]*' | cut -d= -f2)
                local actual; actual=$(_swapfile_offset "$swapfile")
                if [[ -n "$actual" && "$actual" == "$configured" ]]; then
                    _row "Hibernate"  "OK  resume_offset=${configured} correct"
                elif [[ -n "$actual" && "$actual" != "$configured" ]]; then
                    printf -v "$hibernate_stale_ref" '%s' "1"
                    _row "Hibernate"  "!!  resume_offset stale"
                    _row2             "    cmdline=${configured}, actual=${actual}"
                    _row2             "    regenerate UKI before hibernating"
                    if (( ! uki_booted_bad )); then
                        _rec "Hibernate offset stale — run: gen-efi configure ${booted}  [AUTOMATABLE]"
                    fi
                else
                    _row "Hibernate"  "OK  resume_offset present (offset unverifiable)"
                fi
            elif (( ! resume_ok )); then
                _row "Hibernate"  "!!  swapfile present but resume= missing from cmdline"
                _rec "Swapfile present but resume= missing — run: gen-efi configure ${booted}  [AUTOMATABLE]"
            fi
        fi
    fi

    local oom
    oom=$(journalctl -k -b 0 --no-pager -q 2>/dev/null \
        | grep -c 'Out of memory\|oom_kill_process\|Killed process' || echo "0")
    if [[ "$oom" =~ ^[0-9]+$ ]] && (( oom > 0 )); then
        _row "OOM kills"  "!   ${oom} event(s) this boot"
        _rec "${oom} OOM kill(s) this boot — consider more RAM or swap"
    else
        _row "OOM kills"  "OK  none this boot"
    fi
}

_section_storage() {
    _head "Storage"

    local free_kb
    free_kb=$(df --output=avail /data 2>/dev/null | tail -1 | tr -d '[:space:]')
    if [[ "$free_kb" =~ ^[0-9]+$ ]]; then
        _row "Free"       "$(( free_kb / 1024 )) MB  (/data)"
    else
        _row "Free"       "--  /data not mounted"
    fi

    local btrfs_free
    btrfs_free=$(btrfs filesystem usage -b / 2>/dev/null \
        | awk '/Free \(estimated\):/{printf "%.1f GB",$3/1073741824}' || echo "unknown")
    _row "Btrfs free"  "$btrfs_free"

    local backups
    backups=$(btrfs subvolume list / 2>/dev/null \
        | grep -cE '(blue|green)_backup_' || echo "0")
    _row "Backups"     "${backups} snapshot(s)"

    local scrub_st scrub_res
    scrub_st=$(btrfs scrub status / 2>/dev/null || true)
    scrub_res=$(echo "$scrub_st" | awk '/Status:/{print $2}' | head -1 || echo "")
    local scrub_timer
    scrub_timer=$(systemctl is-active btrfs-scrub.timer 2>/dev/null || echo "inactive")

    if [[ "$scrub_timer" == "active" ]]; then
        _row "Scrub tmr"  "OK  active"
    else
        _row "Scrub tmr"  "!!  btrfs-scrub.timer not active"
        _rec "btrfs-scrub.timer not active — run: systemctl enable --now btrfs-scrub.timer  [AUTOMATABLE]"
    fi

    case "$scrub_res" in
        finished)
            local re ce co
            re=$(  echo "$scrub_st" | awk '/read_errors:/{print $2}'      | head -1 || echo "0")
            ce=$(  echo "$scrub_st" | awk '/csum_errors:/{print $2}'      | head -1 || echo "0")
            co=$(  echo "$scrub_st" | awk '/corrected_errors:/{print $2}' | head -1 || echo "0")
            if [[ "${re:-0}" != "0" || "${ce:-0}" != "0" || "${co:-0}" != "0" ]]; then
                _row "Scrub"    "!!  errors: read=${re} csum=${ce} corrected=${co}"
                _rec "Btrfs scrub found errors — investigate: btrfs scrub status /"
            else
                _row "Scrub"    "OK  last run clean"
            fi ;;
        running)  _row "Scrub"    "->  in progress" ;;
        "")        _row "Scrub"    "--  no scrub recorded yet" ;;
        *)         _row "Scrub"    "!   status: ${scrub_res}" ;;
    esac

    local t_ok=() t_bad=()
    for name in balance defrag trim; do
        local unit="btrfs-${name}.timer"
        [[ "$(systemctl is-active "$unit" 2>/dev/null)" == "active" ]] \
            && t_ok+=("$name") || t_bad+=("$name")
    done
    [[ ${#t_ok[@]} -gt 0 ]] && _row "Maint tmrs"  "OK  active: ${t_ok[*]}"
    if [[ ${#t_bad[@]} -gt 0 ]]; then
        _row2 "!!  inactive: ${t_bad[*]}"
        local units; units=$(printf 'btrfs-%s.timer ' "${t_bad[@]}")
        _rec "Btrfs timers inactive (${t_bad[*]}) — run: systemctl enable --now ${units% }  [AUTOMATABLE]"
    fi
    _row2 "-> full analysis: shani-health --storage-info"
}

_section_services() {
    _head "Services"

    local bees_uuid
    bees_uuid=$(blkid -s UUID -o value "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null || true)
    [[ -z "$bees_uuid" && -e "/dev/mapper/${ROOTLABEL}" ]] && \
        bees_uuid=$(blkid -s UUID -o value "/dev/mapper/${ROOTLABEL}" 2>/dev/null || true)
    if [[ -n "$bees_uuid" ]]; then
        local bees_unit="beesd@${bees_uuid}"
        local bees_st; bees_st=$(systemctl is-active "$bees_unit" 2>/dev/null || echo "inactive")
        if [[ "$bees_st" == "active" ]]; then
            _row "bees"      "OK  running"
        else
            _row "bees"      "!!  not running (${bees_st})"
            if [[ ! -f "/etc/bees/${bees_uuid}.conf" ]]; then
                _rec "bees not configured — run beesd-setup first, then enable ${bees_unit}"
            else
                _rec "bees not running — run: systemctl enable --now ${bees_unit}  [AUTOMATABLE]"
            fi
        fi
    else
        _row "bees"      "--  could not determine Btrfs UUID"
    fi

    systemctl is-active --quiet fwupd 2>/dev/null \
        && _row "fwupd"   "OK  running" \
        || _row "fwupd"   "--  not running (on-demand)"

    systemctl is-active --quiet NetworkManager 2>/dev/null \
        && _row "Network"  "OK  NetworkManager active" \
        || _row "Network"  "!   NetworkManager not running"

    local failed_units=()
    mapfile -t failed_units < <(
        systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null \
            | awk '{print $1}' || true)
    if [[ ${#failed_units[@]} -eq 0 ]]; then
        _row "Units"     "OK  no failed systemd units"
    else
        _row "Units"     "!!  ${#failed_units[@]} failed: ${failed_units[*]}"
        _rec "Failed units: ${failed_units[*]} — run: systemctl status <unit>"
    fi
}

_section_boot_entries() {
    _head "Boot Entries"

    if ! mountpoint -q "$ESP" 2>/dev/null; then
        _row "ESP"       "!!  could not mount — boot entries unavailable"
        return
    fi

    local loader_conf="$ESP/loader/loader.conf"
    local def; def=$(grep '^default' "$loader_conf" 2>/dev/null | awk '{print $2}' || echo "unknown")
    _row "Default"   "$def"

    local entries
    entries=$(ls "$ESP/loader/entries/"*.conf 2>/dev/null \
        | xargs -I{} basename {} .conf | tr '\n' '  ' || echo "none")
    _row "Entries"   "$entries"

    local orphans=()
    for slot in blue green; do
        local plain="$ESP/loader/entries/${OS_NAME}-${slot}.conf"
        local tries; tries=$(ls "$ESP/loader/entries/${OS_NAME}-${slot}"+*.conf \
            2>/dev/null | head -1 || echo "")
        [[ -f "$plain" && -n "$tries" ]] && orphans+=("${OS_NAME}-${slot}.conf")
    done
    if [[ ${#orphans[@]} -gt 0 ]]; then
        _row "Orphans"   "!   ${orphans[*]}"
        _rec "Orphaned boot entries (${orphans[*]}) — run: shani-health --fix-security  [AUTOMATABLE]"
    fi

    local editor; editor=$(grep '^editor' "$loader_conf" 2>/dev/null \
        | awk '{print $2}' || echo "not set")
    if [[ "$editor" == "0" ]]; then
        _row "Editor"    "OK  disabled"
    else
        _row "Editor"    "!!  not disabled (cmdline editable at boot)"
        _rec "systemd-boot editor not disabled — add 'editor 0' to loader.conf  [AUTOMATABLE]"
    fi
}

_section_firmware() {
    _head "Firmware"

    if ! command -v fwupdmgr &>/dev/null; then
        _row "fwupd"     "--  not available"
        return
    fi

    local fw_out; fw_out=$(fwupdmgr get-updates --offline 2>/dev/null || true)
    if echo "$fw_out" | grep -q 'GUID\|Version'; then
        local n; n=$(echo "$fw_out" | grep -c 'GUID' || echo "1")
        _row "Updates"   "!   ${n} update(s) available — run: fwupdmgr update"
        _rec "${n} firmware update(s) available — run: fwupdmgr update"
    else
        _row "Updates"   "OK  up to date (cached)"
    fi
}

_section_system_health() {
    _head "System Health"

    if command -v timedatectl &>/dev/null; then
        local td_out ntp_active ntp_synced tsync
        td_out=$(timedatectl show 2>/dev/null || true)
        ntp_active=$(echo "$td_out" | awk -F= '/^NTP=/{print $2}'              | tr -d '[:space:]')
        ntp_synced=$(echo "$td_out" | awk -F= '/^NTPSynchronized=/{print $2}'  | tr -d '[:space:]')
        tsync=$(     systemctl is-active systemd-timesyncd 2>/dev/null || echo "inactive")

        if [[ "$ntp_synced" == "yes" && "$tsync" == "active" ]]; then
            _row "timesyncd"  "OK  synchronised"
        elif [[ "$ntp_active" == "yes" && "$tsync" == "active" ]]; then
            _row "timesyncd"  "!   running but not yet synchronised"
        elif [[ "$ntp_active" == "yes" ]]; then
            _row "timesyncd"  "!!  NTP enabled but service is ${tsync}"
            _rec "systemd-timesyncd not running — run: systemctl enable --now systemd-timesyncd  [AUTOMATABLE]"
        else
            _row "timesyncd"  "!!  disabled"
            _rec "NTP disabled — run: systemctl enable --now systemd-timesyncd && timedatectl set-ntp true  [AUTOMATABLE]"
        fi
    else
        _row "timesyncd"  "--  timedatectl not available"
    fi

    local running installed
    running=$(uname -r 2>/dev/null || echo "")
    installed=$(find /usr/lib/modules/ -maxdepth 1 -mindepth 1 -type d 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^/]*$' | sort -V | tail -1 || echo "")
    if [[ -n "$running" && -n "$installed" ]]; then
        if [[ "$running" == "$installed" ]]; then
            _row "Kernel"     "OK  ${running}"
        else
            _row "Kernel"     "!   running ${running}  /  installed ${installed}"
            _rec "Kernel mismatch: running ${running}, installed ${installed} — reboot"
        fi
    fi

    local j_err j_crit
    j_err=$( journalctl -b 0 -p err  --no-pager -q 2>/dev/null | wc -l || echo "0")
    j_crit=$(journalctl -b 0 -p crit --no-pager -q 2>/dev/null | wc -l || echo "0")
    if [[ "$j_crit" =~ ^[0-9]+$ ]] && (( j_crit > 0 )); then
        _row "Journal"    "!!  ${j_err} error(s), ${j_crit} critical — journalctl -b 0 -p crit"
        _rec "${j_crit} critical journal message(s) this boot — run: journalctl -b 0 -p crit"
    elif [[ "$j_err" =~ ^[0-9]+$ ]] && (( j_err > 20 )); then
        _row "Journal"    "!   ${j_err} error(s) this boot"
    else
        _row "Journal"    "OK  ${j_err:-0} error(s) (normal range)"
    fi

    if command -v systemd-analyze &>/dev/null; then
        local bt bt_sec
        bt=$(systemd-analyze 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+s' | tail -1 || echo "")
        if [[ -n "$bt" ]]; then
            bt_sec=$(echo "$bt" | grep -oE '^[0-9]+' || echo "0")
            if (( bt_sec >= 30 )); then
                _row "Boot time"  "!   ${bt}  (slow — run: systemd-analyze blame)"
            else
                _row "Boot time"  "OK  ${bt}"
            fi
        fi
    fi
}

_section_users() {
    _head "Users"

    local login_users=()
    while IFS=: read -r name _ uid _ _ _ shell; do
        [[ "$uid" -ge 1000 ]] 2>/dev/null || continue
        [[ "$name" == "nobody" ]] && continue
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        login_users+=("$name")
    done < /etc/passwd 2>/dev/null || true
    _row "Login"     "${login_users[*]:-none detected}"

    local wheel_line wheel_members=()
    wheel_line=$(getent group wheel 2>/dev/null || grep '^wheel:' /etc/group 2>/dev/null || true)
    [[ -n "$wheel_line" ]] && IFS=',' read -ra wheel_members <<< "${wheel_line##*:}"
    if [[ ${#wheel_members[@]} -gt 0 && -n "${wheel_members[0]}" ]]; then
        _row "Wheel"     "${wheel_members[*]}"
    else
        _row "Wheel"     "--  no members"
    fi

    local nopasswd=()
    while IFS= read -r line; do
        echo "$line" | grep -qE 'NOPASSWD.*ALL\s*$|NOPASSWD.*ALL\)' && nopasswd+=("$line")
    done < <(grep -rh NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
        | grep -v '^[[:space:]]*#' || true)
    if [[ ${#nopasswd[@]} -gt 0 ]]; then
        _row "NOPASSWD"  "!   passwordless sudo entries found:"
        for e in "${nopasswd[@]}"; do _row2 "$(echo "$e" | xargs)"; done
        _rec "Passwordless sudo (NOPASSWD ALL) found — review /etc/sudoers.d/"
    else
        _row "NOPASSWD"  "OK  no unrestricted passwordless sudo"
    fi
}

_section_realtime() {
    _head "Realtime"

    local rtkit_st; rtkit_st=$(systemctl is-active rtkit-daemon 2>/dev/null || echo "inactive")
    if [[ "$rtkit_st" == "active" ]]; then
        _row "rtkit"     "OK  running"
    else
        _row "rtkit"     "!!  ${rtkit_st}"
        if command -v pipewire &>/dev/null || command -v pulseaudio &>/dev/null; then
            _rec "rtkit-daemon not running — PipeWire RT unavailable: systemctl enable --now rtkit-daemon  [AUTOMATABLE]"
        fi
    fi

    local rt_line rt_members=()
    rt_line=$(getent group realtime 2>/dev/null || grep '^realtime:' /etc/group 2>/dev/null || true)
    if [[ -z "$rt_line" ]]; then
        _row "rt group"  "!!  'realtime' group missing — install realtime-privileges"
        _rec "'realtime' group missing — install: pacman -S realtime-privileges"
    else
        IFS=',' read -ra rt_members <<< "${rt_line##*:}"
        local rt_display; rt_display=$(echo "${rt_members[*]}" | tr -s ' ' | xargs)
        if [[ -n "$rt_display" ]]; then
            _row "rt group"  "OK  members: ${rt_display}"
        else
            _row "rt group"  "!   group exists but is empty"
            _rec "'realtime' group empty — add users: usermod -aG realtime <user>"
        fi
    fi

    local login_users=()
    while IFS=: read -r name _ uid _ _ _ shell; do
        [[ "$uid" -ge 1000 ]] 2>/dev/null || continue
        [[ "$name" == "nobody" ]] && continue
        [[ "$shell" == */nologin || "$shell" == */false ]] && continue
        login_users+=("$name")
    done < /etc/passwd 2>/dev/null || true

    local missing_rt=()
    for u in "${login_users[@]}"; do
        id -nG "$u" 2>/dev/null | grep -qw realtime || missing_rt+=("$u")
    done
    if [[ ${#missing_rt[@]} -gt 0 ]]; then
        _row "RT access"  "!   not in realtime group: ${missing_rt[*]}"
        _rec "User(s) ${missing_rt[*]} not in 'realtime' — add to /etc/shani-extra-groups or: usermod -aG realtime <user>"
    else
        [[ ${#login_users[@]} -gt 0 ]] && _row "RT access"  "OK  all login users in realtime group"
    fi
}

###############################################################################
### system_info — master status report                                       ###
###############################################################################

system_info() {
    _recs_reset

    local _esp_mounted=0
    _esp_mount

    local booted; booted=$(_get_booted_subvol)
    local uki_booted_bad="0"
    local hibernate_stale="0"

    # Pre-check hibernate offset — result shared between _section_secureboot and _section_disk
    local swapfile; swapfile=$(_find_swapfile)
    if [[ -n "$swapfile" ]] && command -v btrfs &>/dev/null; then
        local a_off; a_off=$(_swapfile_offset "$swapfile")
        local c_off; c_off=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2 || echo "")
        [[ -n "$a_off" && -n "$c_off" && "$a_off" != "$c_off" ]] && hibernate_stale="1"
    fi

    local sb_active="no"
    [[ -d /sys/firmware/efi ]] && \
        [[ "$(mokutil --sb-state 2>/dev/null)" == *"SecureBoot enabled"* ]] && sb_active="yes"

    echo ""
    echo "  +----------------------------------------------+"
    printf "  |  %-44s|\n" "ShaniOS System Status"
    printf "  |  %-44s|\n" "shani-health v${SCRIPT_VERSION}  $(date '+%Y-%m-%d %H:%M')"
    echo "  +----------------------------------------------+"

    _section_os_slots          "$booted"
    _section_hardware
    _section_boot_health
    _section_deployment
    _section_immutability
    _section_secureboot        "$booted" uki_booted_bad "$hibernate_stale"
    _section_kernel_security   "$sb_active"
    _section_encryption
    _section_security_services
    _section_disk              "$booted" hibernate_stale "$uki_booted_bad"
    _section_storage
    _section_services
    _section_boot_entries
    _section_firmware
    _section_system_health
    _section_users
    _section_realtime

    # Summary
    echo ""
    if [[ ${#_RECS[@]} -eq 0 ]]; then
        echo "  OK  No issues found"
    else
        echo "  Recommendations"
        local i=1
        for rec in "${_RECS[@]}"; do
            printf "    %2d. %s\n" "$i" "$rec"
            i=$(( i + 1 ))
        done
        echo ""
        echo "  Items marked [AUTOMATABLE] can be fixed by: shani-health --fix-security"
    fi
    echo ""

    _esp_umount
}

###############################################################################
### fix_security                                                             ###
###############################################################################

fix_security() {
    _log_section "Security Auto-Fix"
    local fixed=0 failed=0

    # Internal helper: run a fix, updating counters
    _apply_fix() {
        local desc="$1"; shift
        _log "Fixing: ${desc}..."
        if "$@" 2>/dev/null; then
            _log_ok "${desc}"
            fixed=$(( fixed + 1 ))
        else
            _log_warn "${desc} — FAILED"
            failed=$(( failed + 1 ))
        fi
    }

    # AppArmor
    command -v aa-status &>/dev/null && ! aa-status --enabled >/dev/null 2>&1 && \
        _apply_fix "Enable AppArmor"  systemctl enable --now apparmor

    # Firewall
    command -v firewall-cmd &>/dev/null && ! systemctl is-active --quiet firewalld 2>/dev/null && \
        _apply_fix "Enable firewalld"  systemctl enable --now firewalld

    # fail2ban
    command -v fail2ban-client &>/dev/null && ! systemctl is-active --quiet fail2ban 2>/dev/null && \
        _apply_fix "Enable fail2ban"  systemctl enable --now fail2ban

    # Lock root
    local root_st; root_st=$(passwd -S root 2>/dev/null | awk '{print $2}' || echo "")
    [[ "$root_st" == "P" ]] && _apply_fix "Lock root account"  passwd -l root

    # SSH root login
    if [[ -f /etc/ssh/sshd_config ]]; then
        local ssh_root
        ssh_root=$(grep -rh '^PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ \
            2>/dev/null | tail -1 | awk '{print $2}' || echo "")
        if [[ "$ssh_root" == "yes" ]]; then
            if sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null \
                && systemctl reload sshd 2>/dev/null; then
                _log_ok "SSH root login disabled"
                fixed=$(( fixed + 1 ))
            else
                _log_warn "Failed to disable SSH root login"
                failed=$(( failed + 1 ))
            fi
        fi
    fi

    # systemd-boot editor + orphaned entries
    local _esp_mounted=0
    _esp_mount
    if mountpoint -q "$ESP" 2>/dev/null; then
        local loader_conf="$ESP/loader/loader.conf"
        local editor_val
        editor_val=$(grep '^editor' "$loader_conf" 2>/dev/null | awk '{print $2}' || echo "not set")
        if [[ "$editor_val" != "0" ]]; then
            if grep -q '^editor' "$loader_conf" 2>/dev/null; then
                sed -i 's/^editor .*/editor 0/' "$loader_conf"
            else
                echo "editor 0" >> "$loader_conf"
            fi
            _log_ok "systemd-boot editor disabled"
            fixed=$(( fixed + 1 ))
        fi

        for slot in blue green; do
            local plain="$ESP/loader/entries/${OS_NAME}-${slot}.conf"
            local tries; tries=$(ls "$ESP/loader/entries/${OS_NAME}-${slot}"+*.conf \
                2>/dev/null | head -1 || echo "")
            if [[ -f "$plain" && -n "$tries" ]]; then
                rm -f "$plain" 2>/dev/null && \
                    { _log_ok "Removed orphaned entry: $(basename "$plain")"; fixed=$(( fixed + 1 )); } || \
                    { _log_warn "Failed to remove: $(basename "$plain")";     failed=$(( failed + 1 )); }
            fi
        done
    fi
    _esp_umount

    # rtkit-daemon
    if command -v pipewire &>/dev/null || command -v pulseaudio &>/dev/null; then
        [[ "$(systemctl is-active rtkit-daemon 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable rtkit-daemon"  systemctl enable --now rtkit-daemon
    fi

    # Btrfs maintenance timers
    for timer in btrfs-scrub.timer btrfs-balance.timer btrfs-defrag.timer btrfs-trim.timer; do
        [[ "$(systemctl is-active "$timer" 2>/dev/null)" != "active" ]] && \
            _apply_fix "Enable ${timer}"  systemctl enable --now "$timer"
    done

    # bees
    local bees_uuid
    bees_uuid=$(blkid -s UUID -o value "/dev/disk/by-label/${ROOTLABEL}" 2>/dev/null || true)
    [[ -z "$bees_uuid" && -e "/dev/mapper/${ROOTLABEL}" ]] && \
        bees_uuid=$(blkid -s UUID -o value "/dev/mapper/${ROOTLABEL}" 2>/dev/null || true)
    if [[ -n "$bees_uuid" ]]; then
        local bees_unit="beesd@${bees_uuid}"
        if [[ "$(systemctl is-active "$bees_unit" 2>/dev/null)" != "active" ]]; then
            if [[ ! -f "/etc/bees/${bees_uuid}.conf" ]]; then
                _log_warn "bees not configured — run beesd-setup.service first"
                failed=$(( failed + 1 ))
            else
                _apply_fix "Enable ${bees_unit}"  systemctl enable --now "$bees_unit"
            fi
        fi
    fi

    # TPM2 — requires user interaction
    if [[ -e "/dev/mapper/${ROOTLABEL}" ]] && [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]]; then
        local underlying
        underlying=$(cryptsetup status "/dev/mapper/${ROOTLABEL}" 2>/dev/null \
            | sed -n 's/^ *device: //p' || true)
        if [[ -n "$underlying" ]] && \
            ! systemd-cryptenroll "$underlying" 2>/dev/null | grep -q tpm2; then
            _log_warn "TPM2 not enrolled — requires user interaction: gen-efi enroll-tpm2"
        fi
    fi

    # Hibernate resume_offset — regenerate booted slot UKI
    local swapfile; swapfile=$(_find_swapfile)
    if [[ -n "$swapfile" ]] && command -v btrfs &>/dev/null; then
        local actual_off; actual_off=$(_swapfile_offset "$swapfile")
        local cmdline_off
        cmdline_off=$(grep -o 'resume_offset=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2 || echo "")
        if [[ -n "$actual_off" && -n "$cmdline_off" && "$actual_off" != "$cmdline_off" ]]; then
            local booted; booted=$(_get_booted_subvol)
            if [[ "$booted" != "unknown" && -x "$GENEFI_BIN" ]]; then
                _log "Regenerating UKI for @${booted} (resume_offset ${cmdline_off} -> ${actual_off})..."
                if "$GENEFI_BIN" configure "$booted" 2>&1; then
                    _log_ok "UKI regenerated for @${booted}"
                    fixed=$(( fixed + 1 ))
                else
                    _log_warn "UKI regeneration failed"
                    failed=$(( failed + 1 ))
                fi
            fi
        fi
    fi

    # systemd-timesyncd + NTP + RTC sync
    if command -v timedatectl &>/dev/null; then
        local td ntp_a ntp_s tsync_a _ntp_fixed=0
        td=$(timedatectl show 2>/dev/null || true)
        ntp_a=$(  echo "$td" | awk -F= '/^NTP=/{print $2}'             | tr -d '[:space:]')
        ntp_s=$(  echo "$td" | awk -F= '/^NTPSynchronized=/{print $2}' | tr -d '[:space:]')
        tsync_a=$(systemctl is-active systemd-timesyncd 2>/dev/null || echo "inactive")

        if [[ "$tsync_a" != "active" ]]; then
            _apply_fix "Enable systemd-timesyncd"  systemctl enable --now systemd-timesyncd
            _ntp_fixed=1
        fi
        if [[ "$ntp_a" != "yes" ]]; then
            if timedatectl set-ntp true 2>/dev/null; then
                _log_ok "NTP enabled"
                (( _ntp_fixed )) || fixed=$(( fixed + 1 ))
            else
                _log_warn "timedatectl set-ntp true failed"
                failed=$(( failed + 1 ))
            fi
        fi
        if [[ "$ntp_s" == "yes" ]] && command -v hwclock &>/dev/null; then
            hwclock --systohc 2>/dev/null && _log_ok "RTC synced (hwclock --systohc)" \
                || _log_warn "hwclock --systohc failed"
        fi
    fi

    echo ""
    if (( fixed + failed == 0 )); then
        _log_ok "Nothing to fix — system already hardened"
    else
        _log "Fixed: ${fixed} | Failed: ${failed}"
    fi
    echo ""
    _log "Run 'shani-health' to verify"
}

###############################################################################
### verify_system                                                            ###
###############################################################################

verify_system() {
    _log_section "System Integrity Verification"
    local errors=0

    # UKI signatures
    echo ""
    _log "Checking UKI signatures..."
    local mok_crt="/etc/secureboot/keys/MOK.crt"
    local _esp_mounted=0
    _esp_mount

    if [[ ! -f "$mok_crt" ]]; then
        _log_warn "MOK cert not found at ${mok_crt} — skipping UKI verification"
    else
        for slot in blue green; do
            local uki="$ESP/EFI/${OS_NAME}/${OS_NAME}-${slot}.efi"
            if [[ ! -f "$uki" ]]; then
                _log_warn "UKI missing: ${uki}"; errors=$(( errors + 1 ))
            elif sbverify --cert "$mok_crt" "$uki" &>/dev/null 2>&1; then
                _log_ok "UKI valid:   @${slot}"
            else
                _log_err "UKI INVALID: @${slot}"
                errors=$(( errors + 1 ))
            fi
        done
    fi
    _esp_umount

    # Btrfs data integrity
    echo ""
    _log "Checking Btrfs data integrity (scrub both slots)..."
    local mnt_tmp; mnt_tmp=$(mktemp -d /run/shanios-verify.XXXXXX)
    if ! mount -o subvolid=5,ro "$ROOT_DEV" "$mnt_tmp" 2>/dev/null; then
        _log_err "Cannot mount filesystem root — skipping Btrfs check"
        rmdir "$mnt_tmp" 2>/dev/null || true
        errors=$(( errors + 1 ))
    else
        for slot in blue green; do
            local subvol="$mnt_tmp/@${slot}"
            if [[ ! -d "$subvol" ]]; then
                _log_warn "@${slot} not found on disk — skipping"; continue
            fi
            if btrfs scrub start -Br "$subvol" &>/dev/null 2>&1; then
                local sc_out
                sc_out=$(btrfs scrub status "$subvol" 2>/dev/null || true)
                local re ce co
                re=$(echo "$sc_out" | awk '/read_errors:/{print $2}'      | head -1 || echo "0")
                ce=$(echo "$sc_out" | awk '/csum_errors:/{print $2}'      | head -1 || echo "0")
                co=$(echo "$sc_out" | awk '/corrected_errors:/{print $2}' | head -1 || echo "0")
                if [[ "${re:-0}" != "0" || "${ce:-0}" != "0" || "${co:-0}" != "0" ]]; then
                    _log_err "Btrfs errors on @${slot}: read=${re} csum=${ce} corrected=${co}"
                    errors=$(( errors + 1 ))
                else
                    _log_ok "Btrfs clean: @${slot}"
                fi
            else
                local last; last=$(btrfs scrub status / 2>/dev/null \
                    | awk '/Status:/{print $2}' | head -1 || echo "")
                [[ "$last" == "finished" ]] \
                    && _log "@${slot}: live scrub unavailable (mounted) — last run clean" \
                    || _log_warn "@${slot}: cannot scrub live fs — run: btrfs scrub start /"
            fi
        done
        umount "$mnt_tmp" 2>/dev/null || true
        rmdir  "$mnt_tmp" 2>/dev/null || true
    fi

    # Slot marker consistency
    echo ""
    _log "Checking slot marker consistency..."
    local current; current=$(cat "$DATA_CURRENT_SLOT" 2>/dev/null | tr -d '[:space:]' || echo "")
    local booted;  booted=$(_get_booted_subvol)
    if [[ ! "$current" =~ ^(blue|green)$ ]]; then
        _log_err "current-slot invalid or missing: '${current}'"
        errors=$(( errors + 1 ))
    else
        _log_ok "Markers OK:  current=@${current}  booted=@${booted}"
    fi

    # Boot entry consistency
    echo ""
    _log "Checking boot entry consistency..."
    local _esp_mounted=0
    _esp_mount
    local loader_conf="$ESP/loader/loader.conf"
    if [[ -f "$loader_conf" ]]; then
        local def_entry resolved
        def_entry=$(grep '^default' "$loader_conf" | awk '{print $2}' || echo "")
        # shellcheck disable=SC2086
        resolved=$(ls "$ESP/loader/entries/"${def_entry} 2>/dev/null | head -1 || echo "")
        if [[ -n "$resolved" ]]; then
            _log_ok "Boot entry OK: '${def_entry}' -> $(basename "$resolved")"
        else
            _log_err "Boot entry '${def_entry}' matches no file in loader/entries/"
            errors=$(( errors + 1 ))
        fi
    else
        _log_warn "loader.conf not found — cannot verify boot entries"
    fi
    _esp_umount

    echo ""
    if (( errors == 0 )); then
        _log_ok "Verification passed — no integrity issues"
    else
        _log_err "Verification found ${errors} issue(s)"
    fi
    echo ""
    return $(( errors > 0 ? 1 : 0 ))
}

###############################################################################
### show_history                                                             ###
###############################################################################

# Top-level helper — nested functions cannot write to caller's array in bash
_scan_log_file() {
    local logfile="$1" tmpfile="$2"
    [[ -f "$logfile" ]] || return 0
    local line ts rest ver
    while IFS= read -r line; do
        ts=$(echo "$line" | \
            grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' || true)
        [[ -z "$ts" ]] && continue
        rest="${line#*] }"
        if echo "$line" | grep -q "Deployment successful"; then
            ver=$(echo "$line" | grep -oE 'v[0-9]{8}' | head -1 || echo "")
            echo "${ts}  DEPLOY   ${ver}" >> "$tmpfile"
        elif echo "$line" | grep -q "Emergency rollback complete"; then
            echo "${ts}  ROLLBACK (emergency - deploy failed)" >> "$tmpfile"
        elif echo "$line" | grep -q "Fallback slot ready"; then
            echo "${ts}  ROLLBACK (no backup - snapshot of booted slot)" >> "$tmpfile"
        elif echo "$line" | grep -q "Rollback complete"; then
            echo "${ts}  ROLLBACK (manual)" >> "$tmpfile"
        elif echo "$line" | grep -q "Running system:"; then
            ver=$(echo "$rest" | grep -oE 'v[0-9]+' | head -1 || echo "")
            echo "${ts}  START    ${ver}" >> "$tmpfile"
        fi
    done < "$logfile"
}

show_history() {
    local lines="${1:-50}"

    echo ""
    echo "  ================================================"
    echo "    ShaniOS Deploy History"
    echo "  ================================================"

    if [[ ! -f "$DEPLOY_LOG" ]]; then
        echo "    No log file found at ${DEPLOY_LOG}"
        echo ""
        return 0
    fi

    local tmp; tmp=$(mktemp)
    _scan_log_file "$DEPLOY_LOG"       "$tmp"
    _scan_log_file "${DEPLOY_LOG}.old" "$tmp"

    local -a events=()
    mapfile -t events < <(sort "$tmp")
    rm -f "$tmp"

    if [[ ${#events[@]} -eq 0 ]]; then
        echo "    No deploy events recorded yet."
        echo "    Log: ${DEPLOY_LOG}"
        echo ""
        return 0
    fi

    local total=${#events[@]}
    local start=$(( total > lines ? total - lines : 0 ))
    echo ""
    for (( i=start; i<total; i++ )); do
        local ev="${events[$i]}"
        ev="${ev//  DEPLOY   /  +  }"
        ev="${ev//  ROLLBACK /  <  }"
        ev="${ev//  START    /  >  }"
        echo "    ${ev}"
    done
    echo ""
    (( start > 0 )) && echo "    (showing last ${lines} of ${total} — use: --history ${total} for all)"
    echo "    Full log: ${DEPLOY_LOG}"
    echo ""
}

###############################################################################
### analyze_storage — delegates to shani-deploy --storage-info              ###
###############################################################################

analyze_storage() {
    [[ -x "$DEPLOY_BIN" ]] && { "$DEPLOY_BIN" --storage-info; return $?; }
    _die "shani-deploy not found at ${DEPLOY_BIN}"
}

###############################################################################
### export_logs                                                              ###
###############################################################################

export_logs() {
    local out_dir="${1:-/tmp}"
    local ts; ts=$(date '+%Y%m%d-%H%M%S')
    local bundle="${out_dir}/shanios-report-${ts}.tar.gz"
    local staging; staging=$(mktemp -d /tmp/shanios-report-staging.XXXXXX)

    _log "Collecting system information for bug report..."

    [[ -f "$DEPLOY_LOG"       ]] && cp "$DEPLOY_LOG"       "$staging/shanios-deploy.log"     2>/dev/null || true
    [[ -f "${DEPLOY_LOG}.old" ]] && cp "${DEPLOY_LOG}.old" "$staging/shanios-deploy.log.old" 2>/dev/null || true

    journalctl -b 0 --no-pager -n 500 -o short-iso 2>/dev/null \
        | grep -vi 'password\|passwd\|secret\|token\|luks\|PIN' \
        > "$staging/journal-boot.log" 2>/dev/null || true

    journalctl --no-pager -n 100 -u systemd-boot 2>/dev/null \
        > "$staging/journal-systemd-boot.log" 2>/dev/null || true

    {
        echo "=== shani-health ${SCRIPT_VERSION} bug report — $(date) ==="
        echo ""
        echo "=== /proc/cmdline ===";         cat /proc/cmdline            2>/dev/null; echo ""
        echo "=== uname -a ===";              uname -a                     2>/dev/null; echo ""
        echo "=== /etc/shani-version ===";    cat /etc/shani-version       2>/dev/null; echo ""
        echo "=== /etc/shani-profile ===";    cat /etc/shani-profile       2>/dev/null; echo ""
        echo "=== /etc/shani-channel ===";    cat "$CHANNEL_FILE"          2>/dev/null || echo "(not set)"; echo ""
        echo "=== /data/current-slot ===";    cat "$DATA_CURRENT_SLOT"     2>/dev/null || echo "(missing)"; echo ""
        echo "=== /data/previous-slot ===";   cat "$DATA_PREV_SLOT"        2>/dev/null || echo "(missing)"; echo ""
        echo "=== Boot markers ==="
        for f in boot-ok boot_in_progress boot_failure boot_failure.acked \
                 boot_hard_failure deployment_pending; do
            if [[ -f "/data/${f}" ]]; then
                printf "  /data/%s: %s\n" "$f" "$(cat "/data/${f}" 2>/dev/null || echo "(empty)")"
            else
                printf "  /data/%s: (absent)\n" "$f"
            fi
        done
        echo ""
        echo "=== Btrfs subvolumes ==="; btrfs subvolume list / 2>/dev/null || echo "(unavailable)"; echo ""
        echo "=== findmnt ===";          findmnt                2>/dev/null || true; echo ""
        echo "=== systemctl --failed ==="; \
            systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null || true
    } > "$staging/system-state.txt" 2>/dev/null

    local _esp_mounted=0
    _esp_mount
    if mountpoint -q "$ESP" 2>/dev/null; then
        cp "$ESP/loader/loader.conf" "$staging/loader.conf"      2>/dev/null || true
        ls -la "$ESP/loader/entries/" > "$staging/loader-entries.txt" 2>/dev/null || true
        ls -la "$ESP/EFI/${OS_NAME}/" > "$staging/efi-binaries.txt"   2>/dev/null || true
    fi
    _esp_umount

    tar -czf "$bundle" -C "$(dirname "$staging")" "$(basename "$staging")" 2>/dev/null \
        || _die "Failed to create bundle at ${bundle}"
    rm -rf "$staging"

    _log_ok "Report bundle: ${bundle}"
    _log    "No passwords or private keys included"
    echo ""
}

###############################################################################
### Usage                                                                    ###
###############################################################################

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

  ShaniOS system health, security, and diagnostics.

Options:
  (no args)               Full system status report
  -i, --info              Alias for full system status report
  --fix-security          Auto-fix all [AUTOMATABLE] issues
  --verify                UKI signatures + Btrfs data integrity check
  --history [N]           Last N deploy/rollback events from log (default: 50)
  -s, --storage-info      Btrfs compression/subvolume analysis (via shani-deploy)
  --export-logs [DIR]     Bundle logs + state for bug reports (default: /tmp)
  -v, --verbose           Verbose/debug output
  -h, --help              Show this help

Examples:
  shani-health                     Full status report
  shani-health --fix-security      Auto-fix automatable issues
  shani-health --verify            Deep integrity check
  shani-health --history 100       Last 100 deploy events
  shani-health --export-logs ~/    Bug report bundle in home dir

Install:
  cp shani-health /usr/local/bin/shani-health
  chmod +x /usr/local/bin/shani-health
EOF
}

###############################################################################
### Main                                                                     ###
###############################################################################

main() {
    local MODE="info"
    local HISTORY_LINES=50
    local EXPORT_DIR="/tmp"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)          usage; exit 0 ;;
            -i|--info)          MODE="info";         shift ;;
            --fix-security)     MODE="fix-security"; shift ;;
            --verify)           MODE="verify";       shift ;;
            -s|--storage-info)  MODE="storage-info"; shift ;;
            --history)
                MODE="history"
                if [[ -n "${2:-}" && "${2:-}" =~ ^[0-9]+$ ]]; then
                    HISTORY_LINES="$2"; shift 2
                else
                    shift
                fi ;;
            --export-logs)
                MODE="export-logs"
                if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                    EXPORT_DIR="$2"; shift 2
                else
                    shift
                fi ;;
            -v|--verbose)       VERBOSE="yes"; shift ;;
            *)  _log_warn "Unknown option: $1"; shift ;;
        esac
    done

    _require_root

    case "$MODE" in
        info)           system_info ;;
        fix-security)   fix_security ;;
        verify)         verify_system; exit $? ;;
        history)        show_history "$HISTORY_LINES" ;;
        storage-info)   analyze_storage ;;
        export-logs)    export_logs "$EXPORT_DIR" ;;
    esac
}

main "$@"
