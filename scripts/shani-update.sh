#!/bin/bash
# shani-update — ShaniOS update manager
#
# Handles fallback-boot detection, candidate-boot testing, rollback, and
# OS update checking/installation. Replaces both shani-update and startup-check.
#
# Usage:
#   shani-update [--startup]      Run at login: fallback check → candidate check → update check
#   shani-update                  Interactive: candidate check → update check
#   shani-update --rollback       Roll back the inactive slot immediately
#   shani-update --force          Force deploy even if version matches
#   shani-update --channel CHAN   Update channel: stable|latest (default: stable)
#   shani-update --verbose        Verbose output from shani-deploy
#   shani-update --dry-run        Simulate without changes
#   shani-update --cleanup        Passthrough: shani-deploy --cleanup
#   shani-update --optimize       Passthrough: shani-deploy --optimize (manual dedup)
#   shani-update --download-only  Passthrough: shani-deploy --download-only (fetch+verify, no deploy)
#   shani-update --set-channel CHAN   Passthrough: shani-deploy --set-channel (persist channel)
#   shani-update --skip-self-update   Passthrough: shani-deploy --skip-self-update on install
#   shani-update --update-genefi      Passthrough: shani-deploy --update-genefi on install
#   shani-update --health [ARGS...]   Passthrough to shani-health (report/diagnostics tool)
#   shani-update
#
# Install: /usr/local/bin/shani-update
# Autostart desktop entry: Exec=shani-update --startup
# Autostart systemd unit:  ExecStart=/usr/local/bin/shani-update --startup

set -Eeuo pipefail
IFS=$'\n\t'

#####################################
### Constants                     ###
#####################################

_load_ini_config() {
    local conf_file="$1" section="" line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        if [[ "$line" =~ ^\[([a-zA-Z0-9_]+)\][[:space:]]*$ ]]; then
            section="${BASH_REMATCH[1]}"
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*([a-zA-Z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            value="${value%"${value##*[![:space:]]}"}"
            value="${value#"${value%%[![:space:]]*}"}"
            [[ -z "$section" ]] && continue
            printf -v "${section}_${key}" '%s' "$value"
        fi
    done < "$conf_file"
}

DEFAULT_deploy_r2_base_url="https://downloads.shani.dev"
DEFAULT_deploy_sourceforge_base="https://sourceforge.net/projects/shanios/files"
DEFAULT_deploy_channel_file="/etc/shani-channel"
DEFAULT_deploy_current_slot="/data/current-slot"
DEFAULT_deploy_boot_failure="/data/boot_failure"
DEFAULT_deploy_boot_hard_failure="/data/boot_hard_failure"
DEFAULT_deploy_auto_rollback_done="/data/auto_rollback_done"
DEFAULT_deploy_boot_ok="/data/boot-ok"
DEFAULT_deploy_reboot_needed="/run/shanios/reboot-needed"
DEFAULT_update_network_timeout="30"
DEFAULT_update_curl_retries="3"
DEFAULT_update_curl_retry_delay="5"
DEFAULT_update_defer_delay="86400"
DEFAULT_deploy_log_file="/var/log/shanios-deploy.log"
DEFAULT_update_log_file="/var/log/shani-update.log"
DEFAULT_update_lock_file="/run/shanios/shani-update.lock"

if [[ -f /etc/shani/shani.conf ]]; then
    _load_ini_config /etc/shani/shani.conf
fi
if [[ -f "${XDG_CONFIG_HOME:-${HOME:-}/.config}/shani/shani.conf" ]]; then
    _load_ini_config "${XDG_CONFIG_HOME:-${HOME:-}/.config}/shani/shani.conf"
fi

R2_BASE_URL="${deploy_r2_base_url:-${DEFAULT_deploy_r2_base_url}}"
BASE_URL="${deploy_sourceforge_base:-${DEFAULT_deploy_sourceforge_base}}"
CHANNEL_FILE="${deploy_channel_file:-${DEFAULT_deploy_channel_file}}"
CURRENT_SLOT_FILE="${deploy_current_slot:-${DEFAULT_deploy_current_slot}}"
BOOT_FAILURE_FILE="${deploy_boot_failure:-${DEFAULT_deploy_boot_failure}}"
BOOT_HARD_FAILURE_FILE="${deploy_boot_hard_failure:-${DEFAULT_deploy_boot_hard_failure}}"
AUTO_ROLLBACK_DONE_FILE="${deploy_auto_rollback_done:-${DEFAULT_deploy_auto_rollback_done}}"
BOOT_OK_FILE="${deploy_boot_ok:-${DEFAULT_deploy_boot_ok}}"
REBOOT_NEEDED_FILE="${deploy_reboot_needed:-${DEFAULT_deploy_reboot_needed}}"
NETWORK_TIMEOUT="${update_network_timeout:-${DEFAULT_update_network_timeout}}"
CURL_RETRIES="${update_curl_retries:-${DEFAULT_update_curl_retries}}"
CURL_RETRY_DELAY="${update_curl_retry_delay:-${DEFAULT_update_curl_retry_delay}}"
DEFER_DELAY="${update_defer_delay:-${DEFAULT_update_defer_delay}}"
DEPLOY_LOG="${deploy_log_file:-${DEFAULT_deploy_log_file}}"
LOG_FILE="${update_log_file:-${DEFAULT_update_log_file}}"
LOCK_FILE="${update_lock_file:-${DEFAULT_update_lock_file}}"

readonly SCRIPT_VERSION="3.1"
readonly OS_NAME="shanios"
readonly DEPLOY_BIN="/usr/local/bin/shani-deploy"
readonly HEALTH_BIN="/usr/local/bin/shani-health"
readonly LOCAL_VERSION_FILE="/etc/shani-version"
readonly LOCAL_PROFILE_FILE="/etc/shani-profile"

# LOG_DIR: validate stays within HOME to prevent log injection via XDG_CACHE_HOME
_lcd="${XDG_CACHE_HOME:-$HOME/.cache}"
[[ "$_lcd" != "$HOME"* ]] && _lcd="$HOME/.cache"
readonly LOG_DIR="$_lcd"
unset _lcd

readonly LOG_FILE="$LOG_DIR/shani-update.log"
readonly LOG_TAG="shani-update"

# Lock: prefer XDG_RUNTIME_DIR (user-private 0700) — startup mode requires it.
# In interactive mode LOG_DIR is an acceptable fallback.
readonly LOCK_FILE="${XDG_RUNTIME_DIR:-$LOG_DIR}/shani-update.lock"

mkdir -p "$LOG_DIR" 2>/dev/null || true

#####################################
### Global State                  ###
#####################################

MODE="interactive"          # interactive | startup | rollback | cleanup | optimize | download-only | set-channel | health
FORCE_UPDATE="no"
UPDATE_CHANNEL_DEFAULT="stable"
DEPLOY_CHANNEL="$UPDATE_CHANNEL_DEFAULT"
CHANNEL_FROM_CLI="no"       # set to "yes" once -t/--channel is parsed on the command line
VERBOSE_DEPLOY="no"
DRY_RUN_DEPLOY="no"
SKIP_SELF_UPDATE="no"       # passed through as shani-deploy --skip-self-update
UPDATE_GENEFI="no"          # passed through as shani-deploy --update-genefi
SET_CHANNEL_VALUE=""        # channel arg for MODE=set-channel
HEALTH_ARGS=()               # remaining argv forwarded verbatim to shani-health
SHOW_TERMINAL_MODE="no"     # yes only via --terminal — explicit user opt-in;
                            # default is the graphical progress window (see
                            # _run_gui_progress). A bare terminal only ever
                            # appears otherwise via the progress window's own
                            # "Show Terminal" button, also an explicit click.

LOCAL_VERSION=""
LOCAL_PROFILE=""
REMOTE_VERSION=""
REMOTE_PROFILE=""
TERMINAL=""
CURRENT_SLOT=""
BOOTED_SLOT=""
FAILED_SLOT=""              # set only when a fallback boot is confirmed
FALLBACK_DETECTED=0         # set to 1 when _check_fallback_boot confirms a fallback
REBOOT_VERSION=""           # set when reboot-needed marker is present

#####################################
### Logging                       ###
#####################################

log() {
    local ts msg
    ts=$(date '+%F %T')
    msg="[$ts] $*"
    # Rotate at 1 MB
    if [[ -f "$LOG_FILE" ]]; then
        local sz=0
        sz=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
        [[ $sz -gt 1048576 ]] && mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
    fi
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    echo "$msg" >&2
    if command -v systemd-cat &>/dev/null; then
        echo "$*" | systemd-cat -t "$LOG_TAG" 2>/dev/null || true
    elif command -v logger &>/dev/null; then
        logger -t "$LOG_TAG" "$*" 2>/dev/null || true
    fi
}

warn() { log "WARNING: $*"; }

err() {
    log "ERROR: $*"
    _cleanup_and_exit 1
}

#####################################
### Lock                          ###
#####################################

_acquire_lock() {
    # `mkdir -p` the lock's parent: LOCK_FILE lives under $XDG_RUNTIME_DIR,
    # which is always present in a real session but can be set to a path that
    # doesn't exist yet in a non-session context (a headless test slot, CI, a
    # systemd --user unit with no runtime dir) — confirmed live: without this,
    # `mkdir "$LOCK_FILE"` failed with "No such file or directory" and every
    # invocation died at the lock instead of doing what it was asked to do.
    mkdir -p "${LOCK_FILE%/*}" 2>/dev/null || true
    if ! mkdir "$LOCK_FILE" 2>/dev/null; then
        # A lock dir with no pid file (e.g. a crash between mkdir and writing
        # the pid) is just as stale as one whose owning process has died —
        # treat both the same way instead of exiting forever on every future
        # run until someone manually removes the directory.
        local pid=""
        [[ -f "$LOCK_FILE/pid" ]] && pid=$(cat "$LOCK_FILE/pid" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "Another instance is already running (PID: $pid)" >&2
            exit 1
        fi
        log "Removing stale lock"
        rm -rf "$LOCK_FILE"
        mkdir "$LOCK_FILE" || { echo "Failed to acquire lock" >&2; exit 1; }
    fi
    echo $$ > "$LOCK_FILE/pid"
}

_cleanup_lock() {
    rm -rf "$LOCK_FILE" 2>/dev/null || true
}

_cleanup_and_exit() {
    _cleanup_lock
    exit "${1:-0}"
}

#####################################
### Environment                   ###
#####################################

_validate_environment() {
    [[ -d /etc && -d /usr ]] || err "Invalid system environment"
    local required=(curl bash mkdir rm pkexec)
    for cmd in "${required[@]}"; do
        command -v "$cmd" &>/dev/null || err "Required command not found: $cmd"
    done
    systemctl --user status &>/dev/null || warn "systemd user session unavailable"
    command -v btrfs &>/dev/null        || warn "btrfs not available — slot detection may be limited"
}

#####################################
### Slot Helpers                  ###
#####################################

_get_booted_subvol() {
    # Keep this parsing logic in sync with the other 3 copies —
    # gen-efi.sh's get_booted_subvol(), shani-deploy.sh's
    # get_booted_subvol(), shani-health.sh's _get_booted_subvol() — see
    # AGENTS.md. Only the final not-found handling differs per script.
    local rootflags subvol=""
    rootflags=$(grep -o 'rootflags=[^ ]*' /proc/cmdline 2>/dev/null | cut -d= -f2- || echo "")
    if [[ -n "$rootflags" ]]; then
        subvol=$(grep -oP 'subvol=@?\K[^,]+' <<< "$rootflags" | head -1 || echo "")
        subvol="${subvol#@}"
    fi
    # Fallback: a bare subvol=@name directly on cmdline, no rootflags= wrapper.
    if [[ -z "$subvol" ]]; then
        subvol=$(grep -oP 'subvol=@?\K[^ ,]+' /proc/cmdline 2>/dev/null | head -1 || echo "")
        subvol="${subvol#@}"
    fi
    # Last resort: btrfs default subvolume.
    if [[ -z "$subvol" ]]; then
        subvol=$(btrfs subvolume get-default / 2>/dev/null | awk '{gsub(/@/,""); print $NF}')
    fi
    if [[ -z "$subvol" ]]; then
        err "Cannot detect booted subvolume — /proc/cmdline has no subvol= and btrfs get-default returned nothing"
    fi
    echo "$subvol"
}

_other_slot() {
    [[ "$1" == "blue" ]] && echo "green" || echo "blue"
}

#####################################
### Fallback Boot Detection       ###
#####################################

# Returns 0 and sets FAILED_SLOT if a real boot failure occurred.
_check_fallback_boot() {
    BOOTED_SLOT=$(_get_booted_subvol)

    if [[ -f "$BOOT_HARD_FAILURE_FILE" ]]; then
        FAILED_SLOT=$(cat "$BOOT_HARD_FAILURE_FILE" 2>/dev/null | tr -d '[:space:]')
        # Validate — fall back to current-slot if file is empty or garbage
        if [[ ! "$FAILED_SLOT" =~ ^(blue|green)$ ]]; then
            FAILED_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | tr -d '[:space:]')
        fi
        [[ ! "$FAILED_SLOT" =~ ^(blue|green)$ ]] && FAILED_SLOT=$(_other_slot "$BOOTED_SLOT")
        log "Hard failure marker present — slot '@${FAILED_SLOT}' failed to mount"
        FALLBACK_DETECTED=1
        return 0
    fi

    if [[ -f "$BOOT_OK_FILE" && ! -f "$BOOT_FAILURE_FILE" ]]; then
        log "Clean boot on @${BOOTED_SLOT}"
        return 1
    fi

    CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | tr -d '[:space:]')
    if [[ ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log "Invalid/missing slot marker — using booted slot"
        CURRENT_SLOT="$BOOTED_SLOT"
    fi

    log "Slot marker: @${CURRENT_SLOT} | Booted: @${BOOTED_SLOT}"

    # A same-slot marker is NOT automatically "no fallback" — it's the
    # normal steady state (no pending deploy), but it can ALSO be a
    # genuine same-slot timeout: check-boot-failure.sh legitimately
    # records BOOT_FAILURE_FILE naming the SAME slot now (see
    # shani-deploy/AGENTS.md's known-issues entry — this used to be
    # mis-derived as the sibling slot instead, which is why this same-slot
    # branch never mattered before that fix). Only bail out here when
    # there's also no failure marker at all; otherwise fall through so a
    # real same-slot failure still gets detected and handled below.
    if [[ "$BOOTED_SLOT" == "$CURRENT_SLOT" ]] && \
       [[ ! -f "$BOOT_FAILURE_FILE" && ! -f "${BOOT_FAILURE_FILE}.acked" ]]; then
        log "Booted slot matches marker, no failure recorded — no fallback"
        return 1
    fi

    [[ ! -f "$BOOT_FAILURE_FILE" && ! -f "${BOOT_FAILURE_FILE}.acked" ]] && {
        log "Slot mismatch but no failure file — nothing to act on"
        return 1
    }

    # Already acknowledged earlier this boot (user previously saw the dialog
    # and declined, or a prior run in this same session already processed
    # it). Don't re-prompt — but the slot mismatch here is a *known,
    # already-failed* slot, not a freshly booted candidate update. Flag it
    # so _check_candidate_boot() doesn't mistake the still-failed slot for
    # a new deployment being tested (which would offer to "roll back" the
    # currently-running, healthy fallback slot instead).
    [[ ! -f "$BOOT_FAILURE_FILE" && -f "${BOOT_FAILURE_FILE}.acked" ]] && {
        log "Failure for @${CURRENT_SLOT} already acknowledged this boot — skipping re-prompt"
        FALLBACK_DETECTED=1
        return 1
    }

    FAILED_SLOT=$(cat "$BOOT_FAILURE_FILE" 2>/dev/null | tr -d '[:space:]')
    if [[ "$FAILED_SLOT" != "$CURRENT_SLOT" ]]; then
        warn "Failure slot '@${FAILED_SLOT}' doesn't match marker '@${CURRENT_SLOT}' — ignoring"
        return 1
    fi

    log "Fallback confirmed: booted=@${BOOTED_SLOT} failed=@${FAILED_SLOT}"
    FALLBACK_DETECTED=1
    # Acknowledge the failure marker so mark-boot-in-progress doesn't
    # destroy it before shani-update processes it on the next reboot.
    mv "$BOOT_FAILURE_FILE" "${BOOT_FAILURE_FILE}.acked" 2>/dev/null || true
    return 0
}

#####################################
### Candidate Boot Detection      ###
#####################################

# Returns 0 if currently running the newly updated (candidate) slot.
# Must not fire when we already know this is a fallback boot — in that case
# the slot mismatch (booted != current-slot) is explained by the fallback,
# not by a new deployment being tested.
_check_candidate_boot() {
    if (( FALLBACK_DETECTED )); then
        log "Fallback already detected — skipping candidate boot check"
        return 1
    fi
    if [[ -r "$CURRENT_SLOT_FILE" ]]; then
        CURRENT_SLOT=$(cat "$CURRENT_SLOT_FILE" 2>/dev/null | xargs)
    fi
    if [[ -z "$CURRENT_SLOT" || ! "$CURRENT_SLOT" =~ ^(blue|green)$ ]]; then
        log "No valid slot marker — cannot determine candidate boot state, skipping"
        return 1
    fi

    BOOTED_SLOT=$(_get_booted_subvol)
    log "Booted: @${BOOTED_SLOT} | Marker: @${CURRENT_SLOT}"

    if [[ "$BOOTED_SLOT" != "$CURRENT_SLOT" ]]; then
        local candidate
        candidate=$(_other_slot "$CURRENT_SLOT")
        if [[ "$BOOTED_SLOT" == "$candidate" ]]; then
            log "Candidate boot: running newly updated @${BOOTED_SLOT}"
            return 0
        fi
        warn "Unexpected boot state: @${BOOTED_SLOT} (expected @${CURRENT_SLOT} or @${candidate})"
    fi
    return 1
}

#####################################
### Terminal Detection            ###
#####################################

_find_terminal() {
    local known=(alacritty kitty wezterm foot gnome-terminal kgx tilix
        xfce4-terminal konsole lxterminal mate-terminal deepin-terminal
        terminator xterm urxvt st)

    # Session-native terminal hint: prefer the terminal that matches the
    # running desktop environment so Wayland/X11 display env is already set.
    # KONSOLE_VERSION is set inside any Konsole window; VTE_VERSION inside any
    # VTE-based terminal (gnome-terminal, kgx, tilix, xfce4-terminal, …).
    local desktop="${XDG_CURRENT_DESKTOP:-}"
    local session_hint=""
    if [[ -n "${KONSOLE_VERSION:-}" ]] && command -v konsole &>/dev/null; then
        session_hint="konsole"
    elif [[ -n "${VTE_VERSION:-}" ]]; then
        # Identify which VTE terminal is actually running
        for vte_term in kgx gnome-terminal tilix xfce4-terminal mate-terminal; do
            command -v "$vte_term" &>/dev/null && { session_hint="$vte_term"; break; }
        done
    elif [[ "$desktop" == *KDE* ]] && command -v konsole &>/dev/null; then
        session_hint="konsole"
    elif [[ "$desktop" == *GNOME* ]] && command -v kgx &>/dev/null; then
        session_hint="kgx"
    elif [[ "$desktop" == *GNOME* ]] && command -v gnome-terminal &>/dev/null; then
        session_hint="gnome-terminal"
    fi
    [[ -n "$session_hint" ]] && { echo "$session_hint"; return 0; }

    # Env vars — strip path prefix, validate against allowlist only
    for var in TERMINAL TERMINAL_EMULATOR COLORTERM TERM_PROGRAM; do
        local emu="${!var:-}"
        emu="${emu##*/}"
        if [[ -n "$emu" ]]; then
            for k in "${known[@]}"; do
                [[ "$emu" == "$k" ]] && command -v "$emu" &>/dev/null && { echo "$emu"; return 0; }
            done
        fi
    done

    for term in "${known[@]}"; do
        command -v "$term" &>/dev/null && { echo "$term"; return 0; }
    done
    return 1
}

_build_terminal_args() {
    local terminal="$1" title="$2"
    local -n _arr="$3"
    shift 3
    local -a cmd=("$@")
    case "$terminal" in
        # gnome-terminal: modern (non-deprecated) syntax is `--title=X -- CMD...`.
        # -e/-x are deprecated in favor of --. Ref: gnome-terminal(1).
        # --wait: without it, `gnome-terminal` just hands the command off to
        # the already-running gnome-terminal-server over D-Bus and returns
        # immediately with that handoff's own exit code — NOT the exit code
        # of CMD. Every caller here (_run_rollback in particular) treats a
        # zero exit from this array's invocation as "the launched command
        # actually finished successfully", so without --wait a rollback
        # could still be running (or could have failed) while shani-update
        # already logged "Rollback succeeded" and offered to reboot. --wait
        # makes gnome-terminal block until the window/tab running CMD closes
        # and propagate CMD's exit status, matching every other terminal
        # branch below (kitty/xterm/etc. are all directly exec'd, so their
        # own exit code already is CMD's).
        gnome-terminal)
            _arr=("$terminal" "--wait" "--title=$title" "--" "${cmd[@]}") ;;
        # kgx (GNOME Console) intentionally dropped window titling. Its man
        # page documents -e/--command as the execution flag; "--" is not
        # documented anywhere for kgx (unlike gnome-terminal), and
        # xdg-terminal-exec — the freedesktop.org reference implementation
        # for this exact problem — defaults kgx to -e with no override entry.
        # Ref: manpages.debian.org/.../gnome-console/kgx.1.en.html
        kgx)
            _arr=("$terminal" "-e" "${cmd[@]}") ;;
        # konsole: modern (KF6) konsole no longer documents a top-level --title
        # option — title is set via the `-p tabtitle=` profile property instead.
        # -e must be the last option, as it consumes all following arguments.
        # Ref: docs.kde.org/stable_kf6/en/konsole/konsole/command-line-options.html
        konsole)
            _arr=("$terminal" "-p" "tabtitle=$title" "--noclose" "-e" "${cmd[@]}") ;;
        alacritty)
            _arr=("$terminal" "--title" "$title" "-e" "${cmd[@]}") ;;
        kitty|foot)
            _arr=("$terminal" "--title=$title" "${cmd[@]}") ;;
        # wezterm has no CLI flag for the window *title* (that's normally set
        # via shell/OSC sequences); --class only sets the WM class/app-id, so
        # we use it purely for window-manager grouping, not as a title stand-in.
        wezterm)
            _arr=("$terminal" "start" "--class" "shani-update" "${cmd[@]}") ;;
        terminator)
            _arr=("$terminal" "--title=$title" "-x" "${cmd[@]}") ;;
        xterm|urxvt|st)
            _arr=("$terminal" "-T" "$title" "-e" "${cmd[@]}") ;;
        # tilix: -e/--command must be the last parameter (consumes remainder).
        # Ref: tilix(1) — "this parameter must be the last parameter."
        tilix)
            _arr=("$terminal" "--title=$title" "-e" "${cmd[@]}") ;;
        # xfce4-terminal: does NOT understand a bare `--` terminator like
        # gnome-terminal. Use -x/--execute to consume the remaining argv.
        # Ref: docs.xfce.org/apps/xfce4-terminal/command-line
        xfce4-terminal)
            _arr=("$terminal" "--title=$title" "-x" "${cmd[@]}") ;;
        # lxterminal: -e/--command must be the last option (no `--` support).
        # Ref: lxterminal(1)
        lxterminal)
            _arr=("$terminal" "--title=$title" "-e" "${cmd[@]}") ;;
        # mate-terminal: forked from an older gnome-terminal and kept -x/--execute
        # ("remainder of the command line"); it does not support `--`.
        # Ref: mate-terminal(1)
        mate-terminal)
            _arr=("$terminal" "--title=$title" "-x" "${cmd[@]}") ;;
        # deepin-terminal: no documented --title flag and no `--` support, so we
        # skip the title entirely rather than pass an option it may reject.
        deepin-terminal)
            _arr=("$terminal" "-e" "${cmd[@]}") ;;
        *)
            _arr=("$terminal" "-e" "${cmd[@]}") ;;
    esac
}

#####################################
### Display Env                   ###
#####################################

_build_pkexec_env() {
    # Usage: _build_pkexec_env <nameref_array>
    # pkexec strips almost all environment variables, so we re-inject the ones
    # required for display servers and terminal emulators:
    #   DISPLAY / XAUTHORITY      — X11 terminals
    #   WAYLAND_DISPLAY           — Wayland terminals (kgx, konsole on KDE Wayland, foot, …)
    #   XDG_RUNTIME_DIR           — required by ALL Wayland clients to locate the
    #                               compositor socket; without it kgx/konsole fail
    #                               to open with "cannot open display" or similar.
    local -n _pe="$1"
    local display_env xauth_env wayland_display runtime_dir
    display_env=$(printf '%s'     "${DISPLAY:-:0}"                   | tr -cd '[:alnum:]:._/-')
    xauth_env=$(printf '%s'       "${XAUTHORITY:-$HOME/.Xauthority}" | tr -cd '[:alnum:]/_.-')
    wayland_display=$(printf '%s' "${WAYLAND_DISPLAY:-}"             | tr -cd '[:alnum:]/_.-')
    runtime_dir=$(printf '%s'     "${XDG_RUNTIME_DIR:-}"             | tr -cd '[:alnum:]/_.-')
    _pe=(pkexec env "DISPLAY=$display_env" "XAUTHORITY=$xauth_env")
    [[ -n "$wayland_display" ]] && _pe+=("WAYLAND_DISPLAY=$wayland_display")
    [[ -n "$runtime_dir"     ]] && _pe+=("XDG_RUNTIME_DIR=$runtime_dir")
    return 0
}

#####################################
### GUI Dialog                    ###
#####################################

# show_dialog TITLE TEXT OK_LABEL CANCEL_LABEL [TIMEOUT [ICON]]
# Returns: 0=confirmed  1=cancelled/timeout/closed  2=no GUI
#
# All yad flags below are validated against the "General options" section of
# yad(1) (Arch package extra/yad, https://man.archlinux.org/man/yad.1.en) —
# i.e. the options valid on yad's default question/button dialog. Notably:
#   --wrap is a "Text info options" flag (only valid with --text-info) and
#   is NOT a general option; passing it here caused some yad builds to
#   reject the whole invocation. --text-width is the general-options
#   equivalent — it caps the text width in characters before GTK wraps it.
#
# CONFIRMED LIVE BUG, FIXED 2026-09-19: this list used to also include
# --image-on-top, which does not exist as a yad option at all (confirmed
# against a real yad 15.0: `yad --help-general` lists --image=IMAGE and
# --on-top as two SEPARATE flags — both already present below under their
# real names — but no combined --image-on-top). Every yad invocation
# failed to even parse its command line ("Unable to parse command line:
# Unknown option --image-on-top", exit 255) before ever trying to open a
# display. Worse than a clean failure: the backend-detection logic a few
# lines below only recognizes rc=1 (GTK's real "can't open display" code)
# as a dead backend; rc=255 fell through as "non-standard exit = bad
# backend, try next", silently exhausting every GDK_BACKEND value and
# then zenity too, every single time, on any system, real display or not.
# Net effect: no shani-update dialog has ever actually rendered via yad in
# production — every one of them silently fell through to the
# notify-send/console fallback instead. Found and confirmed live by
# actually rendering a dialog end-to-end (X11-forwarded into a real test
# session — see shani-install-media/AGENTS.md's X11/Wayland-forwarding
# harness entry) rather than trusting this file read alone.
show_dialog() {
    # cancel_label uses ${4-Cancel} (no colon) rather than ${4:-Cancel} —
    # deliberately: show_alert() below passes an explicit empty string to
    # mean "no second button", which the colon form would incorrectly
    # treat the same as "not passed at all" and default back to "Cancel".
    local title="$1" text="$2" ok_label="${3:-OK}" cancel_label="${4-Cancel}"
    local timeout="${5:-120}" icon="${6:-software-update-available}"
    local session="${XDG_SESSION_TYPE:-unknown}"

    if command -v yad &>/dev/null; then
        local -a backends=()
        [[ "$session" == "wayland" ]] && backends=("wayland" "x11" "") || backends=("x11" "wayland" "")
        for backend in "${backends[@]}"; do
            # LC_ALL/LANGUAGE=C: force GTK's error strings to English so the
            # failure-pattern regex below matches reliably. Without this, a
            # non-English locale would translate "cannot open display" etc.,
            # the regex would never match, and a failed backend would be
            # mistaken for a real user Cancel on every non-English system.
            local -a yad_cmd=(env "LC_ALL=C" "LANGUAGE=C")
            [[ -n "$backend" ]] && yad_cmd+=("GDK_BACKEND=$backend")
            yad_cmd+=(yad
                --title="$title"
                --image="$icon"
                --text="$text"
                --text-align=center
                --text-width=60
                --width=480
                --borders=12
                --center
                --on-top
                --sticky
                --selectable-labels
                --button="${ok_label}:0"
            )
            # A single-button "alert" (see show_alert() below) passes an
            # empty cancel_label — skip the second button entirely rather
            # than showing two buttons with confusingly identical labels.
            [[ -n "$cancel_label" ]] && yad_cmd+=(--button="${cancel_label}:1")
            [[ $timeout -gt 0 ]] && yad_cmd+=(--timeout="$timeout" --timeout-indicator=bottom)

            # Capture stderr (discard stdout) instead of throwing it away.
            # A backend that can't open a display fails fast with GTK's
            # generic exit code 1 — the exact same code yad uses for a
            # real user Cancel. Without stderr there is no way to tell
            # "no dialog was ever shown" apart from "user declined", so
            # the wayland/x11 fallback below would never actually run.
            #
            # Also time the call: a human can't see, read, and dismiss a
            # dialog in under ~300ms, so an instant rc=1 with no stderr at
            # all (some backend failures exit silently) is still treated as
            # a failed backend rather than a genuine Cancel.
            local yad_err start_ns end_ns elapsed_ms=-1 rc=0
            start_ns=$(date +%s%N 2>/dev/null)
            yad_err=$("${yad_cmd[@]}" 2>&1 >/dev/null) || rc=$?
            end_ns=$(date +%s%N 2>/dev/null)
            [[ "$start_ns" =~ ^[0-9]+$ && "$end_ns" =~ ^[0-9]+$ ]] && \
                elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

            local backend_failed=0
            if [[ $rc -eq 1 ]]; then
                if [[ -n "$yad_err" ]] && grep -qiE \
                    'cannot open display|failed to open display|no protocol specified|could not connect|gdk_display|unable to init server|wayland display|not a wayland compositor|no such display' \
                    <<< "$yad_err"; then
                    backend_failed=1
                elif [[ -z "$yad_err" && $elapsed_ms -ge 0 && $elapsed_ms -lt 300 ]]; then
                    backend_failed=1
                fi
            fi

            if (( backend_failed )); then
                warn "yad backend '${backend:-default}' failed to initialize (${elapsed_ms}ms${yad_err:+: ${yad_err:0:200}}) — trying next"
                continue
            fi

            [[ $rc -eq 0 ]]   && return 0
            [[ $rc -eq 1 ]]   && return 1
            [[ $rc -eq 70 ]]  && return 1
            [[ $rc -eq 252 ]] && return 1
            # non-standard exit = bad backend, try next
        done
    fi

    if command -v zenity &>/dev/null; then
        local -a z=(zenity --question --title="$title" --icon-name="$icon"
            --width=450 --text="$text" --ok-label="$ok_label" --cancel-label="$cancel_label")
        [[ $timeout -gt 0 ]] && z+=(--timeout="$timeout")
        "${z[@]}" 2>/dev/null && return 0 || return 1
    fi

    if command -v kdialog &>/dev/null; then
        kdialog --title "$title" --yesno "$text" \
            --yes-label "$ok_label" --no-label "$cancel_label" 2>/dev/null && return 0 || return 1
    fi

    return 2
}

# show_alert TITLE TEXT [ICON]
# Single-button acknowledgment dialog for a critical, already-decided
# failure — automatic recovery already ran and failed, there is no
# meaningful "confirm or decline" choice left to offer, just "the user
# needs to know this happened". Uses the same backend-detection/fallback
# machinery as show_dialog() (a real dialog when a display is available,
# notify-send/console otherwise) rather than duplicating it. Returns the
# same codes as show_dialog(): 0=acknowledged, 1=cancelled/timeout,
# 2=no GUI at all. NOTE the return code is deliberately NOT repurposed to
# mean "fallback used": when rc=2 show_alert has ALREADY done the
# notify-send/console fallback itself, so it returns 2 just like
# show_dialog would — every current caller (L1036, L1054) follows it with
# `_cleanup_and_exit N` regardless and never inspects the value, so this
# is a documentation-only distinction, not a behavior one.
show_alert() {
    local title="$1" text="$2" icon="${3:-dialog-error}"
    local rc
    show_dialog "$title" "$text" "OK" "" 0 "$icon"
    rc=$?
    if [[ $rc -eq 2 ]]; then
        command -v notify-send &>/dev/null && \
            notify-send -u critical -i "$icon" "$title" "$text" 2>/dev/null
        [[ -t 1 ]] && printf '\n%s\n%s\n\n' "$title" "$text"
    fi
    return "$rc"
}

# _run_tray — persistent system-tray icon (yad --notification). Requires
# `gnome-shell-extension-appindicator` (already a shani-desktop-gnome
# dependency) or an equivalent StatusNotifierItem host on other desktops
# to actually be visible — GNOME Shell has no built-in legacy tray since
# 3.26. Deliberately does NOT call _acquire_lock: this process is meant to
# live for the whole session (started once at login, see
# shani-update-tray.service), and every action it offers just spawns an
# ORDINARY separate `shani-update` invocation, which acquires and releases
# the single-instance lock itself exactly like a manual or timer-triggered
# run would — a tray icon holding that lock for its entire lifetime would
# deadlock every periodic/manual check for as long as it's running.
# yad's own --menu=LABEL:CMD[|LABEL:CMD...] syntax confirmed live against
# this yad build (see AGENTS.md's yad-audit entry) before wiring it here.
_run_tray() {
    if [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        log "No display — cannot run tray icon"
        exit 0
    fi
    if ! command -v yad &>/dev/null; then
        log "yad not installed — cannot run tray icon"
        exit 0
    fi

    log "Starting shani-update tray icon"
    local view_log_cmd
    if TERMINAL=$(_find_terminal); then
        view_log_cmd="${TERMINAL} -e less \\\"${LOG_FILE}\\\""
    else
        view_log_cmd="xdg-open \\\"${LOG_FILE}\\\""
    fi

    # yad's --command/--menu entries are NOT run through a shell — confirmed
    # live: a bare trailing `&` was passed as a literal argv token to the
    # target program instead of backgrounding it ("Unknown option: &").
    # Every real action (everything except yad's own built-in "quit"
    # keyword) needs an explicit `sh -c "..."` wrapper for `&`/quoting to
    # mean anything.
    local menu_entries="Check for Updates Now:sh -c \"shani-update &\""
    menu_entries+="|View Update Log:sh -c \"${view_log_cmd} &\""
    menu_entries+="|Roll Back...:sh -c \"shani-update --rollback &\""
    menu_entries+="|Quit:quit"

    yad --notification \
        --text="Shani OS Update" \
        --command="sh -c \"shani-update &\"" \
        --menu="$menu_entries"
}

#####################################
### Deploy Launcher                ###
#####################################

# _build_install_args OUT_ARRAY_NAME — builds the shani-deploy flag list for
# an install/update run from the current FORCE_UPDATE/DEPLOY_CHANNEL/
# VERBOSE_DEPLOY/DRY_RUN_DEPLOY/SKIP_SELF_UPDATE/UPDATE_GENEFI state. Shared
# by the automatic flow and the dashboard's Install dialog so there is one
# place that knows how these map to shani-deploy's actual CLI flags.
_build_install_args() {
    local -n _out="$1"
    _out=()
    [[ "$FORCE_UPDATE"      == "yes" ]] && _out+=(--force)
    [[ "$DEPLOY_CHANNEL"    != "$UPDATE_CHANNEL_DEFAULT" ]] && _out+=(--channel "$DEPLOY_CHANNEL")
    [[ "$VERBOSE_DEPLOY"    == "yes" ]] && _out+=(--verbose)
    [[ "$DRY_RUN_DEPLOY"    == "yes" ]] && _out+=(--dry-run)
    [[ "$SKIP_SELF_UPDATE"  == "yes" ]] && _out+=(--skip-self-update)
    [[ "$UPDATE_GENEFI"     == "yes" ]] && _out+=(--update-genefi)
    return 0
}

# _launch_in_terminal TITLE CMD [ARG...]
# Opens CMD in a real terminal window and blocks until it exits, propagating
# its exit code. This is now ONLY reached two ways, both an explicit user
# request rather than the default: (1) `shani-update --terminal` was passed
# on the command line, or (2) the user clicked "Show Terminal" in the
# graphical progress window (see _run_gui_progress) and no display/yad was
# available at all — a real terminal is the only way to show anything then,
# not a preference. Shared by _launch_deploy/_launch_health so there's
# exactly one code path that builds the terminal invocation.
_launch_in_terminal() {
    local title="$1"; shift
    local -a cmd=("$@")

    if ! TERMINAL=$(_find_terminal); then
        err "No terminal emulator found — install konsole (KDE), kgx (GNOME), gnome-terminal, alacritty, kitty, or xterm"
    fi

    local -a terminal_args
    _build_terminal_args "$TERMINAL" "$title" terminal_args "${cmd[@]}"
    log "Launching: ${terminal_args[*]}"
    "${terminal_args[@]}"
}

# _launch_terminal_tail TITLE LOGFILE PID
# The explicit "Show Terminal" escape hatch from inside the graphical
# progress window (see _run_gui_progress): opens a real terminal doing a
# live, read-only follow of the SAME log the GUI window is already showing.
# Deliberately non-blocking (backgrounded) — the caller still owns waiting
# on PID for the operation's real exit code; this is just an extra viewer,
# not a replacement control path.
#
# Returns 0 only if the terminal is confirmed actually running a moment
# after launch, 1 otherwise. This distinction matters: a terminal emulator
# that needs D-Bus activation (gnome-terminal, kgx) can fail asynchronously
# — the initial exec succeeds, a background job starts, and only ~1s later
# does the child actually exit (e.g. "Error spawning command line
# 'dbus-launch ...'" when no D-Bus session bus is available). Confirmed
# live: without this check, _run_gui_progress's caller had already closed
# the yad progress window for the button click, the terminal then silently
# failed to appear a moment later, and the user was left with NO visible
# window at all while the real operation kept running in the background —
# reported live by a user watching the actual X11 display during testing.
_launch_terminal_tail() {
    local title="$1" logfile="$2" pid="$3"
    local terminal
    if ! terminal=$(_find_terminal); then
        warn "No terminal emulator found — staying on the graphical progress view"
        return 1
    fi
    local -a terminal_args
    _build_terminal_args "$terminal" "$title" terminal_args \
        bash -c "tail -n +1 -f --pid=${pid} '${logfile}'; echo; echo '--- finished — press Enter to close ---'; read -r _"
    "${terminal_args[@]}" &
    local term_pid=$!
    disown
    sleep 1.5
    if kill -0 "$term_pid" 2>/dev/null; then
        return 0
    fi
    warn "Terminal ('${terminal}') exited immediately after launch — likely no D-Bus session bus available. Falling back to the graphical progress view."
    return 1
}

# _run_gui_progress TITLE CMD [ARG...]
# Default path for _launch_deploy/_launch_health: runs CMD in the
# background and streams its combined stdout/stderr into a modern yad
# --progress window instead of opening a bare terminal — a real terminal
# now only ever appears on an explicit user request (this window's own
# "Show Terminal" button, or --terminal on shani-update's own command
# line — see _launch_in_terminal).
#
# Uses yad's `--text-info --tail` widget for a live, scrolling, inline log
# view (the original design's intent): the whole run is visible in the
# window as it happens, not just the last line.
#
# `--disable-search` is LOAD-BEARING, not cosmetic — do not remove it.
# yad's text-info builds a search bar whose entry icon (edit-find-symbolic/
# edit-clear-symbolic) resolves to an SVG. This image has NO working SVG
# rasterizer: there is no libpixbufloader-svg.so and no `svg` entry in
# gdk-pixbuf's loaders.cache (gdk-pixbuf 2.44.7 routes SVG through the
# out-of-process glycin loader, whose sandboxed `bwrap ... glycin-svg`
# child exits 1 here), so GTK falls back to image-missing.svg, cannot load
# that either, and asserts (gtkiconhelper.c:495 ... assertion failed) →
# SIGABRT (rc=134). Confirmed live on the shanios image via the
# shani-install-media X11 harness: identical invocation returns rc=134
# without `--disable-search` and rc=124 (renders and stays open) with it;
# the earlier "--text-info unconditionally crashes" finding was this same
# search-bar icon, just not yet isolated to a caller-controllable flag.
#
# `tail --pid=` (GNU coreutils) is the clean producer/consumer split: it
# follows the logfile until CMD's own PID exits, then stops on its own, so
# the window has a natural end and its last line just settles once the real
# work is done, with nothing here having to poll or race anything. yad's
# text-info keeps its window open after this stdin EOF (verified), so the
# user can still read the result and press a button. The actual exit code
# always comes from `wait` on CMD's own PID directly — never from yad's or
# tail's exit status.
_run_gui_progress() {
    local title="$1"; shift
    local -a cmd=("$@")

    if [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] || ! command -v yad &>/dev/null; then
        # No display, or yad isn't installed at all: the graphical view is
        # simply impossible here, not a preference — fall back to a real
        # terminal so the operation is still visible/controllable.
        _launch_in_terminal "$title" "${cmd[@]}"
        return $?
    fi

    local logfile
    logfile=$(mktemp "${XDG_RUNTIME_DIR:-/tmp}/shani-update-progress.XXXXXX.log" 2>/dev/null) || {
        warn "Could not create a progress logfile — falling back to a terminal"
        _launch_in_terminal "$title" "${cmd[@]}"
        return $?
    }

    log "Launching (graphical progress): ${cmd[*]}"
    "${cmd[@]}" >"$logfile" 2>&1 &
    local deploy_pid=$!

    # Loop rather than a single shot: if "Show Terminal" is clicked but the
    # terminal fails to actually come up (see _launch_terminal_tail's own
    # comment), re-show the graphical progress view instead of leaving
    # nothing on screen while $deploy_pid keeps running in the background.
    local yad_rc=0
    while kill -0 "$deploy_pid" 2>/dev/null; do
        yad_rc=0
        tail -n +1 -f --pid="$deploy_pid" "$logfile" | yad --text-info --tail --disable-search \
            --title="$title" \
            --width=700 --height=450 \
            --button="Show Terminal:2" \
            --button="Cancel:1" \
            --button="Close:0" || yad_rc=$?

        if [[ $yad_rc -eq 2 ]] && kill -0 "$deploy_pid" 2>/dev/null; then
            log "User requested the terminal view — opening a live tail of the same output"
            _launch_terminal_tail "$title" "$logfile" "$deploy_pid" && break
            continue
        elif [[ $yad_rc -eq 1 ]] && kill -0 "$deploy_pid" 2>/dev/null; then
            log "User cancelled — terminating ${cmd[0]} (pid $deploy_pid)"
            kill "$deploy_pid" 2>/dev/null || true
            break
        else
            break
        fi
    done

    local rc=0
    wait "$deploy_pid" 2>/dev/null || rc=$?
    rm -f "$logfile" 2>/dev/null || true
    return "$rc"
}

# _launch_deploy TITLE ARG [ARG...]
# Runs `pkexec shani-deploy ARG...` — graphical progress window by default
# (_run_gui_progress), a real terminal only via --terminal or the window's
# own "Show Terminal" button (_launch_in_terminal). Shared by rollback,
# install, cleanup, optimize, and channel changes so there's exactly one
# code path that builds the pkexec invocation.
_launch_deploy() {
    local title="$1"; shift
    log "Launching: $DEPLOY_BIN $*"

    local -a pkexec_args
    _build_pkexec_env pkexec_args
    pkexec_args+=("$DEPLOY_BIN" "$@")

    if [[ "$SHOW_TERMINAL_MODE" == "yes" ]]; then
        _launch_in_terminal "$title" "${pkexec_args[@]}"
        return $?
    fi
    _run_gui_progress "$title" "${pkexec_args[@]}"
}

# _launch_health TITLE [ARG...]
# Runs `shani-health ARG...` — graphical progress window by default, a real
# terminal only via --terminal or the window's own "Show Terminal" button.
# Unlike _launch_deploy this does NOT wrap the command in pkexec —
# shani-health re-execs itself via pkexec/sudo internally (see its
# _require_root) so wrapping it here would just prompt for privileges twice.
_launch_health() {
    local title="$1"; shift
    log "Launching: $HEALTH_BIN $*"

    local -a cmd_args=("$HEALTH_BIN" "$@")

    if [[ "$SHOW_TERMINAL_MODE" == "yes" ]]; then
        _launch_in_terminal "$title" "${cmd_args[@]}"
        return $?
    fi
    _run_gui_progress "$title" "${cmd_args[@]}"
}

#####################################
### Rollback                      ###
#####################################

_run_rollback() {
    local title="${1:-Shani OS — Rollback}"
    log "Launching rollback"

    local -a extra=(--rollback)
    [[ "$VERBOSE_DEPLOY" == "yes" ]] && extra+=(--verbose)
    [[ "$DRY_RUN_DEPLOY" == "yes" ]] && extra+=(--dry-run)

    _launch_deploy "$title" "${extra[@]}"
}


_post_rollback_dialog() {
    local text
    text=$(printf 'Rollback completed.\n\n<b>@%s</b> has been restored.\n\nRestart now to boot back into <b>@%s</b>.' \
        "${FAILED_SLOT:-inactive}" "${BOOTED_SLOT:-current}")

    local rc=0
    show_dialog "Shani OS — Rollback Complete" "$text" "Restart Now" "Restart Later" 300 "system-reboot" || rc=$?

    if [[ $rc -eq 0 ]]; then
        log "Restarting after rollback"
        pkexec systemctl reboot 2>/dev/null || \
        pkexec /usr/sbin/shutdown -r now 2>/dev/null || \
        { warn "Automatic restart failed — please restart manually"
          command -v notify-send &>/dev/null && \
              notify-send -u critical -i dialog-error \
                  "Shani OS — Please Restart" "Rollback done. Restart manually." 2>/dev/null || true; }
    else
        log "User will restart later after rollback"
        command -v notify-send &>/dev/null && \
            notify-send -u low -i system-reboot \
                "Shani OS — Restart When Ready" \
                "Rollback complete. Restart when convenient." 2>/dev/null || true
        # || true: this is the function's last statement, so its own exit
        # status (nonzero whenever stdout isn't a tty -- the normal case for
        # every non-interactive/autostart caller) becomes _post_rollback_dialog's
        # return value. All three call sites invoke it bare, immediately
        # followed by an explicit _cleanup_and_exit 0, so this return value is
        # not currently load-bearing -- but keep the function itself returning
        # 0 rather than relying on that.
        [[ -t 1 ]] && printf '\n✓ Rollback complete. Restart your system when ready.\n\n'
        true
    fi
}

#####################################
### Fallback Boot Handler         ###
#####################################

_handle_fallback_boot() {
    # Called when _check_fallback_boot returns 0 (soft or hard failure).
    #
    # REWRITTEN 2026-09-19: no longer asks "should we roll back?" via an
    # interactive dialog with a decline/timeout option. That was exactly
    # the failure mode shani-auto-rollback.service/.timer exist to fix — a
    # human who isn't present, declines, or lets a 60-120s prompt lapse
    # (the console path defaulted to declining on timeout). Recovery from
    # a confirmed failure isn't a choice to offer, it's the whole point of
    # this mechanism. This function now only:
    #   1. If auto-rollback already ran and failed this boot (markers
    #      still present despite AUTO_ROLLBACK_DONE_FILE existing) — tell
    #      the user clearly and point at the real logs. No retry prompt:
    #      an operation that just failed unattended isn't fixed by asking
    #      the same yes/no question a human wasn't there to answer the
    #      first time either.
    #   2. Otherwise (a genuine race — this session started before
    #      shani-auto-rollback's first ~1-16 minute trigger) — kick off
    #      the SAME canonical mechanism immediately via `systemctl start`
    #      rather than reimplementing rollback-direction logic here a
    #      second time (this file used to call _run_rollback itself,
    #      which duplicated the slot-direction decision instead of
    #      reusing shani-deploy --rollback's now-fixed logic).
    local hard_failure=0
    [[ -f "$BOOT_HARD_FAILURE_FILE" ]] && hard_failure=1
    local kind="soft"; (( hard_failure )) && kind="hard"

    if [[ -f "$AUTO_ROLLBACK_DONE_FILE" ]]; then
        log "ERROR: automatic rollback already ran and failed for @${FAILED_SLOT} (kind=${kind}) — see journalctl -t shani-auto-rollback"
        # A modal dialog here (not just a notify-send bubble, which is easy
        # to dismiss/miss unread) — this is a real "your safety net didn't
        # catch you" event, worth requiring active acknowledgment when a
        # display is available. show_alert() falls back to notify-send/
        # console on its own when one isn't.
        show_alert "Shani OS — Automatic Recovery Failed" \
            "Slot @${FAILED_SLOT} could not be automatically recovered.\n\nRun <b>journalctl -t shani-auto-rollback</b> for details, then <b>shani-deploy --rollback</b> manually." \
            "dialog-error"
        _cleanup_and_exit 1
    fi

    log "Boot failure detected for @${FAILED_SLOT} (kind=${kind}), automatic recovery hasn't run yet this boot — triggering it now"
    command -v notify-send &>/dev/null && \
        notify-send -u critical -i dialog-warning \
            "Shani OS — Boot Failure Detected" \
            "Slot @${FAILED_SLOT} $([[ $hard_failure -eq 1 ]] && echo "could not be mounted by the bootloader" || echo "failed to boot"). Running automatic recovery now…" 2>/dev/null || true

    if pkexec systemctl start shani-auto-rollback.service; then
        log "Automatic recovery completed"
        _post_rollback_dialog
        _cleanup_and_exit 0
    else
        log "ERROR: automatic recovery failed — see journalctl -t shani-auto-rollback"
        show_alert "Shani OS — Rollback Failed" \
            "Run <b>journalctl -t shani-auto-rollback</b> for details, or <b>shani-deploy --rollback</b> manually." \
            "dialog-error"
        _cleanup_and_exit 1
    fi
}

#####################################
### Candidate Boot Handler        ###
#####################################

_handle_candidate_boot() {
    local candidate="$BOOTED_SLOT"
    local text
    text=$(printf "You're running the newly updated system (<b>@%s</b>).\n\nIf everything looks good, no action needed.\nIf something is broken, roll back to <b>@%s</b> now." \
        "$candidate" "$CURRENT_SLOT")

    local rc=0
    show_dialog "Shani OS — Testing New System" "$text" "Roll Back Now" "Keep Testing" 0 "system-reboot" || rc=$?

    if [[ $rc -eq 0 ]]; then
        log "User requested rollback from candidate boot @${candidate}"
        FAILED_SLOT="$candidate"
        if _run_rollback "Shani OS — Rollback"; then
            log "Rollback from candidate boot succeeded"
            # Clear any failure markers left from earlier in this session or a
            # prior boot — shani-deploy --rollback clears them too, but be
            # explicit here for symmetry with _handle_fallback_boot.
            rm -f "$BOOT_FAILURE_FILE" "${BOOT_FAILURE_FILE}.acked" \
                  "$BOOT_HARD_FAILURE_FILE" 2>/dev/null || true
            _post_rollback_dialog
            _cleanup_and_exit 0
        else
            log "ERROR: Rollback failed"
            command -v notify-send &>/dev/null && \
                notify-send -u critical -i dialog-error \
                    "Shani OS — Rollback Failed" "Check $LOG_FILE." 2>/dev/null || true
            _cleanup_and_exit 1
        fi
    else
        log "User chose to keep testing @${candidate}"
        command -v notify-send &>/dev/null && \
            notify-send -u normal -i software-update-available \
                "Shani OS — System Testing" \
                "Testing @${candidate}. Run 'shani-update --rollback' if needed." 2>/dev/null || true
        _cleanup_and_exit 0
    fi
}

#####################################
### Reboot Needed Detection       ###
#####################################

# Returns 0 and sets REBOOT_VERSION if a reboot-needed marker is present.
# No manual cleanup needed — /run is tmpfs and is wiped on every reboot,
# so the file is gone as soon as the user reboots into the new slot.
_check_reboot_needed() {
    [[ -f "$REBOOT_NEEDED_FILE" ]] || return 1

    REBOOT_VERSION=$(cat "$REBOOT_NEEDED_FILE" 2>/dev/null | tr -cd '0-9A-Za-z.-' | head -c 32)
    BOOTED_SLOT=$(_get_booted_subvol)
    log "Reboot needed: deployed v${REBOOT_VERSION}, still running @${BOOTED_SLOT}"
    return 0
}

_handle_reboot_needed() {
    local ver="${REBOOT_VERSION:-unknown}"
    local text
    text=$(printf 'Shani OS has been updated to <b>v%s</b>.\n\nRestart now to boot into the updated system.\nYou can continue using your current session and restart later.' "$ver")

    local rc=0
    show_dialog "Shani OS — Restart Required" "$text" "Restart Now" "Restart Later" 300 "system-reboot" || rc=$?

    if [[ $rc -eq 0 ]]; then
        log "User chose to restart now after update to v${ver}"
        pkexec systemctl reboot 2>/dev/null || \
        pkexec /usr/sbin/shutdown -r now 2>/dev/null || \
        { warn "Automatic restart failed — please restart manually"
          command -v notify-send &>/dev/null && \
              notify-send -u critical -i system-restart \
                  "Shani OS — Please Restart" \
                  "Updated to v${ver}. Restart manually." 2>/dev/null || true; }
    elif [[ $rc -eq 1 ]]; then
        log "User chose to restart later after update to v${ver}"
        command -v notify-send &>/dev/null && \
            notify-send -u normal -i system-reboot \
                "Shani OS Updated to v${ver}" \
                "Restart when convenient to activate the new system." 2>/dev/null || true
    else
        # No GUI — fall back to notification or console
        command -v notify-send &>/dev/null && \
            notify-send -u critical -i software-update-available \
                "Shani OS Updated — Restart Required" \
                "v${ver} is ready. Restart to activate." 2>/dev/null || true
        if [[ -t 0 && -t 1 ]]; then
            printf '\n========================================\n'
            printf '  Shani OS v%s — Restart Required\n' "$ver"
            printf '========================================\n'
            read -rp "Restart now? [y/N]: " -t 60 response || response="n"
            if [[ "${response,,}" == y* ]]; then
                pkexec systemctl reboot 2>/dev/null || \
                pkexec /usr/sbin/shutdown -r now 2>/dev/null || \
                warn "Restart failed — please restart manually"
            fi
        fi
    fi
}

#####################################
### Network & Version Helpers     ###
#####################################

_read_file_or_default() {
    local file="$1" default="$2" filter="$3"
    [[ ! -r "$file" ]] && { echo "$default"; return 0; }
    local content
    content=$(head -n1 "$file" 2>/dev/null | tr -cd "$filter" | xargs echo)
    [[ -z "$content" ]] && { warn "Invalid data in $file — using default: $default"; echo "$default"; return 0; }
    echo "$content"
}

_check_network() {
    log "Checking network connectivity..."
    local dns=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    for d in "${dns[@]}"; do
        ping -c 1 -W 5 "$d" &>/dev/null && { log "Network OK"; return 0; }
    done
    local urls=("https://www.google.com" "https://github.com")
    for u in "${urls[@]}"; do
        curl -fsSL --connect-timeout 5 --max-time 10 --head "$u" &>/dev/null && { log "Network OK"; return 0; }
    done
    nslookup google.com &>/dev/null && { log "Network OK via DNS"; return 0; }
    dig +short google.com &>/dev/null && { log "Network OK via DNS"; return 0; }
    host google.com &>/dev/null     && { log "Network OK via DNS"; return 0; }
    log "No network connectivity"
    return 1
}

_fetch_remote_info() {
    local url="$1"
    local tmp
    tmp=$(mktemp) || { log "ERROR: mktemp failed"; return 1; }
    if ! curl -fsSL \
        --retry "$CURL_RETRIES" --retry-delay "$CURL_RETRY_DELAY" \
        --max-time "$NETWORK_TIMEOUT" --connect-timeout 10 \
        --user-agent "shani-update/$SCRIPT_VERSION" \
        --output "$tmp" "$url" 2>/dev/null; then
        rm -f "$tmp"; log "ERROR: fetch failed for $url"; return 1
    fi
    local sz=0
    sz=$(stat -c%s "$tmp" 2>/dev/null || stat -f%z "$tmp" 2>/dev/null || echo 0)
    if [[ $sz -gt 1024 ]]; then
        rm -f "$tmp"; log "ERROR: Response too large ($sz bytes)"; return 1
    fi
    local content
    content=$(head -n1 "$tmp" 2>/dev/null | tr -cd 'A-Za-z0-9.-' | xargs echo)
    rm -f "$tmp"
    [[ -z "$content" ]] && { log "ERROR: Empty response"; return 1; }
    echo "$content"
}

_validate_version() {
    local v="$1"
    [[ "$v" =~ ^[0-9]{8}$ ]] || return 1
    local y="${v:0:4}" m="${v:4:2}" d="${v:6:2}"
    [[ "$y" < "2020" || "$y" > "2050" ]] && return 1
    [[ "$m" < "01"   || "$m" > "12"   ]] && return 1
    [[ "$d" < "01"   || "$d" > "31"   ]] && return 1
    return 0
}

_version_compare() {
    # Returns 0=equal 1=v1<v2(update available) 2=v1>v2
    local v1="$1" v2="$2"
    [[ "$v1" == "$v2" ]] && return 0
    [[ "$v1" < "$v2"  ]] && return 1
    return 2
}

_is_update_needed() {
    local lv="$1" lp="$2" rv="$3" rp="$4"
    _version_compare "$lv" "$rv"
    case $? in
        0) [[ "$lp" != "$rp" ]] && { log "Profile update: $lp → $rp"; return 0; }
           log "System is current (v${lv}-${lp})"; return 1 ;;
        1) log "Update available: v${lv} → v${rv}"; return 0 ;;
        2) log "System is ahead of remote (v${lv} vs v${rv})"; return 1 ;;
    esac
}

#####################################
### Channel Resolution            ###
#####################################

_validate_channel() {
    case "$1" in
        stable|latest) return 0 ;;
        *) return 1 ;;
    esac
}

# Resolve DEPLOY_CHANNEL exactly the way shani-deploy resolves UPDATE_CHANNEL:
#   CLI flag (already validated at parse time) > $CHANNEL_FILE > "stable".
# Without this, shani-update could check the stable manifest while a later
# `shani-deploy` invocation (launched with no --channel flag) silently reads
# a persisted "latest" setting from $CHANNEL_FILE and deploys that instead —
# showing the user one version and installing another.
_resolve_channel() {
    [[ "$CHANNEL_FROM_CLI" == "yes" ]] && return 0

    if [[ -r "$CHANNEL_FILE" ]]; then
        local file_channel
        file_channel=$(head -n1 "$CHANNEL_FILE" 2>/dev/null | tr -d '[:space:]')
        if _validate_channel "$file_channel"; then
            DEPLOY_CHANNEL="$file_channel"
            log "Channel source: $CHANNEL_FILE ($DEPLOY_CHANNEL)"
            return 0
        elif [[ -n "$file_channel" ]]; then
            warn "Invalid channel '$file_channel' in $CHANNEL_FILE — using default: $UPDATE_CHANNEL_DEFAULT"
        fi
    fi
    log "Channel source: default ($DEPLOY_CHANNEL)"
}

#####################################
### Update Flow                   ###
#####################################

_decide_action() {
    local current="v$LOCAL_VERSION-$LOCAL_PROFILE"
    local remote="v$REMOTE_VERSION-$REMOTE_PROFILE"
    local text
    text=$(printf 'A system update is available for Shani OS.\n\n<b>Current:</b>  %s\n<b>Available:</b> %s\n\nThe update will download and install in a terminal window.\nYou can continue using your computer during the process.' \
        "$current" "$remote")

    log "Session: ${XDG_SESSION_TYPE:-unknown} (${XDG_CURRENT_DESKTOP:-unknown})"
    local rc=0
    show_dialog "Shani OS — Update Available" "$text" "Install Now" "Remind Me Later" 120 || rc=$?

    [[ $rc -eq 0 ]] && { log "User chose to install"; return 0; }
    [[ $rc -eq 1 ]] && { log "User chose to postpone"; return 1; }

    # rc=2: no GUI
    command -v notify-send &>/dev/null && \
        notify-send -u critical -i software-update-available \
            "Shani OS Update Available" \
            "$current → $remote. Run 'shani-update' to install." 2>/dev/null || true

    if [[ -t 0 && -t 1 ]]; then
        printf '\n========================================\n'
        printf '     Shani OS System Update Available   \n'
        printf '========================================\n'
        printf '  Current:   %s\n  Available: %s\n\n' "$current" "$remote"
        read -rp "Install update now? [y/N]: " -t 60 response || response="n"
        [[ "${response,,}" == y* ]] && { log "User chose to install (console)"; return 0; }
        log "User chose to postpone (console)"
        return 1
    fi

    log "No interactive interface — defaulting to postpone"
    return 1
}

_read_local_info() {
    LOCAL_VERSION=$(_read_file_or_default "$LOCAL_VERSION_FILE" "19700101" "0-9")
    # Charset must match shani-deploy's `tr -cd 'a-z0-9_-' < /etc/shani-profile`
    # exactly — a narrower filter here would silently mangle any profile name
    # containing a digit, hyphen, or underscore (e.g. "kde6", "gnome-de"),
    # breaking the update-URL path and the local/remote profile comparison.
    LOCAL_PROFILE=$(_read_file_or_default "$LOCAL_PROFILE_FILE" "default"  "a-z0-9_-")
    _validate_version "$LOCAL_VERSION" || { warn "Corrupted version — treating as outdated"; LOCAL_VERSION="19700101"; }
    log "Local: v${LOCAL_VERSION}-${LOCAL_PROFILE}"
}

# _fetch_and_compare — read local version/profile, fetch the remote manifest,
# and compare. Sets LOCAL_VERSION/LOCAL_PROFILE/REMOTE_VERSION/REMOTE_PROFILE.
# Unlike _run_update_check, this NEVER calls err()/_cleanup_and_exit — it
# returns a status so callers (the unattended --startup flow via
# _run_update_check, and the interactive dashboard) can each decide what to
# do with a failure instead of always killing the whole process.
#   0 = update available   1 = already up to date
#   2 = no network          3 = fetch/parse error
_fetch_and_compare() {
    _read_local_info

    if ! _check_network; then
        warn "No internet — retrying in 30s..."
        sleep 30
        _check_network || { warn "No internet connection after retry"; return 2; }
        log "Connection restored"
    fi

    local channel_url="$BASE_URL/$LOCAL_PROFILE/$DEPLOY_CHANNEL.txt"
    local r2_url="$R2_BASE_URL/$LOCAL_PROFILE/$DEPLOY_CHANNEL.txt"
    local remote_image
    # Try R2 first (same priority as shani-deploy), fall back to SourceForge.
    remote_image=$(_fetch_remote_info "$r2_url") || \
    remote_image=$(_fetch_remote_info "$channel_url") || {
        warn "Unable to fetch update info from server"
        return 3
    }

    if [[ "$remote_image" =~ ^shanios-([0-9]{8})-([a-z0-9_-]+)\.zst$ ]]; then
        REMOTE_VERSION="${BASH_REMATCH[1]}"
        REMOTE_PROFILE="${BASH_REMATCH[2]}"
        if ! _validate_version "$REMOTE_VERSION"; then
            warn "Invalid remote version: $REMOTE_VERSION"
            return 3
        fi
    else
        warn "Unexpected server response: '$remote_image'"
        return 3
    fi
    log "Remote: v${REMOTE_VERSION}-${REMOTE_PROFILE}"

    if _is_update_needed "$LOCAL_VERSION" "$LOCAL_PROFILE" "$REMOTE_VERSION" "$REMOTE_PROFILE"; then
        return 0
    else
        return 1
    fi
}

_run_update_check() {
    local rc=0
    _fetch_and_compare || rc=$?

    case $rc in
        2) err "No internet connection after retry" ;;
        3) err "Unable to fetch update info from server" ;;
        1) log "System is up to date"; _cleanup_and_exit 0 ;;
    esac

    _decide_action || {
        log "Update postponed — scheduling reminder"
        if systemctl --user status &>/dev/null; then
            # Cancel any previously deferred reminders before creating a new one
            # so they don't accumulate across multiple defer sessions.
            systemctl --user stop "${LOG_TAG}-defer-"*.timer 2>/dev/null || true
            systemctl --user reset-failed "${LOG_TAG}-defer-"*.timer 2>/dev/null || true
            local unit
            unit="${LOG_TAG}-defer-$(date +%s)-$$"
            systemd-run --user \
                --unit="$unit" \
                --description="Deferred Shani OS update reminder" \
                --on-active="${DEFER_DELAY}s" \
                "/usr/local/bin/shani-update" 2>/dev/null && \
                log "Reminder set for ${DEFER_DELAY}s" || warn "Could not schedule reminder"
        fi
        _cleanup_and_exit 0
    }

    log "User approved update — launching shani-deploy"

    local -a install_args
    _build_install_args install_args
    local exit_code=0
    _launch_deploy "Shani OS Update" "${install_args[@]}" || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log "Update completed successfully — reboot-needed marker will surface restart dialog"
        # shani-deploy wrote /run/shanios/reboot-needed (tmpfs — auto-cleared on reboot).
        # On next startup or interactive run _check_reboot_needed will pick it up.
    else
        warn "Update failed or cancelled (exit code: $exit_code)"
        command -v notify-send &>/dev/null && \
            notify-send -u critical -i dialog-error \
                "Shani OS Update Failed" \
                "The update did not complete. Check $LOG_FILE." 2>/dev/null || true
        _cleanup_and_exit 1
    fi
}

#####################################
### Main                          ###
#####################################

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --startup)          MODE="startup";       shift ;;
            --tray)             MODE="tray";          shift ;;
            -r|--rollback)      MODE="rollback";      shift ;;
            -f|--force)         FORCE_UPDATE="yes";   shift ;;
            -t|--channel)
                [[ $# -ge 2 ]] || { echo "Option $1 requires an argument (stable|latest)" >&2; exit 1; }
                _validate_channel "$2" || { echo "Invalid channel '$2' — must be 'stable' or 'latest'" >&2; exit 1; }
                DEPLOY_CHANNEL="$2"
                CHANNEL_FROM_CLI="yes"
                shift 2 ;;
            -v|--verbose)       VERBOSE_DEPLOY="yes"; shift ;;
            -d|--dry-run)       DRY_RUN_DEPLOY="yes"; shift ;;
            --terminal)         SHOW_TERMINAL_MODE="yes"; shift ;;
            -c|--cleanup)       MODE="cleanup";       shift ;;
            -o|--optimize)      MODE="optimize";      shift ;;
            --download-only)    MODE="download-only"; shift ;;
            --set-channel)
                [[ $# -ge 2 ]] || { echo "Option $1 requires an argument (stable|latest)" >&2; exit 1; }
                _validate_channel "$2" || { echo "Invalid channel '$2' — must be 'stable' or 'latest'" >&2; exit 1; }
                MODE="set-channel"
                SET_CHANNEL_VALUE="$2"
                shift 2 ;;
            --skip-self-update) SKIP_SELF_UPDATE="yes"; shift ;;
            --update-genefi)    UPDATE_GENEFI="yes";  shift ;;
            --health)
                MODE="health"
                shift
                HEALTH_ARGS=("$@")
                break ;;
            -h|--help)
                cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --startup           Run at login: fallback check → candidate check → update check
  --tray              Run a persistent system-tray icon (yad --notification);
                      click or its menu triggers a normal check on demand
  -r, --rollback      Roll back the inactive slot immediately
  -f, --force         Force deploy even if version matches or slot mismatch
  -t, --channel CHAN  Update channel: stable|latest  (default: $UPDATE_CHANNEL_DEFAULT)
  -v, --verbose       Verbose output from shani-deploy
  -d, --dry-run       Simulate deployment without changes
  --terminal          Show a real terminal window instead of the graphical
                      progress window for this run (default: graphical; a
                      "Show Terminal" button in the progress window is the
                      other way to get one, on demand)
  -c, --cleanup       Passthrough: shani-deploy --cleanup (manual backup/download cleanup)
  -o, --optimize      Passthrough: shani-deploy --optimize (manual Btrfs dedup)
  --download-only     Passthrough: shani-deploy --download-only (fetch+verify update image, no deploy)
  --set-channel CHAN  Passthrough: shani-deploy --set-channel (persist channel to $CHANNEL_FILE)
  --skip-self-update  On install, passed through as shani-deploy --skip-self-update
  --update-genefi     On install, passed through as shani-deploy --update-genefi
  --health [ARGS...]  Passthrough to shani-health (e.g. --health --security). Consumes
                      all remaining arguments — must be last on the command line.
  -h, --help          Show this help

Autostart:  Exec=shani-update --startup
EOF
                exit 0 ;;
            *) warn "Unknown option: $1"; shift ;;
        esac
    done

    log "shani-update v${SCRIPT_VERSION} mode=${MODE}"

    # cleanup / optimize / download-only / set-channel / health: dispatched below, after the lock
    # is acquired (they run shani-deploy or shani-health directly and exit).

    _validate_environment
    _resolve_channel

    # ── Tray mode ────────────────────────────────────────────────────────────
    # Deliberately BEFORE _acquire_lock — see _run_tray()'s own comment for
    # why this long-lived process must never hold the single-instance lock.
    if [[ "$MODE" == "tray" ]]; then
        _run_tray
        exit $?
    fi

    # ── Startup mode ─────────────────────────────────────────────────────────
    if [[ "$MODE" == "startup" ]]; then
        if [[ -z "${XDG_RUNTIME_DIR:-}" ]]; then
            log "XDG_RUNTIME_DIR not set — cannot run safely at startup"
            exit 0
        fi
        # Wait for polkit agent and desktop shell before acquiring the lock so
        # a concurrent manual invocation is not blocked during this delay.
        sleep 15
        if [[ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
            log "No display — skipping startup check"
            exit 0
        fi
    fi

    _acquire_lock
    # EXIT must only drop the lock, never re-enter _cleanup_and_exit: that
    # re-exits 0 regardless of the real status and silently masked every
    # failure path (err(), and the explicit `_cleanup_and_exit 1` in every
    # dispatch branch). Confirmed live: a cancelled rollback logged
    # "ERROR: Rollback failed" yet the process still returned rc=0. Letting
    # bash keep its own status here is what makes those failures visible;
    # INT/TERM get the conventional 128+signal codes instead of also 0.
    trap '_cleanup_lock' EXIT
    trap '_cleanup_and_exit 130' INT
    trap '_cleanup_and_exit 143' TERM

    # ── Startup mode (continued after lock) ───────────────────────────────────
    if [[ "$MODE" == "startup" ]]; then

        # Fallback/failure check runs first — it is the most urgent condition
        # and must not be masked by a stale reboot-needed marker. A boot failure
        # means the system is in a degraded state; showing a "restart to activate
        # update" dialog instead would be misleading and block recovery.
        #
        # NOTE (2026-09-19): this is now a SECONDARY layer, not the primary
        # recovery mechanism. system-level shani-auto-rollback.service/.timer
        # (../systemd/system/) run unconditionally on every boot, no session
        # or display required, and normally resolve a real failure before a
        # user could even log in (~1min for a hard failure, ~16min for a
        # same-slot soft failure) — by the time this --startup path runs (it
        # requires a graphical session at all, see the DISPLAY/WAYLAND_DISPLAY
        # check above, which this repo's own headless `server` profile never
        # satisfies), the markers checked below will usually already be
        # cleared. This code stays as a courtesy for a user who logs in
        # during that window, or as a manual fallback if the automatic path
        # itself failed — see shani-deploy/AGENTS.md's "Automated rollback is
        # now a real, system-level, unattended mechanism" entry for the full
        # history of why this separation exists.
        log "=== Startup: checking fallback boot ==="
        if _check_fallback_boot; then
            _handle_fallback_boot
        fi
        if (( FALLBACK_DETECTED )); then
            # Already acknowledged earlier this boot (see _check_fallback_boot).
            # The slot mismatch is still unresolved — running shani-deploy now
            # would just hit the same mismatch and exit 0, which we'd wrongly
            # log as "update completed successfully". Stop here; the user
            # needs to reboot or run --rollback first.
            log "Fallback already acknowledged this boot — nothing more to do until reboot or rollback"
            _cleanup_and_exit 0
        fi

        log "=== Startup: checking reboot needed ==="
        if _check_reboot_needed; then
            _handle_reboot_needed
            _cleanup_and_exit 0
        fi

        log "=== Startup: checking candidate boot ==="
        if _check_candidate_boot; then
            _handle_candidate_boot
            # _handle_candidate_boot calls _cleanup_and_exit internally
        fi

        log "=== Startup: checking for updates ==="
        _run_update_check
        _cleanup_and_exit 0
    fi

    # ── Explicit rollback ─────────────────────────────────────────────────────
    if [[ "$MODE" == "rollback" ]]; then
        log "=== Manual rollback ==="
        BOOTED_SLOT=$(_get_booted_subvol)
        FAILED_SLOT=$(_other_slot "$BOOTED_SLOT")
        if _run_rollback "Shani OS — Rollback"; then
            log "Rollback succeeded"
            # shani-deploy --rollback clears these, but also clear here so the
            # markers are gone regardless of which binary does the actual work.
            rm -f "$BOOT_FAILURE_FILE" "${BOOT_FAILURE_FILE}.acked" \
                  "$BOOT_HARD_FAILURE_FILE" 2>/dev/null || true
            _post_rollback_dialog
            _cleanup_and_exit 0
        else
            log "ERROR: Rollback failed"
            _cleanup_and_exit 1
        fi
    fi

    # ── Cleanup / Optimize passthrough ────────────────────────────────────────
    if [[ "$MODE" == "cleanup" || "$MODE" == "optimize" ]]; then
        log "=== ${MODE} ==="
        local -a extra=()
        [[ "$MODE" == "cleanup"  ]] && extra+=(--cleanup)
        [[ "$MODE" == "optimize" ]] && extra+=(--optimize)
        [[ "$VERBOSE_DEPLOY" == "yes" ]] && extra+=(--verbose)
        [[ "$DRY_RUN_DEPLOY" == "yes" ]] && extra+=(--dry-run)
        local title="Shani OS — Cleanup"
        [[ "$MODE" == "optimize" ]] && title="Shani OS — Storage Optimize"
        if _launch_deploy "$title" "${extra[@]}"; then
            log "${MODE} completed"
            _cleanup_and_exit 0
        else
            log "ERROR: ${MODE} failed"
            _cleanup_and_exit 1
        fi
    fi

    # ── Download-only passthrough ─────────────────────────────────────────────
    if [[ "$MODE" == "download-only" ]]; then
        log "=== download-only ==="
        local -a extra=(--download-only)
        [[ "$FORCE_UPDATE"   == "yes" ]] && extra+=(--force)
        [[ "$DEPLOY_CHANNEL" != "$UPDATE_CHANNEL_DEFAULT" ]] && extra+=(--channel "$DEPLOY_CHANNEL")
        [[ "$VERBOSE_DEPLOY" == "yes" ]] && extra+=(--verbose)
        [[ "$DRY_RUN_DEPLOY" == "yes" ]] && extra+=(--dry-run)
        if _launch_deploy "Shani OS — Download Update" "${extra[@]}"; then
            log "download-only completed"
            _cleanup_and_exit 0
        else
            log "ERROR: download-only failed"
            _cleanup_and_exit 1
        fi
    fi

    # ── Set-channel passthrough ───────────────────────────────────────────────
    if [[ "$MODE" == "set-channel" ]]; then
        log "=== Set channel: $SET_CHANNEL_VALUE ==="
        if _launch_deploy "Shani OS — Set Channel" --set-channel "$SET_CHANNEL_VALUE"; then
            log "Channel set to $SET_CHANNEL_VALUE"
            _cleanup_and_exit 0
        else
            log "ERROR: Failed to set channel"
            _cleanup_and_exit 1
        fi
    fi

    # ── Health passthrough ────────────────────────────────────────────────────
    if [[ "$MODE" == "health" ]]; then
        log "=== Health passthrough: ${HEALTH_ARGS[*]:-(default report)} ==="
        [[ -x "$HEALTH_BIN" ]] || err "shani-health not found or not executable at $HEALTH_BIN"
        if _launch_health "Shani OS — Health" "${HEALTH_ARGS[@]}"; then
            _cleanup_and_exit 0
        else
            log "ERROR: shani-health exited with an error"
            _cleanup_and_exit 1
        fi
    fi

    # ── Interactive update mode ───────────────────────────────────────────────
    log "=== Interactive: checking fallback boot ==="
    if _check_fallback_boot; then
        _handle_fallback_boot
    fi
    if (( FALLBACK_DETECTED )); then
        log "Fallback already acknowledged this boot — nothing more to do until reboot or rollback"
        _cleanup_and_exit 0
    fi

    log "=== Interactive: checking reboot needed ==="
    if _check_reboot_needed; then
        _handle_reboot_needed
        _cleanup_and_exit 0
    fi

    log "=== Interactive: checking candidate boot ==="
    if _check_candidate_boot; then
        _handle_candidate_boot
        # _handle_candidate_boot calls _cleanup_and_exit internally
    fi

    log "=== Interactive: checking for updates ==="
    _run_update_check
    _cleanup_and_exit 0
}

main "$@"
