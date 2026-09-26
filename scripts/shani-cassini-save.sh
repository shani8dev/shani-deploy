#!/usr/bin/env bash
# shani-cassini-save — install ONE config file, supplied on stdin, over ONE
# known target, as root, on behalf of Shani Cassini.
#
# WHY THIS EXISTS, AND WHY IT IS SHAPED THIS WAY
#
# A root helper reachable through pkexec is a privilege-escalation primitive
# unless it is deliberately narrow, so this one takes no command from the
# caller. The caller supplies a SYMBOLIC NAME and the CONTENT, on stdin. The
# name is resolved here, against the table below, to a fixed path, a fixed mode
# and a fixed validator. A caller that asks for anything not in the table is
# refused, and a caller cannot name a path of its own at all.
#
# The content arrives on a PIPE and root writes the file itself. Nothing
# caller-supplied is ever read back and installed: there is no --staged, and no
# code path opens a path the caller named. The earlier shape - the caller
# stages a file, root installs THAT path - was wrong twice over. It was
# unsatisfiable, because the only caller staged as the user while this script
# demanded root ownership, so no caller could ever reach it. And it was a
# wait-for-root-to-read-my-file primitive: a user-writable file can be rewritten
# between the ownership check and the install. Writing from a pipe removes the
# window by removing the name.
#
# The validator runs HERE, not in the caller, on the bytes received, before
# anything is installed. If the caller is compromised, the worst it can do is
# ask for a file we already know how to check. That inversion is the whole
# point: the caller proposes, this decides.
#
# The caller is Shani Cassini's config_io engine, which refuses rather than
# re-renders and keeps its own backup. This script does the part that needs
# root and nothing else: validate, commit atomically, verify.

set -Eeuo pipefail

readonly PROG="${0##*/}"

# A few rules each. The real /etc/ssh/sshd_config on Arch is under 5 KiB, so
# 16 KiB is generous. The cap is enforced by reading at most MAX_BYTES+1 bytes,
# so an oversized payload is DETECTED rather than silently truncated into a
# config that still parses.
readonly MAX_BYTES=16384

# The allowlist. Nothing outside this table is ever written.
#
# Every target is a DROP-IN, never a main config file:
#   - sshd_config on Arch carries `Include /etc/ssh/sshd_config.d/*.conf`
#   - sudoers carries `@includedir /etc/sudoers.d`
#   - exports(5): "After reading /etc/exports exportfs reads files in the
#     /etc/exports.d directory as extra export tables"
# A drop-in is self-contained, so its validator can check it in isolation.
# That is why we never write /etc/ssh/sshd_config, /etc/sudoers or
# /etc/exports themselves: a mistake in one of those takes SSH, sudo or the
# whole export set away from the machine, while a mistake in a drop-in is
# removable by deleting one file.
#
# The numbers are load-bearing, not decoration. sudoers is LAST-MATCH-WINS in
# lexical order, so an unnumbered name makes precedence accidental; 50- puts
# this drop-in after the common 10- defaults and before a future 90- override.
#
# Modes are enforced, never inherited. sudoers is 0440 because sudo REFUSES a
# group- or world-writable sudoers file - that is a security requirement of
# sudo itself, not a convention.
target_path() {
    case "$1" in
        sudoers)           printf '/etc/sudoers.d/50-shani-cassini' ;;
        sshd_config)       printf '/etc/ssh/sshd_config.d/50-cassini.conf' ;;
        exports)           printf '/etc/exports.d/shani-cassini.exports' ;;
        *)                 return 1 ;;
    esac
}

target_mode() {
    case "$1" in
        # sudo refuses to read a group/world-writable sudoers file.
        sudoers)           printf '0440' ;;
        sshd_config)       printf '0644' ;;
        exports)           printf '0644' ;;
        *)                 return 1 ;;
    esac
}

# Every target gets the same two-phase shape, which is the whole safety
# property: validate the fragment, commit atomically, then check the LIVE
# config the daemon actually read - twice, as a baseline and again after -
# and roll back if the second check finds something the first did not.
#
# An array, not a string: "${PRE_VALIDATOR_CMD[@]}" "$file" is ONE argv
# element per element, so a string makes bash look for a program literally
# named "visudo -c -f".
PRE_VALIDATOR_CMD=()
POST_VALIDATOR_CMD=()
POST_SETTLE=0

target_validators() {
    PRE_VALIDATOR_CMD=()
    POST_VALIDATOR_CMD=()
    POST_SETTLE=0
    case "$1" in
        # visudo -c -f checks ONE file in isolation; visudo -c checks the whole
        # live set, which is what sudo itself will read.
        sudoers)
            PRE_VALIDATOR_CMD=(visudo -c -f)
            POST_VALIDATOR_CMD=(visudo -c)
            ;;
        sshd_config)
            PRE_VALIDATOR_CMD=(sshd -t -f)
            POST_VALIDATOR_CMD=(sshd -t)
            ;;
        # exportfs can only judge the LIVE export set, so there is nothing
        # sensible to check a fragment against before install; the post-check
        # is the verdict and a complaint rolls the install back. The settle
        # delay is exportfs' own cache, not ours. Not an oversight.
        exports)
            POST_VALIDATOR_CMD=(exportfs -ra)
            POST_SETTLE=0.3
            ;;
        *)                 return 1 ;;
    esac
}

usage() {
    cat >&2 <<EOF
usage: $PROG --target <sudoers|sshd_config|exports> [--expect-sha256 <64-hex>] < content

Reads the new content from stdin and installs it over one known target, after
validating it. The content is never taken from a caller-named path.
EOF
    exit 2
}

log() { printf '%s: %s\n' "$PROG" "$*" >&2; }
die() { log "REFUSING: $*"; exit 1; }

[[ $# -gt 0 ]] || usage
target=""
expect_sha=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            # A trailing flag with no value must be a USAGE error, not a bare
            # `shift 2` that aborts under `set -e` with a misleading exit 1.
            [[ $# -ge 2 ]] || usage
            target="$2"; shift 2 ;;
        --expect-sha256)
            [[ $# -ge 2 ]] || usage
            expect_sha="$2"; shift 2 ;;
        -h|--help) usage ;;
        *)         usage ;;
    esac
done
[[ -n "$target" ]] || usage

# ── must already be root: this script is reached through pkexec, never run
#    directly by a user, and it does not elevate on its own.
(( EUID == 0 )) || die "must run as root (reach it through pkexec)"

path="$(target_path "$target")" || die "unknown target '${target}' - not in the allowlist"
mode="$(target_mode "$target")" || die "no mode for '${target}'"
target_validators "$target" || die "no validator for '${target}'"

# ── the parent directory has to exist; creating it here would be a second,
#    separate privileged act and so is not this script's business.
parent="$(dirname "$path")"
[[ -d "$parent" ]] || die "target directory does not exist: ${parent}"

if [[ -n "$expect_sha" ]]; then
    [[ "$expect_sha" =~ ^[0-9a-fA-F]{64}$ ]] \
        || die "--expect-sha256 must be exactly 64 hex characters"
fi

# ── fail closed when a validator is missing. Installing an unvalidated
#    sudoers or sshd drop-in is exactly the failure this script exists to
#    prevent, so "cannot check" must mean "do not write". Both phases count:
#    a missing post-check is just as dangerous as a missing pre-check.
if [[ ${#PRE_VALIDATOR_CMD[@]} -gt 0 ]]; then
    command -v "${PRE_VALIDATOR_CMD[0]}" &>/dev/null \
        || die "${PRE_VALIDATOR_CMD[0]} is not installed; refusing to save ${target} unvalidated"
fi
if [[ ${#POST_VALIDATOR_CMD[@]} -gt 0 ]]; then
    command -v "${POST_VALIDATOR_CMD[0]}" &>/dev/null \
        || die "${POST_VALIDATOR_CMD[0]} is not installed; refusing to save ${target} uncheckable"
fi

# ── state for the single rollback path, declared before the trap so the trap
#    can never see an unset variable under `set -u`.
tmp=""
probe=""
backup=""
had_previous=0
commit_started=0
committed=0
# the two passes of the live check, below: $live_* is whichever pass ran
# last, $baseline_* is frozen before the commit. Declared here so the
# helpers that fill them can never trip `set -u`.
live_out=""
live_rc=0
baseline_out=""
baseline_rc=0

# A scratch file in a config directory must be invisible to every consumer,
# in case this script is killed between mktemp and the commit. All three
# consumers skip dot-prefixed names: sudo's @includedir skips any filename
# CONTAINING a dot, sshd's `Include .../*.conf` glob skips dotfiles, exportfs
# ignores them too. That is the first layer. This is the second one, and it
# does not rely on the first: a scratch name must never end in a suffix any
# of them would match.
assert_scratch_name() {
    case "${1##*/}" in
        *.conf|*.exports)  die "internal error: scratch file $1 would be read as a drop-in" ;;
    esac
}

restore() {
    if (( had_previous )); then
        # Atomically, like every other write here: a temp in the same directory
        # and an mv, never `cat > "$path"`, which leaves a truncated file
        # behind for sudo/sshd/exportfs to read mid-restore.
        local rb
        rb="$(mktemp "${parent}/.cassini.restore.XXXXXX")" || return 1
        if ! cat -- "$backup" > "$rb"; then rm -f -- "$rb"; return 1; fi
        chmod --reference="$backup" "$rb" 2>/dev/null || true
        chown --reference="$backup" "$rb" 2>/dev/null || true
        if ! mv -f -- "$rb" "$path"; then rm -f -- "$rb"; return 1; fi
        log "restored ${path} from backup"
    else
        rm -f -- "$path" || return 1
        log "removed ${path} (there was none before)"
    fi
}

on_exit() {
    local rc=$?
    if (( commit_started )) && (( ! committed )); then
        log "exiting ${rc}; rolling back ${path}"
        restore || log "ROLLBACK FAILED for ${path}"
    fi
    if [[ -n "$tmp" ]];    then rm -f -- "$tmp"    2>/dev/null || true; fi
    if [[ -n "$probe" ]];  then rm -f -- "$probe"  2>/dev/null || true; fi
    if [[ -n "$backup" ]]; then rm -f -- "$backup" 2>/dev/null || true; fi
    return "$rc"
}
trap on_exit EXIT

# ── the temp file lives in the TARGET'S OWN DIRECTORY. That is a requirement,
#    not a preference: /tmp is tmpfs and /etc is the overlay, so a cross-device
#    mv degrades to copy+unlink and the whole atomicity argument below is lost.
#    mktemp creates it with O_EXCL, so its name is ours, in a directory only
#    root writes, which is also why the payload can be re-read by path below
#    without a TOCTOU window.
tmp="$(mktemp "${parent}/.cassini.tmp.XXXXXX")" \
    || die "could not create a temp file in ${parent}"
assert_scratch_name "$tmp"

# The same properties the old staged-file check enforced, now on the object we
# made ourselves rather than one a user handed us: root-owned, and not group-
# or world-writable. sudo refuses such a file in /etc/sudoers.d outright.
[[ "$(stat -c %U "$tmp")" == root ]] || die "internal error: ${tmp} is not root-owned"
(( (8#$(stat -c %a "$tmp") & 8#022) == 0 )) \
    || die "internal error: ${tmp} is group- or world-writable"

# ── read the payload from stdin into that file, on ONE descriptor, which is
#    then reused for the validation: the bytes validated and the bytes
#    committed are provably the same object, and nothing is ever re-opened by
#    the caller's name. The payload is NEVER held in a shell variable:
#    `$(...)` strips trailing newlines and cannot hold NUL.
#
# --expect-sha256 exists because stdin can collide with a pkttyagent password
# prompt reading the same tty, which would otherwise silently corrupt the
# config with a valid-looking one.
#
# fd 3 is opened read-write so a validator can be handed /dev/fd/3 and read
# the same bytes; re-opening a path here would reopen the TOCTOU window.
exec 3<>"$tmp" || die "could not open ${tmp} for writing"
head -c $(( MAX_BYTES + 1 )) >&3 || die "could not read the payload from stdin"
size="$(stat -c %s "$tmp")" || die "could not measure ${tmp}"
(( size > 0 )) || die "refusing to install an empty config (stdin produced 0 bytes)"
(( size <= MAX_BYTES )) || die "payload is ${size} bytes, over the ${MAX_BYTES}-byte limit"

exec 4<"$tmp" || die "could not re-read ${tmp}"
payload_sum="$(sha256sum <&4 | cut -d' ' -f1)" || die "could not hash the received bytes"
exec 4<&-
if [[ -n "$expect_sha" ]]; then
    [[ "${payload_sum,,}" == "${expect_sha,,}" ]] \
        || die "stdin does not match --expect-sha256 (got ${payload_sum})"
    log "stdin matches --expect-sha256"
fi

# ── validate the received bytes, before anything is installed. For sudoers
#    and sshd_config this is the whole safety property: a rejected fragment
#    never reaches the target, so a bad edit cannot lock anyone out.
if [[ ${#PRE_VALIDATOR_CMD[@]} -gt 0 ]]; then
    # sshd -t -f needs a file it can actually start a daemon config from, and
    # a bare drop-in has no host keys, so `sshd -t -f <drop-in>` fails with
    # "no hostkeys available" no matter how valid the fragment is. Do NOT
    # work around that by validating a synthetic file that also Contains the
    # real /etc/ssh/sshd_config: that was tested and has a verified false
    # positive, because an unrelated pre-existing broken drop-in in the include
    # dir fails the check and we would then permanently refuse to save.
    #
    # Validate a SELF-CONTAINED file instead: the fragment plus a HostKey line
    # pointing at a real key. That exits 0 on a bare drop-in. Fail closed if no
    # host key is found - never validate without one.
    validate_arg="/dev/fd/3"
    if [[ "$target" == sshd_config ]]; then
        host_key=""
        for candidate in /etc/ssh/ssh_host_*_key; do
            [[ -f "$candidate" && -r "$candidate" ]] || continue
            host_key="$candidate"
            break
        done
        [[ -n "$host_key" ]] \
            || die "no host key under /etc/ssh/ssh_host_*_key; refusing to validate ${target} without one"
        probe="$(mktemp "${parent}/.cassini.probe.XXXXXX")" \
            || die "could not create a validation probe in ${parent}"
        assert_scratch_name "$probe"
        # HostKey first, because sshd is first-value-wins: that is also the
        # order the real config sees, where the Include sits at the top.
        { printf 'HostKey %s\n' "$host_key"; cat -- "$tmp"; } > "$probe" \
            || die "could not build the validation probe"
        exec 5<>"$probe" || die "could not open ${probe}"
        validate_arg="/dev/fd/5"
    fi
    log "validating ${target} with '${PRE_VALIDATOR_CMD[*]} ${validate_arg}'"
    if out="$("${PRE_VALIDATOR_CMD[@]}" "$validate_arg" 2>&1)"; then
        if [[ -n "$out" ]]; then printf '%s\n' "$out" >&2; fi
        log "validator accepted the fragment; nothing invalid is installed"
    else
        log "validator rejected the fragment; nothing was installed"
        if [[ -n "$out" ]]; then printf '%s\n' "$out" >&2; fi
        exit 1
    fi
fi

# ── the LIVE check, in TWO passes, and the verdict is the DIFFERENCE.
#
# A post-check that only asks "is the live config clean?" judges the MACHINE,
# not the CHANGE - and on a real ShaniOS box that verdict is permanently
# false. The stock /etc/sudoers.d drop-ins (editor, insults, pwfeedback,
# wheel) ship mode 0750, so `visudo -c` complains about all four on every
# run forever, whatever we install, and a perfectly valid save rolled itself
# back every single time. That is the same false-positive shape as the
# synthetic sshd probe documented on the pre-validator above, and it made the
# feature unusable rather than merely noisy.
#
# So the same check runs once BEFORE the commit, and its output and exit
# status are kept as the baseline; then again after. A save succeeds unless
# the post-check surfaces something the baseline did not.
#
# WHICH LINES COUNT AS OURS, i.e. which post-only lines are the expected
# benign difference rather than a new problem: a line reporting on the
# target path we just committed that the tool itself did not call a failure -
# visudo's "<path>: parsed OK", or a line it explicitly labelled a warning.
# `sshd -t` and `exportfs -ra` print nothing at all for a good save, so for
# those two targets the set of such lines is simply empty.
#
# The "did not call it a failure" half is load-bearing and is NOT cosmetic. A
# FATAL complaint about our own file - "syntax error", "bad permissions" - is
# a new problem and must roll the change back, and the only way to tell the
# two apart is that the tools label their own non-fatal diagnostics: a valid
# drop-in that trips, say, visudo's "unused Cmnd_Alias" warning is still a
# valid drop-in, and refusing to install it would be the same dead feature
# this comparison exists to prevent. A post-only line about any OTHER file is
# a new problem whatever it says, and so is a check that went from exit 0 to
# non-zero even if it printed nothing new.
#
# Excluding our own file's non-fatal diagnostics does not hand the safety
# property away, because the two phases above already hold the parts that
# matter: the pre-validator parsed THIS fragment in isolation, and the
# readback proved its mode and owner.

# Runs the target's live check, storing its combined output in $live_out and
# its exit status in $live_rc, and always returning 0: at both call sites a
# failing check is data to be compared, never an abort.
run_live_check() {
    live_out=""
    live_rc=0
    live_out="$("${POST_VALIDATOR_CMD[@]}" 2>&1)" || live_rc=$?
    return 0
}

is_ours_line() {
    local rest
    [[ "$1" == *"$path"* ]] || return 1
    # the path has to stand there as a whole file name - every one of the
    # three checks writes "<path>: ..." - not inside some other file's name
    rest="${1##*"$path"}"
    [[ -z "$rest" || "$rest" == :* || "$rest" == " "* ]] || return 1
    [[ "$1" == *"parsed OK"* || "${1,,}" == warning:* ]]
}

# The lines of one pass that decide the verdict: everything that is not a
# report on our own drop-in. Compared verbatim, so ordering matters - both
# passes read the same directories in the same order.
significant_lines() {
    local line
    [[ -n "$1" ]] || return 0
    while IFS= read -r line; do
        is_ours_line "$line" || printf '%s\n' "$line"
    done <<< "$1"
}

if [[ ${#POST_VALIDATOR_CMD[@]} -gt 0 ]]; then
    log "taking a baseline of the live config with '${POST_VALIDATOR_CMD[*]}'"
    run_live_check
    if (( live_rc == 126 || live_rc == 127 )); then
        # 126/127 mean the check never ran, so there is no baseline and no
        # verdict to reach. Fail closed for this target exactly as a missing
        # binary does above: an uncheckable save is not a safe save, and
        # skipping the comparison to "be nice" is how this bug came back.
        die "could not run '${POST_VALIDATOR_CMD[*]}' to take a baseline; refusing to save ${target} uncheckable"
    fi
    baseline_out="$live_out"
    baseline_rc="$live_rc"
    if [[ -n "$baseline_out" ]]; then printf '%s\n' "$baseline_out" >&2; fi
    if (( baseline_rc == 0 )); then
        log "the live config is clean BEFORE the change"
    else
        log "the live config ALREADY exits ${baseline_rc} before the change; only NEW complaints are ours"
    fi
fi

# ── keep whatever is there now, so a failed apply can be undone. A missing
#    target is recorded as such rather than backed up as an empty file.
if [[ -e "$path" ]]; then
    had_previous=1
    backup="$(mktemp "${parent}/.cassini.bak.XXXXXX")" \
        || die "could not create a backup next to ${path}"
    assert_scratch_name "$backup"
    cat -- "$path" > "$backup" || die "could not read ${path} for backup"
    chmod --reference="$path" "$backup" 2>/dev/null || true
    chown --reference="$path" "$backup" 2>/dev/null || true
    log "backed up ${path} to ${backup}"
else
    log "no existing ${path}; a rollback will remove what we install"
fi

# ── commit. `mv` is the atomic replace: it publishes a NEW inode, so a
#    concurrent sudo/sshd reads either the old file or the new one and never a
#    truncated one. `install -m ... src dst` does NOT: it opens the destination
#    in place, so the inode is unchanged and the destination IS rewritten in
#    place. Mode and owner are set on the temp file BEFORE the rename, so the
#    file is never visible at the target path with the wrong mode.
commit_started=1
chmod "$mode" "$tmp" || die "could not set mode ${mode} on ${tmp}"
chown root:root "$tmp" || die "could not set root:root on ${tmp}"
mv -f -- "$tmp" "$path" || die "could not commit ${path}"
tmp=""   # consumed by the rename; nothing left to clean up

# ── readback is the verdict, not the exit status: prove the bytes on disk are
#    the bytes we received and validated. sha256sum, not cmp(1): cmp is from
#    diffutils, absent from the base install, and a missing cmp made every
#    save fail closed.
installed_sum="$(sha256sum -- "$path" | cut -d' ' -f1)" || die "could not read back ${path}"
if [[ "$installed_sum" != "$payload_sum" ]]; then
    log "readback mismatch on ${path}: installed ${installed_sum}, received ${payload_sum}"
    exit 1
fi
actual_mode="$(stat -c %a "$path")" || die "could not stat ${path}"
[[ "$actual_mode" == "${mode#0}" ]] || {
    log "readback mode is ${actual_mode}, expected ${mode#0}"
    exit 1
}
[[ "$(stat -c %U "$path")" == root ]] || {
    log "readback owner is not root"
    exit 1
}
log "installed ${target} -> ${path} (mode ${actual_mode}, readback verified)"

# ── the LIVE check, second pass, judged against the baseline taken above.
#    exports has no per-file syntax check at all, so its verdict only exists
#    here. The settle delay is exportfs' own cache settling after our change
#    (a race against mountd, not a synchronisation) - the baseline needs no
#    settle, because nothing had changed yet when it was taken.
if [[ ${#POST_VALIDATOR_CMD[@]} -gt 0 ]]; then
    # String comparison, not (( )): POST_SETTLE is 0.3 for exports, and bash
    # arithmetic cannot parse a float -- (( POST_SETTLE > 0 )) raised
    # "syntax error: invalid arithmetic operator" and silently took the false
    # branch, so the settle never happened at all.
    if [[ -n "$POST_SETTLE" && "$POST_SETTLE" != "0" ]]; then sleep "$POST_SETTLE"; fi
    log "checking the live config with '${POST_VALIDATOR_CMD[*]}'"
    run_live_check
    if [[ -n "$live_out" ]]; then printf '%s\n' "$live_out" >&2; fi

    # Two ways to have made the live config worse: a complaint the baseline
    # did not have, or a check that used to pass and now does not (a failure
    # that prints nothing new is still a failure we introduced).
    if [[ "$(significant_lines "$live_out")" == "$(significant_lines "$baseline_out")" ]] \
        && ! (( live_rc != 0 && baseline_rc == 0 )); then
        log "the live config gained no new complaint; the change is accepted"
    else
        log "the change introduced a NEW complaint in the live config; rolling back"
        if [[ -n "$baseline_out" ]]; then
            log "the baseline it must not have made worse was:"
            printf '%s\n' "$baseline_out" >&2
        fi
        exit 1
    fi
fi

# ── committed: clear the rollback so a later unrelated failure cannot undo a
#    good install.
committed=1
trap - EXIT
rm -f -- "$backup" 2>/dev/null || true
if [[ -n "$probe" ]]; then rm -f -- "$probe" 2>/dev/null || true; fi
exit 0
