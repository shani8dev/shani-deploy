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
        # systemd reads /etc/modules-load.d/*.conf in lexical order and the
        # number is only for ordering, so 50- sits after nothing and before any
        # future 90- override - the same convention as the other drop-ins.
        modules_load)      printf '/etc/modules-load.d/50-shani-kvm.conf' ;;
        # modprobe.d is read by kmod itself, in lexical order, for every
        # modprobe call on the machine - it is the same drop-in shape as
        # modules-load.d above and needs no package to create the directory.
        modprobe_blacklist) printf '/etc/modprobe.d/50-shani-blacklist.conf' ;;
        # Samba's include drop-in, read in lexical order. The 50- puts it after
        # any 00- a package ships and before a future 90- override. This path
        # only works because shani-settings ships a comment-only
        # 00-shani-readme.conf, so the directory exists: this script refuses to
        # create a target's parent, on the grounds that creating one would be a
        # second privileged act and not its business. Deliberately NOT the file
        # shani-settings ships - pacman replaces a shipped file, which would
        # delete every share a user had created.
        smb_share)          printf '/etc/samba/smb.conf.d/50-shani-cassini.conf' ;;
        # /etc/hosts is the static name table. The drop-in convention does not
        # apply here - there is no include mechanism for hosts - so this is a
        # direct write to the one file, the same shape as subject_mapping above.
        # Mode 0644: hosts is world-readable by design, every resolver reads it.
        hosts)              printf '/etc/hosts' ;;
        # Three files that have NO drop-in mechanism and NO validator of their
        # own. See target_validators for why they are here at all despite the
        # "drop-ins only" rule above.
        subject_mapping)   printf '/etc/pam_pkcs11/subject_mapping' ;;
        pam_yubico)        printf '/etc/security/pam_yubico.conf' ;;
        krb5_conf)         printf '/etc/krb5.conf' ;;
        # irqbalance's whole configuration surface. The package ships NO /etc
        # directory at all - it ships usr/share/irqbalance/irqbalance.env and
        # reads that plus an optional /etc/default/irqbalance (verified: the
        # unit carries both EnvironmentFile= lines, the second with the `-`
        # prefix). So this file is entirely ours to create, which is why it is a
        # Cassini-owned target rather than an edit of something already there.
        irqbalance_env)    printf '/etc/default/irqbalance' ;;
        # NUT's upsmon.conf, the shutdown policy. This is a DIRECTIVE file
        # (KEY value, no '=' and no sections) - a different shape from the
        # INI-like ups.conf and upsd.users beside it, which the validator for
        # each one parses in its own format rather than one parser for both.
        nut_upsmon_conf)   printf '/etc/nut/upsmon.conf' ;;
        nut_ups_conf)      printf '/etc/nut/ups.conf' ;;
        *)                 return 1 ;;
    esac
}

target_mode() {
    case "$1" in
        # sudo refuses to read a group/world-writable sudoers file.
        sudoers)           printf '0440' ;;
        sshd_config)       printf '0644' ;;
        exports)           printf '0644' ;;
        modules_load)      printf '0644' ;;
        modprobe_blacklist) printf '0644' ;;
        smb_share)          printf '0644' ;;
        hosts)              printf '0644' ;;        # subject_mapping holds a subject-to-login mapping; 0600 because it is
        # a principal list and nothing needs to read it but root. The mode the
        # shipped file already has is preserved by the read-back check, so a
        # number here that disagrees shows up rather than silently changing it.
        subject_mapping)   printf '0600' ;;
        pam_yubico)        printf '0644' ;;
        krb5_conf)         printf '0644' ;;
        irqbalance_env)    printf '0644' ;;
        nut_upsmon_conf)   printf '0644' ;;
        nut_ups_conf)      printf '0644' ;;
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
        # modules-load.d has no validator of its own - systemd-modules-load has
        # no check mode, and nothing else claims to judge the file. So the
        # answer to "would this module load?" is asked of modprobe, which owns
        # module resolution and will say no rather than warn.
        #
        # PRE takes the staged file and checks every module named in it, so a
        # typo never reaches the target. POST re-checks the LIVE installed file
        # the same way, which is what makes it a live check rather than a
        # repeat of the pre-check: it runs after the commit and against what
        # systemd will actually read at boot.
        modules_load)
            # **`$0`, not `$PROG`.** The other validators are external tools
            # found on PATH, so a bare name is right for them. This one is a
            # self-reference, and `$PROG` is `${0##*/}` - the bare name - which
            # `command -v` cannot resolve because the program is not on PATH. The
            # first version used `$PROG` and every save was refused with
            # "shani-cassini-save is not installed; refusing to save
            # modules_load unvalidated": the fail-closed check below ran before
            # the validator ever did, so the target existed and was still
            # unusable. `$0` is the path this script was actually started from.
            PRE_VALIDATOR_CMD=("$0" --check-modules-load)
            POST_VALIDATOR_CMD=("$0" --check-modules-load-live)
            ;;
        # modprobe.d has no check mode either, and modprobe cannot answer
        # "is this file valid" - it answers "can you load this name", which is
        # the wrong question here. A blacklist names modules that must NOT
        # load, so refusing a name modprobe cannot resolve would be backwards:
        # the entries a user most wants are frequently ones the running kernel
        # no longer carries. So this target is checked structurally instead,
        # which is a real parse of the format rather than a grep.
        modprobe_blacklist)
            PRE_VALIDATOR_CMD=("$0" --check-modprobe-blacklist)
            POST_VALIDATOR_CMD=("$0" --check-modprobe-blacklist-live)
            ;;
        # Samba's own parser is the authority here, not a second opinion of it.
        # `testparm -s <file>` parses a file and exits non-zero on a syntax
        # error, so the staged fragment is checked before install — and a
        # fragment of nothing but `[share]` stanzas IS a valid smb.conf, so the
        # same command that validates the whole file validates the piece.
        #
        # The POST check is the stronger one and is why this target is worth
        # having at all: bare `testparm -s` parses the LIVE /etc/samba/smb.conf,
        # which now *includes* this drop-in. So it proves the include line is
        # actually wired and Samba accepts the stanza in context — a fragment
        # that parses on its own can still be rejected by the file that
        # includes it (a section redefined by an earlier include, say).
        #
        # It does NOT prove the share works. `testparm` parses; it does not
        # bind, authenticate, or check that `path` exists or is reachable. A
        # save proves only that Samba accepted the text.
        smb_share)
            PRE_VALIDATOR_CMD=(testparm -s)
            POST_VALIDATOR_CMD=(testparm -s)
            ;;
        # ── the three files with no validator of their own ──────────────────
        #
        # **The "drop-ins only" rule above does not apply here, and pretending
        # otherwise would be worse than the problem.** pam_pkcs11's
        # subject_mapping, pam_yubico.conf and krb5.conf have no include
        # mechanism, so there is no drop-in to move the risk into - writing
        # them is a main-file write whichever route it takes.
        #
        # They are here because the alternative was worse: `config_io`'s
        # `write_staged_privileged` runs `pkexec install` over a temp file the
        # CALLER owns in a directory the CALLER owns. That is a
        # wait-for-root-to-read-my-file window, and it has no polkit rule, so it
        # falls through to admin auth for a generic `install`. Content on stdin
        # removes the window by removing the name - the caller proposes, the
        # helper decides.
        #
        # So the validator is the same shape as modules_load's: this script
        # checks the file itself, because no consuming tool offers a check
        # mode. **That is a weaker guarantee than `visudo -c` and it is stated
        # as such** - what is enforced is "parses as the format it claims, with
        # the sections it had before", not "the PAM stack accepts it". Nobody
        # can check the second thing, and a validator that implied otherwise
        # would be worse than an honest structural one.
        subject_mapping)
            PRE_VALIDATOR_CMD=("$0" --check-subject-mapping)
            POST_VALIDATOR_CMD=("$0" --check-subject-mapping-live)
            ;;
        pam_yubico)
            PRE_VALIDATOR_CMD=("$0" --check-pam-yubico)
            POST_VALIDATOR_CMD=("$0" --check-pam-yubico-live)
            ;;
        krb5_conf)
            PRE_VALIDATOR_CMD=("$0" --check-krb5-conf)
            POST_VALIDATOR_CMD=("$0" --check-krb5-conf-live)
            ;;
        # An EnvironmentFile, parsed by SYSTEMD - not by a shell. That
        # distinction is the whole validator: /etc/default/* is the one place a
        # file that looks like shell is not read by one, so a bash-shaped
        # check would approve things systemd refuses.
        #
        # IRQBALANCE_ARGS is deliberately NOT an allowed key here, and that is
        # the interesting part rather than an omission. The unit's line is
        # `ExecStart=/usr/sbin/irqbalance $IRQBALANCE_ARGS` - UNQUOTED - and
        # systemd.service(5) says a `$FOO` word "will be erased and replaced by
        # the exact value of the environment variable (if any) including all
        # whitespace it contains, always resulting in exactly a single
        # argument". Only `"$FOO"` splits on whitespace. So a value of
        # `--banirq=3 --banmod=foo` reaches the daemon as ONE argument and is
        # rejected as an unknown flag. Accepting that key here would let a save
        # succeed and leave the daemon refusing its own command line - config
        # that reads as applied and is not.
        irqbalance_env)
            PRE_VALIDATOR_CMD=("$0" --check-irqbalance-env)
            POST_VALIDATOR_CMD=("$0" --check-irqbalance-env-live)
            ;;
        nut_upsmon_conf)
            PRE_VALIDATOR_CMD=("$0" --check-nut-upsmon-conf)
            POST_VALIDATOR_CMD=("$0" --check-nut-upsmon-conf-live)
            ;;
        # /etc/hosts has no validator of its own. Check structurally: every
        # non-blank, non-comment line must start with an IP address (IPv4 or
        # IPv6) followed by at least one name.
        hosts)
            PRE_VALIDATOR_CMD=("$0" --check-hosts)
            POST_VALIDATOR_CMD=("$0" --check-hosts-live)
            ;;
        *)                 return 1 ;;
    esac
}

usage() {
    cat >&2 <<EOF
usage: $PROG --target <sudoers|sshd_config|exports|modules_load|modprobe_blacklist|smb_share|subject_mapping|pam_yubico|krb5_conf|irqbalance_env|nut_upsmon_conf|nut_ups_conf|hosts> [--expect-sha256 <64-hex>] < content

Reads the new content from stdin and installs it over one known target, after
validating it. The content is never taken from a caller-named path.
EOF
    exit 2
}

log() { printf '%s: %s\n' "$PROG" "$*" >&2; }
die() { log "REFUSING: $*"; exit 1; }

# ── the modules-load validator ───────────────────────────────────────────────
# Reached as `$PROG --check-modules-load <file>` (pre) or
# `$PROG --check-modules-load-live` (post), because modules-load.d has no
# validator of its own and modprobe is the only thing that knows whether a
# module exists for the running kernel.
#
# The rules being enforced are systemd's, not this script's: blank lines and
# `#` comments are ignored, and everything else is a module name.
# `modprobe --show-depends` resolves the name the way a real load would and
# exits non-zero for a name this kernel cannot provide - which is the answer
# worth refusing on, because a modules-load.d line that cannot resolve is
# silently ignored at boot and the user is left believing a module loaded.
#
# `command -v modprobe` is checked first: fail closed, never "warn and write".
check_modules_load_file() {
    local file="$1" where="$2" module seen=0
    [[ -f "$file" ]] || { printf '%s: no such file: %s\n' "$PROG" "$file" >&2; return 1; }
    while IFS= read -r module || [[ -n "$module" ]]; do
        module="${module%%#*}"
        module="${module#"${module%%[![:space:]]*}"}"
        module="${module%"${module##*[![:space:]]}"}"
        [[ -n "$module" ]] || continue
        seen=1
        if ! out="$(modprobe --show-depends -- "$module" 2>&1)"; then
            printf '%s: %s: cannot load module %s: %s\n' \
                "$PROG" "$where" "$module" "${out//$'\n'/ }" >&2
            return 1
        fi
    done < "$file"
    if (( seen == 0 )); then
        printf '%s: %s: names no modules at all, so it would do nothing\n' \
            "$PROG" "$where" >&2
        return 1
    fi
    return 0
}


# ── the modprobe.d blacklist validator ────────────────────────────────────────
# Reached as `$PROG --check-modprobe-blacklist <file>` (pre) or
# `$PROG --check-modprobe-blacklist-live` (post).
#
# **`modprobe -R` is deliberately NOT used here, and the reason is the whole
# point of the difference from modules_load.** check_modules_load_file refuses a
# name `modprobe` cannot resolve, because a modules-load.d line that names
# nothing loadable is silently ignored at boot. A blacklist is the inverse: it
# names modules that must NOT be loaded, and the entries a user most wants are
# routinely ones the running kernel does not currently carry (a driver for
# hardware not plugged in, a module already replaced). Refusing those would make
# the one save that is always available - the one that removes a last entry -
# the one that fails.
#
# So this is a STRUCTURAL check: every effective line must be exactly
# `blacklist <name>`. Anything else in the file is refused, because a directive
# this page never writes is either a mistake or something that would silently
# do something the user did not ask for.
#
# **An empty file is valid, and deliberately so.** check_modules_load_file
# refuses a file that "names no modules at all"; copying that rule here would
# break the ordinary case of removing the last blacklisted module, because the
# result of that removal IS an empty file. An empty (or comment-only) drop-in
# blacklists nothing, which is exactly what the user asked for.
#
# The name charset is module names only: no wildcards, no paths, no spaces. kmod
# would accept a wildcard in `blacklist`, but this page never writes one and a
# file that cannot be rendered back to a list is a file Cassini would then be
# unable to display honestly.
check_modprobe_blacklist_file() {
    local file="$1" where="$2" line lineno=0 name
    [[ -f "$file" ]] || { printf '%s: no such file: %s\n' "$PROG" "$file" >&2; return 1; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        # **Not `(( lineno++ ))`.** Under this file's `set -e` a bare
        # post-increment aborts the script when the variable is 0, because
        # `(( 0++ ))` evaluates to the PRE-increment value and 0 is falsy.
        # The effect is a validator that rejects every non-empty file and
        # reports nothing at all - this file already records the same defect
        # for `((issues++))` and `((format_count++))`, both fixed the same way.
        lineno=$(( lineno + 1 ))
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        if [[ "$line" != blacklist\ * ]]; then
            printf '%s: %s line %d: only "blacklist MODULE" lines are allowed here, got: %s\n' \
                "$PROG" "$where" "$lineno" "$line" >&2
            return 1
        fi
        name="${line#blacklist }"
        name="${name#"${name%%[![:space:]]*}"}"
        name="${name%"${name##*[![:space:]]}"}"
        if [[ ! "$name" =~ ^[A-Za-z0-9_-]+$ ]]; then
            printf '%s: %s line %d: not a module name: %s\n' \
                "$PROG" "$where" "$lineno" "$name" >&2
            return 1
        fi
    done < "$file"
    return 0
}


# ── the three structural validators ──────────────────────────────────────────
#
# Each is a real parse of the format, not a grep. They exist because no
# consuming tool offers a check mode (see target_validators), so "will this
# parse" is the strongest question anybody can actually ask about these files.
# **What that means, precisely:** these prove the file is well-formed and, for
# the two INI formats, that the sections present before are still present
# afterwards. They do NOT prove PAM or Kerberos will accept the values, because
# nothing can check that without the whole stack.

# NUT's config files. The key lists come from NUT's own documentation rather than
# from guesswork, and the two shapes are parsed separately: upsmon.conf and
# upsd.conf are DIRECTIVE files (`KEY value`), while ups.conf and upsd.users are
# INI-like (`[section]` then `key = value`). Writing one format's parser for the
# other file is exactly the mistake the apcupsd validator once made - it inherited
# KEY=VALUE from the systemd EnvironmentFile target beside it and refused
# apcupsd's real file on its first live line.
#
# **The validator's real job is refusing a value that would make the daemon do
# the wrong thing silently**, not catching a syntax error. MINSUPPLIES 0, a
# 5-field MONITOR line, or an unquoted SHUTDOWNCMD are each accepted by NUT as
# syntactically fine and then never fire - the machine keeps running until the
# UPS dies and nothing reports a complaint, which is why each is checked.
# /etc/default/irqbalance - read by SYSTEMD, not by a shell.
#
# systemd's EnvironmentFile= parser is not bash, so a bash-shaped check would
# approve lines systemd refuses. What systemd does: strip a leading `export`,
# take everything up to the first `=` as the key, and the rest verbatim. It does
# NOT word-split, does NOT do command substitution, and does NOT honour quotes
# the way a shell does - so a value containing `$(...)` is a literal string, and
# a value containing whitespace is a literal string with whitespace in it.
#
# The allowed keys are the ones measured out of the shipped binary's own strings
# (`strings /usr/sbin/irqbalance | grep IRQBALANCE_`) plus the shipped
# usr/share/irqbalance/irqbalance.env: BANNED_CPULIST, BANNED_CPUS, ONESHOT,
# DEBUG, and ARGS.
#
# **ARGS is excluded, and that is the point rather than an oversight.** The unit
# line is `ExecStart=/usr/sbin/irqbalance $IRQBALANCE_ARGS` - UNQUOTED - and
# systemd.service(5) says a `$FOO` word "will be erased and replaced by the
# exact value of the environment variable (if any) including all whitespace it
# contains, always resulting in exactly a single argument"; only `"$FOO"` splits
# on whitespace into zero or more. So `IRQBALANCE_ARGS="--banirq=3
# --banmod=foo"` reaches the daemon as ONE argument and is rejected as an
# unknown flag. Accepting that key would let a save succeed and leave the daemon
# refusing its own command line - config that reads as applied and is not.
check_irqbalance_env_file() {
    local file="$1" where="$2" lineno=0 line key value
    [[ -f "$file" ]] || { printf '%s: no such file: %s\n' "$PROG" "$where" >&2; return 1; }
    local allowed=" IRQBALANCE_BANNED_CPULIST IRQBALANCE_BANNED_CPUS IRQBALANCE_ONESHOT IRQBALANCE_DEBUG IRQBALANCE_ARGS "
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$(( lineno + 1 ))
        line="${line#"${line%%[![:space:]]*}"}"
        [[ "$line" == \#* || -z "$line" ]] && continue
        [[ "$line" == *=* ]] || {
            printf '%s: %s line %s: not KEY=value: %s\n' "$PROG" "$where" "$lineno" "$line" >&2
            return 1; }
        key="${line%%=*}"; value="${line#*=}"
        # systemd strips a leading `export` itself.
        key="${key#export }"
        key="${key%"${key##*[![:space:]]}"}"
        value="${line#*=}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        # A quoted empty value is empty. systemd strips the quotes before it
        # expands the variable, so `IRQBALANCE_ARGS=""` is the shipped state and
        # must be allowed - comparing the raw text would call it non-empty,
        # because `""` is two characters.
        local unquoted="${value%\"}"; unquoted="${unquoted#\"}"
        # **Only a NON-empty value is refused.** The shipped
        # usr/share/irqbalance/irqbalance.env contains `IRQBALANCE_ARGS=""`, so
        # refusing the key outright refuses the distribution's own default file -
        # which is what the first version of this check did, and it was found by
        # running the validator against that file rather than against fixtures.
        # An empty value expands to nothing useful and is the shipped state; a
        # non-empty one is the single-argument bug described above.
        if [[ "$key" == "IRQBALANCE_ARGS" && -n "$unquoted" ]]; then
            printf '%s: %s line %s: IRQBALANCE_ARGS is refused here.\n' "$PROG" "$where" "$lineno" >&2
            printf '  The unit line is ExecStart=...irqbalance $IRQBALANCE_ARGS - unquoted, and systemd\n' >&2
            printf '  passes $VAR as exactly ONE argument, so a value holding two flags reaches the\n' >&2
            printf '  daemon as a single unrecognised option. Bans go on the command line instead.\n' >&2
            return 1
        fi
        # ARGS is allowed when empty, so it must be in the allowed set too.
        [[ "$allowed " == *" $key "* ]] || {
            printf '%s: %s line %s: %s is not a setting irqbalance 1.9.5 reads\n' "$PROG" "$where" "$lineno" "$key" >&2
            return 1; }
        case "$key" in
            IRQBALANCE_BANNED_CPULIST|IRQBALANCE_BANNED_CPUS)
                # A CPU list: 0, 0-3, 0,2,4 or 0-3,5,7-8. Anything else would be
                # silently ignored by the daemon's own parser.
                [[ "$value" =~ ^([0-9]+(-[0-9]+)?)(,[0-9]+(-[0-9]+)?)*$ ]] || {
                    printf '%s: %s line %s: %s wants a CPU list like 0-3 or 0,2,4, not %s\n' \
                        "$PROG" "$where" "$lineno" "$key" "${value:-<empty>}" >&2; return 1; }
                ;;
            IRQBALANCE_ONESHOT|IRQBALANCE_DEBUG)
                [[ "$value" == 0 || "$value" == 1 ]] || {
                    printf '%s: %s line %s: %s is 0 or 1, not %s\n' \
                        "$PROG" "$where" "$lineno" "$key" "${value:-<empty>}" >&2; return 1; }
                ;;
        esac
    done < "$file"
    return 0
}


NUT_UPSMON_CONF="/etc/nut/upsmon.conf"
NUT_UPS_CONF="/etc/nut/ups.conf"
IRQBALANCE_ENV="/etc/default/irqbalance"

check_nut_upsmon_conf() {
    local file="$1" where="$2" lineno=0 line key value rest
    [[ -f "$file" ]] || { printf '%s: no such file: %s\n' "$PROG" "$where" >&2; return 1; }

    # upsmon.conf is a DIRECTIVE file: `KEY value`, one per line, NO `=` and NO
    # sections. That is a different shape from ups.conf and upsd.users beside it,
    # which are INI-like `[section]` files - and assuming one format for the other
    # is exactly how the previous apcupsd validator came to refuse its real file
    # (it inherited KEY=VALUE from the systemd EnvironmentFile target). So these
    # two validators parse the shape each real file actually has.
    # NUT accepts a quoted value as readily as a bare one, and its own shipped
    # file uses the quoted form - `POWERDOWNFLAG "/etc/killpower"` is line 319 of
    # Arch's upsmon.conf and is live. The first version of this validator
    # demanded a bare path and refused that real file on its first live
    # directive, so quotes are stripped before any value is judged. Found by
    # running the validator against the file the distribution ships rather than
    # against a fixture written from what the docstring says.
    _unquote() { local v="$1"; v="${v%\"}"; v="${v#\"}"; printf '%s' "$v"; }

    local known=" ALARM ALARMCRITICAL CERTHOST CERTIDENT CERTPATH CERTVERIFY COMMBAD COMMOK \
DEBUG DEADTIME EXEC FINALDELAY FORCESSL FSD HOSTSYNC IGNORE LOWBATT MINSUPPLIES MONITOR \
NOCOMM NOCOMMWARNTIME NOPARENT NOTE NOTIFY NOTIFYCMD NOTIFYFLAG NOTIFYMSG OBLBDURATION \
OFFDURATION ONBATT ONLINE OVERDURATION POLLFAIL POLLFREQ POLLFREQALERT POWERDOWNFLAG \
RBWARNTIME REPLBATT RUN SHUTDOWN SHUTDOWNCMD SHUTDOWNEXIT SYSLOG UPS WALL WARNING "

    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$(( lineno + 1 ))
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue

        key="${line%%[[:space:]]*}"
        value="${line#"$key"}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"

        [[ " $known " == *" $key "* ]] || {
            printf '%s: %s line %s: %s is not a setting upsmon reads (refusing; a typo\n' \
                "$PROG" "$where" "$lineno" "$key" >&2
            printf '  in a key name silently disables the setting it was meant to be)\n' >&2
            return 1; }

        case "$key" in
            MONITOR)
                # MONITOR <system> <powervalue> <username> <password> ("primary"|"secondary")
                # The arity is the load-bearing part: a short line is accepted by
                # upsmon as a syntax error and the UPS is silently never monitored.
                read -r _sys _pv _user _pass role rest <<<"$value"
                [[ -n "$rest" ]] && {
                    printf '%s: %s line %s: MONITOR takes 6 fields (system powervalue user password master|slave)\n' \
                        "$PROG" "$where" "$lineno" >&2
                    return 1; }
                [[ "$role" == "master" || "$role" == "secondary" ]] || {
                    printf '%s: %s line %s: MONITOR role must be master or secondary, got %s\n' \
                        "$PROG" "$where" "$lineno" "${role:-<empty>}" >&2
                    return 1; }
                [[ -n "$_pv" ]] || {
                    printf '%s: %s line %s: MONITOR needs a power value\n' "$PROG" "$where" "$lineno" >&2
                    return 1; }
                ;;
            MINSUPPLIES)
                # How many supplies must be on battery before shutdown starts. 0
                # is accepted by upsmon but means nothing can ever trigger it, so
                # it is refused rather than written as a policy that cannot fire.
                [[ "$value" =~ ^[0-9]+$ ]] || {
                    printf '%s: %s line %s: MINSUPPLIES must be a whole number, got %s\n' \
                        "$PROG" "$where" "$lineno" "$value" >&2; return 1; }
                (( value >= 1 )) || {
                    printf '%s: %s line %s: MINSUPPLIES 0 means no supply can ever trigger shutdown\n' \
                        "$PROG" "$where" "$lineno" >&2; return 1; }
                ;;
            POLLFREQ|POLLFREQALERT|DEADTIME|FINALDELAY|HOSTSYNC|RBWARNTIME|NOCOMMWARNTIME|OVERDURATION|OBLBDURATION|OFFDURATION)
                # A leading '-' is legal and meaningful: OVERDURATION's NUT
                # default is -1, and nut.conf's own text says a negative value
                # means that condition "will never be considered critical".
                # The first version of this check required an unsigned integer
                # and therefore refused NUT's own default - found by running it
                # against the shipped file, which is exactly why the test does
                # that instead of against a fixture.
                [[ "$(_unquote "$value")" =~ ^-?[0-9]+$ ]] || {
                    printf '%s: %s line %s: %s must be a whole number of seconds (a negative is allowed and means "never"), got %s\n' \
                        "$PROG" "$where" "$lineno" "$key" "$value" >&2; return 1; }
                ;;
            SHUTDOWNCMD)
                # A command, quoted. An unquoted one is still valid to upsmon but
                # only as far as its first word, so the rest of the intended
                # command would be arguments upsmon never sees.
                [[ "$value" == \"*\" ]] || {
                    printf '%s: %s line %s: SHUTDOWNCMD must be quoted (unquoted, only its\n' \
                        "$PROG" "$where" "$lineno" >&2
                    printf '  first word is a command and the rest become arguments nothing reads)\n' >&2
                    return 1; }
                ;;
            POWERDOWNFLAG)
                [[ "$(_unquote "$value")" == /* ]] || {
                    printf '%s: %s line %s: POWERDOWNFLAG must be an absolute path\n' \
                        "$PROG" "$where" "$lineno" >&2; return 1; }
                ;;
        esac
    done < "$file"
    return 0
}

check_nut_ups_conf() {
    local file="$1" where="$2" lineno=0 line in_section=0 key value section
    [[ -f "$file" ]] || { printf '%s: no such file: %s\n' "$PROG" "$where" >&2; return 1; }

    # ups.conf is INI-like: a `[name]` header, then `key = value` pairs. NO
    # device section is shipped by shani-settings, and that is deliberate - what
    # fills one in is `nut-scanner -U`, not a default describing a UPS that is
    # not there. So this validator checks a section a user DID add, and an empty
    # file is a valid, expected state, not an error.
    # The driver check below is DERIVED from the filesystem rather than listed.
    # NUT 2.8.5 ships 73 driver binaries under /usr/lib/nut, and the first
    # version of this validator hand-kept 48 of them - which refused 25 real
    # drivers, including `apcupsd-ups`: the bridge to apcupsd-controlled hardware,
    # and the whole reason apcupsd is still installed. It also misspelled
    # `gamatronic` as `gematronic`. A hand-kept list of another project's
    # binaries is wrong the moment upstream adds a driver, and wrong in the
    # direction of refusing a configuration that would have worked.
    local keys=" driver port desc maxretry sdorder community synchronous nohang \
offdelay ondelay pollinterval "

    # Global directives are legal BEFORE the first section and apply to every
    # device (NUT's own: chroot, driverpath, maxstartdelay, maxretry,
    # retrydelay, pollinterval, synchronous). Requiring a section first would
    # refuse the file this repo ships, which has exactly one such line - found by
    # running the validator against the real ups.conf rather than against a
    # fixture.
    local globals=" chroot driverpath maxstartdelay maxretry retrydelay pollinterval synchronous "

    section=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$(( lineno + 1 ))
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue

        if [[ "$line" == \[*\] ]]; then
            section="${line:1:${#line}-2}"
            # A device name becomes part of a path (`/var/state/ups/<name>`), so
            # it is confined to what cannot escape or collide.
            [[ "$section" =~ ^[A-Za-z0-9_.-]+$ ]] || {
                printf '%s: %s line %s: UPS name %s must be letters, digits, dot, dash or underscore\n' \
                    "$PROG" "$where" "$lineno" "$section" >&2; return 1; }
            in_section=1
            continue
        fi

        # A directive before any section is only valid if it is a global one.
        if (( ! in_section )); then
            _gkey="${line%%=*}"
            _gkey="${_gkey%"${_gkey##*[![:space:]]}"}"
            if [[ " $globals " != *" ${_gkey:-} "* ]]; then
                printf '%s: %s line %s: %s is outside any [section] and is not a global\n' \
                    "$PROG" "$where" "$lineno" "$line" >&2
                return 1
            fi
            continue
        fi

        [[ "$line" == *=* ]] || {
            printf '%s: %s line %s: expected key = value, got %s\n' "$PROG" "$where" "$lineno" "$line" >&2
            return 1; }
        key="${line%%=*}"; value="${line#*=}"
        key="${key%"${key##*[![:space:]]}"}"; value="${value#"${value%%[![:space:]]*}"}"

        [[ " $keys " == *" $key "* ]] || {
            printf '%s: %s line %s: %s is not a setting nut-driver reads\n' "$PROG" "$where" "$lineno" "$key" >&2
            return 1; }

        case "$key" in
            driver)
                # Derived, so it cannot refuse a driver this nut install can
                # actually run. NUT_DRIVER_DIR is an override for the tests and
                # defaults to the real path.
                if [[ ! -x "${NUT_DRIVER_DIR:-/usr/lib/nut}/$value" ]]; then
                    printf '%s: %s line %s: nut ships no driver named %s (nut-scanner -U\n' \
                        "$PROG" "$where" "$lineno" "$value" >&2
                    printf '  writes the one your hardware needs)\n' >&2
                    return 1
                fi
                ;;
            port)
                [[ -n "$value" ]] || {
                    printf '%s: %s line %s: port cannot be empty\n' "$PROG" "$where" "$lineno" >&2
                    return 1; }
                ;;
        esac
    done < "$file"
    return 0
}



# hosts: every non-blank, non-comment line must start with an IP address
# (IPv4 or IPv6) followed by at least one name. A line that does not is
# refused before anything is written.
check_hosts_file() {
    local file="$1" where="$2" lineno=0 line ip names
    [[ -f "$file" ]] || { printf '%s: %s: no such file: %s\n' "$PROG" "$where" "$file" >&2; return 1; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$(( lineno + 1 ))
        line="${line#"${line%%[![:space:]]*}"}"
        [[ "$line" == \#* || -z "$line" ]] && continue
        local body="$line"
        if [[ "$body" == *"#"* ]]; then
            body="${body%%#*}"
            body="${body%"${body##*[![:space:]]}"}"
        fi
        [[ -z "$body" ]] && continue
        read -r ip names <<< "$body"
        [[ -n "$ip" && -n "$names" ]] || {
            printf '%s: %s line %s: expected IP and at least one name: %s\n' \
                "$PROG" "$where" "$lineno" "$line" >&2; return 1; }
        if [[ "$ip" == *:* ]]; then
            [[ "$ip" == *:*:* ]] || {
                printf '%s: %s line %s: not a valid IPv6 address: %s\n' \
                    "$PROG" "$where" "$lineno" "$ip" >&2; return 1; }
        else
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
                printf '%s: %s line %s: not a valid IPv4 address: %s\n' \
                    "$PROG" "$where" "$lineno" "$ip" >&2; return 1; }
        fi
    done < "$file"
    return 0
}

# subject_mapping: one mapping per line, three whitespace-separated fields
# (subject, login, key). A line with the wrong arity is the failure that would
# silently drop a mapping at login time.
check_subject_mapping_file() {
    local file="$1" where="$2" n=0 field_count fields
    [[ -f "$file" ]] || { printf '%s: %s: no such file: %s\n' "$PROG" "$where" "$file" >&2; return 1; }
    local lineno=0 line
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno + 1))
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        read -r -a fields <<< "$line"
        field_count=${#fields[@]}
        if (( field_count != 3 )); then
            printf '%s: %s: line %d has %d fields, expected 3 (subject login key): %s\n' \
                "$PROG" "$where" "$lineno" "$field_count" "$line" >&2
            return 1
        fi
        n=$((n + 1))
    done < "$file"
    if (( n == 0 )); then
        printf '%s: %s: names no mappings at all\n' "$PROG" "$where" >&2
        return 1
    fi
    return 0
}

# _check_ini FILE WHERE MIN_SECTIONS
#   A shared INI parse for the two `key = value` formats. Enforces:
#     - a `[section]` header is well formed and closed by a newline;
#     - inside a section, every non-blank, non-comment line is `key = value`
#       or one of the include forms those formats legitimately carry;
#     - at least MIN_SECTIONS sections exist, so a write that flattened the file
#       to bare keys is refused rather than installed.
_check_ini() {
    local file="$1" where="$2" min_sections="${3:-1}"
    [[ -f "$file" ]] || { printf '%s: %s: no such file: %s\n' "$PROG" "$where" "$file" >&2; return 1; }
    local lineno=0 line sections=0 kv=0 depth=0 in_section=0

    # **krb5.conf is not plain INI, and the stock file proves it.** Arch's
    # /etc/krb5.conf ships this:
    #
    #     [realms]
    #     ATHENA.MIT.EDU = {
    #             admin_server = kerberos.mit.edu
    #     }
    #
    # A first version of this parse had no brace handling, so it refused the
    # stock file with "not a \"key = value\" line: }" — which meant the
    # baseline check failed on every real machine, so every krb5 save rolled
    # itself back. A validator that rejects a stock config is worse than no
    # validator: it disables the feature silently and plausibly.
    #
    # So the brace depth is tracked: `NAME = {` opens, `}` closes, and inside a
    # block only `key = value` is legal. pam_yubico.conf has no blocks and no
    # required section, which is what min_sections=0 means below.
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno + 1))
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] || continue
        [[ "$line" == \#* || "$line" == \;* ]] && continue

        if (( depth > 0 )); then
            if [[ "$line" == "}" ]]; then
                depth=0
                continue
            fi
            if [[ "$line" =~ ^[^=]+=[[:space:]]*.*$ ]]; then
                kv=$((kv + 1))
                continue
            fi
            printf '%s: %s: line %d: inside a block, only "key = value" is legal: %s\n' \
                "$PROG" "$where" "$lineno" "$line" >&2
            return 1
        fi

        if [[ "$line" == \[* ]]; then
            if [[ ! "$line" =~ ^\[[^]]+\]$ ]]; then
                printf '%s: %s: line %d: malformed section header: %s\n' \
                    "$PROG" "$where" "$lineno" "$line" >&2
                return 1
            fi
            sections=$((sections + 1))
            in_section=1
            continue
        fi

        # include / includedir, which krb5.conf carries and a plain INI parse
        # cannot represent - the page notes the same thing in _INCLUDE_RE.
        if [[ "$line" =~ ^([Ii]nclude|[Ii]ncludedir)[[:space:]] ]]; then
            continue
        fi

        # A realm block opener: `REALM = {` on its own line. krb5 also allows
        # `REALM = { kdc = x }` on one line, which the key=value branch below
        # accepts and which needs no depth tracking.
        if [[ "$line" =~ ^[^=]+=[[:space:]]*\{$ ]]; then
            depth=1
            continue
        fi

        if [[ "$line" =~ ^[^=]+=[[:space:]]*.*$ ]]; then
            # **A setting before any section header is a flattened file.**
            # The first version of this check accepted it, because the only
            # rejection left for an out-of-section line was the generic
            # "not a key = value" one - and `default_realm = X` IS a valid
            # key=value. So the one krb5 failure that matters most (a write
            # that dropped every `[section]`) sailed straight through.
            if (( in_section == 0 && min_sections > 0 )); then
                printf '%s: %s: line %d: a setting before any section, so every section was lost: %s\n' \
                    "$PROG" "$where" "$lineno" "$line" >&2
                return 1
            fi
            kv=$((kv + 1))
            continue
        fi

        # A setting outside any section is legal ONLY for the format that
        # declares sections optional (min_sections=0). kerberos refuses it
        # outright, because a bare key at the top of krb5.conf parses as
        # nothing and a write that produced one has lost every section.
        if (( min_sections > 0 )); then
            printf '%s: %s: line %d: a setting outside any section: %s\n' \
                "$PROG" "$where" "$lineno" "$line" >&2
            return 1
        fi
        printf '%s: %s: line %d: not a "key = value" line: %s\n' \
            "$PROG" "$where" "$lineno" "$line" >&2
        return 1
    done < "$file"

    if (( depth != 0 )); then
        printf '%s: %s: a { block was never closed with }\n' "$PROG" "$where" >&2
        return 1
    fi
    if (( sections < min_sections )); then
        printf '%s: %s: only %d section(s); this format needs at least %d, so the file was flattened\n' \
            "$PROG" "$where" "$sections" "$min_sections" >&2
        return 1
    fi
    if (( kv == 0 )); then
        printf '%s: %s: no settings at all, so it would configure nothing\n' \
            "$PROG" "$where" >&2
        return 1
    fi
    return 0
}

live=""
case "${1:-}" in
    --check-modules-load)
        [[ $# -ge 2 ]] || usage
        check_modules_load_file "$2" "the fragment"
        exit $? ;;
    --check-nut-upsmon-conf)     [[ $# -ge 2 ]] || usage; check_nut_upsmon_conf "$2" "the fragment"; exit $? ;;
    --check-nut-upsmon-conf-live)  check_nut_upsmon_conf "$NUT_UPSMON_CONF" "the installed upsmon.conf"; exit $? ;;
    --check-nut-ups-conf)        [[ $# -ge 2 ]] || usage; check_nut_ups_conf "$2" "the fragment"; exit $? ;;
    --check-nut-ups-conf-live)   check_nut_ups_conf "$NUT_UPS_CONF" "the installed ups.conf"; exit $? ;;
    --check-irqbalance-env)      [[ $# -ge 2 ]] || usage; check_irqbalance_env_file "$2" "the fragment"; exit $? ;;
    --check-irqbalance-env-live) check_irqbalance_env_file "$IRQBALANCE_ENV" "the installed /etc/default/irqbalance"; exit $? ;;
    --check-subject-mapping)      [[ $# -ge 2 ]] || usage; check_subject_mapping_file "$2" "the fragment"; exit $? ;;
    # **Absent is success, in every -live mode.** This check also runs as the
    # pre-change BASELINE, on a machine that has never had the drop-in, so the
    # file is not there yet. Treating that as an error makes the baseline red, so
    # the post-commit check looks like a NEW complaint and every save rolls
    # itself back - the target exists in the allowlist and still cannot be
    # written. modules_load had exactly this bug; three more copies of it were
    # added here, so it is fixed in all four places at once.
    --check-subject-mapping-live)
        live="$(target_path subject_mapping)"
        [[ -f "$live" ]] || exit 0
        check_subject_mapping_file "$live" "the live file"; exit $? ;;
    --check-hosts)               [[ $# -ge 2 ]] || usage; check_hosts_file "$2" "the fragment"; exit $? ;;
    --check-hosts-live)
        live="$(target_path hosts)"
        [[ -f "$live" ]] || exit 0
        check_hosts_file "$live" "the live file"; exit $? ;;
    --check-pam-yubico)           [[ $# -ge 2 ]] || usage; _check_ini "$2" "the fragment" 0; exit $? ;;
    --check-pam-yubico-live)
        live="$(target_path pam_yubico)"
        [[ -f "$live" ]] || exit 0
        _check_ini "$live" "the live file" 0; exit $? ;;
    --check-krb5-conf)            [[ $# -ge 2 ]] || usage; _check_ini "$2" "the fragment" 1; exit $? ;;
    --check-krb5-conf-live)
        live="$(target_path krb5_conf)"
        [[ -f "$live" ]] || exit 0
        _check_ini "$live" "the live file" 1; exit $? ;;
    --check-modules-load-live)
        command -v modprobe &>/dev/null \
            || { printf '%s: modprobe is not installed; cannot check\n' "$PROG" >&2; exit 1; }
        # Absent is success: this also runs as the pre-change baseline.
        live="$(target_path modules_load)"
        # **Absent is not a failure.** This check also runs as the BASELINE,
        # before anything is installed, and on a machine that has never had a
        # KVM drop-in the file is simply not there. Treating that as an error
        # made every save fail: the baseline was red, so the post-commit check
        # looked like a NEW complaint and rolled the install back - so the
        # target existed in the allowlist and still could not be written, which
        # is the same dead end the $PROG bug produced.
        #
        # So: no file means nothing to check, and that is success. The post
        # commit pass runs against the file that now exists, so it still
        # verifies the installed content.
        [[ -f "$live" ]] || exit 0
        check_modules_load_file "$live" "the live file"
        exit $? ;;
    --check-modprobe-blacklist)
        [[ $# -ge 2 ]] || usage
        check_modprobe_blacklist_file "$2" "the fragment"
        exit $? ;;
    --check-modprobe-blacklist-live)
        # Absent is success, for the same reason as every other -live mode:
        # this also runs as the pre-change BASELINE, on a machine that has
        # never had the drop-in, so the file is not there yet.
        live="$(target_path modprobe_blacklist)"
        [[ -f "$live" ]] || exit 0
        check_modprobe_blacklist_file "$live" "the live file"
        exit $? ;;
esac

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
