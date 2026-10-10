#!/usr/bin/env bash
# Inner half of tests/config-targets.sh — runs inside the container, against the
# real shani-cassini-save.sh.
#
# The shape is the same as modules-load-target-inner.sh: the real helper, real
# validators, and most of the assertions are about the check FAILING when it
# should. A structural validator that cannot say no is just a comment.
set -uo pipefail

H=/shani-cassini-save
PASS=0
FAIL=0
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }
no() { printf 'FAIL %s -- %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

mkdir -p /etc/pam_pkcs11 /etc/security

echo "  -- subject_mapping: one mapping per line, three fields --"

rm -f /etc/pam_pkcs11/subject_mapping
printf 'subject-one user1 0102030405060708090a0b0c0d0e0f1011121314\n' \
    | "$H" --target subject_mapping >/tmp/sm.log 2>&1
if [[ $? -eq 0 ]]; then ok "a well-formed mapping is accepted"; else no "well-formed accepted" "$(tail -2 /tmp/sm.log)"; fi
grep -q "subject-one" /etc/pam_pkcs11/subject_mapping 2>/dev/null \
    && ok "  and installed to /etc/pam_pkcs11/subject_mapping" || no "  installed" "missing"
perms=$(stat -c %a /etc/pam_pkcs11/subject_mapping 2>/dev/null)
[[ "$perms" == "600" ]] && ok "  mode 0600" || no "  mode 0600" "got $perms"

# NEGATIVE: two fields. A mapping with the wrong arity is silently dropped at
# login time, which is the failure this validator exists to prevent.
out=$(printf 'two-fields only\n' | "$H" --target subject_mapping 2>&1)
[[ $? -ne 0 ]] && ok "a line with 2 fields is refused" || no "2-field refused" "exit 0"
case "$out" in *"expected 3"*) ok "  and says the arity" ;; *) no "  says arity" "$out" ;; esac

out=$(printf 'a b c d\n' | "$H" --target subject_mapping 2>&1)
[[ $? -ne 0 ]] && ok "a line with 4 fields is refused" || no "4-field refused" "exit 0"

out=$(printf '# only a comment\n' | "$H" --target subject_mapping 2>&1)
[[ $? -ne 0 ]] && ok "a file with no mappings at all is refused" || no "empty refused" "exit 0"

# Comments and blank lines must be skipped, not counted as bad lines.
out=$(printf '# a comment\n\n   \nsub user 01\n' | "$H" --target subject_mapping 2>&1)
[[ $? -eq 0 ]] && ok "comments and blank lines are skipped" || no "comments skipped" "$out"

echo "  -- pam_yubico: INI, sections optional --"

rm -f /etc/security/pam_yubico.conf
printf 'authfile = /etc/security/pubring\n' | "$H" --target pam_yubico >/tmp/py.log 2>&1
[[ $? -eq 0 ]] && ok "a bare key = value file is accepted (sections are optional here)" || no "bare kv accepted" "$(tail -2 /tmp/py.log)"
grep -q "authfile" /etc/security/pam_yubico.conf 2>/dev/null && ok "  and installed" || no "  installed" "missing"

out=$(printf 'this line has no equals sign\n' | "$H" --target pam_yubico 2>&1)
[[ $? -ne 0 ]] && ok "a line with no '=' is refused" || no "no-equals refused" "exit 0"
case "$out" in *"key = value"*) ok "  and says what it wanted" ;; *) no "  says what" "$out" ;; esac

# An empty value IS accepted, and that is deliberate: `key =` is legal INI, and
# refusing it would require knowing which keys are meaningfully empty for each
# format - pam_u2f and pam_yubico both have keys where an empty value clears a
# previous setting. So the parse says nothing about the value, only the shape.
# The first version of this suite asserted a refusal here, which was my
# expectation and not the tool's behaviour.
out=$(printf 'authfile =\n' | "$H" --target pam_yubico 2>&1)
[[ $? -eq 0 ]] && ok "an empty value is accepted (shape, not meaning)" || no "empty value accepted" "$out"

printf '[pam_yubico]\nauthfile = /x\n' | "$H" --target pam_yubico >/dev/null 2>&1
[[ $? -eq 0 ]] && ok "a sectioned file is accepted" || no "sectioned accepted" "no"

out=$(printf '[unclosed\n' | "$H" --target pam_yubico 2>&1)
[[ $? -ne 0 ]] && ok "a malformed section header is refused" || no "bad header refused" "exit 0"

echo "  -- krb5_conf: the STOCK file is the test that matters --"

# Arch ships a krb5.conf with `REALM = { ... }` blocks. A validator with no
# brace handling refuses it, which makes the BASELINE check fail and every save
# roll itself back - the feature would be dead on every real machine while the
# suite stayed green on synthetic fixtures. So the stock file is asserted first.
out=$(/shani-cassini-save --check-krb5-conf-live 2>&1); rc=$?
[[ $rc -eq 0 ]] && ok "the STOCK /etc/krb5.conf parses (baseline must not fail)" || no "stock krb5.conf parses" "rc=$rc: $out"
printf '[libdefaults]\n    default_realm = ATHENA.MIT.EDU\n[realms]\n    ATHENA.MIT.EDU = {\n        kdc = kerberos.mit.edu\n        admin_server = kerberos.mit.edu\n    }\n' > /tmp/stock.conf
out=$(/shani-cassini-save --check-krb5-conf /tmp/stock.conf 2>&1); rc=$?
[[ $rc -eq 0 ]] && ok "a realm block with a NESTED setting is accepted" || no "nested realm block" "rc=$rc: $out"
out=$(printf '[realms]\n    ATHENA.MIT.EDU = {\n' | /shani-cassini-save --check-krb5-conf 2>&1); rc=$?
[[ $rc -ne 0 ]] && ok "an UNCLOSED realm block is refused" || no "unclosed block refused" "exit 0"
printf '[realms]\n    ATHENA.MIT.EDU = {\n    }\n    kdc = x\n' > /tmp/brace.conf
out=$(/shani-cassini-save --check-krb5-conf /tmp/brace.conf 2>&1); rc=$?
[[ $rc -eq 0 ]] && ok "a closing brace is not read as a setting" || no "closing brace handled" "$out"
out=$(printf '[realms]\n    ATHENA.MIT.EDU = {\n    notakeyvallue\n    }\n' | /shani-cassini-save --check-krb5-conf 2>&1); rc=$?
[[ $rc -ne 0 ]] && ok "prose INSIDE a realm block is refused" || no "prose in block refused" "exit 0"

echo "  -- krb5_conf: sections required, includes preserved --"

out=$(printf '[libdefaults]\ndefault_realm = EXAMPLE.COM\n' | "$H" --target krb5_conf >/tmp/k5.log 2>&1)
[[ $? -eq 0 ]] && ok "a well-formed krb5.conf is accepted" || no "krb5 accepted" "$(tail -2 /tmp/k5.log)"
grep -q "default_realm" /etc/krb5.conf 2>/dev/null && ok "  and installed to /etc/krb5.conf" || no "  installed" "missing"

# The flattening case, which is the one that matters for a main file: a write
# that reduced the whole file to bare keys has destroyed every section.
out=$(printf 'default_realm = EXAMPLE.COM\n' | "$H" --target krb5_conf 2>&1)
[[ $? -ne 0 ]] && ok "a FLATTENED krb5.conf (no sections) is refused" || no "flattened refused" "exit 0"
case "$out" in *"section was lost"*|*"flattened"*) ok "  and names the failure" ;; *) no "  names failure" "$out" ;; esac

printf '[libdefaults]\ninclude /etc/krb5.conf.d/foo.conf\ndefault_realm = X\n' > /tmp/incl.conf
out=$("$H" --check-krb5-conf /tmp/incl.conf 2>&1)
[[ $? -eq 0 ]] && ok "an include line is not parsed as a setting" || no "include accepted" "$out"
printf '[libdefaults]\nincludedir /etc/krb5.conf.d\ndefault_realm = X\n' > /tmp/incl2.conf
out=$("$H" --check-krb5-conf /tmp/incl2.conf 2>&1)
[[ $? -eq 0 ]] && ok "includedir is not parsed as a setting either" || no "includedir accepted" "$out"
# ...but a file that is ONLY an include does configure nothing, which IS a
# refusal - and that is the validator being right, not wrong.
out=$(printf '[libdefaults]\ninclude /etc/krb5.conf.d/foo.conf\n' | "$H" --target krb5_conf 2>&1)
[[ $? -ne 0 ]] && ok "an include-only file is refused (it configures nothing)" || no "include-only refused" "exit 0"

out=$(printf '[libdefaults]\nthis is prose not a setting\n' | "$H" --target krb5_conf 2>&1)
[[ $? -ne 0 ]] && ok "prose inside a section is refused" || no "prose refused" "exit 0"

out=$(printf 'default_realm = X\n[libdefaults]\n' | "$H" --target krb5_conf 2>&1)
[[ $? -ne 0 ]] && ok "a setting before any section header is refused" || no "setting outside section" "exit 0"

# A temp FILE, never /dev/stdin. The --check-* modes take a path and open it with
# `[[ -f "$file" ]]`, which is FALSE for a pipe, so every negative written as
# `printf ... | helper --check-x /dev/stdin` was refused for "no such file"
# rather than for the bad value - a control that passes without testing anything.
_f() { printf '%b' "$1" > /tmp/frag.conf; "$H" --check-"$2" /tmp/frag.conf 2>&1; }
echo "  -- nut_upsmon_conf: a DIRECTIVE file, not INI --"
# upsmon.conf is `KEY value` per line: no `=` and no [sections]. The file that
# really matters here is the one beside it: ups.conf and upsd.users are INI-like,
# so writing one format's parser for the other file is exactly the mistake the
# apcupsd validator once made - it inherited KEY=VALUE from the systemd
# EnvironmentFile target above and refused a file that has no `=` in it at all.
pacman -S --noconfirm --needed nut >/dev/null 2>&1
if [[ -f /etc/nut/upsmon.conf ]]; then
    out=$("$H" --check-nut-upsmon-conf /etc/nut/upsmon.conf 2>&1)
    [[ $? -eq 0 ]] && ok "the REAL Arch-shipped upsmon.conf passes" \
        || no "shipped upsmon.conf" "$out"
    # And the property that made it pass, asserted directly rather than assumed.
    n_eq=$(grep -cE '^[A-Z][A-Z0-9_]*=' /etc/nut/upsmon.conf || true)
    n_sp=$(grep -cE '^[A-Z][A-Z0-9_]+[[:space:]]' /etc/nut/upsmon.conf || true)
    [[ "$n_eq" == 0 ]] \
        && ok "the format really is KEY value ($n_eq with '=')" \
        || no "format" "$n_eq lines with '='"
else
    echo "  (nut not installable; those checks did not run)"
fi

# The MONITOR line has FIVE values after the key, and a short one is a syntax
# error to upsmon - so the UPS is never monitored and nothing says so.
out=$(_f 'MONITOR myups@localhost 1 monuser pw master\n' nut-upsmon-conf)
[[ $? -eq 0 ]] && ok "a complete MONITOR line is accepted" || no "complete MONITOR" "$out"
out=$(_f 'MONITOR myups@localhost monuser\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "a short MONITOR (3 values) is refused" || no "short MONITOR" "exit 0"
out=$(_f 'MONITOR myups@localhost 1 monuser pw bogus\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "a MONITOR with a bad role is refused" || no "bad role" "exit 0"

out=$(_f 'MINSUPPLIES 0\n' nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "MINSUPPLIES 0 is refused (nothing can trigger)" || no "MINSUPPLIES 0" "exit 0"
out=$(_f 'MINSUPPLIES many\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "a non-numeric MINSUPPLIES is refused" || no "non-numeric" "exit 0"
out=$(_f 'DEADTIME often\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "a non-numeric DEADTIME is refused" || no "DEADTIME text" "exit 0"
out=$(_f 'BOGUSKEY 1\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "an unknown directive is refused" || no "unknown key" "exit 0"
# Unquoted, only the first word is a command and the rest become arguments
# nothing reads - a shutdown that never happens.
out=$(_f 'SHUTDOWNCMD /sbin/shutdown -h now\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "an unquoted SHUTDOWNCMD is refused" || no "unquoted cmd" "exit 0"
out=$(_f 'POWERDOWNFLAG killpower\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "a relative POWERDOWNFLAG is refused" || no "relative flag" "exit 0"
# KEY = value is the OTHER format. Accepting it here would mean the parser has
# drifted into the INI shape and upsmon would read nothing.
out=$(_f 'MINSUPPLIES = 1\n' --check-nut-upsmon-conf)
[[ $? -ne 0 ]] && ok "KEY = value is refused (wrong format for this file)" || no "ini shape" "exit 0"
out=$(_f 'MINSUPPLIES 2\nDEADTIME 15\n' nut-upsmon-conf)
[[ $? -eq 0 ]] && ok "a valid policy fragment is accepted" || no "valid fragment" "$out"

echo "  -- nut_ups_conf: INI with [sections], and globals before them --"
out=$(_f '[myups]\n\tdriver = usbhid-ups\n\tport = auto\n' nut-ups-conf)
[[ $? -eq 0 ]] && ok "a nut-scanner-style section is accepted" || no "scanner section" "$out"
# maxretry is a GLOBAL directive, legal before any section. Requiring a section
# first refused the file this repo ships - found by running the validator against
# the real ups.conf rather than a fixture.
out=$(_f 'maxretry = 3\n[myups]\n\tdriver = usbhid-ups\n\tport = auto\n' nut-ups-conf)
[[ $? -eq 0 ]] && ok "a global before the first section is accepted" || no "global directive" "$out"
out=$(_f 'driver = usbhid-ups\n' --check-nut-ups-conf)
[[ $? -ne 0 ]] && ok "a non-global key outside a section is refused" || no "outside section" "exit 0"
out=$(_f '[myups]\n\tdriver = nosuchdriver\n\tport = auto\n' --check-nut-ups-conf)
[[ $? -ne 0 ]] && ok "an unknown driver is refused" || no "bad driver" "exit 0"
# A device name becomes part of a path (/var/state/ups/<name>), so it is confined.
out=$(_f '[../etc]\n\tdriver = usbhid-ups\n\tport = auto\n' --check-nut-ups-conf)
[[ $? -ne 0 ]] && ok "a path-escaping UPS name is refused" || no "escaping name" "exit 0"
out=$(_f '[myups]\n\tdriver = usbhid-ups\n\tport =\n' --check-nut-ups-conf)
[[ $? -ne 0 ]] && ok "an empty port is refused" || no "empty port" "exit 0"
# upsd.users is deliberately NOT a target: it holds the credential that can force
# a UPS power-down, generated per-install by shani-settings' hook.
if "$H" --check-nut-upsd-users /tmp/frag.conf >/dev/null 2>&1; then
    no "upsd.users target" "the credential file must not be editable"
else
    ok "upsd.users is not a save target (the credential is not editable)"
fi

echo "  -- irqbalance_env: systemd EnvironmentFile, and why ARGS is refused --"
out=$(_f 'IRQBALANCE_BANNED_CPULIST=0-3
' irqbalance-env)
[[ $? -eq 0 ]] && ok "a CPU list is accepted"          || no "CPU list" "$out"
out=$(_f 'IRQBALANCE_BANNED_CPUS=abc
' irqbalance-env)
[[ $? -ne 0 ]] && ok "a non-numeric CPU list is refused" || no "bad CPU list" "exit 0"
out=$(_f 'IRQBALANCE_ONESHOT=yes\n' --check-irqbalance-env)
[[ $? -ne 0 ]] && ok "ONESHOT=yes is refused"          || no "ONESHOT yes" "exit 0"
# The control for the whole reason this target refuses ARGS: the unit's line is
# unquoted, and systemd passes an unquoted $VAR as exactly ONE argument.
out=$(_f 'IRQBALANCE_ARGS=--banirq=3 --banmod=foo
' irqbalance-env)
[[ $? -ne 0 ]] && ok "IRQBALANCE_ARGS with flags is refused" || no "ARGS" "exit 0"
# ...and the shipped file sets it EMPTY, which must be allowed, or the
# distribution's own default is refused.
out=$(_f 'IRQBALANCE_ARGS=""
' irqbalance-env)
[[ $? -eq 0 ]] && ok 'an empty IRQBALANCE_ARGS is allowed (the shipped state)' \
    || no "empty ARGS" "$out"

echo "  -- the pre-existing targets are unchanged --"
for t in sudoers sshd_config exports modules_load nut_upsmon_conf nut_ups_conf irqbalance_env; do
    out=$(printf 'x\n' | "$H" --target "$t" 2>&1)
    case "$out" in
        *"unknown target"*) no "  $t still known" "it vanished from the allowlist" ;;
        *) ok "  $t still known" ;;
    esac
done

echo "  ---- $PASS passed / $FAIL failed"
printf 'SUITE pass=%d fail=%d\n' "$PASS" "$FAIL"
[[ $FAIL -eq 0 ]]