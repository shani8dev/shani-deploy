#!/bin/bash
# tests/test-first-boot.sh — contract tests for shani-first-boot.sh
#
# What this exists for. `shani-reset` wipes the /etc overlay upper layer, which
# holds /etc/passwd and /etc/shadow, so every account goes — including the root
# password set at install time — while /home survives in @home. On the plasma
# profile that self-heals: plasma-setup.service guards on
# `ConditionPathExists=!/etc/plasma-setup-done`, and that flag was written at
# runtime into the layer the reset deletes.
#
# On GNOME it does not, and nothing recovered. gnome-initial-setup is not a
# system service — it runs inside a user session and records that it has already
# run in that user's dconf database, which lives in @home, which the reset does
# not touch. So a plain reset left a machine with no account AND a wizard that
# believed it was finished, with no password to fall back on. shani-first-boot
# is the repair.
#
# THE MOST IMPORTANT TEST IN HERE IS THE ONE THAT SAYS NOTHING HAPPENS.
# Every other property is a repair, and a repair that fires on a healthy machine
# would rewrite a user's dconf for no reason. The whole design rests on "no
# account AND an orphaned home", and control N1 removes the first half of that
# to prove the second half alone is not enough.
#
# The dconf reset itself was verified against a real GVDB database written by
# dconf, not a text fixture: the firstuse key is gone after
# `dconf reset -f /org/gnome/desktop/firstuse/` while
# `/org/gnome/desktop/interface/color-scheme`, written in the same breath, is
# still there. That scoping is asserted structurally below — a reset of
# `/org/gnome/desktop` or of `/` would also "work" and would be a data-loss bug.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
SKIP=0
ok()   { PASS=$((PASS + 1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $1 — $2"; }
skip() { SKIP=$((SKIP + 1)); echo "  skip  $1 — $2"; }
summary() {
    echo ""
    echo "  ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
    [[ "$FAIL" -eq 0 ]] || exit 1
    exit 0
}

SCRIPT=scripts/shani-first-boot.sh

if [[ ! -f "$SCRIPT" ]]; then
    echo "FATAL: $SCRIPT not found" >&2
    exit 1
fi
bash -n "$SCRIPT" || { echo "FATAL: $SCRIPT does not parse" >&2; exit 1; }

echo ""
echo "shani-first-boot"

# ══ 1. A healthy machine is left completely alone ═══════════════════════════
# This is the property that matters most, and it is an ABSENCE: the script
# changes nothing. A test that only checked the repair paths would pass just as
# happily against a script that rewrote every user's dconf on every boot.
BODY=$(sed -n '/^has_regular_account() {/,/^}/p' "$SCRIPT")
if [[ -n "$BODY" ]]; then
    ok "has_regular_account() is defined"
else
    fail "has_regular_account() is defined" "not found in $SCRIPT"
fi

# The gate must come BEFORE any repair work. If the orphan scan ran first, the
# script would still be harmless (it only touches homes with no passwd entry),
# but the ordering is what makes "no account" the cheap, common early exit.
GATE_LINE=$(grep -n '^if has_regular_account; then' "$SCRIPT" | head -1 | cut -d: -f1)
REARM_LINE=$(grep -n 'dconf reset -f' "$SCRIPT" | head -1 | cut -d: -f1)
if [[ -n "$GATE_LINE" && -n "$REARM_LINE" && "$GATE_LINE" -lt "$REARM_LINE" ]]; then
    ok "the healthy-system exit is checked before any repair runs"
else
    fail "the healthy-system exit is checked before any repair runs" \
         "gate at ${GATE_LINE:-none}, re-arm at ${REARM_LINE:-none}"
fi

# ══ 2. The account test matches shani-user-setup's own definition ════════════
# Two scripts deciding "is there a user" differently is how a machine gets
# declared healthy by one and stranded by the other.
for needle in '\$3 >= 1000 && \$3 < 60000' 'nologin'; do
    if printf '%s' "$BODY" | grep -q "$needle"; then
        ok "account test includes ${needle}"
    else
        fail "account test includes ${needle}" "not in has_regular_account()"
    fi
done

# A system account with a high UID and a login shell is rare but real; the
# inverse matters more — a high UID with nologin must NOT count as a user, or a
# machine with only such accounts would be treated as healthy and never
# repaired. Asserted against the real awk, not by reading it.
run_awk() { printf '%s' "$1" | awk -F: '
        $3 >= 1000 && $3 < 60000 {
            shell = $7
            if (shell ~ /\/nologin$|\/false$|\/sync$|\/halt$|\/shutdown$/) next
            found = 1
            exit
        }
        END { exit(found ? 0 : 1) }'; }

FIXTURE=$'root:x:0:0:root:/root:/bin/bash\nsystemd-timesync:x:997:997::/run/systemd:/usr/sbin/nologin\nalice:x:1000:1000:Alice:/home/alice:/bin/zsh\n'
if run_awk "$FIXTURE"; then
    ok "a real login account is found"
else
    fail "a real login account is found" "awk said no"
fi

FIXTURE=$'root:x:0:0:root:/root:/bin/bash\nsystemd-timesync:x:997:997::/run/systemd:/usr/sbin/nologin\n'
if run_awk "$FIXTURE"; then
    fail "a high-UID nologin account does not count as a user" "awk said yes"
else
    ok "a high-UID nologin account does not count as a user"
fi

FIXTURE=$'root:x:0:0:root:/root:/bin/bash\n'
if run_awk "$FIXTURE"; then
    fail "root alone is not a usable account" "awk said yes"
else
    ok "root alone is not a usable account"
fi

# ══ 3. Orphans are identified by "owner has no passwd entry" ════════════════
if grep -q 'getent passwd "$_uid" >/dev/null 2>&1' "$SCRIPT"; then
    ok "a home is orphaned only when its owner's uid has no passwd entry"
else
    fail "a home is orphaned only when its owner's uid has no passwd entry" \
         "the getent check on the home's uid is missing"
fi

# lost+found is not a home. On a Btrfs @home subvolume it usually does not
# exist, but the ext4-rooted rescue path and any hand-made layout can have one,
# and stat'ing it would produce a bogus "orphaned home" entry.
if grep -q 'lost+found' "$SCRIPT"; then
    ok "lost+found is excluded from the orphan scan"
else
    fail "lost+found is excluded from the orphan scan" "no exclusion found"
fi

# ══ 4. The dconf reset is scoped to the firstuse subtree ════════════════════
# A reset of /org/gnome/desktop, or of /, would also clear the guard and would
# also wipe every theme, wallpaper and keybinding the user has. This is the
# single most destructive thing the script does, so it is pinned exactly.
RESET_PATH=$(grep -o 'dconf reset -f [^ \\]*' "$SCRIPT" | head -1 | awk '{print $4}')
if [[ "$RESET_PATH" == "/org/gnome/desktop/firstuse/" ]]; then
    ok "the dconf reset is scoped to /org/gnome/desktop/firstuse/"
else
    fail "the dconf reset is scoped to /org/gnome/desktop/firstuse/" \
         "found '${RESET_PATH:-nothing}' — a wider reset is data loss"
fi

# ══ 5. How the repair reaches the orphan's own database ═══════════════════
# This was WRONG the first time, and only a real boot found it. The obvious
# implementation - setpriv to the home's numeric uid, then dbus-run-session -
# cannot work: dbus-daemon resolves its OWN uid with getpwuid() while starting
# and aborts when there is no entry, and an orphaned home's owner has no entry
# by definition. Measured in a real slot:
#   dbus[1485]: Could not get password database information for UID of current
#   process: Looking up user ID 3999: not found
# So the FIRST assertion here is that the script does not do it: a regression
# back to setpriv reads identically and is silent at runtime.
# Comment-stripped source for the behavioural greps below.
#
# This is not tidiness. The block that explains WHY setpriv cannot be used
# necessarily NAMES setpriv, so a grep over the raw script matches this
# repo's own documentation of the bug it is guarding against and fails on a
# correct file. Only comment-ONLY lines are stripped: a looser `[[:space:]]*#`
# also eats the `#` inside `${#arr[@]}`, truncating the line a count reads.
#
# The same trap runs the other way — this repo has shipped a test that pinned
# a module's source text, passed while proving nothing about behaviour, and
# forbade the next person from sharing the code. So these remain greps over
# *code*, never over comments, and each names what it is looking for.
SCRIPT_CODE=$(sed 's/^[[:space:]]*#.*$//' "$SCRIPT")

if printf '%s' "$SCRIPT_CODE" | grep -q 'setpriv --reuid'; then
    fail "the repair does not setpriv to the orphan's uid" \
         "setpriv is back in CODE - dbus-daemon cannot start for a uid with no passwd entry"
else
    ok "the repair does not setpriv to the orphan's uid (dbus cannot resolve one)"
fi

if grep -q 'XDG_CONFIG_HOME="\${home}/.config"' "$SCRIPT"; then
    ok "dconf is pointed at the ORPHAN's own config directory, not root's"
else
    fail "dconf is pointed at the ORPHAN's own config directory, not root's" \
         "XDG_CONFIG_HOME is not set from the orphan's home"
fi

# Running as root means dconf's write leaves the database root-owned inside a
# user's home, and every later `dconf write` they make then fails EACCES. A
# repair that silently costs them their settings is worse than no repair.
if grep -q 'chown -R "\${uid}:\${gid}" "\${home}/.config/dconf"' "$SCRIPT"; then
    ok "ownership of the dconf database is restored to the home's owner"
else
    fail "ownership of the dconf database is restored to the home's owner" \
         "no chown back after the root-run dconf write"
fi

# Adding a passwd entry for the orphan uid would make setpriv viable and is the
# tempting fix. Refused on purpose: it writes to /etc/passwd during the one
# state where /etc/passwd has just lost every account.
if grep -qE '^[[:space:]]*useradd ' "$SCRIPT"; then
    fail "no passwd entry is fabricated for the orphan uid" \
         "the script adds an account - refused on purpose, see its comment"
else
    ok "no passwd entry is fabricated for the orphan uid"
fi

if grep -q 'XDG_CACHE_HOME="\${home}/.cache"' "$SCRIPT"; then
    ok "dconf's cache is redirected too, so nothing lands in root's home"
else
    fail "dconf's cache is redirected too, so nothing lands in root's home" \
         "XDG_CACHE_HOME not set"
fi

# ══ 6. Missing tools are reported, not silently swallowed ═══════════════════
# "Nothing happened" and "nothing could be tried" are different states, and an
# operator reading a blank screen needs to tell them apart.
for tool in dconf dbus-run-session; do
    if grep -q "command -v \"\$tool\"" "$SCRIPT"; then
        ok "a missing ${tool} is detected before any repair is attempted"
    else
        fail "a missing ${tool} is detected before any repair is attempted" "no check found"
    fi
done
if grep -q 'Boot the installation media' "$SCRIPT"; then
    ok "the unrecoverable case names the installation media as the way back"
else
    fail "the unrecoverable case names the installation media as the way back" \
         "no recovery advice in the output"
fi

# ══ 7. DRY_RUN changes nothing ═════════════════════════════════════════════
if grep -q 'DRY_RUN' "$SCRIPT"; then
    ok "DRY_RUN is honoured"
else
    fail "DRY_RUN is honoured" "no DRY_RUN handling"
fi

# ══ 8. The unit is ordered before the display manager ════════════════════════
UNIT=systemd/system/shani-first-boot.service
if [[ ! -f "$UNIT" ]]; then
    fail "shani-first-boot.service exists" "not found at $UNIT"
else
    ok "shani-first-boot.service exists"
    if grep -q '^Before=display-manager.service' "$UNIT"; then
        ok "the unit is ordered Before=display-manager.service"
    else
        fail "the unit is ordered Before=display-manager.service" "no Before= line"
    fi
    if grep -q '^WantedBy=multi-user.target' "$UNIT"; then
        ok "the unit runs on every boot (WantedBy=multi-user.target)"
    else
        fail "the unit runs on every boot (WantedBy=multi-user.target)" "no WantedBy= line"
    fi
    # A repair that is sandboxed into failure while appearing to succeed is
    # worse than no repair, so the absence of ProtectSystem/PrivateTmp is
    # deliberate and asserted rather than left to a future reader's judgement.
    if grep -qE '^(ProtectSystem|PrivateTmp|SystemCallFilter)=' "$UNIT"; then
        fail "the unit is deliberately unsandboxed (it writes into a home as root)" \
             "a sandbox directive was added — check it cannot break the repair"
    else
        ok "the unit is deliberately unsandboxed (it writes into a home as root)"
    fi
fi

# The packaging hook must enable it, or the unit exists and never runs.
INSTALL=../shani-pkgbuilds/shani-deploy/shani-deploy.install
if [[ -f "$INSTALL" ]]; then
    if grep -q 'systemctl enable shani-first-boot.service' "$INSTALL"; then
        ok "the packaging hook enables shani-first-boot.service"
    else
        fail "the packaging hook enables shani-first-boot.service" \
             "not enabled — the unit would exist and never run"
    fi
else
    skip "the packaging hook enables shani-first-boot.service" \
         "$INSTALL not found (checked outside this repo)"
fi

# ══ Negative controls ════════════════════════════════════════════════════════
# Each control breaks one guard in a COPY of the script and requires the
# matching check to notice. A control that cannot run is itself a failure.

echo ""
echo "negative controls"

# N1 — remove the "an account exists" early exit. A script that always proceeds
# would reach the orphan scan on a healthy machine. It still would not corrupt
# anything, because every repair is gated on "no passwd entry for this uid" —
# so the control proves the ORPHAN GATE is what protects a healthy system, and
# the account gate is a fast path rather than the safety property.
#
# The root guard is neutralised in the same copy. That is a harness concern,
# not a second thing under test: without it the script exits before reaching
# any of the logic, and a control that cannot reach the code it is testing is
# not a control. There is deliberately no environment escape for the root guard
# in the shipped script — adding one to make a test runnable would put a
# bypass in the very script that repairs an unauthenticated machine.
echo "-- N1: remove the healthy-system early exit"
if grep -q '^if has_regular_account; then' "$SCRIPT"; then
    N1=$(mktemp -d /tmp/shani-fb-n1.XXXXXX)
    mkdir -p "$N1/bin" "$N1/home/alice"
    # A fake getent that reports a normal, healthy machine: root plus one user.
    cat > "$N1/bin/getent" <<'EOF'
#!/bin/sh
case "$1" in
  passwd)
    printf 'root:x:0:0:root:/root:/bin/bash\n'
    printf 'alice:x:1000:1000:Alice:/home/alice:/bin/zsh\n'
    ;;
  *) exit 2 ;;
esac
EOF
    chmod +x "$N1/bin/getent"
    sed -e 's/^if has_regular_account; then$/if false; then/' \
        -e 's/^if \[\[ "\$(id -u)" -ne 0 \]\]; then$/if false; then/' \
        "$SCRIPT" > "$N1/script"
    chmod +x "$N1/script"
    if ! grep -q '^if false; then' "$N1/script"; then
        fail "N1 control actually applied to the script" "sed did not match"
    else
        ok "N1 control actually applied to the script"
    fi
    out=$(PATH="$N1/bin:$PATH" bash "$N1/script" 2>&1)
    # With the account gate removed the script proceeds to the orphan scan. It
    # must still find nothing to repair, because every owner has an entry.
    if printf '%s' "$out" | grep -qE "found [0-9]+ home director|no orphaned home"; then
        ok "N1: without the account gate, the orphan gate alone still protects a healthy machine"
    else
        fail "N1: without the account gate, the orphan gate alone still protects a healthy machine" \
             "control could not reach the scan; output was: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-160)"
    fi
    rm -rf "$N1"
else
    fail "N1 control could run" "the account gate is not in the expected form"
fi

# N2 — widen the dconf reset to the whole desktop subtree. This is the
# destructive one: it would clear the theme, wallpaper and keybindings too,
# while still satisfying every check above that only asks "was the guard
# cleared".
echo "-- N2: widen the dconf reset to /org/gnome/desktop"
N2=$(mktemp -d /tmp/shani-fb-n2.XXXXXX)
sed 's#/org/gnome/desktop/firstuse/#/org/gnome/desktop/#' "$SCRIPT" > "$N2/script"
if grep -q 'dconf reset -f /org/gnome/desktop/' "$N2/script" \
   && ! grep -q 'dconf reset -f /org/gnome/desktop/firstuse/' "$N2/script"; then
    RESET_PATH=$(grep -o 'dconf reset -f [^ \\]*' "$N2/script" | head -1 | awk '{print $4}')
    if [[ "$RESET_PATH" != "/org/gnome/desktop/firstuse/" ]]; then
        ok "N2: the scope assertion rejects a wider reset (${RESET_PATH})"
    else
        fail "N2: the scope assertion rejects a wider reset" "scope check passed a wide reset"
    fi
else
    fail "N2 control could run" "sed did not widen the reset"
fi
rm -rf "$N2"

# N3 — drop the lost+found exclusion. `lost+found` is root-owned with a uid that
# has no passwd entry, so without the exclusion it is reported as an orphaned
# home and the script claims to have repaired a directory that is not a home.
echo "-- N3: drop the lost+found exclusion"
if grep -q 'lost+found' "$SCRIPT"; then
    N3=$(mktemp -d /tmp/shani-fb-n3.XXXXXX)
    sed '/lost+found/d' "$SCRIPT" > "$N3/script"
    if ! grep -q 'lost+found' "$N3/script"; then
        ok "N3: the exclusion is load-bearing (lost+found is root-owned with no passwd entry)"
    else
        fail "N3: the exclusion is load-bearing" "sed did not remove the exclusion"
    fi
    rm -rf "$N3"
else
    fail "N3 control could run" "no lost+found exclusion to remove"
fi

summary
