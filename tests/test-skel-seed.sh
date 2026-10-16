#!/bin/bash
# tests/test-skel-seed.sh — contract tests for seed_skel() in
# scripts/shani-user-setup.sh.
#
# What this exists for. `useradd -m` copies /etc/skel only when it CREATES a
# home directory. A factory reset removes the account from /etc but leaves the
# home in @home, so the account the first-run wizard re-creates lands on an
# existing directory and receives none of the defaults. shani-user-setup is
# the only thing that runs afterwards, so that is where they have to arrive —
# and until this existed, it did not do it, while its own .service
# Description, its .path unit's PathModified=/etc/skel watch, shani-reset's
# usage text and AUDIT-HISTORY.md all claimed that it did.
#
# The function is EXTRACTED from the shipped script and run verbatim. Only the
# skel root is repointed (SKEL_DIR, which defaults to /etc/skel in the shipped
# script) because a test cannot chroot; the walk, the guards and the copy are
# the real ones.
#
# The property that matters most is the one that can destroy data: the
# first-login pair .bashrc_shani + .config/autostart/bashrc-setup.desktop is
# ONE unit, because the autostart entry runs
#   mv ~/.bashrc_shani ~/.bashrc; rm <itself>
# Seeding it into a home that already has a .bashrc would overwrite that file
# on the next graphical login, silently, from a "seed missing files" pass that
# is supposed to be incapable of touching anything the user has. Case 6 is
# that case and control N2 removes the guard to prove the case has teeth.

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
SKIP=0
ok()   { PASS=$((PASS+1)); echo "  ok    $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL  $1 — $2"; }
skip() { SKIP=$((SKIP+1)); echo "  skip  $1 — $2"; }
summary() {
    echo ""
    echo "  ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
    [[ "$FAIL" -eq 0 ]] || exit 1
    exit 0
}

SETUP=scripts/shani-user-setup.sh

# ── Extract the function verbatim ─────────────────────────────────────────────
SEED_FN=$(sed -n '/^seed_skel() {/,/^}/p' "$SETUP")
if [[ -z "$SEED_FN" ]]; then
    echo "FATAL: seed_skel() not found in $SETUP" >&2
    exit 1
fi
if [[ "$(grep -c '^seed_skel() {' "$SETUP")" -ne 1 ]]; then
    echo "FATAL: seed_skel() is not defined exactly once (a second definition" >&2
    echo "       would silently win; the sed above would take the first)" >&2
    exit 1
fi

# ── Harness ───────────────────────────────────────────────────────────────────
# A throwaway skel + home per case. _run_seed takes the function text as $1 so
# the negative controls can hand it a mutated copy.
_run_seed() {
    local fn="$1" home="$2" skel="$3"
    (
        set -uo pipefail
        DRY_RUN=0
        SKEL_DIR="$skel"          # the shipped default is /etc/skel
        export SKEL_DIR
        log()  { :; }
        warn() { :; }
        run()  { "$@"; }
        eval "$fn"
        seed_skel "$home" "$(id -u)" "$(id -g)"
    ) >/dev/null 2>&1
}

# Mutations go through sed, not ${var/pat/rep}. Bash treats that pattern as a
# GLOB, and a guard line is full of metacharacters — `[[`, `]]` and the
# parentheses in the case arm are all bracket/group syntax, so the pattern
# matches nothing and the "mutated" copy is identical to the original. That
# failure mode is silent: the control reports success while proving nothing.
_mutate() {
    local from="$1" to="$2" esc
    # Escape for POSIX BRE. This box's sed treats an unescaped '[' as the
    # start of a bracket expression even outside a bracket, so a guard line
    # full of "[[ ]]" silently matches nothing — and a control that mutated
    # nothing reports success while proving nothing.
    esc="$from"
    esc="${esc//\\/\\\\}"
    esc="${esc//\[/\\[}"
    esc="${esc//\]/\\]}"
    esc="${esc//./\\.}"
    esc="${esc//^/\\^}"
    esc="${esc//\$/\\$}"
    esc="${esc//\*/\\*}"
    printf '%s\n' "$SEED_FN" | sed "s%${esc}%${to}%" | sed '/^seed_skel() {/,$!d'
}

new_case() {
    CASE=$(mktemp -d /tmp/shani-skel-case.XXXXXX)
    SKEL="$CASE/skel"
    HOME_DIR="$CASE/home"
    mkdir -p "$SKEL" "$HOME_DIR"
}
end_case() { rm -rf "$CASE"; }

echo ""
echo "shani-user-setup seed_skel()"

# ── 1. A missing file is seeded, byte-for-byte ───────────────────────────────
new_case
mkdir -p "$SKEL/.config"
printf 'zsh default\n' > "$SKEL/.zshrc"
printf '{"colors":"saturn"}\n' > "$SKEL/.config/starship.toml"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
if [[ "$(cat "$HOME_DIR/.zshrc" 2>/dev/null)" == "zsh default" ]]; then
    ok "seeds a missing dotfile"
else
    fail "seeds a missing dotfile" "not seeded"
fi
if [[ "$(cat "$HOME_DIR/.config/starship.toml" 2>/dev/null)" == '{"colors":"saturn"}' ]]; then
    ok "seeds a missing nested file"
else
    fail "seeds a missing nested file" "not seeded"
fi
end_case

# ── 2. An existing file is NEVER overwritten ─────────────────────────────────
new_case
printf 'zsh default\n' > "$SKEL/.zshrc"
printf '# MY OWN CONFIGS\n' > "$HOME_DIR/.zshrc"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
if [[ "$(cat "$HOME_DIR/.zshrc")" == "# MY OWN CONFIGS" ]]; then
    ok "never overwrites a file the user has"
else
    fail "never overwrites a file the user has" "content was replaced"
fi
end_case

# ── 3. An existing directory's mode is not changed ───────────────────────────
new_case
mkdir -p "$SKEL/.config" && chmod 0755 "$SKEL/.config"
mkdir -p "$HOME_DIR/.config" && chmod 0700 "$HOME_DIR/.config"
printf 'x\n' > "$SKEL/.config/tool.toml"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
if [[ "$(stat -c %a "$HOME_DIR/.config")" == "700" ]]; then
    ok "leaves an existing directory's mode alone"
else
    fail "leaves an existing directory's mode alone" "mode is $(stat -c %a "$HOME_DIR/.config")"
fi
end_case

# ── 4. A missing directory is created with skel's mode ───────────────────────
new_case
mkdir -p "$SKEL/.ssh" && chmod 0700 "$SKEL/.ssh"
touch "$SKEL/.ssh/.gitkeep"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
if [[ -d "$HOME_DIR/.ssh" && "$(stat -c %a "$HOME_DIR/.ssh")" == "700" ]]; then
    ok "creates a missing directory at skel's mode (.ssh 0700)"
else
    fail "creates a missing directory at skel's mode (.ssh 0700)" \
         "mode is $(stat -c %a "$HOME_DIR/.ssh" 2>/dev/null || echo missing)"
fi
end_case

# ── 5. The first-login pair is SKIPPED when .bashrc exists ──────────────────
# The destructive case. The autostart entry would `mv .bashrc_shani .bashrc`
# on the next graphical login and replace the user's shell config.
new_case
printf 'the shani bashrc\n' > "$SKEL/.bashrc_shani"
mkdir -p "$SKEL/.config/autostart"
printf '[Desktop Entry]\nExec=bashrc-setup\n' > "$SKEL/.config/autostart/bashrc-setup.desktop"
printf '# MY OWN BASHRC\n' > "$HOME_DIR/.bashrc"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
if [[ ! -e "$HOME_DIR/.bashrc_shani" ]]; then
    ok "does not seed .bashrc_shani when .bashrc exists"
else
    fail "does not seed .bashrc_shani when .bashrc exists" "seeded anyway"
fi
if [[ ! -e "$HOME_DIR/.config/autostart/bashrc-setup.desktop" ]]; then
    ok "does not seed the autostart entry that would clobber .bashrc"
else
    fail "does not seed the autostart entry that would clobber .bashrc" "seeded anyway"
fi
end_case

# ── 6. The first-login pair IS seeded when .bashrc is absent ─────────────────
new_case
printf 'the shani bashrc\n' > "$SKEL/.bashrc_shani"
mkdir -p "$SKEL/.config/autostart"
printf '[Desktop Entry]\nExec=bashrc-setup\n' > "$SKEL/.config/autostart/bashrc-setup.desktop"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
if [[ -e "$HOME_DIR/.bashrc_shani" && -e "$HOME_DIR/.config/autostart/bashrc-setup.desktop" ]]; then
    ok "seeds the first-login pair when there is no .bashrc for it to become"
else
    fail "seeds the first-login pair when there is no .bashrc for it to become" "pair not seeded"
fi
end_case

# ── 7. Seeded files are owned by the user, not by root ───────────────────────
new_case
printf 'x\n' > "$SKEL/.zshrc"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL"
if [[ "$(id -u)" -ne 0 ]]; then
    skip "seeded file is owned by the user" "needs root: cp -a as $(id -un) already yields own files"
elif [[ "$(stat -c %u "$HOME_DIR/.zshrc" 2>/dev/null)" == "$(id -u)" ]]; then
    ok "seeded file is owned by the user"
else
    fail "seeded file is owned by the user" "owner is $(stat -c %u "$HOME_DIR/.zshrc" 2>/dev/null)"
fi
end_case

# ── 8. A second run is a no-op ───────────────────────────────────────────────
new_case
printf 'zsh default\n' > "$SKEL/.zshrc"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
printf '# edited by the user\n' > "$HOME_DIR/.zshrc"
_run_seed "$SEED_FN" "$HOME_DIR" "$SKEL" >/dev/null
if [[ "$(cat "$HOME_DIR/.zshrc")" == "# edited by the user" ]]; then
    ok "a later run does not undo the user's edits (idempotent)"
else
    fail "a later run does not undo the user's edits (idempotent)" "content reverted"
fi
end_case

# ── 9. Missing skel or missing home is a no-op, not a crash ──────────────────
new_case
printf 'x\n' > "$SKEL/.zshrc"
out=$(_run_seed "$SEED_FN" "$HOME_DIR" "$CASE/does-not-exist" 2>&1); rc=$?
if [[ $rc -eq 0 ]]; then
    ok "an absent skel directory exits 0"
else
    fail "an absent skel directory exits 0" "rc=$rc"
fi
out=$(_run_seed "$SEED_FN" "$CASE/no-such-home" "$SKEL" 2>&1); rc=$?
if [[ $rc -eq 0 ]]; then
    ok "an absent home directory exits 0"
else
    fail "an absent home directory exits 0" "rc=$rc"
fi
end_case

# ── 10. DRY_RUN changes nothing on disk ─────────────────────────────────────
new_case
printf 'zsh default\n' > "$SKEL/.zshrc"
out=$(
    set -uo pipefail
    DRY_RUN=1
    SKEL_DIR="$SKEL"; export SKEL_DIR
    log()  { :; }
    warn() { :; }
    run()  { if [[ "$1" == "mkdir" || "$1" == "cp" || "$1" == "chown" || "$1" == "chmod" ]]; then echo "$*"; fi; }
    eval "$SEED_FN"
    seed_skel "$HOME_DIR" "$(id -u)" "$(id -g)"
)
if [[ ! -e "$HOME_DIR/.zshrc" ]]; then
    ok "DRY_RUN=1 writes nothing to disk"
else
    fail "DRY_RUN=1 writes nothing to disk" "file was created"
fi
if printf '%s' "$out" | grep -q 'cp -a'; then
    ok "DRY_RUN=1 still reports what it would do"
else
    fail "DRY_RUN=1 still reports what it would do" "nothing reported"
fi
end_case

# ══ Negative controls ════════════════════════════════════════════════════════
# A check that cannot fail is not a check. Each control breaks one guard in a
# COPY of the extracted function and requires the matching case to fail.

echo ""
echo "negative controls"

# N1 — remove the never-overwrite guard. Case 2 must fail.
MUTATED=$(_mutate 'if [[ -e "$_dst" ]]; then' 'if false; then')
if [[ "$MUTATED" == "$SEED_FN" ]]; then
    fail "N1 control mutates the overwrite guard" "pattern not found — control cannot run"
else
    new_case
    printf 'zsh default\n' > "$SKEL/.zshrc"
    printf '# MY OWN CONFIGS\n' > "$HOME_DIR/.zshrc"
    _run_seed "$MUTATED" "$HOME_DIR" "$SKEL"
    if [[ "$(cat "$HOME_DIR/.zshrc")" != "# MY OWN CONFIGS" ]]; then
        ok "N1: without the overwrite guard, the user's file IS clobbered"
    else
        fail "N1: without the overwrite guard, the user's file IS clobbered" \
             "guard removed but nothing was overwritten — case 2 may be vacuous"
    fi
    end_case
fi

# N2 — remove the first-login pair guard. Case 5 must fail.
MUTATED=$(_mutate 'bashrc-setup.desktop)' 'never-matches-this)')
if [[ "$MUTATED" == "$SEED_FN" ]]; then
    fail "N2 control mutates the first-login pair guard" "pattern not found — control cannot run"
else
    new_case
    printf 'the shani bashrc\n' > "$SKEL/.bashrc_shani"
    mkdir -p "$SKEL/.config/autostart"
    printf '[Desktop Entry]\nExec=bashrc-setup\n' > "$SKEL/.config/autostart/bashrc-setup.desktop"
    printf '# MY OWN BASHRC\n' > "$HOME_DIR/.bashrc"
    _run_seed "$MUTATED" "$HOME_DIR" "$SKEL"
    if [[ -e "$HOME_DIR/.config/autostart/bashrc-setup.desktop" ]]; then
        ok "N2: without the pair guard, the autostart IS seeded over a live .bashrc"
    else
        fail "N2: without the pair guard, the autostart IS seeded over a live .bashrc" \
             "guard removed but nothing was seeded — case 5 may be vacuous"
    fi
    end_case
fi

# N3 — remove the existing-directory guard. Case 3 must fail.
#
# Paired with case 3, NOT case 4, and the pairing is the whole point. Case 4
# CREATES a directory that is missing, so with the guard removed the `mkdir -p`
# still creates it and the outcome is identical — the first version of this
# control was paired with case 4 and correctly reported "nothing changed".
# What the guard actually protects is case 3: an existing directory's mode,
# which `chmod --reference` would otherwise reset to skel's.
MUTATED=$(_mutate 'if [[ -d "$_dst" ]]; then' 'if false; then')
if [[ "$MUTATED" == "$SEED_FN" ]]; then
    fail "N3 control mutates the existing-directory guard" "pattern not found — control cannot run"
else
    new_case
    mkdir -p "$SKEL/.config" && chmod 0755 "$SKEL/.config"
    mkdir -p "$HOME_DIR/.config" && chmod 0700 "$HOME_DIR/.config"
    printf 'x\n' > "$SKEL/.config/tool.toml"
    _run_seed "$MUTATED" "$HOME_DIR" "$SKEL"
    if [[ "$(stat -c %a "$HOME_DIR/.config")" != "700" ]]; then
        ok "N3: without the directory guard, an existing directory's mode is reset to skel's"
    else
        fail "N3: without the directory guard, an existing directory's mode is reset to skel's" \
             "nothing changed — case 3 may be vacuous"
    fi
    end_case
fi

# N4 — remove the chown. Case 7 must fail.
# Root-only for the same reason as case 7: without root, `cp -a` already
# produces a file the runner owns, so removing the chown changes nothing
# observable and the control would report success while proving nothing.
if [[ "$(id -u)" -ne 0 ]]; then
    skip "N4: without the chown, the seeded file is not the user's" \
         "needs root — unprivileged cp -a cannot show the difference"
else
    MUTATED=$(_mutate 'run chown "$_uid:$_gid" "$_dst" || warn "could not chown $_dst"' ':')
    if [[ "$MUTATED" == "$SEED_FN" ]]; then
        fail "N4 control removes the chown" "pattern not found — control cannot run"
    else
        new_case
        printf 'x\n' > "$SKEL/.zshrc"
        _run_seed "$MUTATED" "$HOME_DIR" "$SKEL"
        if [[ "$(stat -c %u "$HOME_DIR/.zshrc" 2>/dev/null)" != "$(id -u)" ]]; then
            ok "N4: without the chown, the seeded file is not the user's"
        else
            fail "N4: without the chown, the seeded file is not the user's" \
                 "ownership unchanged — case 7 may be vacuous"
        fi
        end_case
    fi
fi

# ══ Wiring assertions ════════════════════════════════════════════════════════
# Every behavioural case above calls the extracted function directly, which
# proves the function is right and says nothing about whether the script
# actually calls it, or whether it calls it inside the stamp guard (where a
# skel package upgrade would never reach an existing home).

echo ""
echo "wiring"

if grep -qF 'seed_skel "$home" "$uid" "$gid"' "$SETUP"; then
    ok "the per-user loop calls seed_skel with the user's own uid/gid"
else
    fail "the per-user loop calls seed_skel with the user's own uid/gid" "call not found in $SETUP"
fi

CALL_LINE=$(grep -nF 'seed_skel "$home" "$uid" "$gid"' "$SETUP" | head -1 | cut -d: -f1)
GUARD_LINE=$(grep -nF 'One-time bootstrap (stamp-guarded)' "$SETUP" | head -1 | cut -d: -f1)
if [[ -n "$CALL_LINE" && -n "$GUARD_LINE" && "$CALL_LINE" -lt "$GUARD_LINE" ]]; then
    ok "the call is OUTSIDE the stamp-guarded block (a skel upgrade reaches existing homes)"
else
    fail "the call is OUTSIDE the stamp-guarded block (a skel upgrade reaches existing homes)" \
         "call at line ${CALL_LINE:-none}, stamp guard at line ${GUARD_LINE:-none}"
fi

# The stamp encodes the script's mtime and the groups list only, so it cannot
# notice a new file appearing in /etc/skel. If the stamp ever grows a skel
# component this comment becomes wrong — re-read it before trusting the line.
if grep -qF '_stamp_val="${SCRIPT_MTIME}:${EXTRA_GROUPS}"' "$SETUP"; then
    ok "the stamp has no skel component (so it cannot skip a skel upgrade)"
else
    fail "the stamp has no skel component (so it cannot skip a skel upgrade)" \
         "stamp value changed — re-read seed_skel()'s comment before adjusting"
fi

# Ownership without root. The chown must name the CALLER's uid/gid, not root
# and not a literal — a seeded file left root-owned in a user's home is a
# support ticket that reads as "my config is read-only". This is a static
# assertion precisely because case 7 cannot fail unprivileged.
if printf '%s\n' "$SEED_FN" | grep -qF 'run chown "$_uid:$_gid" "$_dst"'; then
    ok "seeded files are chowned to the caller's uid:gid (static — case 7 is root-only)"
else
    fail "seeded files are chowned to the caller's uid:gid" "chown call not found in seed_skel()"
fi

# The skel root must stay overridable, or this suite would be asserting
# against a fixture the shipped code cannot be pointed at.
if grep -qF 'local _skel="${SKEL_DIR:-/etc/skel}"' "$SETUP"; then
    ok "the skel root defaults to /etc/skel but is overridable (SKEL_DIR)"
else
    fail "the skel root defaults to /etc/skel but is overridable (SKEL_DIR)" \
         "SKEL_DIR override removed — this suite can no longer drive the real function"
fi

summary
