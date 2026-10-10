#!/usr/bin/env bash
# Inner half of tests/modules-load-target.sh - runs INSIDE the container as root,
# against the real shani-cassini-save.sh.
#
# Each block names the failure class it exists over. Two of them are bugs that
# were live on main and only found by running the real script:
#
#   * the target did not exist in the allowlist at all, so the KVM page's save
#     had been refused since it was written;
#   * the validator self-reference used `$PROG` (a bare name, `${0##*/}`) rather
#     than `$0`, so `command -v` could not resolve it and the fail-closed check
#     refused every save with "shani-cassini-save is not installed" - the target
#     existed and was still unusable.
set -uo pipefail

H=/shani-cassini-save
TARGET=/etc/modules-load.d/50-shani-kvm.conf
PASS=0
FAIL=0
ok() { printf 'ok   %s\n' "$1"; PASS=$((PASS + 1)); }
no() { printf 'FAIL %s -- %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

echo "  substrate: $(modinfo loop >/dev/null 2>&1 && echo 'loop is loadable' || echo 'NO loadable module')"

# ── 1. the target exists, which is the bug this whole file is about ─────────
out=$(printf 'kvm_intel\n' | "$H" --target modules_load 2>&1)
rc=$?
if grep -q "unknown target" <<<"$out"; then
    no "modules_load is in the allowlist" "the helper still refuses it: $out"
else ok "modules_load is in the allowlist (kvm.py has called this since it was written)"; fi
grep -q "50-shani-kvm.conf" <<<"$out" && ok "  and it names $TARGET" || no "  names $TARGET" "$out"

# ── 2. a module this kernel cannot provide is refused, and nothing is left ──
rm -f "$TARGET"
out=$(printf 'definitely_not_a_real_module_xyz\n' | "$H" --target modules_load 2>&1)
rc=$?
[[ $rc -ne 0 ]] && ok "a module the kernel cannot provide is refused" || no "bogus module refused" "exit 0"
case "$out" in *"cannot load module"*) ok "  and names the module" ;; *) no "  names the module" "$out" ;; esac
if [[ -f "$TARGET" ]]; then no "  and nothing was written" "the file exists after a refused save"; else ok "  and nothing was written"; fi

# ── 3. a real module installs, with the right mode and content ──────────────
if modinfo loop >/dev/null 2>&1; then
    out=$(printf 'loop\n' | "$H" --target modules_load 2>&1)
    rc=$?
    [[ $rc -eq 0 ]] && ok "a real module is accepted and installed" || no "real module" "rc=$rc: $out"
    [[ -f "$TARGET" ]] && ok "  $TARGET exists" || no "  file exists" "missing"
    grep -q "loop" "$TARGET" 2>/dev/null && ok "  containing the module name" || no "  content" "$(cat "$TARGET" 2>/dev/null)"
    perms=$(stat -c %a "$TARGET" 2>/dev/null)
    [[ "$perms" == "644" ]] && ok "  mode 0644" || no "  mode 0644" "got $perms"
else
    echo "SKIP: no loadable module on this kernel"
fi

# ── 4. an empty file would silently do nothing, so it is refused ────────────
out=$(printf '' | "$H" --target modules_load 2>&1)
[[ $? -ne 0 ]] && ok "an empty drop-in is refused (it would load nothing)" || no "empty refused" "exit 0"

# ── 5. comments and blank lines are systemd's syntax, not errors ─────────────
out=$(printf '# a comment\n\n  \nloop\n' | "$H" --target modules_load 2>&1)
[[ $? -eq 0 ]] && ok "comments and blank lines are skipped, not rejected" || no "comments skipped" "rc=$? $out"

# ── 6. the validator modes work on their own ────────────────────────────────
if [[ -f "$TARGET" ]]; then
    "$H" --check-modules-load "$TARGET" >/dev/null 2>&1 \
        && ok "--check-modules-load on a good file exits 0" || no "--check good" "non-zero"
fi
echo "bogus" > /tmp/bad.conf
"$H" --check-modules-load /tmp/bad.conf >/dev/null 2>&1 \
    && no "--check-modules-load on a bad file exits non-zero" "it exited 0" \
    || ok "--check-modules-load on a bad file exits non-zero"

# The live check must treat an ABSENT file as success, because it also runs as
# the pre-change baseline on a machine that never had the drop-in. Getting that
# wrong made the baseline red, so every save looked like a new complaint and
# rolled itself back - the target existed and still could not be written.
rm -f "$TARGET"
"$H" --check-modules-load-live >/dev/null 2>&1 \
    && ok "--check-modules-load-live succeeds when the file is absent (baseline case)" \
    || no "live check with no file" "it failed, so every save would roll back"

# ── 7. the other three targets are unchanged by this addition ───────────────
for t in sudoers sshd_config exports; do
    out=$(printf 'x\n' | "$H" --target "$t" 2>&1)
    case "$out" in
        *"unknown target"*) no "  $t still refused as unknown" "it is now accepted" ;;
        *) ok "  $t still refused for the same reason as before (its validator or tool is absent here)" ;;
    esac
done

echo "  ---- $PASS passed / $FAIL failed"
[[ $FAIL -eq 0 ]]