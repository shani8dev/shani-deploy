# Agent instructions — shani-deploy

This file applies to any AI coding assistant working in this repository
(Claude Code, opencode, Kilo Code, Cursor, Aider, or similar). Read this
before editing, and follow the verification steps before calling any change
done.

## What this repo is

The blue-green deployment, health/diagnostics, and system-recovery tooling
for Shanios — an immutable, Btrfs-backed Arch Linux derivative. This is the
code that writes a new OS copy to the inactive root subvolume, flips the
boot target, and rolls back on failure. A bug here can leave a real machine
unbootable, not just misbehaving software — treat every change with that
weight, not as ordinary shell scripting.

## This is safety-critical code — treat it that way

This repo is the blue-green deployment, boot-entry, and rollback mechanism
for an immutable OS. A bug here doesn't just fail a test — it can leave a
real machine unable to boot into either slot. **Static review is not
sufficient for anything touching boot-entry writes, signing, chroot
detection, or self-update.** Actually execute the changed code path and
observe the behavior; don't reason about it from the diff alone.

## If you have Superpowers / oh-my-opencode / ultrawork / similar available

If your environment provides Claude Code's **Superpowers** plugin (TDD,
debugging, and verification-discipline skills), OpenCode's
**oh-my-opencode** (parallel/async subagents, LSP/AST tooling), an
**ultrawork**-style high-autonomy parallel execution mode, or an
equivalent skill/subagent framework in whatever tool you're running as —
use its parallel-subagent capability specifically for the
positive-test/negative-control pattern described below (one agent proving
the fix works, another proving the pre-fix code would have failed the
same test) — that pairing is exactly what these frameworks are built to
run concurrently. Don't let a skill framework's plan-and-report output
substitute for actually executing the test-env session below; this repo
has shipped real, boot-affecting bugs that only showed up under real
execution.

## Required verification for any change

```bash
# 1. Syntax check every script you touched
bash -n scripts/shani-deploy.sh scripts/gen-efi.sh scripts/shani-update.sh \
        scripts/check-boot-failure.sh

# 2. The unit-level state/marker tests (fast, no container needed)
bash tests/test-deploy-state.sh     # expect: ✓ N passed, 0 failed
```

`tests/test-deploy-state.sh` used to always fail (it grepped a file from a
different repo that doesn't exist here) and was quietly ignored as a
result — it's fixed now and actually exercises `_restore_state()`'s
variable-whitelist logic, among other things. If it goes red, that's real:
a regression in state persistence across `self_update()`'s re-exec broke
things silently once before (a regex match clobbering `BASH_REMATCH`) and
would again.

## For anything touching boot entries, signing, self-update, or chroot detection

Unit tests can't exercise these for real — they need a real Btrfs slot, a
real ESP, and a real signing keypair. Use the sibling repo's test harness:

```bash
cd ../shani-install-media
./run_in_container.sh build.sh test ca
./run_in_container.sh build.sh test bootstrap -p gnome -d latest
```

`bootstrap` runs the REAL `install.sh`+`configure.sh` from `os-installer-config`
(no separate `disk` step needed — that command is for a different, faster
fabricate-only path `bootstrap` no longer uses). `run_in_container.sh`
bind-mounts this checkout read-only at `/opt/shani-deploy` inside the
container (a no-op if it isn't found as a sibling checkout — set
`SHANIOS_TEST_DEPLOY_HOST_DIR` to point elsewhere), so
`--local-src=/opt/shani-deploy/scripts` on `enter`/`upgrade`/`verify-boot`/
`desktop` always overlays *this* checkout's current scripts *and* units
(`_overlay_local_src` picks up the sibling `systemd/` dir automatically) —
not a stale copy, and not whatever got baked into the image at build time.

For a **real, complete deploy** (download → SHA256+GPG verify → extract →
`gen-efi` UKI generation/signing → boot-entry write), which is what most
changes to `shani-deploy.sh`/`gen-efi.sh` actually need:

```bash
./run_in_container.sh build.sh test upgrade --local-src=/opt/shani-deploy/scripts
```

This calls `shani-deploy` directly (not through `shani-update`, which
needs a real display to open its progress terminal) with `--force
--channel latest --skip-self-update` — `--skip-self-update` matters here,
not just as a flag: without it, `shani-deploy`'s own `self_update()` would
fetch and exec the *published* script mid-run, silently discarding the
`--local-src`-overlaid edited copy you're trying to test. Downloaded
images are cached at a host-persistent path (survives even a fresh
`bootstrap` re-run) — see `--local-src`/caching details in
`../shani-install-media/test-env/README.md`.

For testing an individual function in isolation (a specific fault
condition, e.g. a stub `sbsign` that "succeeds" while writing garbage —
see `sign-efi-binary-test.sh` and its siblings in
`../shani-install-media/test-env/` for the established pattern), use
`enter` instead and call the real function directly:

```bash
./run_in_container.sh build.sh test enter blue --local-src=/opt/shani-deploy/scripts
```

For `shani-health`/`shani-reset` changes — neither goes through `enter`'s
approval/deploy machinery, just run them directly inside a session (both
skip `pkexec`/`sudo` when already root, which this session always is):

```bash
./run_in_container.sh build.sh test enter blue --local-src=/opt/shani-deploy/scripts -- \
  bash -c 'shani-health && shani-health --boot'
./run_in_container.sh build.sh test enter blue --local-src=/opt/shani-deploy/scripts -- \
  shani-reset --dry-run --yes   # note: --yes is required even for --dry-run,
                                 # or it blocks on a confirmation prompt with
                                 # no tty to answer it — confirmed live (hung
                                 # until an outer timeout killed it)
```

A real (non-dry-run) `shani-reset --yes --keep-downloads` genuinely wipes
`/etc`/`/var` overlay state, `varlib`, `varspool`, and boot markers, then
preserves `/data/downloads` as documented — verified live against the
before/after directory contents. Its own final `reboot` step will fail
with `Failed to connect to system scope bus` in any non-`--boot` session
(no real PID 1) — expected, not a bug; use `verify-boot`/`--boot` if you
need the reboot itself to actually happen.

From inside that session you can call the real functions directly
(`sign_efi_binary`, `in_chroot`, `finalize_boot_entries`, etc. — `source`
the script or extract the function, then call it against real paths in
the slot). Run `./run_in_container.sh build.sh test clean` when done to
release loop devices — see `../shani-install-media/test-env/README.md`
for the full command reference.

**Write a negative control, not just a positive test.** For a
security-relevant fix (verify-before-replace ordering, fail-closed
detection, a lock, etc.), the test that actually proves something is one
that shows the *old* behavior would have failed it — e.g. stub the signing
tool to "succeed" while producing garbage and confirm the live file is
never touched; force the chroot-detection `stat` to fail and confirm the
function now errors out instead of silently proceeding. A test that only
exercises the happy path doesn't prove the bug is fixed, only that nothing
broke.

## Known sharp edges (already found once — don't reintroduce)

- `_restore_state()`'s variable-whitelist check
  (`[[ " $_whitelist " =~ " $_var " ]]`) is itself a regex match that
  overwrites `$BASH_REMATCH` — if you read `${BASH_REMATCH[…]}` for the
  variable's *value* after that check runs, capture it *before* the
  whitelist check, or it's always empty.
- Boot-entry writes must go temp-file-then-atomic-`mv`, never a direct
  `cat > file` — a crash between deleting the old entry and writing the
  new one can leave a slot with zero valid boot entries.
- Signing must verify the signed output *before* it replaces the live
  file, never after.
- Any host/network-facing code that runs before a signature check (like
  self-update) must fail closed on any verification failure — keep running
  the current, already-trusted copy rather than falling through to
  execution.

## Audit-verified known issues (confirmed present)

**For the full narrative, verification methodology, and before/after
evidence behind every line below, see `AUDIT-HISTORY.md`.** This section
is deliberately just the current-state summary — what's true right now,
not how it got that way.

- **Terminal exit-code trust — RESOLVED.** `shani-update.sh` uses `--wait`
  for gnome-terminal; rollback "success" reporting while mid-flight is
  fixed.
- **`shani-health.sh`: every single-format structured-output invocation
  was silently broken — FIXED (2026-09-03).** `main()`'s output-format
  counter used `((format_count++))` under `set -Eeuo pipefail`; a bare
  post-increment from 0 evaluates the compound `[[ ... ]] &&
  ((format_count++))` statement as failing (0 is falsy for `((...))`'s
  exit status), and since it's a top-level statement (not an if/while
  condition), that aborted the whole script with **zero output and no
  error message** — for `--verify --json`, `--security --json`,
  `--boot --nagios`, any single-format combo. Verified live in a real
  systemd-nspawn container (`shani-install-media/test-env`): both
  `shani-health --verify --json` and `--security --json` died at
  exactly that line with rc=1, nothing on stdout or stderr. This means
  **`shani-fleet`'s `collect_verify()` — called on every heartbeat —
  has been silently getting empty output and reporting `verify_status:
  "fail"` with an always-empty `failed` array for every machine**,
  regardless of actual health, for as long as this bug has existed.
  Same fix pattern already used elsewhere in this file
  (`errors=$(( errors + 1 ))` in `_check_fail`) applied to all 10
  bare `((issues++))`/`((format_count++))` occurrences.
- **`shani-health.sh --json`/`--nagios`/`--prometheus`: human-readable
  report corrupted the structured output stream — FIXED (2026-09-03).**
  `_row`/`_row2`/`_head`/`_focused_header` print via bare
  `printf`/`echo` (stdout), not the stderr-redirected `_log_*` family a
  stale doc comment claimed was the only output path — so the colored
  report landed on stdout BEFORE the JSON/Nagios/Prometheus blob,
  corrupting it for any consumer piping stdout into `jq` (the
  documented, intended usage: `shani-health --verify --json | jq`).
  Fixed by saving real stdout to fd 3 and redirecting stdout to stderr
  for the report-generation phase in both `verify_system()` and
  `main()`'s generic dispatch, restoring fd 3 immediately before the
  one line of actual structured output. Verified live: `--verify --json`
  and `--security --json` now produce clean, `jq`-parseable JSON with
  correct `errors`/`ok` fields, reproducibly across repeated runs.
- **`shani-health.sh --security`'s structured output had blank/wrong
  section labels — FIXED (2026-09-03).** `_section_secureboot`,
  `_section_tpm2`, `_section_encryption`, `_section_immutability`,
  `_section_kernel_security`, `_section_security_services`,
  `_section_security_audit`, `_section_krb5`, `_section_users`, and
  `_section_groups` never called `_set_section` before recording their
  rows — `_RECORD_SECTION` is a persistent global, so every one of
  their checks inherited whichever section was set last (mostly none —
  blank `section:""`; after adding secureboot/tpm2's own `_set_section`
  calls, everything downstream incorrectly showed `"tpm2"` until all 10
  were fixed). All 10 now set their own section; verified live that
  `--security --json`'s `.checks[].section` values are exactly the 10
  distinct expected names with correct per-section counts, and that
  `--verify --json`'s independent `_CHECK_RESULTS`/`_print_verify_json`
  pipeline (which doesn't use sections at all) is unaffected.
- **`get_booted_subvol()` — 5 copies total (4 named functions + 1 inline
  in `check-boot-failure.sh`), harmonized, not merged into a shared
  file.** All 5 now share the same core parsing logic (including a
  `rootflags=`-wrapper fallback `shani-health.sh` alone used to have) and
  the same fixed regex (`grep -oP 'subvol=@?\K[^,]+'` — the old
  variable-length lookbehind silently worked under `ugrep` but is
  rejected by real GNU grep, so this was silently broken in production
  all along). Each script keeps its own not-found behavior
  (`error_exit`/`err`/`die`/`"unknown"`). Not merged into one sourced
  file — these are independently packaged executables with no existing
  shared-lib mechanism; adding one is a real packaging change, out of
  proportion here. Verified against the real installed binaries in a
  real systemd-nspawn container with real GNU grep.
- **Systemd hardening — added, per-unit not blanket.** All 10 units get
  `NoNewPrivileges=yes`/`PrivateTmp=yes`; 6 (confirmed `/data`/`$HOME`-only
  writers) also get `ProtectSystem=full`. 3 deliberately don't
  (`beesd-setup`/`shani-user-setup` write `/etc`; `bless-boot` matches
  systemd's own unhardened upstream template — needs `/boot/efi` write).
  `shani-update.service` (user) deliberately gets **none of this** — its
  real deploy path re-execs via `pkexec` (setuid), and `NoNewPrivileges`/
  mount-namespacing would silently break that escalation. Verified
  against the real kernel mechanism (`unshare --mount` + real read-only
  bind mounts), not just `systemd-analyze verify`.
- **CI status.** No CI workflows in this repo — verification is entirely
  manual.
- **`log`/`warn` argument-splitting — FIXED.** `shani-user-setup.sh`'s
  array-to-string join now uses `"${arr[*]:-}"` instead of a
  double-quoted `${arr[@]+"${arr[@]}"}` (shellcheck SC2145).
- **`check-boot-failure.sh` has no strict mode — investigated,
  deliberately NOT added.** Adding `set -Eeuo pipefail` causes a real
  regression on a missing-`btrfs`-binary path (a bare `cmd1 && cmd2`
  statement aborts under `set -e` instead of reaching its own graceful
  skip). The script has its own comment explaining why, and what would
  actually be needed first.
- **`CHROOT_ESP_BIND` dead flag — FIXED.** Removed; unmounting a
  bind-mount's target never touches its source, so the flag a stale
  comment claimed cleanup needed was never actually read anywhere.

## Cross-repo impact — check before calling a fix complete

- `shani-fleet`'s `check_self_update()` independently re-implements this
  repo's "download → checksum → GPG-verify → fail closed" trust chain for
  agent self-update. If you fix a bug in this repo's `self_update()` or
  signing logic, check `shani-fleet/agent/bin/shani-fleet-agent` for the
  same class of bug — it's a separate implementation of the same pattern,
  not shared code.
- `get_booted_subvol()` is reimplemented separately in 4 copies:
  `scripts/shani-deploy.sh`, `scripts/shani-update.sh`, `scripts/gen-efi.sh`,
  and `scripts/shani-health.sh` — kept as 4 copies deliberately (see
  "Audit-verified known issues" above for why a shared-lib merge isn't a
  clean fix here). If you fix a bug in the shared parsing logic, find every
  copy (`grep -rn "get_booted_subvol"`) and fix them all; only
  `shani-health.sh`'s not-found handling (returns `"unknown"`, never
  aborts) is supposed to differ from the other 3.
- `shani-install-media/test-env` exercises this repo's real packaged
  binaries. If you change a function's behavior in a way that changes what
  a *correct* test result looks like, update the corresponding test in
  that sibling repo too, or a stale expectation there will pass for the
  wrong reason.

## Where things are documented

`README.md` and `SECURITY.md` describe the intended trust model
(fingerprint-pinned GPG, atomic boot-entry writes, etc.) — if a change
would make either untrue, treat that as the regression, regardless of
whether existing tests still pass. `AUDIT-HISTORY.md` has the full
narrative behind every entry in "Audit-verified known issues" above.
