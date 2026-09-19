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

## Empirical verification (mandatory)

**Reading code is analysis; running code is verification.** A change is not
verified by reading the diff, running `bash -n`, or confirming it "looks
correct." It is verified by observing the actual behavior of the real
thing in the real environment — built, served, deployed, signed, running.
If you haven't seen it work (or fail) for real, it isn't verified.

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

## 🧪 MANDATORY: Full Real Test Harness (non-negotiable)

**You MUST run the full test harness. Do not skip it. Do not substitute
static checks for it. Do not say "this should work" without evidence.**

Every change to this repo must be verified with the real test harness in
`../shani-install-media/test-env/`. This is the ONLY way to prove boot,
signing, deploy, and rollback logic actually works.

### The complete test sequence (run ALL of these)

```bash
cd ../shani-install-media

# 1. Clean any stale loop devices from previous sessions
./run_in_container.sh build.sh test clean

# 2. Generate throwaway CA + leaf cert for downloads.shani.dev
./run_in_container.sh build.sh test ca

# 3. Bootstrap: REAL install.sh + configure.sh into @blue/@green
#    This creates real Btrfs subvolumes, signs EFI binaries, writes boot entries
./run_in_container.sh build.sh test bootstrap -p gnome -d latest

# 4. REAL deploy: download → SHA256+GPG verify → extract → UKI gen/sign → boot entry write
#    --local-src overlays THIS repo's current scripts over the slot
./run_in_container.sh build.sh test upgrade --local-src=/opt/shani-deploy/scripts

# 5. REAL rollback: snapshot current slot, restore previous
./run_in_container.sh build.sh test rollback --local-src=/opt/shani-deploy/scripts

# 6. ALWAYS clean up loop devices when done
./run_in_container.sh build.sh test clean
```

### What each step actually proves

| Step | Proves |
|------|--------|
| `clean` | No stale loop devices break the next run |
| `ca` | Test CA + leaf cert generation works |
| `bootstrap` | install.sh + configure.sh produce a bootable slot with signed EFI |
| `upgrade` | shani-deploy does download → verify → extract → UKI sign → boot entry write |
| `rollback` | Snapshot + restore mechanism works |
| `clean` | Loop devices released, no resource leaks |

### Prerequisites

- Docker must be running (`docker info`)
- The `shani-builder` Docker image must be built (`shrinivasvkumbhar/shani-builder:latest`)
- Pre-built images should exist at `cache/output/<profile>/` — check there first
- No `/dev/kvm` on this host — QEMU boots are very slow, use nspawn commands

### If a step fails

Do NOT skip it. Do NOT say "it probably works." Investigate the failure:
- Check the log file referenced in the error
- Run the step again with verbose output
- If it's a stale loop device issue, run `clean` first
- If it's a corrupted cached package, the error will say so explicitly

### Quick unit tests (fast, no container — run these FIRST)

```bash
# Syntax check ALL scripts
for script in scripts/*.sh bin/*.sh; do bash -n "$script"; done

# Unit tests
bash tests/test-deploy-state.sh     # expect: ✓ N passed, 0 failed
bash tests/test_upgrade_adviser.sh  # expect: 21 passed, 0 failed
```

These are the floor, not the ceiling. The harness above is the real proof.

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

- **`shani-update.sh` crashed on every invocation — FIXED (2026-09-19).**
  Two variables were referenced but never defined anywhere in `scripts/` or
  `bin/`, and this script sources nothing: `UPDATE_CHANNEL_DEFAULT`
  (L121 `DEPLOY_CHANNEL="$UPDATE_CHANNEL_DEFAULT"`) and `LOG_TAG`
  (L158/160 `systemd-cat -t "$LOG_TAG"` / `logger -t "$LOG_TAG"`). Under the
  script's own `set -Eeuo pipefail` that aborts at startup on **every**
  mode — including `--rollback` and `--startup`, i.e. the automatic
  fallback→rollback path (`_check_fallback_boot` L252 →
  `_handle_fallback_boot` L725 → `_run_rollback` L675 →
  `shani-deploy --rollback`) that runs at login. Net effect: the automatic
  boot-failure recovery path was unreachable, even though the manual
  `shani-deploy --rollback` path works fine. Found by the rollback-path
  empirical verification pass; independently re-verified by grep across
  `scripts/`+`bin/` (0 definitions, 0 `source` calls). Fixed by defining
  `UPDATE_CHANNEL_DEFAULT="stable"` (matches `shani-deploy.sh:418`'s default
  and this script's own `--channel` help text) and
  `readonly LOG_TAG="shani-update"` (matches the convention every sibling
  uses, e.g. `shani-reset.sh:51`). Verified: `bash -n` clean,
  `test-deploy-state.sh` 9/0, `test_upgrade_adviser.sh` 21/0, and
  `shani-update --help` / `--rollback` now run to completion instead of
  crashing with "unbound variable".

- **`check-boot-failure.sh` misattributed a same-slot timeout to the
  untouched sibling slot — FIXED (2026-09-19).** Its sanity-check treated
  `FAILED_SLOT == BOOTED_SLOT` as invalid data (comment: "we are on the
  fallback, so current-slot should name the slot that failed, not the one
  we are running") and unconditionally flipped to the opposite slot. That
  assumption is wrong: `/data/current-slot` only advances to a new
  candidate during an active deploy's `finalize_update()` — once a slot
  has been the accepted default for a while (the normal, everyday steady
  state, not an edge case), `current-slot == BOOTED_SLOT` legitimately.
  Reproduced live in `test-env`: entering `@blue` with `current-slot=blue`
  (steady-state, no pending deploy) and `boot_in_progress` set produced
  `boot_failure=green` — blaming the healthy, never-touched sibling slot
  for a timeout that actually happened on `@blue`. Fixed to only derive
  from `BOOTED_SLOT` when `current-slot`'s value is genuinely invalid
  (not blue/green), not merely equal to it. Verified all three cases live
  post-fix: same-slot timeout now correctly records the slot that
  actually timed out; the genuine-fallback case (entering `@green` with
  `current-slot=blue`) still correctly records `blue`, unchanged; garbage
  `current-slot` content still correctly derives from `BOOTED_SLOT`.

- **`shani-deploy --rollback`'s core slot-direction logic had the SAME
  flawed assumption, one level deeper — FIXED (2026-09-19).**
  `rollback_system()` derived `failed_slot` unconditionally as "whichever
  slot is NOT currently booted" (its own comment: "The failed slot is
  always the NON-booted slot") and never treated `/data/boot_failure`'s
  content as authoritative, only as a warn-only cross-check it overrode.
  For a same-slot timeout, `--rollback` had **no code path that could
  ever target the currently-booted slot as the failed one** — it would
  "repair" the healthy, untouched sibling slot from a backup while
  leaving the real problem (the booted default slot itself) completely
  untouched, still the default, and report success despite having fixed
  nothing. Fixed by adding a new `switch_to_sibling_slot()` function,
  called instead of the existing repair-from-backup logic whenever
  `/data/boot_failure`(`.acked`) names the SAME slot as booted: it
  switches `loader.conf`'s default to the sibling slot directly (via
  `finalize_boot_entries`) with **no subvolume snapshot/delete at all** —
  correct, since a same-slot timeout gives no evidence the booted slot's
  filesystem is actually broken, only that it didn't confirm health in
  time. The original "opposite of booted" repair logic is unchanged and
  still runs for its two original, still-valid cases: a genuine confirmed
  fallback (recorded failure names the OTHER slot) and a manual
  `--rollback` invocation with no marker at all. Verified all three cases
  live in `test-env`: same-slot timeout now correctly switches the
  default to the sibling with the booted slot's data untouched; genuine
  fallback still correctly repairs the other slot from backup, booted
  stays default (regression-checked, unchanged); no-marker manual
  invocation still correctly assumes opposite-of-booted (regression-checked,
  unchanged). `tests/test-deploy-state.sh` still 9/9.

- **Automated rollback is now a real, system-level, unattended mechanism —
  separated from `shani-update` (2026-09-19).** Previously, the only code
  that ever acted on a detected boot failure was `shani-update.sh`'s
  `_check_fallback_boot()`/`_handle_fallback_boot()`, reachable only via
  `shani-update --startup` — a `systemd --user` unit that **requires a
  graphical session** (`DISPLAY`/`WAYLAND_DISPLAY`; confirmed live in its
  own startup-mode guard: "No display — skipping startup check", exit 0
  otherwise) and then shows an interactive dialog/console prompt asking
  the user to approve the rollback (defaulting to **decline** on a 60s
  console-prompt timeout, or doing nothing at all with no TTY and no GUI).
  This never ran at all on the `server` profile (no desktop by design),
  and never ran if the failure itself prevented the desktop from starting
  — one of the most likely real failure shapes it needed to catch. The
  "Automated rollback on boot failure" claim in this repo's own
  garuda-comparison table was true only in the loosest sense: a logged-in,
  attentive human had to approve it within a short window.
  New `scripts/shani-auto-rollback.sh` + `shani-auto-rollback.service`/
  `.timer` run unconditionally, system-level, no session/display/TTY of
  any kind: triggered at `OnBootSec=1min` (catches a dracut-recorded hard
  failure fast) and again at `OnBootSec=16min` (one minute after
  `check-boot-failure.timer`'s own 15-minute check, to catch a same-slot
  soft failure it just recorded). It only acts on an actual recorded
  failure marker (never guesses), and calls `shani-deploy --rollback`
  directly — which, after the fix above, now correctly handles both the
  genuine-fallback and same-slot cases itself, so this script doesn't
  duplicate that direction logic. Idempotent via `/data/auto_rollback_done`
  (cleared each boot by `mark-boot-in-progress.service`, added there for
  this purpose) since it can fire twice per boot; the service deliberately
  has no `RemainAfterExit=yes` so the timer's second trigger actually
  re-invokes it rather than finding it already "active" and no-op'ing.
  Verified live end-to-end in `test-env` for both shapes: a same-slot
  marker written by `check-boot-failure` gets picked up and correctly
  triggers the new switch-to-sibling path with zero interaction; a
  dracut-style hard-failure marker (genuine slot mismatch) correctly
  triggers the original repair-from-backup path, keeping the booted slot
  as default. `shani-update.sh`'s dialog is unchanged and still runs
  under `--startup` as a secondary, opt-in UX layer (useful if a user
  happens to log in during the ~16-minute detection window, or wants to
  manually trigger recovery earlier) — but it is no longer the mechanism
  automated recovery depends on. Packaging: `shani-auto-rollback.sh`/
  `.service`/`.timer` are picked up automatically by
  `shani-pkgbuilds/shani-deploy/PKGBUILD`'s existing glob (no PKGBUILD
  change needed, same convention as every other script/unit here); its
  sibling `.install` file needed (and got) one new
  `systemctl enable shani-auto-rollback.timer` line, matching
  `check-boot-failure.timer`'s existing entry exactly.

  Two more real bugs surfaced building and verifying this under a genuine
  `--boot` session (via the sibling repo's `probe` command, not just plain
  `enter` — see its own AGENTS.md's harness-improvement entries for why
  that distinction mattered here):
  - **`${XDG_CONFIG_HOME:-$HOME/.config}` crashes under `set -u` when
    `$HOME` is genuinely unset — FIXED across all 6 scripts that had it**
    (`shani-deploy.sh`, `shani-update.sh`, `shani-health.sh`, `gen-efi.sh`,
    `check-boot-failure.sh`, and the new `shani-auto-rollback.sh`). A
    system-level systemd service (no logged-in user) has no `$HOME` at
    all — confirmed live: `shani-deploy --rollback` crashed immediately
    with `HOME: unbound variable` the first time anything in this repo was
    ever invoked from that kind of context. `$HOME` inside the `:-`
    fallback still gets eagerly expanded even when the outer variable
    (`XDG_CONFIG_HOME`) is unset — bash's `:-` only protects the outer
    variable, not ones referenced inside the default value. Fixed to
    `${XDG_CONFIG_HOME:-${HOME:-}/.config}` (nest a second `:-`) everywhere
    — this was a real, pre-existing, latent bug in all 6 scripts, just
    never triggered before because they'd only ever run from a context
    with `$HOME` set.
  - **`shani-auto-rollback.sh`'s own success/failure check was the exact
    "pipe to logger masks the real exit code" bug this session already
    found and fixed once in `shani-ci-commons` — FIXED here too.**
    `if shani-deploy --rollback 2>&1 | logger ...; then` reports `logger`'s
    exit status (always 0), not `shani-deploy`'s — confirmed live: while
    `shani-deploy` was crashing on the `$HOME` bug above, this script was
    still logging "Automatic rollback completed successfully." Fixed to
    capture the real exit code before piping output to `logger`.

- **`finalize_boot_entries()`'s `+3-0` tries-counted candidate entry for a
  fresh deploy likely provides no real automatic hard-failure fallback on
  this systemd version (High, not independently re-confirmed this
  session — inferred from existing evidence, needs a dedicated real
  QEMU+OVMF hard-failure test to close out).** The function's own comment
  claims "systemd-boot automatically falls back to the fallback entry if
  it fails to reach multi-user.target" via the `+3-0` tries suffix. But
  `bless-boot.service`'s own comment (already verified via a real
  qemu+OVMF boot in an earlier session) states systemd-boot "never
  renames a +tries_left-tries_done loader entry... at all on systemd
  261" — a known, open upstream regression
  (systemd/systemd#40405, only 257 and earlier confirmed working). That
  finding was previously scoped only to `bless-boot.service`'s "blessing"
  step (marking a boot good to stop counting); it was not connected to
  `finalize_boot_entries()`'s use of the SAME tries-file-renaming
  mechanism for the opposite purpose (counting down on failure). If
  renaming never happens at all, the counting-down half is equally inert,
  and a hard failure (e.g. root mount fails) on a freshly-deployed
  candidate slot would not trigger any bootloader-level fallback —
  systemd-boot would keep retrying the same broken `+3-0` entry
  indefinitely, since `loader.conf`'s `default=` still names it and the
  file is never aged out. This session verified the marker-file
  chain (`mark-boot-in-progress`/`mark-boot-success`/`check-boot-failure`)
  thoroughly via `systemd-nspawn` (`enter`/`verify-boot`), but nspawn
  cannot exercise real UEFI firmware/bootloader entry selection at all —
  confirming or refuting this specific claim needs an actual QEMU+OVMF
  boot cycle with a genuinely hard-failing candidate slot, which is slow
  (no `/dev/kvm` on this host) and was not run this session. Until that's
  done, treat "automated rollback on boot failure" (touted in this
  repo's own garuda-comparison table) as unverified for the hard-failure
  case specifically — the marker/timer path is real and verified, but it
  only ever *records* a failure; it does not itself switch the default
  boot entry (see the `--rollback` entry above for what does, and its own
  gap).

- **`shani-health --storage-info` crashed with `STOR_MNT: unbound variable`
  every single time — FIXED (2026-09-18).** `analyze_storage()` sets `trap
  '...cleanup...' RETURN` to unmount its temp mount, but bash's RETURN
  trap re-fires on every ANCESTOR function's return too, not just the
  function that set it — live-confirmed with a minimal repro (3-level
  nested calls: the trap fired once for its own function's return, then
  AGAIN for every caller up the stack, including the shell's real top
  level). Since `STOR_MNT` is `local` to `analyze_storage()`, the second
  firing — attributed by bash to `main()`'s own return, at end of script —
  found it out of scope and crashed with `set -u`, right after the full
  report had already printed correctly (rc=1 despite complete, correct
  output). Fixed by having the trap clear itself
  (`trap - RETURN` appended inside the handler) so it fires exactly once.
  Verified live pre/post: crashed with `rc=1` and the unbound-variable
  message before, `rc=0` with no such error after, same command, same
  session, `--local-src` overlay picking up the edited script automatically.
  **The identical pattern existed 4x in `shani-deploy.sh`**
  (`optimize_storage`/dedup, the chroot-UKI-gen cleanup, `verify_and_create_subvolumes()`,
  `deploy_update()`) — not crashing there only because `MOUNT_DIR` happens
  to be a global, not a `local`, so the re-fired trap just harmlessly
  re-runs an idempotent `safe_umount || true` — but a stale trap firing
  mid-flow could still unmount `MOUNT_DIR` while a later phase is actively
  using it for something else (a live correctness hazard, not just noise).
  Fixed the same way in all 4 places; also removed a stray, ineffective
  `trap - RETURN` sitting after `main "$@"` at the very end of the file —
  a prior, incomplete attempt at this same fix that only ran after the
  script had already finished, so it did nothing. Re-verified the full
  real upgrade→rollback cycle and `--optimize` (real `duperemove` run)
  still pass end-to-end after these changes.
- **`bin/shani-upgrade-adviser` was never installed on any real system —
  FIXED (2026-09-18).** The PKGBUILD (`shani-pkgbuilds/shani-deploy/PKGBUILD`)
  only ever globbed `scripts/*` into `/usr/local/bin`; `bin/` was never
  referenced there at all, despite this repo's own CI syntax-checking it
  and running its 21-test suite, treating it as real shipped code. The
  command was completely unreachable on any installed slot — confirmed
  live inside the real test harness (`command not found`, rc=127) even
  though the script itself is fully implemented and its unit tests pass.
  Fixed by moving it to `scripts/shani-upgrade-adviser.sh` (matching this
  repo's existing `scripts/*.sh`→strip-extension convention exactly, so
  no PKGBUILD change was needed at all — the existing glob just picks it
  up). Updated `tests/test_upgrade_adviser.sh` and `.github/workflows/ci.yml`
  for the new path. Verified live with the test harness's documented
  `SHANIOS_TEST_ALLOW_NEW_LOCAL_SRC=1` opt-in (since it was never
  previously packaged, the default overlay correctly refuses it, exactly
  as designed): `shani-upgrade-adviser` and `--json` both now run for
  real and produce correct output. **Still needs a human**: this fix has
  to actually reach a real install — `shani-pkgbuilds/shani-deploy/PKGBUILD`'s
  pinned `_commit` must be bumped to a commit that includes this rename
  once it's pushed, or the real package will keep shipping without it.
- **Self-update fail-closed behavior — NOT independently re-verified this
  session, environment-blocked.** `test-env/self-update-test.sh` (bad
  SHA256 / bad GPG / valid-signed scenarios) failed all 3 scenarios
  identically with "could not fetch script update," not a differentiated
  pass/fail — traced to the test sandbox's own outbound network being
  intercepted/proxied: a `curl` to the `/etc/hosts`-redirected
  `127.0.0.1` for `raw.githubusercontent.com` returned a **real,
  validly-chained Let's Encrypt certificate for `*.github.io`**, meaning
  something outside this container is terminating/forwarding the
  connection regardless of the container's own `/etc/hosts`, so the
  test's local-mock-server mechanism cannot work in this environment.
  This is an environment limitation of this sandbox, not a change to
  self_update()'s logic in this session (untouched) and not evidence of a
  regression — a previous session did verify this path live (see
  `AUDIT-HISTORY.md`). Flagging for re-verification whenever this repo is
  worked on from an environment with real, unproxied outbound network.
- **`shani-health` — every output-format × mode combination re-verified
  live (2026-09-18).** All of `--verify`/`--security`/`--boot`/`--info`/
  `--network`/`--hardware`/`--packages`/`--storage-info`, crossed with
  plain/`--json`/`--nagios`/`--prometheus` (32 combinations), produce
  non-empty, correctly-structured output with no crashes — `--json`
  output validated with `jq`. `--verify`'s real findings in this test
  slot (root writable, `/etc` overlay not mounted) reflect this being a
  non-`--boot` `enter` session, not a bug in the check itself.
- **`check-boot-failure.sh`, `boot-success-cleanup.sh`, `beesd-setup.sh`,
  `shani-user-setup.sh`, `shani-reset.sh --dry-run --yes` — all
  re-verified live (2026-09-18), no new bugs found**, each executed for
  real inside the test harness against a real bootstrapped slot.
- **`shani-deploy --verify-existing` was completely non-functional — FIXED
  (2026-09-18).** `verify_existing_deployment()` referenced two variables,
  `$DATA_CURRENT_SLOT`/`$DATA_PREV_SLOT`, that are never defined anywhere
  in this file (the real slot-marker paths used everywhere else are the
  literal `/data/current-slot`/`/data/previous-slot`) — under `set -u`
  this crashed with `unbound variable` on the very first line of the
  function, before printing anything. It also called `_row`/`_rec`, helper
  functions that exist only in `shani-health.sh` and were never defined
  here — even past the unbound-variable crash, the function would have
  died with `command not found` at its first `_row` call. Confirmed live
  in a real systemd-nspawn container (`shani-install-media/test-env`):
  `shani-deploy --verify-existing` crashed with exit 127 and zero useful
  output before the fix. Fixed by correcting the two variable references
  to the real paths and adding minimal, self-contained `_row`/`_rec`
  helpers scoped to this function (not the full shani-health.sh
  color/JSON/Nagios machinery, which isn't needed here). Verified live
  post-fix: all 14 checks print correctly, and it correctly detected 2 real
  issues on the test system (a slot mismatch and a missing backup) and
  exited 1.
- **`verify_existing_deployment()`'s `((issues++))` — FIXED (2026-09-18),
  same bug class as `shani-health.sh`'s already-fixed `((format_count++))`
  below.** All 6 occurrences were bare post-increments at top-level
  statements under this file's `set -Eeuo pipefail` (line 20) — when
  `issues` is 0 (the first issue found in a run), `((issues++))` evaluates
  to the pre-increment value (falsy), aborting the whole function silently
  under `-e`. This was masked by the unbound-variable crash above (the
  function never reached this code in practice), but is a real,
  independently-reproducible bug — confirmed live with a minimal repro
  (`set -Eeuo pipefail; f(){ local n=0; echo before; ((n++)); echo after; }; f`
  prints "before" and exits 1, never reaching "after"). Fixed to
  `issues=$(( issues + 1 ))`, matching the pattern already used elsewhere
  in this codebase (`errors=$(( errors + 1 ))` in shani-health.sh's
  `_check_fail`). Verified live post-fix: the function now correctly
  counts and reports multiple issues without aborting.
- **`gen-efi.sh`'s ESP-mount fallback chain — completed and fixed
  (2026-09-18).** A pre-existing uncommitted change to `ensure_esp_mounted()`
  added a fallback chain (already-mounted → direct `mount "$ESP"` → fstab
  entries for `/boot/efi`/`/efi` → lsblk-based partition discovery) but was
  never verified before this pass. Verified live via the mandatory real
  test harness: full `clean → ca → bootstrap -p gnome → upgrade
  --local-src → rollback --local-src → clean` sequence passed end-to-end
  with the change in place. A negative control (unmount `/boot/efi`, strip
  its `/etc/fstab` entry, call `ensure_esp_mounted()` directly in a real
  systemd-nspawn session) exposed a real bug in the lsblk-based discovery
  step: `lsblk -no PATH,PARTLABEL,FSTYPE,PARTTYPE` returns empty
  PARTLABEL/PARTTYPE for the ESP partition node inside this container,
  because the parent whole-disk device isn't bind-mounted into it and
  lsblk needs that parent to read the GPT partition table — so that step
  silently no-ops in exactly the chroot/container context this codebase
  runs `gen-efi` in. Fixed by adding `mount LABEL=shani_boot /boot/efi` as
  an earlier, more reliable fallback step, matching the ESP-labeling
  convention `shani-deploy.sh` already uses in 3 other places (`mount
  LABEL=shani_boot ...`) — this works via `/dev/disk/by-label/`, populated
  by udev from the filesystem superblock alone, independent of parent
  device visibility. Re-ran the same negative control post-fix: confirmed
  live that `ensure_esp_mounted()` now correctly falls through to the
  `LABEL=shani_boot` step and mounts successfully. Also fixed a stale
  doc-comment claiming the fallback chain "mirrors sync-esp-boot.sh's
  ensure_esp_mounted" — no file by that name exists anywhere in the shani
  ecosystem.
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

## Garuda Cross-Reference Findings (added 2026-09-17)

Based on a full scan of 29 garuda-linux repos mapped against shani (see `../garuda-catalog.md` — 29 repos, not 34; several user-listed names don't exist). See `../garuda-mapping-analysis.md` and `../deep-analysis.md` for full details. Garuda-tools is the most directly comparable repo — both handle system deployment and boot management.

### 🟡 HIGH: Config & tooling gaps vs garuda-tools

1. **Add centralized config** (estimated 1-2 days).
   - Garuda uses a layered config system: `/etc/garuda-tools/garuda-tools.conf` (system-wide) + `~/.config/garuda-tools/garuda-tools.conf` (user override). Config defines build targets, chroot dirs, cache dirs, mirrors.
   - Shani scripts hardcode paths or use env vars — no equivalent centralized config for deploy/build tools.
   - **Action**: Create `/etc/shani/shani.conf` (or similar) with DEPLOY_CHANNEL, BUILD_MIRROR, ISO_CACHE_DIR, BUILD_DIR. Follow the user-override pattern.

2. **Add checkpkg equivalent** (estimated 1 day).
   - Garuda's `checkpkg` verifies package builds work before publishing. Shani has no equivalent.
   - **Action**: Create a script that runs a package build in a throwaway container and verifies the result without publishing.

3. **Add upgrade safety check** (estimated 3 days).
   - Garuda's `garuda-upgrade-adviser` checks if a system upgrade is safe before running it. Shani has nothing comparable.
   - **Action**: Create a script that checks: current Btrfs snapshot state, free space, running services that might break, pending updates. Integrate into `shani-update` flow.

### ✅ What shani-deploy has that Garuda lacks

| Feature | Shani-Deploy | Garuda Equivalent |
|---------|-------------|-------------------|
| Blue-green Btrfs slot switching | ✅ | ❌ |
| Automated rollback on boot failure | ✅ | ❌ Manual |
| UKI generation/signing | ✅ | ❌ Manual |
| Boot entry management | ✅ | ⚠️ GUI tools exist but manual |
| Health diagnostics | ✅ | ❌ |
| Self-update with verification | ✅ (GPG-signed, fail-closed) | ❌ |
| Real test harness | ✅ | ❌ |
| Chroot detection safety | ✅ | ❌ |

### 🔍 Re-Scan Findings (2026-09-17)

Re-scan against `../garuda-catalog.md` (29 repos, not 34). **Confirmed mappings: garuda-tools** ✅ (exists — `bin/` has buildpkg, buildiso, buildtree, checkpkg, garuda-chroot, signiso, signpkgs, deployiso, testiso, checksumiso) and **garuda-upgrade-adviser** ✅ (exists — minimal shell tool advising on upgrade safety, packaged in AUR).

**New gaps** (garuda has, shani-deploy lacks):

1. **Standalone GPG signing tools** — garuda-tools ships `signiso`/`signpkgs`/`signfile` with a `gpgkey` config in `garuda-tools.conf`; shani's GPG signing is embedded per-script (`self_update()`, `gen-efi.sh`) with no standalone signer utility.
2. **`garuda-chroot`** — garuda-tools has a first-class chroot-into-installed-system tool; shani only has chroot *detection* safety checks, no chroot entry tool.
3. **`testiso`/`checksumiso`** — garuda-tools verifies built ISOs (boot test + checksum); shani relies on the `test-env` harness but has no packaged ISO-verification tool.
4. **`buildtree`** — garuda-tools syncs ABS + custom git repos; shani has no repo-sync tooling.
5. **DocBook man pages + initcpio hooks** — garuda-tools generates man pages via `docbook/` + `xsltproc` and ships `initcpio/` mkinitcpio hooks; shani-deploy has neither.

**Shani advantages** (shani has, garuda lacks):

- Blue-green Btrfs slot switching with automated rollback on boot failure (garuda: manual)
- Real test harness (`shani-install-media/test-env` exercises real deploy/rollback/UKI-signing)
- GPG-signed fail-closed self-update + per-unit systemd hardening (garuda-tools: no equivalent)
- UKI generation/signing with Secure Boot (garuda: manual)

**Note**: garuda-upgrade-adviser is a minimal repo (2-line README, no CI, no compiled code) — the upgrade-safety gap above is real, but shani's `shani-update.sh` rollback machinery already exceeds the garuda tool itself.

### 📋 Implementation Roadmap (2026-09-17)

Implementation priorities are per `../IMPLEMENTATION-ROADMAP.md` (master roadmap for the whole shani ecosystem).

1. **CI Workflows** (P1, ~2-3 days) — Currently no CI at all; verification is entirely manual. Wire `tests/test-deploy-state.sh` into CI for the unit-level state/marker tests (currently the only fast, container-free test). This is safety-critical code where a regression can leave a real machine unbootable — automated regression detection is not optional. Use `shani-ci-commons` templates. Source: IMPLEMENTATION-ROADMAP.md #7.

2. **Centralized Config** (P1, ~1-2 days) — Create `/etc/shani/shani.conf` (INI format) with `[deploy]`, `[health]`, and `[update]` sections, env-var overrides for each key. Adapted from garuda-tools' `garuda-tools.conf` pattern but scoped to deploy/build tools only — **not** for `shani-settings`, which uses `/etc` overlay correctly and is a different (valid) architecture. Eliminates hardcoded paths and scattered env vars. Source: IMPLEMENTATION-ROADMAP.md #12.

3. **Upgrade Safety Adviser** (P2, ~3 days) — Adapt garuda-upgrade-adviser's pattern: a pre-upgrade check that verifies disk space, pending pacman transactions, package conflicts, and current Btrfs snapshot state before allowing `shani-update` to proceed. Integrate into the `shani-update` flow as a gate. **Note**: shani's rollback machinery already exceeds garuda-upgrade-adviser itself; this adds the pre-flight check that garuda-upgrade-adviser provides, not the rollback. Source: IMPLEMENTATION-ROADMAP.md (garuda cross-reference).

4. **Shared CI Templates, Renovate, Conventional Commits** (P1, cross-repo) — Create `shani-ci-commons` with reusable CI templates (master #7 alone is a 2-3 day build; the Renovate #8 and commitizen #9 add-ons are short per-repo adoptions), and commitizen for conventional commit enforcement. These affect all 15 shani repos. Source: IMPLEMENTATION-ROADMAP.md #7, #8, #9.

5. **Explicit: Do NOT Port Boot-Entry/Deploy Logic from Garuda** — Shani's blue-green Btrfs deployment, automated rollback, UKI signing, and chroot detection safety are all superior to anything garuda-tools provides. The table in "What shani-deploy has that Garuda lacks" above documents this clearly. Only the **config layer** (INI config pattern) and the **upgrade-adviser pattern** (pre-flight safety check) are worth adopting from garuda — everything else in garuda's deploy/boot space would be a downgrade.
