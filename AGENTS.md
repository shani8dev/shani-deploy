# Agent instructions — shani-deploy

This file applies to any AI coding assistant working in this repository
(Claude Code, opencode, Kilo Code, Cursor, Aider, or similar). Read this
before editing, and follow the verification steps before calling any change
done.

## Start here (fast path)

This file is long because it holds both the rules you must follow and a
dated record of every bug ever found here. You do not need to read all of it
before you start.

**Always read these first:**
- `What this repo is` — what a bug here actually costs
- `Empirical verification (mandatory)` — the workspace standard
- `This is safety-critical code — treat it that way`
- `Required verification for any change` — the commands
- `MANDATORY: Full Real Test Harness (non-negotiable)` — not skippable
- `Cross-repo impact — check before calling a fix complete`

**Read when your change touches them:**
- `If you have Superpowers / oh-my-opencode / ultrawork / similar available`
  — use parallel subagents for the positive-test/negative-control pairing
- `For anything touching boot entries, signing, self-update, or chroot detection`
- `Known sharp edges (already found once — don't reintroduce)`
- `Testing Shani Cassini and harness compatibility`

**Current known issues — read this before you start:**
- `Audit-verified known issues (confirmed present)` — ~1080 lines. Dated
  postmortems. **Grep it for the subsystem you are
  changing**; read a hit in full, skip the rest. Per-bug verification
  methodology lives in `AUDIT-HISTORY.md`.

  This section mixes fixed history with issues that are **still open**,
  including Critical security ones. Grep it for `not fixed`,
  `still open`, and your subsystem name before you touch anything.

**Background reference — skippable, pure survey material:**
- `Garuda Cross-Reference Findings (added 2026-09-17)` — comparative survey,
  not a requirement.

**Never skip:** the full harness. Nothing here is verified until the real
blue-green switch has been executed and observed.

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

## Test harness: shani-testbed (use it - and improve it, never invent around it)

The ecosystem's real test harness is the sibling repo **`../shani-testbed`**
(read its `README.md` and `AGENTS.md`). It installs a real ShaniOS image with
the real installer, boots its slots (`systemd-nspawn`, and UEFI + TPM VMs),
runs real deploys and rollbacks, drives GUI apps through their accessibility
tree, and checks web pages in a real headless browser. Every command runs from
`../shani-install-media`, which provides the builder container:

```bash
cd ../shani-install-media
./run_in_container.sh build.sh test <command> ...   # `... test help` lists them all
```

**If the check you need does not exist, add it to shani-testbed - do not invent
around it.** A one-off script in this repo, a scratchpad, or a heredoc piped
into a container is lost when the session ends, and the next agent re-derives
it. Extend the harness instead (see "Extend the harness" in its AGENTS.md):

- an in-slot check -> `shani-testbed/slot-tests/<name>.sh` (`# slot-test-mode: boot`,
  prints `RESULT <name> PASS|FAIL|SKIP` lines), run by `slot-test <slot> <name>`;
- a GUI interaction or assertion -> an `app` action in `lib/app.sh`, or a walk
  through a real app as `app-scripts/<app>.actions`;
- a web check -> `lib/web_client.py`;
- a new way to boot, drive or observe -> a command or option in `lib/`;

each with a negative control (a check that cannot fail is not a check), its
self-test (`tests/run-app-actions.sh`, `tests/run-web-client.sh`, ...), and the
`usage` + README updated. One harness run at a time: disk-touching commands
take `disk/.testbed.lock` and a second run is refused. Plain nspawn boots see
the image's whole `/var`; real boots have an empty tmpfs `/var`
(`systemd.volatile=state`) - use `slot-test --volatile`, or a real UEFI boot
with `iso-install --boot-only --console-exec=CMD`, for anything touching `/var`.

### What to run for this repo

- The mandatory sequence (`suite -p <profile> --local-src=/opt/shani-deploy/scripts`)
  is described above.
- Also: `slot-test <slot> unit-verify config-validators service-start`, both
  plain and with `--volatile`; `slot-diff` after `upgrade` (what the next
  reboot changes); `iso-install --boot-only --console-exec=...` for anything
  only a real boot shows (TPM, the real kernel, the empty `/var`).

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
bash -n scripts/shani-deploy.sh scripts/gen-efi.sh \
        scripts/check-boot-failure.sh scripts/shani-auto-rollback.sh

# 2. The unit-level state/marker tests (fast, no container needed)
bash tests/test-deploy-state.sh     # expect: ✓ N passed, 0 failed
bash tests/test-status-json.sh      # expect: ✓ 20 passed, 0 failed
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

Every change to this repo must be verified with the real test harness
(`../shani-testbed`, run through `../shani-install-media`'s runner; the
commands below are unchanged by the 2026-09-23 split — `suite` runs the
whole sequence in one go). This is the ONLY way to prove boot,
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
# NOTE: there is no bin/ any more — shani-upgrade-adviser moved to
# scripts/ on 2026-09-18, so a `bin/*.sh` glob here silently matches nothing.
for script in scripts/*.sh; do bash -n "$script"; done

# Unit tests
bash tests/test-deploy-state.sh     # expect: ✓ N passed, 0 failed
bash tests/test-status-json.sh      # expect: ✓ 20 passed, 0 failed
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

This invokes `shani-deploy` directly with `--force --channel latest
--skip-self-update`. Shani Cassini's **Updates & Rollback** page normally
drives the same engine through `pkexec`, but the harness runs inside a root
nspawn session and therefore calls it directly. `--skip-self-update`
matters here: without it, `shani-deploy`'s own `self_update()` would fetch
and exec the published script mid-run, silently discarding the
`--local-src`-overlaid edited copy. Downloaded images are cached at a
host-persistent path (survives even a fresh `bootstrap` re-run) — see
`--local-src`/caching details in `../shani-testbed/lib/deploy.sh`.

For testing an individual function in isolation (a specific fault
condition, e.g. a stub `sbsign` that "succeeds" while writing garbage —
see `sign-efi-binary-test.sh` and its siblings in
`../shani-testbed/slot-tests/` — visible in every slot at
`/mnt/testbed/slot-tests/` — for the established pattern), use
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

## Testing Shani Cassini and harness compatibility

The user-facing desktop implementation now lives in `../shani-cassini`; its
**Updates & Rollback** page is the current interface for install, channel
selection, status, and rollback. This repo verifies the engine and the
read-only status contract that Cassini consumes. Do not use the retired
`shani-update` wrapper as a current GUI test entry point.

To render the real Updates & Rollback page in a testbed slot, overlay this
checkout's deployment scripts and follow the current desktop procedure in
`../shani-cassini/AGENTS.md`:

```bash
cd ../shani-install-media
./run_in_container.sh build.sh test desktop -p gnome \
    --local-src=/opt/shani-deploy/scripts \
    --exec="(shani-cassini --section=updates &); sleep 25"
```

The testbed also retains `update-check` as a harness compatibility
interface for the old `update` test-command name:

```bash
./run_in_container.sh build.sh test update-check \
    --local-src=/opt/shani-deploy/scripts
# or request the machine-readable result:
./run_in_container.sh build.sh test update-check --json
```

`update-check` is read-only: it exercises
`shani-deploy --status --check --json` and does not install an image,
switch a slot, or run the Shani Cassini notification agent. The shim lives
in `../shani-testbed/lib/deploy.sh`; it is not a user updater and must not
replace the Cassini desktop test above.

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
- **`gen-efi.sh`'s dispatcher is located by TEXT, and `tests/test-tpm2-status-json.sh`
  pulls it out with `sed -n '/^    tpm2-status)$/,/^[[:space:]]*;;$/p'` — the
  FIRST match in the file.** Adding a second `case` whose arm is also indented
  `    tpm2-status)` anywhere above the real dispatch silently breaks the test:
  it extracts that earlier arm instead, and both dispatcher-arm cases fail with
  `rc=0 out=` (an array assignment, no output) rather than anything that looks
  like a real failure. Hit this live on 2026-09-27 while making
  `REQUIRED_CMDS` per-subcommand — 34/0 at `HEAD` became 32/2. The fix was to
  use `if`/`else` in `gen-efi.sh` so exactly one such line exists, **not** to
  loosen the test's expectations. If you add a `case` on a subcommand name in
  any script a test extracts from, check which match the test's `sed` takes.

## Audit-verified known issues (confirmed present)

- **`--rollback` overwrote the previous system when the two slots' versions
  tied - FIXED (2026-10-01).** The 2026-09-25 "go back instead of
  overwriting" fix (31fffd1) only triggered when the booted slot's version was
  STRICTLY newer. Versions are build dates, so two images built on one day (a
  hotfix rebuild) or a redeployed release tie, and the repair path then
  snapshotted the previous slot from the booted one: the old system gone,
  replaced by a copy of the one being rolled back from. Now, with no
  recorded boot failure, a sibling slot with NO backup (a deploy backs up the
  slot it writes into, `<slot>_backup_<ts>`, so no backup = never deployed
  onto = the intact previous system) is gone back to, not overwritten. Found
  by shani-testbed's `suite` (`rollback:restored` FAIL when bootstrap and
  update were the same release); verified: the suite now PASSES all 8 steps,
  log line "@blue has no backup (no deploy wrote into it) ... rolling back to
  it, not overwriting it".

- **Machine-readable interfaces (2026-09-25) — contracts with Shani
  Cassini; change them together:** `shani-deploy --status [--check] --json`
  (read-only, handled before check_root and the deploy lock), `gen-efi
  tpm2-status --json` (stdout is the JSON alone: `log()` writes to stdout,
  so the branch redirects it), `gen-efi enroll-tpm2 --stdin [--with-pin]`
  (secrets via stdin -> systemd-cryptenroll's PASSWORD/NEWPIN, never argv).

- **TPM2 pcrlock support (2026-09-30) — enrollment, status, and health are all
  pcrlock-aware, and the fallback is a literal PCR pin, never a dropped pin.**
  `enroll_tpm2()` prefers a pcrlock policy when one exists
  (`_tpm2_pcrlock_policy_path()` searches `/run/systemd/pcrlock.json` then
  `/var/lib/systemd/pcrlock.json`, systemd v255's own order) and passes
  `--tpm2-pcrlock=PATH --tpm2-public-key-pcrs=`. The empty
  `--tpm2-public-key-pcrs=` is **load-bearing**: without it systemd applies its
  default pubkey PCR mask and returns `EOPNOTSUPP` for a policy that selects no
  PCRs there. The two flags are mutually exclusive — `--tpm2-pcrlock` and
  `--tpm2-pcrs` together are a hard error — so the choice is an `if/else`, never
  two branches that can both run. With no policy the literal pin is used
  unchanged, so a machine is never left with auto-unlock and no PCR binding.

  **Every existing TPM2 entry token is re-enrolled, not just a new one.**
  Token ids come from `_tpm2_entry_token_ids()` (a `cryptsetup luksDump` parse),
  and each is passed with `--entry-token`. A single plain enrollment would leave
  a second, stale token behind — still valid, still unlocking the disk under the
  *old* policy, which is the exact thing a PCR-hardening change is meant to
  eliminate.

  **That helper is portable awk, not gawk.** It originally used `gensub()`,
  which mawk (the awk on Arch) does not implement; the call failed, `|| true`
  swallowed it, and the function reported **zero** tokens — so cleanup
  silently did nothing and enrollment silently skipped re-enrolling the old
  tokens, while every test still passed. A static assertion in
  `tests/test-tpm2-pcrlock.sh` now fails if `gensub` reappears, and the
  negative control restores it to prove the assertion bites. This also fixed a
  pre-existing bug in `cleanup_tpm2()`: it had the same `gensub`, so TPM2
  cleanup had never actually removed a token.

  **Three new contract suites, 69 assertions, all under negative control.**
  - `tests/test-tpm2-pcrlock.sh` (17) — enrollment: policy discovery and search
    order, pcrlock/literal exclusivity, the empty pubkey mask, all-token
    re-enrollment, fresh enrollment, mawk portability.
  - `tests/test-tpm2-pcrlock-status.sh` (32) — `gen-efi pcrlock-status --json`,
    a NEW read-only subcommand. `enrolled_mode` is `"pcrlock"`, `"literal"`, or
    `null`; an undeterminable field is `null`, never `""` and never a default,
    because this field asserts what protects the disk. It also asserts the
    subcommand is **reachable** — see the whitelist trap below.
  - `tests/test-tpm2-pcrlock-health.sh` (20) — the `shani-health` TPM2 row.

  **`pcrlock-status` shipped UNREACHABLE, and every unit test passed anyway —
  read this before adding any subcommand.** `gen-efi.sh` gates subcommands
  **twice**: a hand-written whitelist `if [[ "${1:-}" != "configure" && … ]]`
  near the top of the file, and the `case` dispatcher at the bottom.
  `pcrlock-status` was added to the dispatcher but not the whitelist, so the
  guard printed usage and `exit 1` before the dispatcher was ever reached —
  `gen-efi pcrlock-status --json` returned rc=1 on a real installed slot while
  all 21 unit assertions were green. **They were green because every suite
  extracts the function and calls it directly, which bypasses the guard
  entirely**: no amount of asserting on `pcrlock_status_json`'s behaviour can
  detect a reachability bug. Only the mandatory harness caught it.
  `tests/test-tpm2-pcrlock-status.sh` now asserts whitelist↔dispatcher parity —
  every dispatcher arm must also be whitelisted — so the *next* subcommand
  cannot repeat this. **When you add a subcommand, add it to both lists.**

  Note this is a sibling of the `sed`-extraction trap in "Known sharp edges"
  below, but the opposite failure: there, a second `case` arm made a test
  extract the wrong text; here there is no `case` at all on the path taken, so
  the test passes while the real command never runs.

  **The status reporter shipped with three defects that all produced a
  well-formed, confidently-wrong JSON document**, which is why none of them
  would have been caught by reading the output:
  1. It enumerated entry tokens with `cryptsetup token list`. **That subcommand
     does not exist** — cryptsetup 2.7.0's token verbs are
     add|remove|import|export only (checked against `cryptsetup --help`, not
     assumed). The call always failed and `|| true` swallowed it, so
     `entry_tokens` was `[]` on every machine.
  2. It parsed `tpm2-policy-hash` with a same-line field split. tok255.c:241
     prints `"tpm2-policy-hash:" CRYPT_DUMP_LINE_SEP "%s\n"` — the value is on
     the **following** line — so the hash was always `null`. Both layouts are
     now handled.
  3. `enrolled_mode` was passed with `--arg` as the string `"true"`, so the
     document claimed `enrolled_mode: "true"` and a literal token was
     indistinguishable from an unknown one.

  **Health had the more serious one.** The Secure-Boot cross-check ran on
  pcrlock tokens. systemd v255 renders `tpm2-hash-pcrs` unconditionally
  (tok255.c:235) from the token JSON, *not* from the sealed policy — so a
  correctly pcrlock-enrolled volume whose header list was not exactly `0+7` was
  reported as "PCR policy mismatch" and told to **re-enroll**, i.e. to replace a
  working pcrlock enrollment with a weaker literal pin. That is a security
  *downgrade* recommended by the health check. The cross-check is now guarded
  with `-z "$_pcrlock"`, and the negative control drops that guard to prove the
  suite catches the fabricated mismatch and the downgrade recommendation.

  **Do not add pcrlock fields to `tpm2_status_json()`.** Its 11 keys are a
  documented contract with Shani Cassini, and the repo's own rule is that a
  field nothing renders is a field nobody has. `pcrlock-status` is a separate
  subcommand precisely so the existing contract stays byte-stable.

  **Not verified, and it is the part that matters:** no real pcrlock enroll +
  unseal has been run. Measured in a real `test enter blue` slot on 2026-09-30,
  pcrlock is inert for **three independent** reasons — any one of which alone
  would be enough. An earlier version of this entry blamed a missing package
  and a missing plugin; both of those turned out to be present, so the reasons
  below are the ones actually observed:

  1. **The cryptsetup token plugin IS shipped** —
     `/usr/lib/cryptsetup/libcryptsetup-token-systemd-tpm2.so` is present in the
     built image, and `/usr/lib/systemd/systemd-pcrlock` plus the full
     `/usr/lib/pcrlock.d/` fragment set (`750-enter-initrd`, `800-leave-initrd`,
     `900-ready`, the `400-`/`500-`/`700-` separator variants) are all there.
     `systemd-pcrlock list-components` runs clean (rc=0) and enumerates them.
     So the packaging is fine and "add the package" is not the fix.
  2. **pcrlock does not reach the initramfs.**
     `lsinitrd /boot/initramfs-linux.img | grep -c pcrlock` returns **0**.
     The fragments are location-keyed to the boot sequence, and nothing pulls
     `systemd-pcrlock@.service` / `systemd-pcrlock.socket` into the initrd, so
     no policy is ever made early enough to matter. `systemd-pcrlock@.service`
     is `static` (socket-activated, which is normal) — the socket is simply not
     in the initrd. Adding that is initramfs/dracut work in
     `shani-settings`/`shani-install-media`, not here.
  3. **`systemd-pcrlock make-policy --location=770` exits 1** in a real slot:
     `Failed to create TPM2 context: State not recoverable`, because there is no
     `/dev/tpmrm0`. `systemd-pcrlock is-supported` reports `partial` (rc=107).
     `predict` fails identically. **Note the failure is loud** — exit 1, no
     `/run/systemd/pcrlock.json` written — so a boot chain that trusted the
     exit status would not silently proceed without a policy.

  A fourth, design-level blocker sits behind those, and it is the one that
  actually decides the matter. The policy-producing unit carries
  `ConditionSecurity=measured-uki`. **Corrected 2026-09-30 — the earlier wording
  here said the condition is satisfied by a `.pcrs` section, which is the wrong
  link in the chain.** `efi_measured_uki()` (v262 `src/shared/efi-loader.c`,
  called from `src/shared/condition.c:857`) consults **no PE section at all**. It
  reads the `StubPcrKernelImage` EFI variable, requires it to exist, parses it
  as a PCR number, and requires it to equal `TPM2_PCR_KERNEL_BOOT` — which is
  **11** (`src/fundamental/tpm2-pcr.h:28`). It also returns 0 outright unless
  `efi_has_tpm2()`. Note a third state: a stub that measured into a
  *different* PCR returns `-EREMOTE`, i.e. an error rather than a clean false.
  `.pcrs` is the upstream **cause** of that variable, not the condition itself —
  the section is what makes sd-stub measure the kernel image and publish
  `StubPcrKernelImage=11` in the first place. So the doc's original inference
  was sound but mis-stated: `.pcrs` absent ⇒ stub never measures ⇒ variable
  absent ⇒ condition false. Shanios' UKI has no `.pcrs`, verified three
  independent ways: `generate_uki()` invokes only `dracut`, `generate_cmdline`,
  `sign_efi_binary`, `_stage_mok_enrollment` and `update_bootloader` (no
  `ukify`, no `objcopy`, no `systemd-measure`, no `.pcrs` handling — it re-signs
  the kernel package's prebuilt UKI rather than assembling one); and `objdump -h`
  on the real `/boot/efi/EFI/shanios/shanios-blue.efi` lists `.text .rodata
  .data .sdmagic .reloc .osrel .cmdline .splash .sbat .linux .initrd` — a
  genuine UKI, with `.pcrs` absent. **So the condition is unsatisfiable, not
  merely likely false**, and no amount of TPM or swtpm will make the pcrlock
  policy phase run. Making pcrlock usable needs measured-UKI/`systemd-measure`
  work in `gen-efi.sh` first — a materially larger change than the
  enrollment/status/health work above, touching how UKIs are built and signed,
  and a decision for a human rather than a mechanical follow-on. (Audit §12
  currently records `systemd-measure` as "SKIP for now" precisely because it
  wants a signing key; pcrlock was meant to cover the need without one, but
  pcrlock itself now turns out to require the measurement.)

  **Two traps in testing any of this, both hit for real on 2026-09-30.**

  1. **`SYSTEMD_TPM2_DEVICE` cannot redirect systemd to an emulator.**
     `tpm2-util.c:617` reads it with `secure_getenv()`, so it is deliberately
     ignored in any privileged (`AT_SECURE`) context — which includes a root
     process in a container. The variable looks like the obvious way to aim
     `systemd-cryptenroll` at a `swtpm` TCTI (`swtpm:host=…,port=…`, and the
     image does ship `libtss2-tcti-swtpm.so.0`), and it silently has no effect:
     the code falls through to its hardcoded `device:/dev/tpmrm0`. A test that
     sets it and sees no error is not testing what it thinks it is.
  2. **`systemd-cryptenroll --tpm2-device=list` succeeding does NOT mean the
     TPM works.** It enumerates devices without opening an ESAPI context, so it
     printed a real chip (`/dev/tpmrm0 NTC0702:00 tpm_tis`, rc=0) on a host where
     `make-policy` then failed with `Failed to open specified TCTI device file
     /dev/tpmrm0`. This is the same "a check that cannot fail" shape as the
     nonexistent `cryptsetup token list` and the `--tpm2-argon2id` flag: always
     use something that actually opens the TPM.

  This host does have **real TPM hardware** (Nuvoton NCT, `/dev/tpm0` +
  `/dev/tpmrm0`). The `root:tss 0660` node is **not** the wall it looks like:
  a container run as uid 0 with `--device /dev/tpmrm0 --device /dev/tpm0`
  gets the node with correct ownership and systemd-cryptenroll enumerates it
  (`NTC0702:00 tpm_tis`). Only an *unprivileged* host process is blocked, and
  only by group membership (there are no ACLs on the node to exploit). So the
  TPM is reachable — that is **not** the blocker.

  The actual blockers to a real enrollment here are two, and both are
  environmental:

  1. **Loop devices are exhausted.** A LUKS2 volume needs a block device, and
     all 31 loop devices on this host are held by snapd. `losetup --show -f`
     inside a `--privileged` container fails ("failed to set up loop device"),
     and the fix — detaching a snapd loop — would break the user's installed
     snaps, so it is not ours to do. (A container run here also leaked a
     loop device; `losetup -d` needs root, so it needs clearing by hand.)
  2. **`systemd-pcrlock` is absent from `shrinivasvkumbhar/shani-builder`.**
     The builder image has `systemd-cryptenroll`, `cryptsetup`, `losetup` and
     `libcryptsetup-token-systemd-tpm2.so`, so a *literal*-PCR enrollment would
     work given a loop device — but there is no `systemd-pcrlock` to
     `make-policy` with, so the pcrlock path cannot be set up from that image
     without copying the binary in from the built rootfs.

  `swtpm` is apt-installable and runs fine as a non-root user, but per (1) it
  cannot be substituted for systemd. `systemd-vmspawn` is absent from host and
  image, so the clean route — a VM with a virtual TPM, which also solves the
  loop-device problem because the guest gets its own devices — is unavailable;
  testbed `vmspawn` support is the intended one.

  **Conclusion: TPM2 enrollment cannot be exercised on this host** (pcrlock or
  literal) because of loop-device exhaustion and a missing builder binary, not
  because of TPM permissions and not because of anything in this code. The
  reasoning is recorded because the first two conclusions reached here were
  both wrong: "no TPM exists" and "the TPM is unopenable" were each refuted by
  the next experiment.

- **`shani-deploy --list-backups --json` is a contract added 2026-09-27, and it
  is the one place the `--json` guard was relaxed.** `--json` is otherwise
  refused without `--status`/`--check`, so the relaxation is deliberately
  narrow: `--list-backups` only. The JSON is built with `jq -nc`, never by
  string-concatenating a tool's output. Each entry carries a **per-slot**
  version — a slot's backups are identified by the slot they came from, not by
  the current slot. The unmount before the read **refuses to touch subvolid 5**,
  because that is the filesystem root and unmounting it is how a machine stops
  booting; a refusal is reported, not forced. `tests/test-list-backups-json.sh`
  (27 cases) is the contract test. Read-only and unprivileged, like `--status`.

- **`gen-efi tpm2-status --json` gained four LUKS fields on 2026-09-27, and the
  original seven keys did not change.** `luks_version`, `luks_cipher`,
  `luks_kdf` and `luks_keyslots_in_use` were added so Cassini would stop
  asserting "LUKS2" from what LUKS2 usually is. **This was backend-only until
  the same day** — a field nothing renders is a field nobody has, and it took a
  renderer in `tabs/encryption.py` plus four tests to make it real; treat
  adding a JSON key here as unfinished until something consumes it. A field the
  tool cannot determine is omitted or empty rather than defaulted, because
  Cassini draws an empty value as "Not available" and a default would be a
  claim about what protects the disk. **`luks_keyslots_in_use` is JSON `null`
  when undetermined, never `0`** — fixed 2026-09-27: the count awk matched only
  LUKS2's `  0: luks2` shape, so a LUKS1 disk (which says `Key Slot 0: ENABLED`
  and always lists all eight slots, seven DISABLED) reported 0, and `${x:-0}`
  turned that into a literal 0 the GUI printed as "0 keyslots in use". Both
  shapes are counted now, LUKS1 counting ENABLED only, and neither matching
  yields null. `tests/test-tpm2-status-json.sh` (34 cases) is the contract test;
  its LUKS1 fixture is verbatim real `cryptsetup luksDump` output, because the
  previous one was LUKS2-shaped fiction and passed against a format LUKS1 never
  emits.
- **The POPULATED branch is verified end to end against a real encrypted slot
  (2026-09-27).** Reaching it needed a test-only unlock: a Shanios install is
  configured `rd.luks.options=<uuid>=tpm2-device=auto` with no keyfile, so a
  container with no TPM cannot boot an encrypted root unattended.
  `shani-testbed/lib/install.sh` `cmd_bootstrap` now drops a throwaway keyfile
  into the slot, points its `/etc/crypttab` at it, adds both to dracut
  `install_items` and regenerates the initramfs — guarded on `encrypted`, so
  default and unencrypted runs are untouched. With that, `dmsetup mknodes` plus a
  node for the mapping's backing device (read the real major:minor out of
  `dmsetup table`) makes gen-efi report `luks_version=2`,
  `luks_cipher=aes-xts-plain64`, `luks_kdf=argon2id`, `luks_keyslots_in_use=1`
  on a genuinely encrypted slot. That verbatim JSON is checked in as
  `shani-cassini/tests/fixtures/tpm2-status-encrypted-slot.json` and drives the
  real `EncryptionTab._on_status` in three tests, so the contract and the GUI
  are joined by real bytes rather than by hand-written dicts. Not yet proven:
  a live session photographed with those values in the widget tree; the harness
  click/OCR path could not locate the Check button reliably.

- **shani.conf's values reached `mount`, `umount`, `mkdir` and `cryptsetup`
  unvalidated — FIXED in `gen-efi.sh` (2026-09-27); the other four copies are
  still open, deliberately.** `_load_ini_config()` accepts any value: the key
  and section regexes already constrain the *variable name* to `[A-Za-z0-9_]`
  and `printf -v '%s'` does not expand the value, so there is no injection —
  but nothing checked the value either. `deploy_esp_path` becomes `ESP`, which
  reaches `mount "$ESP"`, `umount "$ESP"`, `mkdir -p "${ESP}/EFI/BOOT"` and a
  `cp` of `MOK.der` onto the ESP; `deploy_rootlabel` is interpolated into
  `/dev/mapper/<label>` and handed to `cryptsetup status`/`luksDump`. A
  mistyped or hand-edited `/etc/shani/shani.conf` could point any of those
  somewhere unintended — `esp_path=/` and `esp_path=boot/efi` were both
  accepted verbatim. The parser is **byte-identical in five scripts** (md5
  `b180d40b…` in `gen-efi.sh`, `shani-deploy.sh`, `shani-health.sh`,
  `check-boot-failure.sh`, `shani-auto-rollback.sh`), the same shape as the
  documented 5-copy `get_booted_subvol()`.

  `_validate_config()` now runs after both config loads and before `ESP` is
  assigned: `esp_path` must be absolute, must not be `/`, must not contain
  `..`; `rootlabel` must match `^[A-Za-z0-9_-]+$`. A rejected value falls back
  to the default and warns on stderr — it is not used, and not silently
  dropped either. `/efi` and a trailing slash are deliberately still accepted:
  `/efi` is a real ESP on this image, so a rule that rejected it would break a
  working machine.

  **Severity, stated honestly: this is robustness, not a privilege boundary.**
  Measured, not assumed: a `sudo`-invoked root process gets `HOME=/root`, not
  the invoking user's home, so that path resolves to `/root/.config/shani/shani.conf`;
  under a system service `HOME` is unset and it collapses to
  `/.config/shani/shani.conf`; `pkexec` sanitises the environment. All three are
  root-owned, so a user's own `~/.config` copy is never read by a privileged
  invocation. Only a root-written `/etc/shani/shani.conf` (or `/root/.config/…`)
  can produce a bad value. Do not "upgrade" this into a security fix without new
  evidence about the invocation context — the obvious escalation here was
  investigated and does not exist.

  **The one genuinely self-referential thing nearby, also not a vulnerability.**
  Under `--update-genefi`, `shani-deploy` downloads `gen-efi.sh` from
  `deploy_genefi_script_url`, fetches `${URL}.sha256` and `${URL}.asc` **from the
  same origin**, and verifies the signature against `deploy_gpg_key_id` — so all
  four (URL, checksum, signature, verifying key) come from the same config file,
  and the SHA256+GPG check proves nothing against someone who can write that
  file. It looks alarming and is not an escalation, for the reason above: the
  config is root-owned, and pointing a mirror at your own host and key is a
  legitimate thing for an operator to do. Two things are still worth knowing:
  the default path does **not** download anything (it copies the host's
  installed `gen-efi`, and only `--update-genefi` reaches the download branch),
  and the comment above that block claims the verification protects the
  "code that will run as root inside the chroot", which is true of its
  fail-closed fallback to the host copy but not of its trust anchor. If
  `deploy_gpg_key_id` is ever meant to be operator-independent, it has to stop
  being read from the same file as the URL.

  **Do not add a key allowlist to this parser.** It is the obvious completion
  of this fix and it would be a live regression. The shipped
  `etc/shani/shani.conf` documents **34** keys while the scripts read **38**;
  an allowlist built from the sample silently drops 12 keys that are in use
  today (`deploy_booted`, `deploy_state`, `deploy_auto_rollback_done`,
  `deploy_genefi_bin`, `deploy_user_setup_bin`, …), and 9 documented keys are
  read by nothing. The sample is documentation, not an inventory.
  `tests/test-config-validation.sh` asserts both directions of that, so the
  next person to try gets a red test rather than a broken image.

  **The first version of that test was vacuous, and the negative control is
  what caught it.** It extracted `_load_ini_config`/`_validate_config` and
  called them itself, so it proved the validator works while saying nothing
  about whether the script *uses* it — commenting out the single
  `_validate_config` call still reported 12/12. The test now also asserts the
  wiring and its **order** (after the loads, before `ESP=`), because order is
  what makes it a protection; with the call removed it reports 3 failures and
  exits 1. 15 assertions, all six unit gates green, and the full mandatory
  harness green with the edit in place (`clean → ca → bootstrap -p gnome →
  upgrade --local-src → rollback --local-src → clean`), the `upgrade` step
  doing the real UKI generate-and-sign for `@green`.

  **Now fixed in `shani-deploy.sh` as well (2026-09-27), which is the one that
  mattered most.** It resolves the same config into 22 variables and feeds
  three sinks `gen-efi.sh` does not: `MOUNT_DIR` (mount/umount of the chroot
  root), `GENEFI_SCRIPT` (handed to `chroot` to be **run as root**), and five
  thresholds that land in `$(( ))`/`(( ))`, where a non-numeric value is an
  arithmetic error rather than a diagnosis of the typo. Same shape of
  validation, with the numeric cases clamped to a **floor** rather than to the
  default — `max_inhibit_depth=0` and `min_free_space_mb=0` are deliberate
  choices and are kept, while `max_download_attempts=0` is raised to 1 because
  a zero-retry loop is not a choice anyone means to make. It has to run between
  the assignments and the `readonly` block that follows them, so it is a call
  there and not a check folded into the assignments; the test pins that order,
  because correcting an already-`readonly` variable would fail outright.

  **All four consumers are now done (2026-09-27), and the fifth was never
  exposed.** `check-boot-failure.sh` (six marker paths) and
  `shani-auto-rollback.sh` (four) also `rm -f` / `>` / `touch` their values as
  root, so they get the same narrow rule — absolute, not `/`, no `..` — with the
  width chosen so a legitimate marker under `/data` **or `/run`** keeps working.
  `/run` is not hypothetical: `reboot_needed=/run/shanios/reboot-needed` is
  shipped in the sample config, and a rule tightened to "must be under /data"
  would break it. `shani-health.sh` resolves **no** config-derived variable at
  all — it reads the file and uses none of it — so it was never in scope and
  should not be "fixed" by copying code into it.

  **Four copies of `_vc_bad_path`, deliberately independent**, matching the
  existing 5-copy `get_booted_subvol()` convention: these are separately
  packaged executables with no shared-library mechanism, and a sourcing change
  is a packaging change. What guards against them drifting apart is in the test,
  not in a shared file: `tests/test-config-validation.sh` counts the guarded
  variables against the assigned ones **per script**, so adding a marker without
  guarding it fails.

- **`gen-efi.sh`'s dependency preflight was unconditional, so the read-only
  `tpm2-status` demanded the whole write-path toolchain — FIXED (2026-09-27).**
  `REQUIRED_CMDS` was one flat list of 19 commands checked before dispatch, so
  `tpm2-status --json` aborted with `Required command 'dracut' not found` on any
  machine missing `dracut`/`sbsign`/`sbverify`/`bootctl`/`blkid`/`btrfs`/
  `lsblk`/`findmnt`/`df` — tools that path never calls. `tpm2_status_json()`
  only reads: `cryptsetup` for the mapper status and LUKS header, `jq` to emit
  the document, `grep`/`awk`/`sed` to slice those tools' free-form text. The
  visible failure was the documented "stdout is the JSON alone" contract
  returning **empty stdout**, because the branch is the one that redirects
  stdout to stderr and reserves fd 3 for the JSON — so Cassini's encryption
  page got nothing to parse and the error named a boot tool for an operation
  that never touches the boot chain. The set is now chosen per subcommand:
  `tpm2-status` gets `cryptsetup jq grep awk sed date`, and **every other
  subcommand keeps the original list byte for byte** (verified by md5 of the
  list line against `HEAD`), because all six of them sign or write boot state.
  `systemd-cryptenroll` and `mokutil` are deliberately still absent from the
  reduced set — `tpm2_status_json()` already treats them as optional
  (`command -v` guard, `|| true`) and reports their absence as a false field,
  so requiring them would reintroduce the same class of failure.

  Verified with a negative control rather than a positive test alone: the
  pristine `HEAD` script and the edited one were run against an **identical**
  stripped `PATH` (only the six read-side tools; no `blkid`, no `dracut`, no
  `pkexec`/`sudo`). Pre-fix `tpm2-status` failed naming `blkid`; post-fix it
  passes. All six write subcommands, plus no-args and a bogus subcommand,
  behaved **identically in both** — still refusing on `blkid`, i.e. nothing was
  relaxed. Then as real root in a real installed slot (`test enter blue
  --local-src`), with `dracut`/`bootctl`/`blkid`/`sbverify` all absent from
  `PATH`: `tpm2-status --json` returned rc=0 with clean sole-stdout
  `jq`-parseable JSON, all 11 keys present and `luks_keyslots_in_use: null`
  (not `0`, per the contract above), empty stderr — while all six write
  subcommands on that same reduced `PATH` still exited 1 naming `blkid`. Full
  mandatory harness green with the edit in place (`clean → ca → bootstrap -p
  gnome → upgrade --local-src → rollback --local-src → clean`), the `upgrade`
  step exercising the real write path: UKI generated and signed for `@green`,
  "Deployment successful!". Unit gates: `test-deploy-state` 12/0,
  `test-status-json` 20/0, `test-list-backups-json` 27/0,
  `test-tpm2-status-json` 34/0, adviser suite pass.

- **`--status --json` boot/recovery fields are a real, marker-derived
  contract (2026-09-25).** Cassini's Updates & Rollback / System views read
  `boot_failure`, `boot_hard_failure`, `auto_rollback_done`,
  `reboot_needed` and `candidate_boot`; every one is read from a marker
  some other part of this repo really writes, and unreadable state is
  reported empty/false — never guessed, never defaulted. Semantics, all
  enforced by `tests/test-status-json.sh` (20 tests):
  - `boot_failure` — `$BOOT_FAILURE_FILE`, falling back to its `.acked`
    copy, the same precedence `rollback_system()` uses, so `--status` can
    never disagree with what `--rollback` would act on. `""` = none.
  - `boot_hard_failure` — `$BOOT_HARD_FAILURE_FILE` (dracut initramfs
    hook, before the root mount is attempted). Never merged into the soft
    field; `shani-auto-rollback` gives it priority.
  - `auto_rollback_done` — `$AUTO_ROLLBACK_DONE_FILE`. Written by
    `shani-auto-rollback.sh` on success **and** on failure (it is the
    "don't retry this boot" flag) and cleared at the start of every boot
    by `mark-boot-in-progress.service`, so `true` means "already
    attempted this boot", NOT "recovered" — the outcome is only in
    `journalctl -t shani-auto-rollback`. Do not read it as a success flag.
  - `reboot_needed` — version string from `$REBOOT_NEEDED_FILE`, written
    by `finalize_update()` and removed by every rollback path; `/run` is
    tmpfs, so it also vanishes on the next reboot. `""` = no finished
    deploy awaiting a reboot.
  - `candidate_boot` — true ONLY while a finished deploy is still pending
    in this session: the reboot marker exists AND the slot markers show
    the default really moved to the other slot while we keep running the
    old one. **It must never be derived from `booted != current` alone** —
    that is equally true after a bootloader fallback (a failure, reported
    via `boot_failure`) and after a rollback that already switched the
    default, where nothing is pending at all. Both inputs missing or not
    a real slot name ⇒ `false`.
  - `booted_slot` — `""` when the running subvolume cannot be determined
    at all. It is reported, never fatal: `--status --json` must always
    emit one valid JSON object, whatever the machine state.
  - Two live bugs fixed here, both found by that "always emit JSON" rule:
    `get_booted_subvol()` ends in `die()`, and an `exit` inside `$(...)`
    kills the subshell before an inner `|| true` can run, so
    `booted=$(get_booted_subvol 2>/dev/null || true)` returned non-zero
    and aborted the whole script under `set -e` — **`--status --json`
    printed nothing and exited 1** whenever the booted subvolume was
    undetectable. The `|| booted=""` must sit OUTSIDE the substitution.
    The same class of bug (a bare `[[ ... ]] && var=true` statement
    aborting under `set -e` when the test is false — see the
    `((issues++))` entries below) had also been introduced for
    `auto_rollback_done` and `candidate_boot`; both are `if` blocks now.
  - `CURRENT_SLOT_FILE`/`PREV_SLOT_FILE`/`AUTO_ROLLBACK_DONE_FILE` are
    new config-resolved read paths. The slot-marker **writes** in this
    file still use the literal `/data/current-slot` and
    `/data/previous-slot` — same defaults, but never change one side
    without the other. `tests/test-status-json.sh` fails if a literal
    `/data/` or `/run/shanios` path reappears inside `status_json()`.
  - **Still needs the real harness** (see "Required verification"): the
    unit tests drive the real `status_json()` against a sandbox of marker
    files with only `get_booted_subvol`/`read_channel_from_file` stubbed.
    What they cannot cover is the real marker lifecycle on a real
    installed system — the actual transitions below still need a live
    `bootstrap → upgrade → reboot → fallback → rollback` run.
- **Oversized swapfiles from old ISOs:** `check_space` shrinks/drops
  /swap/swapfile when the update does not fit (`reclaim_swap_space`) and
  `sync -f`s before re-measuring — Btrfs' df only moves on commit.

- **`-r` from the updated system destroyed the previous one — FIXED
  (2026-09-25).** `rollback_system` assumed it runs from the slot to keep
  and repaired the other from its backup; the previous slot has no backup
  (it was never a deploy candidate), so it was replaced with a snapshot of
  the booted one - both slots ran the new build. The docs and the fleet
  guide (`ssh ... 'shani-deploy -r && reboot'`) run it exactly that way.
  Now: booted slot newer than the other and no recorded boot failure ->
  `switch_to_sibling_slot ... go-back` (boot entries + markers only). The
  suite's `rollback:restored` check (shani-testbed) now fails the old
  behaviour; it exited 0 and passed before.
- **Found by shani-testbed's release gate on 2026-09-24, all FIXED:** a
  successful deploy exited 1 when the reboot timer could not be armed;
  self-update carried a pre-2026-08-21 script's `AUTO_REBOOT=yes`;
  `shani-user-setup` compared shells by name (/bin/zsh vs /usr/bin/zsh
  after the sbin merge) and rewrote passwd on every run until the path
  unit's trigger limit killed it, and it forced every user back to zsh
  (now only a missing shell is replaced); fstab bind sources were created
  at the Btrfs top level (a stray `data/varlib/*`) instead of `@data`;
  `check_space` ran before knowing whether an update exists; a
  deploy-time swapfile ignored the update reserve; `shani-health
  --security` scored no units (systemd-analyze only lists loaded ones).

- **Chroot teardown left `/mnt/proc` mounted under nspawn; the emergency
  rollback then hung forever in `btrfs subvolume sync` — FIXED
  (2026-09-24).** The mandatory suite's `upgrade` failed twice (2026-09-23
  11:19 and 21:21) right after "UKI generated": `Failed to unmount:
  /mnt/proc` → `/mnt` stuck → `restore_candidate` mounted `subvolid=5` on
  top of the still-mounted `@green`, deleted `@green` underneath it
  ("Subvolume restore failed"), and `btrfs subvolume sync /mnt` waited 4 h+
  (the deploy namespace showed `/mnt` rooted at `/@green//deleted`). Root
  cause, reproduced under plain systemd-nspawn: an rbind of `/proc` carries
  `/proc/sys/kernel/random/boot_id` twice, and both `umount -R` and
  `umount -R -l` abort on the second copy ("not mounted", rc 32) leaving the
  tree mounted; a plain `umount -l` (MNT_DETACH) takes the whole subtree off
  (rc 0). Fixes in `shani-deploy.sh`: `_umount_tree()` (`-R` → `-R -l` →
  `-l`) used by `safe_umount` and every `restore_candidate` unmount;
  `restore_candidate` now refuses to stack `subvolid=5` on a still-mounted
  `$MOUNT_DIR` and aborts before touching any subvolume; `btrfs_sync` is
  bounded (`BTRFS_SYNC_TIMEOUT`, default 900 s) because a deleted-but-mounted
  subvolume is never cleaned. `shani-health.sh`'s unmount got the same `-l`
  fallback. Verified: full `suite -p gnome` PASSED (upgrade 132 s,
  "Deployment successful!", no unmount warning). The same run exposed a
  *harness* pin on rollback (the upgrade step's `@blue` overlay stayed
  mounted), fixed in shani-testbed `_enter_prep`, not here.

**For the full narrative, verification methodology, and before/after
  evidence behind every line below, see `AUDIT-HISTORY.md`.** This section
  is deliberately just the current-state summary — what's true right now,
  not how it got that way.

- **`download_update()` built its R2 path from the wrong profile token —
  FIXED (2026-09-19). R2 was wired in but the path was wrong, so every
  deploy silently fell back to SourceForge.** `r2_image_path` used
  `${REMOTE_PROFILE}` = `stable-gnome`, but R2 stores artifacts under the
  bare profile (`gnome/`); `stable-gnome/` 404s, so `get_remote_file_size`
  returned 0 and the mirror fallback ran instead. Fixed to
  `${REMOTE_PROFILE#stable-}` in `fetch_update()` (L3058) — applied to
  `REMOTE_PROFILE` *itself*, so EVERY downstream use gets the bare profile:
  the R2/SF download URLs, the checksum/asc URLs, the mirror-discovery
  path, and the profile-mismatch comparison against `LOCAL_PROFILE` (which
  `/etc/shani-profile` stores bare). Verified live: R2 now reports `Primary
  server available — image size: 2.4G` and the zsync2 differential download
  begins from `downloads.shani.dev/gnome/20260918/...`. **SourceForge's
  v20260918 404 is a separate, real upstream publish gap** (pointer exists,
  artifact not uploaded) — host-confirmed, not this bug. SF and R2 use
  *different* directory conventions for the same artifact, so the fix is
  R2-only; the SF checksum/signature URLs still use `stable-gnome/`.
  **Note:** the fix was already documented here as applied before this
  session's regression run, but the source did not actually contain it —
  the full `clean → ca → bootstrap → upgrade → rollback → clean` sequence
  reproduced the failure live (`Remote version: v20260918 (stable-gnome)`
  → R2 404 → SF 404 → "All download tools failed"), which is how the gap
  between doc and code was found. The strip is now a no-op for manifests
  that are already bare (e.g. `shanios-20260807-gnome.zst`), so it handles
  both filename forms.

- **`show_dialog()`'s yad invocation used a flag that doesn't exist —
  FIXED (2026-09-19). No shani-update dialog had EVER actually rendered
  via yad, on any real system, ever.** `--image-on-top` was never a real
  yad option (confirmed against a real yad 15.0: `yad --help-general`
  lists `--image=IMAGE` and `--on-top` as two SEPARATE flags — both
  already present in this file under their real names — no combined
  `--image-on-top`). Every yad invocation failed to even parse its
  command line ("Unable to parse command line: Unknown option
  --image-on-top", exit 255) before ever trying to open a display.
  Worse than a clean failure: the backend-detection logic only recognizes
  `rc=1` (GTK's real "can't open display" code) as a dead backend; `rc=255`
  fell through as "non-standard exit = bad backend, try next", silently
  exhausting every `GDK_BACKEND` value and then zenity too, every time.
  Found and confirmed by actually rendering a dialog end-to-end — not by
  reading the code — via a new X11/Wayland-forwarding capability added to
  the sibling `shani-install-media` test harness specifically because the
  harness's existing headless-Wayland-compositor approach (`gnome-shell
  --headless --virtual-monitor=...`) has its own real GTK3/Wayland client
  compatibility gap (see that repo's AGENTS.md for the full story). Fixed
  by removing the invalid flag; `--image=`/`--on-top` already provide the
  real functionality it was trying to duplicate. Every other yad flag in
  this file was cross-checked against a real `yad --help-all` dump and
  confirmed valid — this was the only one.
- **Critical failure notifications upgraded from passive `notify-send`
  bubbles to modal dialogs — new `show_alert()` (2026-09-19).**
  `_handle_fallback_boot()`'s "automatic recovery failed" paths only used
  `notify-send`, which is trivially missed (auto-dismisses, easy to not
  notice) for what is a "your safety net didn't catch you" event that
  deserves active acknowledgment. `show_alert()` wraps `show_dialog()` in
  single-button mode (a new capability: `cancel_label=""` now suppresses
  the second button entirely, via `${4-Cancel}` instead of
  `${4:-Cancel}` in `show_dialog()`'s own parameter defaults — the colon
  form can't distinguish "explicitly empty" from "not passed") with the
  same GUI/notify-send/console fallback chain `show_dialog()` already has.
  **Return-code contract (corrected 2026-09-19):** `show_alert()` returns
  the SAME codes as `show_dialog()` — 0=acknowledged, 1=cancelled/timeout,
  2=no GUI at all. It does NOT repurpose rc to mean "fallback used": when
  rc=2 it has ALREADY done the notify-send/console fallback itself. Every
  current caller (`_handle_fallback_boot` L1036/L1054) follows it with
  `_cleanup_and_exit N` regardless and never inspects the value, so this
  is documentation-only, not a behavior change. (An earlier version of the
  docstring claimed rc=1 meant "fallback used"; that was wrong — confirmed
  by a deterministic unit test with stubbed yad/notify-send.)
- **New: persistent system-tray icon — `shani-update --tray` +
  `shani-update-tray.service` (2026-09-19).** Uses `yad --notification`,
  which needs a StatusNotifierItem/AppIndicator host to render at all
  under modern GNOME (no built-in legacy tray since 3.26) —
  `gnome-shell-extension-appindicator` is already a `shani-desktop-gnome`
  PKGBUILD dependency, confirmed present. Deliberately does NOT call
  `_acquire_lock`: this is a long-lived process (started once at login,
  `WantedBy=graphical-session.target`), and its menu actions each spawn
  an ORDINARY separate `shani-update` invocation that acquires/releases
  the single-instance lock itself — a tray icon holding that lock for its
  whole lifetime would deadlock every periodic/manual check for as long
  as it's running. **Real bug found and fixed via live testing**: yad's
  `--command=`/`--menu=` entries are NOT run through a shell — a bare
  trailing `&` (intended to background the spawned `shani-update`) was
  passed as a literal argv token instead ("Unknown option: &"), confirmed
  live. Every real action now wraps in `sh -c "..."` explicitly (yad's own
  built-in `quit` keyword is the one exception, left bare). Verified live:
  the icon now starts and stays running (`RC=124` = killed by an external
  timeout while still blocking correctly, not crashing) with no parse
  errors.

- **`_launch_deploy`/`_launch_health` now default to a graphical progress
  window, not a bare terminal — a real terminal only appears on explicit
  user request (2026-09-19).** Previously EVERY real `shani-deploy`/
  `shani-health` invocation (update install, rollback, cleanup, optimize,
  channel change, health report) unconditionally opened a terminal emulator
  running `pkexec shani-deploy ...` — functional, but not what "make full
  use of yad" should look like for the common case, and not something a
  non-technical user should have to look at by default. New default path
  (`_run_gui_progress`): the command runs in the background with its
  combined stdout/stderr redirected to a per-run logfile
  (`mktemp .../shani-update-progress.XXXXXX.log`), and `tail -n +1 -f
  --pid=<pid> logfile | yad --text-info --tail --disable-search` streams
  that log live into a scrolling, inline log view (`Show Terminal` /
  `Cancel` / `Close` buttons) — the whole run is visible in the window as
  it happens, not just a single status line. `tail`'s own `--pid=` (GNU
  coreutils) makes it stop following on its own once the real command
  exits, so the window's last line just settles naturally with no polling
  loop on this script's side; yad's text-info keeps the window open after
  that stdin EOF, so the finished result stays readable until a button is
  pressed. The actual exit code always comes from `wait`ing on the command's
  own PID directly — never from yad's or tail's exit status — so every
  existing call site's `if _launch_deploy ...; then / else` contract is
  unchanged.
  **`--disable-search` is LOAD-BEARING, not cosmetic — do not remove it.**
  yad's text-info builds a search bar whose entry icon
  (`edit-find-symbolic`/`edit-clear-symbolic`) resolves to an SVG, and this
  image has NO working SVG rasterizer — no `libpixbufloader-svg.so`, no
  `svg` entry in gdk-pixbuf 2.44.7's `loaders.cache`, and the out-of-process
  glycin loader's sandboxed `bwrap ... glycin-svg` child exits 1 — so GTK
  falls back to `image-missing.svg`, cannot load that either, and asserts
  (`gtkiconhelper.c:495:ensure_surface_for_gicon: assertion failed`) →
  SIGABRT (rc=134). This is exactly what the earlier "--text-info
  unconditionally crashes" finding was, just not yet isolated to a
  caller-controllable flag: confirmed live via the `shani-install-media`
  X11-forwarding + real `--exec=` probe against this exact yad build
  (15.0/GTK+ 3.24.52), the identical invocation returns `rc=134` without
  `--disable-search` and `rc=124` (renders and stays open) with it.
  `_run_gui_progress` now ships `--text-info --tail --disable-search`;
  removing the flag reproduces the SIGABRT.
  A real terminal now only appears two ways, both an explicit ask, never
  the default: (1) `shani-update --terminal` (new CLI flag) forces the old
  terminal-only behavior for that whole invocation, or (2) clicking
  "Show Terminal" inside the progress window opens a real terminal doing a
  live, read-only `tail -f --pid=` of the exact same logfile (the window
  stays the authority on the real exit code either way — the terminal here
  is just an extra viewer, not a replacement control path). `_launch_in_
  terminal` (the old terminal-building code, renamed/kept verbatim) is also
  the automatic fallback when no display or no `yad` is available at all —
  that's an environment fact, not a preference, so it's not gated behind
  the explicit-request logic.
  **Known limitation, not yet independently verified:** this assumes a
  graphical polkit authentication agent is registered for the session
  (standard for GNOME/Plasma/Cosmic — `polkit-gnome-authentication-agent-1`
  or equivalent, normally pulled in by the desktop session package) since
  `pkexec`'s own stdin/stdout are now redirected to the logfile rather than
  a real TTY; on a session with no graphical polkit agent, `pkexec` would
  have nothing to prompt on. The previous terminal-per-invocation design
  had the same requirement in practice (a text-mode polkit fallback prompt
  needs a real, interactive TTY, which a terminal emulator provides and a
  redirected-to-file stdin does not) — this is a pre-existing assumption
  made more explicit by this change, not a new one introduced by it.
  **Cancel's signal delivery is a known simplification:** the `Cancel`
  button sends `SIGTERM` to the `pkexec` PID directly (not to a process
  group), relying on `pkexec`'s own documented behavior of forwarding
  common signals to its child — not independently re-verified here.

  **Full empirical verification pass (2026-09-19), every branch exercised
  against the real, shipped code (not a reimplementation) via the
  `shani-install-media` X11-forwarding test harness:**
  - Happy path (`Close` after natural completion): `rc=0`, matching the
    real command's own exit.
  - `Cancel` clicked mid-run: the underlying process was confirmed actually
    gone (not just the window closed) — but the exit code the caller got
    back was **masked to 0**, not `143`. The earlier "`rc=143`" reading was
    the worker *process* receiving SIGTERM, not the code the caller
    observed: `shani-update.sh`'s EXIT trap re-invoked `_cleanup_and_exit`
    with no argument, so `exit "${1:-0}"` reset every non-zero exit to 0
    (see the "exit-code masking" entry below). FIXED 2026-09-19 — verified
    live: the real `shani-update --health` now returns `rc=1` when its
    worker genuinely fails.
  - `Show Terminal` clicked mid-run: a real `gnome-terminal` window opened
    (needs a D-Bus session bus present — see the next bullet), the
    underlying command kept running in the background, and the final
    `rc=0` matched its natural completion.
  - `yad` missing (real binary temporarily renamed aside, then restored via
    a trap — never left the image in a broken state): confirmed live,
    screenshotted, a real terminal renders the fallback output end-to-end;
    `rc=0`.
  - No `DISPLAY`/`WAYLAND_DISPLAY` at all: correctly attempts the terminal
    fallback, which correctly fails (`rc=1`) since a display is genuinely
    required — no false success reported.
  - `mktemp` failure (`XDG_RUNTIME_DIR` pointed at a nonexistent dir, with
    a real display otherwise available): correctly falls back to a
    terminal, which renders fully; `rc=0`.
  - `--terminal` CLI flag: confirmed it skips `_run_gui_progress` (and any
    `yad` attempt) entirely, going straight to a real terminal.
  - The actual `shani-update --rollback` binary, overlaid onto a live probe
    via `test-env/test.sh probe --local-src=/opt/shani-deploy/scripts`
    (not extracted functions) — the real rollback succeeded, the real
    progress window rendered and streamed live `[INFO]` lines from
    `shani-deploy`'s own output, exit code `0`.
  - **Two real bugs found and fixed only because of this pass:**
    1. `_build_pkexec_env`'s `tr -cd '[:alnum:]:._-/'` placed `-` between
       `_` and `/`, which `tr` parses as a (reversed, invalid) range —
       confirmed reproducing `tr: range-endpoints of '_-/' are in reverse
       collating sequence order` on both the host and inside the test
       image. `tr` errors and produces empty output, so `DISPLAY` silently
       became an empty string in the `pkexec env DISPLAY=... ...` line
       passed to every privileged `shani-deploy` invocation — confirmed
       live in the real rollback run above (`DISPLAY=` empty in the
       logged command line) before the fix, `DISPLAY=:1` correctly
       preserved after it. Fixed by moving `-` to the end of the set
       (`'[:alnum:]:._/-'`), where `tr` always treats it as a literal.
    2. `_launch_terminal_tail` had no way to detect that a terminal it just
       launched failed to actually come up — reported live by a user
       watching the real X11 display during this same testing session
       ("clicked show terminal and it closed"): `gnome-terminal`/`kgx` can
       fail *asynchronously* (their D-Bus-activation client process starts
       fine, then exits ~1s later once activation itself fails, e.g. no
       D-Bus session bus present), and by the time that happens the yad
       progress window had already closed for the button click — leaving
       the user with no visible window at all while the real operation
       kept running unattended in the background. Fixed two ways together:
       `_launch_terminal_tail` now waits 1.5s after launch and checks the
       terminal's own PID is still alive before reporting success; and
       `_run_gui_progress` now loops — a failed terminal launch re-shows
       the graphical progress view instead of leaving the screen blank.
  - **One real, pre-existing bug found but NOT fixed here (out of this
    session's scope — not part of the GUI-progress-window change):** in
    that same real `--rollback` run, `_post_rollback_dialog`'s
    `show_dialog()` call (asking "Restart Now?") failed to open a display
    on *every* `GDK_BACKEND` it tried (`yad backend 'wayland' failed to
    initialize ...: cannot open display: :1`), even though a `yad`
    text-info window from the exact same script invocation, on the exact
    same `DISPLAY=:1`, had rendered correctly just ~71 seconds earlier (the
    real rollback's own duration). `show_dialog()` explicitly forces
    `GDK_BACKEND=wayland`/`x11` per attempt (see its own code, ~L555-560),
    while `_run_gui_progress`'s `yad` call sets no `GDK_BACKEND`
    at all — the working theory is something in the session state changed
    over that ~71s window (candidates: `XDG_SESSION_TYPE` getting set by
    the `systemctl --user`/D-Bus activity visible in the same log, or a
    stale/reused `GDK_BACKEND` value forced too early) that made explicit
    backend-forcing fail where auto-detection still succeeds — not
    root-caused further here. User-visible effect: the post-rollback
    "restart now?" dialog silently never appears in this scenario, falling
    straight to the quieter `notify-send`/log fallback ("User will restart
    later after rollback") instead.

- **`shani-update.sh` silently masked the real exit code of every operation
  it ran — FIXED (2026-09-19).** `_cleanup_and_exit()` ended with a bare
  `exit "${1:-0}"`, and the trap was the single line
  `trap '_cleanup_and_exit' EXIT INT TERM`. On a real `exit 1` — any of the
  ~10 `_cleanup_and_exit 1` sites, or the `err()` path — the EXIT trap
  re-invoked `_cleanup_and_exit` with **no argument**, so `"${1:-0}"`
  reset the code to **0**: every failure was reported to the caller and to
  `systemd` as success. Confirmed live on the real overlaid binary
  (`shani-update --health` with `/usr/local/bin/shani-health` moved aside,
  forcing the post-trap `err()` path): the buggy trap form returned
  `rc=0`, the fixed form returns `rc=1`, identical ERROR output — a
  positive test and a within-run negative control. Fixed by splitting
  cleanup from exit: a new idempotent `_cleanup_lock()` runs on `EXIT`,
  and `INT`/`TERM` map to `_cleanup_and_exit 130`/`143`, so the signal is
  still honoured while cleanup stays single-instance. This is also why the
  GUI-progress "Cancel" test above originally *looked* like it returned
  `143` when it did not.

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
  as default. `shani-update.sh`'s own fallback handling was rewritten to
  match (see the next entry) rather than left as a parallel, now-redundant
  implementation. Packaging: `shani-auto-rollback.sh`/
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

- **`shani-update.sh`'s fallback-boot dialog rewritten — no longer asks
  "should we roll back?" (2026-09-19).** With `shani-auto-rollback`
  handling real recovery unconditionally, an interactive confirm/decline
  dialog was exactly the failure mode that mechanism exists to fix (the
  console path even defaulted to DECLINE on a 60s timeout). Rewrote
  `_handle_fallback_boot()`: if `/data/auto_rollback_done` already exists
  (auto-rollback tried this boot) and markers are still present, tell the
  user it failed and point at `journalctl -t shani-auto-rollback` — no
  retry prompt, an unattended operation that already failed isn't fixed
  by asking the same question a human wasn't there to answer the first
  time. Otherwise (a genuine race — a user logged in faster than
  auto-rollback's first ~1-16 minute trigger), call
  `pkexec systemctl start shani-auto-rollback.service` directly instead
  of reimplementing rollback-direction logic via `_run_rollback` a second
  time in this file. `_run_rollback`/`show_dialog` themselves are
  untouched — still used by `_handle_candidate_boot()` (a genuinely
  different, opt-in "try the new update, keep or roll back?" feature, not
  failure recovery) and the manual `-r`/`--rollback` CLI flag.
  This also surfaced that `_check_fallback_boot()` had the SAME "same-slot
  can't be meaningful" assumption as the two bugs above, a third
  occurrence of the class: it returned "no fallback" whenever
  `BOOTED_SLOT == CURRENT_SLOT`, **regardless of whether a failure marker
  was present** — meaning a same-slot failure recorded by
  `check-boot-failure.sh` (real, reachable, since that script's own fix
  above) would never even reach the rewritten handler above. Fixed to
  only bail out on a same-slot match when there's also no failure marker
  at all. Verified live, both branches: with `auto_rollback_done` present
  and a same-slot `boot_failure` marker, `_check_fallback_boot` now
  correctly returns 0 ("Fallback confirmed") and `_handle_fallback_boot`
  correctly reports the already-failed state; without
  `auto_rollback_done`, it correctly triggers `shani-auto-rollback.service`
  immediately via `systemctl start` and the rollback completes for real
  (confirmed via `current-slot`/`loader.conf` state after). Also
  re-verified the genuine hard-failure path (differing slot) still works
  unchanged through the same rewritten function.
  `tests/test-deploy-state.sh` (9/9) still pass.

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

- **Boot-safety units now record their own failure — NEW (2026-09-23).**
  `mark-boot-in-progress`, `mark-boot-success`, `check-boot-failure` and
  `shani-auto-rollback` have `OnFailure=shani-boot-safety-failed@%n.service`,
  which logs `daemon.crit` (`journalctl -t shani-boot-safety`) and appends
  `<ISO time> <unit>` to `/data/boot_safety_failed` (last 20 lines).
  `shani-health --boot` shows it as "Safety units" (it survives a reboot,
  unlike `systemctl is-failed`), and `shani-reset` wipes it with the other
  markers. Deliberately not on `bless-boot.service` (best-effort, #40405).
  `Wants=`/`After=data.mount`, not `Requires=`, so the journal line is
  written even when `/data` is the problem. Verified live with the harness
  `probe` (real `systemd --boot`, systemd 261.2, `--local-src`, needs
  `SHANIOS_TEST_ALLOW_NEW_LOCAL_SRC=1` since the template is new): forcing
  `check-boot-failure` to `/bin/true` recorded nothing (negative control);
  `/bin/false` produced the crit line and the marker; 25 triggers left
  exactly 20 lines; the health row appears/disappears with the file.
  **Limit:** a unit that never starts because `data.mount` failed ends in
  "dependency failed", not "failed", so `OnFailure=` doesn't fire for that
  case.
- **`shani-health --boot` shows systemd-pstore kernel-crash records — NEW
  (2026-09-23).** "Kernel crash" row when `/var/lib/systemd/pstore` (on
  `/data/varlib/systemd`, shared by both slots) is non-empty. Verified live
  in the same probe, both with and without a record present; `--boot
  --json` stays `jq`-valid.
- **`shani-health --security` has a "Unit Sandboxing" section — NEW
  (2026-09-23).** `systemd-analyze security` exposure score for ShaniOS's
  own service units. Informational only: several units are deliberately
  unsandboxed (see "Systemd hardening" below), so no recommendation is
  raised. Shows "not available" when there is no running systemd (plain
  `enter`).
- **`shani-health --boot` runs `systemd-sysctl --verify` — NEW (2026-09-29),
  and the first version of it was a check that could not fail.**
  The row proves shani-settings' sysctl.d values are APPLIED at boot, not
  merely shipped on disk. It shipped with two defects, both of which made it
  permanently silent, so it had never once reported anything on any machine:
  - It was gated on `command -v systemd-sysctl`. That binary is a systemd
    private helper at `/usr/lib/systemd/systemd-sysctl` and is **not on
    PATH** (confirmed: `command -v` finds nothing, the file exists at both
    `/usr/lib/systemd/` and `/lib/systemd/`). The gate was always false, so
    the row never rendered at all — dead code, not a passing check.
  - It counted findings with `grep -c '^not applied'`. Upstream never emits
    that string: from `src/sysctl/sysctl.c` a failure goes through
    `log_error_errno` on **stderr**, and a healthy run prints **nothing at
    all**. The count was therefore always 0, and the second branch reported
    "no shipped-vs-live mismatches reported" for every real mismatch. This
    is the exact shape of a control that cannot fail, and the host's real
    systemd 255 proves the diagnostic text is neither of those strings
    (`unrecognized option '--verify'`).
  Now: the binary is located by absolute path (`command -v` first, then
  `/usr/lib/systemd/`, then `/lib/systemd/`); **any** non-empty output is a
  finding, with no string matching, so an unrecognised diagnostic can never
  read as healthy; and an unsupported `--verify` is reported as `--  not
  available` rather than as a fault, because otherwise every pre-262 image
  would raise a permanent, meaningless recommendation. Healthy is defined as
  *silent*, so a non-zero exit with no output is not a fault either.

  **`tests/test-sysctl-verify.sh` (17 cases) is the contract test.** It
  extracts the block from the shipped script and runs it verbatim; only the
  two hardcoded binary paths are repointed at fixtures, because the real path
  cannot be shadowed without root (`unshare` is denied in this environment —
  confirmed, not assumed). The real paths are pinned separately by static
  assertions so the repointing cannot hide a path regression. Extraction is
  anchored on the block's own comments and both anchors are asserted to match
  exactly once: anchoring on `^    fi$` instead extracts only the
  binary-discovery conditional (there are two bare 4-space `fi` lines in the
  region and the first closes that one), which silently tests a block
  containing no rows at all.

  **Verified with a negative control, not a positive test alone.** The same
  14-case suite was run against a copy of the script with the pre-fix block
  restored: 11 of 14 fail, including both defects above, and every
  behavioural case reproduces the original symptom (no row emitted, because
  the `command -v` gate is false with `PATH` stripped — which is the real
  condition). Post-fix: 14/0.

  **The "unavailable" branch is now verified against the real binary, not just
  fixtures (2026-09-30).** Everything above was previously reasoned about the
  real binary; only the fixture-shaped halves were exercised. A real booted
  `@blue` slot (systemd 261.2) now settles the two things that actually decide
  what a user sees today:

  - The helper **is** present at the absolute path —
    `/usr/lib/systemd/systemd-sysctl`, 23496 bytes, with `/lib/systemd/` a
    copy. The bare name is not on `PATH` (that is what the `command -v` gate
    discovers, and why it must not be the only lookup), but the absolute-path
    branch is the one that fires in the image. Verified by running the real
    binary, not by reading the fallback chain.
  - `systemd-sysctl --verify` on that real binary exits **rc=1 with 47 bytes:
    `systemd-sysctl: unrecognized option '--verify'`.** That exact string
    matches the shipped `unrecognized option|unknown option|invalid option`
    alternation, so real 261.x images take the "not available" branch.
    Rendered live: `Sysctl verify — not available (needs systemd 262; this is
    older)`, and `shani-health --boot --json` reports **zero** sysctl
    recommendations. That is the failure this design exists to prevent —
    without the branch, every real image in the field would raise a permanent,
    meaningless "run systemd-sysctl --verify" recommendation for a flag it
    cannot support. It does not.

  **What is still unverified, and it is now a much narrower claim:** the
  262-only *runtime* behaviour — "healthy prints nothing" and "real mismatch is
  reported". Note the version claim is no longer pinned from below only: the
  v262 source confirms 262 accepts `--verify` (`src/sysctl/sysctl.c` declares
  `OPTION_LONG("verify", …)` setting `arg_verify` and calls
  `sysctl_write_verify()`; v261's copy of that file contains **zero**
  occurrences of "verify"). That is source-level confirmation, not an executed
  262 binary, so "needs 262" stands, but the 262 paths below still need a real
  one. The host is systemd 255 and installed images are 261.2, so neither the
  host nor the harness can close this.

  **`--strict` is LOAD-BEARING, and bare `--verify` was a false green (fixed
  2026-09-30).** `--verify` reads each value back and returns a negative errno
  on mismatch or refusal, but the caller swallows one whole failure class.
  `sysctl_write_or_warn()` is literally
  `if (ignore_failure || (!arg_strict && ERRNO_IS_NEG_FS_WRITE_REFUSED(r))) log_debug_errno(…)`
  followed by `return 0`, and `ERRNO_IS_NEG_FS_WRITE_REFUSED(r)` is
  `r == -EROFS || ERRNO_IS_NEG_PRIVILEGE(r)` (`src/basic/errno-util.h:191`) —
  so EROFS/EACCES/EPERM are logged at **debug** level and the tool **succeeds**.
  Since this row defines healthy as *silent*, bare `--verify` would render
  "OK all shipped sysctl.d values are live" on exactly the read-only or
  hardened sysctls the row exists to police, including
  `90-security-hardening.conf`. Upstream says the same in v262 NEWS: "Call it
  with `--strict` and targeted configuration when exact verification is
  desired." A *mismatch* is `-EINVAL`, which is not write-refused, so it is
  reported either way — it is the refusal class that only `--strict` unmasks.
  The invocation is now `--verify --strict`.

  **Proved inert on 261.2, live, before editing** (it must be: the flag is
  useless on an image that rejects `--verify` anyway). A real booted `@blue`
  slot: both `--verify --strict` and `--strict --verify` return rc=1 with
  `systemd-sysctl: unrecognized option '--verify'` — getopt fails on the first
  unknown option, so ordering is irrelevant — and both are still classified by
  the shipped regex as "unavailable". No permanent recommendation on any
  pre-262 image, which is the failure this design exists to prevent.

  **The suite is 17 cases now (was 14), and the new guard is not vacuous.** All
  six behavioural fixtures require `$2 == --strict`, not just `$1 == --verify`.
  A new static assertion greps **comment-stripped** code for `--verify --strict`
  — the block's own comments deliberately name the flag, so a raw grep matches
  that documentation and goes green even with the flag dropped from the command
  (same trap as the runtime-only suite's assertions). New case 9 emulates
  upstream's swallow path directly: the same simulated EROFS fault is **silent
  without** `--strict` and **reported with** it, so the test proves the flag
  changes the row's verdict rather than merely matching an argv. Negative
  control: reverting the invocation to bare `--verify` gives **9 passed, 8
  failed**, exit 1 (captured without a pipe masking it), and reproduces the
  false-green verbatim —
  `ROW|Sysctl verify|OK|all shipped sysctl.d values are live` on a fixture that
  is failing.

  **Read NEWS and the source, not man7, for anything recent.** The man7
  `systemd-sysctl` page is a `262~devel` snapshot obtained 2026-08-04, which
  **predates the merge**: it documents no `--verify` whatsoever, and describes
  `--strict` only as the 252 "return non-zero on failure" flag. Reasoning from
  it — as this session initially did — concludes `--strict` is an unrelated
  exit-code option and that the shipped code ignoring the exit code makes the
  flag pointless. That conclusion is wrong on both counts. The behaviour lives
  in `arg_strict` inside systemd's C, and the man page does not describe it.

  **Accepted trade-off, stated rather than hidden:** `--strict` also makes
  failures in sysctl.d files shani-settings does not ship visible, since a bare
  invocation processes all of `/etc`, `/run` and `/usr/lib` sysctl.d. That can
  produce a noisy recommendation; a false green on security hardening is the
  worse outcome, so noise is the safe direction. Upstream's "targeted
  configuration" (explicit config paths or `--prefix=`) would narrow the scope,
  and is deliberately **not** done: it would hardcode shani-settings' file list
  into shani-deploy, a cross-repo coupling that will drift. Revisit only with a
  262 image in hand.
- **`shani-health` reports runtime-only enabled units — NEW (2026-09-30), and
  the obvious implementation of it is a check that cannot fail.** A unit enabled
  with `--runtime` (or by a package that did so) runs now and is gone after the
  next reboot — and on this OS every reboot is *also* a blue-green slot switch,
  so a runtime-only enable is precisely how a service silently disappears one
  update later with nothing in the journal to explain it. **No other row in
  this script can catch it**, which is why it needed its own: `systemctl
  list-units --state=failed` cannot see an absent unit, and an absent unit has
  no `systemd-analyze security` exposure score to report. It is emitted as
  `Runtime-only units` in the Units section, `--` (informational, not a fault),
  with a `_rec` naming the fix (`systemctl enable <unit>`, drop `--runtime`).

  **Read from `systemctl list-unit-files --no-legend --plain` (state filtered by
  awk), NOT `systemd-analyze unit-files`.** The latter's documented output is
  a `UNIT FILE / STATE / PRESET` table, but that is not what it emits when piped
  on systemd 255: measured on this host, 941 lines and **zero** `UNIT FILE`
  headers, every row in the form `ids: NAME → PATH`. There is no state column,
  so a column scrape matches nothing and reports a permanent, confident "all
  clear" — indistinguishable from healthy. The negative control in
  `tests/test-runtime-only-units.sh` reproduces exactly that: swapping the
  command in yields rows reading `gone after reboot: ids:`, i.e. the literal
  `ids:` prefix parsed as a unit name. Note the division of labour, measured in
  a `test enter` session: `list-unit-files` needs no bus (rc=0, 768 lines), but
  the `enabled-runtime` *state* lives in `/run/systemd/system`, which does not
  exist there — so the command works offline and still has nothing to report.
  `--state=enabled-runtime` collapses both into a single rc=1, which is why the
  state is filtered by awk instead.

  **The fsck/remount generators are excluded and that exclusion is
  load-bearing.** `systemd-fsck-root.service` and `systemd-remount-fs.service`
  are `enabled-runtime` **by design** (they are generator-produced), so
  reporting them would fire on every machine and train the user to ignore the
  row. The suite's case 2 is exactly that fixture and must stay silent; its case
  4 is the control, re-running the same fixture through the pipeline with the
  exclusion removed (15/17, 2 failures) so the guard is proven to be able to
  fail rather than merely passing.

  **`tests/test-runtime-only-units.sh` (17 cases) is the contract test.** It
  extracts the block from the shipped script and runs it verbatim with only
  `systemctl` stubbed, so the parsing pipeline, the exclusion and the
  `_row`/`_rec` wiring under test are the real ones. Covers: a genuine
  third-party enable reported, by-design generators alone staying silent, a
  mixed fixture counted correctly (2, not 4), a failing `systemctl` neither
  crashing the run nor emitting a row (the script is `set -Eeuo pipefail`).
  A third mutant control reinstates `--state=enabled-runtime` and must fail
  (15/17, 2 failures) — it is the regression guard for the whole reason the
  awk filter exists.

  **The static assertions grep comment-stripped code, and that is not
  cosmetic.** The block's own comments deliberately *name* the forbidden
  `systemd-analyze unit-files`, so grepping the raw block matches the
  documentation and the guard would happily pass on a regression reintroducing
  the very call it forbids. Note the stripping must drop only comment-*only*
  lines (`s/^[[:space:]]*#.*$//`): a looser `[[:space:]]*#` also eats the `#`
  inside `${#_runtime_only[@]}`, truncating the line the count assertion reads.

  **Verified:** the full mandatory harness green with the row in place
  (`clean → ca → bootstrap -p gnome → upgrade --local-src → rollback
  --local-src → clean`, 6/6 RC=0), all 12 unit suites green (278 assertions —
  the twelfth is `test_upgrade_adviser.sh`, whose underscore name means a
  `tests/test-*.sh` glob silently skips it, so "11 suites" here was a glob
  artifact rather than a count anyone verified), `bash -n` and
  shellcheck `-S error` clean, and `shani-health` + `shani-health --json` both
  rc=0 with valid JSON when run for real in a `test enter` slot.

  **Verified live, in a real boot.** A `probe` (real PID 1 — `bus=yes`,
  `/run/systemd/system` present) with two planted third-party units, differing
  only in how they were enabled:

  | unit | `list-unit-files` state | named by the row? |
  |---|---|---|
  | `zz-runtime-probe.service` | `enabled-runtime` | **yes** |
  | `zz-persist-probe.service` | `enabled`         | no — correctly excluded |

  The persistent unit is the real negative control: same service, same
  `[Install]`, so the row is proven to discriminate on *state*, not on name or
  on "is there any unit file at all". Before that control, an unplanted probe
  boot had the row report a genuine `console-getty.service` on its own.

  **The JSON contract is verified too, because a field nothing renders is a
  field nobody has.** Same probe, `shani-health --json` (rc=0, `jq -e` valid,
  23872 bytes) with the runtime unit planted. The verbatim check object:

  ```json
  {"section":"units","key":"Runtime-only units","status":"info",
   "message":"2 enabled for this boot only, gone after reboot: console-getty.service zz-json-probe.service"}
  ```

  All three fields Cassini's generic renderer reads are present and correctly
  named, and the message names the offending unit. Worth recording because the
  obvious way to query for this row is wrong: the label `Runtime-only units` is
  in **`key`**, not in `message` (the message is the unit list), so a
  `select(.message|test("Runtime-only"))` silently matches nothing and reads as
  "the row is missing". Select on `.key`, or test `.message` for the unit name.

  **The row is silent in a `test enter` slot, and that is correct — not a
  defect.** A non-boot `enter` session has no `/run/systemd/system` at all, so
  `list-unit-files` returns no `enabled-runtime` rows to report. Confirmed by
  isolation in that same session: plain `list-unit-files` returns 768 lines,
  while `--state=enabled-runtime` returns rc=1 with no output. That is exactly
  why the state is filtered with awk rather than `--state=` — with `--state=`
  the row would be silently empty in the sessions where a slot is inspected.
  Do not "simplify" the awk back into `--state=`.

  **The 6/6 harness run above was done with the awk filter in place, not with
  the earlier `--state=` form.** When this was changed, the comment in the
  block, this paragraph, and the suite's case count were all wrong at the same
  time; the harness was then re-run in full (`clean → ca → bootstrap -p gnome →
  upgrade --local-src → rollback --local-src → clean`, 6/6 RC=0) specifically so
  this claim covers the code that actually ships. `rollback` took the
  same-slot-direction path (booted `@green` newer → default switched back to
  `@blue`, `@green` left untouched), which is the branch most at risk from a
  stray behaviour change anywhere in the deploy path.
- **`oomctl` adoption was investigated and deliberately NOT implemented — the
  harness cannot execute the code path at all, so a row would ship
  permanently silent.** This is the "a check that cannot fail" class again, one
  level worse than the `systemd-sysctl` case above, and it is recorded so the
  next person does not write a parser against an output format nobody has seen.

  What is real, measured in a real `probe` boot (real PID 1, `bus=yes`) on
  2026-09-30: `oomctl` **is** present (`/usr/sbin/oomctl`), and
  `systemd-oomd` **is** enabled (`systemctl is-enabled` → `enabled`; it is
  enabled by `shani-pkgbuilds/shani-settings/shani-settings.install:39`). But
  `systemd-oomd` never actually runs, so `oomctl dump` can never produce
  output. Both halves, verbatim:

  ```
  systemctl start systemd-oomd   → unit failed
  oomctl dump                    → rc=1, 0 bytes,
      "Failed to dump context: Could not activate remote peer
       'org.freedesktop.oom1': unit failed"
  ```

  The cause is in the unit's own journal, not an inference:
  `Userspace Out-Of-Memory (OOM) Killer skipped, unmet condition check
  ConditionControlGroupController=memory`. A container does not expose the
  memory cgroup controller, so the unit skips itself. This holds for `enter`
  **and** for a real `--boot` `probe` — a boot is still a container, so the
  memory controller is still absent. There is therefore **no environment in
  this harness where an `oomctl` code path executes even once**, and the real
  `oomctl dump` output format (including its kill-report shape) could not be
  captured at all. Writing a parser now would mean inventing a format from
  memory and proving it only against self-authored fixtures — a fixture that
  passes against a format the tool never emits is the exact trap already
  recorded for `tests/test-tpm2-status-json.sh`'s LUKS1 fixture.

  So the existing `oomd` row (`OK running` / `! enabled but not running` /
  `! not enabled`) is left exactly as it is, and the genuine gap it has — it
  never says *what oomd killed*, only that it is running — stays open and
  recorded rather than half-solved. **If this is picked up, the first step is
  not code: it is getting one real `oomctl dump` transcript from a machine
  with a working memory cgroup controller, then parsing that.** Note also that
  the row's `OK running` is itself untrustworthy inside the harness, since
  oomd never starts there — a harness run will not show that branch.

- **CI: `unit-files` job — NEW (2026-09-23).** `tests/verify-units.sh` runs
  `systemd-analyze verify` over every unit here inside `archlinux:latest`
  (real Arch systemd). It stubs only what ShaniOS provides at runtime (its
  `/usr/local/bin` scripts, `data.mount`) and treats ANY output as failure,
  because unknown keys only warn. It refuses to run outside a container (it
  writes into `/usr/lib/systemd`). Verified: the current tree gives rc=0;
  a typo'd key and a missing `ExecStart=` binary each give rc=1. It does
  NOT catch a bad argument to a valid binary (the old `bootctl set-good`
  class) or a typo in an `OnFailure=` target.

- **`shani-user-setup.path` went to `failed` (`trigger-limit-hit`) seconds
  after every boot — FIXED (2026-09-23, harness verification: see below).**
  Seen in two real `systemd --boot` runs of `@blue` via the harness `probe`
  command: `shani-user-setup.path: Trigger limit hit, refusing further
  activation` → `Failed with result 'trigger-limit-hit'`. Cause:
  `PathExists=/data/overlay/etc/upper/passwd` is true on every installed
  system, and systemd re-checks `PathExists=` each time the triggered
  service exits (systemd.path(5)), so it re-fired until `TriggerLimitBurst=3`
  tripped. The unit's old comment ("PathExists fires once when the file is
  first created") was wrong about that. Effect: once failed, later user
  additions (`PathChanged=`) and skel changes were no longer watched until
  the next boot. Fix: drop that one `PathExists=` line and keep
  `PathChanged=` on the same file. First boot and slot switches don't need
  it: `/data/user-setup-needed` is already written by
  `os-installer-config/scripts/configure.sh:1100` (install) and
  `scripts/shani-deploy.sh:3632` (every slot switch), and is consumed by the
  service's `ExecStartPost=`, so its `PathExists=` never loops.

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
- **Systemd hardening — extended to seccomp/namespace level, per-unit, and the
  omissions are load-bearing (2026-09-30).** The earlier pass stopped at
  `NoNewPrivileges`/`PrivateTmp`/`ProtectSystem`. 10 units now also get
  `SystemCallArchitectures=native`, `SystemCallFilter=~@mount @raw-io @debug
  @reboot`, `RestrictNamespaces=yes`, `LockPersonality=yes`,
  `MemoryDenyWriteExecute=yes`, `RestrictSUIDSGID=yes`,
  `RestrictRealtime=yes`, `RemoveIPC=yes`, `KeyringMode=private`,
  `ProtectControlGroups=yes`, `ProtectKernelTunables/Modules/Logs=yes`,
  `ProtectHome=yes`, `ProtectProc=invisible`, `UMask=`, and
  `LogRateLimitIntervalSec=`/`LogRateLimitBurst=`/`LogLevelMax=`.

  **Read the `ExecStart` before adding a directive — four of these break the
  boot-safety chain if applied blanket, and all four were caught by reading the
  scripts first, not by `systemd-analyze verify` (which only proves the
  directive is *recognised*):**
  - **`ProcSubset=pid` must NOT be used anywhere.** `boot-success-cleanup.sh`
    and `check-boot-failure.sh` both derive the booted slot from
    **`/proc/cmdline`**; `pid` subsets hide it, so slot detection silently
    returns empty. `ProtectProc=invisible` is used instead (it only hides other
    users' processes).
  - **`PrivateDevices=yes` must NOT be used on any unit that calls `logger`.**
    It exposes only null/zero/full/random/urandom/tty, so **`/dev/log` is
    gone** and `shani-boot-safety-failed@.service` (the unit that records boot
    *safety* failures) cannot report anything.
  - **`@raw-io` is safe to exclude even though `check-boot-failure.sh` runs
    `btrfs subvolume get-default`.** That needs `ioctl`, and `ioctl` is in
    **`@default`** ("system calls that are always permitted",
    `src/shared/seccomp-util.c` v261), not `@raw-io` — `@raw-io` is
    `ioperm`/`iopl`/`pciconfig_*`, raw *port* I/O.
  - **`bless-boot` gets neither `ProtectKernelTunables` nor `ProtectSystem`.**
    It writes EFI variables through `/sys/firmware/efi/efivars` and renames
    loader entries under `/boot/efi`, so making `/sys` or `/boot` read-only
    stops it doing the one thing it exists to do.
  - `MemoryDenyWriteExecute`/`LockPersonality` are **omitted from the
    flatpak units** (C++ + dbus) and `shani-download-only` (curl/aria2/rclone).
  - `shani-user-setup` keeps **no** `ProtectSystem` (it writes `/etc/passwd`,
    `/etc/group`); `flatpak-update-user` keeps **no** `ProtectHome` (it needs
    `~/.local`).
  - `RestrictAddressFamilies=AF_UNIX` only — `logger` and `systemctl` need
    AF_UNIX, and the download/user-setup units add `AF_INET AF_INET6`.
    `@network-io` covers local AF_UNIX, so it is *not* excluded.

  **`shani-auto-rollback.service` is still deliberately unhardened** (it does
  losetup/mount/chroot/btrfs; `SystemCallFilter=~@mount`, `ProtectProc`,
  `ReadWritePaths=` and `PrivateDevices` would all break it). Same for
  `shani-update.service`, whose real deploy path re-execs via `pkexec`
  (setuid) — `NoNewPrivileges`/mount-namespacing would silently break that
  escalation.

  **What is verified and what is not.** Verified: all 17 units load under real
  Arch systemd **261.3** with no unknown-key warnings (`tests/verify-units.sh`,
  rc=0); the full mandatory harness `clean → ca → bootstrap → upgrade →
  rollback → clean` is green; `verify-boot` PASSED, and `/data/boot-ok` being
  present with `boot_in_progress` removed proves the hardened
  `mark-boot-success.service` actually **ran and succeeded** in a real boot; no
  hardened unit appears in `systemctl list-units --state=failed`; and the
  captured boot console has **zero** seccomp/`EPERM` denials. The 13-14 failed
  units in a harness boot are pre-existing and environmental (auditd,
  qemu-guest-agent, `/var/log` unmount), not these units.

  **Not verified:** `check-boot-failure.service`'s *service* body never fires in
  a 90 s `verify-boot` window (its timer is `OnBootSec=15min`), so its
  `btrfs`-under-`SystemCallFilter` path rests on the `@default`/`ioctl` source
  fact above, not on an observed run. An attempt to prove it with
  `systemd-run` under the same property set was **invalid** — a non-boot
  `enter` session has no systemd PID 1, so every invocation failed with
  "Host is down" regardless of the sandbox. Do not trust a `systemd-run`
  result from a non-boot session.
- **CI status — corrected, was stale.** `.github/workflows/ci.yml` has
  three jobs: `lint` (shellcheck via the shared `shani-ci-commons`
  template), `unit-tests` (`test-deploy-state.sh` 9/9 +
  `test-status-json.sh` 20/0 + `test_upgrade_adviser.sh` 21/21), and
  `security` (secret scan via the
  shared template). Migrated from the old hand-written single-job
  workflow 2026-09-20; a fourth job, `unit-files` (`systemd-analyze
  verify` in `archlinux:latest`, see above), added 2026-09-23. The full
  boot/signing/deploy/rollback harness in
  `../shani-testbed/` (via `../shani-install-media/run_in_container.sh`)
  is still manual — that's the
  safety-critical proof, and CI is the floor, not the ceiling.
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
- `get_booted_subvol()` is present in the three shipped commands
  `scripts/shani-deploy.sh`, `scripts/gen-efi.sh`, and
  `scripts/shani-health.sh`. A fourth copy historically lived in the
  retired `scripts/shani-update.sh` wrapper and is removed by the current
  source migration. The three shipped copies remain intentionally
  independent (see "Audit-verified known issues" above for why a
  shared-library merge is not a clean fix here); keep their parsing
  behavior aligned.
- `../shani-testbed` exercises this repo's real packaged binaries through
  `../shani-install-media/run_in_container.sh`. If you change a function's
  behavior in a way that changes what a *correct* test result looks like,
  update the corresponding test in that sibling repo too, or a stale
  expectation there will pass for the wrong reason. The testbed's
  `update-check` shim is read-only status compatibility, not a user
  updater.

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
