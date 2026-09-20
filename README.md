# shani-deploy

Blue-green deployment, health/diagnostics, and system-recovery tooling for
Shanios — an immutable, Btrfs-backed Arch Linux derivative that updates by
writing a full new OS copy to an inactive root subvolume while the running
system stays untouched, then switching to it on the next boot.

This repo is standalone read-mostly-plus-deploy tooling: `shani-deploy`
writes the new state, `shani-health` inspects and reports on it,
`shani-reset` and the boot-failure/rollback machinery recover from it going
wrong.

## The blue-green model, in short

Shanios keeps two root subvolumes, `@blue` and `@green`. Exactly one is
booted (active); the other is the candidate. An update extracts a fresh
image into the candidate slot, builds and signs a new Unified Kernel Image
(UKI) for it, and updates the systemd-boot entries so the candidate becomes
the next-boot default — all while the active slot keeps running completely
untouched. Rebooting is a slot switch, not an in-place package install:
there is no "installing updates, do not power off" phase, because the
install already finished before you ever reboot.

If the new slot fails to boot, systemd-boot's own boot-counting (`+3-0`
tries) falls back to the previous slot automatically, and the
`check-boot-failure` machinery records what happened so `shani-update` can
offer to roll back.

## Scripts

### `scripts/shani-deploy.sh`

Core deployment engine. Typical flow: self-update check, fetch manifest, verify GPG signature, `btrfs receive` into candidate slot, generate/sign UKI, update boot entries, write reboot-needed marker.

Key flags:
- `-r`, `--rollback` — restore the non-booted slot from its most recent backup snapshot
- `-c`, `--cleanup` — remove old backup snapshots and cached downloads
- `-o`, `--optimize` — manual maintenance dedup pass
- `-t`, `--channel <chan>` — `latest` or `stable`
- `--download-only` — fetch and verify the image, don't deploy it yet
- `-d`, `--dry-run` — simulate without making changes
- `--set-channel` — persist a channel choice to `/etc/shani-channel`

Auto-reboot is opt-in (`AUTO_REBOOT=yes`, default `no`). The candidate slot is fully deployed and bootable the moment the script finishes — nothing about correctness depends on rebooting promptly.

`flock`-based locking on `/run/shanios-deploy.lock` means overlapping invocations fail fast instead of racing.

### `scripts/boot-success-cleanup.sh`

Clears a stale boot-failure marker after a successful boot. Triggered by the `mark-boot-success.service` one-shot unit.

### `scripts/shani-health.sh`

System health, security, and diagnostics — read-mostly, no deployment side effects. Run with no arguments for a full report, or scope it down with `--security`, `--boot`, `--network`, `--verify`, etc.

### `scripts/shani-update.sh`

User-facing update wrapper. Resolves the update channel, validates input, and launches `shani-deploy` with sanitized environment.

### `scripts/gen-efi.sh`

Builds and signs the Unified Kernel Image for a given slot. `sign_efi_binary()` uses temp-file-then-atomic-replace — never leaves a partially-signed or corrupted EFI binary on failure.

### `scripts/beesd-setup.sh`

One-time setup for `bees` (continuous Btrfs deduplication). Re-run is idempotent.

### `scripts/shani-user-setup.sh`

Syncs extra groups, default shell, and one-time per-user bootstrap for every regular user (UID 1000–59999). Triggered by `shani-user-setup.path` watching the OverlayFS upper-layer `/etc/passwd` and a deploy-written marker — not a polling timer.

### `scripts/check-boot-failure.sh`
Runs from `check-boot-failure.timer` (15 minutes after boot). If
`boot_in_progress` is still present and `boot-ok` was never written, the
boot didn't complete cleanly even though it didn't hard-fail at the
initramfs level — records which slot failed so `shani-update` can offer a
rollback on next run.

### `scripts/shani-reset.sh`
Factory reset: wipes `/data` (all `/etc`/`/var` overlay changes, service
state, boot markers) and reboots; `systemd-tmpfiles` recreates the
structure fresh on next boot. Does **not** touch `/home`, `/root`,
`@blue`/`@green`, or the ESP/UKI — a reset restores first-boot state on the
currently-installed OS, it doesn't touch the OS copies themselves or your
files. `--home` additionally wipes `/home` (separately confirmed).

### `scripts/shani-auto-rollback.sh`

System-level, unattended boot-failure recovery. Runs from
`shani-auto-rollback.service`/`.timer` (triggered at `OnBootSec=1min` for
dracut-recorded hard failures and again at `OnBootSec=16min`, one minute
after `check-boot-failure.timer`'s 15-minute check, for same-slot soft
failures). No session, display, or TTY required — works on the `server`
profile and when the failure itself prevented the desktop from starting.
Acts only on a recorded failure marker (`/data/boot_failure`), never
guesses. Idempotent via `/data/auto_rollback_done` (cleared each boot by
`mark-boot-in-progress.service`). Calls `shani-deploy --rollback` directly.

### `scripts/shani-upgrade-adviser.sh`

Pre-upgrade safety check. Advises whether a system upgrade is safe before
`shani-update` proceeds (Btrfs snapshot state, free space, running
services, pending transactions). Supports `--json` for machine-readable
output.

## systemd units

**Boot lifecycle:** `mark-boot-in-progress.service` → (boot completes) →
`mark-boot-success.service` writes the success marker. If it's never
reached, `check-boot-failure.timer`/`.service` (15 min post-boot) catches
it. `bless-boot.service` handles systemd-boot's own boot-counting
integration.

**Updates:** `shani-update.timer`/`.service` (user-level) — the periodic
unattended check-for-updates path. `shani-download-only.timer`/`.service`
(system-level) — an opt-in pre-fetch-only timer, separate from actually
deploying. `flatpak-update-system.timer`/`.service` and the user-level
`flatpak-update-user.timer`/`.service` — Flatpak updates, independent of
the OS slot update cycle.

**User provisioning:** `shani-user-setup.path`/`.service` — see above.

**Maintenance:** `beesd-setup.service` — runs `beesd-setup.sh` once to
configure continuous dedup.

**Boot failure recovery:** `shani-auto-rollback.service`/`.timer` —
system-level, unattended rollback on a recorded boot failure (see
`shani-auto-rollback.sh` above). `shani-update-tray.service` — persistent
system-tray icon (`shani-update --tray`), started at
`WantedBy=graphical-session.target`.

## Recovery paths

- **Boot failure** (new slot won't boot at all): systemd-boot's own
  tries-counter falls back to the previous slot automatically; no manual
  action needed to get back to a working system. `check-boot-failure`
  records it so a rollback can be offered.
- **Boot "succeeds" but something's wrong** (`--rollback`): restores the
  non-booted slot from its most recent backup snapshot, regenerates its
  UKI, and updates boot entries — run from the slot you want to **keep**.
- **Everything's a mess** (`shani-reset`): wipes persistent `/etc`/`/var`
  state and boot markers back to first-boot defaults, without touching
  either OS copy or your files.

## Testing changes

The scripts here expect the Shanios Btrfs layout (`@blue`/`@green` slots,
UKI boot entries), so testing on a random machine isn't meaningful. Two
supported paths:

1. **Loop-mounted test environment** — [`shani-install-media/test-env`](https://github.com/shani8dev/shani-install-media/tree/main/test-env)
   installs a real image onto loop-mounted disks, then runs
install/boot/update/rollback cycles against it. This is how
   `shani-deploy` is verified end to end — **there is no CI in this
   repo, verification is entirely manual**, so every change is exercised
   through this harness by hand:

   ```bash
   cd ../shani-install-media
   ./run_in_container.sh build.sh test bootstrap -p plasma   # install + first boot
   ./run_in_container.sh build.sh test cycle -p plasma       # update → rollback → verify
   ```

   2. **Static checks** — always run before committing:

    ```bash
    bash -n scripts/*.sh        # syntax check every script
    shellcheck scripts/*.sh     # lint (warnings are triaged, errors must be fixed)

    # Unit tests — fast, no container needed
    bash tests/test-deploy-state.sh      # expect: ✓ N passed, 0 failed
    bash tests/test_upgrade_adviser.sh   # expect: 21 passed, 0 failed
    ```

When changing user-visible flags or output, regenerate any affected docs —
`docs/updates/system.md` in [shani-docs](https://github.com/shani8dev/shani-docs)
and the blog reference posts mirror this README's flag tables.

## Contributing

- Every new CLI flag needs: implementation, a line in `usage()`, an entry in
  this README's flag list, and a mention in the matching docs page.
- Destructive operations (subvolume deletion, slot wipes) must go through
  `btrfs_subvolume_delete_safe()` — see the bees note above for why.
- Keep POSIX-portable patterns where practical; these scripts also run in
  minimal chroot contexts during image build.
- PRs should include the output of the static checks above and, for
  deploy-path changes, a `test cycle` run summary.

## Known gaps & design rules

**Safety-critical invariants (don't reintroduce):**
- Boot-entry writes must go temp-file-then-atomic-`mv`, never a direct
  `cat > file` — a crash between deleting the old entry and writing the
  new one can leave a slot with zero valid boot entries.
- Signing must verify the signed output *before* it replaces the live
  file, never after.
- Any host/network-facing code that runs before a signature check (like
  self-update) must fail closed on any verification failure — keep running
  the current, already-trusted copy rather than falling through to
  execution.
- `_restore_state()`'s variable-whitelist check
  (`[[ " $_whitelist " =~ " $_var " ]]`) is itself a regex match that
  overwrites `$BASH_REMATCH` — if you read `${BASH_REMATCH[…]}` for the
  variable's *value* after that check runs, capture it *before*.

**Open, not yet independently verified:**
- `finalize_boot_entries()`'s `+3-0` tries-counted candidate entry likely
  provides no real automatic hard-failure fallback on systemd 261
  (systemd/systemd#40405). Needs a dedicated real QEMU+OVMF hard-failure
  test to close out. Until then, treat "automated rollback on boot
  failure" as unverified for the hard-failure case specifically — the
  marker/timer path is real and verified, but it only ever *records* a
  failure; it does not itself switch the default boot entry.

**Cross-repo impact:**
- `shani-fleet`'s `check_selfupdate()` independently re-implements this
  repo's "download → checksum → GPG-verify → fail closed" trust chain for
  agent self-update. If you fix a bug in this repo's `self_update()` or
  signing logic, check `shani-fleet/agent/bin/shani-fleet-agent` for the
  same class of bug — it's a separate implementation of the same pattern,
  not shared code.
- `get_booted_subvol()` is reimplemented separately in 4 copies:
  `scripts/shani-deploy.sh`, `scripts/shani-update.sh`,
  `scripts/gen-efi.sh`, and `scripts/shani-health.sh` — kept as 4 copies
  deliberately (no shared-lib mechanism exists). If you fix a bug in the
  shared parsing logic, find every copy and fix them all.

**Trust model:** See `SECURITY.md` for the intended trust model
(fingerprint-pinned GPG, atomic boot-entry writes, fail-closed
self-update) — if a change would make either untrue, that's the
regression, regardless of whether tests still pass.
