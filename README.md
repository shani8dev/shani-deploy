# shani-deploy

Blue-green deployment, health/diagnostics, and system-recovery tooling for
ShaniOS — an immutable, Btrfs-backed Arch Linux derivative that updates by
writing a full new OS copy to an inactive root subvolume while the running
system stays untouched, then switching to it on the next boot.

This repo is standalone read-mostly-plus-deploy tooling: `shani-deploy`
writes the new state, `shani-health` inspects and reports on it,
`shani-reset` and the boot-failure/rollback machinery recover from it going
wrong.

## The blue-green model, in short

ShaniOS keeps two root subvolumes, `@blue` and `@green`. Exactly one is
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
The core deployment engine. Typical flow: self-update check, fetch the
update manifest, verify GPG signature, snapshot the candidate slot as a
timestamped backup, `btrfs receive` the new image into it, generate/sign
the UKI via `gen-efi` inside a chroot, update boot entries, write the
`/run/shanios/reboot-needed` marker.

Key flags:
- `-r`, `--rollback` — restore the non-booted slot from its most recent
  backup snapshot. Run from the slot you want to **keep**.
- `-c`, `--cleanup` — remove old backup snapshots and cached downloads.
- `-o`, `--optimize` — manual maintenance dedup pass (bees itself runs
  continuously in the background; this is not required for normal operation).
- `-t`, `--channel <chan>` — `latest` or `stable`.
- `--download-only` — fetch and verify the image, don't deploy it yet.
- `-d`, `--dry-run` — simulate without making changes.
- `--set-channel` — persist a channel choice to `/etc/shani-channel`.

**Auto-reboot is opt-in (`AUTO_REBOOT=yes`, default `no`).** The candidate
slot is fully deployed and bootable the moment the script finishes —
nothing about correctness depends on rebooting promptly — so by default
`shani-deploy` leaves the reboot to the user's own convenience. Set
`AUTO_REBOOT=yes` (and optionally `AUTO_REBOOT_DELAY=<seconds>`, default 60)
to arm a one-shot `shanios-auto-reboot` systemd timer instead; cancel a
pending one with `systemctl stop shanios-auto-reboot.timer`.

Every subvolume deletion in this script (backup cleanup, candidate/
temp_update cleanup during deploy, and both the emergency-rollback and
explicit `--rollback` paths) goes through `btrfs_subvolume_delete_safe()`,
which pauses the `beesd@<uuid>` service around the delete and resumes it
afterward. bees continuously deduplicates identical extents across every
subvolume and has no way to know which one "matters more" — deleting a
subvolume that bees has deduped against, while bees is concurrently running
its own `LOGICAL_INO`/dedupe ioctls on the same shared extents, can trigger
a documented, still-unfixed kernel hang/extent-accounting race. Pausing
bees for the duration of the delete avoids it regardless of which
subvolume bees happened to pick as the canonical copy.

`flock`-based locking on `/run/shanios-deploy.lock` means overlapping
invocations (a timer firing while an admin runs it manually, or two timers
racing) fail fast with "Another shani-deploy is already running" instead of
racing each other.

### `scripts/shani-health.sh`
System health, security, and diagnostics — read-mostly, no deployment side
effects (except `--clean-logs` and `--clear-boot-failure`, which are
explicit and narrowly scoped). Run with no arguments for a full report, or
scope it down:

`--security` · `--boot` · `--network` · `--hardware` · `--packages` ·
`--verify` (deep integrity check: UKI signatures, Btrfs scrub, immutability
— slower, use `--json` for machine-readable output) · `--journal [level]` ·
`-s`/`--storage-info` · `--history [N]` · `--clean-logs [days]` ·
`--clear-boot-failure` · `--export-logs [dir]`.

Covers, among much else: boot slots and boot entries, the `/etc` OverlayFS
and immutable-root guarantees (including that the `/usr/abin`
pacman/useradd/adduser safety wrappers are actually installed, actually
take PATH precedence, and actually block a write operation — not just that
the files exist), the `[shani]` pacman repo's signing-key trust and
`SigLevel`, Secure Boot/UKI signatures, LUKS encryption, TPM2, users and
groups, hardware, storage, package managers, containers, virtualization,
and firmware.

### `scripts/shani-update.sh`
The user-facing update wrapper — the thing the desktop timer/notification
actually calls. Resolves the update channel (CLI flag > persisted file >
default), validates version/channel input against untrusted external
sources (remote manifests, downloaded metadata) before trusting it, and
launches `shani-deploy` (in a detected terminal emulator when run
interactively, or unattended via the timer) with sanitized environment.

### `scripts/gen-efi.sh`
Builds and signs the Unified Kernel Image for a given slot: MOK key
handling, `sign_efi_binary()`'s tmp+backup+verify+atomic-replace pattern
(never leaves a partially-signed or corrupted EFI binary on failure),
crypttab/cmdline generation, and slot-target validation (refuses to
generate a UKI for a slot other than the one actually booted/being
configured).

### `scripts/beesd-setup.sh`
One-time-per-filesystem setup for `bees` (continuous Btrfs deduplication):
resolves the filesystem UUID, writes `/etc/bees/<uuid>.conf` sized off the
filesystem's capacity, and enables `beesd@<uuid>.service`. Re-run is
idempotent (checks a version marker in the config before doing anything).

### `scripts/shani-user-setup.sh`
Syncs extra groups (from `/etc/shani-extra-groups`, the single source of
truth shared with the `useradd`/`adduser` wrappers in shani-install-media),
default shell, and one-time per-user bootstrap (Flatpak remote, Nix
channel, subuid/subgid ranges, Podman storage migration) for every regular
user (UID 1000–59999). Triggered by `shani-user-setup.path` watching the
OverlayFS upper-layer `/etc/passwd` and a deploy-written marker — not a
polling timer.

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
