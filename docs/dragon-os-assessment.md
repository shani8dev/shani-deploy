# Dragon OS vs ShaniOS — assessment and take/reject list

**Written 2026-10-31.** This is an ecosystem-wide assessment: a comparison
against the Dragon OS architecture specification, an audit of every Shani
repo, and the resulting list of ideas worth taking.

**It is kept here, in `shani-deploy/docs/`, because the two highest-priority
actions in it are shani-deploy changes** (pre-deploy data snapshots and the
ENOSPC preflight). The rest is recorded so the work is not re-derived.

---

## Verification status (2026-10-31)

Every factual claim below was re-checked against the working trees before this
file was committed — not accepted from the earlier analysis. Evidence came
from grepping `shani-backup`, `shani-deploy`, `shani-settings`,
`shani-pkgbuilds`, `os-installer-config`, `shani-install-media`,
`shani-cassini`, `shani-docs` and `shani-wiki`; reading
`bits/part.sfdisk`, `gen-efi.sh`, `shani-health.sh`, `home.py` and the
`btrfsmaintenance` drop-in; and checking the shipped package contents.

### Corrections found by that verification

1. **"The deploy path never calls the home snapshot" is no longer true.**
   It did when the analysis was written. As of commit `109d81b`
   (`shani-deploy` pkgrel 108) `deploy_update()` calls
   `shani-snapshot-home`, which asks `shani-backup home predeploy --keep 2`
   *before* it mounts the disk. The gap that remains is narrower: **`/home`
   only — `@data` and `@root` are still not snapshotted by the deploy path.**

2. **The predicted new retention class was implemented, not left as a note.**
   `shani-backup` (commit `0daa24d`, pkgrel 9) added a `predeploy` snapshot
   kind with `PREDEPLOY_KEEP = 2`, separate from `daily`, precisely because
   `daily` is idempotent per day and would answer "already exists" to an
   afternoon update. Real-btrfs verification lives in
   `shani-testbed/slot-tests/home-snapshots.sh`.

3. **vkBasalt is present.** It is not a pacman package, which is why a
   package-list grep says "absent", but the Vulkan layer ships as a Flatpak in
   the `gamescope`, `plasma` and `shared` profiles
   (`runtime/org.freedesktop.Platform.VulkanLayer.vkBasalt/x86_64/25.08`).
   The "gaming gaps" row below is corrected accordingly.

4. **Flatpak maintenance is real and lives in `shani-deploy`, not
   `shani-settings`.** `flatpak-update-system.{service,timer}` and the user
   equivalents run `flatpak update` followed by
   `flatpak uninstall --unused --delete-data`. There is no runtime
   `flatpak repair`; a build-time `flatpak repair --system` exists in
   `shani-install-media/scripts/build-flatpak-image.sh`.

5. **Cassini's page count.** It has **73 tab modules** under
   `src/shani_cassini/tabs/`, not 68 "pages" — a count of files, not of
   user-visible pages.

Everything else in the tables was confirmed as stated: the 1 GiB ESP, the six
LSMs, x86_64-only, GPG+SHA256+zsync2, the absence of pcrlock-with-`systemd-measure`,
rescue UKI, ballast, squota, sysext, homed, verity/EROFS, reflink/chunk deltas,
`--profile`, `MODULE_SIG_FORCE`, xpadneo/xone/scx/swtpm/edk2-ovmf/virtiofsd, and
the weekly btrfs defrag/balance/scrub/trim.

---

## The correction that prompted this file: `@home` snapshots already exist

The original claim was "no `/home` snapshots, no quota." The first half was
wrong.

| What exists | Evidence |
|---|---|
| Daily read-only snapshot of every home, 14-day retention | `shani-backup/src/shani_backup/home.py`, `data/shani-backup-home.timer` |
| Enabled on install, not opt-in | `shani-pkgbuilds/shani-backup/shani-backup.install` → `systemctl enable shani-backup-home.timer` |
| Ships on gnome/plasma/niri/cosmic | `image_profiles/*/Packages-Desktop` |
| Whole-`/home` snapshot for plain-folder homes, per-user subvolume snapshots otherwise | `home.py` `snapshot_whole()` / `snapshot_person()` |
| Per-user ACLs, root-owned snapshot dirs, read-only | `home.py` `_person_dir()`, `btrfs.create_snapshot_detailed(..., readonly=True)` |
| Retention reduced to 2 when free space < 15% | `home.py` `FREE_LIMIT = 0.15`, `LOW_SPACE_KEEP = 2` |
| Off-disk restic backups | `src/shani_backup/restic.py`, `data/shani-backup-restic.timer` |
| Pre-deploy snapshot, newest 2 kept | `home.py` `predeploy()` / `PREDEPLOY_KEEP`, `shani-deploy/scripts/shani-snapshot-home.sh` |
| GUI + shell integration | `shani-cassini/.../tabs/backup.py`, `shani-shell/.../Backup.qml`, Chronoa `skills/snapshot_status.py`, `senses/snapshots.py` |

**What is genuinely missing is narrower:**

- ~~the deploy path never calls it~~ — **fixed 2026-10-31** for `/home`;
  `@data` (config/service state) and `@root` are still not covered by a
  pre-deploy snapshot.
- **No quota cap.** Retention is a free-space heuristic, not `btrfs quota` /
  `squota` enforcement.
- The daily snapshot is idempotent per day, so calling it at deploy time would
  not refresh a morning snapshot — **this is why a separate `predeploy` kind
  was added**, rather than reusing `daily`.

---

## Repo audit

| Repo | Role | What it means for the Dragon comparison |
|---|---|---|
| `os-installer-config` | Installer: GPT, LUKS, fstab, entries, cmdline | 1 GiB ESP (`bits/part.sfdisk`), optional LUKS, six LSMs (`lsm=landlock,lockdown,yama,integrity,apparmor,bpf`), `ro` root; no rescue, no verity |
| `shani-install-media` | Image/ISO builder, profiles, signing, upload | x86_64 only; GPG `.asc` + `.sha256`; zsync2 (`zsyncmake2`); profiles are the "edition" mechanism; flatpak/snap images are bundled send-streams |
| `shani-deploy` | Deploy, rollback, health, reset | The strongest area; no pcrlock *phase*, pre-deploy `/home` snapshot now wired, fixed 10 GiB preflight; flatpak update units live here |
| `shani-pkgbuilds` | Custom packages and meta-packages | Pulls in waydroid/nix/flatpak/podman/distrobox/gamescope/mangohud (mostly as `shani-core`/desktop deps); missing xpadneo/xone/scx/vkBasalt-as-package/swtpm/edk2/virtiofsd (vkBasalt is present as a Flatpak layer) |
| `shani-settings` | `/etc` + `/usr` defaults | Polkit tiers (`99-shani.rules`), btrfsmaintenance (weekly defrag/balance/scrub/trim, all enabled), zram, systemd-oomd (via `systemd-oomd-defaults`), sysctl |
| `shani-backup` | Home snapshots + restic | Already solves the `@home` half; now wired into deploy for `/home` |
| `shani-cassini` | GTK management UI, 73 tab modules | Updates, boot recovery, TPM, firewall, backup pages; actuator paths via pkexec + CLI |
| `shani-shell` | niri/Quickshell AI desktop | Backup service, settings, control centre |
| `shani-chronoa` | AI assistant, large skill/tool surface, MCP | Senses/skills for boots, updates, snapshots, disk (`skills/snapshot_status.py`, `senses/snapshots.py`); no deploy/rollback actuator by design |
| `shani-testbed` | VM + real UEFI harness | The evidence layer; power-cut scenarios already measured |
| `shani-builder` | Build container + package publisher | No SBOM/provenance; not reproducible in the mkosi sense |
| `shani-ci-commons` | Reusable CI | Gate templates |
| `shani-keyring` | Pacman trust root | Supply-chain trust for `[shani]` |
| `shani-repo` | Published pacman repo | Delivery |
| `shani-docs` | Authored docs | Positioning and architecture claims |
| `shani-wiki` | Wiki | Prose stale since 2026-04-15 (its own README says so); later commits are markup, CSS, CI and agent notes |
| `shani-blog`, `shani-website` | Content/marketing | Not technical |
| `shani-fleet`, `shani-insights`, `shani-platform` | Commercial fleet/analytics/server planes | Not OS |
| `niri-remote`, `aiyantra-extra`, `garuda-clones` | Non-ShaniOS tools/reference | No bearing |

---

## Delta against Dragon, verified

| Dragon item | ShaniOS status | Verdict |
|---|---|---|
| pcrlock + signed PCR 11 + credential in initramfs | Enroll/health support exists (`gen-efi.sh` `_tpm2_pcrlock_policy_path()`; `shani-health.sh` pcrlock rows); no `systemd-measure`, no `.pcrsig`, no pcrlock phase in the initramfs (the script says so explicitly) | Take |
| Rescue UKI in ESP | Absent; `gen-efi.sh` only says "no ESP key recovery" | Take |
| Home snapshots + quota | Snapshots present; `/home` now pre-deploy-triggered; no quota | Integrate, don't build |
| ENOSPC ballast, squota, 1.5× preflight | No ballast, no squota config, fixed 10 GiB gate; health checks qgroup consistency only | Take ballast + 1.5×; squota optional |
| systemd-sysext | Absent | Take |
| systemd-homed | Absent (health mentions only) | Defer — identity change, not additive |
| dm-verity / EROFS | Absent | Reject — rearchitecture |
| Reflink slot seeding / chunk deltas | Absent; zsync2 download only | Reject — depends on EROFS image |
| Profile/edition swap | Manifest carries profile; deploy warns on mismatch but has no `--profile` | Take — small |
| `lockdown=confidentiality` | Absent; `shani-health` already recommends it (line ~1870) | Take — one token |
| `MODULE_SIG_FORCE` | Absent | Reject — custom kernel |
| Gaming/input gaps | gamescope, mangohud, game-devices-udev present; **vkBasalt present as a Flatpak Vulkan layer**; xpadneo/xone/scx absent | Take the missing pacman packages; vkBasalt needs no work |
| Virtualisation gaps | libvirt + qemu-base present; swtpm/edk2-ovmf/virtiofsd absent | Take packages |
| Waydroid | waydroid + waydroid-helper present; no `binder_linux` module found anywhere | Fix/verify |
| Flatpak maintenance | `flatpak update` + `flatpak uninstall --unused --delete-data` (system and user units in `shani-deploy`); no runtime `flatpak repair` | Take one line |
| Browser RAM cache | No `profile-sync-daemon` | Take |
| ddcutil | Installed via `shani-tools-extra` (in `Packages-Extras`); no `i2c-dev` / PowerDevil integration | Small take |
| Weekly btrfs defrag | Present (`BTRFS_DEFRAG_PERIOD="weekly"`), which breaks reflinks/dedup and adds wear; balance/scrub/trim also weekly | Review — ShaniOS-specific, not from Dragon |
| 7 GB ESP / whole-disk / single DE / boot counting / `chattr +i` / assistant rewrite | — | Reject |

---

## Revised take list — additive only, no rearchitecture

### Immediate (small, testable, independent)

1. **Wire `shani-backup` into deploy.** Call a pre-deploy snapshot for
   `/home` **and `@data`** with its own retention class (not the idempotent
   daily), so an update always has a same-minute undo.
   **`/home` is done (2026-10-31, `109d81b` + `0daa24d`, pkgrels 108/9).
   `@data` is still open.**
2. **pcrlock phase.** `systemd-measure` → `.pcrsig` in the UKI; forward
   loader/credentials/`pcrlock.cred` into the initramfs via
   `module-setup.sh`; keep the literal PCR pin as fallback. Health already
   knows how to report it.
3. **ENOSPC ballast + proportional preflight.** Preallocate a reserve,
   truncate at boot below a threshold, and replace the fixed 10 GiB gate with
   `max(10 GiB, 1.5 × payload)` using the existing `Free (estimated)` read
   (`shani-deploy.sh:754`).
4. **`systemd-sysext`.** Enable `systemd-sysext.service` and
   `/var/lib/extensions`; no `/usr` change.
5. **`lockdown=confidentiality`** in the UKI cmdline, behind a testbed run
   for hibernation/kexec/NVIDIA.

### Next (additive, needs a build or a test)

6. **Rescue UKI in the 1 GiB ESP** — measured, not 450 MB by assumption; keep
   it compatible with existing 1 GiB installs.
7. **Package gaps** — xpadneo, xone, scx-scheds, swtpm, edk2-ovmf, virtiofsd;
   verify/fix `binder_linux` for Waydroid. (vkBasalt is already delivered as
   a Flatpak layer.)
8. **Profile swap into the standby slot** — `shani-deploy --profile <name>`;
   the artifact and slot mechanism already exist.
9. **`flatpak repair` + `profile-sync-daemon`** — one line for repair (the
   update/uninstall units already exist), one package/config for psd.
10. **Review btrfsmaintenance:** weekly defrag is actively harmful to reflinks
    and dedup; weekly balance is more aggressive than needed. Reduce both,
    keep weekly scrub/trim.

### Later, still additive

11. **Offline update bundle** (image + signature + manifest) and **SBOM
    emission** from the existing build.
12. **`systemd-homed`** only if accounts should survive factory reset; it needs
    `/var/lib/systemd/home` persisted, which is a design decision, not a quick
    change.

**Dropped from the earlier list:** dm-verity/EROFS, reflink/chunk deltas,
mkosi, custom kernel/module signing, aarch64, the privileged D-Bus daemon
(Cassini already has actuator paths and a polkit policy), and the assistant
rewrite (Cassini + Chronoa already cover it).

---

## Bottom line

Dragon's genuinely additive ideas are five: **pcrlock, rescue UKI, ENOSPC
ballast/1.5×, sysext, and pre-deploy data snapshots** — and the last one is
mostly wiring `shani-backup` into `shani-deploy`. The rest is either already
shipped, a rearchitecture that has been ruled out, or a downgrade.

The suggested start is items **1 (`@data` half) and 3**: both are small, both
are testable in `shani-testbed`, and neither touches the boot flip.
