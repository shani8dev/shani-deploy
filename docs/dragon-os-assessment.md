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

6. **`@data` pre-deploy snapshot implemented and then reverted** (2026-10-31).
   Architectural check: `@data` snapshots would live inside `@data`, which
   `shani-reset --hard` wipes, and rollback does not restore `@data`, so there
   is no durable home and no automatic restore path. Home snapshots survive
   reset because they live under `@home`. The etc-factory overlay already
   handles default upgrades for `@data`. Only the `/home` half ships.

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
| dm-verity / EROFS | Absent. Research: dm-verity is a block-level target over a *read-only* image (EROFS/ext4/squashfs) — it cannot cover a mutable, in-place-updated btrfs root, so adopting it means rearchitecting `/usr` into a sealed image (mkosi, no pacman at runtime). `fs-verity` (file-level, btrfs since kernel 6.2) is available and could harden individual read-only files, but is not whole-filesystem. ShaniOS instead gets integrity from btrfs checksums + scrub and authenticity from GPG-signed updates + UKI signing at deploy time | Reject (rearchitecture); fs-verity noted as optional per-file hardening |
| Reflink slot seeding / chunk deltas | Absent; zsync2 download only | Reject — depends on EROFS image |
| Profile/edition swap | `--profile NAME` now implemented (2026-10-31): overrides the download profile and rewrites `/etc/shani-profile` only after a successful deploy; needs a testbed run before calling done | Implemented, unverified |
| `lockdown=confidentiality` | Present in UKI cmdline (2026-10-31, configure.sh + gen-efi.sh); testbed `verify-boot` PASSED | Done |
| `MODULE_SIG_FORCE` | Absent | Reject — custom kernel |
| Gaming/input gaps | gamescope, mangohud, game-devices-udev present; **vkBasalt present as a Flatpak Vulkan layer**; scx-scheds + scx-tools now in `shani-core` (2026-10-31); xpadneo/xone are AUR-only and need their own PKGBUILDs | Partially done |
| Virtualisation gaps | libvirt + qemu-base present; swtpm/edk2-ovmf/virtiofsd now in `shani-core` (2026-10-31) | Done |
| Waydroid | waydroid + waydroid-helper present; no `binder_linux` module found anywhere | Fix/verify |
| Flatpak maintenance | `flatpak update` + `flatpak uninstall --unused --delete-data` (system and user units in `shani-deploy`); `flatpak repair` now runs as a best-effort `ExecStartPre` on both units (2026-10-31), plus a generous `TimeoutStartSec` | Done |
| Browser RAM cache | No `profile-sync-daemon` | Take |
| ddcutil | Installed via `shani-tools-extra` (in `Packages-Extras`); no `i2c-dev` / PowerDevil integration | Small take |
| Weekly btrfs defrag | Present (`BTRFS_DEFRAG_PERIOD="weekly"`), which breaks reflinks/dedup and adds wear; balance/scrub/trim also weekly | Review — ShaniOS-specific, not from Dragon |
| 7 GB ESP / whole-disk / single DE / boot counting / `chattr +i` / assistant rewrite | — | Reject |

---

## Revised take list — additive only, no rearchitecture

### Immediate (small, testable, independent)

1. **Wire `shani-backup` into deploy (home half).** `/home` done (`109d81b` +
   `0daa24d`, pkgrels 108/9) via shani-backup, non-fatal and opt-out.
   **`@data` not shipped** after an architectural check: @data snapshots would
   live inside @data, which `shani-reset --hard` wipes, and rollback does not
   restore @data, so there is no durable home and no automatic restore path.
   Home snapshots survive reset because they live under @home. The etc-factory
   overlay already handles default upgrades for @data.
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
7. **Package gaps** — scx-scheds/scx-tools, swtpm, edk2-ovmf, virtiofsd now
   shipped in `shani-core` (2026-10-31). xpadneo and xone are AUR-only and
   need their own PKGBUILDs (ChimeraOS packages them; DKMS). `binder_linux`
   for Waydroid still unverified. (vkBasalt is already delivered as a Flatpak
   layer.)
8. **Profile swap into the standby slot** — implemented (2026-10-31) as
   `shani-deploy --profile <name>`: overrides the download profile and rewrites
   `/etc/shani-profile` only after a successful deploy. Needs a testbed run.
9. **`flatpak repair`** — done (best-effort `ExecStartPre` on both update
   units, 2026-10-31). `profile-sync-daemon` still open.
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

---

## Appendix: full spec (ARCH-DRAGON-005) claim-by-claim verification

Every claim below was checked against the working trees on 2026-10-31 (grep,
file reads, and `pacman`/Arch-package lookups), not accepted from the spec.
Rows marked **Match** mean ShaniOS already does it; **Take** = worth adding;
**Reject** = rearchitecture or downgrade; **Defer** = design decision needed.

### §1 Topology & guarantees

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| Whole-disk ownership, 100% of the drive | `os-installer-config` supports a pre-partitioned device (`OSI_DEVICE_IS_PARTITION`) and multiple profiles; dual-boot/pre-partitioned installs are a feature | Reject |
| Two-partition GPT, write-once geometry | `bits/part.sfdisk` is exactly 2 partitions (1 GiB ESP + root); `install.sh` runs `sfdisk` once | Match |
| Hermetic `/usr` (EROFS + dm-verity) | `/usr` lives in a Btrfs subvolume `@blue`/`@green`, not EROFS; `gen-efi.sh` re-signs the kernel's prebuilt UKI; no verity anywhere | Reject (rearchitecture) |
| Infinite slot elasticity (shared pool) | `@blue`/`@green` share one Btrfs pool; `deploy_update()` snapshots into the candidate slot | Match |
| Double dedup (reflink CoW + beesd) | No reflink slot seeding; `beesd-setup.sh`/`shani-deploy` dedup exists; `btrfsmaintenance` runs balance/scrub | Partial (no reflink seeding) |
| ENOSPC immunity (squota, 2 GB ballast, 1.5× preflight) | No ballast, no squota; fixed 10 GiB gate (`DEFAULT_deploy_min_free_space_mb`); health checks qgroup consistency only | Take ballast + 1.5×; squota optional |
| 4-stage rollback watchdog | dracut pre-mount hook rewrites `loader.conf`; `shani-auto-rollback.service` (1 min + 16 min); `+3-0` tries counter is inert on this systemd (documented) | Partial (marker path verified; `+3-0` path unverified) |
| Unbrickable offline+delta updates | zsync2 differential download from R2/SF; offline bundle not shipped | Take (offline bundle) |

### §2 Base & desktop

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| Arch rolling via mkosi, pacman stripped at runtime | ShaniOS ships pacman and is Arch-based; `shani-core` pulls `base` etc. | Reject (rearchitecture) |
| aarch64 (Archports) | x86_64 only (`build.sh` writes `x86_64/`) | Reject (already) |
| Single DE: minimal KDE Plasma 6 | gnome/plasma/niri/cosmic/gamescope/kiosk/server profiles | Reject (single-DE downgrade) |
| ddcutil + i2c-dev in PowerDevil | `ddcutil` via `shani-tools-extra` (in `Packages-Extras`); no `i2c-dev`/PowerDevil integration | Take (small) |

### §3 Storage & space guard

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| 7 GB FAT32 ESP | `bits/part.sfdisk`: `size=1G` | Reject (measured; 1 GiB) |
| ESP automount, 60 s idle timeout | `gen-efi.sh`/mount uses `LABEL=shani_boot`; no automount timeout logic found | Take (optional) |
| LUKS2 aes-xts-plain64, 512-bit, Argon2id | `configure.sh` generates `rd.luks.uuid=... rd.luks.name=...` LUKS2 entries; cipher/KDF not pinned in code (LUKS defaults) | Match (default) |
| `@slots`/`@data`/`@home`/`@root`/`@snapshots`/`@nix`/`@swap` | ShaniOS: `@blue`/`@green`/`@data`/`@home` (and `@root`?); no `@nix`/`@swap`/`@snapshots` named; home snapshots are subvolume snapshots, not `@snapshots` | Partial |
| `@data/.emergency_ballast` (2 GB, truncates <512 MB) | None | Take |
| squota, 25 % ceiling on `@snapshots` | No squota config; health checks qgroup consistency only | Take (optional) |
| beesd dedup | `beesd-setup.sh` + `shani-deploy` dedup path exists | Match |
| Volatile `/var` (systemd.volatile=state) + selective bind mounts | `cmdline` includes `systemd.volatile=state`; bind mounts for flatpak/containers/waydroid/libvirt/NM/bluetooth/tailscale/fprint/colord/journal not verified in code | Partial |
| profile-sync-daemon (browser RAM sync) | No `profile-sync-daemon` anywhere | Take |
| btrfs-balance monthly, scrub monthly, trim weekly, cleanup daily | `BTRFS_*_PERIOD="weekly"` for defrag/balance/scrub/trim in shared overlay | Review (weekly is aggressive) |
| 4-layer ENOSPC immunity | Initramfs sweeper not found; squota no; ballast no; preflight fixed 10 GiB | Take (ballast + 1.5×) |

### §4 Boot chain, TPM, LSM

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| pcrlock + signed PCR 11 (`.pcrsig`) | `gen-efi.sh` detects pcrlock policy and passes `--tpm2-pcrlock=`; no `systemd-measure`/`.pcrsig` anywhere; no pcrlock phase in initramfs (script says so) | Take (pcrlock phase) |
| 6 LSMs in confidentiality mode | UKI cmdline enforces `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` and now also `lockdown=confidentiality` (gen-efi.sh:638); `shani-health.sh` still advises it when Secure Boot is active and the running kernel reports `none` | Done (2026-10-31) |
| MODULE_SIG_FORCE=y | Absent | Reject (custom kernel) |
| 4-stage boot watchdog table | mark-boot-in-progress/success + check-boot-failure + auto-rollback; `systemd-bless-boot`/try-counter renaming inert on this systemd (documented) | Partial (marker path real) |
| dm-verity on `/usr` | Absent | Reject (rearchitecture) |

### §5 State reconciliation & reset

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| systemd-sysusers / tmpfiles self-heal | Standard Arch/systemd; `shani-user-setup` re-seeds skel; factory reset wipes `@data` | Match-ish |
| etc-factory OverlayFS (`/etc` over `/usr/share/factory/etc`) | `/etc` is an overlay over `@data` (upper) + lower; `configure.sh` sets it up | Match |
| systemd-homed (accounts survive reset) | Absent; health mentions only | Defer |
| Factory reset keeps `@home` | `shani-reset` wipes `/data` (and thus `/etc` upper) but keeps `@home` | Match |

### §6 Sandboxes & package delivery

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| Flatpak (active), AppImage (active), Snap (dormant socket), Nix (optional), sysext (active) | Flatpak active (system+user update units); snapd present via `shani-core`; Nix via `shani-core`; AppImage not explicitly; sysext absent | Partial (sysext take; snapd already there) |
| systemd-sysext + `/var/lib/extensions` | Absent | Take |

### §7 Dev/virt/container plumbing

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| Podman/Buildah/Skopeo/Distrobox/Toolbx | All in `shani-core` | Match |
| Waydroid (binderfs + lxc + dnsmasq) | `waydroid` + `waydroid-helper` in `shani-core`; no `binder_linux` module found anywhere | Fix/verify |
| KVM/QEMU: swtpm, edk2-ovmf, virtiofsd | Now in `shani-core` (2026-10-31) | Done |
| udev rules (adb/fastboot/MCU) | `android-udev` in `shani-peripherals`; MCU rules not verified | Partial |
| Core CLI suite (zsh, git, etc.) | Standard Arch packages | Match |

### §8 Gaming/input

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| ntsync (`/dev/ntsync`) | Mainline kernel ships it; no explicit enable needed | Match (via kernel) |
| sched-ext (scx_lavd, scx_bpfland) | `scx-scheds` + `scx-tools` now in `shani-core` (2026-10-31) | Done |
| gamescope, mangohud, vkBasalt in `/usr` | gamescope + mangohud via `shani-desktop-gamescope`; vkBasalt only as a Flatpak Vulkan layer | Partial (vkBasalt not a pacman pkg) |
| xpadneo, xone | AUR-only; not in official repos | Need own PKGBUILDs |
| game-devices-udev | Present (`shani-peripherals`) | Match |
| GameMode (Feral) | Present in `shani-settings` | Match |
| PipeWire realtime, NFS/SMB/WireGuard/Tailscale, Noto fonts | `shani-multimedia`/`shani-network`/`shani-fonts` | Match |

### §9 Update engine

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| 4-phase atomic update (inhibit, space guard 1.5×, reflink seed, desync chunks, verity verify, atomic rename, pcrlock refresh) | ShaniOS: download → SHA256+GPG verify → extract to temp → atomic `subvolume snapshot` publish → UKI gen/sign → boot entry write; no reflink/chunk deltas; no dm-verity; pcrlock refresh not done | Reject deltas/verity; take 1.5× preflight; pcrlock refresh with pcrlock phase |
| Edition swapping (Full vs Lite) | Profile is baked at install; `shani-deploy --profile NAME` overrides the download profile and rewrites `/etc/shani-profile` only after a successful deploy (2026-10-31) | Implemented, unverified |
| Pre-deploy snapshot of `@home` + `@data` | `/home` done (2026-10-31, shani-backup). `@data` **not shipped**: @data snapshots would live inside @data, which `shani-reset --hard` wipes, and rollback does not restore @data — so there is no durable home and no automatic restore path. Kept as manual recovery only if ever needed; not a default | Partial (home only) |

### §10 Maintenance suite

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| beesd (continuous dedup) | `beesd-setup.sh` + dedup in `shani-deploy` | Match |
| btrfs-scrub (monthly) | weekly (shared overlay) | Review cadence |
| btrfs-balance (monthly, <20 % usage) | weekly | Review cadence |
| btrfs-trim (weekly) | weekly | Match |
| btrfs-cleanup (daily, squota) | `shani-backup` prunes snapshots on low space; no daily timer by that name | Partial |
| flatpak-maint (12 h, update + prune + repair) | `flatpak-update-{system,user}.timer` (12 h); repair now added (2026-10-31) | Match |
| systemd-oomd (cgroup PSI) | `systemd-oomd-defaults` + enabled in `shani-settings.install` | Match |

### §11 Assistant & build pipeline

| Dragon claim | ShaniOS reality | Verdict |
|---|---|---|
| Privileged daemon `dragon-managerd` (Rust, D-Bus, polkit) + Flutter/Qt6 GUI | Cassini (GTK, 73 tabs) + Chronoa (AI assistant); actuator paths via pkexec + CLI; polkit policy in `shani-settings` | Reject rewrite (already covered) |
| mkosi reproducible build, 7 GB ESP recovery UKI (~450 MB) | `shani-install-media/build.sh` (archiso-based, not mkosi); 1 GiB ESP; no rescue UKI | Reject mkosi; take rescue UKI (measure size) |
| SBOM / provenance | Not found in `shani-builder` | Take (later) |

### Net assessment

Dragon's genuinely additive ideas remain five: **pcrlock phase, rescue UKI,
ENOSPC ballast + 1.5× preflight, systemd-sysext, and the `@data` pre-deploy
snapshot** (the `/home` half is already shipped). Everything else in the spec
is either already present in ShaniOS, a rearchitecture that has been ruled
out (dm-verity/EROFS, reflink/chunk deltas, mkosi, custom kernel signing,
aarch64, whole-disk ownership, single DE, no-pacman runtime), or a
downgrade (7 GB ESP, assistant rewrite).

---

## Appendix B: ShaniOS internal architecture consistency audit (2026-10-31)

Checked: subvolume layout vs. bind mounts, volatile `/var` vs. persisted state,
security posture, scheduling claims, profile coverage, and reset durability.
Findings are ordered by severity.

### B.1 Real inconsistencies (shipped code contradicts the claim or breaks on reboot)

| # | Finding | Evidence | Impact | Fix |
|---|---|---|---|---|
| 1 | **scx schedulers installed but dormant.** | `grep scx shani-settings/` → empty | Gaming boosters inert | **Fixed 2026-10-31:** `scx_loader.service` enabled (guarded) with `--auto` drop-in and `/etc/scx_loader.toml` (default `scx_lavd`); `ntsync.conf` modules-load.d added. Needs testbed verification (replaces CFS) |
| 2 | **LSM `lockdown` in "none" mode while health recommends confidentiality.** | `configure.sh:911` cmdline; health row | Security claim overstated | **Fixed + verified 2026-10-31:** `lockdown=confidentiality` added to the UKI cmdline (configure.sh + gen-efi.sh); testbed `verify-boot` PASSED. Remaining caveat: NVIDIA/kexec/hibernation on real hardware |
| 3 | **Weekly btrfs defrag fights dedup.** `BTRFS_DEFRAG_PERIOD="weekly"` in shared/server overlays; defrag breaks reflinks/dedup and adds wear, while beesd dedups. Contradictory goals. | overlay `btrfsmaintenance` | Wear + dedup loss | Defrag → monthly or `none`; keep scrub (monthly) + trim (weekly) |
| 4 | **`shani-settings` manifest in volatile `/var`.** `install_nut_baseline()` writes `/var/lib/shani-settings/nut-baseline.sha256`; `/var/lib/shani-settings` is **not** in the `varlib_dirs` bind list, so `/var` is tmpfs at runtime → manifest lost on reboot. | `configure.sh` varlib_dirs (no `shani*`); install hook | Baseline re-evaluated every boot | **Fixed 2026-10-31:** manifest path moved to `/data/varlib/shani-settings/nut-baseline.sha256` (persistent, no bind mount needed) |
| 5 | **gamescope profile lacks home snapshots.** `shani-backup` is in gnome/plasma/niri/cosmic `Packages-Desktop` but not gamescope. A gaming profile has no automated `/home` snapshots. | profile Packages-Desktop grep | Inconsistent coverage | Add `shani-backup` to gamescope Packages-Desktop |
| 6 | **shim MOK password is the well-known literal `shanios`** on every install. Documented, but any attacker who knows it can enroll their own MOK at first boot if they win the race. | `configure.sh:1105` | Documented risk | Acceptable (documented); consider randomizing per-install if higher assurance wanted |
| 7 | **plasmalogin greeter branding lost on reboot.** `provision_plasmalogin()` writes theme/kdeglobals/kvantum to `/var/lib/plasmalogin/.config/kdedefaults`, but `/var/lib/plasmalogin` was not in `varlib_dirs`, so `/var` tmpfs wipes it → stock Breeze greeter at runtime. | `shani-desktop-plasma.install` provision_plasmalogin; varlib_dirs | Visible regression | **Fixed 2026-10-31:** branding now shipped under `/usr/share/shani/plasmalogin/` and re-applied at boot by `shani-plasmalogin-branding.service`; `plasmalogin` added to `varlib_dirs` (install.sh + configure.sh) for persistence |

### B.2 Architectural gaps / unfulfilled claims (not bugs, but "claimed and not delivered")

| # | Claim | Reality | Action |
|---|---|---|---|
| 7 | "Encrypted hibernation" via `@swap` | `@swap` + nodatacow exists and `resume=` is wired in `configure.sh`/`gen-efi.sh` | OK, verified wired |
| 8 | `+3-0` tries counter as automatic fallback | Inert on this systemd (documented); dracut hook is the real recovery | Documented; no code change (advertised design is misleading though) |
| 9 | Waydroid (binderfs) | `rust_binder` is built into the Arch `linux` package (modules.builtin); no DKMS or modprobe needed. Added `binder.conf` modules-load.d anyway (harmless). Claim holds. | Verified (no action) |
| 10 | `@data` pre-deploy snapshot | Reverted (no durable home / no auto-restore). Documented. | Keep reverted |
| 11 | `fs-verity` per-file hardening | Available (kernel 6.2+), not used | Optional, low priority |
| 12 | Virtual devices (v4l2loopback, vhba) | Not shipped. Added `v4l2loopback-dkms` + `v4l2loopback-utils` + `vhba-module-dkms` to `shani-video`, plus `linux-headers` to `shani-core` (DKMS prerequisite). | Fixed 2026-10-31 |

### B.3 Things that are consistent and correct (no action)

- Subvolume layout (`@blue`/`@green`/`@home`/`@root`/`@data`/`@nix`/`@cache`/`@log`/`@flatpak`/`@snapd`/`@waydroid`/`@containers`/`@machines`/`@lxc`/`@lxd`/`@qemu`/`@libvirt`/`@swap`) matches the persistent-state bind-mount strategy; volatile `/var` base + persistent subvolumes on top is coherent.
- `/etc` overlay (etc-factory) over `/usr/share/factory/etc` with `@data/overlay/etc/{upper,work}` is correct and matches the factory-reset semantics.
- `/home` snapshots live under `@home/.snapshots` → survive `shani-reset`, per-user ACLs, 14-day retention + restic off-disk. Coherent.
- Slot markers (`/data/current-slot`, `/data/previous-slot`) + `shani-profile` identity are both in `@data` and persist across slot switches. Coherent.
- Flatpak maintenance: 12 h system+user timers + best-effort repair (2026-10-31) matches the intended cadence.
- beesd dedup present; zram + swappiness 133 + priority 100 paired correctly.
- systemd-oomd enabled via shani-settings.install.
- Hibernate wired (`resume=` in configure.sh and gen-efi.sh).
- Profile swap (`--profile`) writes identity only after successful deploy.
- shani-reset wipes `/data` but preserves @home/@root/@blue/@green/ESP; accounts recreated by first-run wizard. Coherent with the overlay model.

### Fixed in this pass (2026-10-31)

- **btrfs defrag** `BTRFS_DEFRAG_PERIOD="weekly"` → `"none"` in shared + server overlays; `btrfs-defrag.timer` no longer enabled in `shani-settings.install` (defrag remains available on demand via `btrfs filesystem defragment`). Scrub/trim/balance cadence left as-is pending a separate decision.
- **gamescope profile** gained `shani-backup` in `Packages-Desktop` (home snapshots now cover the gaming profile).
- **nut baseline manifest** moved from `/var/lib/shani-settings/` to `/data/varlib/shani-settings/` (persistent).
- **plasmalogin greeter branding** no longer lost on reboot (shipped under `/usr/share/shani/plasmalogin/`, re-applied by `shani-plasmalogin-branding.service`, `plasmalogin` added to `varlib_dirs`).
- **Waydroid binder** verified present (rust_binder built into Arch `linux`); added `binder.conf` modules-load.d (harmless, explicit).
- **Virtual devices** (v4l2loopback, vhba): added `v4l2loopback-dkms` + `v4l2loopback-utils` + `vhba-module-dkms` to `shani-video`, and `linux-headers` to `shani-core` (DKMS prerequisite).
- **LSM lockdown**: `lockdown=confidentiality` added to the UKI cmdline (configure.sh + gen-efi.sh); testbed `verify-boot` PASSED. Remaining caveat: NVIDIA/kexec/hibernation on real hardware.
- **scx schedulers**: added `scx_loader.service.d/10-shani.conf` drop-in (`--auto`) and `/etc/scx_loader.toml` (default `scx_lavd`); enabled in `shani-settings.install` (guarded by `command -v scx_loader`). Added `ntsync.conf` modules-load.d. Needs testbed verification.

### B.4 Recommended improvement order (lowest risk first)

1. **scx scheduler enablement** (B.1 #1) — small, fulfills an existing claim.
2. **btrfsmaintenance defrag cadence** (B.1 #3) — one-line overlay edit.
3. **lockdown=confidentiality** (B.1 #2) — one token, needs testbed.
4. **shani-settings manifest → /data** (B.1 #4) — small, correctness.
5. **gamescope home snapshots** (B.1 #5) — one line in Packages-Desktop.
6. **Waydroid binder auto-load** (B.2 #9) — verify + modprobe.d if needed.
7. **Drop or qualify the "+3-0 automatic fallback" and "Next-Gen Scheduling" claims** in docs until the mechanisms actually run.
