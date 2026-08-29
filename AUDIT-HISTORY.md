# shani-deploy — audit/fix history

This file is the full narrative behind every entry in `AGENTS.md`'s
"Audit-verified known issues" section — the verification methodology,
before/after evidence, and reasoning for each fix. **Read `AGENTS.md`
first** — that file is the current-state summary; this one is why and how.

This file is append-only in spirit: when `AGENTS.md`'s summary is updated
for a new fix, the full narrative for that fix should land here, not
inflate the main file back to unreadable length.

---

- **Terminal exit-code trust RESOLVED.** `scripts/shani-update.sh:370` now
  uses `--wait` for gnome-terminal — rollback "success" reporting while
  mid-flight is fixed.
- **`get_booted_subvol()` duplicated 4× — harmonized, deliberately not
  merged into one shared file.** Was: the 4 copies (`scripts/shani-deploy.sh`,
  `scripts/shani-update.sh`, `scripts/gen-efi.sh`, `scripts/shani-health.sh`)
  weren't just textually duplicated, they had genuinely *different*
  behavior — `shani-health.sh`'s copy alone had an extra fallback (a bare
  `subvol=@name` directly on cmdline, no `rootflags=` wrapper) and never
  aborts (returns `"unknown"` instead), since a health/diagnostics tool
  shouldn't crash on a detection miss. A blind merge into one shared
  function would have either dropped that fallback from the other 3 or
  forced `shani-health.sh` to abort like the others — instead, backported
  the extra fallback into all 4 and left each script's own not-found
  handling (`error_exit`/`err`/`die`/`"unknown"`) untouched. Not merged into
  one sourced file: these 4 are packaged and installed as independent
  executables (see `shani-pkgbuilds/shani-deploy/PKGBUILD`) with no existing
  shared-lib mechanism between them — adding one is a real packaging change
  or a fresh repo-clone hazard, out of proportion to a maintainability
  finding on non-broken code. Each copy now has a comment pointing at the
  other 3.
  **Also found and fixed a real, separate bug this surfaced**: every copy's
  regex was `grep -oP '(?<=subvol=@?)[^,]+'` — a *variable-length* PCRE
  lookbehind (`@?` inside `(?<=...)`), which **real GNU grep rejects**
  ("lookbehind assertion is not fixed length") even though it silently
  works under `ugrep` (a grep-compatible reimplementation with a more
  permissive PCRE2 JIT engine) — meaning this had been silently broken on
  the *actual* production `/usr/bin/grep` all along, always falling through
  to the last-resort `btrfs subvolume get-default` path, or erroring, and
  nobody caught it because casual/interactive testing on a dev machine with
  `ugrep` aliased over `grep` never reproduces it. Rewrote as
  `grep -oP 'subvol=@?\K[^,]+'` (`\K` resets the match start instead of
  using a lookbehind, so it has no fixed-length restriction). **Verified
  for real, not just statically**: used `shani-install-media`'s
  `test-env` harness (`build.sh test bootstrap -p gnome`, then
  `build.sh test enter blue --local-src=<dir-of-edited-scripts>`) to
  install the actual edited `gen-efi`/`shani-deploy`/`shani-update`/
  `shani-health` binaries into a real systemd-nspawn container and confirm
  `grep` there resolves to genuine GNU grep (3.12, not `ugrep`), then ran
  each script's real `get_booted_subvol`/`_get_booted_subvol` (extracted
  from the actual installed binary via `source`, not retyped) against all
  3 real cmdline shapes with `/proc/cmdline` shadowed to a controlled file
  — all 4 correctly returned `blue`/`green`/not-found, each preserving its
  own not-found behavior (`error_exit`/`err`/`die`/`"unknown"`).
- **No systemd hardening — FIXED, per-unit not blanket.** Added
  `NoNewPrivileges=yes`/`PrivateTmp=yes` to all 10 units, plus
  `ProtectSystem=full` on the 6 confirmed to write only `/data`, flatpak's
  own data dirs, or `$HOME` (`check-boot-failure`, `mark-boot-success`,
  `mark-boot-in-progress`, `flatpak-update-system`,
  `flatpak-update-user`, `shani-download-only` — the last one grep-checked
  to confirm `--download-only` mode exits right after `download_update()`,
  before any `/etc`/`/boot` write). Deliberately did **not** apply
  `ProtectSystem` to 3 units that genuinely need it off:
  `beesd-setup.service` (writes `/etc/bees/*.conf`, runs `systemctl
  enable`), `shani-user-setup.service` (syncs `/etc/passwd`/skel for all
  users — its whole job), `bless-boot.service` (matches systemd's *own*
  upstream `systemd-bless-boot.service` template, which ships with zero
  hardening — checked the real installed file, almost certainly because
  it needs to write boot-loader state under `/boot/efi`).
  **`shani-update.service` (user) deliberately got none of this at all** —
  found via grep that `shani-update.sh`'s real deploy path re-execs itself
  via `pkexec shani-deploy ...` (a setuid-root binary); `NoNewPrivileges`
  is inherited by child processes and would silently block that
  escalation entirely, and any mount-namespacing directive
  (`ProtectSystem`/`PrivateTmp`) is inherited across the `pkexec` boundary
  the same way (`pkexec` doesn't create a new mount namespace), which
  would sandbox the escalated `shani-deploy` process that needs real
  `/etc`/`/boot` access — silently breaking every update this unit exists
  to trigger. Commented in the unit file so a future edit doesn't
  "helpfully" add hardening back.
  **Verified for real, not just `systemd-analyze verify`**: that alone
  passed clean (no error attributable to the new directives — only
  pre-existing host noise and expected "binary not found" since this
  host isn't a real ShaniOS system), but a real `systemd-run` inside the
  `shani-install-media` test-env nspawn container failed for an
  unrelated reason (no PID 1 systemd in a plain non-`--boot` entry) — so
  instead recreated `ProtectSystem=full`'s actual kernel mechanism
  directly (`unshare --mount` + real `mount --bind -o ro` on
  `/usr`/`/etc`/`/boot`) and ran the real installed binaries under it:
  confirmed `/etc` was genuinely read-only in that namespace, then ran
  `mark-boot-in-progress`'s commands, `mark-boot-success`'s commands, the
  real `check-boot-failure` binary (correctly recorded the right failed
  slot through its full logic, matching the non-sandboxed run), and
  `shani-deploy --download-only` (ran several real steps — connectivity
  check, script-update check, power-inhibit — with no permission error
  before the test's own `timeout` cut it off) — all functioned identically
  under real `ProtectSystem=full` enforcement.
- **CI status.** No CI workflows in this repo — verification is entirely
  manual.
- **`log`/`warn` argument-splitting — FIXED.** Was:
  `scripts/shani-user-setup.sh:235-237` used `${arr[@]+"${arr[@]}"}` inside
  a double-quoted string (shellcheck SC2145), splitting into multiple
  positional args instead of one string — harmless only because
  `log()`/`warn()` happened to re-join with `"$*"`. Changed to
  `"${arr[*]:-}"` (a proper single space-joined string); verified directly
  against a real empty array and a populated one under `set -u` (bash
  5.2), both correct.
- **`check-boot-failure.sh` has no strict mode — investigated, deliberately
  NOT added.** Tried adding `set -Eeuo pipefail` to match its siblings,
  then live-tested it against 5 real scenarios (hard-failure early exit,
  stale-marker clearing, no-op happy path, failure recording, and a
  missing-`btrfs`-binary case) in a sandboxed copy — the last one revealed
  a real regression: `[ -z "$BOOTED_SLOT" ] && BOOTED_SLOT=$(btrfs ...)` is
  a bare `cmd1 && cmd2` statement, so under `set -e` a failing `btrfs` call
  there (missing binary, not-a-btrfs-root, run inside a container) aborts
  the whole script instead of reaching the graceful "cannot detect booted
  subvolume — skip" exit a few lines later. Reverted; the script now has a
  comment explaining why it deliberately has no strict mode, and what
  would actually be needed (auditing every risky line for an explicit
  `|| true` guard first) before it could safely get one.
- **A 5th, previously-unaudited copy of the booted-subvol detection logic
  — found and fixed while working the "duplicated 4×" item above.**
  `check-boot-failure.sh:35-39` has its own inline copy — missed by the
  original "4 copies" count because `grep -rn "get_booted_subvol"` only
  finds the named-function copies, and this one is inline. It already used
  the safe `awk`-based extraction (not the broken lookbehind regex the
  other 4 had), so it wasn't affected by that bug — but it lacked the
  "bare `subvol=@name`, no `rootflags=` wrapper" fallback the other 4 now
  have. Added the same fallback, preserving this script's deliberate
  no-`set -e` structure exactly (see the item above — this script cannot
  safely use `set -e`). **Verified for real**, not just the isolated regex:
  ran the actual installed `check-boot-failure` binary inside a real
  systemd-nspawn container (`shani-install-media`'s `test-env`) against
  both a `rootflags=`-wrapped and a bare `subvol=` cmdline, in each case
  setting up real `/data/current-slot`+`/data/boot_in_progress` marker
  state and confirming the script recorded the *correct* failed slot
  through its full downstream mismatch-derivation logic, not just that the
  slot name parsed correctly in isolation.
- **`CHROOT_ESP_BIND` dead flag — FIXED.** Was: `scripts/shani-deploy.sh:108,1605,1609`
  set a global that a comment claimed cleanup needed (to avoid unmounting
  the host's real ESP), but `cleanup_chroot()` never read it — confirmed
  harmless because unmounting a bind-mount's target never touches its
  source regardless. Removed the dead variable and the 3 assignments;
  replaced the misleading comment with one explaining why no such flag is
  needed. `bash -n` clean, `tests/test-deploy-state.sh` still 9/9.
