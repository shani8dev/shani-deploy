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

- **`_run_gui_progress` switched from `--progress --pulsate` to an inline
  `--text-info --tail --disable-search` log view — and the earlier
  "`--text-info` unconditionally crashes" finding was corrected
  (2026-09-19).** The user's actual ask ("it should have shown an inline
  terminal in the yad UI, like Ubuntu's installer") is a scrolling log
  view, not a single pulsing status line — the original `--progress`
  fallback was a workaround for a crash, not the intended design. Re-ran
  the crash investigation with the user's own report as the new data
  point ("i clicked on show terminal and it exited"):
  1. Root-caused the `--text-info` SIGABRT (rc=134) to a **search-bar
     icon**, not anything `--text-info` unconditionally does. yad's
     text-info builds a search entry whose icon resolves to an SVG; the
     image has no working SVG rasterizer (no `libpixbufloader-svg.so`, no
     `svg` in gdk-pixbuf 2.44.7's `loaders.cache`; glycin's sandboxed
     `bwrap ... glycin-svg` child exits 1 under `/usr/share/glycin-loaders`),
     GTK falls back to `image-missing.svg` (present, 1331 bytes, but still
     unloadable), and asserts in `gtkiconhelper.c:495`. Isolated with
     `yad --list` (renders, rc=124) and `bwrap --ro-bind / / true` (works,
     so bwrap itself is fine).
  2. Found `--disable-search` via `yad --help-all` ("Disable search in
     text and html dialogs") and proved it fixes the exact invocation.
  3. Probe matrix on one yad build, all else equal: plain `--text-info`
     → **rc=134** (the control); `--text-info --disable-search --tail
     --filename` → **rc=124**; live stdin stream → rc=124; the real shape
     (icon + `Show Terminal`/`Cancel`/`Close`) → rc=124; `tail -f --pid |
     --text-info --disable-search --tail` → rc=124. A no-`--tail`
     variant returned rc=1 from the harness's own timeout-kill teardown
     (benign X MIT-SHM BadAccess), not a render failure.
  4. **Shipped and verified end-to-end on the real path, with visual
     evidence**: `shani-update --health` overlaid via `test-env/test.sh
     probe --local-src=/opt/shani-deploy/scripts`, screenshotted off the
     live X11 display. The screenshot shows a scrollable multi-line log
     with **real health-report content** (the smsd/Samba/NFS/Caddy/… rows),
     the **Show Terminal / Cancel / Close** buttons, and **no search bar**
     (confirming `--disable-search` took effect). Live streaming was proved
     by two snapshots of the same run: at ~3 s the view showed `live-log`
     lines 1–4; ~12 s later it showed lines 1–16, timestamps one second
     apart — content accumulating in place, which the old single-line
     `--progress` view could not have shown. Window geometry was exactly
     the configured 700×450.
  The `--disable-search` flag is now documented in the function's own
  comment as load-bearing (removing it reproduces the SIGABRT).

- **`shani-update.sh` masked the real exit code of every operation —
  FIXED (2026-09-19).** `_cleanup_and_exit()` ended with a bare
  `exit "${1:-0}"` and the trap was `trap '_cleanup_and_exit' EXIT INT
  TERM`. A genuine `exit 1` (any of the ~10 `_cleanup_and_exit 1` sites or
  `err()`) fired the EXIT trap, which re-invoked `_cleanup_and_exit` with
  **no argument**, so `"${1:-0}"` reset the status to **0** — every
  failure reported as success to the caller and to `systemd`.
  This was found while investigating the user's Cancel report: an earlier
  session claimed "Cancel → rc=143", but a real repackaged rollback run
  produced `REAL_ROLLBACK_EXIT_CODE:0` — the worker *process* was indeed
  killed (no orphan; the signal delivery was fine), but the code the
  caller observed was wrong. Verified live on the real overlaid binary
  (`shani-update --health`, `/usr/local/bin/shani-health` moved aside, so
  execution reaches the **post-trap** `err()` at the health dispatch):
  **positive test** — fixed script returns `rc=1`; **negative control**
  — the same real script with only the trap lines reverted to the buggy
  single-line form returns `rc=0`, with identical ERROR output. Also
  unit-controlled the mechanism with `/tmp/ec_new.sh` (rc=1) vs
  `/tmp/ec_old.sh` (rc=0). Fixed by splitting lock cleanup from exit: a
  new idempotent `_cleanup_lock()` on `EXIT`, and `INT`/`TERM` mapped to
  `_cleanup_and_exit 130`/`143`. `bash -n` clean;
  `tests/test-deploy-state.sh` 9/9; `tests/test_upgrade_adviser.sh` 21/21.
  While in the area, the Cancel log line was corrected from a hardcoded
  `$DEPLOY_BIN` to the actual worker `${cmd[0]}` — the health path was
  logging "terminating shani-deploy" while killing `shani-health`.

- **`download_update()` built its R2 path from the wrong profile token —
  R2 was "checked" and silently abandoned on every deploy (2026-09-19).**
  `r2_image_path="${REMOTE_PROFILE}/${REMOTE_VERSION}/${IMAGE_NAME}"`
  put the artifact under `stable-gnome/...`, but R2 stores it under the
  **bare** profile directory (`gnome/...`). `REMOTE_PROFILE` is parsed from
  the image *filename* (`shanios-20260918-stable-gnome.zst` → `stable-gnome`),
  which embeds the release-branch prefix; the R2 directory is the plain
  profile, matching `build-base-image.sh:92`
  (`IMAGE_NAME="${OS_NAME}-${BUILD_DATE}-${BRANCH}-${PROFILE}.zst"` published
  to `${R2_BASE_URL}/${PROFILE}/${BUILD_DATE}/${IMAGE_NAME}`) and
  `promote-stable.sh`'s `${R2_BASE_URL}/${PROFILE}/...` layout. There is no
  `stable-gnome/` directory on R2 at all, so `get_remote_file_size` returned
  0 and the code fell back to SourceForge — for every profile, every deploy,
  ever. This is why the user's question "download should have used r2?"
  was the right one: R2 was wired in (`R2_BASE_URL=https://downloads.shani.dev`,
  `download_from_r2()`, the "Checking primary download server (R2)..." log
  line at `download_update` L3231) but the path was wrong, so it was
  effectively dead code. **Confirmed live against the real public R2:**
  `gnome/20260918/shanios-20260918-stable-gnome.zst` → **200**,
  `content-length: 2541284404` (~2.5 GB), first bytes `28 b5 2f fd` (valid
  zstd), plus `.sha256`/`.asc`/`.zsync` all **200**; the same path under
  `stable-gnome/` → **404**. The harness log showed the failure in action:
  `Checking primary download server (R2)...` → immediately
  `Discovering SourceForge mirror...` → SF 403/404 on all 5 attempts →
  `FATAL Download failed after 5 attempts`. The v20260918 artifact is
  genuinely missing from SourceForge (host-confirmed 404), so the SF leg
  was an upstream publish gap, not the bug — but the R2 leg was ours.
  **Fix** (`shani-deploy.sh` L3230):
  `local r2_image_path="${REMOTE_PROFILE#*-}/${REMOTE_VERSION}/${IMAGE_NAME}"`
  — strip the branch prefix with a single parameter expansion, correct for
  every branch (`stable-gnome` → `gnome`, `unstable-gnome` → `gnome`) and
  for cross-profile updates, and strictly safer than the current code.
  This also fixes the `.sha256`/`.asc` fetches at L3394/3399, which derive
  from the same `r2_image_path` and 404 identically. `bash -n` clean.
  **Verified live in the real harness:** `clean`/`ca`/`bootstrap` all pass,
  and `upgrade` now reaches R2 — `Primary server available — image size:
  2.4G`, `use_r2=1`, and it begins the zsync2 differential download from
  `https://downloads.shani.dev/gnome/20260918/shanios-20260918-stable-gnome.zst.zsync`
  (confirmed via the container's own process table and an established HTTPS
  connection to `204.90.140.1:443`). The full 2.5 GB transfer was not
  completed here — this sandbox's egress is throttled (~150 KB/s) and
  zsync2 is CPU-bound at ~99% computing rsync checksums over the 4.8 GB of
  seed files, so the run was stopped rather than burn the session on a
  multi-hour download. The R2 path is proven reachable and correct; the
  remaining time is pure transfer, not correctness. Left a clean state:
  removed the partial 20260918 artifacts and the stale `mirror.url` cache.
  **Note on the SourceForge side:** `sha_url`/`asc_url` (L3222-3223) still
  use `${REMOTE_PROFILE}` = `stable-gnome/`, which matches what SourceForge
  *does* serve (the log's mirror URL is `/stable-gnome/...`) — SF and R2
  genuinely use different directory conventions for the same artifact, so
  the fix is R2-only, not a blanket `REMOTE_PROFILE`→`LOCAL_PROFILE` swap.
