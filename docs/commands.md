# shani-deploy Command Reference

Production blue-green Btrfs deployment system for Shanios, an immutable Arch Linux derivative. This reference covers the current `shani-deploy`, `shani-health`, and `shani-reset` commands, Shani Cassini's integration, and the testbed's read-only `update-check` compatibility command.

---

## shani-deploy

Core deployment engine. Typical flow: self-update check, fetch manifest, verify GPG signature, `btrfs receive` into candidate slot, generate/sign UKI, update boot entries, write reboot-needed marker.

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-h, --help` | Show help and exit | — |
| `-r, --rollback` | From the newer system, make the previous one the default again (nothing is deleted; reboot to use it). From the older system after a fallback, repair the other slot from its pre-update backup. | — |
| `-c, --cleanup` | Manual cleanup: remove old backup snapshots and cached downloads | — |
| `-o, --optimize` | Run manual deduplication via `duperemove` (maintenance only; `bees` handles continuous dedup) | — |
| `-t, --channel <chan>` | Update channel: `stable` or `latest` | `stable` |
| `-f, --force` | Deploy even if version matches or boot mismatch | — |
| `--download-only` | Fetch and verify the update image, then exit without deploying | — |
| `-d, --dry-run` | Simulate without making changes | — |
| `-v, --verbose` | Detailed debug output | — |
| `--set-channel <chan>` | Persistently set channel in `/etc/shani-channel` (`stable` or `latest`) | — |
| `--verify-existing` | Verify current deployment integrity without updating | — |
| `--list-backups` | List available rollback backups with timestamps | — |
| `--channel-status` | Show latest/stable versions available remotely | — |
| `--status --json` | Print local deployment state as JSON (slots, version, channel, boot and recovery markers); read-only and no root | — |
| `--status --check --json` | Add remote stable/latest versions and `update_available` to the JSON status; read-only and no root | — |
| `--skip-self-update` | Skip auto-update of `shani-deploy` itself | — |
| `--update-genefi` | Download latest `gen-efi` from upstream and use it in the chroot (not installed to host) | — |

### Notes

- `--download-only` cannot be combined with `--rollback`, `--cleanup`, `--optimize`, `--set-channel`, `--verify-existing`, `--list-backups`, or `--channel-status`.
- The new slot is fully deployed and bootable as soon as this script finishes. Rebooting promptly is not required.
- `flock`-based locking on `/run/shanios-deploy.lock` serializes overlapping invocations.

---

## Shani Cassini and testbed compatibility

The `shani-update` binary is retired. The current user-facing deploy and
rollback interface is Shani Cassini's **Updates & Rollback** page, which
streams the same deployment engine through `pkexec`.

| Interface | Behavior |
|-----------|----------|
| `shani-cassini` (Updates & Rollback) | Install, channel selection, status, and rollback UI |
| `shani-deploy --status --check --json` | Read-only local and remote update state used by Cassini |
| `pkexec shani-deploy` | Install an available update through the deployment engine |
| `pkexec shani-deploy --rollback` | Roll back according to the current slot/boot-failure state |
| `pkexec shani-deploy --set-channel stable\|latest` | Persist the selected update channel |
| `shani-cassini-agent.timer` / `.service` | Periodically run the read-only status check and send update/boot notifications; the agent never deploys or rolls back |

The testbed retains `update-check` as a read-only compatibility interface
for the old `update` test-command name:

```bash
./run_in_container.sh build.sh test update-check \
    --local-src=/opt/shani-deploy/scripts
./run_in_container.sh build.sh test update-check --json
```

`update-check` exercises the `shani-deploy --status --check --json`
contract only. It does not install an image, switch a slot, or run the
Shani Cassini notification agent, and it is not a user updater.

---

## shani-health

System health, security, and diagnostics tool. Read-mostly, no deployment side effects. Requires root (auto-escalates via `pkexec` or `sudo`).

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `(no args)` | Full system status report | — |
| `-i, --info` | Alias for full system status report | — |
| `--clean-logs [DAYS]` | Clean old app logs from `/var/log` | Keep last 30 days |
| `--verify` | Deep integrity check: UKI signatures, Btrfs scrub, immutability | — |
| `--json` | With `--verify`: also print a machine-readable JSON summary to stdout | — |
| `--nagios` | Output in Nagios-compatible format (exit code: 0=OK, 1=WARN, 2=CRIT) | — |
| `--prometheus` | Output in Prometheus text format (for scraping) | — |
| `--fix` | Auto-remediate safe issues (enable timers, start services, sync keymap) | — |
| `--security` | Security report: boot chain, immutability, encryption, services, users, Kerberos | — |
| `--journal [level]` | Show journal entries | `crit` |
| `--since TIME` | Limit journal output to entries since TIME (e.g. `-1h`, `-2d`, `2026-01-01`) | — |
| `-s, --storage-info` | Btrfs storage analysis: subvolume sizes, compression, snapshots | — |
| `--history [N]` | Last N deploy/rollback events from log | 50 |
| `--clear-boot-failure` | Clear a stale boot failure marker (when current boot is healthy) | — |
| `--boot` | Boot report: slots, entries, deployment, immutability, UKI | — |
| `--network` | Network report: NM, DNS, VPN, firewall, SSH, servers | — |
| `--hardware` | Hardware report: CPU, disk, SMART, temps, battery, firmware | — |
| `--packages` | Package report: flatpak, snap, nix, containers, virtualisation | — |
| `--export-logs [DIR]` | Bundle logs + state for bug reports | `/tmp` |
| `-v, --verbose` | Verbose/debug output | — |
| `-h, --help` | Show help and exit | — |

### Output Formats

`--json`, `--nagios`, and `--prometheus` are mutually exclusive. They modify the output of the selected mode (typically `--verify` or `--info`).

---

## shani-reset

Factory reset: wipes `/data` (all `/etc`/`/var` overlay changes, service state, boot markers) and reboots. `systemd-tmpfiles` recreates the structure fresh on next boot. Does not touch `/home`, `/root`, `@blue`/`@green`, or the ESP/UKI.

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--hard` | Wipe `/data` entirely instead of selectively. Both modes produce the same end state; `--hard` also removes any unknown files that accumulated in `/data`. | — |
| `--keep-downloads` | Preserve `/data/downloads` (cached OS images, can be GBs) | — |
| `--home` | Also wipe `/home` (user files — irreversible, asks twice) | — |
| `--dry-run` | Print what would be deleted without making changes | — |
| `--yes, -y` | Skip the confirmation prompt (for scripted use) | — |
| `-h, --help` | Show help and exit | — |

### What Survives

- `/home` and `/root` — user home directories (separate Btrfs subvolumes, NOT wiped unless `--home` is passed)
- `@blue` and `@green` — OS root subvolumes (system still boots normally after reset)
- ESP / UKIs — boot images and entries (untouched)

### Important

User accounts (`/etc/passwd` entries) are part of the `/etc` overlay and ARE wiped. Home directory files in `/home` survive, but the accounts that own them must be re-created after reboot. On a desktop system, the KDE (`plasma-welcome`) or GNOME (`gnome-initial-setup`) first-run wizard starts automatically and creates a new user account.

---

## Self-Update Mechanism

`shani-deploy` updates itself before any deployment work begins. The mechanism is fail-closed: any verification failure keeps the current trusted copy running.

### Step-by-step

1. **Skip checks** — If `--skip-self-update` is set, or a deployment is mid-flight (`/data/deployment_pending` exists), self-update is skipped.
2. **Download** — Fetches the latest `shani-deploy.sh`, its `.sha256`, and `.asc` from `https://raw.githubusercontent.com/shani8dev/shani-deploy/refs/heads/main/scripts/shani-deploy.sh`.
3. **SHA256 verification** — Verifies the downloaded script against its `.sha256` sidecar.
4. **GPG verification** — Verifies the `.asc` signature against the pinned key (`7B927BFFD4A9EAAA8B666B77DE217F3DA8014792`). Prefers the bundled key at `/etc/shani-keys/signing.asc`; falls back to keyservers if the bundled key is missing, fails to import, or its fingerprint does not match (covers key rotation).
5. **Content sanity check** — Confirms the downloaded file contains `#!/bin/bash` and `shanios-deploy` to prevent executing a non-script file that passed cryptographic checks.
6. **Comparison** — If the downloaded script differs from the running copy (`cmp -s`), it is marked executable and re-executed via `exec /bin/bash "$temp" "${ORIGINAL_ARGS[@]}"`.
7. **State preservation** — Before `exec`, the script cleans up `STATE_DIR` (the EXIT trap does not fire after `exec`) and exports `LOCK_ACQUIRED=1` so the re-exec'd instance knows it already holds the deploy lock.
8. **Fail-closed** — Any failure in download, checksum, signature, or sanity check logs an error and continues with the current trusted copy. The temporary files are cleaned up.

---

## Environment Variables

### shani-deploy

| Variable | Description | Default |
|----------|-------------|---------|
| `SHANIOS_DEPLOY_STATE_FILE` | Path to a state file for restoration across re-execs. Must match `/run/shanios_deploy_state.[A-Za-z0-9]+` to be trusted. | — |
| `SHANIOS_DEPLOY_GPG_KEY_ID` | GPG key ID for image/script verification | `7B927BFFD4A9EAAA8B666B77DE217F3DA8014792` |
| `AUTO_REBOOT` | Opt-in auto-reboot after successful deployment (`yes`/`no`) | `no` |
| `AUTO_REBOOT_DELAY` | Seconds to wait before auto-reboot | `60` |
| `BACKUP_NAME` | Override backup name for rollback | — |
| `CURRENT_SLOT` | Override current slot | — |
| `CANDIDATE_SLOT` | Override candidate slot | — |
| `REMOTE_VERSION` | Override remote version | — |
| `REMOTE_PROFILE` | Override remote profile | — |
| `IMAGE_NAME` | Override image name | — |
| `UPDATE_CHANNEL` | Override update channel (`stable`/`latest`) | `stable` |
| `UPDATE_CHANNEL_SOURCE` | Source of the update channel | — |
| `DRY_RUN` | Dry run mode (`yes`/`no`) | `no` |
| `VERBOSE` | Verbose mode (`yes`/`no`) | `no` |
| `SKIP_SELF_UPDATE` | Skip self update (`yes`/`no`) | `no` |
| `SELF_UPDATE_DONE` | Set by self-update to prevent re-running | — |
| `UPDATE_GENEFI` | Update gen-efi flag (`yes`/`no`) | `no` |
| `FORCE_UPDATE` | Force update flag (`yes`/`no`) | `no` |
| `DOWNLOAD_ONLY` | Download only flag (`yes`/`no`) | `no` |
| `CANDIDATE_MODIFIED` | Candidate modified flag (`yes`/`no`) | `no` |

### Shani Cassini agent

| Variable | Description | Default |
|----------|-------------|---------|
| `XDG_STATE_HOME` | Base for the agent's deduplication state | `~/.local/state` |
| `XDG_RUNTIME_DIR` | Runtime directory supplied by the systemd user manager | — |

### shani-reset

| Variable | Description | Default |
|----------|-------------|---------|
| `DISPLAY`, `XAUTHORITY`, `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS` | Preserved across `pkexec` re-invocation for display/terminal access | — |

---

## Exit Codes

| Code | Script | Meaning |
|------|--------|---------|
| `0` | `shani-deploy` | Success (deployment, cleanup, optimize, or info query completed) |
| `1` | `shani-deploy` | Fatal error (invoked via `die()`) |
| `0` | Shani Cassini agent | Status check completed; no action taken |
| `1` | Shani Cassini agent | Status check could not be read or parsed |
| `0` | `shani-health` | Success / no issues found |
| `1` | `shani-health` | Fatal error, or (for `--verify`) integrity issues found |
| `0` | `shani-reset` | Success (or user aborted confirmation) |
| `1` | `shani-reset` | Fatal error (pre-condition failed, e.g. `/data` not mounted, deployment in progress) |

---

## See Also

- `README.md` — Project overview, blue-green model, script descriptions, systemd units, recovery paths, and testing instructions.
- `AGENTS.md` — Agent instructions for this repository, including safety-critical coding guidelines, verification requirements, and known sharp edges.
