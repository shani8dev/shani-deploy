# Security Policy

## Trust Model

`shani-deploy` is the blue-green deployment, boot-entry, and rollback mechanism
for Shanios immutable OS images. It operates under a **fingerprint-pinned,
fail-closed, atomic-write** trust model:

- All remote artifacts (update scripts, EFI binaries) are verified by
  **SHA256 checksum + GPG signature** against a pinned fingerprint before
  execution or replacement.
- Boot entries are written via **temp-file-then-atomic-`mv`** — a crash cannot
  leave a slot with zero valid boot entries.
- `self_update()` applies the same download → checksum → GPG-verify → fail-closed
  chain as the agent's `check_self_update()`.
- The live file is never observed in a signed-but-invalid state — verification
  happens before replacement, never after.

## Key Security Mechanisms

| Mechanism | Implementation |
|-----------|----------------|
| GPG fingerprint pinning | `GPG_KEY_ID="7B927BFFD4A9EAAA8B666B77DE217F3DA8014792"` (`scripts/shani-deploy.sh`) |
| Atomic boot entries | `finalize_boot_entries()` writes `.tmp` then `mv` (`scripts/shani-deploy.sh:1726-1824`) |
| Verify-before-replace | `sign_efi_binary()` verifies signed tmp via `sbverify` before `mv` (`scripts/gen-efi.sh:295-334`) |
| Self-update trust chain | `self_update()` requires `.sha256` + `.asc`; fails closed on any mismatch (`scripts/shani-deploy.sh:1290-1330`) |
| Boot-failure detection | `check-boot-failure.sh` uses `flock -w 30` to avoid TOCTOU races |

## Known Limitations

- **No `NoNewPrivileges`/`ProtectSystem`/`PrivateTmp`.** Systemd units lack
  these sandboxing directives.

## Reporting a Vulnerability

If you discover a security vulnerability in any Shanios project, please report it
responsibly by opening a private security advisory on GitHub:

https://github.com/shani8dev/shani-deploy/security/advisories/new

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 72 hours and provide a detailed response
within 7 days. Thank you for helping keep Shanios secure.
