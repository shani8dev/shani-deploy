#!/bin/bash
# sign-deploy-script.sh - Generate SHA256 checksum and GPG signature for shani-deploy.sh
#
# This script is run by the CI workflow to produce the .sha256 and .asc files
# that shani-deploy's self_update() mechanism requires.
#
# Requirements:
#   - GPG_PRIVATE_KEY in environment (or GPG key in default keyring)
#   - GPG_PASSPHRASE in environment (if key is passphrase-protected)
#   - GPG_KEY_ID in environment (default: 7B927BFFD4A9EAAA8B666B77DE217F3DA8014792)

set -Eeuo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
TARGET_SCRIPT="$SCRIPT_DIR/shani-deploy.sh"

GPG_KEY_ID="${GPG_KEY_ID:-7B927BFFD4A9EAAA8B666B77DE217F3DA8014792}"
BUILDER_GNUPGHOME="${GNUPGHOME:-/tmp/gnupg-sign-deploy}"

log()  { echo "[INFO] $*" >&2; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# Check target exists
[[ -f "$TARGET_SCRIPT" ]] || die "Target script not found: $TARGET_SCRIPT"

# Generate SHA256 checksum
log "Generating SHA256 checksum for $(basename "$TARGET_SCRIPT")..."
# Hash from inside scripts/ so the file records the bare name (as f82f2d7
# did by hand), not the CI runner's absolute path; verify_sha256 only reads
# the hash field, but `sha256sum -c` and humans read the name too.
(cd "$SCRIPT_DIR" && sha256sum "$(basename "$TARGET_SCRIPT")") > "${TARGET_SCRIPT}.sha256" || die "Checksum generation failed"
log "SHA256: $(cat "${TARGET_SCRIPT}.sha256")"

# Prepare GPG keyring
log "Preparing GPG keyring in ${BUILDER_GNUPGHOME}..."
mkdir -p "${BUILDER_GNUPGHOME}"
chmod 700 "${BUILDER_GNUPGHOME}"

# Import private key if provided via env
if [[ -n "${GPG_PRIVATE_KEY:-}" ]]; then
    log "Importing GPG private key from environment..."
    printf '%s\n' "$GPG_PRIVATE_KEY" | gpg --homedir "$BUILDER_GNUPGHOME" --batch --import \
        || die "Failed to import GPG private key"
fi

# Set ultimate trust
echo "${GPG_KEY_ID}:6:" \
    | gpg --homedir "$BUILDER_GNUPGHOME" --batch --import-ownertrust \
    || die "Failed to set ultimate trust for ${GPG_KEY_ID}"

# Verify secret key is present
if ! gpg --homedir "$BUILDER_GNUPGHOME" --list-secret-keys "$GPG_KEY_ID" >/dev/null 2>&1; then
    die "GPG secret key not found in ${BUILDER_GNUPGHOME}: ${GPG_KEY_ID}"
fi

# Create detached armored GPG signature
log "GPG signing: $(basename "$TARGET_SCRIPT")..."
gpg --homedir "$BUILDER_GNUPGHOME" \
    --batch \
    --yes \
    --pinentry-mode loopback \
    --passphrase "${GPG_PASSPHRASE:-}" \
    --default-key "$GPG_KEY_ID" \
    --detach-sign \
    --armor \
    --output "${TARGET_SCRIPT}.asc" \
    "$TARGET_SCRIPT" \
    || die "GPG signing failed for ${TARGET_SCRIPT}"

log "GPG signature created: ${TARGET_SCRIPT}.asc"

# Verify the signature
log "Verifying signature..."
gpg --homedir "$BUILDER_GNUPGHOME" \
    --batch \
    --verify "${TARGET_SCRIPT}.asc" "$TARGET_SCRIPT" \
    || die "Signature verification failed"

log "All done! Generated:"
log "  ${TARGET_SCRIPT}.sha256"
log "  ${TARGET_SCRIPT}.asc"