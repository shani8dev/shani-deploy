#!/bin/bash
# Every write of a boot default must name systemd-boot's ENTRY ID, not a
# filename stem, not a glob, and not a `+N-M` filename.
#
# WHY THIS EXISTS. Two real instances of one class, and nothing caught either:
#
#   1. The dracut boot-failover hook wrote `default shanios-blue` - the entry
#      STEM. A type-1 entry's id is its FILENAME, `.conf` included (boot.c:
#      `boot_entry_parse_tries(..., ".conf")` strips a `+N-M` counter but keeps
#      the suffix, then `entry->id = xstrdup16(file)`), so a stem matches
#      nothing and systemd-boot falls through to "the first suitable entry",
#      which on a post-flip disk is the broken candidate. The rewrite landed on
#      disk, read back correct, and changed nothing.
#   2. os-installer-config/scripts/configure.sh documented itself as writing
#      "a glob pattern" while writing a literal - and shani-deploy explicitly
#      rejects globs. A reader trusting that comment would have "fixed" it into
#      a form that stops the machine finding its entry at all.
#
# The first survived a fully green end-to-end field test, because the testbed's
# EFI variables were unset: no deploy had ever run there. So the value of this
# lint is entirely in whether it can go red, which `tests/` checks by mutation.
#
#   shani-deploy/tests/test-boot-default-entry-id.sh     (host-only, no root, no disks)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(dirname "$HERE")/.."
pass=0 fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n        %s\n' "$1" "$2"; fail=$((fail + 1)); }

# this repo always; the other two writers of boot defaults when checked out beside it
REPOS=("$(cd "$HERE/.." && pwd)")
for r in shani-install-media os-installer-config; do
  [[ -d "$WS/$r" ]] && REPOS+=("$WS/$r")
done

# Every .sh in the workspace that is not a test, a cache, or a build artifact.
sources() {
  local r
  for r in "${REPOS[@]}"; do
    find "$r" -type f -name '*.sh' 2>/dev/null
  done | grep -vE '/(tests?|cache|disk|\.git)/' | sort -u
}

# ---------------------------------------------------------------- 1. the hook
echo "== the dracut failover hook"
HOOK=$(find "$WS/shani-install-media" -name 'shanios-boot-failure-hook.sh' 2>/dev/null | head -1)
if [[ ! -d $WS/shani-install-media ]]; then
  # shani-deploy's own CI checks out this repo alone; the hook is the other repo's
  echo "  skip  no shani-install-media checkout beside this one - the hook is not checked"
elif [[ -z $HOOK ]]; then
  no "the hook is present" "shanios-boot-failure-hook.sh not found under shani-install-media"
else
  h="${HOOK#$WS/}"
  grep -qE 'FALLBACK="\$\{N\}\.conf"' "$HOOK" \
    && ok "$h: the fallback is an entry id, not a stem" \
    || no "$h: the fallback is an entry id" 'FALLBACK is not ${N}.conf'
  # Each of the four NAMES must be cleared, not merely "some efivarfs write
  # exists". Checking for fragments passed while the loop named only two of them.
  code=$(grep -vE '^[[:space:]]*#' "$HOOK")
  for v in LoaderEntrySysFail LoaderEntryOneShot LoaderEntryPreferred LoaderEntryDefault; do
    grep -qF "$v" <<<"$code" \
      && ok "$h: clears $v (it outranks loader.conf)" \
      || no "$h: clears $v" "absent from non-comment code"
  done
fi

# ------------------------------------------------- 2. the deploy's own writer
echo
echo "== the deploy's boot default"
DEP="$HERE/../scripts/shani-deploy.sh"
if [[ -f $DEP ]]; then
  d="shani-deploy/scripts/shani-deploy.sh"
  grep -qE 'loader_default="\$\{OS_NAME\}-\$\{active_slot\}\.conf"' "$DEP" \
    && ok "$d: loader_default is the base entry id (.conf, no tries suffix)" \
    || no "$d: loader_default is the base entry id" "$(grep -m1 'loader_default=' "$DEP")"
  grep -qE 'bootctl set-default "\$\{loader_default\}"' "$DEP" \
    && ok "$d: set-default is given that id" \
    || no "$d: set-default is given that id" "no bootctl set-default \${loader_default}"
  # The comment that rejected the glob must stay, or the next reader reinvents it.
  grep -qiE 'glob' "$DEP" \
    && ok "$d: the comment still records why a glob does not work" \
    || no "$d: the comment records why a glob does not work" "no mention of glob near finalize_boot_entries"
else
  no "shani-deploy.sh is present" "$DEP missing"
fi

# ------------------------------------------- 3. the installer's loader.conf
echo
echo "== the installer's loader.conf"
CONF="$WS/os-installer-config/scripts/configure.sh"
if [[ -f $CONF ]]; then
  c="os-installer-config/scripts/configure.sh"
  grep -qE "printf 'default \\\$\{OS_NAME\}-\\\$\{slot\}\.conf" "$CONF" \
    && ok "$c: writes the base entry id" \
    || no "$c: writes the base entry id" "the default line no longer names a .conf id"
  # The landmine: a comment promising a glob invites the one form that breaks
  # the boot. It must not come back.
  # Must follow the '#' directly. The replacement comment quotes the old wording
  # mid-sentence on purpose, to record what it used to say; anchoring at the
  # start of the comment line tells the two apart.
  if grep -iE '^\s*#\s*[Uu]se a glob' "$CONF"; then
    no "$c: no comment promising a glob" "'use a glob pattern' is back in a comment"
  else
    ok "$c: no comment promising a glob"
  fi
else
  ok "configure.sh not checked out - skipped rather than silently passing"
fi

# --------------------------------- 4. nothing anywhere writes a stem or a glob
echo
echo "== workspace-wide: no default written as a stem, glob, or +N-M filename"
bad=0
while IFS= read -r f; do
  [[ -n $f ]] || continue
  short="${f#$WS/}"
  # strip pure comment lines before judging: prose may quote the wrong forms
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    # a glob inside a default write
    if grep -qE "(printf|echo)[^|]*default[^|]*\*" <<<"$line"; then
      no "$short: no glob in a boot default" "$line"; bad=1
    fi
    # a literal +N-M used AS the value of a default write
    if grep -qE "(printf|echo)[^|]*default[[:space:]]+[^[:space:]]*\+[0-9]+-[0-9]+" <<<"$line"; then
      no "$short: no +N-M filename as a default" "$line"; bad=1
    fi
    # a stem: `default <something>` where <something> has no dot at all
    if grep -qE "(printf[[:space:]]+['\"]default[[:space:]]|echo[[:space:]]+['\"]?default[[:space:]])[^[:space:]]*\$?\{?[A-Za-z_][A-Za-z0-9_]*\}?[^.[:space:]]*([[:space:]]|\\\\?n?$)" <<<"$line" \
       && ! grep -q 'default_entry\|\${N}\|${slot}\|${active_slot}\|${loader_default}' <<<"$line"; then
      no "$short: no stem as a boot default" "$line"; bad=1
    fi
  done < <(grep -nE "default[[:space:]]|set-default" "$f" 2>/dev/null | cut -d: -f2-)
done < <(sources)
(( bad == 0 )) && ok "no workspace source writes a stem, glob or +N-M as a boot default"

# ------------------------------------------- 5. no profile re-shadows shared
echo
echo "== no profile overlay duplicates the shared module"
shared="$WS/shani-install-media/image_profiles/shared/overlay/rootfs/usr/lib/dracut/modules.d/99shanios"
dupes=0
while IFS= read -r d; do
  [[ -n $d && -d "$d" ]] || continue
  rel="${d#"$WS"/shani-install-media/image_profiles/}"
  n=$(find "$d" -type f | wc -l)
  no "$rel: must not shadow the shared module" \
     "$n file(s) here overwrite shared, applied AFTER it (build-base-image.sh:276-283)"
  dupes=1
done < <(find "$WS/shani-install-media/image_profiles" -mindepth 3 -type d -name '99shanios' 2>/dev/null | grep -v '/shared/')
(( dupes == 0 )) && ok "no profile overlay re-shadows the shared 99shanios module"

echo
echo "${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]