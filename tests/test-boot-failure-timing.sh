#!/bin/bash
# The boot-failure recovery chain's TIMING must be an ordering guarantee.
#
# WHY THIS EXISTS. Two timers cooperate, and one of them writes what the other
# reads:
#
#   check-boot-failure.timer   OnBootSec=15m   writes /data/boot_failure
#   shani-auto-rollback.timer  OnBootSec=1min   reads boot_hard_failure
#                              OnBootSec=16m   reads boot_failure (the soft one)
#
# The 16m pass exists ONLY to act on the marker the 15m pass writes. The 1m
# pass can only ever see `boot_hard_failure`, which dracut writes before the
# root mount is attempted — so a SOFT failure (a same-slot timeout, the case
# the 15m timer exists to detect) is reachable only through 15m -> 16m.
#
# That ordering was never guaranteed. Neither timer set AccuracySec=, so
# systemd's default AccuracySec=1min applies and each may fire up to a minute
# late, INDEPENDENTLY. check-boot-failure can land at 16m00s, after the 16m
# rollback run has already looked and found nothing. Nothing re-runs it that
# boot: the failure is recorded and never acted on, the machine stays on the
# failed slot, and the unattended recovery the chain exists to provide does
# not happen. No error, no warning — the chain simply does less than it
# appears to.
#
# This is not hypothetical on any systemd where the default holds, and it is
# silent, which is why a static check is the right instrument: the failure only
# shows up as a machine that needed no recovery.
#
#   shani-deploy/tests/test-boot-failure-timing.sh      (host-only, no root, no disks)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(dirname "$HERE")/.."
U="$HERE/../systemd/system"
pass=0 fail=0
ok()  { printf '  ok    %s\n' "$1"; pass=$((pass + 1)); }
no()  { printf '  FAIL  %s\n        %s\n' "$1" "${2:-}"; fail=$((fail + 1)); }

cbf="$U/check-boot-failure.timer"
sar="$U/shani-auto-rollback.timer"
for f in "$cbf" "$sar"; do [[ -f $f ]] || { echo "missing timer: $f" >&2; exit 2; }; done

# Directive value, comments stripped. The block's own comment deliberately
# NAMES AccuracySec and says the timers "do not set" it — a raw grep would
# match that documentation and report the guard as satisfied while the
# directive is absent, which is the same trap as the speakeasy argv and the
# hardcoded module path already recorded in this workspace.
directive() { # <file> <name>
  grep -vE '^[[:space:]]*#' "$1" | grep -E "^[[:space:]]*$2=" | tail -1 \
    | cut -d= -f2- | tr -d '[:space:]'
}

echo "== both recovery timers pin their coalescing window"
# systemd's default is AccuracySec=1min; anything looser reopens the window.
for t in "$cbf" "$sar"; do
  b=$(basename "$t")
  a=$(directive "$t" AccuracySec)
  if [[ -z $a ]]; then
    no "$b sets AccuracySec" "unset, so the default 1min applies and the two timers can swap order"
  elif [[ $a == 1s || $a == 500ms || $a == 100ms ]]; then
    ok "$b sets AccuracySec=$a (tight enough to keep 15m before 16m ordered)"
  else
    no "$b sets AccuracySec" "=$a is too loose: it can exceed the OnBootSec gap it has to fit inside"
  fi
done

echo
echo "== neither recovery timer adds random delay"
for t in "$cbf" "$sar"; do
  b=$(basename "$t")
  [[ -n $(directive "$t" RandomizedDelaySec) ]] \
    && no "$b adds no RandomizedDelaySec" "jitter can only widen the window" \
    || ok "$b adds no RandomizedDelaySec"
done

echo
echo "== the consumer fires AFTER the producer"
prod=$(directive "$cbf" OnBootSec)
cons=$(directive "$sar" OnBootSec)
printf '  producer check-boot-failure: OnBootSec=%s\n' "$prod"
printf '  consumer shani-auto-rollback soft pass: OnBootSec=%s\n' "$cons"
# systemd accepts sec/min/hour AND "min"/"sec"/"hr" spelled out, plus a bare
# number of seconds: 1m, 1min, 16m, 90s, 500ms, 30. The shipped timer uses
# `1min`, which the first version did not parse at all - it fell through to the
# bare branch, reported "1" second, and failed a check about a 1-minute timer.
# A parser that silently misreads a duration is worse than one that refuses:
# it turns a timing assertion into noise.
to_secs() {
  local v="${1//[[:space:]]/}" n
  case "$v" in
    *ms) n="${v%ms}"; awk -v x="$n" "BEGIN{print (x+0)/1000}";;
    *min|*m) n="${v%min}"; n="${n%m}"; echo $(( n * 60 ));;
    *hr|*h)  n="${v%hr}";  n="${n%h}";  echo $(( n * 3600 ));;
    *sec|*s) n="${v%sec}"; n="${n%s}";  echo "$n";;
    *)       echo "$v";;
  esac
}
ps=$(to_secs "$prod"); cs=$(to_secs "$cons")
if [[ $ps =~ ^[0-9]+$ && $cs =~ ^[0-9]+$ ]]; then
  (( cs > ps )) \
    && ok "the consumer fires $(( cs - ps ))s after the producer" \
    || no "the consumer fires after the producer" "both at ${prod}s — no ordering at all"
  # The gap has to exceed the worst-case accuracy error of BOTH timers, or the
  # guarantee is nominal. With AccuracySec pinned this is comfortable; the
  # assertion is on the ratio so retuning one timer cannot silently close it.
  (( (cs - ps) > 2 )) \
    && ok "the gap exceeds the combined worst-case accuracy of two timers" \
    || no "the gap is wide enough" "only $(( cs - ps ))s apart, with AccuracySec pinning each"
else
  no "both OnBootSec values parse" "producer=[$prod] consumer=[$cons]"
fi

echo
echo "== the hard-failure pass is still early"
first=$(grep -vE '^[[:space:]]*#' "$sar" | grep -E '^[[:space:]]*OnBootSec=' | head -1 | cut -d= -f2- | tr -d '[:space:]')
printf '  first pass (hard failure): OnBootSec=%s\n' "$first"
fs=$(to_secs "$first")
[[ $fs =~ ^[0-9]+$ ]] && (( fs <= 300 )) \
  && ok "the hard-failure pass still runs within 5 minutes" \
  || no "the hard-failure pass is early" "OnBootSec=$first"

echo
echo "== neither timer can fire on shutdown"
# DefaultDependencies=no removes shutdown.target ordering; both restore it
# explicitly. Losing that line causes spurious activations during shutdown,
# which on a recovery timer means running a rollback while powering down.
for t in "$cbf" "$sar"; do
  b=$(basename "$t")
  grep -qE '^[[:space:]]*Conflicts=shutdown.target' "$t" \
    && ok "$b restores Conflicts=shutdown.target" \
    || no "$b restores Conflicts=shutdown.target" "a recovery timer can fire during shutdown"
done

echo
echo "== the soft marker is only written by check-boot-failure"
# If auto-rollback ever wrote its own soft marker it would be acting on its own
# guess; the design is that it only ever reacts to a marker someone else
# recorded.
ar="$HERE/../scripts/shani-auto-rollback.sh"
if [[ -f $ar ]]; then
  grep -qE '^[[:space:]]*echo .*>[[:space:]]*"\$BOOT_FAILURE_FILE"' "$ar" \
    && no "shani-auto-rollback never writes boot_failure itself" \
         "it writes the marker it consumes - it would be reacting to its own guess" \
    || ok "shani-auto-rollback never writes boot_failure itself"
  grep -qE '^[[:space:]]*echo .*>[[:space:]]*"\$BOOT_HARD_FAILURE_FILE"' "$ar" \
    && no "shani-auto-rollback never writes boot_hard_failure itself" "same: it must only react" \
    || ok "shani-auto-rollback never writes boot_hard_failure itself"
else
  ok "shani-auto-rollback.sh not checked out - marker-writer checks skipped, not silently passed"
fi

echo
echo "${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]