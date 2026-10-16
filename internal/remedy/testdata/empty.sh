#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk lockout_risk
# planned 0 (script 0, text only 0); above max-risk 0; not planned: error 0, manual 0, warn_degraded 0
set -u
umask 077
log() { printf 'muster-fix: %s\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }
# host guard: off (the snapshot has no machine id)
MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
case "$MUSTER_BACKUP" in
  /|//*|*/.|*/..|*/./*|*/../*) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
  /?*) ;;
  *) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
esac
mkdir -p "$MUSTER_BACKUP" || exit 2
[ -n "$(find "$MUSTER_BACKUP" -maxdepth 0 -type d -user 0 ! -perm /022 2>/dev/null)" ] || { printf 'muster-fix: MUSTER_BACKUP must be a root-owned directory that only root can write\n' >&2; exit 2; }
backup() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      if [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
      rm -f "$MB/absent$p"
      mkdir -p "$MB/files$(dirname "$p")" && cp -a "$p" "$MB/files$p" || return 1
    else
      if [ -e "$MB/absent$p" ] || [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then continue; fi
      mkdir -p "$MB/absent$(dirname "$p")" && : > "$MB/absent$p" || return 1
    fi
  done
}
restore() {
  brc=0
  for p in "$@"; do
    if [ -e "$MB/absent$p" ]; then
      if [ -d "$p" ] && [ ! -L "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
      rm -f "$p" || { log "restore: $p failed"; brc=1; }
      continue
    fi
    { [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; brc=1; continue; }; fi
    cp -a "$MB/files$p" "$p" || { log "restore: $p failed"; brc=1; }
  done
  return $brc
}
save_units() {
  mkdir -p "$MB/units" || return 1
  for u in "$@"; do
    f="$MB/units/$u"
    if [ -f "$f" ] && ! grep -qx 'absent absent' "$f"; then log "$u: unit state exists, keeping the first"; continue; fi
    if systemctl cat -- "$u" >/dev/null 2>&1; then
      ue=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
      ua=$(systemctl is-active -- "$u" 2>/dev/null) || :
      printf '%s %s\n' "${ue:-unknown}" "${ua:-unknown}" > "$f" || return 1
      : > "$f.deps" || return 1
      for d in $(systemctl show -p RequiredBy -p BoundBy -p ConsistsOf --value -- "$u" 2>/dev/null); do
        if systemctl is-active --quiet -- "$d"; then printf '%s\n' "$d" >> "$f.deps" || return 1; fi
      done
    else
      printf 'absent absent\n' > "$f" || return 1
    fi
  done
}
restore_units() {
  urc=0
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    [ "$ue" = absent ] || systemctl --quiet unmask -- "$u" || urc=1
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in
      enabled) systemctl --quiet enable -- "$u" || urc=1;;
      enabled-runtime) systemctl --quiet enable --runtime -- "$u" || urc=1;;
      linked|linked-runtime) log "$u: was $ue; the link is not restored"; urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in
      disabled) now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
        case "$now" in
          enabled) systemctl --quiet disable -- "$u" || urc=1;;
          enabled-runtime) systemctl --quiet disable --runtime -- "$u" || urc=1;;
        esac;;
    esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in
      masked) systemctl --quiet mask -- "$u" || urc=1;;
      masked-runtime) systemctl --quiet mask --runtime -- "$u" || urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    case "$ue" in masked|masked-runtime) continue;; esac
    case "$ua" in active|activating|reloading) systemctl --quiet start -- "$u" || urc=1;; esac
  done
  for u in "$@"; do
    [ -f "$MB/units/$u.deps" ] || continue
    while read -r d; do
      systemctl is-active --quiet -- "$d" || systemctl --quiet start -- "$d" || urc=1
    done < "$MB/units/$u.deps"
  done
  for u in "$@"; do
    [ -f "$MB/units/$u" ] || continue
    read -r ue ua < "$MB/units/$u"
    [ "$ue" = absent ] && continue
    now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
    [ "${now:-unknown}" = "$ue" ] || { log "$u: enablement not restored (was $ue, now ${now:-unknown})"; urc=1; }
  done
  return $urc
}
modes_paths() { # one path per line for one entry
  case "$1" in
    */\*/\*) find "${1%/\*/\*}" -mindepth 2 -maxdepth 2 ! -type l 2>/dev/null;;
    */\*) find "${1%/\*}" -mindepth 1 -maxdepth 1 ! -type l 2>/dev/null;;
    *) if [ -e "$1" ] && [ ! -L "$1" ]; then printf '%s\n' "$1"; fi;;
  esac
  return 0
}
modes_type() { if [ -f "$1" ]; then echo f; elif [ -d "$1" ]; then echo d; else echo o; fi; }
save_modes() {
  [ -f "$MB/modes.list" ] || : > "$MB/modes.list" || return 1
  for spec in "$@"; do
    modes_paths "$spec" | while IFS= read -r p; do
      P="$p" awk '{ q=$0; sub(/^[^ ]+ [^ ]+ [^ ]+ [^ ]+ /, "", q); if (q == ENVIRON["P"]) f=1 } END { exit !f }' "$MB/modes.list" && continue
      if s=$(stat -c '%u %g %a' -- "$p" 2>/dev/null); then
        printf '%s %s %s\n' "$s" "$(modes_type "$p")" "$p" >> "$MB/modes.list" || exit 1
      elif [ -e "$p" ]; then
        exit 1
      else
        log "save_modes: $p vanished, not recorded"
      fi
    done || return 1
  done
}
restore_modes() {
  mrc=0
  while read -r uid gid mode t p; do
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then continue; fi
    if [ -L "$p" ] || [ "$(modes_type "$p")" != "$t" ]; then log "restore_modes: $p changed type, left as is"; mrc=1; continue; fi
    cur=$(stat -c '%u %g %a' -- "$p" 2>/dev/null) || cur=
    [ "$cur" = "$uid $gid $mode" ] && continue
    modes_trusted "$p" "$uid" || { log "restore_modes: $p is under a directory others can write, left as is"; mrc=1; continue; }
    if [ "${cur% *}" != "$uid $gid" ]; then chown -h -- "$uid:$gid" "$p" || { mrc=1; continue; }; fi # a chown drops security.capability
    chmod -- "$mode" "$p" || mrc=1
  done < "$MB/modes.list"
  return $mrc
}
modes_trusted() { # modes_trusted <path> <recorded uid>: no one but root can swap <path> (S-24)
  d=${1%/*}
  if [ "$2" != 0 ] && [ -n "$(find "${d:-/}" -maxdepth 0 -perm /022 2>/dev/null)" ]; then return 1; fi
  while :; do
    [ -n "$(find "${d:-/}" -maxdepth 0 -user 0 ! -perm -002 2>/dev/null)" ] || return 1
    [ -n "$d" ] || return 0
    d=${d%/*}
  done
}
save_sysctl() {
  [ -f "$MB/sysctl.list" ] || : > "$MB/sysctl.list" || return 1
  for k in "$@"; do
    awk -v k="$k" '$1 == k { f=1 } END { exit !f }' "$MB/sysctl.list" && continue
    v=$(sysctl -n -- "$k" 2>/dev/null) || v=absent
    printf '%s %s\n' "$k" "$v" >> "$MB/sysctl.list" || return 1
  done
}
restore_sysctl() {
  src=0
  for k in "$@"; do
    v=$(awk -v k="$k" '$1 == k { $1=""; sub(/^ /, ""); print; exit }' "$MB/sysctl.list")
    case "$v" in ''|absent) continue;; esac
    sysctl -q -w -- "$k=$v" || src=1
  done
  return $src
}
save_modules() {
  [ -f "$MB/modules.list" ] || : > "$MB/modules.list" || return 1
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    awk -v m="$n" '$1 == m { f=1 } END { exit !f }' "$MB/modules.list" && continue
    if grep -q "^$n " /proc/modules; then s=loaded; else s=not-loaded; fi
    printf '%s %s\n' "$n" "$s" >> "$MB/modules.list" || return 1
  done
}
restore_modules() {
  orc=0
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    [ "$(awk -v m="$n" '$1 == m { print $2; exit }' "$MB/modules.list")" = loaded ] || continue
    modprobe --ignore-install -- "$n" || orc=1
  done
  return $orc
}
failed=0

# nothing to fix

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
