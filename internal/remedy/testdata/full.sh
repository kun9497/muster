#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk lockout_risk
# planned 9 (script 6, text only 3); above max-risk 0; not planned: error 1, manual 1, warn_degraded 1
set -u
umask 077
log() { printf 'muster-fix: %s\n' "$*"; }
muster_machine_id_hash() {
  id=$( { tr -d '[:space:]' < "$1"; } 2>/dev/null ) || id=
  case "$id" in *[!0-9a-f]*|'') return 0;; esac
  [ "${#id}" -eq 32 ] || return 0
  { printf '%s' "$id" | sha256sum | cut -d' ' -f1; } 2>/dev/null
}
[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }
MUSTER_SNAPSHOT_HOST=3eb1bd439947eb762998e566ccc2e099c791118b2f40579cc4f7da2b5061b7f9
here=$(muster_machine_id_hash /etc/machine-id)
if [ "$here" != "$MUSTER_SNAPSHOT_HOST" ]; then
  if [ "${MUSTER_ANY_HOST:-}" = 1 ]; then
    log "warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1"
  else
    printf 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n' >&2
    exit 2
  fi
fi
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

# ---- 1/9 muster.test.e_param [risk none] [fail, high]
# why: mode 777
# do:  fix e
# ko:  조치 e
# text only: params tuned, see muster check --format json: check.param_sources

# ---- 2/9 muster.test.f_partial [risk none] [warn, high]
# why: observations need human review
# do:  fix f
# ko:  조치 f
# text only: no script declared

# ---- 3/9 muster.test.h_params [risk none] [fail, medium]
# why: clause does not hold
# do:  fix h
# ko:  조치 h
fix_muster_test_h_params() {
  P_limit='5'
  P_names='a b'
  MB="$MUSTER_BACKUP/blocks/fix_muster_test_h_params"; mkdir -p "$MB" || { log "muster.test.h_params: backup failed, nothing changed"; return 1; }
  backup /etc/h.conf || { log "muster.test.h_params: backup failed, nothing changed"; return 1; }
  ( set -e
    for n in $P_names; do printf '%s %s\n' "$n" "$P_limit" >> /etc/h.conf; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.h_params: script failed (rc $rc), rolling back"
    restore /etc/h.conf || log "muster.test.h_params: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    [ "$P_limit" -ge 1 ]
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.h_params: validate failed, rolling back"
    restore /etc/h.conf || log "muster.test.h_params: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.test.h_params: done"
}
fix_muster_test_h_params
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 4/9 muster.test.i_state [risk none] [fail, medium]
# why: clause does not hold
# do:  fix i
# ko:  조치 i
fix_muster_test_i_state() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_test_i_state"; mkdir -p "$MB" || { log "muster.test.i_state: backup failed, nothing changed"; return 1; }
  save_modes '/etc/i.d/*' '/etc/i.conf' || { log "muster.test.i_state: backup failed, nothing changed"; return 1; }
  save_sysctl kernel.i_key || { log "muster.test.i_state: backup failed, nothing changed"; return 1; }
  save_modules i-mod || { log "muster.test.i_state: backup failed, nothing changed"; return 1; }
  ( set -e
    chmod o-w /etc/i.conf
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.i_state: script failed (rc $rc), rolling back"
    restore_modes || log "muster.test.i_state: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.i_key || log "muster.test.i_state: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules i-mod || log "muster.test.i_state: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    true
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.i_state: validate failed, rolling back"
    restore_modes || log "muster.test.i_state: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.i_key || log "muster.test.i_state: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules i-mod || log "muster.test.i_state: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.test.i_state: done"
}
fix_muster_test_i_state
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 5/9 muster.test.a_none [risk none] [fail, low]
# why: clause does not hold: files.etc_hosts.mode in [0 420]
# do:  fix a
# ko:  조치 a
fix_muster_test_a_none() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_test_a_none"; mkdir -p "$MB" || { log "muster.test.a_none: backup failed, nothing changed"; return 1; }
  backup /etc/hosts || { log "muster.test.a_none: backup failed, nothing changed"; return 1; }
  ( set -e
    chmod 644 /etc/hosts
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.a_none: script failed (rc $rc), rolling back"
    restore /etc/hosts || log "muster.test.a_none: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.test.a_none: done"
}
fix_muster_test_a_none
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 6/9 muster.test.b_restart [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  fix b <a & b>
# ko:  조치 b
fix_muster_test_b_restart() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_test_b_restart"; mkdir -p "$MB" || { log "muster.test.b_restart: backup failed, nothing changed"; return 1; }
  ( set -e
    systemctl restart foo
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.b_restart: script failed (rc $rc), rolling back"
    ( set -e
      systemctl restart foo
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.test.b_restart: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.test.b_restart: done"
}
fix_muster_test_b_restart
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 7/9 muster.test.g_units [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  t
# ko:  조치
fix_muster_test_g_units() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_test_g_units"; mkdir -p "$MB" || { log "muster.test.g_units: backup failed, nothing changed"; return 1; }
  save_units g.socket g.service || { log "muster.test.g_units: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='g.socket g.service'
    for u in $UNITS; do systemctl --quiet disable --now "$u"; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.g_units: script failed (rc $rc), rolling back"
    restore_units g.socket g.service || log "muster.test.g_units: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet g.service
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.g_units: validate failed, rolling back"
    restore_units g.socket g.service || log "muster.test.g_units: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.test.g_units: done"
}
fix_muster_test_g_units
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 8/9 muster.test.d_reboot [risk reboot_required] [fail, high]
# why: clause does not hold
# do:  fix d
# ko:  조치 d
# text only: no script declared

# ---- 9/9 muster.test.c_lockout [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  fix c
# ko:  조치 c
fix_muster_test_c_lockout() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_test_c_lockout"; mkdir -p "$MB" || { log "muster.test.c_lockout: backup failed, nothing changed"; return 1; }
  backup /etc/ssh/sshd_config || { log "muster.test.c_lockout: backup failed, nothing changed"; return 1; }
  ( set -e
    sed -i s/a/b/ /etc/ssh/sshd_config
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.c_lockout: script failed (rc $rc), rolling back"
    ( set -e
      systemctl reload ssh
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.test.c_lockout: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config || log "muster.test.c_lockout: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    sshd -t
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.c_lockout: validate failed, rolling back"
    ( set -e
      systemctl reload ssh
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.test.c_lockout: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config || log "muster.test.c_lockout: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.test.c_lockout: done"
}
fix_muster_test_c_lockout
[ "$?" -eq 0 ] || failed=$((failed+1))

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
