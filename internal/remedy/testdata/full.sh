#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk lockout_risk
# planned 7 (script 4, text only 3); above max-risk 0; not planned: error 1, manual 1, warn_degraded 1
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
    { [ -e "$p" ] || [ -L "$p" ]; } || continue
    if [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
    mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p" || return 1
  done
}
restore() {
  brc=0
  for p in "$@"; do
    { [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; brc=1; continue; }; fi
    cp -a "$MUSTER_BACKUP$p" "$p" || { log "restore: $p failed"; brc=1; }
  done
  return $brc
}
save_units() {
  mkdir -p "$MUSTER_BACKUP/muster-units" || return 1
  for u in "$@"; do
    f="$MUSTER_BACKUP/muster-units/$u"
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
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    [ "$ue" = absent ] || systemctl --quiet unmask -- "$u" || urc=1
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      enabled) systemctl --quiet enable -- "$u" || urc=1;;
      enabled-runtime) systemctl --quiet enable --runtime -- "$u" || urc=1;;
      linked|linked-runtime) log "$u: was $ue; the link is not restored"; urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      disabled) now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
        case "$now" in
          enabled) systemctl --quiet disable -- "$u" || urc=1;;
          enabled-runtime) systemctl --quiet disable --runtime -- "$u" || urc=1;;
        esac;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      masked) systemctl --quiet mask -- "$u" || urc=1;;
      masked-runtime) systemctl --quiet mask --runtime -- "$u" || urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in masked|masked-runtime) continue;; esac
    case "$ua" in active|activating|reloading) systemctl --quiet start -- "$u" || urc=1;; esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u.deps" ] || continue
    while read -r d; do
      systemctl is-active --quiet -- "$d" || systemctl --quiet start -- "$d" || urc=1
    done < "$MUSTER_BACKUP/muster-units/$u.deps"
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    [ "$ue" = absent ] && continue
    now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
    [ "${now:-unknown}" = "$ue" ] || { log "$u: enablement not restored (was $ue, now ${now:-unknown})"; urc=1; }
  done
  return $urc
}
failed=0

# ---- 1/7 muster.test.e_param [risk none] [fail, high]
# why: mode 777
# do:  fix e
# ko:  조치 e
# text only: params tuned, see muster check --format json: check.param_sources

# ---- 2/7 muster.test.f_partial [risk none] [warn, high]
# why: observations need human review
# do:  fix f
# ko:  조치 f
# text only: no script declared

# ---- 3/7 muster.test.a_none [risk none] [fail, low]
# why: clause does not hold: files.etc_hosts.mode in [0 420]
# do:  fix a
# ko:  조치 a
fix_muster_test_a_none() {
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

# ---- 4/7 muster.test.b_restart [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  fix b <a & b>
# ko:  조치 b
fix_muster_test_b_restart() {
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

# ---- 5/7 muster.test.g_units [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  t
# ko:  조치
fix_muster_test_g_units() {
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

# ---- 6/7 muster.test.d_reboot [risk reboot_required] [fail, high]
# why: clause does not hold
# do:  fix d
# ko:  조치 d
# text only: no script declared

# ---- 7/7 muster.test.c_lockout [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  fix c
# ko:  조치 c
fix_muster_test_c_lockout() {
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
