#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk none
# planned 2 (script 1, text only 1); above max-risk 3; not planned: error 0, manual 0, warn_degraded 0
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
        case "$now" in enabled|enabled-runtime) systemctl --quiet disable -- "$u" || urc=1;; esac;;
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

# ---- 1/5 muster.test.e_param [risk none] [fail, high]
# why: absent counts as fail: no /etc/group
# do:  fix e
# ko:  조치 e
# text only: the finding is an absent file

# ---- 2/5 muster.test.a_none [risk none] [fail, low]
# why: clause does not hold
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

# ---- 3/5 muster.test.b_restart [risk restart_service] [fail, medium] -- above max-risk none, NOT RUN
# why: clause does not hold
# do:  fix b <a & b>
# ko:  조치 b
# fix_muster_test_b_restart() {
#   ( set -e
#     systemctl restart foo
#   ); rc=$?
#   if [ "$rc" -ne 0 ]; then
#     log "muster.test.b_restart: script failed (rc $rc), rolling back"
#     ( set -e
#       systemctl restart foo
#     ); rrc=$?
#     [ "$rrc" -eq 0 ] || log "muster.test.b_restart: rollback failed (rc $rrc)"
#     return 1
#   fi
#   log "muster.test.b_restart: done"
# }
# fix_muster_test_b_restart
# [ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 4/5 muster.test.d_reboot [risk reboot_required] [fail, high] -- above max-risk none, NOT RUN
# why: clause does not hold
# do:  fix d
# ko:  조치 d
# text only: no script declared

# ---- 5/5 muster.test.c_lockout [risk lockout_risk] [fail, high] -- above max-risk none, NOT RUN
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  fix c
# ko:  조치 c
# fix_muster_test_c_lockout() {
#   backup /etc/ssh/sshd_config || { log "muster.test.c_lockout: backup failed, nothing changed"; return 1; }
#   ( set -e
#     sed -i s/a/b/ /etc/ssh/sshd_config
#   ); rc=$?
#   if [ "$rc" -ne 0 ]; then
#     log "muster.test.c_lockout: script failed (rc $rc), rolling back"
#     ( set -e
#       systemctl reload ssh
#     ); rrc=$?
#     [ "$rrc" -eq 0 ] || log "muster.test.c_lockout: rollback failed (rc $rrc)"
#     restore /etc/ssh/sshd_config || log "muster.test.c_lockout: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
#     return 1
#   fi
#   # validate
#   ( set -e
#     sshd -t
#   ); rc=$?
#   if [ "$rc" -ne 0 ]; then
#     log "muster.test.c_lockout: validate failed, rolling back"
#     ( set -e
#       systemctl reload ssh
#     ); rrc=$?
#     [ "$rrc" -eq 0 ] || log "muster.test.c_lockout: rollback failed (rc $rrc)"
#     restore /etc/ssh/sshd_config || log "muster.test.c_lockout: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
#     return 1
#   fi
#   log "muster.test.c_lockout: done"
# }
# fix_muster_test_c_lockout
# [ "$?" -eq 0 ] || failed=$((failed+1))

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
