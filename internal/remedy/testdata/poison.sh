#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host\x1b[31m\n# $(id) `id`, collected 2026\x1b[31m\n# $(id) `id`; controls v\x1b[31m\n# $(id) `id` d\x1b[31m\n# $(id) `id`
# profile p\x1b[31m\n# $(id) `id` (pd\x1b[31m\n# $(id) `id`); max-risk lockout_risk
# planned 2 (script 1, text only 1); above max-risk 0; not planned: error 0, manual 0, warn_degraded 0
set -u
umask 077
[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }
MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
case "$MUSTER_BACKUP" in
  /|//*|*/.|*/..|*/./*|*/../*) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
  /?*) ;;
  *) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
esac
mkdir -p "$MUSTER_BACKUP" || exit 2
log() { printf 'muster-fix: %s\n' "$*"; }
backup() {
  for p in "$@"; do
    { [ -e "$p" ] || [ -L "$p" ]; } || continue
    if [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
    mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p" || return 1
  done
}
restore() {
  rc=0
  for p in "$@"; do
    { [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; rc=1; continue; fi
    cp -a "$MUSTER_BACKUP$p" "$p" || { log "restore: $p failed"; rc=1; }
  done
  return $rc
}
failed=0

# ---- 1/2 muster.test.p_text [risk none] [fail, high]
# why: value \x1b[31m\n# $(id) `id`
# do:  text \x1b]0;x\u0007\n$(id)
# ko:  글 \n# $(id)
# text only: no script declared

# ---- 2/2 muster.test.p_script [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: value \x1b[31m\n# $(id) `id`
# do:  do \x1b[31m\n# $(id) `id`
# ko:  조치 \x1b[31m\n# $(id)
fix_muster_test_p_script() {
  backup /etc/hosts || { log "muster.test.p_script: backup failed, nothing changed"; return 1; }
  ( set -e
    chmod 644 /etc/hosts
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.p_script: script failed (rc $rc), rolling back"
    ( set -e
      systemctl reload ssh
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.test.p_script: rollback failed (rc $rrc)"
    restore /etc/hosts || log "muster.test.p_script: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%a' /etc/hosts
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.test.p_script: validate failed, rolling back"
    ( set -e
      systemctl reload ssh
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.test.p_script: rollback failed (rc $rrc)"
    restore /etc/hosts || log "muster.test.p_script: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.test.p_script: done"
}
fix_muster_test_p_script
[ "$?" -eq 0 ] || failed=$((failed+1))

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
