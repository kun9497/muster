#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk lockout_risk
# planned 16 (script 16, text only 0); above max-risk 0; not planned: error 0, manual 0, warn_degraded 0
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

# ---- 1/16 muster.file.hosts_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
# ko:  chown root:root /etc/hosts; chmod 600 /etc/hosts
fix_muster_file_hosts_permissions() {
  backup /etc/hosts || { log "muster.file.hosts_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/hosts ]
    chown root:root /etc/hosts
    chmod 600 /etc/hosts
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_permissions: script failed (rc $rc), rolling back"
    restore /etc/hosts || log "muster.file.hosts_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%u %g %a' /etc/hosts | grep -qx '0 0 600'
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_permissions: validate failed, rolling back"
    restore /etc/hosts || log "muster.file.hosts_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.hosts_permissions: done"
}
fix_muster_file_hosts_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 2/16 muster.file.passwd_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chown root:root /etc/passwd; chmod 644 /etc/passwd; setfacl -b /etc/passwd
# ko:  chown root:root /etc/passwd; chmod 644 /etc/passwd; setfacl -b /etc/passwd
fix_muster_file_passwd_permissions() {
  backup /etc/passwd || { log "muster.file.passwd_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/passwd ]
    chown root:root /etc/passwd
    chmod 644 /etc/passwd
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/passwd; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.passwd_permissions: script failed (rc $rc), rolling back"
    restore /etc/passwd || log "muster.file.passwd_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%u %g %a' /etc/passwd | grep -qx '0 0 644'
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.passwd_permissions: validate failed, rolling back"
    restore /etc/passwd || log "muster.file.passwd_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.passwd_permissions: done"
}
fix_muster_file_passwd_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 3/16 muster.file.services_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chown root:root /etc/services; chmod 644 /etc/services
# ko:  chown root:root /etc/services; chmod 644 /etc/services
fix_muster_file_services_permissions() {
  backup /etc/services || { log "muster.file.services_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/services ]
    chown root:root /etc/services
    chmod 644 /etc/services
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.services_permissions: script failed (rc $rc), rolling back"
    restore /etc/services || log "muster.file.services_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%u %g %a' /etc/services | grep -qx '0 0 644'
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.services_permissions: validate failed, rolling back"
    restore /etc/services || log "muster.file.services_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.services_permissions: done"
}
fix_muster_file_services_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 4/16 muster.file.shadow_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow. On Debian and Ubuntu unix_chkpwd reads /etc/shadow through group shadow; a site that keeps 0640 relaxes allowed_modes, and the plan then leaves the script out.
# ko:  chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow. Debian과 Ubuntu에서는 unix_chkpwd가 shadow 그룹으로 /etc/shadow를 읽으므로, 0640을 유지하는 사이트는 allowed_modes를 완화하고 그러면 계획이 스크립트를 뺍니다.
fix_muster_file_shadow_permissions() {
  backup /etc/shadow || { log "muster.file.shadow_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/shadow ]
    chown root /etc/shadow
    chmod 400 /etc/shadow
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/shadow; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.shadow_permissions: script failed (rc $rc), rolling back"
    restore /etc/shadow || log "muster.file.shadow_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%u %a' /etc/shadow | grep -qx '0 400'
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.shadow_permissions: validate failed, rolling back"
    restore /etc/shadow || log "muster.file.shadow_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.shadow_permissions: done"
}
fix_muster_file_shadow_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 5/16 muster.file.hosts_lpd_permissions [risk none] [fail, low]
# why: clause does not hold
# do:  chown root:root /etc/hosts.lpd; chmod 600 /etc/hosts.lpd
# ko:  chown root:root /etc/hosts.lpd; chmod 600 /etc/hosts.lpd
fix_muster_file_hosts_lpd_permissions() {
  backup /etc/hosts.lpd || { log "muster.file.hosts_lpd_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/hosts.lpd ]
    chown root:root /etc/hosts.lpd
    chmod 600 /etc/hosts.lpd
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_lpd_permissions: script failed (rc $rc), rolling back"
    restore /etc/hosts.lpd || log "muster.file.hosts_lpd_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%u %g %a' /etc/hosts.lpd | grep -qx '0 0 600'
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_lpd_permissions: validate failed, rolling back"
    restore /etc/hosts.lpd || log "muster.file.hosts_lpd_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.hosts_lpd_permissions: done"
}
fix_muster_file_hosts_lpd_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 6/16 muster.service.automount_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and disable autofs (systemctl disable --now autofs.service) unless the host genuinely relies on automounted shares.
# ko:  이 호스트가 자동 마운트 공유에 실제로 의존하지 않는다면 autofs 를 중지·비활성화합니다 (systemctl disable --now autofs.service).
fix_muster_service_automount_disabled() {
  ( set -e
    if systemctl cat autofs.service >/dev/null 2>&1; then
      systemctl disable --now autofs.service
      systemctl mask autofs.service || true
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.automount_disabled: script failed (rc $rc), rolling back"
    ( set -e
      if systemctl cat autofs.service >/dev/null 2>&1; then
        systemctl unmask autofs.service
        systemctl enable --now autofs.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.automount_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet autofs.service && case "$(systemctl is-enabled autofs.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.automount_disabled: validate failed, rolling back"
    ( set -e
      if systemctl cat autofs.service >/dev/null 2>&1; then
        systemctl unmask autofs.service
        systemctl enable --now autofs.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.automount_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.automount_disabled: done"
}
fix_muster_service_automount_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 7/16 muster.service.dos_services_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Disable and mask the echo, discard, daytime and chargen services or remove their inetd/xinetd entries. An echo, discard, daytime or chargen started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  echo, discard, daytime, chargen 서비스를 비활성화·mask 하거나 inetd/xinetd 의 해당 항목을 제거합니다. inetd나 xinetd가 띄우는 echo, discard, daytime, chargen은 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_dos_services_disabled() {
  ( set -e
    for u in echo.socket discard.socket daytime.socket chargen.socket; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.dos_services_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in echo.socket discard.socket daytime.socket chargen.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in echo.socket discard.socket daytime.socket chargen.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.dos_services_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet echo.socket && case "$(systemctl is-enabled echo.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet discard.socket && case "$(systemctl is-enabled discard.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet daytime.socket && case "$(systemctl is-enabled daytime.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet chargen.socket && case "$(systemctl is-enabled chargen.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.dos_services_disabled: validate failed, rolling back"
    ( set -e
      for u in echo.socket discard.socket daytime.socket chargen.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in echo.socket discard.socket daytime.socket chargen.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.dos_services_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.dos_services_disabled: done"
}
fix_muster_service_dos_services_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 8/16 muster.service.finger_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Disable and mask the finger service or remove the finger server package, and remove any inetd/xinetd finger entry. A finger started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  finger 서비스를 비활성화·mask 하거나 finger 서버 패키지를 제거하고, inetd/xinetd 의 finger 항목을 제거합니다. inetd나 xinetd가 띄우는 finger는 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_finger_disabled() {
  ( set -e
    for u in finger.socket fingerd.service; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.finger_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in finger.socket fingerd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in finger.socket fingerd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.finger_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet finger.socket && case "$(systemctl is-enabled finger.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet fingerd.service && case "$(systemctl is-enabled fingerd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.finger_disabled: validate failed, rolling back"
    ( set -e
      for u in finger.socket fingerd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in finger.socket fingerd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.finger_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.finger_disabled: done"
}
fix_muster_service_finger_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 9/16 muster.service.nfs_server_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and disable the NFS server (systemctl disable --now nfs-server.service) unless the host must actually export filesystems over NFS.
# ko:  이 호스트가 실제로 NFS 로 파일시스템을 공유해야 하는 것이 아니라면 NFS 서버를 중지·비활성화합니다 (systemctl disable --now nfs-server.service).
fix_muster_service_nfs_server_disabled() {
  ( set -e
    for u in nfs-server.service nfs-kernel-server.service; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nfs_server_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in nfs-server.service nfs-kernel-server.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in nfs-server.service nfs-kernel-server.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.nfs_server_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet nfs-server.service && case "$(systemctl is-enabled nfs-server.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet nfs-kernel-server.service && case "$(systemctl is-enabled nfs-kernel-server.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nfs_server_disabled: validate failed, rolling back"
    ( set -e
      for u in nfs-server.service nfs-kernel-server.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in nfs-server.service nfs-kernel-server.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.nfs_server_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.nfs_server_disabled: done"
}
fix_muster_service_nfs_server_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 10/16 muster.service.nis_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and disable ypserv and ypbind (systemctl disable --now ypserv.service ypbind.service) and remove nis/nisplus from the passwd and group lines of /etc/nsswitch.conf.
# ko:  ypserv 와 ypbind 를 중지·비활성화하고 (systemctl disable --now ypserv.service ypbind.service) /etc/nsswitch.conf 의 passwd·group 줄에서 nis·nisplus 를 제거합니다.
fix_muster_service_nis_disabled() {
  ( set -e
    for u in ypserv.service ypbind.service ypxfrd.service yppasswdd.service; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nis_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in ypserv.service ypbind.service ypxfrd.service yppasswdd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in ypserv.service ypbind.service ypxfrd.service yppasswdd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.nis_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet ypserv.service && case "$(systemctl is-enabled ypserv.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet ypbind.service && case "$(systemctl is-enabled ypbind.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet ypxfrd.service && case "$(systemctl is-enabled ypxfrd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet yppasswdd.service && case "$(systemctl is-enabled yppasswdd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nis_disabled: validate failed, rolling back"
    ( set -e
      for u in ypserv.service ypbind.service ypxfrd.service yppasswdd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in ypserv.service ypbind.service ypxfrd.service yppasswdd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.nis_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.nis_disabled: done"
}
fix_muster_service_nis_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 11/16 muster.service.rpcbind_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and mask rpcbind (systemctl disable --now rpcbind.service rpcbind.socket) unless another RPC service on this host genuinely requires it.
# ko:  이 호스트의 다른 RPC 서비스가 실제로 필요로 하지 않는다면 rpcbind 를 중지·mask 합니다 (systemctl disable --now rpcbind.service rpcbind.socket).
fix_muster_service_rpcbind_disabled() {
  ( set -e
    for u in rpcbind.socket rpcbind.service; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rpcbind_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in rpcbind.socket rpcbind.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in rpcbind.socket rpcbind.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.rpcbind_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet rpcbind.socket && case "$(systemctl is-enabled rpcbind.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet rpcbind.service && case "$(systemctl is-enabled rpcbind.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rpcbind_disabled: validate failed, rolling back"
    ( set -e
      for u in rpcbind.socket rpcbind.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in rpcbind.socket rpcbind.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.rpcbind_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.rpcbind_disabled: done"
}
fix_muster_service_rpcbind_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 12/16 muster.service.rservices_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Disable and mask the rsh, rlogin and rexec services or remove the r-services package, and remove any inetd/xinetd r-services entries. An rsh, rlogin or rexec started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  rsh, rlogin, rexec 서비스를 비활성화·mask 하거나 r-services 패키지를 제거하고, inetd/xinetd 의 r-services 항목을 제거합니다. inetd나 xinetd가 띄우는 rsh, rlogin, rexec는 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_rservices_disabled() {
  ( set -e
    for u in rsh.socket rlogin.socket rexec.socket; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rservices_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in rsh.socket rlogin.socket rexec.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in rsh.socket rlogin.socket rexec.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.rservices_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet rsh.socket && case "$(systemctl is-enabled rsh.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet rlogin.socket && case "$(systemctl is-enabled rlogin.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet rexec.socket && case "$(systemctl is-enabled rexec.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rservices_disabled: validate failed, rolling back"
    ( set -e
      for u in rsh.socket rlogin.socket rexec.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in rsh.socket rlogin.socket rexec.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.rservices_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.rservices_disabled: done"
}
fix_muster_service_rservices_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 13/16 muster.service.tftp_talk_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and disable the tftp and talk (and ntalk) services or sockets and remove their inetd/xinetd entries. A tftp, talk or ntalk started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  tftp 와 talk(ntalk 포함) 서비스·소켓을 중지·비활성화하거나 inetd/xinetd 의 해당 항목을 제거합니다. inetd나 xinetd가 띄우는 tftp, talk, ntalk는 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_tftp_talk_disabled() {
  ( set -e
    for u in tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.tftp_talk_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.tftp_talk_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet tftp.socket && case "$(systemctl is-enabled tftp.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet tftp.service && case "$(systemctl is-enabled tftp.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet tftpd.service && case "$(systemctl is-enabled tftpd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet tftpd-hpa.service && case "$(systemctl is-enabled tftpd-hpa.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet atftpd.socket && case "$(systemctl is-enabled atftpd.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet atftpd.service && case "$(systemctl is-enabled atftpd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet talk.socket && case "$(systemctl is-enabled talk.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet ntalk.socket && case "$(systemctl is-enabled ntalk.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.tftp_talk_disabled: validate failed, rolling back"
    ( set -e
      for u in tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.tftp_talk_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.tftp_talk_disabled: done"
}
fix_muster_service_tftp_talk_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 14/16 muster.service.snmp_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Stop and disable the SNMP agent (systemctl disable --now snmpd.service) unless it is required, in which case harden it under the U-59/U-60/U-61 controls.
# ko:  SNMP 에이전트가 필요하지 않다면 중지·비활성화하고 (systemctl disable --now snmpd.service), 필요하다면 U-59/U-60/U-61 점검에 따라 강화합니다.
fix_muster_service_snmp_disabled() {
  ( set -e
    if systemctl cat snmpd.service >/dev/null 2>&1; then
      systemctl disable --now snmpd.service
      systemctl mask snmpd.service || true
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.snmp_disabled: script failed (rc $rc), rolling back"
    ( set -e
      if systemctl cat snmpd.service >/dev/null 2>&1; then
        systemctl unmask snmpd.service
        systemctl enable --now snmpd.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.snmp_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet snmpd.service && case "$(systemctl is-enabled snmpd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.snmp_disabled: validate failed, rolling back"
    ( set -e
      if systemctl cat snmpd.service >/dev/null 2>&1; then
        systemctl unmask snmpd.service
        systemctl enable --now snmpd.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.snmp_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.snmp_disabled: done"
}
fix_muster_service_snmp_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 15/16 muster.service.telnet_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Stop and mask the telnet socket and service, or remove the telnet server package; use SSH instead. A telnet started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  telnet 소켓과 서비스를 중지·mask 하거나 telnet 서버 패키지를 제거하고, 대신 SSH 를 사용합니다. inetd나 xinetd가 띄우는 telnet은 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_telnet_disabled() {
  ( set -e
    for u in telnet.socket telnet.service telnetd.service; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      systemctl disable --now "$u"
      systemctl mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.telnet_disabled: script failed (rc $rc), rolling back"
    ( set -e
      for u in telnet.socket telnet.service telnetd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in telnet.socket telnet.service telnetd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.telnet_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  ( set -e
    ! systemctl is-active --quiet telnet.socket && case "$(systemctl is-enabled telnet.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet telnet.service && case "$(systemctl is-enabled telnet.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet telnetd.service && case "$(systemctl is-enabled telnetd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.telnet_disabled: validate failed, rolling back"
    ( set -e
      for u in telnet.socket telnet.service telnetd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl unmask "$u"
      done
      for u in telnet.socket telnet.service telnetd.service; do
        systemctl cat "$u" >/dev/null 2>&1 || continue
        systemctl enable --now "$u"
      done
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.telnet_disabled: rollback failed (rc $rrc)"
    return 1
  fi
  log "muster.service.telnet_disabled: done"
}
fix_muster_service_telnet_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 16/16 muster.account.root_remote_login [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  Set PermitRootLogin no in /etc/ssh/sshd_config.d/00-muster.conf, validate with sshd -t, then restart sshd while keeping a second session open. Where /etc/securetty lists pts/* entries instead, remove those lines so no pseudo-terminal can be used for a securetty-gated root login. sshd keeps the first value it reads: a drop-in that sorts before 00-muster.conf, or a PermitRootLogin line before the Include in sshd_config, still wins.
# ko:  /etc/ssh/sshd_config.d/00-muster.conf 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤, 다른 세션을 열어 둔 채 sshd 를 재시작합니다. 대신 /etc/securetty 에 pts/* 항목이 있다면 그 줄을 제거하여 securetty 로 통제되는 root 로그인에 가상 터미널을 쓸 수 없게 합니다. sshd는 처음 읽은 값을 지키므로 00-muster.conf보다 먼저 정렬되는 드롭인이나 sshd_config의 Include 앞 PermitRootLogin 줄이 여전히 이깁니다.
fix_muster_account_root_remote_login() {
  backup /etc/ssh/sshd_config.d/00-muster.conf /etc/securetty || { log "muster.account.root_remote_login: backup failed, nothing changed"; return 1; }
  ( set -e
    if command -v sshd >/dev/null 2>&1; then
      [ -d /run/sshd ] || mkdir -p /run/sshd
      printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/00-muster.conf
      chmod 644 /etc/ssh/sshd_config.d/00-muster.conf
      sshd -t
    fi
    if [ -f /etc/securetty ]; then
      sed -i '/^pts\//d' /etc/securetty
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.root_remote_login: script failed (rc $rc), rolling back"
    ( set -e
      rm -f /etc/ssh/sshd_config.d/00-muster.conf
      if command -v sshd >/dev/null 2>&1; then sshd -t; fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.root_remote_login: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config.d/00-muster.conf /etc/securetty || log "muster.account.root_remote_login: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -qx 'permitrootlogin no'; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.root_remote_login: validate failed, rolling back"
    ( set -e
      rm -f /etc/ssh/sshd_config.d/00-muster.conf
      if command -v sshd >/dev/null 2>&1; then sshd -t; fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.root_remote_login: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config.d/00-muster.conf /etc/securetty || log "muster.account.root_remote_login: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.root_remote_login: done"
}
fix_muster_account_root_remote_login
[ "$?" -eq 0 ] || failed=$((failed+1))

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
