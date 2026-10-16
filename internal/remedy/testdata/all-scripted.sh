#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk lockout_risk
# planned 16 (script 16, text only 0); above max-risk 0; not planned: error 0, manual 0, warn_degraded 0
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
    [ "$(stat -c '%u %g %a' -- "$p" 2>/dev/null)" = "$uid $gid $mode" ] && continue
    modes_trusted "$p" "$uid" || { log "restore_modes: $p is under a directory others can write, left as is"; mrc=1; continue; }
    if chown -h -- "$uid:$gid" "$p"; then chmod -- "$mode" "$p" || mrc=1; else mrc=1; fi
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

# ---- 1/16 muster.file.passwd_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chown root:root /etc/passwd; chmod 644 /etc/passwd; setfacl -b /etc/passwd (the script only clears bits; a stricter file is left as it is)
# ko:  chown root:root /etc/passwd; chmod 644 /etc/passwd; setfacl -b /etc/passwd (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다)
fix_muster_file_passwd_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_passwd_permissions"; mkdir -p "$MB" || { log "muster.file.passwd_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/passwd || { log "muster.file.passwd_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/passwd ]
    chown root:root /etc/passwd
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/passwd; fi
    chmod u-xs,g-wxs,o-wxt /etc/passwd
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.passwd_permissions: script failed (rc $rc), rolling back"
    restore /etc/passwd || log "muster.file.passwd_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(stat -c '%u %g %a' /etc/passwd)" in '0 0 0'|'0 0 4'|'0 0 40'|'0 0 44'|'0 0 200'|'0 0 204'|'0 0 240'|'0 0 244'|'0 0 400'|'0 0 404'|'0 0 440'|'0 0 444'|'0 0 600'|'0 0 604'|'0 0 640'|'0 0 644') ;; *) false;; esac
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

# ---- 2/16 muster.file.services_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chown root:root /etc/services; chmod 644 /etc/services (the script only clears bits; a stricter file is left as it is)
# ko:  chown root:root /etc/services; chmod 644 /etc/services (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다)
fix_muster_file_services_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_services_permissions"; mkdir -p "$MB" || { log "muster.file.services_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/services || { log "muster.file.services_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/services ]
    chown root:root /etc/services
    chmod u-xs,g-wxs,o-wxt /etc/services
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.services_permissions: script failed (rc $rc), rolling back"
    restore /etc/services || log "muster.file.services_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(stat -c '%u %g %a' /etc/services)" in '0 0 0'|'0 0 4'|'0 0 40'|'0 0 44'|'0 0 200'|'0 0 204'|'0 0 240'|'0 0 244'|'0 0 400'|'0 0 404'|'0 0 440'|'0 0 444'|'0 0 600'|'0 0 604'|'0 0 640'|'0 0 644') ;; *) false;; esac
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

# ---- 3/16 muster.file.shadow_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow (the script only clears bits; a stricter file is left as it is). On Debian and Ubuntu unix_chkpwd reads /etc/shadow through group shadow; a site that keeps 0640 relaxes allowed_modes, and the plan then leaves the script out.
# ko:  chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다). Debian과 Ubuntu에서는 unix_chkpwd가 shadow 그룹으로 /etc/shadow를 읽으므로, 0640을 유지하는 사이트는 allowed_modes를 완화하고 그러면 계획이 스크립트를 뺍니다.
fix_muster_file_shadow_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_shadow_permissions"; mkdir -p "$MB" || { log "muster.file.shadow_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/shadow || { log "muster.file.shadow_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/shadow ]
    chown root /etc/shadow
    if command -v setfacl >/dev/null 2>&1; then setfacl -b /etc/shadow; fi
    chmod u-wxs,g-rwxs,o-rwxt /etc/shadow
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.shadow_permissions: script failed (rc $rc), rolling back"
    restore /etc/shadow || log "muster.file.shadow_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(stat -c '%u %a' /etc/shadow)" in '0 0'|'0 400') ;; *) false;; esac
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

# ---- 4/16 muster.file.hosts_lpd_permissions [risk none] [fail, low]
# why: clause does not hold
# do:  chown root:root /etc/hosts.lpd; chmod 600 /etc/hosts.lpd (the script only clears bits; a stricter file is left as it is)
# ko:  chown root:root /etc/hosts.lpd; chmod 600 /etc/hosts.lpd (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다)
fix_muster_file_hosts_lpd_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_hosts_lpd_permissions"; mkdir -p "$MB" || { log "muster.file.hosts_lpd_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/hosts.lpd || { log "muster.file.hosts_lpd_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/hosts.lpd ]
    chown root:root /etc/hosts.lpd
    chmod u-xs,g-rwxs,o-rwxt /etc/hosts.lpd
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_lpd_permissions: script failed (rc $rc), rolling back"
    restore /etc/hosts.lpd || log "muster.file.hosts_lpd_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(stat -c '%u %g %a' /etc/hosts.lpd)" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac
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

# ---- 5/16 muster.file.hosts_permissions [risk restart_service] [fail, high]
# why: clause does not hold
# do:  chown root:root /etc/hosts; chmod 600 /etc/hosts (the script only clears bits; a stricter file is left as it is). At 0600 non-root processes can no longer read /etc/hosts, so services that resolve names through it fail; a site that keeps 0644 relaxes allowed_modes, and the plan then leaves the script out.
# ko:  chown root:root /etc/hosts; chmod 600 /etc/hosts (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다). 0600에서는 root가 아닌 프로세스가 /etc/hosts를 읽지 못해 그것으로 이름을 푸는 서비스가 실패합니다. 0644를 유지하는 사이트는 allowed_modes를 완화하고 그러면 계획이 스크립트를 뺍니다.
fix_muster_file_hosts_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_hosts_permissions"; mkdir -p "$MB" || { log "muster.file.hosts_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/hosts || { log "muster.file.hosts_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/hosts ]
    chown root:root /etc/hosts
    chmod u-xs,g-rwxs,o-rwxt /etc/hosts
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_permissions: script failed (rc $rc), rolling back"
    restore /etc/hosts || log "muster.file.hosts_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(stat -c '%u %g %a' /etc/hosts)" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac
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

# ---- 6/16 muster.service.automount_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and disable autofs (systemctl disable --now autofs.service) unless the host genuinely relies on automounted shares.
# ko:  이 호스트가 자동 마운트 공유에 실제로 의존하지 않는다면 autofs 를 중지·비활성화합니다 (systemctl disable --now autofs.service).
fix_muster_service_automount_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_automount_disabled"; mkdir -p "$MB" || { log "muster.service.automount_disabled: backup failed, nothing changed"; return 1; }
  save_units autofs.service || { log "muster.service.automount_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='autofs.service'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.automount_disabled: script failed (rc $rc), rolling back"
    restore_units autofs.service || log "muster.service.automount_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet autofs.service && case "$(systemctl is-enabled autofs.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.automount_disabled: validate failed, rolling back"
    restore_units autofs.service || log "muster.service.automount_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
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
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_dos_services_disabled"; mkdir -p "$MB" || { log "muster.service.dos_services_disabled: backup failed, nothing changed"; return 1; }
  save_units echo.socket discard.socket daytime.socket chargen.socket || { log "muster.service.dos_services_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='echo.socket discard.socket daytime.socket chargen.socket'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.dos_services_disabled: script failed (rc $rc), rolling back"
    restore_units echo.socket discard.socket daytime.socket chargen.socket || log "muster.service.dos_services_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet echo.socket && case "$(systemctl is-enabled echo.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet discard.socket && case "$(systemctl is-enabled discard.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet daytime.socket && case "$(systemctl is-enabled daytime.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet chargen.socket && case "$(systemctl is-enabled chargen.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.dos_services_disabled: validate failed, rolling back"
    restore_units echo.socket discard.socket daytime.socket chargen.socket || log "muster.service.dos_services_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
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
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_finger_disabled"; mkdir -p "$MB" || { log "muster.service.finger_disabled: backup failed, nothing changed"; return 1; }
  save_units finger.socket fingerd.service || { log "muster.service.finger_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='finger.socket fingerd.service'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.finger_disabled: script failed (rc $rc), rolling back"
    restore_units finger.socket fingerd.service || log "muster.service.finger_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet finger.socket && case "$(systemctl is-enabled finger.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet fingerd.service && case "$(systemctl is-enabled fingerd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.finger_disabled: validate failed, rolling back"
    restore_units finger.socket fingerd.service || log "muster.service.finger_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
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
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_nfs_server_disabled"; mkdir -p "$MB" || { log "muster.service.nfs_server_disabled: backup failed, nothing changed"; return 1; }
  save_units nfs-server.service nfs-kernel-server.service || { log "muster.service.nfs_server_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='nfs-server.service nfs-kernel-server.service'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nfs_server_disabled: script failed (rc $rc), rolling back"
    restore_units nfs-server.service nfs-kernel-server.service || log "muster.service.nfs_server_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet nfs-server.service && case "$(systemctl is-enabled nfs-server.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet nfs-kernel-server.service && case "$(systemctl is-enabled nfs-kernel-server.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nfs_server_disabled: validate failed, rolling back"
    restore_units nfs-server.service nfs-kernel-server.service || log "muster.service.nfs_server_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.nfs_server_disabled: done"
}
fix_muster_service_nfs_server_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 10/16 muster.service.rpcbind_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and mask rpcbind (systemctl disable --now rpcbind.service rpcbind.socket) unless another RPC service on this host genuinely requires it.
# ko:  이 호스트의 다른 RPC 서비스가 실제로 필요로 하지 않는다면 rpcbind 를 중지·mask 합니다 (systemctl disable --now rpcbind.service rpcbind.socket).
fix_muster_service_rpcbind_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_rpcbind_disabled"; mkdir -p "$MB" || { log "muster.service.rpcbind_disabled: backup failed, nothing changed"; return 1; }
  save_units rpcbind.socket rpcbind.service || { log "muster.service.rpcbind_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='rpcbind.socket rpcbind.service'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rpcbind_disabled: script failed (rc $rc), rolling back"
    restore_units rpcbind.socket rpcbind.service || log "muster.service.rpcbind_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet rpcbind.socket && case "$(systemctl is-enabled rpcbind.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet rpcbind.service && case "$(systemctl is-enabled rpcbind.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rpcbind_disabled: validate failed, rolling back"
    restore_units rpcbind.socket rpcbind.service || log "muster.service.rpcbind_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.rpcbind_disabled: done"
}
fix_muster_service_rpcbind_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 11/16 muster.service.rservices_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Disable and mask the rsh, rlogin and rexec services or remove the r-services package, and remove any inetd/xinetd r-services entries. An rsh, rlogin or rexec started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  rsh, rlogin, rexec 서비스를 비활성화·mask 하거나 r-services 패키지를 제거하고, inetd/xinetd 의 r-services 항목을 제거합니다. inetd나 xinetd가 띄우는 rsh, rlogin, rexec는 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_rservices_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_rservices_disabled"; mkdir -p "$MB" || { log "muster.service.rservices_disabled: backup failed, nothing changed"; return 1; }
  save_units rsh.socket rlogin.socket rexec.socket || { log "muster.service.rservices_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='rsh.socket rlogin.socket rexec.socket'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rservices_disabled: script failed (rc $rc), rolling back"
    restore_units rsh.socket rlogin.socket rexec.socket || log "muster.service.rservices_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet rsh.socket && case "$(systemctl is-enabled rsh.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet rlogin.socket && case "$(systemctl is-enabled rlogin.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet rexec.socket && case "$(systemctl is-enabled rexec.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.rservices_disabled: validate failed, rolling back"
    restore_units rsh.socket rlogin.socket rexec.socket || log "muster.service.rservices_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.rservices_disabled: done"
}
fix_muster_service_rservices_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 12/16 muster.service.tftp_talk_disabled [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Stop and disable the tftp and talk (and ntalk) services or sockets and remove their inetd/xinetd entries. A tftp, talk or ntalk started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  tftp 와 talk(ntalk 포함) 서비스·소켓을 중지·비활성화하거나 inetd/xinetd 의 해당 항목을 제거합니다. inetd나 xinetd가 띄우는 tftp, talk, ntalk는 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_tftp_talk_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_tftp_talk_disabled"; mkdir -p "$MB" || { log "muster.service.tftp_talk_disabled: backup failed, nothing changed"; return 1; }
  save_units tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket || { log "muster.service.tftp_talk_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.tftp_talk_disabled: script failed (rc $rc), rolling back"
    restore_units tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket || log "muster.service.tftp_talk_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet tftp.socket && case "$(systemctl is-enabled tftp.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet tftp.service && case "$(systemctl is-enabled tftp.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet tftpd.service && case "$(systemctl is-enabled tftpd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet tftpd-hpa.service && case "$(systemctl is-enabled tftpd-hpa.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet atftpd.socket && case "$(systemctl is-enabled atftpd.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet atftpd.service && case "$(systemctl is-enabled atftpd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet talk.socket && case "$(systemctl is-enabled talk.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet ntalk.socket && case "$(systemctl is-enabled ntalk.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.tftp_talk_disabled: validate failed, rolling back"
    restore_units tftp.socket tftp.service tftpd.service tftpd-hpa.service atftpd.socket atftpd.service talk.socket ntalk.socket || log "muster.service.tftp_talk_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.tftp_talk_disabled: done"
}
fix_muster_service_tftp_talk_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 13/16 muster.service.snmp_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Stop and disable the SNMP agent (systemctl disable --now snmpd.service) unless it is required, in which case harden it under the U-59/U-60/U-61 controls.
# ko:  SNMP 에이전트가 필요하지 않다면 중지·비활성화하고 (systemctl disable --now snmpd.service), 필요하다면 U-59/U-60/U-61 점검에 따라 강화합니다.
fix_muster_service_snmp_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_snmp_disabled"; mkdir -p "$MB" || { log "muster.service.snmp_disabled: backup failed, nothing changed"; return 1; }
  save_units snmpd.service || { log "muster.service.snmp_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='snmpd.service'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.snmp_disabled: script failed (rc $rc), rolling back"
    restore_units snmpd.service || log "muster.service.snmp_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet snmpd.service && case "$(systemctl is-enabled snmpd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.snmp_disabled: validate failed, rolling back"
    restore_units snmpd.service || log "muster.service.snmp_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.snmp_disabled: done"
}
fix_muster_service_snmp_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 14/16 muster.service.telnet_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Stop and mask the telnet socket and service, or remove the telnet server package; use SSH instead. A telnet started by inetd or xinetd is not stopped by the script; remove its entry there.
# ko:  telnet 소켓과 서비스를 중지·mask 하거나 telnet 서버 패키지를 제거하고, 대신 SSH 를 사용합니다. inetd나 xinetd가 띄우는 telnet은 스크립트가 멈추지 않습니다. 거기서 항목을 지우십시오.
fix_muster_service_telnet_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_telnet_disabled"; mkdir -p "$MB" || { log "muster.service.telnet_disabled: backup failed, nothing changed"; return 1; }
  save_units telnet.socket telnet.service telnetd.service || { log "muster.service.telnet_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='telnet.socket telnet.service telnetd.service'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.telnet_disabled: script failed (rc $rc), rolling back"
    restore_units telnet.socket telnet.service telnetd.service || log "muster.service.telnet_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet telnet.socket && case "$(systemctl is-enabled telnet.socket 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet telnet.service && case "$(systemctl is-enabled telnet.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet telnetd.service && case "$(systemctl is-enabled telnetd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.telnet_disabled: validate failed, rolling back"
    restore_units telnet.socket telnet.service telnetd.service || log "muster.service.telnet_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.telnet_disabled: done"
}
fix_muster_service_telnet_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 15/16 muster.account.root_remote_login [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  Set PermitRootLogin no in /etc/ssh/sshd_config.d/00-muster.conf, validate with sshd -t, then restart sshd while keeping a second session open. Where /etc/securetty lists pts/* entries instead, remove those lines so no pseudo-terminal can be used for a securetty-gated root login. sshd keeps the first value it reads: a drop-in that sorts before 00-muster.conf, or a PermitRootLogin line before the Include in sshd_config, still wins. The script reloads a running sshd; a Match block that sets PermitRootLogin for root also wins, and the validate then fails and rolls back.
# ko:  /etc/ssh/sshd_config.d/00-muster.conf 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤, 다른 세션을 열어 둔 채 sshd 를 재시작합니다. 대신 /etc/securetty 에 pts/* 항목이 있다면 그 줄을 제거하여 securetty 로 통제되는 root 로그인에 가상 터미널을 쓸 수 없게 합니다. sshd는 처음 읽은 값을 지키므로 00-muster.conf보다 먼저 정렬되는 드롭인이나 sshd_config의 Include 앞 PermitRootLogin 줄이 여전히 이깁니다. 스크립트는 실행 중인 sshd를 다시 읽게 합니다. root에 PermitRootLogin을 정하는 Match 블록도 이기며, 그러면 validate가 실패하고 롤백합니다.
fix_muster_account_root_remote_login() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_root_remote_login"; mkdir -p "$MB" || { log "muster.account.root_remote_login: backup failed, nothing changed"; return 1; }
  backup /etc/ssh/sshd_config.d/00-muster.conf /etc/securetty || { log "muster.account.root_remote_login: backup failed, nothing changed"; return 1; }
  ( set -e
    if command -v sshd >/dev/null 2>&1; then
      [ -d /run/sshd ] || mkdir -p /run/sshd
      printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/00-muster.conf
      chmod 644 /etc/ssh/sshd_config.d/00-muster.conf
      sshd -t
      if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
      if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
    fi
    if [ -f /etc/securetty ]; then
      sed -i '/^[[:space:]]*pts\//d' /etc/securetty
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.root_remote_login: script failed (rc $rc), rolling back"
    ( set -e
      rm -f /etc/ssh/sshd_config.d/00-muster.conf
      if command -v sshd >/dev/null 2>&1; then sshd -t; fi
      if command -v sshd >/dev/null 2>&1; then
        if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
        if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.root_remote_login: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config.d/00-muster.conf /etc/securetty || log "muster.account.root_remote_login: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    if command -v sshd >/dev/null 2>&1; then sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | grep -qx 'permitrootlogin no'; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.root_remote_login: validate failed, rolling back"
    ( set -e
      rm -f /etc/ssh/sshd_config.d/00-muster.conf
      if command -v sshd >/dev/null 2>&1; then sshd -t; fi
      if command -v sshd >/dev/null 2>&1; then
        if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
        if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.root_remote_login: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config.d/00-muster.conf /etc/securetty || log "muster.account.root_remote_login: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.root_remote_login: done"
}
fix_muster_account_root_remote_login
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 16/16 muster.service.nis_disabled [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  Stop and disable ypserv and ypbind (systemctl disable --now ypserv.service ypbind.service) and remove nis/nisplus from the passwd and group lines of /etc/nsswitch.conf. On a host whose accounts come from NIS, stopping ypbind cuts those accounts off; change nsswitch first.
# ko:  ypserv 와 ypbind 를 중지·비활성화하고 (systemctl disable --now ypserv.service ypbind.service) /etc/nsswitch.conf 의 passwd·group 줄에서 nis·nisplus 를 제거합니다. 계정을 NIS에서 받는 호스트에서 ypbind를 멈추면 그 계정이 끊깁니다. 먼저 nsswitch를 바꾸십시오.
fix_muster_service_nis_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_nis_disabled"; mkdir -p "$MB" || { log "muster.service.nis_disabled: backup failed, nothing changed"; return 1; }
  save_units ypserv.service ypbind.service ypxfrd.service yppasswdd.service || { log "muster.service.nis_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='ypserv.service ypbind.service ypxfrd.service yppasswdd.service'
    todo=
    for u in $UNITS; do
      systemctl cat "$u" >/dev/null 2>&1 || continue
      [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
      todo="$todo $u"
    done
    for u in $todo; do
      systemctl --quiet disable --now "$u"
      systemctl --quiet mask "$u" || true
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nis_disabled: script failed (rc $rc), rolling back"
    restore_units ypserv.service ypbind.service ypxfrd.service yppasswdd.service || log "muster.service.nis_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    ! systemctl is-active --quiet ypserv.service && case "$(systemctl is-enabled ypserv.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet ypbind.service && case "$(systemctl is-enabled ypbind.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet ypxfrd.service && case "$(systemctl is-enabled ypxfrd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac && ! systemctl is-active --quiet yppasswdd.service && case "$(systemctl is-enabled yppasswdd.service 2>/dev/null)" in enabled|enabled-runtime) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nis_disabled: validate failed, rolling back"
    restore_units ypserv.service ypbind.service ypxfrd.service yppasswdd.service || log "muster.service.nis_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.nis_disabled: done"
}
fix_muster_service_nis_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
