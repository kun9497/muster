#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk lockout_risk
# planned 32 (script 32, text only 0); above max-risk 0; not planned: error 0, manual 0, warn_degraded 0
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

# ---- 1/32 muster.beyond.aslr_and_link_protection [risk none] [fail, high]
# why: clause does not hold
# do:  Write kernel.randomize_va_space = 2, fs.protected_symlinks = 1, fs.protected_hardlinks = 1, fs.protected_fifos = 1 and fs.protected_regular = 2 into /etc/sysctl.d/99-muster-aslr-and-link-protection.conf and apply it with sysctl --system; if an existing hardening file lowers one of them, correct that file rather than adding a later one. All five take effect at once and need no reboot. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-aslr-and-link-protection.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-aslr-and-link-protection.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-aslr-and-link-protection.conf 에 kernel.randomize_va_space = 2, fs.protected_symlinks = 1, fs.protected_hardlinks = 1, fs.protected_fifos = 1, fs.protected_regular = 2 를 적고 sysctl --system 으로 적용합니다. 기존 하드닝 파일이 그중 하나를 낮추고 있다면 뒤에 파일을 더 얹지 말고 그 파일을 고치십시오. 다섯 값 모두 즉시 반영되며 재부팅이 필요 없습니다. /etc/sysctl.conf나 99-muster-aslr-and-link-protection.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-aslr-and-link-protection.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_aslr_and_link_protection() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_aslr_and_link_protection"; mkdir -p "$MB" || { log "muster.beyond.aslr_and_link_protection: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-aslr-and-link-protection.conf || { log "muster.beyond.aslr_and_link_protection: backup failed, nothing changed"; return 1; }
  save_sysctl kernel.randomize_va_space fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular || { log "muster.beyond.aslr_and_link_protection: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-aslr-and-link-protection.conf
    if [ -L "$f" ]; then log "muster.beyond.aslr_and_link_protection: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n kernel.randomize_va_space)" in 2) ;; *) put kernel.randomize_va_space 2;; esac
    case "$(sysctl -n fs.protected_symlinks)" in 1) ;; *) put fs.protected_symlinks 1;; esac
    case "$(sysctl -n fs.protected_hardlinks)" in 1) ;; *) put fs.protected_hardlinks 1;; esac
    case "$(sysctl -n fs.protected_fifos)" in 1|2) ;; *) put fs.protected_fifos 1;; esac
    case "$(sysctl -n fs.protected_regular)" in 1|2) ;; *) put fs.protected_regular 2;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.aslr_and_link_protection: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-aslr-and-link-protection.conf || log "muster.beyond.aslr_and_link_protection: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.randomize_va_space fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular || log "muster.beyond.aslr_and_link_protection: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n kernel.randomize_va_space)" in 2) ;; *) false;; esac && case "$(sysctl -n fs.protected_symlinks)" in 1) ;; *) false;; esac && case "$(sysctl -n fs.protected_hardlinks)" in 1) ;; *) false;; esac && case "$(sysctl -n fs.protected_fifos)" in 1|2) ;; *) false;; esac && case "$(sysctl -n fs.protected_regular)" in 1|2) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.aslr_and_link_protection: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-aslr-and-link-protection.conf || log "muster.beyond.aslr_and_link_protection: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.randomize_va_space fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular || log "muster.beyond.aslr_and_link_protection: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.aslr_and_link_protection: done"
}
fix_muster_beyond_aslr_and_link_protection
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 2/32 muster.file.passwd_permissions [risk none] [fail, high]
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

# ---- 3/32 muster.file.services_permissions [risk none] [fail, high]
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

# ---- 4/32 muster.file.shadow_permissions [risk none] [fail, high]
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

# ---- 5/32 muster.beyond.icmp_redirects_ignored [risk none] [fail, medium]
# why: clause does not hold
# do:  Write the six values as 0 - net.ipv4.conf.all.accept_redirects, net.ipv4.conf.default.accept_redirects, the same two for secure_redirects and for send_redirects - into /etc/sysctl.d/99-muster-icmp-redirects-ignored.conf and apply it with sysctl --system; they take effect at once. A host that really routes for its link may need send_redirects; such a host waives the finding. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-icmp-redirects-ignored.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-icmp-redirects-ignored.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  net.ipv4.conf.all.accept_redirects, net.ipv4.conf.default.accept_redirects 와 secure_redirects, send_redirects 의 같은 두 값, 모두 여섯 값을 0 으로 /etc/sysctl.d/99-muster-icmp-redirects-ignored.conf 에 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 실제로 링크를 위해 라우팅하는 호스트는 send_redirects 가 필요할 수 있으며 그런 호스트는 예외(waiver)로 처리합니다. /etc/sysctl.conf나 99-muster-icmp-redirects-ignored.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-icmp-redirects-ignored.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_icmp_redirects_ignored() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_icmp_redirects_ignored"; mkdir -p "$MB" || { log "muster.beyond.icmp_redirects_ignored: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-icmp-redirects-ignored.conf || { log "muster.beyond.icmp_redirects_ignored: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects || { log "muster.beyond.icmp_redirects_ignored: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-icmp-redirects-ignored.conf
    if [ -L "$f" ]; then log "muster.beyond.icmp_redirects_ignored: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv4.conf.all.accept_redirects)" in 0) ;; *) put net.ipv4.conf.all.accept_redirects 0;; esac
    case "$(sysctl -n net.ipv4.conf.default.accept_redirects)" in 0) ;; *) put net.ipv4.conf.default.accept_redirects 0;; esac
    case "$(sysctl -n net.ipv4.conf.all.secure_redirects)" in 0) ;; *) put net.ipv4.conf.all.secure_redirects 0;; esac
    case "$(sysctl -n net.ipv4.conf.default.secure_redirects)" in 0) ;; *) put net.ipv4.conf.default.secure_redirects 0;; esac
    case "$(sysctl -n net.ipv4.conf.all.send_redirects)" in 0) ;; *) put net.ipv4.conf.all.send_redirects 0;; esac
    case "$(sysctl -n net.ipv4.conf.default.send_redirects)" in 0) ;; *) put net.ipv4.conf.default.send_redirects 0;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.icmp_redirects_ignored: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-icmp-redirects-ignored.conf || log "muster.beyond.icmp_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects || log "muster.beyond.icmp_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n net.ipv4.conf.all.accept_redirects)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.default.accept_redirects)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.all.secure_redirects)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.default.secure_redirects)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.all.send_redirects)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.default.send_redirects)" in 0) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.icmp_redirects_ignored: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-icmp-redirects-ignored.conf || log "muster.beyond.icmp_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects || log "muster.beyond.icmp_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.icmp_redirects_ignored: done"
}
fix_muster_beyond_icmp_redirects_ignored
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 6/32 muster.beyond.ipv6_redirects_ignored [risk none] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv6.conf.all.accept_redirects = 0 and net.ipv6.conf.default.accept_redirects = 0 into /etc/sysctl.d/99-muster-ipv6-redirects-ignored.conf and apply it with sysctl --system; they take effect at once. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ipv6-redirects-ignored.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ipv6-redirects-ignored.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-ipv6-redirects-ignored.conf 에 net.ipv6.conf.all.accept_redirects = 0 과 net.ipv6.conf.default.accept_redirects = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. /etc/sysctl.conf나 99-muster-ipv6-redirects-ignored.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ipv6-redirects-ignored.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_ipv6_redirects_ignored() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_ipv6_redirects_ignored"; mkdir -p "$MB" || { log "muster.beyond.ipv6_redirects_ignored: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-ipv6-redirects-ignored.conf || { log "muster.beyond.ipv6_redirects_ignored: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects || { log "muster.beyond.ipv6_redirects_ignored: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-ipv6-redirects-ignored.conf
    if [ -L "$f" ]; then log "muster.beyond.ipv6_redirects_ignored: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv6.conf.all.accept_redirects)" in 0) ;; *) put net.ipv6.conf.all.accept_redirects 0;; esac
    case "$(sysctl -n net.ipv6.conf.default.accept_redirects)" in 0) ;; *) put net.ipv6.conf.default.accept_redirects 0;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_redirects_ignored: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-redirects-ignored.conf || log "muster.beyond.ipv6_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects || log "muster.beyond.ipv6_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n net.ipv6.conf.all.accept_redirects)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv6.conf.default.accept_redirects)" in 0) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_redirects_ignored: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-redirects-ignored.conf || log "muster.beyond.ipv6_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects || log "muster.beyond.ipv6_redirects_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.ipv6_redirects_ignored: done"
}
fix_muster_beyond_ipv6_redirects_ignored
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 7/32 muster.beyond.ipv6_router_advertisements_ignored [risk none] [fail, medium]
# why: clause does not hold
# do:  On a host with a static IPv6 address, or none, write net.ipv6.conf.all.accept_ra = 0 and net.ipv6.conf.default.accept_ra = 0 into /etc/sysctl.d/99-muster-ipv6-router-advertisements-ignored.conf and apply it with sysctl --system. Check first how the host gets its IPv6 address - a host addressed by SLAAC loses its address and default route; it names 1 in params.allowed_accept_ra instead. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ipv6-router-advertisements-ignored.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ipv6-router-advertisements-ignored.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  정적 IPv6 주소를 쓰거나 IPv6 주소가 없는 호스트는 /etc/sysctl.d/99-muster-ipv6-router-advertisements-ignored.conf 에 net.ipv6.conf.all.accept_ra = 0 과 net.ipv6.conf.default.accept_ra = 0 을 적고 sysctl --system 으로 적용합니다. 먼저 호스트가 IPv6 주소를 어떻게 받는지 확인하십시오. SLAAC 로 주소를 받는 호스트는 주소와 기본 경로를 잃으므로 대신 params.allowed_accept_ra 에 1 을 적습니다. /etc/sysctl.conf나 99-muster-ipv6-router-advertisements-ignored.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ipv6-router-advertisements-ignored.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_ipv6_router_advertisements_ignored() {
  P_allowed_accept_ra='0'
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_ipv6_router_advertisements_ignored"; mkdir -p "$MB" || { log "muster.beyond.ipv6_router_advertisements_ignored: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-ipv6-router-advertisements-ignored.conf || { log "muster.beyond.ipv6_router_advertisements_ignored: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra || { log "muster.beyond.ipv6_router_advertisements_ignored: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-ipv6-router-advertisements-ignored.conf
    if [ -L "$f" ]; then log "muster.beyond.ipv6_router_advertisements_ignored: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    first=${P_allowed_accept_ra%% *}
    case " $P_allowed_accept_ra " in *" $(sysctl -n net.ipv6.conf.all.accept_ra) "*) ;; *) put net.ipv6.conf.all.accept_ra "$first";; esac
    case " $P_allowed_accept_ra " in *" $(sysctl -n net.ipv6.conf.default.accept_ra) "*) ;; *) put net.ipv6.conf.default.accept_ra "$first";; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_router_advertisements_ignored: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-router-advertisements-ignored.conf || log "muster.beyond.ipv6_router_advertisements_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra || log "muster.beyond.ipv6_router_advertisements_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case " $P_allowed_accept_ra " in *" $(sysctl -n net.ipv6.conf.all.accept_ra) "*) ;; *) false;; esac && case " $P_allowed_accept_ra " in *" $(sysctl -n net.ipv6.conf.default.accept_ra) "*) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_router_advertisements_ignored: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-router-advertisements-ignored.conf || log "muster.beyond.ipv6_router_advertisements_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra || log "muster.beyond.ipv6_router_advertisements_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.ipv6_router_advertisements_ignored: done"
}
fix_muster_beyond_ipv6_router_advertisements_ignored
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 8/32 muster.beyond.ipv6_source_routing_rejected [risk none] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv6.conf.all.accept_source_route = 0 and net.ipv6.conf.default.accept_source_route = 0 into /etc/sysctl.d/99-muster-ipv6-source-routing-rejected.conf and apply it with sysctl --system; they take effect at once. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ipv6-source-routing-rejected.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ipv6-source-routing-rejected.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-ipv6-source-routing-rejected.conf 에 net.ipv6.conf.all.accept_source_route = 0 과 net.ipv6.conf.default.accept_source_route = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. /etc/sysctl.conf나 99-muster-ipv6-source-routing-rejected.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ipv6-source-routing-rejected.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_ipv6_source_routing_rejected() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_ipv6_source_routing_rejected"; mkdir -p "$MB" || { log "muster.beyond.ipv6_source_routing_rejected: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-ipv6-source-routing-rejected.conf || { log "muster.beyond.ipv6_source_routing_rejected: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route || { log "muster.beyond.ipv6_source_routing_rejected: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-ipv6-source-routing-rejected.conf
    if [ -L "$f" ]; then log "muster.beyond.ipv6_source_routing_rejected: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv6.conf.all.accept_source_route)" in 0) ;; *) put net.ipv6.conf.all.accept_source_route 0;; esac
    case "$(sysctl -n net.ipv6.conf.default.accept_source_route)" in 0) ;; *) put net.ipv6.conf.default.accept_source_route 0;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_source_routing_rejected: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-source-routing-rejected.conf || log "muster.beyond.ipv6_source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route || log "muster.beyond.ipv6_source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n net.ipv6.conf.all.accept_source_route)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv6.conf.default.accept_source_route)" in 0) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_source_routing_rejected: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-source-routing-rejected.conf || log "muster.beyond.ipv6_source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route || log "muster.beyond.ipv6_source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.ipv6_source_routing_rejected: done"
}
fix_muster_beyond_ipv6_source_routing_rejected
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 9/32 muster.beyond.kernel_pointer_exposure [risk none] [fail, medium]
# why: clause does not hold
# do:  Write kernel.kptr_restrict = 1 (or 2) and kernel.dmesg_restrict = 1 into /etc/sysctl.d/99-muster-kernel-pointer-exposure.conf and apply it with sysctl --system; both take effect at once and need no reboot. Check first that no monitoring or crash-reporting agent on the host reads dmesg as an unprivileged user. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-kernel-pointer-exposure.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-kernel-pointer-exposure.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-kernel-pointer-exposure.conf 에 kernel.kptr_restrict = 1(또는 2) 과 kernel.dmesg_restrict = 1 을 적고 sysctl --system 으로 적용합니다. 두 값 모두 즉시 반영되며 재부팅이 필요 없습니다. 적용 전에 호스트의 모니터링·크래시 리포트 에이전트가 비권한 사용자로 dmesg 를 읽고 있지 않은지 확인하십시오. /etc/sysctl.conf나 99-muster-kernel-pointer-exposure.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-kernel-pointer-exposure.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_kernel_pointer_exposure() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_kernel_pointer_exposure"; mkdir -p "$MB" || { log "muster.beyond.kernel_pointer_exposure: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-kernel-pointer-exposure.conf || { log "muster.beyond.kernel_pointer_exposure: backup failed, nothing changed"; return 1; }
  save_sysctl kernel.kptr_restrict kernel.dmesg_restrict || { log "muster.beyond.kernel_pointer_exposure: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-kernel-pointer-exposure.conf
    if [ -L "$f" ]; then log "muster.beyond.kernel_pointer_exposure: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n kernel.kptr_restrict)" in 1|2) ;; *) put kernel.kptr_restrict 1;; esac
    case "$(sysctl -n kernel.dmesg_restrict)" in 1) ;; *) put kernel.dmesg_restrict 1;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.kernel_pointer_exposure: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-kernel-pointer-exposure.conf || log "muster.beyond.kernel_pointer_exposure: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.kptr_restrict kernel.dmesg_restrict || log "muster.beyond.kernel_pointer_exposure: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n kernel.kptr_restrict)" in 1|2) ;; *) false;; esac && case "$(sysctl -n kernel.dmesg_restrict)" in 1) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.kernel_pointer_exposure: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-kernel-pointer-exposure.conf || log "muster.beyond.kernel_pointer_exposure: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.kptr_restrict kernel.dmesg_restrict || log "muster.beyond.kernel_pointer_exposure: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.kernel_pointer_exposure: done"
}
fix_muster_beyond_kernel_pointer_exposure
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 10/32 muster.beyond.ptrace_restriction [risk none] [fail, medium]
# why: clause does not hold
# do:  Write kernel.yama.ptrace_scope = 1 and kernel.perf_event_paranoid = 2 into /etc/sysctl.d/99-muster-ptrace-restriction.conf and apply it with sysctl --system; the review script writes a key only when its value is outside the accepted set, and leaves a host at kernel.yama.ptrace_scope = 3, which locks until reboot, alone. Confirm first that no debugger, profiler or crash handler on the host attaches to a process it did not start; 1 is the value that keeps gdb working on a program you launched yourself, and 3 cannot be undone without a reboot. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ptrace-restriction.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ptrace-restriction.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-ptrace-restriction.conf 에 kernel.yama.ptrace_scope = 1 과 kernel.perf_event_paranoid = 2 를 적고 sysctl --system 으로 적용합니다. 검토 스크립트는 값이 허용 범위 밖인 키만 쓰며, 재부팅 전까지 잠기는 kernel.yama.ptrace_scope = 3인 호스트는 그대로 둡니다. 호스트의 디버거·프로파일러·크래시 처리기가 자신이 띄우지 않은 프로세스에 붙지 않는지 먼저 확인하십시오. 직접 실행한 프로그램에 gdb 를 붙이는 용도는 값 1 에서 그대로 동작하며, 3 은 재부팅 없이는 되돌릴 수 없습니다. /etc/sysctl.conf나 99-muster-ptrace-restriction.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ptrace-restriction.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_ptrace_restriction() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_ptrace_restriction"; mkdir -p "$MB" || { log "muster.beyond.ptrace_restriction: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-ptrace-restriction.conf || { log "muster.beyond.ptrace_restriction: backup failed, nothing changed"; return 1; }
  save_sysctl kernel.yama.ptrace_scope kernel.perf_event_paranoid || { log "muster.beyond.ptrace_restriction: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-ptrace-restriction.conf
    if [ -L "$f" ]; then log "muster.beyond.ptrace_restriction: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n kernel.yama.ptrace_scope)" in 1|2|3) ;; *) put kernel.yama.ptrace_scope 1;; esac
    case "$(sysctl -n kernel.perf_event_paranoid)" in [2-9]|[1-9][0-9]|[1-9][0-9][0-9]*) ;; *) put kernel.perf_event_paranoid 2;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ptrace_restriction: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-ptrace-restriction.conf || log "muster.beyond.ptrace_restriction: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.yama.ptrace_scope kernel.perf_event_paranoid || log "muster.beyond.ptrace_restriction: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n kernel.yama.ptrace_scope)" in 1|2|3) ;; *) false;; esac && case "$(sysctl -n kernel.perf_event_paranoid)" in [2-9]|[1-9][0-9]|[1-9][0-9][0-9]*) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ptrace_restriction: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-ptrace-restriction.conf || log "muster.beyond.ptrace_restriction: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.yama.ptrace_scope kernel.perf_event_paranoid || log "muster.beyond.ptrace_restriction: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.ptrace_restriction: done"
}
fix_muster_beyond_ptrace_restriction
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 11/32 muster.beyond.reverse_path_filtering [risk none] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv4.conf.all.log_martians = 1 and net.ipv4.conf.default.log_martians = 1, and rp_filter = 1 or 2 for all and default if they are 0, into /etc/sysctl.d/99-muster-reverse-path-filtering.conf and apply it with sysctl --system; they take effect at once. Choose 2 on a host with asymmetric routes (several uplinks, policy routing), where strict filtering drops legitimate replies. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-reverse-path-filtering.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-reverse-path-filtering.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  net.ipv4.conf.all.log_martians = 1 과 net.ipv4.conf.default.log_martians = 1 을, rp_filter 가 0 이면 all 과 default 에 1 또는 2 를 /etc/sysctl.d/99-muster-reverse-path-filtering.conf 에 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 비대칭 경로가 있는 호스트(여러 업링크, 정책 라우팅)에서는 strict 필터링이 정상 응답을 버리므로 2 를 고릅니다. /etc/sysctl.conf나 99-muster-reverse-path-filtering.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-reverse-path-filtering.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_reverse_path_filtering() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_reverse_path_filtering"; mkdir -p "$MB" || { log "muster.beyond.reverse_path_filtering: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-reverse-path-filtering.conf || { log "muster.beyond.reverse_path_filtering: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians || { log "muster.beyond.reverse_path_filtering: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-reverse-path-filtering.conf
    if [ -L "$f" ]; then log "muster.beyond.reverse_path_filtering: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv4.conf.all.rp_filter)" in 1|2) ;; *) put net.ipv4.conf.all.rp_filter 1;; esac
    case "$(sysctl -n net.ipv4.conf.default.rp_filter)" in 1|2) ;; *) put net.ipv4.conf.default.rp_filter 1;; esac
    case "$(sysctl -n net.ipv4.conf.all.log_martians)" in 1) ;; *) put net.ipv4.conf.all.log_martians 1;; esac
    case "$(sysctl -n net.ipv4.conf.default.log_martians)" in 1) ;; *) put net.ipv4.conf.default.log_martians 1;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.reverse_path_filtering: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-reverse-path-filtering.conf || log "muster.beyond.reverse_path_filtering: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians || log "muster.beyond.reverse_path_filtering: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n net.ipv4.conf.all.rp_filter)" in 1|2) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.default.rp_filter)" in 1|2) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.all.log_martians)" in 1) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.default.log_martians)" in 1) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.reverse_path_filtering: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-reverse-path-filtering.conf || log "muster.beyond.reverse_path_filtering: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians || log "muster.beyond.reverse_path_filtering: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.reverse_path_filtering: done"
}
fix_muster_beyond_reverse_path_filtering
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 12/32 muster.beyond.source_routing_rejected [risk none] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv4.conf.all.accept_source_route = 0 and net.ipv4.conf.default.accept_source_route = 0 into /etc/sysctl.d/99-muster-source-routing-rejected.conf and apply it with sysctl --system; they take effect at once. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-source-routing-rejected.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-source-routing-rejected.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-source-routing-rejected.conf 에 net.ipv4.conf.all.accept_source_route = 0 과 net.ipv4.conf.default.accept_source_route = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. /etc/sysctl.conf나 99-muster-source-routing-rejected.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-source-routing-rejected.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_source_routing_rejected() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_source_routing_rejected"; mkdir -p "$MB" || { log "muster.beyond.source_routing_rejected: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-source-routing-rejected.conf || { log "muster.beyond.source_routing_rejected: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route || { log "muster.beyond.source_routing_rejected: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-source-routing-rejected.conf
    if [ -L "$f" ]; then log "muster.beyond.source_routing_rejected: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv4.conf.all.accept_source_route)" in 0) ;; *) put net.ipv4.conf.all.accept_source_route 0;; esac
    case "$(sysctl -n net.ipv4.conf.default.accept_source_route)" in 0) ;; *) put net.ipv4.conf.default.accept_source_route 0;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.source_routing_rejected: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-source-routing-rejected.conf || log "muster.beyond.source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route || log "muster.beyond.source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n net.ipv4.conf.all.accept_source_route)" in 0) ;; *) false;; esac && case "$(sysctl -n net.ipv4.conf.default.accept_source_route)" in 0) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.source_routing_rejected: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-source-routing-rejected.conf || log "muster.beyond.source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route || log "muster.beyond.source_routing_rejected: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.source_routing_rejected: done"
}
fix_muster_beyond_source_routing_rejected
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 13/32 muster.beyond.suid_dumpable_disabled [risk none] [fail, medium]
# why: clause does not hold
# do:  Write fs.suid_dumpable = 0 into /etc/sysctl.d/99-muster-suid-dumpable-disabled.conf and apply it with sysctl --system; it takes effect at once and needs no reboot. A crash-reporting tool that collects dumps from setuid programs stops receiving them, which is the intent. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-suid-dumpable-disabled.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-suid-dumpable-disabled.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-suid-dumpable-disabled.conf 에 fs.suid_dumpable = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영되며 재부팅이 필요 없습니다. setuid 프로그램의 덤프를 수집하던 크래시 리포트 도구는 더 이상 그것을 받지 못하는데, 그것이 이 설정의 의도입니다. /etc/sysctl.conf나 99-muster-suid-dumpable-disabled.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-suid-dumpable-disabled.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_suid_dumpable_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_suid_dumpable_disabled"; mkdir -p "$MB" || { log "muster.beyond.suid_dumpable_disabled: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-suid-dumpable-disabled.conf || { log "muster.beyond.suid_dumpable_disabled: backup failed, nothing changed"; return 1; }
  save_sysctl fs.suid_dumpable || { log "muster.beyond.suid_dumpable_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-suid-dumpable-disabled.conf
    if [ -L "$f" ]; then log "muster.beyond.suid_dumpable_disabled: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n fs.suid_dumpable)" in 0) ;; *) put fs.suid_dumpable 0;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.suid_dumpable_disabled: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-suid-dumpable-disabled.conf || log "muster.beyond.suid_dumpable_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl fs.suid_dumpable || log "muster.beyond.suid_dumpable_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n fs.suid_dumpable)" in 0) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.suid_dumpable_disabled: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-suid-dumpable-disabled.conf || log "muster.beyond.suid_dumpable_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl fs.suid_dumpable || log "muster.beyond.suid_dumpable_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.suid_dumpable_disabled: done"
}
fix_muster_beyond_suid_dumpable_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 14/32 muster.beyond.syn_cookies_enabled [risk none] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv4.tcp_syncookies = 1 into /etc/sysctl.d/99-muster-syn-cookies-enabled.conf and apply it with sysctl --system; it takes effect at once. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-syn-cookies-enabled.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-syn-cookies-enabled.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-syn-cookies-enabled.conf 에 net.ipv4.tcp_syncookies = 1 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. /etc/sysctl.conf나 99-muster-syn-cookies-enabled.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-syn-cookies-enabled.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_syn_cookies_enabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_syn_cookies_enabled"; mkdir -p "$MB" || { log "muster.beyond.syn_cookies_enabled: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-syn-cookies-enabled.conf || { log "muster.beyond.syn_cookies_enabled: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv4.tcp_syncookies || { log "muster.beyond.syn_cookies_enabled: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-syn-cookies-enabled.conf
    if [ -L "$f" ]; then log "muster.beyond.syn_cookies_enabled: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv4.tcp_syncookies)" in 1) ;; *) put net.ipv4.tcp_syncookies 1;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.syn_cookies_enabled: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-syn-cookies-enabled.conf || log "muster.beyond.syn_cookies_enabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.tcp_syncookies || log "muster.beyond.syn_cookies_enabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n net.ipv4.tcp_syncookies)" in 1) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.syn_cookies_enabled: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-syn-cookies-enabled.conf || log "muster.beyond.syn_cookies_enabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.tcp_syncookies || log "muster.beyond.syn_cookies_enabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.syn_cookies_enabled: done"
}
fix_muster_beyond_syn_cookies_enabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 15/32 muster.beyond.sysrq_restricted [risk none] [fail, medium]
# why: clause does not hold
# do:  Write kernel.sysrq = 0 into /etc/sysctl.d/99-muster-sysrq-restricted.conf and apply it with sysctl --system, or, if your operations team relies on the distribution's value, keep it and add that number to params.allowed_sysrq so the decision is recorded. A host whose console is physically controlled and whose recovery procedure uses SysRq is the case the parameter exists for. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-sysrq-restricted.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-sysrq-restricted.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-sysrq-restricted.conf 에 kernel.sysrq = 0 을 적고 sysctl --system 으로 적용합니다. 운영 절차가 배포판 값에 의존한다면 값을 유지하되 그 숫자를 params.allowed_sysrq 에 추가해 결정을 기록하십시오. 콘솔이 물리적으로 통제되고 복구 절차가 SysRq 를 쓰는 호스트가 바로 이 파라미터가 존재하는 이유입니다. /etc/sysctl.conf나 99-muster-sysrq-restricted.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-sysrq-restricted.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_sysrq_restricted() {
  P_allowed_sysrq='0'
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_sysrq_restricted"; mkdir -p "$MB" || { log "muster.beyond.sysrq_restricted: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-sysrq-restricted.conf || { log "muster.beyond.sysrq_restricted: backup failed, nothing changed"; return 1; }
  save_sysctl kernel.sysrq || { log "muster.beyond.sysrq_restricted: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-sysrq-restricted.conf
    if [ -L "$f" ]; then log "muster.beyond.sysrq_restricted: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    first=${P_allowed_sysrq%% *}
    case " $P_allowed_sysrq " in *" $(sysctl -n kernel.sysrq) "*) ;; *) put kernel.sysrq "$first";; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.sysrq_restricted: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-sysrq-restricted.conf || log "muster.beyond.sysrq_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.sysrq || log "muster.beyond.sysrq_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case " $P_allowed_sysrq " in *" $(sysctl -n kernel.sysrq) "*) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.sysrq_restricted: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-sysrq-restricted.conf || log "muster.beyond.sysrq_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.sysrq || log "muster.beyond.sysrq_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.sysrq_restricted: done"
}
fix_muster_beyond_sysrq_restricted
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 16/32 muster.beyond.icmp_broadcast_and_bogus_ignored [risk none] [fail, low]
# why: clause does not hold
# do:  Write net.ipv4.icmp_echo_ignore_broadcasts = 1 and net.ipv4.icmp_ignore_bogus_error_responses = 1 into /etc/sysctl.d/99-muster-icmp-broadcast-and-bogus-ignored.conf and apply it with sysctl --system; they take effect at once. A file that sets either to 0 is the one to find and fix first. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-icmp-broadcast-and-bogus-ignored.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-icmp-broadcast-and-bogus-ignored.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-icmp-broadcast-and-bogus-ignored.conf 에 net.ipv4.icmp_echo_ignore_broadcasts = 1 과 net.ipv4.icmp_ignore_bogus_error_responses = 1 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 둘 중 하나를 0 으로 설정한 파일을 먼저 찾아 고치십시오. /etc/sysctl.conf나 99-muster-icmp-broadcast-and-bogus-ignored.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-icmp-broadcast-and-bogus-ignored.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_icmp_broadcast_and_bogus_ignored() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_icmp_broadcast_and_bogus_ignored"; mkdir -p "$MB" || { log "muster.beyond.icmp_broadcast_and_bogus_ignored: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-icmp-broadcast-and-bogus-ignored.conf || { log "muster.beyond.icmp_broadcast_and_bogus_ignored: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses || { log "muster.beyond.icmp_broadcast_and_bogus_ignored: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-icmp-broadcast-and-bogus-ignored.conf
    if [ -L "$f" ]; then log "muster.beyond.icmp_broadcast_and_bogus_ignored: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)" in 1) ;; *) put net.ipv4.icmp_echo_ignore_broadcasts 1;; esac
    case "$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses)" in 1) ;; *) put net.ipv4.icmp_ignore_bogus_error_responses 1;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.icmp_broadcast_and_bogus_ignored: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-icmp-broadcast-and-bogus-ignored.conf || log "muster.beyond.icmp_broadcast_and_bogus_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses || log "muster.beyond.icmp_broadcast_and_bogus_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)" in 1) ;; *) false;; esac && case "$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses)" in 1) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.icmp_broadcast_and_bogus_ignored: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-icmp-broadcast-and-bogus-ignored.conf || log "muster.beyond.icmp_broadcast_and_bogus_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses || log "muster.beyond.icmp_broadcast_and_bogus_ignored: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.icmp_broadcast_and_bogus_ignored: done"
}
fix_muster_beyond_icmp_broadcast_and_bogus_ignored
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 17/32 muster.beyond.unprivileged_bpf_restricted [risk none] [fail, low]
# why: clause does not hold
# do:  Write kernel.unprivileged_bpf_disabled = 2 (1 locks the setting until reboot, so the review script writes 2 and leaves a host already at 1 alone) and net.core.bpf_jit_harden = 2 into /etc/sysctl.d/99-muster-unprivileged-bpf-restricted.conf and apply it with sysctl --system. Check first whether any observability or container-networking agent on the host loads BPF programs as an unprivileged account; those agents normally run with CAP_BPF and are unaffected, and constant blinding costs throughput on a host whose packet path is BPF-based. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-unprivileged-bpf-restricted.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-unprivileged-bpf-restricted.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-unprivileged-bpf-restricted.conf 에 kernel.unprivileged_bpf_disabled = 2(1은 재부팅 전까지 설정을 잠그므로 검토 스크립트는 2를 쓰고, 이미 1인 호스트는 그대로 둡니다) 와 net.core.bpf_jit_harden = 2 를 적고 sysctl --system 으로 적용합니다. 호스트의 관측·컨테이너 네트워킹 에이전트가 비권한 계정으로 BPF 프로그램을 적재하지는 않는지 먼저 확인하십시오. 그런 에이전트는 보통 CAP_BPF 로 실행되어 영향을 받지 않으며, 상수 가림은 패킷 경로가 BPF 기반인 호스트에서 처리량 비용이 있습니다. /etc/sysctl.conf나 99-muster-unprivileged-bpf-restricted.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-unprivileged-bpf-restricted.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_unprivileged_bpf_restricted() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_unprivileged_bpf_restricted"; mkdir -p "$MB" || { log "muster.beyond.unprivileged_bpf_restricted: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-unprivileged-bpf-restricted.conf || { log "muster.beyond.unprivileged_bpf_restricted: backup failed, nothing changed"; return 1; }
  save_sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden || { log "muster.beyond.unprivileged_bpf_restricted: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-unprivileged-bpf-restricted.conf
    if [ -L "$f" ]; then log "muster.beyond.unprivileged_bpf_restricted: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    case "$(sysctl -n kernel.unprivileged_bpf_disabled)" in 1|2) ;; *) put kernel.unprivileged_bpf_disabled 2;; esac
    case "$(sysctl -n net.core.bpf_jit_harden)" in 1|2) ;; *) put net.core.bpf_jit_harden 2;; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.unprivileged_bpf_restricted: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-unprivileged-bpf-restricted.conf || log "muster.beyond.unprivileged_bpf_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden || log "muster.beyond.unprivileged_bpf_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(sysctl -n kernel.unprivileged_bpf_disabled)" in 1|2) ;; *) false;; esac && case "$(sysctl -n net.core.bpf_jit_harden)" in 1|2) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.unprivileged_bpf_restricted: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-unprivileged-bpf-restricted.conf || log "muster.beyond.unprivileged_bpf_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden || log "muster.beyond.unprivileged_bpf_restricted: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.unprivileged_bpf_restricted: done"
}
fix_muster_beyond_unprivileged_bpf_restricted
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 18/32 muster.file.hosts_lpd_permissions [risk none] [fail, low]
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

# ---- 19/32 muster.file.hosts_permissions [risk restart_service] [fail, high]
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

# ---- 20/32 muster.service.automount_disabled [risk restart_service] [fail, high]
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

# ---- 21/32 muster.service.dos_services_disabled [risk restart_service] [fail, high]
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

# ---- 22/32 muster.service.finger_disabled [risk restart_service] [fail, high]
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

# ---- 23/32 muster.service.nfs_server_disabled [risk restart_service] [fail, high]
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

# ---- 24/32 muster.service.rpcbind_disabled [risk restart_service] [fail, high]
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

# ---- 25/32 muster.service.rservices_disabled [risk restart_service] [fail, high]
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

# ---- 26/32 muster.service.tftp_talk_disabled [risk restart_service] [fail, high]
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

# ---- 27/32 muster.beyond.ip_forwarding_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv4.ip_forward = 0 into /etc/sysctl.d/99-muster-ip-forwarding-disabled.conf and apply it with sysctl --system; it takes effect at once. Check first that the host is not a router, VPN gateway or container host - turning forwarding off there cuts its clients and containers off the network; such a host names 1 in params.allowed_forward instead; writing 0 cuts forwarding at once on a router or a container host. The kernel resets net.ipv4.conf.all.accept_redirects whenever forwarding changes, so the review script puts back the value it read before the write and keeps it in the file only when that value is 0. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ip-forwarding-disabled.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ip-forwarding-disabled.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-ip-forwarding-disabled.conf 에 net.ipv4.ip_forward = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 먼저 호스트가 라우터, VPN 게이트웨이, 컨테이너 호스트가 아닌지 확인하십시오. 그런 호스트에서 포워딩을 끄면 클라이언트와 컨테이너가 네트워크에서 끊기므로, 대신 params.allowed_forward 에 1 을 적습니다. 0을 쓰면 라우터나 컨테이너 호스트의 포워딩이 바로 끊깁니다. 커널은 포워딩이 바뀔 때마다 net.ipv4.conf.all.accept_redirects 를 다시 설정하므로, 검토 스크립트는 쓰기 전에 읽은 값을 되돌려 놓고 그 값이 0일 때만 파일에 남깁니다. /etc/sysctl.conf나 99-muster-ip-forwarding-disabled.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ip-forwarding-disabled.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_ip_forwarding_disabled() {
  P_allowed_forward='0'
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_ip_forwarding_disabled"; mkdir -p "$MB" || { log "muster.beyond.ip_forwarding_disabled: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-ip-forwarding-disabled.conf || { log "muster.beyond.ip_forwarding_disabled: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects || { log "muster.beyond.ip_forwarding_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-ip-forwarding-disabled.conf
    if [ -L "$f" ]; then log "muster.beyond.ip_forwarding_disabled: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    first=${P_allowed_forward%% *}
    case " $P_allowed_forward " in
      *" $(sysctl -n net.ipv4.ip_forward) "*) ;;
      *) r=$(sysctl -n net.ipv4.conf.all.accept_redirects)
         put net.ipv4.ip_forward "$first"
         if [ "$r" = 0 ]; then put net.ipv4.conf.all.accept_redirects 0
         elif [ "$(sysctl -n net.ipv4.conf.all.accept_redirects)" != "$r" ]; then sysctl -q -w "net.ipv4.conf.all.accept_redirects=$r"; fi;;
    esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ip_forwarding_disabled: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-ip-forwarding-disabled.conf || log "muster.beyond.ip_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects || log "muster.beyond.ip_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case " $P_allowed_forward " in *" $(sysctl -n net.ipv4.ip_forward) "*) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ip_forwarding_disabled: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-ip-forwarding-disabled.conf || log "muster.beyond.ip_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects || log "muster.beyond.ip_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.ip_forwarding_disabled: done"
}
fix_muster_beyond_ip_forwarding_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 28/32 muster.beyond.ipv6_forwarding_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv6.conf.all.forwarding = 0 and net.ipv6.conf.default.forwarding = 0 into /etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf and apply it with sysctl --system; they take effect at once. A router, VPN gateway or container host names 1 in params.allowed_forward instead - turning forwarding off there cuts its clients off. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ipv6-forwarding-disabled.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ipv6-forwarding-disabled.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf 에 net.ipv6.conf.all.forwarding = 0 과 net.ipv6.conf.default.forwarding = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 라우터, VPN 게이트웨이, 컨테이너 호스트는 포워딩을 끄면 클라이언트가 끊기므로 대신 params.allowed_forward 에 1 을 적습니다. /etc/sysctl.conf나 99-muster-ipv6-forwarding-disabled.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ipv6-forwarding-disabled.conf 는 그대로 두고 그 블록을 멈춥니다.
fix_muster_beyond_ipv6_forwarding_disabled() {
  P_allowed_forward='0'
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_ipv6_forwarding_disabled"; mkdir -p "$MB" || { log "muster.beyond.ipv6_forwarding_disabled: backup failed, nothing changed"; return 1; }
  backup /etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf || { log "muster.beyond.ipv6_forwarding_disabled: backup failed, nothing changed"; return 1; }
  save_sysctl net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding || { log "muster.beyond.ipv6_forwarding_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf
    if [ -L "$f" ]; then log "muster.beyond.ipv6_forwarding_disabled: $f is a symlink (a mask), left as is"; exit 1; fi
    put() {
      sysctl -q -w "$1=$2"
      if grep -q "^$1 " "$f" 2>/dev/null; then sed -i "s|^$1 .*|$1 = $2|" "$f"; else printf '%s = %s\n' "$1" "$2" >> "$f"; fi
    }
    first=${P_allowed_forward%% *}
    case " $P_allowed_forward " in *" $(sysctl -n net.ipv6.conf.all.forwarding) "*) ;; *) put net.ipv6.conf.all.forwarding "$first";; esac
    case " $P_allowed_forward " in *" $(sysctl -n net.ipv6.conf.default.forwarding) "*) ;; *) put net.ipv6.conf.default.forwarding "$first";; esac
    if [ -f "$f" ] && [ ! -L "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_forwarding_disabled: script failed (rc $rc), rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf || log "muster.beyond.ipv6_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding || log "muster.beyond.ipv6_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case " $P_allowed_forward " in *" $(sysctl -n net.ipv6.conf.all.forwarding) "*) ;; *) false;; esac && case " $P_allowed_forward " in *" $(sysctl -n net.ipv6.conf.default.forwarding) "*) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.ipv6_forwarding_disabled: validate failed, rolling back"
    restore /etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf || log "muster.beyond.ipv6_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_sysctl net.ipv6.conf.all.forwarding net.ipv6.conf.default.forwarding || log "muster.beyond.ipv6_forwarding_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.ipv6_forwarding_disabled: done"
}
fix_muster_beyond_ipv6_forwarding_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 29/32 muster.service.snmp_disabled [risk restart_service] [fail, medium]
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

# ---- 30/32 muster.service.telnet_disabled [risk restart_service] [fail, medium]
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

# ---- 31/32 muster.account.root_remote_login [risk lockout_risk] [fail, high]
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

# ---- 32/32 muster.service.nis_disabled [risk lockout_risk] [fail, high]
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
