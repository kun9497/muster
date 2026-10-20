#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host host-a, collected 2026-10-08T00:00:00Z; controls test+1 sha256:c0
# profile default (sha256:p0); max-risk lockout_risk
# planned 56 (script 56, text only 0); above max-risk 0; not planned: error 0, manual 0, warn_degraded 0
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

# ---- 1/56 muster.account.cron_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chmod 0640 the crontab-format files (/etc/crontab, /etc/cron.d/*, user spools), chown system files to root, chmod go-w (0640 breaks run-parts) the /etc/cron.{hourly,daily,weekly,monthly} directories and scripts, and chmod o-w the cron directories. A pending at job keeps its execute bit, so this control stays FAIL until it has run. On Debian and Ubuntu a root-group access file gets group crontab (cron.allow, cron.deny) or daemon (at.allow, at.deny). A system crontab (/etc/crontab, /etc/anacrontab, /etc/cron.d/*) not owned by root is never chowned (cron ignores it, and adopting it would run what another user wrote); the block logs it and rolls back, so review it and chown it by hand. The script never follows a symlink; it fixes the directories first, then changes files only in a directory root-owned and not world-writable up to / (a root-owned group-writable one, like the crontabs spool, is trusted with its group); any other, like a daemon-owned at spool, is left to the operator.
# ko:  crontab 형식 파일(/etc/crontab, /etc/cron.d/*, 사용자별 스풀)에 chmod 0640 을 적용하고 시스템 파일을 root 로 chown 하며, /etc/cron.{hourly,daily,weekly,monthly} 주기 스크립트 디렉터리와 그 스크립트에는 (run-parts 를 깨뜨리는 0640 이 아니라) chmod go-w 를 적용하고, cron 디렉터리에 chmod o-w 를 적용합니다. 대기 중인 at 작업은 실행 가능 표시인 실행 비트를 유지하므로, 그 작업이 실행될 때까지 이 control은 FAIL로 남습니다. 검토 스크립트는 그 비트를 지우지 않습니다. Debian 과 Ubuntu 에서는 그룹이 root 인 접근 제어 파일에 crontab(cron.allow, cron.deny) 또는 daemon(at.allow, at.deny) 그룹을 줍니다. root 소유가 아닌 시스템 crontab(/etc/crontab, /etc/anacrontab, /etc/cron.d/*)은 chown 하지 않습니다. cron 은 지금 그 파일을 무시하며, 그 파일을 넘겨받으면 다른 사용자가 쓴 내용이 실행됩니다. 검토 스크립트는 이를 기록하고 블록은 실패해 되돌아가므로, 내용을 검토한 뒤 직접 chown 하십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않습니다. cron 디렉터리를 먼저 고친 뒤, / 까지 root 소유이고 전체 쓰기가 불가능한 디렉터리 안의 파일만 바꿉니다. Debian 의 crontabs 스풀처럼 root 소유이면서 그룹 쓰기가 가능한 디렉터리는 그 그룹과 함께 신뢰합니다. daemon 소유 at 스풀 같은 그 밖의 디렉터리는 운영자에게 맡깁니다.
fix_muster_account_cron_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_cron_permissions"; mkdir -p "$MB" || { log "muster.account.cron_permissions: backup failed, nothing changed"; return 1; }
  save_modes '/etc/crontab' '/etc/anacrontab' '/etc/cron.allow' '/etc/cron.deny' '/etc/at.allow' '/etc/at.deny' '/etc/cron.d/*' '/etc/cron.d' '/etc/cron.hourly' '/etc/cron.daily' '/etc/cron.weekly' '/etc/cron.monthly' '/etc/cron.hourly/*' '/etc/cron.daily/*' '/etc/cron.weekly/*' '/etc/cron.monthly/*' '/var/spool/cron' '/var/spool/cron/*' '/var/spool/cron/crontabs' '/var/spool/cron/crontabs/*' '/var/spool/cron/atjobs' '/var/spool/cron/atjobs/*' '/var/spool/at' '/var/spool/at/*' || { log "muster.account.cron_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    for c in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/at; do
      if [ -d "$c" ] && [ ! -L "$c" ]; then chmod o-w "$c"; fi
    done
    for p in /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        u=$(stat -c %u "$p")
        case "$p" in
          /etc/crontab|/etc/anacrontab) if [ "$u" != 0 ]; then log "muster.account.cron_permissions: $p is owned by uid $u; review it before chown root, left as is"; continue; fi;;
        esac
        chown root "$p"
        if [ "$(stat -c %g "$p")" = 0 ]; then
          case "$p" in
            /etc/cron.allow|/etc/cron.deny) if getent group crontab >/dev/null; then chgrp crontab "$p"; fi;;
            /etc/at.allow|/etc/at.deny) a=$(command -v at || :); if [ -n "$a" ] && [ -g "$a" ] && [ "$(stat -c %G "$a")" = daemon ]; then chgrp daemon "$p"; fi;;
          esac
        fi
        chmod u-xs,g-wxs,o-rwxt "$p"
      fi
    done
    if [ -d /etc/cron.d ] && [ ! -L /etc/cron.d ]; then
      if modes_trusted /etc/cron.d/. 0; then
        find /etc/cron.d -mindepth 1 -maxdepth 1 -type f ! -user root -printf '%U %p\n' | while read -r u f; do log "muster.account.cron_permissions: $f is owned by uid $u; review it before chown root, left as is"; done
        find /etc/cron.d -mindepth 1 -maxdepth 1 -type f -user root -exec chmod u-xs,g-wxs,o-rwxt {} +
      else
        log "muster.account.cron_permissions: /etc/cron.d is not root's, left as is"
      fi
    fi
    for c in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
      if [ -d "$c" ] && [ ! -L "$c" ]; then
        if modes_trusted "$c/." 0; then
          find "$c" -mindepth 1 -maxdepth 1 -type f -exec chown root {} + -exec chmod o-w {} +
        else
          log "muster.account.cron_permissions: $c is not root's, left as is"
        fi
      fi
    done
    for c in /var/spool/cron /var/spool/cron/crontabs; do
      if [ -d "$c" ] && [ ! -L "$c" ]; then
        if modes_trusted "$c/." 0; then
          find "$c" -mindepth 1 -maxdepth 1 -type f -exec chmod u-xs,g-wxs,o-rwxt {} +
        else
          log "muster.account.cron_permissions: $c is not root's, left as is"
        fi
      fi
    done
    for s in /var/spool/cron/atjobs /var/spool/at; do
      if [ -d "$s" ] && [ ! -L "$s" ]; then
        if modes_trusted "$s/." 0; then
          find "$s" -mindepth 1 -maxdepth 1 -type f -exec chmod u-s,g-wxs,o-rwxt {} +
        elif [ -n "$(find "$s" -mindepth 1 -maxdepth 1 -type f -perm /7037 2>/dev/null)" ]; then
          log "muster.account.cron_permissions: $s is not root's, left as is"
        fi
      fi
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.cron_permissions: script failed (rc $rc), rolling back"
    restore_modes || log "muster.account.cron_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    [ -z "$(find /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny -maxdepth 0 -type f \( -perm /7137 -o ! -user root \) 2>/dev/null)" ] && { [ ! -d /etc/cron.d ] || [ -L /etc/cron.d ] || ! modes_trusted /etc/cron.d/. 0 || [ -z "$(find /etc/cron.d -mindepth 1 -maxdepth 1 -type f \( -perm /7137 -o ! -user root \) 2>/dev/null)" ]; } && for c in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do if [ -d "$c" ] && [ ! -L "$c" ] && modes_trusted "$c/." 0 && [ -n "$(find "$c" -mindepth 1 -maxdepth 1 -type f \( -perm /002 -o ! -user root \) 2>/dev/null)" ]; then exit 1; fi; done && for c in /var/spool/cron /var/spool/cron/crontabs; do if [ -d "$c" ] && [ ! -L "$c" ] && modes_trusted "$c/." 0 && [ -n "$(find "$c" -mindepth 1 -maxdepth 1 -type f -perm /7137 2>/dev/null)" ]; then exit 1; fi; done && for s in /var/spool/cron/atjobs /var/spool/at; do if [ -d "$s" ] && [ ! -L "$s" ] && modes_trusted "$s/." 0 && [ -n "$(find "$s" -mindepth 1 -maxdepth 1 -type f -perm /7037 2>/dev/null)" ]; then exit 1; fi; done && [ -z "$(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/at -maxdepth 0 -type d -perm /002 2>/dev/null)" ]
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.cron_permissions: validate failed, rolling back"
    restore_modes || log "muster.account.cron_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.cron_permissions: done"
}
fix_muster_account_cron_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 2/56 muster.beyond.aslr_and_link_protection [risk none] [fail, high]
# why: clause does not hold
# do:  Write kernel.randomize_va_space = 2, fs.protected_symlinks = 1, fs.protected_hardlinks = 1, fs.protected_fifos = 1 and fs.protected_regular = 2 into /etc/sysctl.d/99-muster-aslr-and-link-protection.conf and apply it with sysctl --system. All five take effect at once and need no reboot. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-aslr-and-link-protection.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-aslr-and-link-protection.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-aslr-and-link-protection.conf 에 kernel.randomize_va_space = 2, fs.protected_symlinks = 1, fs.protected_hardlinks = 1, fs.protected_fifos = 1, fs.protected_regular = 2 를 적고 sysctl --system 으로 적용합니다. 다섯 값 모두 즉시 반영되며 재부팅이 필요 없습니다. /etc/sysctl.conf나 99-muster-aslr-and-link-protection.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-aslr-and-link-protection.conf 는 그대로 두고 그 블록을 멈춥니다.
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

# ---- 3/56 muster.beyond.bootloader_config_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chmod 0600 and chown root:root the grub.cfg your distribution uses (/boot/grub/grub.cfg on Debian and Ubuntu, /boot/grub2/grub.cfg on the EL family, plus the EFI copy where one exists). Regenerating the file with grub-mkconfig keeps the mode, so the change survives a kernel update; a grub.cfg on a FAT EFI system partition cannot carry a Unix mode at all and is governed by the mount options of /boot/efi instead. A grub.cfg on the EFI system partition takes its mode from the mount's fmask, set in fstab (fmask=0177); the review script leaves it. The review script never follows a symlink.
# ko:  배포판이 쓰는 grub.cfg(Debian·Ubuntu 는 /boot/grub/grub.cfg, EL 계열은 /boot/grub2/grub.cfg, EFI 사본이 있으면 그것도)에 chmod 0600 과 chown root:root 을 적용합니다. grub-mkconfig 로 파일을 다시 생성해도 mode 가 유지되므로 커널 업데이트 후에도 설정이 남습니다. FAT 인 EFI 시스템 파티션의 grub.cfg 는 Unix mode 를 가질 수 없으므로 대신 /boot/efi 의 마운트 옵션이 그 역할을 합니다. EFI 시스템 파티션의 grub.cfg는 마운트의 fmask에서 모드를 받으므로 fstab에서 정합니다(fmask=0177). 검토 스크립트는 그대로 둡니다. 검토 스크립트는 심볼릭 링크를 따라가지 않습니다.
fix_muster_beyond_bootloader_config_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_bootloader_config_permissions"; mkdir -p "$MB" || { log "muster.beyond.bootloader_config_permissions: backup failed, nothing changed"; return 1; }
  backup /boot/grub/grub.cfg /boot/grub2/grub.cfg || { log "muster.beyond.bootloader_config_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    for p in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root:root "$p"
        chmod u-xs,g-rwxs,o-rwxt "$p"
      fi
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.bootloader_config_permissions: script failed (rc $rc), rolling back"
    restore /boot/grub/grub.cfg /boot/grub2/grub.cfg || log "muster.beyond.bootloader_config_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    for p in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do [ ! -f "$p" ] || [ -L "$p" ] || case "$(stat -c '%u %g %a' "$p")" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) exit 1;; esac; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.bootloader_config_permissions: validate failed, rolling back"
    restore /boot/grub/grub.cfg /boot/grub2/grub.cfg || log "muster.beyond.bootloader_config_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.bootloader_config_permissions: done"
}
fix_muster_beyond_bootloader_config_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 4/56 muster.file.inetd_conf_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chmod 0600 /etc/inetd.conf or /etc/xinetd.conf and its fragments, chown them to root, and prefer removing the super-server if no service needs it. The review script never follows a symlink.
# ko:  /etc/inetd.conf 또는 /etc/xinetd.conf 와 그 조각에 chmod 0600 을 적용하고 root 로 chown 하며, 필요한 서비스가 없으면 슈퍼서버 제거를 우선합니다. 검토 스크립트는 심볼릭 링크를 따라가지 않습니다.
fix_muster_file_inetd_conf_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_inetd_conf_permissions"; mkdir -p "$MB" || { log "muster.file.inetd_conf_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/inetd.conf /etc/xinetd.conf || { log "muster.file.inetd_conf_permissions: backup failed, nothing changed"; return 1; }
  save_modes '/etc/xinetd.d/*' || { log "muster.file.inetd_conf_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    for p in /etc/inetd.conf /etc/xinetd.conf; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root "$p"
        chmod u-xs,g-rwxs,o-rwxt "$p"
      fi
    done
    if [ -d /etc/xinetd.d ] && [ ! -L /etc/xinetd.d ]; then
      find /etc/xinetd.d -mindepth 1 -maxdepth 1 -type f -exec chmod go-w {} +
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.inetd_conf_permissions: script failed (rc $rc), rolling back"
    restore_modes || log "muster.file.inetd_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore /etc/inetd.conf /etc/xinetd.conf || log "muster.file.inetd_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    { [ ! -f /etc/inetd.conf ] || [ -L /etc/inetd.conf ] || [ -z "$(find /etc/inetd.conf \( -perm /024 -o ! -user root \))" ]; } && { [ ! -f /etc/xinetd.conf ] || [ -L /etc/xinetd.conf ] || case "$(stat -c '%u %a' /etc/xinetd.conf)" in '0 0'|'0 200'|'0 400'|'0 600') ;; *) false;; esac; } && [ -z "$(find /etc/xinetd.d -mindepth 1 -maxdepth 1 -type f -perm /022 2>/dev/null)" ]
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.inetd_conf_permissions: validate failed, rolling back"
    restore_modes || log "muster.file.inetd_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore /etc/inetd.conf /etc/xinetd.conf || log "muster.file.inetd_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.inetd_conf_permissions: done"
}
fix_muster_file_inetd_conf_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 5/56 muster.file.passwd_permissions [risk none] [fail, high]
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

# ---- 6/56 muster.file.services_permissions [risk none] [fail, high]
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

# ---- 7/56 muster.file.shadow_permissions [risk none] [fail, high]
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

# ---- 8/56 muster.file.syslog_conf_permissions [risk none] [fail, high]
# why: clause does not hold
# do:  chmod 0640 /etc/rsyslog.conf and the files under /etc/rsyslog.d, and chown them to root; investigate any config that could not be read. The review script never follows a symlink.
# ko:  /etc/rsyslog.conf 와 /etc/rsyslog.d 아래 파일에 chmod 0640 을 적용하고 root 로 chown 하며, 읽을 수 없었던 설정은 조사합니다. 검토 스크립트는 심볼릭 링크를 따라가지 않습니다.
fix_muster_file_syslog_conf_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_syslog_conf_permissions"; mkdir -p "$MB" || { log "muster.file.syslog_conf_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/rsyslog.conf /etc/systemd/journald.conf /etc/syslog-ng/syslog-ng.conf || { log "muster.file.syslog_conf_permissions: backup failed, nothing changed"; return 1; }
  save_modes '/etc/rsyslog.d/*' '/etc/systemd/journald.conf.d/*' '/etc/syslog-ng/conf.d/*' || { log "muster.file.syslog_conf_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    for p in /etc/rsyslog.conf /etc/systemd/journald.conf /etc/syslog-ng/syslog-ng.conf; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root "$p"
        chmod u-xs,g-wxs,o-rwxt "$p"
      fi
    done
    for d in /etc/rsyslog.d /etc/systemd/journald.conf.d /etc/syslog-ng/conf.d; do
      if [ -d "$d" ] && [ ! -L "$d" ]; then
        find "$d" -mindepth 1 -maxdepth 1 -type f -name '*.conf' -exec chown root {} + -exec chmod u-xs,g-wxs,o-rwxt {} +
      fi
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.syslog_conf_permissions: script failed (rc $rc), rolling back"
    restore_modes || log "muster.file.syslog_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore /etc/rsyslog.conf /etc/systemd/journald.conf /etc/syslog-ng/syslog-ng.conf || log "muster.file.syslog_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    for p in /etc/rsyslog.conf /etc/systemd/journald.conf /etc/syslog-ng/syslog-ng.conf /etc/rsyslog.d /etc/systemd/journald.conf.d /etc/syslog-ng/conf.d; do [ ! -e "$p" ] || [ -L "$p" ] || [ -z "$(find "$p" -maxdepth 1 -type f \( -path "$p" -o -name '*.conf' \) \( -perm /7137 -o ! -user root \))" ] || exit 1; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.syslog_conf_permissions: validate failed, rolling back"
    restore_modes || log "muster.file.syslog_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore /etc/rsyslog.conf /etc/systemd/journald.conf /etc/syslog-ng/syslog-ng.conf || log "muster.file.syslog_conf_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.syslog_conf_permissions: done"
}
fix_muster_file_syslog_conf_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 9/56 muster.account.sudoers_permissions [risk none] [fail, medium]
# why: clause does not hold
# do:  chmod 0440 /etc/sudoers and chown it to root; chmod go-w each active file under /etc/sudoers.d. A sudoers file (/etc/sudoers or an active file under /etc/sudoers.d) not owned by root is never chowned or re-moded - sudo refuses it today, and adopting it would activate rules another user wrote; the review script logs it and the block fails and rolls back, so review its content and chown it by hand.
# ko:  /etc/sudoers 에 chmod 0440 을 적용하고 root 로 chown 하며, /etc/sudoers.d 아래 활성 파일에 chmod go-w 를 적용합니다. root 소유가 아닌 sudoers 파일(/etc/sudoers 나 /etc/sudoers.d 아래 활성 파일)은 chown 하거나 모드를 바꾸지 않습니다. sudo 는 지금 그 파일을 거부하며, 그 파일을 넘겨받으면 다른 사용자가 쓴 규칙이 활성화됩니다. 검토 스크립트는 이를 기록하고 블록은 실패해 되돌아가므로, 내용을 검토한 뒤 직접 chown 하십시오.
fix_muster_account_sudoers_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_sudoers_permissions"; mkdir -p "$MB" || { log "muster.account.sudoers_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/sudoers || { log "muster.account.sudoers_permissions: backup failed, nothing changed"; return 1; }
  save_modes '/etc/sudoers.d/*' || { log "muster.account.sudoers_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    if [ -f /etc/sudoers ] && [ ! -L /etc/sudoers ]; then
      u=$(stat -c %u /etc/sudoers)
      if [ "$u" = 0 ]; then
        chmod u-wxs,g-wxs,o-rwxt /etc/sudoers
      else
        log "muster.account.sudoers_permissions: /etc/sudoers is owned by uid $u; review it before chown root, left as is"
      fi
    fi
    if [ -d /etc/sudoers.d ] && [ ! -L /etc/sudoers.d ]; then
      find /etc/sudoers.d -mindepth 1 -maxdepth 1 -type f ! -name '*.*' ! -name '*~' ! -user root -printf '%U %p\n' | while read -r u f; do log "muster.account.sudoers_permissions: $f is owned by uid $u; review it before chown root, left as is"; done
      find /etc/sudoers.d -mindepth 1 -maxdepth 1 -type f ! -name '*.*' ! -name '*~' -user root -exec chmod go-w {} +
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.sudoers_permissions: script failed (rc $rc), rolling back"
    restore_modes || log "muster.account.sudoers_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore /etc/sudoers || log "muster.account.sudoers_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case "$(stat -c '%u %a' /etc/sudoers)" in '0 0'|'0 40'|'0 400'|'0 440') ;; *) false;; esac && [ -z "$(find /etc/sudoers.d -mindepth 1 -maxdepth 1 -type f ! -name '*.*' ! -name '*~' \( ! -user root -o -perm /022 \) 2>/dev/null)" ]
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.sudoers_permissions: validate failed, rolling back"
    restore_modes || log "muster.account.sudoers_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore /etc/sudoers || log "muster.account.sudoers_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.sudoers_permissions: done"
}
fix_muster_account_sudoers_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 10/56 muster.account.umask_policy [risk none] [fail, medium]
# why: clause does not hold
# do:  Set UMASK 027 in /etc/login.defs and ensure a "session optional pam_umask.so" line is present in the login and non-login PAM session stacks (pam-auth-update on Debian, authselect on RHEL). The review script sets UMASK in /etc/login.defs only and never edits a PAM stack, so on a host without a pam_umask line the block ends done and the control still FAILs. A symlinked /etc/login.defs is never followed; the block stops.
# ko:  /etc/login.defs 에 UMASK 027 을 설정하고 로그인·비로그인 PAM 세션 스택에 "session optional pam_umask.so" 줄이 있게 합니다(Debian 은 pam-auth-update, RHEL 은 authselect). 검토 스크립트는 /etc/login.defs 의 UMASK 만 고치며 PAM 스택은 건드리지 않으므로, pam_umask 줄이 없는 호스트에서는 블록이 done 으로 끝나도 이 control은 FAIL로 남습니다. 심볼릭 링크인 /etc/login.defs 는 따라가지 않고 그 블록을 멈춥니다.
fix_muster_account_umask_policy() {
  P_acceptable='027 022 077 0027 0022 0077'
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_umask_policy"; mkdir -p "$MB" || { log "muster.account.umask_policy: backup failed, nothing changed"; return 1; }
  backup /etc/login.defs || { log "muster.account.umask_policy: backup failed, nothing changed"; return 1; }
  ( set -e
    ld=/etc/login.defs
    if [ -L "$ld" ]; then log "muster.account.umask_policy: $ld is a symlink, left as is"; exit 1; fi
    first=${P_acceptable%% *}
    v=$(awk '$1 == "UMASK" { print $2; exit }' "$ld")
    case " $P_acceptable " in
      *" $v "*) ;;
      *) if grep -Eq '^[[:space:]]*UMASK[[:space:]]' "$ld"; then sed -i -E "s|^([[:space:]]*UMASK)[[:space:]].*|\1 $first|" "$ld"; else printf 'UMASK %s\n' "$first" >> "$ld"; fi;;
    esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.umask_policy: script failed (rc $rc), rolling back"
    restore /etc/login.defs || log "muster.account.umask_policy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    case " $P_acceptable " in *" $(awk '$1 == "UMASK" { print $2; exit }' /etc/login.defs) "*) ;; *) false;; esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.umask_policy: validate failed, rolling back"
    restore /etc/login.defs || log "muster.account.umask_policy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.umask_policy: done"
}
fix_muster_account_umask_policy
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 11/56 muster.beyond.audit_log_permissions [risk none] [fail, medium]
# why: clause does not hold
# do:  chown root the audit log and its directory, chmod 0600 the log (0640 where log_group in auditd.conf names an administrators' group such as adm) and chmod 0700 the directory (0750 with such a group). auditd creates each rotated file with the mode and log_group its configuration gives, so set log_group to root or to a group only administrators belong to, rather than fixing the files alone. The review script changes owner and mode only; a log in a group outside params.allowed_groups needs chgrp or the group named in the parameter. A log_file that auditd.conf names elsewhere is yours to fix, as the review script changes /var/log/audit/audit.log and its directory alone. It fixes the directory first and changes the log only when the directories up to / are root-owned and not world-writable; otherwise the log is left to the operator.
# ko:  감사 로그와 그 디렉터리를 chown root 하고, 로그는 chmod 0600(auditd.conf 의 log_group 이 adm 같은 관리자 그룹을 지정하면 0640), 디렉터리는 chmod 0700(그런 그룹이면 0750)으로 둡니다. auditd 는 순환할 때마다 설정이 주는 mode 와 log_group 으로 새 파일을 만들므로 파일만 고치지 말고 log_group 을 root 나 관리자만 속한 그룹으로 설정하십시오. 검토 스크립트는 소유자와 모드만 바꿉니다. params.allowed_groups 밖 그룹의 로그는 chgrp하거나 그 그룹을 파라미터에 적어야 합니다. auditd.conf 의 log_file 이 다른 곳을 가리키면 그 파일은 운영자가 고쳐야 하며, 검토 스크립트는 /var/log/audit/audit.log 와 그 디렉터리만 바꿉니다. 디렉터리를 먼저 고치고, / 까지의 디렉터리가 root 소유이며 전체 쓰기가 불가능할 때만 로그를 바꿉니다. 그렇지 않으면 로그는 운영자에게 맡깁니다.
fix_muster_beyond_audit_log_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_audit_log_permissions"; mkdir -p "$MB" || { log "muster.beyond.audit_log_permissions: backup failed, nothing changed"; return 1; }
  save_modes '/var/log/audit/audit.log' '/var/log/audit' || { log "muster.beyond.audit_log_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    if [ -d /var/log/audit ] && [ ! -L /var/log/audit ]; then
      chown root /var/log/audit
      chmod g-w,o-rwx /var/log/audit
    fi
    if [ -f /var/log/audit/audit.log ] && [ ! -L /var/log/audit/audit.log ]; then
      if modes_trusted /var/log/audit/. 0; then
        chown root /var/log/audit/audit.log
        chmod u-xs,g-wxs,o-rwxt /var/log/audit/audit.log
      else
        log "muster.beyond.audit_log_permissions: /var/log/audit is not root's, left as is"
      fi
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.audit_log_permissions: script failed (rc $rc), rolling back"
    restore_modes || log "muster.beyond.audit_log_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    { [ ! -f /var/log/audit/audit.log ] || [ -L /var/log/audit/audit.log ] || ! modes_trusted /var/log/audit/. 0 || case "$(stat -c '%u %a' /var/log/audit/audit.log)" in '0 0'|'0 200'|'0 400'|'0 600'|'0 40'|'0 240'|'0 440'|'0 640') ;; *) false;; esac; } && [ -z "$(find /var/log/audit -maxdepth 0 \( -perm /026 -o ! -user root \))" ]
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.audit_log_permissions: validate failed, rolling back"
    restore_modes || log "muster.beyond.audit_log_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.audit_log_permissions: done"
}
fix_muster_beyond_audit_log_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 12/56 muster.beyond.icmp_redirects_ignored [risk none] [fail, medium]
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

# ---- 13/56 muster.beyond.ipv6_redirects_ignored [risk none] [fail, medium]
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

# ---- 14/56 muster.beyond.ipv6_router_advertisements_ignored [risk none] [fail, medium]
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

# ---- 15/56 muster.beyond.ipv6_source_routing_rejected [risk none] [fail, medium]
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

# ---- 16/56 muster.beyond.kernel_pointer_exposure [risk none] [fail, medium]
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

# ---- 17/56 muster.beyond.ptrace_restriction [risk none] [fail, medium]
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

# ---- 18/56 muster.beyond.source_routing_rejected [risk none] [fail, medium]
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

# ---- 19/56 muster.beyond.suid_dumpable_disabled [risk none] [fail, medium]
# why: clause does not hold
# do:  Write fs.suid_dumpable = 0 into /etc/sysctl.d/99-muster-suid-dumpable-disabled.conf and apply it with sysctl --system; it takes effect at once and needs no reboot. A crash-reporting tool that collects dumps from setuid programs stops receiving them, which is the intent. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-suid-dumpable-disabled.conf, still wins at boot; correct it there. On an Ubuntu host running apport, apport writes 2 to fs.suid_dumpable each time it starts, so the value returns at boot; disable apport or the fix does not last. The review script never follows a symlink; a 99-muster-suid-dumpable-disabled.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-suid-dumpable-disabled.conf 에 fs.suid_dumpable = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영되며 재부팅이 필요 없습니다. setuid 프로그램의 덤프를 수집하던 크래시 리포트 도구는 더 이상 그것을 받지 못하는데, 그것이 이 설정의 의도입니다. /etc/sysctl.conf나 99-muster-suid-dumpable-disabled.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. apport 가 실행되는 Ubuntu 호스트에서는 apport 가 시작할 때마다 fs.suid_dumpable 에 2 를 쓰므로 부팅 때 값이 되돌아옵니다. apport 를 끄지 않으면 이 수정은 유지되지 않습니다. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-suid-dumpable-disabled.conf 는 그대로 두고 그 블록을 멈춥니다.
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

# ---- 20/56 muster.beyond.syn_cookies_enabled [risk none] [fail, medium]
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

# ---- 21/56 muster.beyond.sysrq_restricted [risk none] [fail, medium]
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

# ---- 22/56 muster.beyond.uncommon_network_protocols_disabled [risk none] [fail, medium]
# why: clause does not hold
# do:  Write one install <name> /bin/false line per protocol into a file under /etc/modprobe.d, for example /etc/modprobe.d/99-muster-uncommon-network-protocols-disabled.conf, and rebuild the initramfs (the review script does not). A vendor file whose install line for the module loads it wins over this one; the review script's validate then fails and the block rolls back. The review script never follows a symlink; a 99-muster-uncommon-network-protocols-disabled.conf that is a symlink (a mask) is left as is and the block stops. A module that is already loaded stays loaded until it is unloaded (modprobe -r) or the host reboots; the review script unloads it, and fails and rolls back when the module is in use. Hosts that genuinely speak one of these — an SCTP signalling gateway, a TIPC cluster member, an RDS fabric — should carry a waiver naming the module instead of leaving the control undecided for all four.
# ko:  프로토콜마다 install <name> /bin/false 한 줄씩을 /etc/modprobe.d 아래 파일(예를 들어 /etc/modprobe.d/99-muster-uncommon-network-protocols-disabled.conf)에 적고 initramfs 를 다시 만듭니다(검토 스크립트는 하지 않습니다). 모듈을 적재하는 install 줄을 둔 벤더 파일이 이 파일을 이기며, 그때 검토 스크립트의 validate가 실패해 블록이 롤백됩니다. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-uncommon-network-protocols-disabled.conf 는 그대로 두고 그 블록을 멈춥니다. 이미 적재된 모듈은 내리거나(modprobe -r) 재부팅할 때까지 남아 있습니다. 검토 스크립트는 이를 내리며, 모듈이 사용 중이면 실패하고 롤백합니다. 이들 중 하나를 실제로 쓰는 호스트(SCTP 신호 게이트웨이, TIPC 클러스터 구성원, RDS 패브릭 등)는 네 개 전부를 미결로 두지 말고 해당 모듈을 지목하는 waiver 를 두십시오.
fix_muster_beyond_uncommon_network_protocols_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_uncommon_network_protocols_disabled"; mkdir -p "$MB" || { log "muster.beyond.uncommon_network_protocols_disabled: backup failed, nothing changed"; return 1; }
  backup /etc/modprobe.d/99-muster-uncommon-network-protocols-disabled.conf || { log "muster.beyond.uncommon_network_protocols_disabled: backup failed, nothing changed"; return 1; }
  save_modules dccp sctp rds tipc || { log "muster.beyond.uncommon_network_protocols_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/modprobe.d/99-muster-uncommon-network-protocols-disabled.conf
    if [ -L "$f" ]; then log "muster.beyond.uncommon_network_protocols_disabled: $f is a symlink (a mask), left as is"; exit 1; fi
    mods='dccp sctp rds tipc'
    for m in $mods; do
      n=$(printf '%s' "$m" | tr - _)
      case "$(modprobe --showconfig 2>/dev/null | awk -v m="$n" '$1 == "install" && $2 == m { print $3; exit }')" in
        /bin/false|/bin/true|/usr/bin/false|/usr/bin/true|false|true) ;;
        *) grep -q "^install $n " "$f" 2>/dev/null || printf 'install %s /bin/false\n' "$n" >> "$f";;
      esac
      if grep -q "^$n " /proc/modules; then modprobe -r -- "$n"; fi
    done
    if [ -f "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.uncommon_network_protocols_disabled: script failed (rc $rc), rolling back"
    restore /etc/modprobe.d/99-muster-uncommon-network-protocols-disabled.conf || log "muster.beyond.uncommon_network_protocols_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules dccp sctp rds tipc || log "muster.beyond.uncommon_network_protocols_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    mods='dccp sctp rds tipc'; for m in $mods; do n=$(printf '%s' "$m" | tr - _); case "$(modprobe --showconfig 2>/dev/null | awk -v m="$n" '$1 == "install" && $2 == m { print $3; exit }')" in /bin/false|/bin/true|/usr/bin/false|/usr/bin/true|false|true) ;; *) exit 1;; esac; ! grep -q "^$n " /proc/modules || exit 1; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.uncommon_network_protocols_disabled: validate failed, rolling back"
    restore /etc/modprobe.d/99-muster-uncommon-network-protocols-disabled.conf || log "muster.beyond.uncommon_network_protocols_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules dccp sctp rds tipc || log "muster.beyond.uncommon_network_protocols_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.uncommon_network_protocols_disabled: done"
}
fix_muster_beyond_uncommon_network_protocols_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 23/56 muster.file.log_dir_permissions [risk none] [fail, medium]
# why: clause does not hold
# do:  chmod o-w each world-writable log path; for a group-writable path owned by an unexpected group, chown it to root or a logging group, or add that group to the parameter if it is legitimate. The review script clears the others' write bit only; a group-writable path in a group outside params.allowed_groups is left for you to change. The review script never follows a symlink. It changes files only in a directory that is root-owned and not world-writable up to /; a root-owned group-writable directory such as /var/log is trusted with its group; any other directory is left to the operator and named in the log.
# ko:  전체 쓰기 가능한 로그 경로에 chmod o-w 를 적용하고, 예상치 못한 그룹이 소유한 그룹-쓰기 경로는 root 나 로깅 그룹으로 chown 하거나, 정당하면 그 그룹을 파라미터에 추가합니다. 검토 스크립트는 다른 사용자의 쓰기 비트만 지웁니다. params.allowed_groups 밖 그룹의 그룹-쓰기 경로는 직접 바꿔야 합니다. 검토 스크립트는 심볼릭 링크를 따라가지 않습니다. / 까지 root 소유이고 전체 쓰기가 불가능한 디렉터리 안의 파일만 바꿉니다. /var/log 처럼 root 소유이면서 그룹 쓰기가 가능한 디렉터리는 그 그룹과 함께 신뢰합니다. 그 밖의 디렉터리는 운영자에게 맡기고 로그에 이름을 남깁니다.
fix_muster_file_log_dir_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_log_dir_permissions"; mkdir -p "$MB" || { log "muster.file.log_dir_permissions: backup failed, nothing changed"; return 1; }
  save_modes '/var/log' '/var/log/*' '/var/log/*/*' || { log "muster.file.log_dir_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    if [ -d /var/log ] && [ ! -L /var/log ] && modes_trusted /var/log 0 && [ -n "$(find /var/log -maxdepth 0 -perm /002)" ]; then chmod o-w /var/log; fi
    for l in /var/log /var/log/* /var/log/.[!.]* /var/log/..?*; do
      if [ -d "$l" ] && [ ! -L "$l" ]; then
        if modes_trusted "$l/." 0; then
          find "$l" -mindepth 1 -maxdepth 1 ! -type l -perm /002 -exec chmod o-w {} +
        elif [ -n "$(find "$l" -mindepth 1 -maxdepth 1 ! -type l -perm /002 2>/dev/null)" ]; then
          log "muster.file.log_dir_permissions: $l is not root's, left as is"
        fi
      fi
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.log_dir_permissions: script failed (rc $rc), rolling back"
    restore_modes || log "muster.file.log_dir_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    if [ -d /var/log ] && [ ! -L /var/log ] && modes_trusted /var/log 0 && [ -n "$(find /var/log -maxdepth 0 -perm /002)" ]; then exit 1; fi; for l in /var/log /var/log/* /var/log/.[!.]* /var/log/..?*; do if [ -d "$l" ] && [ ! -L "$l" ] && modes_trusted "$l/." 0 && [ -n "$(find "$l" -mindepth 1 -maxdepth 1 ! -type l -perm /002 2>/dev/null)" ]; then exit 1; fi; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.log_dir_permissions: validate failed, rolling back"
    restore_modes || log "muster.file.log_dir_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.log_dir_permissions: done"
}
fix_muster_file_log_dir_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 24/56 muster.account.session_timeout [risk none] [fail, low]
# why: clause does not hold
# do:  Set a ClientAliveInterval of at most params.max_interval (default 300) and a ClientAliveCountMax of at most params.max_count in /etc/ssh/sshd_config.d/00-muster-session.conf, keeping a value already in range, validate with sshd -t, then reload sshd; an earlier ClientAliveInterval before the Include beats any drop-in. The review script never follows a symlink; a 00-muster-session.conf that is a symlink (a mask) is left as is and the block stops. On a host without sshd the review script changes nothing. Alternatively, since this control accepts either mechanism, set and export an interactive-shell TMOUT in a system profile file - for example a file under /etc/profile.d/ containing "readonly TMOUT=600; export TMOUT".
# ko:  /etc/ssh/sshd_config.d/00-muster-session.conf 에 params.max_interval(기본 300) 이하의 ClientAliveInterval 과 params.max_count 이하의 ClientAliveCountMax 를 설정하되 이미 범위 안에 있는 값은 유지하고, sshd -t 로 검증한 뒤 sshd 를 다시 읽힙니다(reload). Include 보다 앞에 있는 ClientAliveInterval 은 어떤 드롭인보다도 우선합니다. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 00-muster-session.conf 는 그대로 두고 그 블록을 멈춥니다. sshd 가 없는 호스트에서는 검토 스크립트가 아무것도 바꾸지 않습니다. 이 컨트롤은 두 방식 중 어느 쪽이든 인정하므로, 대안으로 시스템 프로파일 파일에 대화형 셸 TMOUT 을 설정하고 export 할 수 있습니다 - 예를 들어 /etc/profile.d/ 아래 파일에 "readonly TMOUT=600; export TMOUT" 를 둡니다.
fix_muster_account_session_timeout() {
  P_max_count='3'
  P_max_interval='300'
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_session_timeout"; mkdir -p "$MB" || { log "muster.account.session_timeout: backup failed, nothing changed"; return 1; }
  backup /etc/ssh/sshd_config.d/00-muster-session.conf || { log "muster.account.session_timeout: backup failed, nothing changed"; return 1; }
  ( set -e
    if command -v sshd >/dev/null 2>&1; then
      [ -d /run/sshd ] || mkdir -p /run/sshd
      i=$(sshd -T 2>/dev/null | awk '$1 == "clientaliveinterval" { print $2 }')
      c=$(sshd -T 2>/dev/null | awk '$1 == "clientalivecountmax" { print $2 }')
      case "$i" in ''|*[!0-9]*) i="$P_max_interval";; *) if [ "$i" -lt 1 ] || [ "$i" -gt "$P_max_interval" ]; then i="$P_max_interval"; fi;; esac
      case "$c" in ''|*[!0-9]*) c="$P_max_count";; *) if [ "$c" -lt 1 ] || [ "$c" -gt "$P_max_count" ]; then c="$P_max_count"; fi;; esac
      if [ -L /etc/ssh/sshd_config.d/00-muster-session.conf ]; then log "muster.account.session_timeout: /etc/ssh/sshd_config.d/00-muster-session.conf is a symlink (a mask), left as is"; exit 1; fi
      printf 'ClientAliveInterval %s\nClientAliveCountMax %s\n' "$i" "$c" > /etc/ssh/sshd_config.d/00-muster-session.conf
      chmod 644 /etc/ssh/sshd_config.d/00-muster-session.conf
      sshd -t
      if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
      if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.session_timeout: script failed (rc $rc), rolling back"
    ( set -e
      f=/etc/ssh/sshd_config.d/00-muster-session.conf
      if [ -L "$f" ]; then :; elif [ -e "$MB/files$f" ]; then cp -a "$MB/files$f" "$f"; else rm -f "$f"; fi
      if command -v sshd >/dev/null 2>&1; then
        sshd -t
        if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
        if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.session_timeout: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config.d/00-muster-session.conf || log "muster.account.session_timeout: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | awk '$1 == "clientaliveinterval" { i = $2 } $1 == "clientalivecountmax" { c = $2 } END { exit !(i >= 1 && i <= I && c >= 1 && c <= C) }' I="$P_max_interval" C="$P_max_count"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.session_timeout: validate failed, rolling back"
    ( set -e
      f=/etc/ssh/sshd_config.d/00-muster-session.conf
      if [ -L "$f" ]; then :; elif [ -e "$MB/files$f" ]; then cp -a "$MB/files$f" "$f"; else rm -f "$f"; fi
      if command -v sshd >/dev/null 2>&1; then
        sshd -t
        if systemctl is-active --quiet sshd.service; then systemctl reload sshd.service; fi
        if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service; fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.session_timeout: rollback failed (rc $rrc)"
    restore /etc/ssh/sshd_config.d/00-muster-session.conf || log "muster.account.session_timeout: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.session_timeout: done"
}
fix_muster_account_session_timeout
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 25/56 muster.beyond.icmp_broadcast_and_bogus_ignored [risk none] [fail, low]
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

# ---- 26/56 muster.beyond.uncommon_filesystems_disabled [risk none] [fail, low]
# why: clause does not hold
# do:  Write one install <name> /bin/false line per module into a file under /etc/modprobe.d, for example /etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf, and rebuild the initramfs (the review script does not) so the setting also applies during early boot. A vendor file whose install line for the module loads it wins over this one; the review script's validate then fails and the block rolls back. The review script never follows a symlink; a 99-muster-uncommon-filesystems-disabled.conf that is a symlink (a mask) is left as is and the block stops. A blacklist line alongside it does no harm but is not what muster credits. A module already built into the running kernel needs a kernel without it — the distribution kernels ship all six as modules, so this is rare — and a host that genuinely mounts one of these types, an optical drive reading UDF for instance, should carry a waiver naming the module rather than leaving the whole control undecided.
# ko:  모듈마다 install <name> /bin/false 한 줄씩을 /etc/modprobe.d 아래 파일(예를 들어 /etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf)에 적고, 초기 부팅 단계에도 적용되도록 initramfs 를 다시 만듭니다(검토 스크립트는 하지 않습니다). 모듈을 적재하는 install 줄을 둔 벤더 파일이 이 파일을 이기며, 그때 검토 스크립트의 validate가 실패해 블록이 롤백됩니다. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-uncommon-filesystems-disabled.conf 는 그대로 두고 그 블록을 멈춥니다. blacklist 줄을 함께 두어도 해롭지는 않지만 muster 가 인정하는 것은 아닙니다. 이미 실행 중인 커널에 내장된 모듈은 그것이 빠진 커널이 필요합니다. 배포판 커널은 여섯 개를 모두 모듈로 배포하므로 드문 경우입니다. UDF 를 읽는 광학 드라이브처럼 이 유형 중 하나를 실제로 마운트하는 호스트는 항목 전체를 미결로 두지 말고 해당 모듈을 지목하는 waiver 를 두십시오.
fix_muster_beyond_uncommon_filesystems_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_uncommon_filesystems_disabled"; mkdir -p "$MB" || { log "muster.beyond.uncommon_filesystems_disabled: backup failed, nothing changed"; return 1; }
  backup /etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf || { log "muster.beyond.uncommon_filesystems_disabled: backup failed, nothing changed"; return 1; }
  save_modules cramfs freevxfs jffs2 hfs hfsplus udf || { log "muster.beyond.uncommon_filesystems_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf
    if [ -L "$f" ]; then log "muster.beyond.uncommon_filesystems_disabled: $f is a symlink (a mask), left as is"; exit 1; fi
    mods='cramfs freevxfs jffs2 hfs hfsplus udf'
    for m in $mods; do
      n=$(printf '%s' "$m" | tr - _)
      case "$(modprobe --showconfig 2>/dev/null | awk -v m="$n" '$1 == "install" && $2 == m { print $3; exit }')" in
        /bin/false|/bin/true|/usr/bin/false|/usr/bin/true|false|true) ;;
        *) grep -q "^install $n " "$f" 2>/dev/null || printf 'install %s /bin/false\n' "$n" >> "$f";;
      esac
      if grep -q "^$n " /proc/modules; then modprobe -r -- "$n"; fi
    done
    if [ -f "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.uncommon_filesystems_disabled: script failed (rc $rc), rolling back"
    restore /etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf || log "muster.beyond.uncommon_filesystems_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules cramfs freevxfs jffs2 hfs hfsplus udf || log "muster.beyond.uncommon_filesystems_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    mods='cramfs freevxfs jffs2 hfs hfsplus udf'; for m in $mods; do n=$(printf '%s' "$m" | tr - _); case "$(modprobe --showconfig 2>/dev/null | awk -v m="$n" '$1 == "install" && $2 == m { print $3; exit }')" in /bin/false|/bin/true|/usr/bin/false|/usr/bin/true|false|true) ;; *) exit 1;; esac; ! grep -q "^$n " /proc/modules || exit 1; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.uncommon_filesystems_disabled: validate failed, rolling back"
    restore /etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf || log "muster.beyond.uncommon_filesystems_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules cramfs freevxfs jffs2 hfs hfsplus udf || log "muster.beyond.uncommon_filesystems_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.uncommon_filesystems_disabled: done"
}
fix_muster_beyond_uncommon_filesystems_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 27/56 muster.beyond.unprivileged_bpf_restricted [risk none] [fail, low]
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

# ---- 28/56 muster.file.hosts_lpd_permissions [risk none] [fail, low]
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

# ---- 29/56 muster.service.ftpusers_permissions [risk none] [fail, low]
# why: clause does not hold
# do:  Create the access-control file the daemon names if it does not exist, then chown root:root and chmod 640 each of /etc/ftpusers, the pam_listfile list and vsftpd's userlist_file. The review script changes the owner and mode of those of /etc/ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd/user_list, /etc/vsftpd.user_list and /etc/vsftpd.ftpusers that exist and never creates a file; a list that vsftpd's userlist_file or a pam_listfile file= names elsewhere is yours to fix. The review script never follows a symlink.
# ko:  데몬이 지정한 접근 제어 파일이 없으면 만든 뒤, /etc/ftpusers 와 pam_listfile 목록, vsftpd 의 userlist_file 각각에 chown root:root 와 chmod 640 을 적용합니다. 검토 스크립트는 /etc/ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd/user_list, /etc/vsftpd.user_list, /etc/vsftpd.ftpusers 중 존재하는 파일의 소유자와 mode 만 바꾸며 파일을 만들지 않습니다. vsftpd 의 userlist_file 이나 pam_listfile 의 file= 이 다른 곳을 가리키는 목록은 운영자가 고쳐야 합니다. 검토 스크립트는 심볼릭 링크를 따라가지 않습니다.
fix_muster_service_ftpusers_permissions() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_ftpusers_permissions"; mkdir -p "$MB" || { log "muster.service.ftpusers_permissions: backup failed, nothing changed"; return 1; }
  backup /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list /etc/vsftpd.ftpusers || { log "muster.service.ftpusers_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    for p in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list /etc/vsftpd.ftpusers; do
      if [ -f "$p" ] && [ ! -L "$p" ]; then
        chown root "$p"
        chmod u-xs,g-wxs,o-rwxt "$p"
      fi
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.ftpusers_permissions: script failed (rc $rc), rolling back"
    restore /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list /etc/vsftpd.ftpusers || log "muster.service.ftpusers_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    for p in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list /etc/vsftpd.ftpusers; do [ ! -f "$p" ] || [ -L "$p" ] || case "$(stat -c '%u %a' "$p")" in '0 0'|'0 40'|'0 200'|'0 240'|'0 400'|'0 440'|'0 600'|'0 640') ;; *) exit 1;; esac; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.ftpusers_permissions: validate failed, rolling back"
    restore /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list /etc/vsftpd.ftpusers || log "muster.service.ftpusers_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.ftpusers_permissions: done"
}
fix_muster_service_ftpusers_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 30/56 muster.beyond.audit_rules_loaded [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Write the rules into a file under /etc/audit/rules.d whose name ends in .rules, then run augenrules --load, which regenerates /etc/audit/audit.rules from rules.d and loads it into the kernel. The review script acts in three cases. With no rule persisted and none loaded it writes muster's minimum watch set to /etc/audit/rules.d/50-muster.rules (mode 0640): wa watches on /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/ and /etc/audit/ under muster-* keys, for the paths that exist; replace it with the site's own rules. With rules persisted and the kernel list empty it runs augenrules --load while auditd runs, else augenrules alone. With rules loaded and none persisted it leaves them: persist your own set. It refuses a missing or symlinked rules.d, never loads while -e 2 or --loginuid-immutable is pending or in force, and on rollback deletes only rules this run loaded and puts back the kernel settings it recorded.
# ko:  /etc/audit/rules.d 아래 이름이 .rules 로 끝나는 파일에 규칙을 적고 augenrules --load 를 실행합니다. 이 명령은 rules.d 에서 /etc/audit/audit.rules 를 다시 만들어 커널에 적재합니다. 검토 스크립트는 세 경우에만 움직입니다. 저장된 규칙도 적재된 규칙도 없으면 muster 의 최소 감시 규칙을 /etc/audit/rules.d/50-muster.rules(모드 0640)에 씁니다. /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/, /etc/audit/ 가운데 존재하는 경로에 muster-* 키로 wa 감시를 겁니다. 이 파일은 사이트 자체 규칙으로 바꾸십시오. 저장된 규칙이 있고 커널 목록이 비어 있으면 auditd 가 실행 중일 때 augenrules --load 를, 아니면 augenrules 만 실행합니다. 적재된 규칙만 있고 저장된 규칙이 없으면 그대로 둡니다. 직접 규칙을 저장하십시오. rules.d 가 없거나 심볼릭 링크이면 거부하고, -e 2 나 --loginuid-immutable 이 대기 중이거나 적용된 상태에서는 적재하지 않으며, 롤백은 이번 실행이 적재한 규칙만 지우고 기록해 둔 커널 설정을 되돌립니다.
fix_muster_beyond_audit_rules_loaded() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_audit_rules_loaded"; mkdir -p "$MB" || { log "muster.beyond.audit_rules_loaded: backup failed, nothing changed"; return 1; }
  backup /etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules || { log "muster.beyond.audit_rules_loaded: backup failed, nothing changed"; return 1; }
  ( set -e
    rm -f "$MB/audit.loaded" "$MB/audit.status" "$MB/auditd.edited"
    d=/etc/audit/rules.d
    f=/etc/audit/rules.d/50-muster.rules
    if [ ! -d "$d" ] || [ -L "$d" ]; then log "muster.beyond.audit_rules_loaded: $d is missing or a symlink; refused"; exit 1; fi
    if [ -L "$f" ]; then log "muster.beyond.audit_rules_loaded: $f is a symlink (a mask), left as is"; exit 1; fi
    rd_present() { LC_ALL=C grep -Esq '^[[:space:]]*-[waA]' "$@"; }
    rd_lock() { LC_ALL=C grep -Esq '(^|[[:space:]])(-e[[:space:]]*\+?0*2([[:space:]]|$)|--loginuid-immutable([[:space:]]|$))' "$@"; }
    s=$(LC_ALL=C auditctl -s) || { log "muster.beyond.audit_rules_loaded: auditctl -s cannot tell the lock state; refused"; exit 1; }
    e=$(printf '%s\n' "$s" | LC_ALL=C awk '$1 == "enabled" { v = $2 } END { print v }')
    if [ -z "$e" ]; then log "muster.beyond.audit_rules_loaded: auditctl -s cannot tell the lock state; refused"; exit 1; fi
    if printf '%s\n' "$s" | LC_ALL=C awk '($1 == "enabled" && $2 == "2") || ($1 == "loginuid_immutable" && $2 == "1") { f = 1 } END { exit !f }' || rd_lock "$d"/*.rules /etc/audit/audit.rules; then
      log "muster.beyond.audit_rules_loaded: a one-way audit setting is pending or in force; refused"
      exit 1
    fi
    l=$(LC_ALL=C auditctl -l) || { log "muster.beyond.audit_rules_loaded: auditctl -l failed; refused"; exit 1; }
    if rd_present "$d"/*.rules; then pr=1; else pr=; fi
    if [ -z "$pr" ] && [ "$l" != "No rules" ]; then
      log "muster.beyond.audit_rules_loaded: kernel rules are not persisted; persist your own set"
      exit 0
    fi
    if [ -z "$pr" ]; then
      new=
      if [ ! -e "$f" ]; then new=1; fi
      : > "$MB/auditd.edited"
      for w in /etc/passwd=muster-identity /etc/group=muster-identity /etc/shadow=muster-identity /etc/gshadow=muster-identity /etc/sudoers=muster-privilege /etc/sudoers.d/=muster-privilege /etc/audit/=muster-audit-config; do
        if [ -e "${w%%=*}" ]; then printf -- '-w %s -p wa -k %s\n' "${w%%=*}" "${w#*=}"; fi
      done > "$f"
      chmod 0640 "$f"
      if [ -n "$new" ]; then
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi
      fi
    fi
    if LC_ALL=C systemctl is-active --quiet auditd.service && [ "$l" = "No rules" ]; then
      printf '%s\n' "$s" | LC_ALL=C awk '$1 == "enabled" || $1 == "failure" || $1 == "backlog_limit" || $1 == "backlog_wait_time" || $1 == "rate_limit" { print $1, $2 }' > "$MB/audit.status"
      : > "$MB/audit.loaded"
      augenrules --load
    else
      augenrules
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.audit_rules_loaded: script failed (rc $rc), rolling back"
    ( set -e
      restore /etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules
      if [ -f "$MB/audit.loaded" ]; then
        s=$(LC_ALL=C auditctl -s 2>/dev/null) || s=
        if ! printf '%s\n' "$s" | LC_ALL=C awk '($1 == "enabled" && $2 == "2") || ($1 == "loginuid_immutable" && $2 == "1") { f = 1 } END { exit !f }'; then
          e='' fm='' b='' w='' r=''
          while read -r k v; do
            case "$k" in enabled) e=$v;; failure) fm=$v;; backlog_limit) b=$v;; backlog_wait_time) w=$v;; rate_limit) r=$v;; esac
          done < "$MB/audit.status"
          if [ -n "$e" ] && [ "$e" != 2 ]; then auditctl -e "$e"; fi
          if [ -n "$fm" ]; then auditctl -f "$fm"; fi
          if [ -n "$b" ]; then auditctl -b "$b"; fi
          if [ -n "$w" ]; then auditctl --backlog_wait_time "$w"; fi
          if [ -n "$r" ]; then auditctl -r "$r"; fi
          auditctl -D
        fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.beyond.audit_rules_loaded: rollback failed (rc $rrc)"
    restore /etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules || log "muster.beyond.audit_rules_loaded: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    if LC_ALL=C grep -Esq '^[[:space:]]*-[waA]' /etc/audit/rules.d/*.rules; then ! LC_ALL=C systemctl is-active --quiet auditd.service || { l=$(LC_ALL=C auditctl -l) && [ "$l" != "No rules" ]; }; else l=$(LC_ALL=C auditctl -l) && [ "$l" != "No rules" ]; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.audit_rules_loaded: validate failed, rolling back"
    ( set -e
      restore /etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules
      if [ -f "$MB/audit.loaded" ]; then
        s=$(LC_ALL=C auditctl -s 2>/dev/null) || s=
        if ! printf '%s\n' "$s" | LC_ALL=C awk '($1 == "enabled" && $2 == "2") || ($1 == "loginuid_immutable" && $2 == "1") { f = 1 } END { exit !f }'; then
          e='' fm='' b='' w='' r=''
          while read -r k v; do
            case "$k" in enabled) e=$v;; failure) fm=$v;; backlog_limit) b=$v;; backlog_wait_time) w=$v;; rate_limit) r=$v;; esac
          done < "$MB/audit.status"
          if [ -n "$e" ] && [ "$e" != 2 ]; then auditctl -e "$e"; fi
          if [ -n "$fm" ]; then auditctl -f "$fm"; fi
          if [ -n "$b" ]; then auditctl -b "$b"; fi
          if [ -n "$w" ]; then auditctl --backlog_wait_time "$w"; fi
          if [ -n "$r" ]; then auditctl -r "$r"; fi
          auditctl -D
        fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.beyond.audit_rules_loaded: rollback failed (rc $rrc)"
    restore /etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules || log "muster.beyond.audit_rules_loaded: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.audit_rules_loaded: done"
}
fix_muster_beyond_audit_rules_loaded
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 31/56 muster.beyond.auditd_active [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Install the audit daemon (the audit package on the EL family, auditd on Debian and Ubuntu) and run systemctl enable --now auditd, which starts it now and at every boot. Check that the kernel command line does not carry audit=0, which keeps the unit from starting; the EL unit refuses a manual stop (RefuseManualStop), so there a restart after a configuration change is service auditd restart rather than systemctl restart. The review script unmasks and enables the unit and starts it when it is stopped; the package install and the audit=0 check stay the operator's. It does not start auditd over a kernel rule list that is not empty (the unit's rule load would delete it), nor while -e 2 or --loginuid-immutable stands in the rules files, whatever the kernel's lock state. Starting auditd applies the host's configured disk actions at once, single and halt included. A failed block leaves a started daemon running, with the persisted control settings its load applied.
# ko:  감사 데몬(EL 계열은 audit 패키지, Debian·Ubuntu 는 auditd)을 설치하고 systemctl enable --now auditd 를 실행하면 지금 시작되고 매 부팅 시에도 시작됩니다. 커널 명령줄에 유닛의 시작을 막는 audit=0 이 없는지 확인하십시오. EL 계열의 유닛은 수동 중지를 거부하므로(RefuseManualStop) 그곳에서 설정 변경 후 재시작은 systemctl restart 대신 service auditd restart 로 합니다. 검토 스크립트는 유닛의 mask 를 풀고 활성화하며, 멈춰 있으면 시작합니다. 패키지 설치와 audit=0 확인은 운영자의 몫입니다. 커널 규칙 목록이 비어 있지 않으면(유닛의 규칙 적재가 그것을 지웁니다) auditd 를 시작하지 않고, 규칙 파일에 -e 2 나 --loginuid-immutable 이 있으면 커널의 잠금 상태와 관계없이 시작하지 않습니다. auditd 를 시작하면 호스트에 설정된 디스크 조치가 single 과 halt 를 포함해 곧바로 적용됩니다. 실패한 블록은 시작된 데몬을 실행 중인 채로 남기며, 그 적재가 적용한 저장된 제어 설정도 남습니다.
fix_muster_beyond_auditd_active() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_auditd_active"; mkdir -p "$MB" || { log "muster.beyond.auditd_active: backup failed, nothing changed"; return 1; }
  save_units auditd.service || { log "muster.beyond.auditd_active: backup failed, nothing changed"; return 1; }
  ( set -e
    UNITS='auditd.service'
    rd_lock() { LC_ALL=C grep -Esq '(^|[[:space:]])(-e[[:space:]]*\+?0*2([[:space:]]|$)|--loginuid-immutable([[:space:]]|$))' "$@"; }
    for u in $UNITS; do
      if ! systemctl cat "$u" >/dev/null 2>&1; then
        log "muster.beyond.auditd_active: install the audit package (audit on the EL family, auditd on Debian and Ubuntu)"
        continue
      fi
      systemctl --quiet unmask "$u"
      systemctl --quiet enable "$u"
      if LC_ALL=C systemctl is-active --quiet "$u"; then continue; fi
      l=$(LC_ALL=C auditctl -l) || { log "muster.beyond.auditd_active: auditctl -l failed; start refused"; exit 1; }
      if [ "$l" != "No rules" ]; then
        log "muster.beyond.auditd_active: kernel holds rules a start would replace; start left to the operator"
        continue
      fi
      if rd_lock /etc/audit/rules.d/*.rules /etc/audit/audit.rules; then
        log "muster.beyond.auditd_active: a one-way audit setting is pending (-e 2 or --loginuid-immutable); start refused"
        exit 1
      fi
      systemctl --quiet start "$u"
    done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.auditd_active: script failed (rc $rc), rolling back"
    restore_units auditd.service || log "muster.beyond.auditd_active: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    if systemctl cat auditd.service >/dev/null 2>&1; then systemctl is-enabled --quiet auditd.service && { systemctl is-active --quiet auditd.service || { l=$(LC_ALL=C auditctl -l) && [ "$l" != "No rules" ]; }; }; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.auditd_active: validate failed, rolling back"
    restore_units auditd.service || log "muster.beyond.auditd_active: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.auditd_active: done"
}
fix_muster_beyond_auditd_active
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 32/56 muster.file.hosts_permissions [risk restart_service] [fail, high]
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

# ---- 33/56 muster.file.rhosts_forbidden [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Remove the "+" entries from the offending ~/.rhosts, ~/.shosts and /etc/hosts.equiv, or remove the files entirely if r-command trust is not in use. The review script backs up /etc/hosts.equiv and comments out every line of it whose first non-blank character is "+" - a bare "+", "+host" and "+@netgroup" alike - by prefixing the line with "# muster: "; a file holding a "+" line whose user field is "-user" or "-@netgroup" is refused and left for a hand edit, since the first matching line decides and commenting that denial out would widen trust; a /etc/hosts.equiv that is a symlink is left as is. ~/.rhosts and ~/.shosts remain for the operator to edit: they sit in homes their accounts own, which the review script does not write.
# ko:  문제되는 ~/.rhosts, ~/.shosts, /etc/hosts.equiv 에서 "+" 항목을 제거하거나, r-command 신뢰를 쓰지 않으면 파일을 아예 삭제합니다. 검토 스크립트는 /etc/hosts.equiv 를 백업한 뒤, 공백이 아닌 첫 글자가 "+" 인 모든 줄(단독 "+", "+host", "+@netgroup" 모두)의 앞에 "# muster: " 를 붙여 주석 처리합니다. 사용자 필드가 "-user" 나 "-@netgroup" 인 "+" 줄이 있는 파일은 손대지 않고 거부하며 운영자가 직접 고칩니다. 처음 일치하는 줄이 결정하므로 그 거부 줄을 주석 처리하면 신뢰가 넓어지기 때문입니다. 심볼릭 링크인 /etc/hosts.equiv 는 그대로 둡니다. ~/.rhosts 와 ~/.shosts 는 각 계정이 소유한 홈에 있어 검토 스크립트가 쓰지 않으므로 운영자가 직접 정리합니다.
fix_muster_file_rhosts_forbidden() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_file_rhosts_forbidden"; mkdir -p "$MB" || { log "muster.file.rhosts_forbidden: backup failed, nothing changed"; return 1; }
  backup /etc/hosts.equiv || { log "muster.file.rhosts_forbidden: backup failed, nothing changed"; return 1; }
  ( set -e
    rd_plus() { LC_ALL=C grep -Ec '^[[:space:]]*\+' "$1" || :; }
    if [ -f /etc/hosts.equiv ] && [ ! -L /etc/hosts.equiv ]; then
      if LC_ALL=C grep -Eq '^[[:space:]]*\+[^[:space:]]*[[:space:]]+-' /etc/hosts.equiv; then log "muster.file.rhosts_forbidden: /etc/hosts.equiv has a '+' line that denies a user; edit it by hand"; exit 1; fi
      if [ "$(rd_plus /etc/hosts.equiv)" != 0 ]; then LC_ALL=C sed -i 's/^\([[:space:]]*+\)/# muster: \1/' /etc/hosts.equiv; fi
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.rhosts_forbidden: script failed (rc $rc), rolling back"
    restore /etc/hosts.equiv || log "muster.file.rhosts_forbidden: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    [ ! -f /etc/hosts.equiv ] || [ -L /etc/hosts.equiv ] || [ "$(LC_ALL=C grep -Ec '^[[:space:]]*\+' /etc/hosts.equiv || :)" = 0 ]
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.rhosts_forbidden: validate failed, rolling back"
    restore /etc/hosts.equiv || log "muster.file.rhosts_forbidden: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.rhosts_forbidden: done"
}
fix_muster_file_rhosts_forbidden
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 34/56 muster.service.automount_disabled [risk restart_service] [fail, high]
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

# ---- 35/56 muster.service.dos_services_disabled [risk restart_service] [fail, high]
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

# ---- 36/56 muster.service.finger_disabled [risk restart_service] [fail, high]
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

# ---- 37/56 muster.service.ftp_anonymous [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Set anonymous_enable=NO in vsftpd.conf, remove the <Anonymous> block from proftpd.conf, or set NoAnonymous yes for pure-ftpd, then restart the daemon. The review script backs up /etc/vsftpd.conf and /etc/vsftpd/vsftpd.conf and, in each that is a regular file where vsftpd reads anonymous_enable as other than NO, FALSE or 0 (a missing key is the compiled YES), writes anonymous_enable=NO - every anonymous_enable line is rewritten, or one is appended; a symlink is left as is. This closes an anonymous service someone may have meant to run, so check first that nothing depends on it. When it changed a file and vsftpd was running, it restarts vsftpd.service. The proftpd <Anonymous> block and pure-ftpd's NoAnonymous stay the operator's. vsftpd.conf is a package configuration file on both families: at the next upgrade dpkg (Debian, Ubuntu) asks about the edited file, and rpm (EL) keeps the edit and writes the package's version beside it as .rpmnew.
# ko:  vsftpd.conf 에 anonymous_enable=NO 를 설정하거나, proftpd.conf 의 <Anonymous> 블록을 제거하거나, pure-ftpd 에 NoAnonymous yes 를 설정한 뒤 데몬을 재시작합니다. 검토 스크립트는 /etc/vsftpd.conf 와 /etc/vsftpd/vsftpd.conf 를 백업한 뒤, 일반 파일이면서 vsftpd 가 anonymous_enable 을 NO, FALSE, 0 이외의 값으로 읽는(키가 없으면 컴파일 기본값 YES) 파일마다 anonymous_enable=NO 를 씁니다(모든 anonymous_enable 줄을 고쳐 쓰고, 없으면 한 줄을 덧붙입니다). 심볼릭 링크는 그대로 둡니다. 누군가 의도해서 운영했을 수도 있는 익명 서비스를 닫는 것이므로, 이에 기대는 곳이 없는지 먼저 확인합니다. 파일을 바꾸었고 vsftpd 가 실행 중이었으면 vsftpd.service 를 재시작합니다. proftpd 의 <Anonymous> 블록과 pure-ftpd 의 NoAnonymous 는 운영자가 정리합니다. vsftpd.conf 는 두 계열 모두에서 패키지 설정 파일이므로, 다음 업그레이드 때 dpkg(Debian, Ubuntu)는 수정된 파일을 어떻게 할지 묻고, rpm(EL)은 수정본을 유지한 채 패키지의 버전을 옆에 .rpmnew 로 씁니다.
fix_muster_service_ftp_anonymous() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_ftp_anonymous"; mkdir -p "$MB" || { log "muster.service.ftp_anonymous: backup failed, nothing changed"; return 1; }
  backup /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf || { log "muster.service.ftp_anonymous: backup failed, nothing changed"; return 1; }
  ( set -e
    rm -f "$MB/vsftpd.was-running" "$MB/vsftpd.edited"
    if LC_ALL=C systemctl is-active --quiet vsftpd.service; then : > "$MB/vsftpd.was-running"; fi
    rd_anon() { LC_ALL=C awk '{ l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; k = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", k); k = tolower(k); v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); if (k == "anonymous_enable") a = tolower(v) } END { if (a == "no" || a == "false" || a == "0") print "no"; else print "yes" }' "$1"; }
    for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
      if [ -f "$f" ] && [ ! -L "$f" ]; then
        if [ "$(rd_anon "$f")" = yes ]; then
          : > "$MB/vsftpd.edited"
          if LC_ALL=C grep -Eiq '^[[:space:]]*anonymous_enable[[:space:]]*=' "$f"; then
            LC_ALL=C sed -i -E 's/^[[:space:]]*anonymous_enable[[:space:]]*=.*/anonymous_enable=NO/I' "$f"
          else
            if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi
            echo 'anonymous_enable=NO' >> "$f"
          fi
        fi
      fi
    done
    if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then
      systemctl reset-failed vsftpd.service 2>/dev/null || :
      systemctl restart vsftpd.service
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.ftp_anonymous: script failed (rc $rc), rolling back"
    ( set -e
      restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf
      if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then
        systemctl reset-failed vsftpd.service 2>/dev/null || :
        systemctl restart vsftpd.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.ftp_anonymous: rollback failed (rc $rrc)"
    restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf || log "muster.service.ftp_anonymous: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    { [ ! -f /etc/vsftpd.conf ] || [ -L /etc/vsftpd.conf ] || [ "$(LC_ALL=C awk '{ l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; k = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", k); k = tolower(k); v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); if (k == "anonymous_enable") a = tolower(v) } END { if (a == "no" || a == "false" || a == "0") print "no"; else print "yes" }' /etc/vsftpd.conf)" = no ]; } && { [ ! -f /etc/vsftpd/vsftpd.conf ] || [ -L /etc/vsftpd/vsftpd.conf ] || [ "$(LC_ALL=C awk '{ l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; k = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", k); k = tolower(k); v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); if (k == "anonymous_enable") a = tolower(v) } END { if (a == "no" || a == "false" || a == "0") print "no"; else print "yes" }' /etc/vsftpd/vsftpd.conf)" = no ]; } && { [ ! -f "$MB/vsftpd.was-running" ] || systemctl is-active --quiet vsftpd.service; }
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.ftp_anonymous: validate failed, rolling back"
    ( set -e
      restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf
      if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then
        systemctl reset-failed vsftpd.service 2>/dev/null || :
        systemctl restart vsftpd.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.ftp_anonymous: rollback failed (rc $rrc)"
    restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf || log "muster.service.ftp_anonymous: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.ftp_anonymous: done"
}
fix_muster_service_ftp_anonymous
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 38/56 muster.service.nfs_export_access [risk restart_service] [fail, high]
# why: clause does not hold
# do:  Replace every wildcard client in /etc/exports with the hosts or networks that need the share, remove no_root_squash from its options, then chown root:root /etc/exports and chmod 644 /etc/exports, and apply the result with exportfs -ra. The review script backs up /etc/exports and, in a regular file, makes it root's, clears every mode bit outside 0644 and swaps no_root_squash for root_squash where it is an option in a client's or a -options default list (a comment and a client name are untouched; a path whose name holds ,no_root_squash or (no_root_squash before a blank, comma or ")" is rewritten too); a symlink is left. When it swapped and nfs-server.service was active, it runs exportfs -ra, which resyncs the kernel's table to every export file: pending /etc/exports.d edits apply, exports made only at run time drop, and a rollback, too, restores the files' view, not a hand-made live table. Wildcard clients and /etc/exports.d/*.exports stay the operator's.
# ko:  /etc/exports 의 와일드카드 클라이언트를 공유가 필요한 호스트나 네트워크로 바꾸고, 옵션에서 no_root_squash 를 제거한 뒤, chown root:root /etc/exports 와 chmod 644 /etc/exports 를 적용하고 exportfs -ra 로 반영합니다. 검토 스크립트는 /etc/exports 를 백업한 뒤, 일반 파일이면 root 소유로 바꾸고 0644 밖의 권한 비트를 모두 지우며, 클라이언트의 옵션 목록이나 -options 기본 목록에 옵션으로 들어 있는 no_root_squash 를 root_squash 로 바꿉니다(주석과 클라이언트 이름은 그대로 두지만, 이름에 ,no_root_squash 나 (no_root_squash 가 공백, 쉼표, ")" 앞에 오는 경로는 함께 바뀝니다). 심볼릭 링크는 그대로 둡니다. 바꾼 것이 있고 nfs-server.service 가 활성 상태였으면 exportfs -ra 를 실행하는데, 이는 커널의 공유 테이블을 모든 공유 파일에 다시 맞추므로 아직 반영되지 않은 /etc/exports.d 수정도 적용하고 실행 중에만 만든 공유는 없앱니다. 롤백도 손으로 만든 실행 중 테이블이 아니라 파일 기준의 상태를 되돌립니다. 와일드카드 클라이언트와 /etc/exports.d/*.exports 는 운영자가 정리합니다.
fix_muster_service_nfs_export_access() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_nfs_export_access"; mkdir -p "$MB" || { log "muster.service.nfs_export_access: backup failed, nothing changed"; return 1; }
  backup /etc/exports || { log "muster.service.nfs_export_access: backup failed, nothing changed"; return 1; }
  ( set -e
    rm -f "$MB/nfs.was-running" "$MB/nfs.edited"
    rd_nrs() { LC_ALL=C grep -Ec '^[^#]*([(,]|[[:space:]]-)no_root_squash([,)[:space:]]|$)' "$1" || :; }
    if [ -f /etc/exports ] && [ ! -L /etc/exports ]; then
      if LC_ALL=C systemctl is-active --quiet nfs-server.service; then : > "$MB/nfs.was-running"; fi
      chown root /etc/exports
      chmod u-xs,g-wxs,o-wxt /etc/exports
      if [ "$(rd_nrs /etc/exports)" != 0 ]; then
        : > "$MB/nfs.edited"
        n=0
        while [ "$(rd_nrs /etc/exports)" != 0 ] && [ "$n" -lt 10 ]; do
          LC_ALL=C sed -i -E 's/^([^#]*)([(,]|[[:space:]]-)no_root_squash([,)[:space:]]|$)/\1\2root_squash\3/' /etc/exports
          n=$((n+1))
        done
      fi
      if [ -f "$MB/nfs.edited" ] && [ -f "$MB/nfs.was-running" ]; then exportfs -ra; fi
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nfs_export_access: script failed (rc $rc), rolling back"
    ( set -e
      restore /etc/exports
      if [ -f "$MB/nfs.edited" ] && [ -f "$MB/nfs.was-running" ]; then exportfs -ra; fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.nfs_export_access: rollback failed (rc $rrc)"
    restore /etc/exports || log "muster.service.nfs_export_access: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    [ ! -f /etc/exports ] || [ -L /etc/exports ] || { case "$(stat -c '%u %a' /etc/exports)" in '0 0'|'0 4'|'0 40'|'0 44'|'0 200'|'0 204'|'0 240'|'0 244'|'0 400'|'0 404'|'0 440'|'0 444'|'0 600'|'0 604'|'0 640'|'0 644') ;; *) false;; esac && [ "$(LC_ALL=C grep -Ec '^[^#]*([(,]|[[:space:]]-)no_root_squash([,)[:space:]]|$)' /etc/exports || :)" = 0 ]; }
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.nfs_export_access: validate failed, rolling back"
    ( set -e
      restore /etc/exports
      if [ -f "$MB/nfs.edited" ] && [ -f "$MB/nfs.was-running" ]; then exportfs -ra; fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.nfs_export_access: rollback failed (rc $rrc)"
    restore /etc/exports || log "muster.service.nfs_export_access: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.nfs_export_access: done"
}
fix_muster_service_nfs_export_access
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 39/56 muster.service.nfs_server_disabled [risk restart_service] [fail, high]
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

# ---- 40/56 muster.service.rpcbind_disabled [risk restart_service] [fail, high]
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

# ---- 41/56 muster.service.rservices_disabled [risk restart_service] [fail, high]
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

# ---- 42/56 muster.service.tftp_talk_disabled [risk restart_service] [fail, high]
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

# ---- 43/56 muster.beyond.audit_disk_actions [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Set all five lines in /etc/audit/auditd.conf to listed actions (email needs action_mail_acct naming a mailbox someone reads; single and halt stop the host, see the description) and make auditd reread it with auditctl --signal reload. The review script backs up auditd.conf (a symlink is refused) and rewrites every line of each key whose action is outside its list to the first listed value that keeps the host up: syslog or rotate for the space and full-disk keys, syslog for disk_error_action, rotate, keep_logs or syslog for max_log_file_action. It never writes email, exec, single or halt; a key whose list holds no such value is left. rotate deletes logs beyond num_logs; a tuning that lists keep_logs first keeps them. When it changed the file and auditd was running, it sends auditctl --signal reload. auditd.conf is a package configuration file: at the next upgrade dpkg (Debian, Ubuntu) asks about the edited file, and rpm (EL) keeps the edit and writes the package's version as .rpmnew.
# ko:  /etc/audit/auditd.conf 의 다섯 줄을 모두 목록에 있는 조치로 설정하고(email 은 action_mail_acct 에 누군가 읽는 메일함이 있어야 하며, single 과 halt 는 호스트를 멈춥니다. 설명 참고) auditctl --signal reload 로 데몬이 파일을 다시 읽게 합니다. 검토 스크립트는 auditd.conf 를 백업한 뒤(심볼릭 링크이면 거부합니다), 조치가 목록 밖에 있는 키마다 그 키의 모든 줄을 목록에서 호스트를 멈추지 않는 첫 번째 값으로 고쳐 씁니다. 두 공간 키와 디스크 가득 참 키에는 syslog 나 rotate, disk_error_action 에는 syslog, max_log_file_action 에는 rotate, keep_logs, syslog 가운데 하나입니다. email, exec, single, halt 는 쓰지 않으며, 목록에 쓸 수 있는 값이 없는 키는 운영자에게 맡깁니다. rotate 는 num_logs 를 넘는 로그를 지우며, keep_logs 를 먼저 둔 튜닝은 로그를 남깁니다. 파일을 바꾸었고 auditd 가 실행 중이었으면 auditctl --signal reload 를 보냅니다. auditd.conf 는 패키지 설정 파일이므로, 다음 업그레이드 때 dpkg(Debian, Ubuntu)는 수정된 파일을 어떻게 할지 묻고, rpm(EL)은 수정본을 유지한 채 패키지의 버전을 옆에 .rpmnew 로 씁니다.
fix_muster_beyond_audit_disk_actions() {
  P_allowed_disk_error_actions='syslog exec single halt'
  P_allowed_disk_full_actions='syslog rotate exec single halt'
  P_allowed_rotate_actions='rotate keep_logs syslog'
  P_allowed_space_actions='syslog email exec rotate single halt'
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_audit_disk_actions"; mkdir -p "$MB" || { log "muster.beyond.audit_disk_actions: backup failed, nothing changed"; return 1; }
  backup /etc/audit/auditd.conf || { log "muster.beyond.audit_disk_actions: backup failed, nothing changed"; return 1; }
  ( set -e
    rm -f "$MB/disk.keys" "$MB/auditd.edited" "$MB/auditd.was-running"
    f=/etc/audit/auditd.conf
    if [ -L "$f" ]; then log "muster.beyond.audit_disk_actions: $f is a symlink, left as is"; exit 1; fi
    if LC_ALL=C systemctl is-active --quiet auditd.service; then : > "$MB/auditd.was-running"; fi
    rd_action() { LC_ALL=C awk -v k="$2" '{ l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; n = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", n); if (tolower(n) != k) next; v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); sub(/ .*$/, "", v); a = tolower(v) } END { print a }' "$1"; }
    one() {
      v=$(rd_action "$f" "$1")
      if [ -n "$v" ]; then
        case " $2 " in *" $v "*) return 0;; esac
      fi
      n=
      for x in $2; do
        case " $3 " in *" $x "*) n=$x; break;; esac
      done
      if [ -z "$n" ]; then
        log "muster.beyond.audit_disk_actions: $1: no writable value in the list in force; left to the operator"
        return 0
      fi
      printf '%s\n' "$1" >> "$MB/disk.keys"
      : > "$MB/auditd.edited"
      LC_ALL=C sed -i -E "s/^[[:space:]]*$1[[:space:]]*=.*/$1 = $n/I" "$f"
    }
    sp=$P_allowed_space_actions
    fu=$P_allowed_disk_full_actions
    er=$P_allowed_disk_error_actions
    ro=$P_allowed_rotate_actions
    one space_left_action "$sp" 'syslog rotate'
    one admin_space_left_action "$sp" 'syslog rotate'
    one disk_full_action "$fu" 'syslog rotate'
    one disk_error_action "$er" 'syslog'
    one max_log_file_action "$ro" 'rotate keep_logs syslog'
    if [ -f "$MB/auditd.edited" ] && [ -f "$MB/auditd.was-running" ]; then auditctl --signal reload; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.audit_disk_actions: script failed (rc $rc), rolling back"
    ( set -e
      restore /etc/audit/auditd.conf
      if [ -f "$MB/auditd.edited" ] && [ -f "$MB/auditd.was-running" ]; then auditctl --signal reload; fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.beyond.audit_disk_actions: rollback failed (rc $rrc)"
    restore /etc/audit/auditd.conf || log "muster.beyond.audit_disk_actions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    LC_ALL=C awk -v sp="$P_allowed_space_actions" -v fu="$P_allowed_disk_full_actions" -v er="$P_allowed_disk_error_actions" -v ro="$P_allowed_rotate_actions" -v keys="$(cat "$MB/disk.keys" 2>/dev/null)" 'BEGIN { L["space_left_action"] = sp; L["admin_space_left_action"] = sp; L["disk_full_action"] = fu; L["disk_error_action"] = er; L["max_log_file_action"] = ro } { l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; n = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", n); n = tolower(n); v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); sub(/ .*$/, "", v); a[n] = tolower(v) } END { m = split(keys, K, /[[:space:]]+/); bad = 0; for (j = 1; j <= m; j++) { k = K[j]; if (index(" " L[k] " ", " " a[k] " ") == 0) bad = 1 } exit bad }' /etc/audit/auditd.conf && { [ ! -f "$MB/auditd.was-running" ] || systemctl is-active --quiet auditd.service; }
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.audit_disk_actions: validate failed, rolling back"
    ( set -e
      restore /etc/audit/auditd.conf
      if [ -f "$MB/auditd.edited" ] && [ -f "$MB/auditd.was-running" ]; then auditctl --signal reload; fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.beyond.audit_disk_actions: rollback failed (rc $rrc)"
    restore /etc/audit/auditd.conf || log "muster.beyond.audit_disk_actions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.audit_disk_actions: done"
}
fix_muster_beyond_audit_disk_actions
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 44/56 muster.beyond.ip_forwarding_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv4.ip_forward = 0 into /etc/sysctl.d/99-muster-ip-forwarding-disabled.conf and apply it with sysctl --system; it takes effect at once. Check first that the host is not a router, VPN gateway or container host - turning forwarding off there cuts its clients and containers off the network; such a host names 1 in params.allowed_forward instead. The kernel resets net.ipv4.conf.all.accept_redirects whenever forwarding changes, so the review script puts back the value it read before the write and keeps it in the file only when that value is 0. A failed block puts back net.ipv4.ip_forward only; every interface's forwarding then follows that global value, because the kernel copies it. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ip-forwarding-disabled.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ip-forwarding-disabled.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-ip-forwarding-disabled.conf 에 net.ipv4.ip_forward = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 먼저 호스트가 라우터, VPN 게이트웨이, 컨테이너 호스트가 아닌지 확인하십시오. 그런 호스트에서 포워딩을 끄면 클라이언트와 컨테이너가 네트워크에서 끊기므로, 대신 params.allowed_forward 에 1 을 적습니다. 커널은 포워딩이 바뀔 때마다 net.ipv4.conf.all.accept_redirects 를 다시 설정하므로, 검토 스크립트는 쓰기 전에 읽은 값을 되돌려 놓고 그 값이 0일 때만 파일에 남깁니다. 실패한 블록은 net.ipv4.ip_forward 만 되돌리며, 커널이 그 값을 복사하므로 각 인터페이스의 포워딩은 그 전역 값을 따릅니다. /etc/sysctl.conf나 99-muster-ip-forwarding-disabled.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ip-forwarding-disabled.conf 는 그대로 두고 그 블록을 멈춥니다.
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

# ---- 45/56 muster.beyond.ipv6_forwarding_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv6.conf.all.forwarding = 0 and net.ipv6.conf.default.forwarding = 0 into /etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf and apply it with sysctl --system; they take effect at once. A router, VPN gateway or container host names 1 in params.allowed_forward instead - turning forwarding off there cuts its clients off. A failed block puts back net.ipv6.conf.all.forwarding and net.ipv6.conf.default.forwarding only; every interface's forwarding then follows the global value, because the kernel copies it. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-ipv6-forwarding-disabled.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-ipv6-forwarding-disabled.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  /etc/sysctl.d/99-muster-ipv6-forwarding-disabled.conf 에 net.ipv6.conf.all.forwarding = 0 과 net.ipv6.conf.default.forwarding = 0 을 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 라우터, VPN 게이트웨이, 컨테이너 호스트는 포워딩을 끄면 클라이언트가 끊기므로 대신 params.allowed_forward 에 1 을 적습니다. 실패한 블록은 net.ipv6.conf.all.forwarding 과 net.ipv6.conf.default.forwarding 만 되돌리며, 커널이 전역 값을 복사하므로 각 인터페이스의 포워딩은 그 전역 값을 따릅니다. /etc/sysctl.conf나 99-muster-ipv6-forwarding-disabled.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-ipv6-forwarding-disabled.conf 는 그대로 두고 그 블록을 멈춥니다.
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

# ---- 46/56 muster.beyond.reverse_path_filtering [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Write net.ipv4.conf.all.log_martians = 1 and net.ipv4.conf.default.log_martians = 1, and rp_filter = 1 or 2 for all and default if they are 0, into /etc/sysctl.d/99-muster-reverse-path-filtering.conf and apply it with sysctl --system; they take effect at once. The review script writes 1 (strict), which drops asymmetrically routed traffic, replies that come back on another interface included; a host with asymmetric routes (several uplinks, policy routing) sets 2 instead. A value set in /etc/sysctl.conf, or in a sysctl.d file that sorts after 99-muster-reverse-path-filtering.conf, still wins at boot; correct it there. The review script never follows a symlink; a 99-muster-reverse-path-filtering.conf that is a symlink (a mask) is left as is and the block stops.
# ko:  net.ipv4.conf.all.log_martians = 1 과 net.ipv4.conf.default.log_martians = 1 을, rp_filter 가 0 이면 all 과 default 에 1 또는 2 를 /etc/sysctl.d/99-muster-reverse-path-filtering.conf 에 적고 sysctl --system 으로 적용합니다. 즉시 반영됩니다. 검토 스크립트는 1(strict)을 쓰며, 이 값은 다른 인터페이스로 돌아오는 응답을 포함해 비대칭으로 라우팅되는 트래픽을 버립니다. 비대칭 경로가 있는 호스트(여러 업링크, 정책 라우팅)는 대신 2 를 설정합니다. /etc/sysctl.conf나 99-muster-reverse-path-filtering.conf 뒤에 정렬되는 sysctl.d 파일에 둔 값이 부팅 때 여전히 이기므로 그 파일을 고치십시오. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-reverse-path-filtering.conf 는 그대로 두고 그 블록을 멈춥니다.
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

# ---- 47/56 muster.beyond.usb_storage_disabled [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Write install usb-storage /bin/false into a file under /etc/modprobe.d, for example /etc/modprobe.d/99-muster-usb-storage-disabled.conf, and rebuild the initramfs (the review script does not) so the setting applies during early boot as well. A vendor file whose install line for the module loads it wins over this one; the review script's validate then fails and the block rolls back. The review script never follows a symlink; a 99-muster-usb-storage-disabled.conf that is a symlink (a mask) is left as is and the block stops. Check first that the host does not boot or install from USB media and that no operational procedure depends on a USB device for backups or recovery, because those stop working immediately. A USB keyboard, mouse or serial adapter is unaffected — this is the mass-storage driver alone, not USB support.
# ko:  /etc/modprobe.d 아래 파일(예를 들어 /etc/modprobe.d/99-muster-usb-storage-disabled.conf)에 install usb-storage /bin/false 를 적고, 초기 부팅 단계에도 적용되도록 initramfs 를 다시 만듭니다(검토 스크립트는 하지 않습니다). 모듈을 적재하는 install 줄을 둔 벤더 파일이 이 파일을 이기며, 그때 검토 스크립트의 validate가 실패해 블록이 롤백됩니다. 검토 스크립트는 심볼릭 링크를 따라가지 않으므로, 심볼릭 링크(마스크)인 99-muster-usb-storage-disabled.conf 는 그대로 두고 그 블록을 멈춥니다. USB 매체로 부팅하거나 설치하지 않는지, 백업이나 복구 절차가 USB 장치에 의존하지 않는지 먼저 확인하십시오. 그런 것들은 즉시 동작을 멈춥니다. USB 키보드·마우스·시리얼 어댑터에는 영향이 없습니다. 이것은 USB 지원 전체가 아니라 대용량 저장 장치 드라이버 하나입니다.
fix_muster_beyond_usb_storage_disabled() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_usb_storage_disabled"; mkdir -p "$MB" || { log "muster.beyond.usb_storage_disabled: backup failed, nothing changed"; return 1; }
  backup /etc/modprobe.d/99-muster-usb-storage-disabled.conf || { log "muster.beyond.usb_storage_disabled: backup failed, nothing changed"; return 1; }
  save_modules usb-storage || { log "muster.beyond.usb_storage_disabled: backup failed, nothing changed"; return 1; }
  ( set -e
    f=/etc/modprobe.d/99-muster-usb-storage-disabled.conf
    if [ -L "$f" ]; then log "muster.beyond.usb_storage_disabled: $f is a symlink (a mask), left as is"; exit 1; fi
    mods='usb-storage'
    for m in $mods; do
      n=$(printf '%s' "$m" | tr - _)
      case "$(modprobe --showconfig 2>/dev/null | awk -v m="$n" '$1 == "install" && $2 == m { print $3; exit }')" in
        /bin/false|/bin/true|/usr/bin/false|/usr/bin/true|false|true) ;;
        *) grep -q "^install $n " "$f" 2>/dev/null || printf 'install %s /bin/false\n' "$n" >> "$f";;
      esac
      if grep -q "^$n " /proc/modules; then modprobe -r -- "$n"; fi
    done
    if [ -f "$f" ]; then chmod 644 "$f"; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.usb_storage_disabled: script failed (rc $rc), rolling back"
    restore /etc/modprobe.d/99-muster-usb-storage-disabled.conf || log "muster.beyond.usb_storage_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules usb-storage || log "muster.beyond.usb_storage_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    mods='usb-storage'; for m in $mods; do n=$(printf '%s' "$m" | tr - _); case "$(modprobe --showconfig 2>/dev/null | awk -v m="$n" '$1 == "install" && $2 == m { print $3; exit }')" in /bin/false|/bin/true|/usr/bin/false|/usr/bin/true|false|true) ;; *) exit 1;; esac; ! grep -q "^$n " /proc/modules || exit 1; done
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.usb_storage_disabled: validate failed, rolling back"
    restore /etc/modprobe.d/99-muster-usb-storage-disabled.conf || log "muster.beyond.usb_storage_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    restore_modules usb-storage || log "muster.beyond.usb_storage_disabled: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.usb_storage_disabled: done"
}
fix_muster_beyond_usb_storage_disabled
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 48/56 muster.service.mail_expn_vrfy [risk restart_service] [fail, medium]
# why: clause does not hold
# do:  Set disable_vrfy_command = yes in postfix's main.cf, or add novrfy and noexpn to the PrivacyOptions line of sendmail.cf, then restart the mail transfer agent. The review script acts on postfix only: it backs up /etc/postfix/main.cf, refuses a symlinked main.cf and a configuration postfix check already rejects, and, where postconf does not read disable_vrfy_command as yes, sets it with postconf -e, runs postfix check again and, when postfix was running, postfix reload; the reload also applies any master.cf edit still pending. A host without postconf is left as it is: the sendmail half stays the operator's. On the EL family main.cf is a package configuration file: at the next upgrade rpm keeps the edit and writes the package's version beside it as .rpmnew; on Debian and Ubuntu it is not a dpkg conffile.
# ko:  postfix 는 main.cf 에 disable_vrfy_command = yes 를 설정하고, sendmail 은 sendmail.cf 의 PrivacyOptions 줄에 novrfy 와 noexpn 을 추가한 뒤 메일 서버를 재시작합니다. 검토 스크립트는 postfix 만 다룹니다. /etc/postfix/main.cf 를 백업하고, main.cf 가 심볼릭 링크이거나 postfix check 가 이미 거부하는 설정이면 거부하며, postconf 가 disable_vrfy_command 를 yes 로 읽지 않으면 postconf -e 로 설정한 뒤 postfix check 를 다시 실행하고, postfix 가 실행 중이었으면 postfix reload 를 실행합니다. 이 reload 는 아직 반영되지 않은 master.cf 수정도 함께 적용합니다. postconf 가 없는 호스트는 그대로 두며, sendmail 쪽은 운영자가 정리합니다. EL 계열에서 main.cf 는 패키지 설정 파일이므로 다음 업그레이드 때 rpm 은 수정본을 유지한 채 패키지의 버전을 옆에 .rpmnew 로 쓰고, Debian 과 Ubuntu 에서는 dpkg conffile 이 아닙니다.
fix_muster_service_mail_expn_vrfy() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_mail_expn_vrfy"; mkdir -p "$MB" || { log "muster.service.mail_expn_vrfy: backup failed, nothing changed"; return 1; }
  backup /etc/postfix/main.cf || { log "muster.service.mail_expn_vrfy: backup failed, nothing changed"; return 1; }
  ( set -e
    rm -f "$MB/postfix.was-running" "$MB/postfix.edited"
    if ! command -v postconf >/dev/null 2>&1; then
      log "muster.service.mail_expn_vrfy: postconf is missing; the sendmail half is the operator's"
      exit 0
    fi
    if [ -L /etc/postfix/main.cf ]; then log "muster.service.mail_expn_vrfy: /etc/postfix/main.cf is a symlink, left as is"; exit 1; fi
    if ! postfix check; then log "muster.service.mail_expn_vrfy: postfix check fails before any change; refused"; exit 1; fi
    if postfix status >/dev/null 2>&1; then : > "$MB/postfix.was-running"; fi
    rd_vrfy() { LC_ALL=C postconf -c "$1" -h disable_vrfy_command; }
    case "$(rd_vrfy /etc/postfix)" in
      [Yy][Ee][Ss]) ;;
      *)
        : > "$MB/postfix.edited"
        f=/etc/postfix/main.cf
        if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi
        postconf -c /etc/postfix -e 'disable_vrfy_command = yes'
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi
        postfix check
        if [ -f "$MB/postfix.was-running" ]; then postfix reload; fi
        ;;
    esac
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.mail_expn_vrfy: script failed (rc $rc), rolling back"
    ( set -e
      restore /etc/postfix/main.cf
      if [ -f "$MB/postfix.edited" ]; then
        postfix check
        if [ -f "$MB/postfix.was-running" ]; then postfix reload; fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.mail_expn_vrfy: rollback failed (rc $rrc)"
    restore /etc/postfix/main.cf || log "muster.service.mail_expn_vrfy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    if command -v postconf >/dev/null 2>&1; then case "$(LC_ALL=C postconf -c /etc/postfix -h disable_vrfy_command)" in [Yy][Ee][Ss]) postfix check ;; *) false ;; esac; fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.mail_expn_vrfy: validate failed, rolling back"
    ( set -e
      restore /etc/postfix/main.cf
      if [ -f "$MB/postfix.edited" ]; then
        postfix check
        if [ -f "$MB/postfix.was-running" ]; then postfix reload; fi
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.mail_expn_vrfy: rollback failed (rc $rrc)"
    restore /etc/postfix/main.cf || log "muster.service.mail_expn_vrfy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.mail_expn_vrfy: done"
}
fix_muster_service_mail_expn_vrfy
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 49/56 muster.service.snmp_disabled [risk restart_service] [fail, medium]
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

# ---- 50/56 muster.service.telnet_disabled [risk restart_service] [fail, medium]
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

# ---- 51/56 muster.service.ftp_banner [risk restart_service] [fail, low]
# why: clause does not hold
# do:  Set ftpd_banner to a notice that names no product in vsftpd.conf (or point banner_file at such a file), or set ServerIdent on "<notice>" in proftpd.conf, then restart the daemon. The review script backs up /etc/vsftpd.conf and /etc/vsftpd/vsftpd.conf and, in each that is a regular file whose greeting names a product or is vsftpd's compiled one, writes ftpd_banner=FTP server ready. - every ftpd_banner line is rewritten, or one is appended; a banner_file naming a non-empty regular file sets the greeting and is left to the operator (the script never opens it), and a symlink is left as is. When it changed a file and vsftpd was running, it restarts vsftpd.service. proftpd's ServerIdent stays the operator's, and a pure-ftpd host is reviewed by hand. vsftpd.conf is a package configuration file on both families: at the next upgrade dpkg (Debian, Ubuntu) asks about the edited file, and rpm (EL) keeps the edit and writes the package's version beside it as .rpmnew.
# ko:  vsftpd.conf 의 ftpd_banner 를 제품명이 없는 안내 문구로 설정하거나(또는 banner_file 이 그런 파일을 가리키게 하고), proftpd.conf 에 ServerIdent on "<안내 문구>" 를 설정한 뒤 데몬을 재시작합니다. 검토 스크립트는 /etc/vsftpd.conf 와 /etc/vsftpd/vsftpd.conf 를 백업한 뒤, 일반 파일이면서 접속 문구가 제품명을 담거나 vsftpd 의 컴파일 기본 문구인 파일마다 ftpd_banner=FTP server ready. 를 씁니다(모든 ftpd_banner 줄을 고쳐 쓰고, 없으면 한 줄을 덧붙입니다). banner_file 이 비어 있지 않은 일반 파일을 가리켜 문구를 정하는 경우는 운영자에게 맡기고(스크립트는 그 파일을 열지 않습니다), 심볼릭 링크는 그대로 둡니다. 파일을 바꾸었고 vsftpd 가 실행 중이었으면 vsftpd.service 를 재시작합니다. proftpd 의 ServerIdent 는 운영자가 정리하며, pure-ftpd 호스트는 수동으로 검토합니다. vsftpd.conf 는 두 계열 모두에서 패키지 설정 파일이므로, 다음 업그레이드 때 dpkg(Debian, Ubuntu)는 수정된 파일을 어떻게 할지 묻고, rpm(EL)은 수정본을 유지한 채 패키지의 버전을 옆에 .rpmnew 로 씁니다.
fix_muster_service_ftp_banner() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_service_ftp_banner"; mkdir -p "$MB" || { log "muster.service.ftp_banner: backup failed, nothing changed"; return 1; }
  backup /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf || { log "muster.service.ftp_banner: backup failed, nothing changed"; return 1; }
  ( set -e
    rm -f "$MB/vsftpd.was-running" "$MB/vsftpd.edited"
    if LC_ALL=C systemctl is-active --quiet vsftpd.service; then : > "$MB/vsftpd.was-running"; fi
    rd_greeting() { LC_ALL=C awk '{ l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; k = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", k); k = tolower(k); v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); if (k == "ftpd_banner") b = v; if (k == "banner_file") f = v } END { if (b == "" || tolower(b) ~ /(^|[^[:alnum:]_])(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)([^[:alnum:]_]|$)/) g = "disclose"; else g = "clean"; print g " " f }' "$1" | { read -r g bf; if [ -f "$bf" ] && [ ! -L "$bf" ] && [ -s "$bf" ]; then echo file; else echo "$g"; fi; }; }
    for f in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
      if [ -f "$f" ] && [ ! -L "$f" ]; then
        case "$(rd_greeting "$f")" in
          file) log "muster.service.ftp_banner: banner_file $(LC_ALL=C sed -n -E 's/^[[:space:]]*banner_file[[:space:]]*=[[:space:]]*//Ip' "$f" | tail -n 1) sets the greeting; left to the operator";;
          disclose)
            : > "$MB/vsftpd.edited"
            if LC_ALL=C grep -Eiq '^[[:space:]]*ftpd_banner[[:space:]]*=' "$f"; then
              LC_ALL=C sed -i -E 's/^[[:space:]]*ftpd_banner[[:space:]]*=.*/ftpd_banner=FTP server ready./I' "$f"
            else
              if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi
              echo 'ftpd_banner=FTP server ready.' >> "$f"
            fi
            ;;
        esac
      fi
    done
    if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then
      systemctl reset-failed vsftpd.service 2>/dev/null || :
      systemctl restart vsftpd.service
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.ftp_banner: script failed (rc $rc), rolling back"
    ( set -e
      restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf
      if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then
        systemctl reset-failed vsftpd.service 2>/dev/null || :
        systemctl restart vsftpd.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.ftp_banner: rollback failed (rc $rrc)"
    restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf || log "muster.service.ftp_banner: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    { [ ! -f /etc/vsftpd.conf ] || [ -L /etc/vsftpd.conf ] || case "$(LC_ALL=C awk '{ l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; k = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", k); k = tolower(k); v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); if (k == "ftpd_banner") b = v; if (k == "banner_file") f = v } END { if (b == "" || tolower(b) ~ /(^|[^[:alnum:]_])(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)([^[:alnum:]_]|$)/) g = "disclose"; else g = "clean"; print g " " f }' /etc/vsftpd.conf | { read -r g bf; if [ -f "$bf" ] && [ ! -L "$bf" ] && [ -s "$bf" ]; then echo file; else echo "$g"; fi; })" in clean|file) true;; *) false;; esac; } && { [ ! -f /etc/vsftpd/vsftpd.conf ] || [ -L /etc/vsftpd/vsftpd.conf ] || case "$(LC_ALL=C awk '{ l = $0; sub(/^[[:space:]]+/, "", l); if (l == "" || substr(l, 1, 1) == "#") next; i = index(l, "="); if (i == 0) next; k = substr(l, 1, i - 1); sub(/[[:space:]]+$/, "", k); k = tolower(k); v = substr(l, i + 1); sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+$/, "", v); if (k == "ftpd_banner") b = v; if (k == "banner_file") f = v } END { if (b == "" || tolower(b) ~ /(^|[^[:alnum:]_])(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)([^[:alnum:]_]|$)/) g = "disclose"; else g = "clean"; print g " " f }' /etc/vsftpd/vsftpd.conf | { read -r g bf; if [ -f "$bf" ] && [ ! -L "$bf" ] && [ -s "$bf" ]; then echo file; else echo "$g"; fi; })" in clean|file) true;; *) false;; esac; } && { [ ! -f "$MB/vsftpd.was-running" ] || systemctl is-active --quiet vsftpd.service; }
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.service.ftp_banner: validate failed, rolling back"
    ( set -e
      restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf
      if [ -f "$MB/vsftpd.edited" ] && [ -f "$MB/vsftpd.was-running" ]; then
        systemctl reset-failed vsftpd.service 2>/dev/null || :
        systemctl restart vsftpd.service
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.service.ftp_banner: rollback failed (rc $rrc)"
    restore /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf || log "muster.service.ftp_banner: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.service.ftp_banner: done"
}
fix_muster_service_ftp_banner
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 52/56 muster.account.lockout_threshold [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  RHEL family - authselect enable-feature with-faillock and set deny in /etc/security/faillock.conf; Debian family - add pam_faillock.so preauth and authfail lines to common-auth and a pam_faillock.so line to common-account (or use a pam-auth-update profile), then set deny in /etc/security/faillock.conf. A deny= argument on the pam_faillock lines wins over the file; the review script edits the file only.
# ko:  RHEL 계열은 authselect enable-feature with-faillock 을 실행하고 /etc/security/faillock.conf 에 deny 를 설정하며, Debian 계열은 common-auth 에 pam_faillock.so preauth 와 authfail 줄, common-account 에 pam_faillock.so 줄을 추가하거나 pam-auth-update 프로파일을 쓴 뒤 /etc/security/faillock.conf 에 deny 를 설정합니다. pam_faillock 줄의 deny= 인자는 파일보다 우선하며, 검토 스크립트는 파일만 고칩니다.
fix_muster_account_lockout_threshold() {
  P_max_attempts='5'
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_lockout_threshold"; mkdir -p "$MB" || { log "muster.account.lockout_threshold: backup failed, nothing changed"; return 1; }
  backup /etc/security/faillock.conf || { log "muster.account.lockout_threshold: backup failed, nothing changed"; return 1; }
  ( set -e
    fc=/etc/security/faillock.conf
    if [ -L "$fc" ]; then log "muster.account.lockout_threshold: $fc is a symlink, left as is"; exit 1; fi
    n=$P_max_attempts
    if [ -e "$fc" ]; then had=1; else had=0; fi
    v=$(awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); k = tolower(k) } k == "deny" { d = $2 } END { gsub(/[[:space:]]/, "", d); print d }' "$fc" 2>/dev/null) || v=
    case "$v" in ''|*[!0-9]*) v=3;; esac
    if [ "$v" -lt 1 ] || [ "$v" -gt "$n" ]; then
      if grep -Eq '^[[:space:]]*[Dd][Ee][Nn][Yy][[:space:]]*=' "$fc" 2>/dev/null; then sed -i -E "s|^([[:space:]]*)[Dd][Ee][Nn][Yy][[:space:]]*=.*|\1deny = $n|" "$fc"; else printf 'deny = %s\n' "$n" >> "$fc"; fi
      if [ "$had" = 0 ]; then chmod 644 "$fc"; fi
    fi
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.lockout_threshold: script failed (rc $rc), rolling back"
    restore /etc/security/faillock.conf || log "muster.account.lockout_threshold: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    { cat /etc/security/faillock.conf 2>/dev/null || :; } | awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); k = tolower(k) } k == "deny" { d = $2 } END { gsub(/[[:space:]]/, "", d); if (d == "") d = 3; exit !(d + 0 >= 1 && d + 0 <= M) }' M="$P_max_attempts"
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.lockout_threshold: validate failed, rolling back"
    restore /etc/security/faillock.conf || log "muster.account.lockout_threshold: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.lockout_threshold: done"
}
fix_muster_account_lockout_threshold
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 53/56 muster.account.password_policy [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  Install libpam-pwquality (Debian) or keep pam_pwquality in the authselect profile (RHEL). The review script tightens PASS_* in /etc/login.defs and minlen/minclass only where looser; libpwquality reads /etc/security/pwquality.conf after its .d drop-ins, so a key the main file sets is rewritten there, any other goes to pwquality.conf.d/99-muster.conf. Arguments on the pam_pwquality.so line win over the files. chage applies the ageing to every hashed account except root (uid 0, left to you), one past the maximum age (change it first), and one with no last-change day or due to change at next login (day 0). An expired password stops that account's cron and at jobs and makes an SSH-key-only account change it at login, which an unattended session cannot; exempt or lock such accounts first. A symlinked login.defs or pwquality.conf, or a symlinked 99-muster.conf (a mask), is never followed; the block stops.
# ko:  libpam-pwquality 를 설치하거나 (Debian 계열) authselect 프로파일에 pam_pwquality 를 유지합니다 (RHEL 계열). 검토 스크립트는 /etc/login.defs의 PASS_* 값을 조이고, 합친 값이 더 느슨할 때만 minlen/minclass를 조입니다. libpwquality 는 pwquality.conf.d 드롭인을 읽은 뒤 /etc/security/pwquality.conf 를 마지막에 읽으므로, 주 파일이 정한 키는 그 자리에서 고쳐 쓰고 나머지는 pwquality.conf.d/99-muster.conf에 씁니다. 또한 비밀번호 해시가 있는 모든 계정에 chage로 기간을 적용합니다. 단, root(uid 0)는 운영자에게 맡기고, 비밀번호가 이미 최대 기간에 이른 계정은 그 자리에서 만료되므로 건너뜁니다(먼저 비밀번호를 바꾸세요). pam_pwquality.so 줄의 인자는 파일보다 우선합니다. 계정의 비밀번호가 만료되면 그 계정의 cron 과 at 작업이 멈추며, SSH 키로만 로그인하는 계정은 로그인할 때 비밀번호를 바꾸라는 요구를 받는데 무인 세션은 바꿀 수 없습니다. 그런 계정은 제외하거나 먼저 비밀번호를 잠그세요. 마지막 변경일이 없는 계정과 다음 로그인 때 바꾸도록 이미 설정된 계정(0일)은 그대로 둡니다. 심볼릭 링크인 /etc/login.defs·pwquality.conf 와 심볼릭 링크(마스크)인 99-muster.conf 는 따라가지 않고 그 블록을 멈춥니다.
fix_muster_account_password_policy() {
  P_max_days='90'
  P_min_classes='3'
  P_min_days='1'
  P_min_len='8'
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_password_policy"; mkdir -p "$MB" || { log "muster.account.password_policy: backup failed, nothing changed"; return 1; }
  backup /etc/login.defs /etc/security/pwquality.conf /etc/security/pwquality.conf.d/99-muster.conf || { log "muster.account.password_policy: backup failed, nothing changed"; return 1; }
  ( set -e
    ld=/etc/login.defs
    pc=/etc/security/pwquality.conf
    pf=/etc/security/pwquality.conf.d/99-muster.conf
    if [ -L "$ld" ]; then log "muster.account.password_policy: $ld is a symlink, left as is"; exit 1; fi
    if [ -L "$pc" ]; then log "muster.account.password_policy: $pc is a symlink, left as is"; exit 1; fi
    if [ -L "$pf" ]; then log "muster.account.password_policy: $pf is a symlink (a mask), left as is"; exit 1; fi
    first_val() { awk -v k="$1" '$1 == k { print $2; exit }' "$ld"; }
    set_key() {
      if grep -Eq "^[[:space:]]*$1[[:space:]]" "$ld"; then sed -i -E "s|^([[:space:]]*$1)[[:space:]].*|\1 $2|" "$ld"; else printf '%s %s\n' "$1" "$2" >> "$ld"; fi
    }
    v=$(first_val PASS_MAX_DAYS)
    case "$v" in ''|*[!0-9]*) set_key PASS_MAX_DAYS "$P_max_days";; *) if [ "$v" -gt "$P_max_days" ]; then set_key PASS_MAX_DAYS "$P_max_days"; fi;; esac
    v=$(first_val PASS_MIN_DAYS)
    case "$v" in ''|*[!0-9]*) set_key PASS_MIN_DAYS "$P_min_days";; *) if [ "$v" -lt "$P_min_days" ]; then set_key PASS_MIN_DAYS "$P_min_days"; fi;; esac
    v=$(first_val PASS_MIN_LEN)
    case "$v" in ''|*[!0-9]*) set_key PASS_MIN_LEN "$P_min_len";; *) if [ "$v" -lt "$P_min_len" ]; then set_key PASS_MIN_LEN "$P_min_len"; fi;; esac
    merged() { # minlen and required classes over the file chain in libpwquality's order (the drop-ins, then pwquality.conf), last wins
      for f in /etc/security/pwquality.conf.d/*.conf "$pc"; do
        if [ -f "$f" ]; then cat "$f"; echo; fi
      done | awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); k = tolower(k); v = $2; gsub(/[[:space:]]/, "", v) } k ~ /^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)$/ { x[k] = v } END { ml = ("minlen" in x) ? x["minlen"] + 0 : 8; rc = x["minclass"] + 0; n = 0; if (x["dcredit"] + 0 <= -1) n++; if (x["ucredit"] + 0 <= -1) n++; if (x["lcredit"] + 0 <= -1) n++; if (x["ocredit"] + 0 <= -1) n++; if (n > rc) rc = n; print ml, rc }'
    }
    pput() { # pwquality.conf is read last: a key it sets is rewritten there, on every line that sets it; any other goes to 99-muster.conf
      if [ -f "$pc" ] && awk -F= -v k="$1" '{ x = $1; gsub(/[[:space:]]/, "", x) } tolower(x) == k { f = 1 } END { exit !f }' "$pc"; then
        awk -F= -v k="$1" -v v="$2" '{ x = $1; gsub(/[[:space:]]/, "", x) } tolower(x) == k { print k " = " v; next } { print }' "$pc" > "$MB/pwquality.tmp"
        cat "$MB/pwquality.tmp" > "$pc"
        return 0
      fi
      if [ ! -d /etc/security/pwquality.conf.d ]; then mkdir -p /etc/security/pwquality.conf.d; chmod 755 /etc/security/pwquality.conf.d; fi
      if [ -f "$pf" ] && awk -F= -v k="$1" '{ x = $1; gsub(/[[:space:]]/, "", x) } tolower(x) == k { f = 1 } END { exit !f }' "$pf"; then
        awk -F= -v k="$1" -v v="$2" '{ x = $1; gsub(/[[:space:]]/, "", x) } tolower(x) == k { print k " = " v; next } { print }' "$pf" > "$MB/pwquality.tmp"
        cat "$MB/pwquality.tmp" > "$pf"
      else printf '%s = %s\n' "$1" "$2" >> "$pf"; fi
      chmod 644 "$pf"
    }
    # shellcheck disable=SC2046
    set -- $(merged)
    if [ "$1" -lt "$P_min_len" ]; then pput minlen "$P_min_len"; fi
    if [ "$2" -lt "$P_min_classes" ]; then pput minclass "$P_min_classes"; fi
    today=$(( $(date +%s) / 86400 ))
    awk -F: -v OFS=: 'NF >= 8 && $1 !~ /^#/ && $1 != "" && $2 != "" && $2 !~ /^[!*]/ { print $1, $3, $4, $5 }' /etc/shadow > "$MB/ageing.scan"
    while IFS=: read -r name last min max; do
      awk -F: -v n="$name" '$1 == n { f = 1 } END { exit !f }' /etc/passwd || { log "muster.account.password_policy: $name: not in /etc/passwd, left as is"; continue; }
      if awk -F: -v n="$name" '$1 == n && $3 == 0 { f = 1 } END { exit !f }' /etc/passwd; then log "muster.account.password_policy: $name: root's password ageing is left to the operator: an expired root password stops root's cron and at jobs"; continue; fi
      case "$last" in ''|0|*[!0-9]*) log "muster.account.password_policy: $name has no last-change day, left as is"; continue;; esac
      if [ $((today - last)) -ge "$P_max_days" ]; then log "muster.account.password_policy: $name: password at least $P_max_days days old, change it first"; continue; fi
      awk -F: -v n="$name" '$1 == n { f = 1 } END { exit !f }' "$MB/ageing.list" 2>/dev/null || printf '%s:%s:%s\n' "$name" "${min:--1}" "${max:--1}" >> "$MB/ageing.list"
      case "$max" in ''|*[!0-9]*) chage -M "$P_max_days" -- "$name";; *) if [ "$max" -gt "$P_max_days" ]; then chage -M "$P_max_days" -- "$name"; fi;; esac
      case "$min" in ''|*[!0-9]*) chage -m "$P_min_days" -- "$name";; *) if [ "$min" -lt "$P_min_days" ]; then chage -m "$P_min_days" -- "$name"; fi;; esac
    done < "$MB/ageing.scan"
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.password_policy: script failed (rc $rc), rolling back"
    ( set -e
      if [ -f "$MB/ageing.list" ]; then
        while IFS=: read -r name min max; do chage -m "$min" -M "$max" -- "$name"; done < "$MB/ageing.list"
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.password_policy: rollback failed (rc $rrc)"
    restore /etc/login.defs /etc/security/pwquality.conf /etc/security/pwquality.conf.d/99-muster.conf || log "muster.account.password_policy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    awk '$1 == "PASS_MAX_DAYS" && a == "" { a = $2 } $1 == "PASS_MIN_DAYS" && b == "" { b = $2 } $1 == "PASS_MIN_LEN" && c == "" { c = $2 } END { exit !(a != "" && a + 0 <= M && b + 0 >= m && c + 0 >= l) }' M="$P_max_days" m="$P_min_days" l="$P_min_len" /etc/login.defs && for f in /etc/security/pwquality.conf.d/*.conf /etc/security/pwquality.conf; do if [ -f "$f" ]; then cat "$f"; echo; fi; done | awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); k = tolower(k); v = $2; gsub(/[[:space:]]/, "", v) } k ~ /^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)$/ { x[k] = v } END { ml = ("minlen" in x) ? x["minlen"] + 0 : 8; rc = x["minclass"] + 0; n = 0; if (x["dcredit"] + 0 <= -1) n++; if (x["ucredit"] + 0 <= -1) n++; if (x["lcredit"] + 0 <= -1) n++; if (x["ocredit"] + 0 <= -1) n++; if (n > rc) rc = n; exit !(ml >= L && rc >= C) }' L="$P_min_len" C="$P_min_classes"
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.password_policy: validate failed, rolling back"
    ( set -e
      if [ -f "$MB/ageing.list" ]; then
        while IFS=: read -r name min max; do chage -m "$min" -M "$max" -- "$name"; done < "$MB/ageing.list"
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.password_policy: rollback failed (rc $rrc)"
    restore /etc/login.defs /etc/security/pwquality.conf /etc/security/pwquality.conf.d/99-muster.conf || log "muster.account.password_policy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.password_policy: done"
}
fix_muster_account_password_policy
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 54/56 muster.account.root_remote_login [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  Set PermitRootLogin no in /etc/ssh/sshd_config.d/00-muster.conf, validate with sshd -t, then restart sshd while keeping a second session open. Where /etc/securetty lists pts/* entries instead, remove those lines so no pseudo-terminal can be used for a securetty-gated root login. sshd keeps the first value it reads: a drop-in that sorts before 00-muster.conf, or a PermitRootLogin line before the Include in sshd_config, still wins. The script reloads a running sshd; a Match block that sets PermitRootLogin for root also wins, and the validate then fails and rolls back.
# ko:  /etc/ssh/sshd_config.d/00-muster.conf 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤, 다른 세션을 열어 둔 채 sshd 를 재시작합니다. 대신 /etc/securetty 에 pts/* 항목이 있다면 그 줄을 제거하여 securetty 로 통제되는 root 로그인에 가상 터미널을 쓸 수 없게 합니다. sshd는 처음 읽은 값을 지키므로 00-muster.conf보다 먼저 정렬되는 드롭인이나 sshd_config의 Include 앞 PermitRootLogin 줄이 여전히 이깁니다. 스크립트는 실행 중인 sshd를 다시 읽게 합니다. root에 PermitRootLogin을 정하는 Match 블록도 이기며, 그러면 validate가 실패하고 롤백합니다.
fix_muster_account_root_remote_login() {
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_root_remote_login"; mkdir -p "$MB" || { log "muster.account.root_remote_login: backup failed, nothing changed"; return 1; }
  backup /etc/ssh/sshd_config.d/00-muster.conf /etc/securetty || { log "muster.account.root_remote_login: backup failed, nothing changed"; return 1; }
  ( set -e
    if [ -L /etc/ssh/sshd_config.d/00-muster.conf ]; then log "muster.account.root_remote_login: /etc/ssh/sshd_config.d/00-muster.conf is a symlink (a mask), left as is"; exit 1; fi
    if [ -L /etc/securetty ]; then log "muster.account.root_remote_login: /etc/securetty is a symlink, left as is"; exit 1; fi
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
      [ -L /etc/ssh/sshd_config.d/00-muster.conf ] || rm -f /etc/ssh/sshd_config.d/00-muster.conf
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
      [ -L /etc/ssh/sshd_config.d/00-muster.conf ] || rm -f /etc/ssh/sshd_config.d/00-muster.conf
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

# ---- 55/56 muster.service.nis_disabled [risk lockout_risk] [fail, high]
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

# ---- 56/56 muster.beyond.account_inactivity_lock [risk lockout_risk] [fail, medium]
# keep a second session open; a lockout here needs console access
# why: clause does not hold
# do:  The review script writes INACTIVE=<max_inactive_days> to /etc/default/useradd when its value is unset or above the bound (a symlink stops the block), then runs chage -I on each local login-capable account, root included, whose field is unset or above it. It logs the day each account with a real maximum age will be disabled unless its password changes, root first: on a host that ages root, root's key login stops that day. It skips and names an account with no /etc/shadow entry, a field that is not a number, one that must change its password at next login (day 0, or no last-change day under a real maximum), and one whose password expired max_inactive_days or more days ago, which the bound would disable at once: change it first. Accounts only a remote NSS source holds are left. The rollback replays the old values. /etc/default/useradd is a package configuration file: at the next upgrade dpkg (Debian, Ubuntu) asks about the edit, and rpm (EL) writes the package's version as .rpmnew.
# ko:  검토 스크립트는 /etc/default/useradd 의 값이 설정되지 않았거나 기한보다 크면 INACTIVE=<max_inactive_days> 를 쓰고(심볼릭 링크이면 블록을 멈춥니다), root 를 포함한 로컬의 로그인 가능한 계정 중 필드가 비어 있거나 기한보다 큰 계정마다 chage -I 를 실행합니다. 실제 최대 사용 기간이 있는 계정은 비밀번호를 바꾸지 않으면 비활성화되는 날짜를 root 부터 기록합니다. root 에 사용 기간을 두는 호스트에서는 그날부터 root 의 키 로그인도 멈춥니다. /etc/shadow 항목이 없는 계정, 필드가 숫자가 아닌 계정, 다음 로그인 때 비밀번호를 바꿔야 하는 계정(0일, 또는 실제 최대 기간이 있는데 마지막 변경일이 없는 계정), 비밀번호가 만료된 지 max_inactive_days 일 이상 지나 기한을 주면 곧바로 비활성화될 계정은 건너뛰고 이름을 남깁니다. 이런 계정은 먼저 비밀번호를 바꾸세요. 원격 NSS 소스에만 있는 계정은 그대로 둡니다. 롤백은 이전 값을 되돌립니다. /etc/default/useradd 는 패키지 설정 파일이므로, 다음 업그레이드 때 dpkg(Debian, Ubuntu)는 수정된 파일을 어떻게 할지 묻고, rpm(EL)은 패키지의 버전을 .rpmnew 로 씁니다.
fix_muster_beyond_account_inactivity_lock() {
  P_max_inactive_days='35'
  MB="$MUSTER_BACKUP/blocks/fix_muster_beyond_account_inactivity_lock"; mkdir -p "$MB" || { log "muster.beyond.account_inactivity_lock: backup failed, nothing changed"; return 1; }
  backup /etc/default/useradd || { log "muster.beyond.account_inactivity_lock: backup failed, nothing changed"; return 1; }
  ( set -e
    n=$P_max_inactive_days
    rm -f "$MB/inactive.run"
    : > "$MB/inactive.run"
    if [ "$n" -lt 0 ]; then log "muster.beyond.account_inactivity_lock: max_inactive_days is negative; refused"; exit 1; fi
    f=/etc/default/useradd
    if [ -L "$f" ]; then log "muster.beyond.account_inactivity_lock: $f is a symlink, left as is"; exit 1; fi
    rd_inactive() { LC_ALL=C awk 'function num(s,  i, n, g, b, v, d, st) { n = length(s); i = 1; while (i <= n && index(" \t\n\v\f\r", substr(s, i, 1))) i++; g = 1; if (i <= n && (substr(s, i, 1) == "+" || substr(s, i, 1) == "-")) { if (substr(s, i, 1) == "-") g = -1; i++ } b = 10; if (i + 2 <= n && substr(s, i, 2) ~ /^0[xX]$/ && index("0123456789abcdefABCDEF", substr(s, i + 2, 1))) { b = 16; i += 2 } else if (substr(s, i, 1) == "0") b = 8; st = i; v = 0; for (; i <= n; i++) { d = index("0123456789abcdef", tolower(substr(s, i, 1))) - 1; if (d < 0 || d >= b) break; v = v * b + d } if (i == st || i <= n) return -1; if (g < 0) return (v == 0) ? 0 : -1; return v } BEGIN { v = -1 } /^INACTIVE=/ { v = num(substr($0, 10)) } END { print v }' "$1"; }
    rd_login() { LC_ALL=C awk -F: 'FILENAME == ARGV[1] { if (!got) { l = $0; gsub(/[[:space:]]+/, " ", l); sub(/^ /, "", l); if (l != "" && l !~ /^#/ && split(l, w, " ") >= 2 && w[1] == "UID_MIN") { got = 1; m = (w[2] ~ /^[+-]?[0-9]+$/) ? w[2] + 0 : 1000 } } next } FILENAME == ARGV[2] { l = $0; sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+$/, "", l); if (l != "" && l !~ /^#/) sh[l] = 1; next } { sub(/\r$/, "") } $0 ~ /^#/ || NF < 7 || $1 == "" { next } { u = $3; sub(/^[[:space:]]+/, "", u); sub(/[[:space:]]+$/, "", u); u = (u ~ /^[+-]?[0-9]+$/) ? u + 0 : -1; if (u > 0 && u < (got ? m : 1000)) next; if ($7 == "" || $7 ~ /\/(nologin|false)$/ || !($7 in sh)) next; if (u == 0) print $1; else r[++c] = $1 } END { for (i = 1; i <= c; i++) print r[i] }' "$1" "$2" "$3"; }
    v=-1
    if [ -f "$f" ]; then v=$(rd_inactive "$f"); fi
    case "$v" in ''|*[!0-9-]*|??????????*) v=-1;; esac
    if [ "$v" -lt 0 ] || [ "$v" -gt "$n" ]; then
      if [ ! -e "$f" ]; then
        printf 'INACTIVE=%s\n' "$n" > "$f"
        chmod 644 "$f"
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi
      elif LC_ALL=C grep -q '^INACTIVE=' "$f"; then
        sed -i "s/^INACTIVE=.*/INACTIVE=$n/" "$f"
      else
        if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi
        printf 'INACTIVE=%s\n' "$n" >> "$f"
      fi
    fi
    ld=/etc/login.defs
    if [ ! -f "$ld" ]; then ld=/dev/null; fi
    sf=/etc/shadow
    if [ ! -f "$sf" ]; then sf=/dev/null; fi
    rd_login "$ld" /etc/shells /etc/passwd > "$MB/inactive.scan"
    LC_ALL=C awk -F: 'function d(v,  g) { if (v == "") return -1; if (v !~ /^-?[0-9]+$/) return "x"; g = ""; if (v ~ /^-/) { g = "-"; v = substr(v, 2) } sub(/^0+/, "", v); if (v == "") return 0; if (length(v) > 9) return "x"; return g v } FILENAME == ARGV[1] { sub(/\r$/, ""); if (NF >= 8 && $1 != "" && $1 !~ /^#/) { m = d($5); if (m != "x" && m + 0 < -1) m = "x"; s[$1] = d($3) ":" m ":" d($7); c[$1]++ } next } !seen[$0]++ { print $0 ":" (($0 in s) ? (c[$0] > 1 ? "2:" : "1:") s[$0] : "0:::") }' "$sf" "$MB/inactive.scan" > "$MB/inactive.rows"
    today=$(( $(date +%s) / 86400 ))
    : >> "$MB/inactive.list"
    while IFS=: read -r name has last max old; do
      if [ "$has" = 0 ]; then log "muster.beyond.account_inactivity_lock: $name: no /etc/shadow entry, left as is"; continue; fi
      if [ "$has" != 1 ]; then log "muster.beyond.account_inactivity_lock: $name: more than one /etc/shadow entry, left as is"; continue; fi
      if [ "$old" != x ] && [ "$old" != -1 ] && [ "$old" -le "$n" ]; then continue; fi
      if [ "$old" = x ]; then log "muster.beyond.account_inactivity_lock: $name: inactivity field is not a number, left as is"; continue; fi
      if [ "$last" = x ] || [ "$max" = x ]; then log "muster.beyond.account_inactivity_lock: $name: password ageing fields are not numbers or the maximum is below -1, left as is"; continue; fi
      aged=
      if [ "$max" -ge 0 ] && [ "$max" -ne 99999 ]; then aged=1; fi
      if [ "$last" -eq 0 ] || { [ "$last" -lt 0 ] && [ -n "$aged" ]; }; then log "muster.beyond.account_inactivity_lock: $name: must change its password at next login, left as is"; continue; fi
      if [ "$last" -gt 0 ] && [ "$max" -ge 0 ] && [ $((today - last)) -ge $((max + n)) ]; then
        log "muster.beyond.account_inactivity_lock: $name: password expired $((today - last - max)) days ago; the bound would disable it now; change its password first"
        continue
      fi
      if [ -n "$aged" ] && [ "$last" -gt 0 ]; then log "muster.beyond.account_inactivity_lock: $name will be disabled on $(date -u -d "@$(( (last + max + n) * 86400 ))" +%F) unless its password changes"; fi
      k=$name LC_ALL=C awk -F: '$1 == ENVIRON["k"] { f = 1 } END { exit !f }' "$MB/inactive.list" || printf '%s:%s\n' "$name" "$old" >> "$MB/inactive.list"
      printf '%s\n' "$name" >> "$MB/inactive.run"
      chage -I "$n" -- "$name"
    done < "$MB/inactive.rows"
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.account_inactivity_lock: script failed (rc $rc), rolling back"
    ( set -e
      rc=0
      if [ -f "$MB/inactive.run" ]; then
        while IFS= read -r name; do
          old=$(k=$name LC_ALL=C awk -F: '$1 == ENVIRON["k"] { print $2; exit }' "$MB/inactive.list")
          chage -I "$old" -- "$name" || rc=1
        done < "$MB/inactive.run"
      fi
      exit "$rc"
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.beyond.account_inactivity_lock: rollback failed (rc $rrc)"
    restore /etc/default/useradd || log "muster.beyond.account_inactivity_lock: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    v=$(LC_ALL=C awk 'function num(s,  i, n, g, b, v, d, st) { n = length(s); i = 1; while (i <= n && index(" \t\n\v\f\r", substr(s, i, 1))) i++; g = 1; if (i <= n && (substr(s, i, 1) == "+" || substr(s, i, 1) == "-")) { if (substr(s, i, 1) == "-") g = -1; i++ } b = 10; if (i + 2 <= n && substr(s, i, 2) ~ /^0[xX]$/ && index("0123456789abcdefABCDEF", substr(s, i + 2, 1))) { b = 16; i += 2 } else if (substr(s, i, 1) == "0") b = 8; st = i; v = 0; for (; i <= n; i++) { d = index("0123456789abcdef", tolower(substr(s, i, 1))) - 1; if (d < 0 || d >= b) break; v = v * b + d } if (i == st || i <= n) return -1; if (g < 0) return (v == 0) ? 0 : -1; return v } BEGIN { v = -1 } /^INACTIVE=/ { v = num(substr($0, 10)) } END { print v }' /etc/default/useradd) && [ "$v" -ge 0 ] && [ "$v" -le "$P_max_inactive_days" ] && { [ ! -s "$MB/inactive.run" ] || LC_ALL=C awk -F: -v N="$P_max_inactive_days" 'FILENAME == ARGV[1] { w[$0] = 1; next } { sub(/\r$/, "") } ($1 in w) && NF >= 8 { x[$1] = $7 } END { for (k in w) if ((k in x) && !(x[k] ~ /^[0-9]+$/ && x[k] + 0 <= N + 0)) exit 1 }' "$MB/inactive.run" /etc/shadow; }
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.beyond.account_inactivity_lock: validate failed, rolling back"
    ( set -e
      rc=0
      if [ -f "$MB/inactive.run" ]; then
        while IFS= read -r name; do
          old=$(k=$name LC_ALL=C awk -F: '$1 == ENVIRON["k"] { print $2; exit }' "$MB/inactive.list")
          chage -I "$old" -- "$name" || rc=1
        done < "$MB/inactive.run"
      fi
      exit "$rc"
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.beyond.account_inactivity_lock: rollback failed (rc $rrc)"
    restore /etc/default/useradd || log "muster.beyond.account_inactivity_lock: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.beyond.account_inactivity_lock: done"
}
fix_muster_beyond_account_inactivity_lock
[ "$?" -eq 0 ] || failed=$((failed+1))

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
