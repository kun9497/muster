#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host ubuntu-container, collected 2026-10-20T02:41:54Z; controls kisa-unix-2026+2026.10.19 sha256:46be3e952588b21dda1314a9bc002f6f2ef777dc9b57a441e2ee68a9c2f159ef
# profile default (sha256:f4db63e671d12ad73cca111ca4132cb5459983bc32409b21c571067674bf9c78); max-risk lockout_risk
# planned 10 (script 5, text only 5); above max-risk 0; not planned: error 0, manual 2, warn_degraded 0
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

# ---- 1/10 muster.account.cron_permissions [risk none] [fail, high]
# why: clause does not hold: cron.files each require mode in [0 32 128 160 256 288 384 416]
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

# ---- 2/10 muster.file.services_permissions [risk none] [fail, high]
# why: absent counts as fail: files.etc_services.uid is absent on this host
# do:  chown root:root /etc/services; chmod 644 /etc/services (the script only clears bits; a stricter file is left as it is)
# ko:  chown root:root /etc/services; chmod 644 /etc/services (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다)
# text only: the finding is an absent file

# ---- 3/10 muster.file.shadow_permissions [risk none] [fail, high]
# why: clause does not hold: files.etc_shadow.mode in [0 256]
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

# ---- 4/10 muster.account.session_timeout [risk none] [fail, low]
# why: absent counts as fail: no mechanism applies to this host
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

# ---- 5/10 muster.account.unnecessary_accounts [risk none] [warn, low]
# why: clause does not hold: accounts.users none where name in [lp uucp nuucp]
# do:  Remove each listed account with userdel <name> after confirming nothing on the host runs as it (ps -u <name>; find / -user <name>).
# ko:  호스트에서 해당 계정으로 실행되는 것이 없음을 확인한 뒤 (ps -u <name>; find / -user <name>) userdel <name> 으로 제거합니다.
# text only: no script declared

# ---- 6/10 muster.service.login_banner [risk none] [warn, low]
# why: clause does not hold: banners.issue_net.os_escapes eq false
# do:  Point sshd's Banner at a file holding your warning (Banner /etc/issue.net in /etc/ssh/sshd_config.d/, validate with sshd -t, restart sshd) and replace the distribution string in /etc/issue and /etc/issue.net with an authorized-use warning.
# ko:  sshd 의 Banner 를 경고 문구가 담긴 파일로 지정하고(/etc/ssh/sshd_config.d/ 에 Banner /etc/issue.net, sshd -t 로 검증 후 재시작) /etc/issue 와 /etc/issue.net 의 배포판 문자열을 인가된 사용 경고로 바꿉니다.
# text only: no script declared

# ---- 7/10 muster.file.hosts_permissions [risk restart_service] [fail, high]
# why: clause does not hold: files.etc_hosts.mode in [0 128 256 384]
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

# ---- 8/10 muster.account.lockout_threshold [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: absent counts as fail: pam.faillock.deny is absent on this host
# do:  RHEL family - authselect enable-feature with-faillock and set deny in /etc/security/faillock.conf; Debian family - add pam_faillock.so preauth and authfail lines to common-auth and a pam_faillock.so line to common-account (or use a pam-auth-update profile), then set deny in /etc/security/faillock.conf. A deny= argument on the pam_faillock lines wins over the file; the review script edits the file only.
# ko:  RHEL 계열은 authselect enable-feature with-faillock 을 실행하고 /etc/security/faillock.conf 에 deny 를 설정하며, Debian 계열은 common-auth 에 pam_faillock.so preauth 와 authfail 줄, common-account 에 pam_faillock.so 줄을 추가하거나 pam-auth-update 프로파일을 쓴 뒤 /etc/security/faillock.conf 에 deny 를 설정합니다. pam_faillock 줄의 deny= 인자는 파일보다 우선하며, 검토 스크립트는 파일만 고칩니다.
# text only: the finding is an absent file

# ---- 9/10 muster.account.password_policy [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: absent counts as fail: accounts.login_defs.pass_min_len is absent on this host
# do:  Install libpam-pwquality (Debian family) or keep pam_pwquality in the authselect profile (RHEL family). The review script tightens PASS_* in /etc/login.defs, writes minlen/minclass to /etc/security/pwquality.conf.d/99-muster.conf only where the merged value is looser, and applies the ageing with chage to every account with a password hash except root (uid 0, left to you) and one whose password has already reached the maximum age (it would expire on the spot; change it first). Arguments on the pam_pwquality.so line win over the files. Once an account's password expires, that account's cron and at jobs stop, and an account that logs in only by SSH key is made to change its password at login, which an unattended session cannot; exempt such accounts or lock their password first. An account with no last-change day, or set to change at next login (day 0), is left as is. A symlinked /etc/login.defs, or a 99-muster.conf that is a symlink (a mask), is never followed; the block stops.
# ko:  libpam-pwquality 를 설치하거나 (Debian 계열) authselect 프로파일에 pam_pwquality 를 유지합니다 (RHEL 계열). 검토 스크립트는 /etc/login.defs의 PASS_* 값을 조이고, 합친 값이 더 느슨할 때만 minlen/minclass를 /etc/security/pwquality.conf.d/99-muster.conf에 쓰며, 비밀번호 해시가 있는 모든 계정에 chage로 기간을 적용합니다. 단, root(uid 0)는 운영자에게 맡기고, 비밀번호가 이미 최대 기간에 이른 계정은 그 자리에서 만료되므로 건너뜁니다(먼저 비밀번호를 바꾸세요). pam_pwquality.so 줄의 인자는 파일보다 우선합니다. 계정의 비밀번호가 만료되면 그 계정의 cron 과 at 작업이 멈추며, SSH 키로만 로그인하는 계정은 로그인할 때 비밀번호를 바꾸라는 요구를 받는데 무인 세션은 바꿀 수 없습니다. 그런 계정은 제외하거나 먼저 비밀번호를 잠그세요. 마지막 변경일이 없는 계정과 다음 로그인 때 바꾸도록 이미 설정된 계정(0일)은 그대로 둡니다. 심볼릭 링크인 /etc/login.defs 와 심볼릭 링크(마스크)인 99-muster.conf 는 따라가지 않고 그 블록을 멈춥니다.
fix_muster_account_password_policy() {
  P_max_days='90'
  P_min_classes='3'
  P_min_days='1'
  P_min_len='8'
  MB="$MUSTER_BACKUP/blocks/fix_muster_account_password_policy"; mkdir -p "$MB" || { log "muster.account.password_policy: backup failed, nothing changed"; return 1; }
  backup /etc/login.defs /etc/security/pwquality.conf.d/99-muster.conf || { log "muster.account.password_policy: backup failed, nothing changed"; return 1; }
  ( set -e
    ld=/etc/login.defs
    pf=/etc/security/pwquality.conf.d/99-muster.conf
    if [ -L "$ld" ]; then log "muster.account.password_policy: $ld is a symlink, left as is"; exit 1; fi
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
    merged() { # minlen and required classes over the file chain, last wins (the collector's read)
      for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
        if [ -f "$f" ]; then cat "$f"; fi
      done | awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); k = tolower(k); v = $2; gsub(/[[:space:]]/, "", v) } k ~ /^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)$/ { x[k] = v } END { ml = ("minlen" in x) ? x["minlen"] + 0 : 8; rc = x["minclass"] + 0; n = 0; if (x["dcredit"] + 0 <= -1) n++; if (x["ucredit"] + 0 <= -1) n++; if (x["lcredit"] + 0 <= -1) n++; if (x["ocredit"] + 0 <= -1) n++; if (n > rc) rc = n; print ml, rc }'
    }
    pput() {
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
    restore /etc/login.defs /etc/security/pwquality.conf.d/99-muster.conf || log "muster.account.password_policy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  # validate
  ( set -e
    awk '$1 == "PASS_MAX_DAYS" && a == "" { a = $2 } $1 == "PASS_MIN_DAYS" && b == "" { b = $2 } $1 == "PASS_MIN_LEN" && c == "" { c = $2 } END { exit !(a != "" && a + 0 <= M && b + 0 >= m && c + 0 >= l) }' M="$P_max_days" m="$P_min_days" l="$P_min_len" /etc/login.defs && for f in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do if [ -f "$f" ]; then cat "$f"; fi; done | awk -F= '{ k = $1; gsub(/[[:space:]]/, "", k); k = tolower(k); v = $2; gsub(/[[:space:]]/, "", v) } k ~ /^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)$/ { x[k] = v } END { ml = ("minlen" in x) ? x["minlen"] + 0 : 8; rc = x["minclass"] + 0; n = 0; if (x["dcredit"] + 0 <= -1) n++; if (x["ucredit"] + 0 <= -1) n++; if (x["lcredit"] + 0 <= -1) n++; if (x["ocredit"] + 0 <= -1) n++; if (n > rc) rc = n; exit !(ml >= L && rc >= C) }' L="$P_min_len" C="$P_min_classes"
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.account.password_policy: validate failed, rolling back"
    ( set -e
      if [ -f "$MB/ageing.list" ]; then
        while IFS=: read -r name min max; do chage -m "$min" -M "$max" -- "$name"; done < "$MB/ageing.list"
      fi
    ); rrc=$?
    [ "$rrc" -eq 0 ] || log "muster.account.password_policy: rollback failed (rc $rrc)"
    restore /etc/login.defs /etc/security/pwquality.conf.d/99-muster.conf || log "muster.account.password_policy: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.account.password_policy: done"
}
fix_muster_account_password_policy
[ "$?" -eq 0 ] || failed=$((failed+1))

# ---- 10/10 muster.account.su_restricted [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold: pam.su.wheel_required eq true
# do:  Uncomment or add "auth required pam_wheel.so use_uid" in /etc/pam.d/su and put the administrators in the wheel group (or name another group with group=).
# ko:  /etc/pam.d/su 에서 "auth required pam_wheel.so use_uid" 줄의 주석을 풀거나 추가하고, 관리자를 wheel 그룹 (또는 group= 으로 지정한 그룹) 에 넣습니다.
# text only: no script declared

if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
