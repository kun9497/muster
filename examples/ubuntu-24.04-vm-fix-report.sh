#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host github-runner, collected 2026-10-20T02:41:54Z; controls kisa-unix-2026+2026.10.19 sha256:46be3e952588b21dda1314a9bc002f6f2ef777dc9b57a441e2ee68a9c2f159ef
# profile default (sha256:f4db63e671d12ad73cca111ca4132cb5459983bc32409b21c571067674bf9c78); max-risk lockout_risk
# planned 43 (script 20, text only 23); above max-risk 0; not planned: error 0, manual 7, warn_degraded 1
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
MUSTER_SNAPSHOT_HOST=e7244411fdd82f17ae61972eb64a50c3df21d38725238f76d6ce6064a1bc4701
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

# ---- 1/43 muster.account.cron_permissions [risk none] [fail, high]
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

# ---- 2/43 muster.account.root_home_and_path [risk none] [fail, high]
# why: clause does not hold: env.shell.root_path_entries none where is_dot eq true
# do:  chown root:root /root, chmod 700 /root, and remove any empty, ".", relative, or world-writable entry from root's PATH in /etc/profile and root's shell startup files.
# ko:  chown root:root /root, chmod 700 /root 를 적용하고, /etc/profile 과 root 의 셸 시작 파일에서 root PATH 의 빈 요소, ".", 상대 경로, 전체 쓰기 가능 항목을 제거합니다.
# text only: no script declared

# ---- 3/43 muster.beyond.package_files_unmodified [risk none] [fail, high]
# why: clause does not hold: packages.verify.modified none where path present
# do:  For each path in packages.verify.modified, find the package that owns it (rpm -qf, or dpkg -S) and find out why it changed. A change nobody can account for is an incident — keep the file for analysis before replacing it. Otherwise reinstall the package (dnf reinstall, or apt install --reinstall) to put the packaged file back, and make a deliberate local change through a configuration file or a package of your own instead.
# ko:  packages.verify.modified 의 각 경로마다 소유 패키지를 찾고(rpm -qf 또는 dpkg -S) 바뀐 이유를 확인합니다. 아무도 설명할 수 없는 변경은 침해 사고이므로 교체하기 전에 분석용으로 파일을 보관하십시오. 그렇지 않다면 패키지를 다시 설치해(dnf reinstall 또는 apt install --reinstall) 패키지의 파일을 되돌리고, 의도한 로컬 변경은 설정 파일이나 자체 패키지로 하십시오.
# text only: no script declared

# ---- 4/43 muster.beyond.root_unit_exec_writable [risk none] [fail, high]
# why: clause does not hold: units.exec_writable none where why present
# do:  For each row, record the current owner and mode first (stat -c '%U:%G %a %n' <path>), then chown root:root <path> and chmod go-w <path> - on the file, or on its directory when the row says parent_writable - or move the executable to a root-owned directory and point the unit at it. Restore with chown <recorded owner> <path> and chmod <recorded mode> <path>. systemctl daemon-reload picks up an edited unit file.
# ko:  각 행마다 먼저 현재 소유자와 mode 를 기록한 뒤(stat -c '%U:%G %a %n' <path>) chown root:root <path> 와 chmod go-w <path> 를 실행합니다. 대상은 그 파일이며, 행이 parent_writable 이면 그 디렉터리입니다. 또는 실행 파일을 root 소유 디렉터리로 옮기고 unit 이 그것을 가리키게 합니다. chown <기록한 소유자> <path> 와 chmod <기록한 mode> <path> 로 되돌립니다. 편집한 unit 파일은 systemctl daemon-reload 로 반영됩니다.
# text only: no script declared

# ---- 5/43 muster.beyond.sudo_nopasswd_all [risk none] [fail, high]
# why: clause does not hold: sudo.nopasswd_all none where value not_in []
# do:  Copy the file first (cp -a <file> <file>.bak), then edit it with visudo -f <file> - drop NOPASSWD from the ALL line, or narrow the line to the commands the account really needs - and remove any Defaults !authenticate line. Give the account a password or a key-backed PAM method before it loses NOPASSWD, or it cannot use sudo at all. Restore with cp -a <file>.bak <file>; visudo -c checks the result.
# ko:  먼저 파일을 복사한 뒤(cp -a <file> <file>.bak) visudo -f <file> 로 편집합니다. ALL 줄에서 NOPASSWD 를 빼거나 그 계정이 정말 필요한 명령으로 줄을 좁히고, Defaults !authenticate 줄을 지웁니다. NOPASSWD 를 잃기 전에 그 계정에 비밀번호나 키 기반 PAM 방식을 주어야 합니다. 그렇지 않으면 sudo 를 전혀 쓸 수 없습니다. cp -a <file>.bak <file> 로 되돌리며, visudo -c 로 결과를 검사합니다.
# text only: no script declared

# ---- 6/43 muster.file.shadow_permissions [risk none] [fail, high]
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

# ---- 7/43 muster.file.suid_sgid [risk none] [fail, high]
# why: clause does not hold: walk.sticky_missing none where path present
# do:  Record the current mode first (stat -c '%a %n' <path>) so the change can be undone. For a setuid or setgid file no package declares, remove the bit with chmod u-s <path> or chmod g-s <path>, or delete the file if nothing needs it; restore with chmod <recorded mode> <path>. For a directory in the sticky list, add the bit with chmod +t <path>; undo with chmod -t <path>.
# ko:  되돌릴 수 있도록 현재 모드를 먼저 기록합니다(stat -c '%a %n' <path>). 어떤 패키지도 선언하지 않은 setuid·setgid 파일은 chmod u-s <path> 또는 chmod g-s <path> 로 비트를 제거하거나, 필요 없다면 파일을 삭제합니다. 되돌릴 때는 chmod <기록한 모드> <path> 입니다. sticky 목록의 디렉터리는 chmod +t <path> 로 비트를 추가하고, chmod -t <path> 로 되돌립니다.
# text only: no script declared

# ---- 8/43 muster.file.suid_sgid_unverified [risk none] [warn, high]
# why: clause does not hold: walk.suid_sgid_unverified none where path present
# do:  For each row, compare the file against the vendor's own package (dpkg-deb -c or rpm -qlvp on the downloaded package, or debsums -c) and record the current mode first (stat -c '%a %n' <path>). If the package really ships the bit, leave it and waive the row with that reason; if it does not, remove the bit with chmod u-s <path> or chmod g-s <path>, restoring with chmod <recorded mode> <path>.
# ko:  각 행마다 배포사의 패키지와 파일을 직접 대조하고(내려받은 패키지에 dpkg-deb -c 또는 rpm -qlvp, 혹은 debsums -c), 현재 모드를 먼저 기록합니다(stat -c '%a %n' <path>). 패키지가 실제로 그 비트를 배포한다면 그대로 두고 그 사유로 waive 합니다. 그렇지 않다면 chmod u-s <path> 또는 chmod g-s <path> 로 비트를 제거하고, chmod <기록한 모드> <path> 로 되돌립니다.
# text only: no script declared

# ---- 9/43 muster.file.syslog_conf_permissions [risk none] [fail, high]
# why: clause does not hold: files.syslog_configs each require mode in [0 32 128 160 256 288 384 416]
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

# ---- 10/43 muster.file.world_writable [risk none] [warn, high]
# why: clause does not hold: walk.world_writable each require package_declared eq true
# do:  Review each listed path; remove the world-writable bit with chmod o-w unless the application requires it, and record a waiver with the reason if it does.
# ko:  나열된 경로를 검토합니다. 애플리케이션이 요구하지 않으면 chmod o-w 로 world-writable 비트를 제거하고, 요구한다면 사유를 적은 waiver 를 남깁니다.
# text only: no script declared

# ---- 11/43 muster.account.password_hash_algorithm [risk none] [fail, medium]
# why: clause does not hold: accounts.users each require hash_algo in [$5$ $6$ $y$ $gy$ $7$ $2b$ $2y$ $2a$]
# do:  Set ENCRYPT_METHOD SHA512 (or YESCRYPT) in /etc/login.defs, make the PAM password stack use the same algorithm, and have every listed account change its password so the hash is regenerated. Locking the account does not clear the finding, and never blank the password field.
# ko:  /etc/login.defs 에 ENCRYPT_METHOD SHA512 (또는 YESCRYPT) 를 설정하고 PAM password 스택이 같은 알고리즘을 쓰게 한 뒤, 나열된 계정의 비밀번호를 변경해 해시를 다시 생성합니다. 계정을 잠가도 이 항목은 해소되지 않으며, 비밀번호 필드를 비워 두어서는 안 됩니다.
# text only: no script declared

# ---- 12/43 muster.beyond.bootloader_password [risk none] [fail, medium]
# why: clause does not hold: boot.grub_password_set eq true
# do:  Generate a hash with grub2-mkpasswd-pbkdf2 (EL) or grub-mkpasswd-pbkdf2 (Debian and Ubuntu) and record it — on the EL family as GRUB2_PASSWORD= in /boot/grub2/user.cfg, which survives grub2-mkconfig, and on Debian and Ubuntu as a set superusers and password_pbkdf2 pair in a new /etc/grub.d fragment, then regenerate grub.cfg. Keep the password where the people who need console recovery can get it, because a host whose boot menu is locked and whose password is lost needs installation media to recover.
# ko:  grub2-mkpasswd-pbkdf2(EL) 또는 grub-mkpasswd-pbkdf2(Debian·Ubuntu)로 해시를 만들어 기록합니다. EL 계열에서는 grub2-mkconfig 를 거쳐도 남는 /boot/grub2/user.cfg 에 GRUB2_PASSWORD= 로, Debian·Ubuntu 에서는 새 /etc/grub.d 조각에 set superusers 와 password_pbkdf2 한 쌍으로 적은 뒤 grub.cfg 를 다시 생성합니다. 부팅 메뉴가 잠긴 채 비밀번호를 잃어버린 호스트는 설치 미디어가 있어야 복구할 수 있으므로, 콘솔 복구가 필요한 사람들이 접근할 수 있는 곳에 비밀번호를 보관하십시오.
# text only: no script declared

# ---- 13/43 muster.beyond.file_integrity_tool [risk none] [fail, medium]
# why: clause does not hold: fim.tool ne none
# do:  Install AIDE (apt install aide, or dnf install aide) and initialise its database on a host known to be clean — aideinit on the Debian family, which puts the new database in place; aide --init on EL, then move /var/lib/aide/aide.db.new.gz to /var/lib/aide/aide.db.gz. Then make sure a check runs daily. On Ubuntu 22.04 and Debian /etc/cron.daily/aide runs unless /etc/default/aide sets CRON_DAILY_RUN to something other than yes; Ubuntu 24.04 enables dailyaidecheck.timer; on EL9 run systemctl enable --now aide-check.timer. A database initialised after a compromise records the compromise as the baseline.
# ko:  AIDE 를 설치하고(apt install aide 또는 dnf install aide), 깨끗하다고 알려진 상태에서 데이터베이스를 초기화합니다. Debian 계열에서는 새 데이터베이스를 제자리에 두는 aideinit 을, EL 에서는 aide --init 을 실행한 뒤 /var/lib/aide/aide.db.new.gz 를 /var/lib/aide/aide.db.gz 로 옮깁니다. 그다음 매일 검사가 실행되는지 확인합니다. Ubuntu 22.04 와 Debian 에서는 /etc/default/aide 가 CRON_DAILY_RUN 을 yes 가 아닌 값으로 설정하지 않는 한 /etc/cron.daily/aide 가 실행되고, Ubuntu 24.04 는 dailyaidecheck.timer 를 활성화하며, EL9 에서는 systemctl enable --now aide-check.timer 를 실행합니다. 침해 이후에 초기화한 데이터베이스는 침해된 상태를 기준으로 기록합니다.
# text only: no script declared

# ---- 14/43 muster.beyond.icmp_redirects_ignored [risk none] [fail, medium]
# why: clause does not hold: net.sysctl.ipv4_default_accept_redirects eq 0
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

# ---- 15/43 muster.beyond.ipv6_redirects_ignored [risk none] [fail, medium]
# why: clause does not hold: net.sysctl.ipv6_all_accept_redirects eq 0
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

# ---- 16/43 muster.beyond.ipv6_router_advertisements_ignored [risk none] [fail, medium]
# why: clause does not hold: net.sysctl.ipv6_all_accept_ra in [0]
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

# ---- 17/43 muster.beyond.source_routing_rejected [risk none] [fail, medium]
# why: clause does not hold: net.sysctl.ipv4_default_accept_source_route eq 0
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

# ---- 18/43 muster.beyond.suid_dumpable_disabled [risk none] [fail, medium]
# why: clause does not hold: coredump.suid_dumpable eq 0
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

# ---- 19/43 muster.beyond.sysrq_restricted [risk none] [fail, medium]
# why: clause does not hold: kernel.sysctl.sysrq in [0]
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

# ---- 20/43 muster.beyond.uncommon_network_protocols_disabled [risk none] [fail, medium]
# why: clause does not hold: kernel.modules each require disabled eq true
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

# ---- 21/43 muster.file.log_dir_permissions [risk none] [fail, medium]
# why: clause does not hold: files.log_dirs each require group in [root syslog adm utmp]
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

# ---- 22/43 muster.account.system_account_shells [risk none] [fail, low]
# why: clause does not hold: accounts.users each require shell_valid eq false
# do:  Set the shell of each listed system account to nologin (usermod -s /usr/sbin/nologin <name> on Debian and Ubuntu, /sbin/nologin on Rocky and AlmaLinux).
# ko:  나열된 시스템 계정의 셸을 nologin 으로 바꿉니다 (Debian·Ubuntu 는 usermod -s /usr/sbin/nologin <name>, Rocky·AlmaLinux 는 /sbin/nologin).
# text only: no script declared

# ---- 23/43 muster.account.unnecessary_accounts [risk none] [warn, low]
# why: clause does not hold: accounts.users none where name in [lp uucp nuucp]
# do:  Remove each listed account with userdel <name> after confirming nothing on the host runs as it (ps -u <name>; find / -user <name>).
# ko:  호스트에서 해당 계정으로 실행되는 것이 없음을 확인한 뒤 (ps -u <name>; find / -user <name>) userdel <name> 으로 제거합니다.
# text only: no script declared

# ---- 24/43 muster.beyond.uncommon_filesystems_disabled [risk none] [fail, low]
# why: clause does not hold: kernel.modules each require disabled eq true
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

# ---- 25/43 muster.beyond.unprivileged_bpf_restricted [risk none] [fail, low]
# why: clause does not hold: kernel.sysctl.bpf_jit_harden in [1 2]
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

# ---- 26/43 muster.file.hidden_entries [risk none] [warn, low]
# why: clause does not hold: walk.hidden each require package_declared eq true
# do:  Inspect each listed entry (ls -ld <path>; file <path>) and find out what wrote it. Move a file that belongs to an application into its own directory under a visible name, or delete it with rm -i <path> once you have a copy (cp -a <path> <backup>) to restore from. An entry you have confirmed as legitimate is waived with the reason rather than renamed.
# ko:  나열된 항목을 각각 확인하고(ls -ld <path>; file <path>) 무엇이 만들었는지 파악합니다. 애플리케이션의 파일이라면 보이는 이름의 전용 디렉터리로 옮기고, 복원할 사본을 만든 뒤(cp -a <path> <backup>) rm -i <path> 로 삭제합니다. 정당한 항목으로 확인했다면 이름을 바꾸는 대신 사유를 적어 waive 합니다.
# text only: no script declared

# ---- 27/43 muster.service.login_banner [risk none] [warn, low]
# why: clause does not hold: sshd.banner_file.nonempty eq true
# do:  Point sshd's Banner at a file holding your warning (Banner /etc/issue.net in /etc/ssh/sshd_config.d/, validate with sshd -t, restart sshd) and replace the distribution string in /etc/issue and /etc/issue.net with an authorized-use warning.
# ko:  sshd 의 Banner 를 경고 문구가 담긴 파일로 지정하고(/etc/ssh/sshd_config.d/ 에 Banner /etc/issue.net, sshd -t 로 검증 후 재시작) /etc/issue 와 /etc/issue.net 의 배포판 문자열을 인가된 사용 경고로 바꿉니다.
# text only: no script declared

# ---- 28/43 muster.beyond.auditd_active [risk restart_service] [fail, high]
# why: clause does not hold: services.auditd.installed eq true
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

# ---- 29/43 muster.beyond.container_runtime_access [risk restart_service] [fail, high]
# why: clause does not hold: privilege.runtime_group_members none where member not_in []
# do:  Record the group's members and the socket's owner, mode and ACL first (getent group <group>; stat -c '%U:%G %a' <socket>; getfacl <socket>), then remove each account that should not reach the API from the group (gpasswd -d <user> <group>), and let the runtime recreate the socket root-owned and 0660 without an ACL (setfacl -b <socket>, or the runtime's socket unit, then restart it). An account that needs containers can use a rootless runtime instead. Restore with gpasswd -a <user> <group> and the recorded settings; a removed member keeps access in sessions opened before the change until they log out.
# ko:  먼저 그룹의 구성원과 소켓의 소유자, mode, ACL 을 기록합니다(getent group <group>; stat -c '%U:%G %a' <socket>; getfacl <socket>). 그다음 API 에 접근하면 안 되는 계정을 그룹에서 빼고(gpasswd -d <user> <group>), 런타임이 소켓을 root 소유 0660 에 ACL 없이 다시 만들게 합니다(setfacl -b <socket>, 또는 런타임의 socket unit 을 고친 뒤 다시 시작). 컨테이너가 필요한 계정은 rootless 런타임을 쓸 수 있습니다. gpasswd -a <user> <group> 와 기록한 설정으로 되돌리며, 뺀 구성원은 변경 전에 연 세션에서 로그아웃할 때까지 접근을 유지합니다.
# text only: no script declared

# ---- 30/43 muster.file.hosts_permissions [risk restart_service] [fail, high]
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

# ---- 31/43 muster.beyond.dev_shm_mount_options [risk restart_service] [fail, medium]
# why: clause does not hold: mounts.points each require options contains noexec
# do:  Add a /dev/shm line to /etc/fstab with tmpfs and defaults,nodev,nosuid,noexec, or drop a /etc/systemd/system/dev-shm.mount override carrying the same options, then remount. Software that maps executable pages from /dev/shm will stop working under noexec, so restart the stack and watch for an allocation failure before treating the change as done.
# ko:  /etc/fstab 에 tmpfs 와 defaults,nodev,nosuid,noexec 로 /dev/shm 줄을 추가하거나 같은 옵션을 담은 /etc/systemd/system/dev-shm.mount 재정의를 놓고 다시 마운트합니다. /dev/shm 에서 실행 가능한 페이지를 매핑하는 소프트웨어는 noexec 아래에서 동작하지 않으므로, 변경을 끝난 것으로 보기 전에 스택을 재시작해 할당 실패가 없는지 확인하십시오.
# text only: no script declared

# ---- 32/43 muster.beyond.ip_forwarding_disabled [risk restart_service] [fail, medium]
# why: clause does not hold: net.sysctl.ipv4_ip_forward in [0]
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

# ---- 33/43 muster.beyond.no_deleted_executables [risk restart_service] [fail, medium]
# why: clause does not hold: processes.deleted_executables none where pid gte 0
# do:  Restart the services the list names (systemctl restart <unit>), or reboot when the list includes pid 1, the session manager or many library-heavy daemons; needrestart (Debian, Ubuntu) or dnf needs-restarting -s (EL) names the units. A process whose executable nobody upgraded, or a memfd one, is to be investigated before it is killed - copy /proc/<pid>/exe out first, since it is the only copy left.
# ko:  목록에 있는 서비스를 재시작하거나(systemctl restart <unit>), 목록에 pid 1, 세션 관리자 또는 라이브러리를 많이 쓰는 여러 데몬이 있으면 재부팅합니다. needrestart(Debian, Ubuntu) 또는 dnf needs-restarting -s(EL)가 유닛을 알려 줍니다. 아무도 업그레이드하지 않은 실행 파일이나 memfd 실행 파일을 가진 프로세스는 종료하기 전에 조사합니다. 남은 유일한 사본이므로 먼저 /proc/<pid>/exe 를 복사해 둡니다.
# text only: no script declared

# ---- 34/43 muster.beyond.reverse_path_filtering [risk restart_service] [fail, medium]
# why: clause does not hold: net.sysctl.ipv4_all_log_martians eq 1
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

# ---- 35/43 muster.beyond.usb_storage_disabled [risk restart_service] [fail, medium]
# why: clause does not hold: kernel.modules each require disabled eq true
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

# ---- 36/43 muster.beyond.remote_log_forwarding [risk restart_service] [fail, low]
# why: clause does not hold: logging.rsyslog.forwards_remote eq true
# do:  Add a forwarding action to a file under /etc/rsyslog.d/ — for example *.* @@logs.example.com:514, or action(type="omfwd" target="logs.example.com" port="514" protocol="tcp") — and restart rsyslog; or install systemd-journal-upload, set URL= under [Upload] in /etc/systemd/journal-upload.conf and run systemctl enable --now systemd-journal-upload.service. Make sure the receiving host accepts and stores the messages first. Restarting the logger can drop the messages sent while it restarts.
# ko:  /etc/rsyslog.d/ 아래 파일에 전달 액션(예 *.* @@logs.example.com:514, 또는 action(type="omfwd" target="logs.example.com" port="514" protocol="tcp"))을 추가하고 rsyslog 를 재시작하거나, systemd-journal-upload 를 설치하고 /etc/systemd/journal-upload.conf 의 [Upload] 에 URL= 을 설정한 뒤 systemctl enable --now systemd-journal-upload.service 를 실행합니다. 받는 호스트가 메시지를 받아 저장하는지 먼저 확인하십시오. 로거를 재시작하는 동안 보낸 메시지는 유실될 수 있습니다.
# text only: no script declared

# ---- 37/43 muster.beyond.secure_boot_enabled [risk reboot_required] [fail, medium]
# why: clause does not hold: boot.secure_boot eq true
# do:  Enable Secure Boot in the firmware setup of the machine and leave the platform in user mode rather than setup mode. Confirm first that every kernel, initramfs and out-of-tree module the host loads is signed by a key the platform trusts, because an unsigned third-party driver — a hypervisor guest agent, a vendor storage module, a DKMS build — will stop loading the moment Secure Boot is enforcing. A host that cannot report the variable needs efivarfs mounted at /sys/firmware/efi/efivars before muster can judge it.
# ko:  장비의 펌웨어 설정에서 보안 부팅을 켜고 플랫폼을 setup mode 가 아닌 user mode 로 둡니다. 보안 부팅이 적용되는 순간 서명되지 않은 제3자 드라이버(하이퍼바이저 게스트 에이전트, 벤더 스토리지 모듈, DKMS 로 빌드한 모듈 등)는 더 이상 적재되지 않으므로, 호스트가 적재하는 모든 커널·initramfs·외부 모듈이 플랫폼이 신뢰하는 키로 서명되어 있는지 먼저 확인하십시오. 변수를 보고하지 못하는 호스트는 muster 가 판정하려면 efivarfs 가 /sys/firmware/efi/efivars 에 마운트되어 있어야 합니다.
# text only: no script declared

# ---- 38/43 muster.beyond.separate_partitions [risk reboot_required] [warn, medium]
# why: clause does not hold: mounts.points each require separate eq true
# do:  Give each directory a volume or partition of its own at installation time, or on a host already in service create the volume, copy the contents across in single-user mode, and add the mount to /etc/fstab. Where a full split is not worth the effort, /var and /var/log/audit are the two that repay it most — they are the ones whose exhaustion costs the host its logs and its audit trail. A host that genuinely wants fewer of them narrows params.required_separate so the decision is recorded rather than repeated at every run.
# ko:  설치 시점에 각 디렉터리에 별도 볼륨이나 파티션을 배정하거나, 이미 서비스 중인 호스트에서는 볼륨을 만들고 단일 사용자 모드에서 내용을 옮긴 뒤 /etc/fstab 에 마운트를 추가합니다. 전부 분리할 만한 상황이 아니라면 /var 와 /var/log/audit 두 개가 가장 값어치를 합니다. 이 둘이 가득 차면 호스트가 로그와 감사 기록을 잃기 때문입니다. 정말로 더 적게 요구하려는 호스트는 params.required_separate 를 좁혀 그 결정을 매 실행마다 반복하지 않고 기록해 두면 됩니다.
# text only: no script declared

# ---- 39/43 muster.account.lockout_threshold [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: absent counts as fail: pam.faillock.deny is absent on this host
# do:  RHEL family - authselect enable-feature with-faillock and set deny in /etc/security/faillock.conf; Debian family - add pam_faillock.so preauth and authfail lines to common-auth and a pam_faillock.so line to common-account (or use a pam-auth-update profile), then set deny in /etc/security/faillock.conf. A deny= argument on the pam_faillock lines wins over the file; the review script edits the file only.
# ko:  RHEL 계열은 authselect enable-feature with-faillock 을 실행하고 /etc/security/faillock.conf 에 deny 를 설정하며, Debian 계열은 common-auth 에 pam_faillock.so preauth 와 authfail 줄, common-account 에 pam_faillock.so 줄을 추가하거나 pam-auth-update 프로파일을 쓴 뒤 /etc/security/faillock.conf 에 deny 를 설정합니다. pam_faillock 줄의 deny= 인자는 파일보다 우선하며, 검토 스크립트는 파일만 고칩니다.
# text only: the finding is an absent file

# ---- 40/43 muster.account.password_policy [risk lockout_risk] [fail, high]
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

# ---- 41/43 muster.account.su_restricted [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold: pam.su.wheel_required eq true
# do:  Uncomment or add "auth required pam_wheel.so use_uid" in /etc/pam.d/su and put the administrators in the wheel group (or name another group with group=).
# ko:  /etc/pam.d/su 에서 "auth required pam_wheel.so use_uid" 줄의 주석을 풀거나 추가하고, 관리자를 wheel 그룹 (또는 group= 으로 지정한 그룹) 에 넣습니다.
# text only: no script declared

# ---- 42/43 muster.file.ip_port_restriction [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: clause does not hold: firewall.restricts_inbound eq true
# do:  Enable a host firewall with a default-deny inbound policy (ufw default deny incoming; firewalld default zone target DROP; or an nftables/iptables INPUT policy of drop with explicit allow rules), or deny by default in /etc/hosts.deny (ALL: ALL) and allow only required sources in /etc/hosts.allow.
# ko:  기본 차단 인바운드 정책의 호스트 방화벽을 설정하거나(ufw default deny incoming; firewalld 기본 zone target DROP; nftables/iptables INPUT 정책 drop + 명시적 허용 규칙), /etc/hosts.deny 에서 기본 차단(ALL: ALL) 후 /etc/hosts.allow 에 필요한 출발지만 허용합니다.
# text only: no script declared

# ---- 43/43 muster.beyond.account_inactivity_lock [risk lockout_risk] [fail, medium]
# keep a second session open; a lockout here needs console access
# why: clause does not hold: accounts.login_capable none where inactive_unset eq true
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
