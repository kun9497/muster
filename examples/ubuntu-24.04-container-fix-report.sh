#!/bin/sh
# shellcheck disable=SC2181
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host ubuntu-container, collected 2026-10-13T08:25:27Z; controls kisa-unix-2026+2026.10.13 sha256:f19aabb3a5704b459246b30850f221e08d90369f7e043e16db157d39648342e1
# profile default (sha256:f4db63e671d12ad73cca111ca4132cb5459983bc32409b21c571067674bf9c78); max-risk lockout_risk
# planned 10 (script 2, text only 8); above max-risk 0; not planned: error 0, manual 2, warn_degraded 0
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

# ---- 1/10 muster.account.cron_permissions [risk none] [fail, high]
# why: clause does not hold: cron.files each require mode in [0 32 128 160 256 288 384 416]
# do:  chmod 0640 the crontab-FORMAT files (/etc/crontab, /etc/cron.d/* and the per-user spools), chown the system files to root, and chmod go-w (not 0640, which would break run-parts) the /etc/cron.{hourly,daily,weekly,monthly} periodic-script directories and their scripts; chmod o-w the cron directories.
# ko:  crontab 형식 파일(/etc/crontab, /etc/cron.d/*, 사용자별 스풀)에 chmod 0640 을 적용하고 시스템 파일을 root 로 chown 하며, /etc/cron.{hourly,daily,weekly,monthly} 주기 스크립트 디렉터리와 그 스크립트에는 (run-parts 를 깨뜨리는 0640 이 아니라) chmod go-w 를 적용하고, cron 디렉터리에 chmod o-w 를 적용합니다.
# text only: no script declared

# ---- 2/10 muster.account.password_policy [risk none] [fail, high]
# why: absent counts as fail: accounts.login_defs.pass_min_len is absent on this host
# do:  Set PASS_MAX_DAYS, PASS_MIN_DAYS and PASS_MIN_LEN in /etc/login.defs and apply the ageing values to existing accounts with chage; install libpam-pwquality (Debian family) or keep pam_pwquality in the authselect profile (RHEL family), then set minlen and minclass (or the four credits) in /etc/security/pwquality.conf.
# ko:  /etc/login.defs 에 PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_MIN_LEN 을 설정하고 기존 계정에는 chage 로 사용 기간 값을 적용하며, libpam-pwquality 를 설치하거나 (Debian 계열) authselect 프로파일에 pam_pwquality 를 유지한 뒤 (RHEL 계열) /etc/security/pwquality.conf 에 minlen 과 minclass (또는 네 credit) 를 설정합니다.
# text only: no script declared

# ---- 3/10 muster.file.services_permissions [risk none] [fail, high]
# why: absent counts as fail: files.etc_services.uid is absent on this host
# do:  chown root:root /etc/services; chmod 644 /etc/services (the script only clears bits; a stricter file is left as it is)
# ko:  chown root:root /etc/services; chmod 644 /etc/services (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다)
# text only: the finding is an absent file

# ---- 4/10 muster.file.shadow_permissions [risk none] [fail, high]
# why: clause does not hold: files.etc_shadow.mode in [0 256]
# do:  chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow (the script only clears bits; a stricter file is left as it is). On Debian and Ubuntu unix_chkpwd reads /etc/shadow through group shadow; a site that keeps 0640 relaxes allowed_modes, and the plan then leaves the script out.
# ko:  chown root /etc/shadow; chmod 400 /etc/shadow; setfacl -b /etc/shadow (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다). Debian과 Ubuntu에서는 unix_chkpwd가 shadow 그룹으로 /etc/shadow를 읽으므로, 0640을 유지하는 사이트는 allowed_modes를 완화하고 그러면 계획이 스크립트를 뺍니다.
fix_muster_file_shadow_permissions() {
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

# ---- 5/10 muster.account.session_timeout [risk none] [fail, low]
# why: absent counts as fail: no mechanism applies to this host
# do:  Set ClientAliveInterval 300 and ClientAliveCountMax 1 in a file under /etc/ssh/sshd_config.d/, validate with sshd -t, then restart sshd. Alternatively, since this control accepts either mechanism, set and export an interactive-shell TMOUT in a system profile file - for example a file under /etc/profile.d/ containing "readonly TMOUT=600; export TMOUT".
# ko:  /etc/ssh/sshd_config.d/ 아래 파일에 ClientAliveInterval 300 과 ClientAliveCountMax 1 을 설정하고 sshd -t 로 검증한 뒤 sshd 를 재시작합니다. 이 컨트롤은 두 방식 중 어느 쪽이든 인정하므로, 대안으로 시스템 프로파일 파일에 대화형 셸 TMOUT 을 설정하고 export 할 수 있습니다 - 예를 들어 /etc/profile.d/ 아래 파일에 "readonly TMOUT=600; export TMOUT" 를 둡니다.
# text only: no script declared

# ---- 6/10 muster.account.unnecessary_accounts [risk none] [warn, low]
# why: clause does not hold: accounts.users none where name in [lp uucp nuucp]
# do:  Remove each listed account with userdel <name> after confirming nothing on the host runs as it (ps -u <name>; find / -user <name>).
# ko:  호스트에서 해당 계정으로 실행되는 것이 없음을 확인한 뒤 (ps -u <name>; find / -user <name>) userdel <name> 으로 제거합니다.
# text only: no script declared

# ---- 7/10 muster.service.login_banner [risk none] [warn, low]
# why: clause does not hold: banners.issue_net.os_escapes eq false
# do:  Point sshd's Banner at a file holding your warning (Banner /etc/issue.net in /etc/ssh/sshd_config.d/, validate with sshd -t, restart sshd) and replace the distribution string in /etc/issue and /etc/issue.net with an authorized-use warning.
# ko:  sshd 의 Banner 를 경고 문구가 담긴 파일로 지정하고(/etc/ssh/sshd_config.d/ 에 Banner /etc/issue.net, sshd -t 로 검증 후 재시작) /etc/issue 와 /etc/issue.net 의 배포판 문자열을 인가된 사용 경고로 바꿉니다.
# text only: no script declared

# ---- 8/10 muster.file.hosts_permissions [risk restart_service] [fail, high]
# why: clause does not hold: files.etc_hosts.mode in [0 128 256 384]
# do:  chown root:root /etc/hosts; chmod 600 /etc/hosts (the script only clears bits; a stricter file is left as it is). At 0600 non-root processes can no longer read /etc/hosts, so services that resolve names through it fail; a site that keeps 0644 relaxes allowed_modes, and the plan then leaves the script out.
# ko:  chown root:root /etc/hosts; chmod 600 /etc/hosts (스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로 둡니다). 0600에서는 root가 아닌 프로세스가 /etc/hosts를 읽지 못해 그것으로 이름을 푸는 서비스가 실패합니다. 0644를 유지하는 사이트는 allowed_modes를 완화하고 그러면 계획이 스크립트를 뺍니다.
fix_muster_file_hosts_permissions() {
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

# ---- 9/10 muster.account.lockout_threshold [risk lockout_risk] [fail, high]
# keep a second session open; a lockout here needs console access
# why: absent counts as fail: pam.faillock.deny is absent on this host
# do:  RHEL family - authselect enable-feature with-faillock and set deny in /etc/security/faillock.conf; Debian family - add pam_faillock.so preauth and authfail lines to common-auth and a pam_faillock.so line to common-account (or use a pam-auth-update profile), then set deny in /etc/security/faillock.conf.
# ko:  RHEL 계열은 authselect enable-feature with-faillock 을 실행하고 /etc/security/faillock.conf 에 deny 를 설정하며, Debian 계열은 common-auth 에 pam_faillock.so preauth 와 authfail 줄, common-account 에 pam_faillock.so 줄을 추가하거나 pam-auth-update 프로파일을 쓴 뒤 /etc/security/faillock.conf 에 deny 를 설정합니다.
# text only: no script declared

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
