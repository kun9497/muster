# 3D-2d단계 — audit 묶음, 비활성 한도, 그리고 파일이 말하는 것

영어 원본: `2026-10-19-stage3d2d-content-scripts-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`
(§6.2 스키마, §7.5 `fix --dry-run`, §10.2 로드맵, D24, D34). 이 사이클이 딛고 서는 설계:
`2026-10-07-stage3d2-fix-dry-run-design.ko.md`(X-1..X-10), `2026-10-13-stage3d2b-remedy-proof-design.ko.md`
(Q-1..Q-6), `2026-10-14-stage3d2c-remedy-scripts-design.ko.md`(E-1..E-13. 플랜의 S-18..S-50, 구현된 모습은 그
§8). 이 설계의 판정은 O 목록입니다(H는 2H단계가 이미 씀). 스펙 리뷰 둘을 제자리에 접어 넣었습니다. 첫 번째(렌즈
여섯, 발견마다 반박자 셋, 크리틱: 발견 76개, 63개 유지, 33개로 병합)와 접은 초안에 대한 두 번째(렌즈 넷: 발견
50개, 43개 유지, 22개로 병합)입니다. 범위 지도, 두 리뷰 요약, 크리틱의 메모는 이 사이클의 무시되는 작업 공간
파일(`code-map-*.md`, `spec-review-r{1,2}.md`)이며, 구속력이 있는 발견은 여기에 다시 적었습니다.

## 1. 범위와 의도

3D-2c 뒤 control 48개가 `script`를 가집니다. 메인 설계는 3D-2d를 "audit 묶음,
`account_inactivity_lock`, 파일 control의 내용 쪽"으로 이름 붙이고, 안전한 모양이 있는 곳에는 스크립트를, 없는
곳에는 텍스트를 둡니다. 안전한 모양이란 다음 넷을 한꺼번에 뜻합니다.

1. 본문은 일방향 runtime 변경을 하지 않고, 그 밖의 모든 변경은 기록했다가 실패 때 되돌리거나, 블록이 실패한
   뒤에도 남는다고 control의 텍스트에 이름 붙입니다(O-2).
2. 호스트가 절의 허용 집합 밖일 때만 씁니다(O-6이 고친 E-8).
3. 쓰는 값은 muster가 사이트를 모르고도 고를 수 있는 값입니다. 사람이 골라야 하는 주소, 계정, 인증서,
   문구가 아닙니다(고정 문자열이 그런 문구가 아닌 때는 O-15가 말함).
4. CI 행이 수리와 실패 둘 다 처음부터 끝까지 실행하거나, 어떤 행도 닿지 않는 분기는 stub 테스트로 고정하고 그
   행에서 증명되지 않는다고 이름 붙입니다.

스크립트가 없는 control 69개 중 여덟이 그 기준을 넘고, 배포된 본문 하나에 두 번째 쪽이 생깁니다. 이들을 쓰다가
본문이 고치는 바로 그 파일에 대해 틀린 collector 읽기 셋을 찾았습니다. 그것들을 먼저, 각각 자기 커밋에서
고칩니다(O-14, O-17, O-18). 나머지는 텍스트로 남습니다. 호스트마다의 판단(어느 계정, 포트, 비트, 클라이언트),
일방향 runtime 쓰기, 패키지 설치, PAM 스택 편집, 또는 `automation: manual` control입니다(§7).

- **O-1 — 새 본문 여덟과 확장된 본문 하나. scripted control은 모두 56개.**
  - audit 묶음: `muster.beyond.auditd_active`, `muster.beyond.audit_rules_loaded`,
    `muster.beyond.audit_disk_actions`(§4.1–§4.3).
  - 비활성 한도: `muster.beyond.account_inactivity_lock`(§4.4).
  - 내용 쪽: `muster.file.rhosts_forbidden`(`/etc/hosts.equiv` 쪽),
    `muster.service.mail_expn_vrfy`(postfix 쪽), `muster.service.ftp_banner`와
    `muster.service.ftp_anonymous`(vsftpd 쪽), 그리고 배포된 `muster.service.nfs_export_access` 본문에
    `no_root_squash` 쪽이 생깁니다(§4.5–§4.9).
  - 스키마 필드, lint 규칙, 프롤로그 헬퍼, 기록 종류는 더하지 않습니다. 이 본문들이 필요로 하는 것은 3D-2c 뒤에
    모두 있습니다. `backup`, `units`, `script_params`, 선언된 `rollback`, 그리고 `$MB` 아래 본문이 쓰는
    기록(`ageing.list` 패턴)입니다. §3은 이들이 CONTRIBUTING에 더하는 규약을 적습니다.
- **O-2 — 본문은 일방향 runtime 변경을 절대 하지 않는다. 그 밖의 모든 runtime 효과는 기록했다가 재생하거나,
  텍스트에 이름 붙인다.** `auditctl -e 2`와 `--loginuid-immutable`은 다음 부팅까지 커널 상태를 잠급니다.
  어떤 rollback도 되돌릴 수 없고, runner 행에서는 어느 쪽이든 job의 남은 동안 VM을 잠급니다. 그래서
  `muster.beyond.audit_immutable`은 텍스트로 남고, 위험도는 `reboot_required`가 됩니다(텍스트를 따랐을 때의
  운영상 영향: 이후 모든 규칙 변경에 재부팅이 필요). 기록했다가 재생하는 것: `audit_rules_loaded`의 적재가 바꿀
  수 있는 커널 audit 설정(`auditctl -s`의 `enabled`, `failure`, `backlog_limit`, `backlog_wait_time`,
  `rate_limit`, §4.2). 블록이 실패한 뒤에도 남는다고 텍스트에 이름 붙이는 것: `auditd_active`의 시작(실행 중인
  데몬, 그리고 그 유닛의 적재가 적용하는 커널 audit 설정), `exportfs -ra`(커널의 export 표를 모든 export 파일에
  다시 맞춤), `postfix reload`(대기 중인 `master.cf` 편집을 적용함).
- **O-3 — 어떤 본문도 대기 중인 일방향 설정 위에 규칙을 적재하거나 auditd를 시작하지 않는다.** 검사는 두
  쪽이고, getopt 방식으로(플래그가 값에 붙을 수 있음: `-e2`, `-w/etc/passwd`) `LC_ALL=C` 아래에서 읽습니다.
  - **runtime 잠금**: `auditctl -s`가 `enabled 2`나 `loginuid_immutable 1`을 보고합니다(키는 접두어가 아니라
    통째로 맞춤).
  - **대기 중인 잠금**: `/etc/audit/rules.d/*.rules`나 `/etc/audit/audit.rules`의 어떤 줄이든
    `(^|[[:space:]])(-e[[:space:]]*\+?0*2([[:space:]]|$)|--loginuid-immutable([[:space:]]|$))`에 맞는 것(토큰은 줄의 어디에 있어도 됨: `-b 8192 -e 2`도 잠금을 적용함). 이
    검사는 augenrules의 "마지막 `-e`가 이김"보다 넓고 적어도 collector의 `lastEnableValue`만큼 넓습니다. 거부의
    값은 control이 FAIL로 남는 실패한 블록이고, 잘못된 추측의 값은 잠긴 커널입니다.
  거부는 로그를 남기고, 어떤 쓰기보다 먼저 1로 끝나며, 블록이 실패합니다(복원이 돌지만 바뀐 것은 없음). 본문별로:
  `audit_rules_loaded`는 어떤 적재보다 먼저 두 쪽을 모두 실행하고, 0이 아닌 값으로 끝나거나 `enabled` 줄을
  출력하지 않는 `auditctl -s`는 거부합니다. `auditd_active`는 시작 앞에서만 두 쪽을 실행하고, 거기서는 판단할 수
  없는 `auditctl -s`를 "잠기지 않음"으로 셉니다. 그래서 대기 중인 잠금이 거부합니다(§4.1).
- **O-4 — `audit_rules_loaded`는 세 경우에 작용하고 네 번째는 그대로 둔다.** "커널 목록이 비어 있음"은
  `auditctl -l`이 0으로 끝나고 `No rules`를 출력한다는 뜻이고, "규칙을 가짐"은 0으로 끝나고 다른 것을 출력한다는
  뜻입니다. 0이 아닌 종료는 본문에서는 거부하고 validate에서는 실패합니다.
  - (a) **규칙이 지속됨, 커널 목록이 비어 있음**: auditd가 active일 때만 그것을 적재합니다(`augenrules --load`).
    데몬 없는 커널에 적재하면 아무도 읽지 않는 레코드가 쌓이고, 지속된 `-f 2`가 있으면 호스트가 panic할 수
    있습니다. auditd가 inactive이면 본문은 다시 생성만 하고, 유닛 자신의 시작이 그 집합을 적재합니다.
  - (b) **커널이 규칙을 가짐, 지속된 것 없음**: 그대로 둡니다. muster는 `auditctl -l` 출력을 지속시키지 않고(규칙
    파일로 믿을 만하게 왕복하지 않음), 운영자의 살아 있는 집합 옆에 바닥 집합을 쓰지 않습니다. 재부팅 때 바닥
    집합이 그것을 대체할 것이기 때문입니다. 본문은 `kernel rules are not persisted; persist your own set`를
    로그에 남기고, validate는 이 모양을 받아들이고, 블록은 `done`으로 끝나며, control은 FAIL로 남습니다(X-10).
  - (c) **둘 다 비어 있음**: muster의 최소 감시 집합을 `/etc/audit/rules.d/50-muster.rules`에 쓰고, 그다음 (a).
  - (d) **둘 다 있음**: control이 통과합니다. 절대 계획되지 않습니다.
  바닥 집합이 §1의 기준을 넘는 이유(그리고 범위 지도가 제안한 적재만 하는 모양에서 벗어나는 이유): 규칙 없이 도는
  auditd는 시스템 호출이 고르는 것을 아무것도 기록하지 않으며, 그것이 바로 발견입니다. 바닥 집합은 모든 호스트에
  있는 고정 경로 일곱을 `wa` 권한으로만(양이 적음), 운영자가 찾아 지울 수 있는 `muster-*` 키 아래 감시합니다.
  텍스트는 그것을 사이트의 규칙으로 바꾸라고 말합니다. 줄은 muster 자신의 키를 쓴 auditctl(8) 문법이고, 어떤
  벤치마크의 텍스트도 아닙니다(ATTRIBUTION 메모).
- **O-5 — `auditd_active`는 enable하는 첫 units 본문이고, 그 모양에 대해 Q-2를 고친다.** `units:
  [auditd.service]`를 선언하고, 유닛을 unmask하고 enable하며, 유닛이 inactive이고, 커널 목록이 비어 있고, 대기
  중인 잠금이 없거나 runtime이 이미 잠겨 있을 때만 시작합니다(잠긴 runtime 아래의 시작은 일방향으로 아무것도
  바꾸지 않음: 유닛의 적재가 거부되고 그 `-` 접두어가 실패를 무시함). auditd를 시작하면 `augenrules --load`가
  돌고, 그 끌어올린 `-D`가 커널 목록을 지웁니다. 그래서 비어 있지 않은 목록 위의 inactive 유닛은 enable하되
  시작하지 않습니다(`kernel holds rules a start would replace; start left to the operator`). Q-2의 units 기록은
  enable 상태와 mask에 대해서는 "있던 것을 되돌려 놓"지만, 활성 상태에 대해서는 그럴 수 없습니다.
  `restore_units`는 유닛을 절대 멈추지 않고, auditd 유닛은 어차피 수동 정지를 거부합니다. 실패한 블록은 시작된
  auditd를 그 적재가 적용한 설정과 함께 실행 중으로 남깁니다. 이는 안전한 상태 쪽으로의 실패이고 텍스트가
  그렇게 말합니다.
- **O-6 — 쓰는 값은 적용 중인 목록에서 대상이 받아들이고 호스트를 살려 두는 첫 요소다(E-8을 고침).**
  `audit_disk_actions`의 쓸 수 있는 집합은 키마다 다르며 auditd.conf(5)를 따릅니다.
  `space_left_action`, `admin_space_left_action`, `disk_full_action` — `syslog`, `rotate`; `disk_error_action` —
  `syslog`; `max_log_file_action` — `rotate`, `keep_logs`, `syslog`. `email`(메일함 필요), `exec`(경로),
  `single`과 `halt`(호스트를 내림)는 절대 쓰지 않습니다. 쓸 수 있는 요소가 없는 적용 중인 목록은 그 키를 텍스트에
  맡기고, validate는 본문이 둔 키를 검사하지 않습니다. E-8의 "가이드의 값이거나 적용 중인 목록의 첫 요소"는 그
  값이 언제나 쓸 수 있는 모든 control에 그대로입니다.
- **O-7 — 비활성 한도는 root를 포함하고, 그 자리에서 비활성화할 계정은 건너뛴다.** 본문은
  `/etc/default/useradd`의 1열 `INACTIVE=` 줄(collector와 useradd가 읽는 줄. 기본값 집합 전체를 다시 쓰는
  `useradd -D`는 절대 쓰지 않음)을 고치고, collector가 login-capable이라 부르는 로컬 계정에 root를 포함해
  `chage -I <n>`을 실행합니다. S-48(ageing 루프는 root를 그대로 둠)과 달리 root가 들어갑니다. root에 최대값이
  없는 곳(`password_policy`가 두는 대로 비었거나 -1이거나 99999)에서는 운영자가 root에 실제 ageing을 줄 때까지
  필드 7이 효과가 없고, root 없이는 control이 어떤 호스트에서도 통과할 수 없습니다. root(또는 어떤 계정)에 실제
  최대값이 있는 곳에서는 본문이 비밀번호가 바뀌지 않으면 그 계정이 비활성화될 날짜를 root부터 로그에 남깁니다.
  텍스트는 root를 ageing하는 호스트에서는 그 날짜에 root의 키 로그인이 멈춘다고 말합니다. 비밀번호가 이미 `n`일
  이상 만료된 계정은 건너뛰고 이름을 남깁니다. 각 계정의 이전 필드 7은 `$MB/inactive.list`에 갑니다(`name:old`,
  빈 필드는 `-1`로 기록, 첫 기록 유지). 선언된 rollback이 그것을 재생합니다. 위험도는 `lockout_risk`가
  됩니다(전에는 `none`).
- **O-8 — 내용 쪽은 muster가 이미 판정하는 파일의 일반적인 편집이다. control의 나머지는 텍스트로 남고, 텍스트가
  어느 쪽인지 말한다.** 계획에는 절 단위 가드가 없습니다. 실패하는 절이 본문이 두는 쪽에 속하는 control도 블록을
  받고, 그 블록은 아무것도 바꾸지 않고 `done`으로 끝나지만 다음 `check`는 여전히 FAIL입니다(X-10). 그래서 쪽만
  스크립트가 있는 각 control의 텍스트는 자기가 두는 쪽을 이름 붙입니다. 새 본문은 누군가 쓴 줄을 절대 지우지
  않습니다. `/etc/hosts.equiv`의 실격시키는 `+` 줄은 `# muster: ` 접두어로 주석 처리합니다. 키는 있으면 제자리에서
  다시 쓰고 없으면 덧붙입니다. 배포된 `/etc/securetty` 편집(3D-2)은 그대로입니다.
- **O-9 — 선언된 rollback은 `restore <path>`를 부를 수 있다. 데몬은 이 실행이 기록한 것에 대해서만 검사하고,
  reload하고, restart한다.** E-11에 따라 데몬이 다시 읽는 파일의 선언된 rollback은 그 파일을 스스로 되돌려
  놓습니다(선언된 rollback은 템플릿의 `restore` 앞에 돔). 새 본문은 복사를 다시 구현하지 않고 프롤로그의
  `restore`를 부릅니다. 같은 경로에 대한 템플릿의 이후 `restore`는 무해한 두 번째 처리입니다(테스트가 고정).
  실행마다의 표지 둘이 데몬 단계를 이끕니다.
  - `$MB/<daemon>.was-running`: 데몬이 돌고 있으면 어떤 편집보다 먼저 씁니다. 본문의 reload나 restart와
    rollback의 그것은 둘 다 "지금 돌고 있음"이 아니라 이 표지를 봅니다. 실패한 restart는 유닛을 failed로
    남기므로 rollback은 그래도 그것을 다시 시작해야 하고, 앞선 실행 이후 운영자가 멈춘 데몬은 절대 시작하지
    않습니다.
  - `$MB/<daemon>.edited`: 본문의 첫 쓰기 바로 앞에서 touch합니다. rollback은 이것이 있을 때만 데몬의 검사와
    reload나 restart를 실행합니다. 없으면 복원하고 0으로 끝나므로, 어떤 쓰기보다 먼저 한 거부(이미 실패한
    `postfix check`)는 `rollback failed` 줄을 절대 만들지 않습니다.
- **O-10 — 파일을 collector처럼 읽는 모든 본문은 collector와 대조한다.** E-8은 본문의 읽기가 Go 파서와 일치하는
  데 기대고 있습니다. Linux 테스트가 새 본문마다의 읽기 식을 파서의 fixture와 fuzz 시드, 그리고 손으로 쓴 경계
  행에 대해 실행해 답을 비교하며, 고친 읽기(O-14, O-17, O-18)를 기준으로 씁니다. auditd.conf(`parseAuditdConf`.
  행 `exec /path`, `EXEC /x`); 규칙 존재와 잠금(`parseAuditRules`/`auditKind`, `lastEnableValue`. 잠금 행은
  한쪽만 봄 — 본문은 collector가 잠금을 읽는 모든 곳에서 거부해야 하고, 더 많이 거부해도 됨);
  `/etc/default/useradd`(`parseUseraddDefaults`); vsftpd 읽기(인사말과 `anonymous_enable`. 행 `PureFTPd ready`,
  `myvsftpd`, 드러내는 `banner_file` 옆의 깨끗한 `ftpd_banner`와 그 반대, 빈 `banner_file`,
  `anonymous_enable=FALSE`와 `=0`); postfix의 `disable_vrfy_command`(`parsePostfixInto`/`postfixYes`. 키 대소문자
  접기는 알려진 차이); exports 옵션 읽기(주석 처리된 줄, 끝의 주석, `\` 이어짐, `-opts` 기본 목록, 그 단어를 담은
  경로에 대한 행. collector의 부분 문자열 검사와 본문의 옵션 범위 맞춤 사이는 본문의 보수적인 방향으로의 알려진
  차이); 그리고 hosts.equiv 줄 읽기(순수 함수 `hostsEquivLines([]byte)`로 떼어 내고, CLAUDE.md가 `[]byte` 함수에
  요구하는 대로 `FuzzHostsEquivLines` 대상을 둠).
- **O-11 — 심볼릭 링크 가드 없이 쓰는 배포된 본문 둘이 본문과 rollback에 그것을 얻는다.**
  `lockout_threshold`는 `/etc/security/faillock.conf`를, `root_remote_login`은 `00-muster.conf`와
  `/etc/securetty`를 `[ -L ]` 검사 없이 씁니다. faillock.conf와 securetty는 벤더 파일이고(K2 선례: `is a symlink,
  left as is`를 로그에 남기고 블록을 실패시킴), `00-muster.conf`는 muster의 drop-in입니다(S-27).
  `root_remote_login`에서는 두 검사가 drop-in `printf` 앞, 본문 맨 위에 갑니다. 그 rollback은 템플릿의 `restore`
  앞에 `00-muster.conf`를 지우고 sshd를 reload하므로 심볼릭 링크도 건너뛰어야 합니다(`session_timeout` 모양).
  세 경로가 `TestAccountBodiesLeaveASymlinkedDropIn`에 들어가고, 그 stub sshd는 reload 때 링크가 있었는지
  기록합니다.
- **O-12 — 증명.** audit 본문과 비활성 본문은 `env.container eq none`으로 가드된 `beyond` control이라 `runner`
  행만 그것들을 실행합니다. 내용 본문은 자기 데몬을 가진 컨테이너 행에서 돌고, init 행은 vsftpd와 postfix를
  시작해 restart와 reload 분기가 돌게 합니다. stub만(어떤 행도 닿지 않음): auditd의 시작 분기, inactive 데몬의
  적재, 경우 (b), NFS rollback의 `exportfs -ra`(다음 블록 `nfs_server_disabled`가 init 행에서 그것을 mask함).
  `record()`에 audit 커널 상태, shadow 필드 7과 다른 shadow 필드의 체크섬, NFS export 표, vsftpd와 postfix의 실행
  상태가 추가됩니다(§5). SELinux 레이블은 CI에서 증명하지 않습니다. SELinux를 돌리는 행이 없습니다(§7).
- **O-13 — 판정 결과 셋이 고침으로서 바뀌고, 위험도 넷이 움직인다.** 셋은 O-14, O-17, O-18입니다. 파라미터 기본값은
  바뀌지 않습니다. 위험도: `auditd_active` `none` → `restart_service`, `account_inactivity_lock` `none` →
  `lockout_risk`, `rhosts_forbidden` `none` → `restart_service`(`rservices_disabled`의 값. 그래서 `--max-risk
  restart_service`가 이 더 작은 편집을 건너뛰면서 더 큰 r-services 차단을 실행하는 일이 없음),
  `audit_immutable` `restart_service` → `reboot_required`. `controls/VERSION`이 올라갑니다. plan JSON은 모양을
  유지하고, examples는 새로 고쳐야 합니다.
- **O-14 — vsftpd의 인사말 우선순위를 collector에서 고친다.** vsftpd는 `banner_file` 옵션이 설정되어 있고 그
  파일이 비어 있지 않으면 그 내용을, 아니면 설정되어 있을 때 `ftpd_banner`를, 아니면 컴파일된 인사말을
  보냅니다(vsftpd.conf(5): banner_file "overrides the banner string provided by the ftpd_banner option").
  collector는 그 반대로 읽습니다(`publishVsftpdBanner`). 드러내는 `banner_file` 옆에 깨끗한 `ftpd_banner`를 가진
  호스트는 오늘 PASS로 읽히고 고친 뒤 FAIL로 읽힙니다. 드러내는 `ftpd_banner` 옆의 빈 `banner_file`은 계속 FAIL로
  읽힙니다. 자기 커밋: 읽기, fixture(두 키 모두 설정, 각 방향; 빈 `banner_file`), 뒤집힌 `ftp_test.go` 기대값,
  fuzz 시드, facts 설명, CHANGELOG "Fixed" 줄. 사전 점검이 경우마다 회선 위의 220 줄을 읽습니다.
- **O-15 — 내용을 금지하기만 하는 절은 고정된 중립 문자열로 만족시킬 수 있다.** `ftp_banner`는 FTP 제품을 이름
  붙이지 않는 어떤 인사말이든 받아들입니다. `FTP server ready.`를 쓰는 것은 정책이 아닙니다. 검사가 닫힌 목록
  밖의 어떤 문자열이든 받아들이기 때문입니다. `login_banner`는 다릅니다. 사이트 경고문을 요구하고 그 문구는
  사이트의 것이라 텍스트로 남습니다. 그 문자열은 결코 법적 고지가 아닙니다.
- **O-16 — 이 실행을 묘사하는 기록은 첫 기록을 유지하지 않는다.** `audit.loaded`, `audit.status`,
  `<daemon>.was-running`과 `<daemon>.edited` 표지, `disk.keys`, `inactive.run`은 이번 실행이 본 것과 한 것을
  묘사합니다. 각 본문은 첫 동작으로 이것들을 지우고 새로 씁니다. 파일 백업과 `inactive.list`(rollback이 재생하는
  되돌릴 길)는 첫 기록을 유지합니다. 그래서 다시 실행한 rollback은 앞선 실행을 근거로 규칙을 지우거나, 설정을
  재생하거나, 데몬을 restart하는 일이 절대 없고, 다시 실행한 validate는 이번 실행이 쓴 것만 검사합니다.
- **O-17 — auditd의 `exec` 동작은 첫 단어로 판정한다.** `space_left_action = exec /usr/local/sbin/x`는 관리자
  자신의 대처지만, `parseAuditdConf`는 값 전체를 소문자로 바꾸고 목록 요소 `exec`는 `exec /usr/local/sbin/x`와
  결코 같지 않으므로, 그 행은 오늘 FAIL이고 본문은 그것을 `syslog`로 덮어쓸 것입니다. 판정되는 동작은 공백으로
  나눈 첫 단어를 소문자로 바꾼 것이 됩니다. 경로는 적힌 대로 유지하고 판정의 일부가 아닙니다. 자기 커밋: 읽기,
  fixture(`exec /usr/local/sbin/x`, `EXEC /x`), fuzz 시드, facts 설명, CHANGELOG "Fixed" 줄. §4.3은 그 단어만
  비교합니다.
- **O-18 — exports 기본 옵션 목록을 읽는다.** exports(5)는 줄이 클라이언트 앞에 `-opts`를 그 클라이언트들의
  기본값으로 줄 수 있게 합니다(클라이언트 자신의 옵션이 그것을 덮어씀). collector는 모든 `-` 토큰을 BSD 문법으로
  보고 건너뛰므로 `/srv -no_root_squash host`가 `root_squash` true로 읽힙니다. 상 control의 거짓 PASS입니다.
  `parseExportsContent`가 그 줄에서 기본 목록 뒤의 클라이언트에 기본 목록을 적용합니다. 커밋 전에 사전 점검이
  init 행 셋에서 nfs-utils가 그 문법을 받아들이는지 확인합니다. 받아들이지 않으면 collector는 계속 건너뛰고
  O-10이 그 차이를 기록합니다. 자기 커밋: 읽기, `fail-` fixture, fuzz 시드, CHANGELOG "Fixed" 줄.

## 2. 구현된 대로 남는 것

- 템플릿, 그 프롤로그, `$MUSTER_BACKUP/blocks/<fn>/` 아래 블록마다의 기록, 실패 순서(선언된 rollback →
  `restore_units` → `restore_modes` → `restore` → `restore_sysctl` → `restore_modules`), 롤백 단어 여섯, 모든
  lint 규칙은 그대로입니다.
- 롤백 단어는 기존 `rollbackWord`에서: `auditd_active` → `units`; `audit_rules_loaded`,
  `audit_disk_actions`, `account_inactivity_lock`, `mail_expn_vrfy`, `ftp_banner`, `ftp_anonymous`,
  `nfs_export_access` → `both`(`backup`과 선언된 rollback); `rhosts_forbidden` → `restore_backup`.
- 파라미터: `audit_disk_actions`는 리스트 파라미터 넷을, `account_inactivity_lock`은 int 파라미터 하나를
  `script_params`에 적습니다. 각각 본문에서 쓰이므로 `script_params_used`가 성립합니다. 적용 중인 값은 문자 집합
  아래 `P_` 줄로 본문에 닿습니다(E-1). int 문자 집합은 음수를 받아들이고, 비활성 본문이 그것을 거부합니다
  (§4.4).
- 어떤 새 본문도 `script_on_absent`를 설정하지 않습니다. `audit_rules_loaded`와 `account_inactivity_lock`은
  `absent_means: fail`이고, 그 absent 행(지속된 규칙도 `audit.rules`도 없음; `/etc/passwd`가 없음)은 텍스트만인
  `absent`이며 작용할 대상이 없습니다. `auditd_active`도 `absent_means: fail`이지만, services collector는 설치되지
  않은 유닛에 absent가 아니라 `ok:false`를 쓰므로 설치되지 않은 행은 계획되고 본문이 그것을 처리합니다(§4.1).
  나머지는 `absent_means: manual`이라 그 absent 행은 MANUAL이고 절대 계획되지 않습니다.
- 로캘: 템플릿은 로캘을 고정하지 않습니다. 명령 출력(`auditctl -s`/`-l`, `postconf -h`, `systemctl is-*`,
  `postfix status`)을 파싱하는 모든 본문, validate, rollback은 그 명령을 `LC_ALL=C` 아래에서 실행합니다.
- 계획 안의 순서(위험도 → 적용 중인 심각도 → id): `audit_rules_loaded`와 `auditd_active`는 둘 다 상이고
  `restart_service`이며, `audit_`가 `auditd`보다 앞에 정렬되므로 rules 블록이 먼저 돕니다. auditd가 inactive이고
  규칙이 없는 호스트에서는 rules 블록이 바닥 집합을 쓰고 다시 생성만 하며, 이어서 `auditd_active`의 시작이 그것을
  적재합니다. 둘을 모두 담은 계획이 바닥 집합이 적재된 채로 끝남을 stub 테스트가 고정합니다. 실패 실행에서는
  rules 블록의 rollback이 `auditd_active`의 `restore_units`보다 먼저 돕니다. `audit_disk_actions`(중)는 둘 뒤에
  돌고, 그 `was-running` 표지는 둘의 변경 뒤에 쓰입니다. `nfs_export_access`는 `nfs_server_disabled`보다 먼저
  돕니다(둘 다 상, `restart_service`).

## 3. 새 본문이 더하는 규약 (CONTRIBUTING)

이것들은 CONTRIBUTING의 "조치 본문"(Remediation bodies) 절에 영어와 한국어로 들어갑니다.

1. **일방향 runtime 변경은 없다. 그 밖의 모든 runtime 효과는 기록했다가 재생하거나 텍스트에 이름 붙인다(O-2).**
2. **enable하는 units 본문(O-5).** 두 번에 걸친 disable 루프는 disable의 모양으로 남습니다. enable하는 본문은
   `$UNITS`를 돌며 unmask하고, enable하고, inactive인 유닛만 시작합니다. 그 텍스트는 실패한 블록이 시작된
   유닛을 실행 중으로 남긴다고 말합니다.
3. **`restore`를 부르는 rollback(O-9).** `restore <path>`; 그다음 `$MB/<daemon>.edited`가 있을 때만 데몬의
   검사를, 그리고 `$MB/<daemon>.was-running`이 있을 때 reload나 restart를. 두 표지는 실행마다의 것입니다
   (O-16). 먼저 지우고, `was-running`은 어떤 편집보다 먼저, `edited`는 첫 쓰기 바로 앞에 씁니다.
4. **실행마다의 기록(O-16)**은 먼저 지우고 새로 씁니다. 파일 백업과 재생 목록만 첫 기록을 유지합니다.
5. **지우지 말고 주석 처리한다(O-8)**, 새 본문에서. 실격시키는 줄에는 `# muster: ` 접두어를 붙이고, 그 파일은
   `backup`에 있습니다.
6. **자기 파일을 쓰는 도구는 그 파일을 collector처럼 읽는 곳에서 쓴다**(`postconf -e`). 그 파일은 `backup`에
   남습니다. 키 하나보다 많이 다시 쓰는 도구는 쓰지 않습니다.
7. **끝 줄바꿈이 없을 수 있는 파일에 덧붙이기**: 먼저 `if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >>
   "$f"; fi`. 배포된 덧붙이기 본문은 나중에 이를 따릅니다(§7).
8. **쓰는 값(O-6)**과 **고정된 중립 문자열(O-15)**은 거기 적은 대로.
9. **가드된 validate.** 세 모양 옆에, validate는 본문이 로그에 남기는 그대로 두기(X-10)를 `[ guard
   ] || …`나 한 줄 위의 `{ …; } || { …; }` 묶음으로 받아들일 수 있습니다. 배포된 `audit_log_permissions`와
   `cron_permissions` validate가 이미 쓰는 모양입니다.
10. **읽기 대조 테스트(O-10).** 파일에서 읽은 값으로 가드하는 본문은 대조 테스트의 표에 그 읽기를 이름
    붙입니다.
11. **SELinux.** 본문은 도구가 바꿔 놓거나 만든 파일(`postconf -e`, 새로 만든 `/etc/default/useradd`나
    `50-muster.rules`)에만 `restorecon`을 실행합니다. `sed -i` 뒤(GNU sed는 컨텍스트를 지킴)와 `restore` 뒤(`cp -a`가
    지킴)에는 절대 하지 않으며, 표기는 `if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled && command -v
    restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi`입니다.
12. **업그레이드.** 본문이 제자리에서 고치는 벤더 설정 파일은 다음 업그레이드 때 패키지 관리자가 보고합니다.
    Debian과 Ubuntu에서는 dpkg(또는 ucf)가 고쳐진 conffile에 대해 묻고, EL 계열에서는 rpm이 고친 것을 유지하고
    패키지의 판을 그 옆에 `.rpmnew`로 씁니다. 텍스트는 control마다 한 번 그렇게 말하며, 사전 점검이 패키지 소유
    설정으로 확인한 파일만 이름 붙입니다(Debian의 `main.cf`는 postinst가 생성하며 conffile이 아님).

## 4. 본문

모든 본문은 POSIX `sh`이고, 기본 심각도에서 shellcheck를 통과하며(CI의 v0.9.0에 고정), 본문 subshell 안에서
`set -e`에 안전하고, collector 방식으로 읽은 값이 허용 집합 밖일 때만 씁니다. 어떤 쓰기보다 먼저 심볼릭 링크인
대상을 거부합니다(S-27. 벤더 파일은 K2). 단, collector가 그 경로의 심볼릭 링크를 `error`로 읽어(C4) 그 행이
절대 계획되지 않는 곳은 예외이며, 거기서는(§4.5, §4.7, §4.8) 본문이 그 경로를 건너뜁니다. 모든 validate는 세
모양 중 하나이거나 §3.9의 가드된 모양인 한 줄입니다. 텍스트는 문장을 유지하고, 이제 스크립트가 있는 곳은 무엇을
쓰는지와 두는 쪽을 이름 붙입니다. lint는 각 텍스트를 1000 rune으로 제한합니다. `audit_disk_actions`(오늘 영어
616, 한국어 475)가 여유가 가장 적고, 추가가 넘치는 곳에서는 문장이 description으로 옮겨 갑니다. 스케치는 모양을
정하고, 본문은 플랜이 씁니다.

### 4.1 `muster.beyond.auditd_active` (상, 위험도 `restart_service`)

- `units: [auditd.service]`; `backup` 없음, `rollback` 없음(`units_exclusive`).
- 본문, `$UNITS`의 이름마다 차례로:
  1. `systemctl cat`이 그런 유닛을 찾지 못하면 `install the audit package (audit on the EL family, auditd on
     Debian and Ubuntu)`를 로그에 남기고 계속합니다(어떤 본문도 패키지를 설치하지 않음).
  2. `systemctl --quiet unmask`, `systemctl --quiet enable`.
  3. `systemctl is-active --quiet`가 실패할 때: `auditctl -l`이 0이 아닌 값으로 끝나면 → 로그를 남기고 `exit 1`;
     규칙을 가지면 → `kernel holds rules a start would replace; start left to the operator`를 로그에 남기고 계속;
     잠금이 대기 중이고 runtime이 잠기지 않았으면(O-3. 판단할 수 없는 runtime은 잠기지 않음으로 셈) → 로그를
     남기고 `exit 1`; 그 밖에는 `systemctl --quiet start`.
- validate(한 줄, 가드됨): 유닛이 없으면 통과; 아니면 `is-enabled` `&&` (`is-active`, 또는 `auditctl -l`이
  0으로 끝나고 규칙을 가짐).
- `TestServiceScriptsNameTheCollectorsUnits`는 units를 선언하는 control 열하나를 세고, 그 doc 주석이 그렇게 말하며,
  그 표에 services의 `auditd` 행(`auditd.service`)이 들어갑니다.
- stub `systemctl`/`auditctl` 테스트가 어떤 CI 행도 닿지 않는 시작 분기를 고정합니다. active + 대기 중인 잠금 +
  disabled → enabled, `done`; inactive + 잠긴 runtime → 시작됨; inactive + 잠기지 않음 + 대기 중인 잠금(`-e2`
  철자) → 거부, exit 1; inactive + 대기 중인 잠금 + `auditctl -s` 실패 → 거부, exit 1; inactive + 비어 있지 않은
  목록 → enabled, 시작 안 됨, `done`; inactive + `auditctl -l` 실패 → exit 1; inactive + 깨끗함 → 시작됨.
- 텍스트: 본문은 유닛을 enable하고 시작합니다. 패키지 설치와 `audit=0` 검사는 운영자의 몫으로 남습니다. 실패한
  블록은 시작된 데몬을, 그 적재가 적용한 지속된 제어 설정과 함께 실행 중으로 남깁니다.

### 4.2 `muster.beyond.audit_rules_loaded` (상, 위험도 `restart_service`)

- `backup: [/etc/audit/rules.d/50-muster.rules, /etc/audit/audit.rules]`(augenrules가 `audit.rules`를 다시
  생성하므로 drop-in과 함께 복원하고 실패 실행의 체크섬이 비교됨). augenrules는 `/etc/audit/audit.rules.prev`도
  남깁니다. 그것은 적지 않고(augenrules 자신의 것), 사전 점검이 그 동작을 확인합니다.
- 본문, 차례로:
  1. `rm -f "$MB/audit.loaded" "$MB/audit.status" "$MB/auditd.edited"`(O-16).
  2. `/etc/audit/rules.d`가 없거나 심볼릭 링크일 때(만들면 augenrules가 손으로 쓴 `audit.rules`를 덮어쓰게 됨),
     drop-in 경로가 심볼릭 링크일 때, 또는 O-3에 따라(두 쪽 모두) 거부합니다(로그, `exit 1`).
  3. 존재는 `auditKind`처럼 getopt 방식으로 읽습니다. `rules.d/*.rules`에서 `^[[:space:]]*-[waA]`에 맞는 줄.
     O-4의 경우 (b) — 지속된 것 없음, 커널이 규칙을 가짐 — 는 로그를 남기고 끝납니다.
  4. 경우 (c): `$MB/auditd.edited`를 touch하고, `50-muster.rules`를 모드 0640으로 씁니다. 감시(권한 `wa`) 대상은
     `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`(키 `muster-identity`), `/etc/sudoers`,
     `/etc/sudoers.d/`(키 `muster-privilege`), `/etc/audit/`(키 `muster-audit-config`)이며, 경로가 있는 줄만
     씁니다(auditctl은 없는 경로의 감시를 거부함).
  5. `systemctl is-active --quiet auditd.service`이고 커널 목록이 비어 있을 때: `$MB/audit.status`(`auditctl -s`의
     `enabled`, `failure`, `backlog_limit`, `backlog_wait_time`, `rate_limit` 줄. 키는 통째로 맞춤 —
     `backlog_wait_time_actual`은 다른 키)를 쓰고, `touch "$MB/audit.loaded"`, `augenrules --load`.
     그 밖에는 `augenrules`만(다시 생성).
- validate(한 줄, `LC_ALL=C` 아래): `{ ! <persisted presence> && <kernel holds rules>; } || { <persisted
  presence> && { <auditd inactive> || <kernel holds rules>; }; }` — 경우 (b)는 통과하고, auditd가 inactive인 채
  다시 생성만 한 실행은 지속된 쪽으로 통과하며(다음 check가 runtime 쪽을 이름 붙임), 실패하는 `auditctl -l`은
  실패합니다.
- rollback: `restore /etc/audit/rules.d/50-muster.rules /etc/audit/audit.rules`; `$MB/audit.loaded`가 있고
  runtime이 잠기지 않았으면 `$MB/audit.status`를 재생하고(`auditctl -f`, `-b`, `--backlog_wait_time`, `-r`, 그리고
  기록된 `enabled`가 2가 아니었을 때 `-e 0|1`) `auditctl -D`(이 실행의 적재 전에 커널 목록은 비어 있었음. 지우는
  것이 정확한 되돌릴 길이고 운영자의 대기 중인 집합을 적재하지 않음).
- `50-muster`는 `ls -v` 순서에서 stock `audit.rules` 파일보다 앞에 정렬됩니다. augenrules는 순서와 상관없이 `-D`를
  맨 위로, `-e`를 맨 끝으로 끌어올리므로 stock 파일의 `-D`는 muster의 감시를 지우지 않습니다(사전 점검이 두
  계열에서, 아무것도 바꾸지 않는 맨 `augenrules`의 종료 코드와 함께 확인).
- stub 테스트: inactive 데몬 분기(다시 생성, 적재 없음, 표지 없음); 경우 (b)(exit 0, 지속 메시지, `done`, 쓴 것
  없음); 앞선 실행이 적재했고 지금 커널 목록이 비어 있지 않으며 실패를 강제한 재실행(`-D`는 불리지 않고
  `audit.status`는 이번 실행의 것); `-e2` 철자 거부; inactive 유닛 위에서 이 블록과 `auditd_active`를 담은
  계획(바닥 집합이 적재된 채 끝남).

### 4.3 `muster.beyond.audit_disk_actions` (중, 위험도 `restart_service`)

- `script_params: [allowed_space_actions, allowed_disk_full_actions, allowed_disk_error_actions,
  allowed_rotate_actions]`; `backup: [/etc/audit/auditd.conf]`; 선언된 rollback.
- O-17 뒤의 `parseAuditdConf`처럼 읽습니다. `#` 줄은 건너뛰고, `key = value`, 키는 대소문자를 가리지 않고 맞추며,
  마지막 줄이 이기고, 판정되는 동작은 값의 첫 단어를 소문자로 바꾼 것. 첫 단어가 목록에 있는 줄은 절대 다시 쓰지
  않습니다.
- 본문: 실행마다의 기록을 지웁니다(O-16). `auditd.service`가 active이면 `$MB/auditd.was-running`. 목록 밖의 키마다
  O-6이 값을 고릅니다. 본문은 그 키를 `$MB/disk.keys`에 덧붙이고, 첫 쓰기 앞에 `$MB/auditd.edited`를 touch하고,
  값을 보통 변수에 옮겨 담고, 그 키의 모든 줄을 `sed -i`로 다시 씁니다. `space_left_action`이
  `admin_space_left_action`을 절대 건드리지 않도록 고정합니다. 없는 키는 절대 더하지 않습니다. 그 행은 FAIL이 아니라
  MANUAL이라 본문이 만나지 않습니다.
- reload: `was-running` 표지가 있으면 `auditctl --signal reload`만 씁니다. pid 파일로 `kill`하지 않습니다(오래된
  pid 파일은 재사용된 pid를 가리킬 수 있음)(사전 점검이 모든 계열에서 `--signal`을, 그리고 HUP가 다섯 키를 적용하는지를 확인함 — runner에서 저널의 auditd
  reconfigure 줄로 읽음. 적용하지 않으면 텍스트가 다음 시작 때 적용된다고 말함). restart는 절대 하지 않습니다
  (restart는 augenrules를 다시 실행함, O-3).
- validate(한 줄): 네 목록을 `-v`로 넘긴 파일 위의 `awk`로 collector의 읽기를 따르며, `$MB/disk.keys`의 키만
  검사하고, `&&` (`was-running` 표지가 없거나, `systemctl is-active --quiet auditd.service`). 뒤쪽 절반은 살아
  있는지만 봅니다. auditd는 reconfigure가 실패하면 옛 설정을 유지하고, collector는 파일을 읽습니다.
- rollback: `restore /etc/audit/auditd.conf`; `edited`와 `was-running` 표지가 있으면 같은 reload.
- 텍스트에 더함: `rotate`는 `num_logs`를 넘는 로그를 지웁니다. `keep_logs`를 먼저 적는 튜닝은 그것을 유지합니다.
- 테스트: 첫 요소가 그 키에 유효하지 않은 튜닝 목록(`disk_error_action`에 `[rotate, syslog]`는 `syslog`를 씀;
  `space_left_action`에 `[keep_logs]`는 그 키를 둠); `halt`/`single`만인 목록 → exit 0, `done`, 그 키는 바이트가
  같고 다른 키는 씀; `exec /path`는 둠; 앞선 실행의 `disk.keys`가 이번 실행이 두는 키를 이름 붙인 재실행.

### 4.4 `muster.beyond.account_inactivity_lock` (중, 위험도 `lockout_risk`)

- `script_params: [max_inactive_days]`; `backup: [/etc/default/useradd]`; 선언된 rollback.
- 본문:
  1. `rm -f "$MB/inactive.run"`(O-16). `n=$P_max_inactive_days`; `n < 0`은 거부합니다(int 문자 집합은 그것을
     받아들임. 음수 한도는 비밀번호가 만료된 모든 계정을 비활성화할 것).
  2. 심볼릭 링크인 `/etc/default/useradd`는 거부합니다(K2). 마지막 1열 `INACTIVE=` 줄을 읽고, 그 값을 C
     `strtol` base 0으로 읽습니다(collector가 읽는 대로). 없거나, 숫자가 아니거나, `0..n` 밖이면 그런 줄을 모두
     `INACTIVE=n`으로 다시 쓰거나 하나를 덧붙입니다(§3.7). 없는 파일은 모드 0644로 만듭니다.
  3. 로컬 login-capable 계정을 collector 방식으로 열거합니다. uid가 `0 < uid < UID_MIN`(login.defs의 주석 아닌 첫
     `UID_MIN`, 기본 1000)이 아니고 셸이 `/etc/shells`에 있으며 `*/nologin`이나 `*/false`가 아닌 모든
     `/etc/passwd` 행. 원격 NSS 소스만 가진 계정은 `/etc/passwd`에 없으므로 건드리지 않습니다(control은 그것을
     WARN으로 읽고 계획하지 않음). 어떤 산술보다 먼저 빈 `last`나 `max`는 `-1`로 읽습니다. 계정마다:
     - shadow 행 없음 → 건너뛰고 이름을 남김(`chage`가 하나를 지어낼 것);
     - 필드 7이 -1이 아니고 `n` 이하인 십진 정수(-1보다 작은 음수 포함: 절이 받아들임) → 둠;
     - 필드 7이 비어 있지 않고 십진 정수가 아님 → 건너뛰고 이름을 남김(본문이 그 텍스트를 복원할 수 없음);
     - `last = 0` → 건너뛰고 이름을 남김(다음 로그인 때 바꿔야 함. pam_unix는 거기에 비활성을 적용하지 않으므로
       이는 안전한 쪽으로 더 건너뜀); `max`가 설정되어 있고 99999가 아닌데 `last`가 비었거나 음수 → 건너뛰고 이름을
       남김(pam_unix의 만료 검사에는 설정되지 않은 마지막 변경일을 막는 가드가 없어, 필드 7이 설정되면 계정이 만료로
       읽힘); `last <= 0`일 때는 날짜 줄을 절대 찍지 않음;
     - `last > 0`, `max >= 0`, 그리고 `today - last >= max + n`(today = `$(( $(date +%s) / 86400 ))`; `>=`는
       shadow의 `isexpired` 경계이며 pam_unix의 `>`보다 보수적인 쪽) → 건너뛰고 이름을 남김(`change its password
       first`);
     - 그 밖에는: `max`가 설정되어 있고 99999가 아니면 비밀번호가 바뀌지 않을 때 계정이 비활성화될 날짜를
       로그에 남김(root 먼저); 이름이 `$MB/inactive.list`에 없으면 `name:old`(빈 값 → `-1`)를 기록;
       `$MB/inactive.run`에 이름을 덧붙임; `chage -I n -- name`.
- validate(한 줄): useradd 줄이 `0..n`의 숫자 `&&` `inactive.run`의 이름 중 아직 shadow 행이 있는 모든 이름의 필드
  7이 `0..n`의 숫자. 건너뛴 계정은 검증하지 않습니다. 블록은 `done`으로 끝나고 다음 `check`가 그것들을 이름
  붙입니다(X-10, `password_policy`의 ageing 루프처럼).
- rollback: `inactive.list`를 줄마다 `chage -I "$old" -- "$name" || rc=1`로 재생하고 끝에서 `exit $rc`(그사이 지운
  계정은 보고되고 나머지는 그래도 복원됨). 템플릿의 `restore`가 useradd 파일을 되돌려 놓습니다.
- `password_policy`와의 순서(역시 `lockout_risk`, 상이라 먼저 돎): 그것은 `max_days`보다 젊은 해시 있는 계정에서만
  `max`를 낮추므로, 건너뛰기는 새 최대값을 읽고 올바르게 남습니다.
- 테스트: `PATH` 맨 앞의 stub `chage`가 경계일, `last = 0`, 빈 `last`와 빈 `max`, 최대값 없는 root, 실제 최대값이
  있는 root(날짜를 로그에 남김), shadow 행 없는 이름, 쓰레기 필드 7, 빈 필드 7(rollback argv `-I -1`), 재실행에서
  첫 기록 유지와 재실행에서 건너뛴 이름은 검증 안 됨, 음수 파라미터, rollback 때 지워진 계정, 끝 줄바꿈 없는
  useradd 파일을 다룹니다. 두 번째 테스트가 accounts fixture 위에서 본문의 계정 집합을 `loginCapable`과 대조해
  고정합니다.

### 4.5 `muster.file.rhosts_forbidden` — `/etc/hosts.equiv` 쪽 (상, 위험도 `restart_service`)

- `backup: [/etc/hosts.equiv]`.
- 본문: `/etc/hosts.equiv`가 정규 파일이고 심볼릭 링크가 아니면, 공백 아닌 첫 문자가 `+`인 모든 줄을 주석
  처리합니다(`# muster: ` 접두어). 이는 맨 `+`와, collector가 역시 판정하는 범위가 정해진 `+host`, `+@netgroup`
  신뢰를 덮습니다. 텍스트가 둘 다 이름 붙입니다. 이 파일을 다시 읽는 데몬은 없습니다(rshd는 연결마다 읽음).
- validate: `[ ! -f /etc/hosts.equiv ] || [ -L /etc/hosts.equiv ] || ! grep -Eq '^[[:space:]]*\+'
  /etc/hosts.equiv`.
- `~/.rhosts`와 `~/.shosts` 쪽은 텍스트로 남습니다. 그 파일들은 계정이 소유하는 홈에 있고, `modes_trusted`가 그것을
  거부합니다(S-47).

### 4.6 `muster.service.mail_expn_vrfy` — postfix 쪽 (중, 위험도 `restart_service`)

- `backup: [/etc/postfix/main.cf]`; 선언된 rollback.
- 본문: 실행마다의 표지를 지웁니다(O-16). `postconf`가 없으면 sendmail 쪽이 운영자의 몫이라고 로그에 남기고 아무것도
  바꾸지 않습니다. 심볼릭 링크인 `main.cf`는 거부합니다. `postfix check`를 먼저 실행하고 이미 실패하면 거부합니다
  (그러면 이후의 실패는 물려받은 것이 아니라 편집의 것). `postfix status`가 성공하면 `$MB/postfix.was-running`.
  `postconf -h disable_vrfy_command`가 `yes`가 아니면(대소문자 무시): `$MB/postfix.edited`를 touch하고, `postconf -e
  'disable_vrfy_command = yes'`, `postfix check`, 그리고 `was-running` 표지가 있으면 `postfix reload`(systemd가 있든
  없든 동작).
- validate(`postconf`로 가드됨): `postconf -h disable_vrfy_command`가 대소문자 무시로 `yes` `&&` `postfix check`.
- rollback: `restore /etc/postfix/main.cf`; `edited` 표지가 있으면 `postfix check`, 그다음 `was-running` 표지가
  있으면 `postfix reload`.
- stub 테스트: 편집 전에 `postfix check`가 실패 → exit 1, `rollback failed` 줄 없음.
- 텍스트에 더함: reload는 대기 중인 `master.cf` 편집도 적용합니다. sendmail 쪽(생성된 `sendmail.cf`의
  `PrivacyOptions`)은 텍스트로 남습니다.

### 4.7 `muster.service.ftp_banner` — vsftpd 쪽 (하, 위험도 `restart_service`)

- `backup: [/etc/vsftpd.conf, /etc/vsftpd/vsftpd.conf]`(Debian, EL); 본문은 정규 파일이고 심볼릭 링크가 아닌 것마다
  작용합니다.
- O-14 뒤에 collector가 읽는 대로 읽습니다. 키는 소문자로, 마지막 줄이 이기며, 인사말은 `banner_file` 옵션이
  설정되어 있고 파일이 비어 있지 않으면 그 내용, 아니면 설정되어 있을 때 `ftpd_banner`, 아니면 컴파일된
  인사말(드러냄). 제품은 collector의 패턴 `(?i)\b(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)\b`이고, 본문·가드·validate를
  위해 `grep -Eiq
  '(^|[^[:alnum:]_])(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)([^[:alnum:]_]|$)'`로 씁니다.
- 비어 있지 않은 `banner_file`이 설정되어 있으면 본문은 그것을 둡니다(`banner_file <path> sets the greeting; left to the
  operator`). 그 파일은 운영자의 고지이고, 옵션을 주석 처리하면 그것을 버리게 됩니다. 빈 것은 다음으로 넘어갑니다.
  그 밖에, `ftpd_banner`가 설정되지 않았거나 제품을 이름 붙이면 `$MB/vsftpd.edited`를 touch하고 모든
  `ftpd_banner=` 줄을 `ftpd_banner=FTP server ready.`로 다시 쓰거나 하나를 덧붙입니다(§3.7)(O-15).
- restart: 실행마다의 표지를 먼저 지웁니다(O-16). `systemctl is-active --quiet vsftpd.service`이면
  `$MB/vsftpd.was-running`; 그것이 있으면 `systemctl restart vsftpd.service`(vsftpd에는 reload도 설정 검사도 없음).
  FTP control 둘을 모두 담은 계획은 그것을 두 번 restart합니다. 그것은 받아들입니다.
- validate(비어 있지 않은 `banner_file`로 가드됨): 같은 방식으로 읽은 인사말이 제품을 이름 붙이지 않음 `&&`
  (`was-running` 표지가 없거나, 유닛이 active).
- rollback: 두 경로를 `restore`; `edited`와 `was-running` 표지가 있으면 `systemctl restart vsftpd.service`(본문의
  restart가 failed로 남긴 유닛을 다시 시작함).
- 테스트: 두 키 모두와 빈 파일 행; 앞선 실행의 `was-running` 표지가 있고 지금 vsftpd가 멈춘 재실행(restart 없음);
  끝 줄바꿈 없는 conf.
- proftpd 쪽(`ServerIdent`)은 텍스트로 남습니다. proftpd를 배포하는 CI 이미지가 없습니다.

### 4.8 `muster.service.ftp_anonymous` — vsftpd 쪽 (상, 위험도 `restart_service`)

- §4.7과 같은 대상, 읽기, 표지, restart, validate 모양, rollback. vsftpd가 읽는 대로 유효한 `anonymous_enable`이
  거짓(`no`, `false`, `0`, 대소문자 무시. 없는 키는 컴파일된 YES)이 아니면 모든 `anonymous_enable=` 줄을
  `anonymous_enable=NO`로 다시 쓰거나 하나를 덧붙입니다.
- 텍스트는 본문이 누군가 돌리려 했을 수 있는 익명 서비스를 닫는다고, 그리고 proftpd `<Anonymous>` 블록과
  pure-ftpd의 `NoAnonymous`는 운영자의 몫으로 남는다고 말합니다.

### 4.9 `muster.service.nfs_export_access` — `no_root_squash` 쪽 (상, 위험도 `restart_service`)

- 배포된 본문(`/etc/exports`의 소유자와 모드, `backup: [/etc/exports]`)이 기존 가드 안에서, 줄의 첫 `#` 앞
  텍스트의 옵션 목록으로 범위를 정한 바꾸기를 얻습니다. `(`, `,`, 또는 기본 목록을 여는 공백 뒤의 `-`(O-18)가 앞에
  있고 `,`, `)`, 공백, 또는 줄 끝이 뒤에 있는 `no_root_squash`가 `root_squash`가 되며, 남은 것이 없을 때까지 한 번에
  하나씩 바꿉니다(인접한 맞춤은 쉼표를 공유함). 그 단어를 담기만 한 경로나 클라이언트 이름은 건드리지 않습니다.
  가드, validate, 대조 행, 바꾸기는 하나의 ERE를 함께 씁니다: `^[^#]*([(,]|[[:space:]]-)no_root_squash([,)[:space:]]|$)`.
- 표지(O-16): `nfs-server.service`가 active이면 `$MB/nfs.was-running`(Debian의 `nfs-kernel-server`는 별칭);
  바꾸기 앞에 `$MB/nfs.edited`; 둘 다 있으면 `exportfs -ra`. 그 `exportfs`는 살아 있는 서버 위에서 돌고, 다음 블록
  `nfs_server_disabled`가 이어서 그것을 멈춥니다(§2).
- validate: 기존 모드 `case` `&&` 옵션 범위의 `no_root_squash` 없음, 같은 가드 아래.
- rollback(새것이라 단어가 `both`가 됨): `restore /etc/exports`; 두 표지가 있으면 `exportfs -ra`. stub 테스트가
  그것을 고정합니다(§5).
- 텍스트에 더함: `exportfs -ra`는 커널의 표를 모든 export 파일에 다시 맞춥니다 — 대기 중인 `/etc/exports.d` 편집을
  적용하고 runtime에만 있는 export를 떨어뜨림 — 그리고 rollback은 손으로 만든 살아 있는 표가 아니라 파일의 관점을
  복원합니다. 와일드카드 쪽(어느 클라이언트)과 `/etc/exports.d/*.exports`는 텍스트로 남습니다(`backup`은 글롭을
  받지 않음).

## 5. 증명

**runner 행**(`ci/roundtrip/runner.sh`, 멱등). 새 시드와 초기화:

| control | 시드 / 초기화 |
|---|---|
| `auditd_active` | `systemctl disable auditd`, 실행 중으로 유지(`record()`가 `is-active`를 비교하고, 무엇도 그것을 다시 멈출 수 없음); 수리 실행이 그것을 enable하고, 실패 실행의 `restore_units`가 다시 disable함 |
| `audit_rules_loaded` | 초기화: `rm -f /etc/audit/rules.d/50-muster.rules`, stock 집합의 `augenrules --load`(커널 목록이 다시 `No rules`), 그다음 `auditctl -b 4321` — 지속된 집합이 담지 않는 runtime 값이라 제대로 동작하는 `audit.status` 재생만이 그것을 복원함; stock은 두 절 모두 FAIL(경우 c) |
| `audit_disk_actions` | 첫 실행이 원래의 `auditd.conf`를 어떤 본문도 쓰지 않는 경로에 저장함; 매 실행이 그것을 되돌려 복사하고, `disk_full_action = suspend`를 설정하고, auditd에 신호를 보냄 |
| `account_inactivity_lock` | 첫 실행이 원래의 `/etc/default/useradd`를 같은 방식으로 저장함; 매 실행이 그것을 되돌려 복사하고 모든 로컬 login-capable 계정에 `chage -I -1`을 실행함; stock은 FAIL |

`runner.sh`는 `-e 2`나 `--loginuid-immutable`을 어디에도 쓰지 않고, `augenrules --load` 앞에 muster의 audit
drop-in을 지웁니다. `rhosts_forbidden`은 runner에 없습니다. VM의 `files.user_rhosts`가 absent라(시스템 계정의 홈이
선언 밖) 그 행은 MANUAL이고 절대 계획되지 않습니다.

**컨테이너 행.** `rhosts_forbidden`은 넷 모두에서 돕니다(시드 `printf '+\n' > /etc/hosts.equiv`, 모드 0644).
`ftp_banner`(stock FAIL), `ftp_anonymous`(시드 `anonymous_enable=YES`), `mail_expn_vrfy`(stock postfix FAIL),
`nfs_export_access`(시드 `/srv 192.0.2.0/24(rw,no_root_squash)`, RFC 5737 범위, 그다음 `exportfs -ra`)는 init 행
셋에서 돕니다. `ubuntu2204`에는 systemd가 없어 거기서 services 가드는 NOT_APPLICABLE로 읽힙니다. 시드 방식:

- 아래의 IPv6 우회는 EL과 Debian 시드에 똑같이 적용됩니다. EL 시드는 첫 `dnf` 줄에서 `vsftpd`와 `postfix`를 설치하고, 시작 루프 앞에 설정 시드(`anonymous_enable=YES`)를
  씁니다. Debian은 사전 점검이 정한 debconf 답으로 `postfix`를 비대화식으로 설치합니다;
- `vsftpd.service`와 `postfix.service`가 각 init 행의 `START_UNITS`에 들어갑니다. `postfix.service`가 `/bin/true`
  래퍼인 Debian에서는 정착 검사가 `postfix@-.service`(또는 `postfix status`)를 읽습니다;
- 시작 사전 점검은 랩에서만이 아니라 fix-roundtrip job 자신의 docker에서(브랜치 dispatch) 돕니다. EL stock
  vsftpd(`listen_ipv6=YES`)와 postfix(`inet_protocols=all`)는 러너 docker의 IPv6에 의존합니다. 어떤 우회책이든
  (`listen=YES`/`listen_ipv6=NO`, `postconf -e inet_protocols=ipv4`) 시드가 plan 전에 적용하므로, 실행 전 기록이 그것을
  담습니다;
- 어떤 행에서 돌 수 없는 데몬은 그 행의 `START_UNITS`와 정착 검사에서 빠지고, 그 restart 경로는 이 설계의 §8,
  플랜, CONTRIBUTING에서(`unproven_units`가 선언된 유닛만 이름 붙이는 `_roundtrip.yaml`이 아니라) 그 행에서
  증명되지 않는다고 그 stub 테스트와 함께 이름 붙습니다.

**`record()`**에 계획된 항목마다 추가됩니다. audit id가 계획되면 `auditctl -l`과 `auditctl -s`의 `enabled`,
`failure`, `backlog_limit`, `backlog_wait_time`, `rate_limit`, `loginuid_immutable` 줄(키는 통째로 맞춤);
`password_policy`나 `account_inactivity_lock`이 계획되면 계정마다 shadow 필드 4, 5, 7과 그 세 필드를 비운
`/etc/shadow`의 체크섬(그래서 다른 무엇이든 바꾼 `chage`가 잡힘); `nfs_export_access`가 계획되면 `exportfs -s`; FTP
id가 계획되면 `systemctl is-active vsftpd.service`; `mail_expn_vrfy`가 계획되면 `postfix status`의 종료 코드.
`.backup[]` 체크섬이 이미 파일 쪽을 바이트 단위로 증명합니다.

**표.** `_roundtrip.yaml`에 id 여덟이 들어가고, `nfs_export_access`는 자기 행을 유지합니다. ci.yml의 `seeded`
문자열은 같은 커밋에서 바뀝니다.

| controls | 행 |
|---|---|
| `auditd_active`, `audit_rules_loaded`, `audit_disk_actions`, `account_inactivity_lock` | `runner` |
| `rhosts_forbidden` | 컨테이너 행 넷 |
| `mail_expn_vrfy`, `ftp_banner`, `ftp_anonymous`, `nfs_export_access` | init 행 셋 |

**플랜이 먼저 실행하는 사전 점검**(랩 컨테이너, 브랜치 dispatch로 fix-roundtrip docker, 그리고 답이 VM에 달린
곳에서는 runner). 각 답은 플랜의 판정이 됩니다.

- augenrules: `-D`/`-e`의 끌어올림; 맨 `augenrules`가 다시 생성만 한다는 것과 바뀐 것이 없을 때의 종료 코드;
  `audit.rules.prev`; auditctl이 받아들이는 `-e` 철자(`0`/`1`/`2`만이라면 collector의 `-e 02` 읽기는 기록된 과잉
  읽기).
- auditd: Ubuntu 24.04의 stock `auditd.conf`; EL9, Debian 12, Ubuntu 22.04/24.04에서의 `auditctl --signal reload`;
  HUP가 다섯 동작 키를 적용하는지(reconfigure 저널 줄); 모든 행의 유닛 파일에서 유닛의 `RefuseManualStop`과 augenrules
  `ExecStartPost`(그 `-` 접두어와 함께); runner 커널에서 `auditctl -s`의 정확한 키 이름.
- postfix: init 행 셋에서의 비대화식 설치, 그 stock `disable_vrfy_command`, `umask 077` 아래 `postconf -e` 뒤
  `main.cf`의 모드와 inode, `postfix check`가 디렉터리를 만드는지, 각 컨테이너에서 시작되는지, 각 계열에서
  `main.cf`가 conffile인지.
- vsftpd: 그 stock `ftpd_banner`/`anonymous_enable` 줄; 각 컨테이너에서 시작되는지; 두 배너 키를 모두 각 방향으로
  설정했을 때와 빈 배너 파일일 때 포트 21에서 읽은 220 줄.
- NFS: 각 init 컨테이너에서 시드한 줄로 `exportfs -ra`(overlay 루트 위의 `/srv`; 실패하면 `fsid=`를 쓴 tmpfs);
  nfs-utils가 `-opts` 기본 목록을 받아들이는지(O-18).
- SELinux: SELinux가 enforcing인 EL9 호스트에서 `sed -i`, `postconf -e`, `cp -a`가 파일의 컨텍스트를 유지하는지,
  그런 랩 VM이 있는 곳에서 읽음; §3.11의 `restorecon` 규칙은 어느 쪽이든 성립합니다.
- runner: 첫 실행 전의 로컬 login-capable 계정과 그 shadow 필드(`runner` 계정은 비활성화되면 안 됨), 그리고
  init 행에서 vsftpd나 postfix가 돈다는 이유로 계획되는 다른 scripted control이 없다는 것.

## 6. 테스트, 문서

**커밋, 차례로.** collector 고침 셋이 먼저, 각각 따로 옵니다(O-14, O-17, O-18). 읽기, `controls/testdata/<id>/`
아래의 fixture, 바뀐 파서의 fuzz 시드, 생존자 0인 mutation 테스트, 설명만 바뀐 facts 골든 재생성(리프를 더할
때만 `since` 항목), CHANGELOG "Fixed" 줄. 그다음 O-11의 가드, 그다음 본문, 그다음 CI, 그다음 문서.

**테스트.** 본문마다 3D-2c 방식의 배포 본문 Linux 테스트(경로는 다시 기준을 잡고, 도구는 `PATH` 맨 앞에 stub)를
§4에 적은 대로; 이중 `restore`(O-9); 재실행에서의 실행마다의 기록(O-16); 읽기 대조 테스트(O-10); 심볼릭 링크 표의
O-11 경로 셋; 위와 같은 왕복 표 테스트와 units 고정. `all-scripted.sh`, remedy 골든, shellcheck 집합이 다시
생성됩니다. `examples/*-fix-report.*`가 바뀌고 머지 전에 브랜치의 `examples.yml` 실행에서 새로 고칩니다.
mutation 테스트는 생존자 0을 유지합니다.

**문서**(영어와 한국어를 같은 커밋에서. 이 설계의 `.ko.md` 짝은 설계 커밋 전에 씀). 메인 설계: §10.2가 3D-2d를 이
설계의 링크와 함께 표시하고 다음에 올 것(3D-1b, 3D-3)을 이름 붙임; D34는 그대로. CLAUDE.md의 Fix 절: enable하는
units 본문, O-2/O-3, `restore`를 부르는 rollback, 실행마다의 표지, 새 시드와 `record()` 줄. CONTRIBUTING 짝: §3의
규약, enable하는 본문에 맞게 고쳐 쓴 units 본문 문단. README 짝: 상태와 로드맵. THREAT_MODEL: O-2와 O-3, 그리고
"no body deletes a kernel audit rule it did not load in this run". ATTRIBUTION: 바닥 집합의 규칙 줄(O-4). CHANGELOG:
Fixed — vsftpd의 인사말 우선순위(O-14), auditd의 `exec` 동작(O-17), exports 기본 목록(O-18); Added — 본문 여덟과
`no_root_squash` 쪽; Changed — 위험도 넷, 심볼릭 링크 가드, `password_hash_algorithm` 텍스트; Controls: 새
`controls/VERSION`.

## 7. 미룬 항목

- **언제까지나 텍스트**(호스트마다의 판단, 정책, 또는 자격 증명): `audit_immutable`(O-2), 로그인 배너의
  문구(`login_banner`), `sudo_logging`(sudoers 편집은 sudo 장애 위험. stock 두 계열은 통과),
  `remote_log_forwarding`(수신자), `file_integrity_tool`(패키지와 기준선), `password_hash_algorithm`(재해시에는
  평문이 필요. 그 텍스트에 "locking the account does not clear the finding, and never blank the field"가 더해짐),
  snmp, dns, ftp TLS, 방화벽, 계정 선택 control, `automation: manual`인 mail과 dns control 넷, NFS 와일드카드 쪽,
  `.rhosts` 쪽, vsftpd의 비어 있지 않은 `banner_file` 경우, `audit_log_permissions`의 `log_group` 쪽(Ubuntu의
  `adm`은 호스트의 결정).
- **나중 사이클(3D-2e 후보):** 사용자 홈과 dotfile의 모드·소유자 작업(`env_file_permissions`,
  `home_dir_permissions`, `startup_script_permissions`), 계정 필드(`system_account_shells`,
  `ftp_account_shell`, `ftpusers_root`), `shadow_passwords`(`pwconv`), journald 지속성(`syslog_policy`의
  journald 쪽), `session_timeout`의 TMOUT 쪽, `*_mount_options` control 넷을 위한 mounts 기록 종류, 그리고 서비스
  control 열의 super-server 쪽과 `nis_disabled`의 nsswitch 쪽(둘 다 `units` 옆에 `backup`이 필요하고
  `units_exclusive`가 그것을 금지함 — 스키마 결정). 배포된 덧붙이기 본문을 위한 끝 줄바꿈 규칙(§3.7).
- CI에서의 SELinux 레이블 증명(SELinux를 돌리는 행이 없음. 그동안은 §3.11이 규칙).
- 공유 "키 설정" 헬퍼(파일마다 문법이 다름: 첫 줄이 이김, 마지막 줄이 이김, 대소문자, 구분자)와 쓰는 모든 경로가
  가드되고 `backup`에 있다는 lint(O-10/O-11의 테스트가 이 사이클의 답).
