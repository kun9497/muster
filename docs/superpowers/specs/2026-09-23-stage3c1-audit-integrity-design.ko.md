# 3C-1 단계 — 감사 파이프라인 상태와 패키지 무결성

*[English](2026-09-23-stage3c1-audit-integrity-design.md) · 한국어*

이 문서는 muster 계획 3C-1의 설계입니다. 메인 설계(`2026-09-02-muster-design.md`, §10.2
"Stage 3")가 "3C 감사 / 노출 / root 등가 경로(그리고 패키지 검증, W-8)"로 남겨 둔 하위
프로젝트의 앞쪽 절반입니다. 2026-09-21에 이 하위 프로젝트를 주제별로 나눴습니다. **3C-1
"무결성"** — 호스트가 자신에게 일어난 일을 기록하는가, 자신의 파일이 바뀌지 않았음을 확인할 수
있는가 — 와 **3C-2 "노출·권한"** — 프로세스 수집기, 소켓 → 프로세스 → 패키지 → 방화벽
교차검사, root 등가 경로, 그리고 3A·3B가 3C로 넘긴 항목(네트워크 sysctl, 워크의 file
capability·ACL)입니다. 이 문서는 3C-1만 다루며 3C-2는 3C-1이 병합된 뒤 별도 설계를 갖습니다.
결정은 I-1 … I-12로 번호를 붙이고 계획을 구속합니다. 2026-09-23의 새 리뷰(blocking 4, medium
10, low 16)와 lab 호스트의 실측(`dpkg --verify`: 벽시계 10분 20초, `missing` 행 1199, exit 0)을
반영했고, 계획의 pre-flight 정정(계획의 J-1 … J-6: `auditctl` 종료 코드, 컨테이너가 답할 수 있는 것,
dpkg의 종료 코드와 줄 형식, 세 릴리스의 AIDE 사실, 디렉터리 모드)도 반영했습니다. 이 판이 초안과
다른 곳은 그것들의 몫입니다. 여기의 모든 점검은 1차 출처 —
`auditd.conf(5)`, `auditctl(8)`, `augenrules(8)`, `aide(1)`과 `aide.conf(5)`, `sudoers(5)`,
`rpm(8)`, `dpkg(1)`, `journal-upload.conf(5)` — 에서 muster의 말로 썼고, CIS 권고 번호를 달지
않으며, 벤치마크 문장을 옮기지 않습니다(메인 설계 §11, D04).

브레인스토밍에서 내린 네 선택이 아래 전부를 규정합니다. 위의 분할(Q1); 패키지 검증은 데이터베이스
전체를 `rpm -Va` / `dpkg --verify`로, 인자 고정, `--deep`에서만(Q2) — 그래서 3A의 W-8이 예상한
`CommandTemplate`은 만들지 않습니다. 가변 인자 꼬리를 필요로 하는 것이 더는 없기 때문입니다;
auditd 쪽은 파이프라인의 상태를 판정하고 규칙은 내용을 판정하지 않은 채 근거로 기록합니다(Q3);
AIDE가 muster가 모델링하는 파일 무결성 도구이고, 다른 도구를 쓰는 호스트는 그 도구 이름과 함께
검토 대상으로 보고합니다(Q4).

## 1. 목표

`beyond` 카테고리 컨트롤 아홉 개 — 감사 데몬 다섯, 로그 전송 하나, sudo 자체 로그 하나, 파일
무결성 도구 하나, 패키지 무결성 하나 — 를 새 수집기 셋(`audit`, `fim`, `pkgverify`), 확장
둘(sudo 리더의 `sudo.log.*`, `logging`의 `journal-upload`와 rsyslog 원격 대상), `services`
표의 새 행 둘(`auditd`, `journal_upload`), `collect` 플래그 둘(`--verify-timeout`,
`--no-verify`)로 먹입니다. 3C-1 뒤 제어집합은 컨트롤 96개(67개 항목의 68개는 그대로, 가이드 밖
28개), `controls/VERSION`은 `kisa-unix-2026+2026.09.23`, `schema_version`은 그대로입니다(키와
레코드 필드를 더할 뿐 바꾸지 않음. 메인 §5.7).

범위 밖(계획이 흘러가지 않도록 이름을 적음): 3C-2의 전부(위); 호스트가 어떤 감사 규칙을
가져야 하는지 판정하는 것(그것은 벤치마크의 표이며 `references.cis`를 달 수 있는 3D의 CIS
프로파일 몫); AIDE 외 도구의 자동 판정; AIDE 데이터베이스의 최신성; verify 행과 워크의 패키지
표 결합(두 도구는 패키지 이름을 출력하지 않고, 결합은 3C-2의 프로세스 → 패키지 작업과 함께 옴);
sudo 세션 기록(`log_input`, `log_output`) — 여기서 읽는 것이 없으므로 사실로도 싣지 않음; 원격
로그 경로의 암호화 여부. 메인 설계가 감사 파이프라인 상태 아래 적은 "journald 영속"은 여기서
컨트롤이 **아닙니다**. U-65(`syslog_policy`)가 journald-only 호스트에서 그것을, rsyslog
호스트에서 파일 영속을 이미 판정하므로 두 번째 컨트롤은 다른 id 아래 같은 판정일 뿐입니다.

## 2. 3B에서 이어받은 원칙

1. **판정은 실행 중인 상태를 읽고, 영속 파일은 근거이자 "재부팅 뒤에도 남는가"의 답입니다.**
   감사 데몬의 규칙과 불변 플래그는 두 집 setting입니다. runtime 쪽은 `auditctl -l` /
   `auditctl -s`(인자 고정, root), persisted 쪽은 규칙 파일, `default_on: effective`이며
   effective는 3B의 sysctl처럼 runtime의 복사본입니다(K-3).
2. **명령은 인자가 고정이고 종료 코드는 데이터입니다.** `rpm -Va`는 "무언가 다르다"를 1로
   말합니다 — `patch` 수집기가 `dnf check-update`의 100과 `needs-restarting`의 1을 이미 그렇게
   읽습니다; 인자 없는 `dpkg --verify`는 언제나 0으로 끝나므로(그 `verify()`는 설치되지 않은
   이름의 패키지에만 실패를 돌려주며, lab의 `missing` 행 1199개도 0이었음) 판정은 행에서 읽고 종료
   코드는 "답했다"(0, 또는 행이 있는 1)와 "실패했다"만 가릅니다. `auditctl`은 uid가 아니라 유효
   `CAP_AUDIT_CONTROL`로 문을 지키며 커널에 닿기 전에 exit 4로 거부하고, root일 때 답하지 않는
   커널은 stderr와 exit 255로 압니다(I-3). 그 밖의 코드는 명령과 코드를 적은 `error`.
3. **데몬 설정이 가리키는 경로는 그 데몬의 수집기 몫입니다**(C1): `auditd.conf`의 `log_file`,
   `aide.conf`의 `database_in`. 권한 사실은 `writePermFacts`가 쓰는 아홉 leaf뿐입니다.
4. **노이즈는 걸러내고 필터는 사실입니다.** verify 출력에서 무엇이 어떤 규칙으로 몇 행 빠졌는지가
   스냅샷에 있습니다. 필터를 되읽을 수 없는 PASS는 누구도 검증할 수 없는 PASS입니다.
5. **모든 beyond 컨트롤은 `env.container eq none`으로 게이트됩니다.** 컨트롤 하나가 `--deep`에
   의존합니다. `--deep` 없는 실행은 워크가 `walk.*`를 두듯 `packages.verify.*` 키를 쓰지 않고,
   그 컨트롤은 I-9의 규칙으로 MANUAL("run collect --deep")로 읽힙니다. root 없이는
   `walk.complete`처럼 `packages.verify.complete`가 `denied`이고 나머지는 쓰지 않습니다. 두
   명령은 느리고 디스크에 매입니다(lab의 `dpkg --verify`는 CPU 20초에 벽시계 10분). 그래서 자기
   한도를 갖습니다: `--verify-timeout`(기본 30분)이 명령 타임아웃이고, `--deep`은 기본
   `--timeout`을 워크 예산 + verify 타임아웃 + 5분으로 올리며(수집기는 한 마감 아래 차례로 돌고
   `pkgverify`가 `walk`보다 앞에 정렬되므로, 느린 verify가 워크를 굶기지 않게 하는 것이 이 합),
   `--no-verify`는 deep 실행을 3A의 비용에 묶어 둡니다 — `packages.verify.*` 키는 쓰이지 않고
   컨트롤은 플래그를 적은 MANUAL로 읽힙니다.
6. **모든 파서는 fuzz하고, 데몬이 답할 수 있으면 데몬과 비교합니다.** 새 파서 셋(감사 규칙,
   `auditd.conf`, verify 출력)과 작은 넷(`auditctl -s` 리더, sudoers `Defaults`, `aide.conf`
   매크로, `journal-upload.conf`)이 각각 seed 달린 `Fuzz<Name>` 대상을 갖고, verify 파서는 실제
   `rpm -Va`·`dpkg --verify` 출력과, runtime 리더는 `auditctl`과 CI 컨테이너 안에서
   비교합니다(I-11).

## 3. 사실과 수집기 (I-3 … I-7)

레지스트리 키 64개: `audit.*` 34, `fim.*` 9, `packages.verify.*` 7, `sudo.*` 3, `logging.*` 3,
`services.*` 8. 어떤 키도 다른 키의 접두어가 아닙니다(Builder는 leaf 아래의 leaf를 거부함).
규칙 목록이 `audit.rules`가 아니라 `audit.rules.persisted`인 이유입니다. 달리 말하지 않으면
민감도는 `public`. 모든 목록은 정렬되고 상한이 있으며 상한에 닿으면 그 키에 `truncated: true`.

### I-3 — `audit` 수집기

선언: 읽기 `/etc/audit/auditd.conf`, `/etc/audit/audit.rules`, `/etc/audit/rules.d/*.rules`
(Glob), stat 전용 `/var/log`, `/var/log/audit`, `/var/log/audit/*`, `/var/log/*`; 명령
`/usr/sbin/auditctl -l`과 `/usr/sbin/auditctl -s`(각 5초, 1 MiB. EL9의 `/sbin`은 `usr/sbin`
링크라 한 경로가 두 계열을 다 섬김).

- `audit.rules.present` — `setting<bool>`. runtime: `auditctl -l`이 규칙 줄을 하나 이상
  출력("No rules"는 false). persisted: 영속 소스에 규칙 줄(`-w`, `-a`, `-A`)이 하나 이상.
  `audit.rules.loaded_count`와 `audit.rules.persisted_count`는 두 개수(`int`), 근거.
  `audit.rules.persisted`는 `list<record>` `{file, line, kind, key, text}`(`internal`; `line`은
  줄 번호; `kind` ∈ watch | syscall | control | other; `key`는 `-k`/`key=` 값 또는 빈 문자열;
  2000행 상한), 읽은 그대로의 영속 규칙을 파일 순서로 — `augenrules`는 적재 전에 주석을 걷어내고
  제어 줄을 재배치하므로(`-D`를 앞에, `-e`를 끝에) 이 목록은 병합된 `audit.rules`가 아니라 파일
  그 자체입니다.
- **영속 소스는 systemd 호스트의 유일한 적재기인 `augenrules(8)`를 모델링합니다**(두 계열 다
  `ExecStartPost=-/sbin/augenrules --load`; 데몬 자신은 `/etc/audit/audit.rules`를 읽지 않음):
  영속 답은 `/etc/audit/rules.d/`의 `*.rules` 파일을 C 로케일 사전순으로 읽은 것입니다. 빈
  디렉터리는 "규칙 없음"이라는 영속 답이고(augenrules가 빈 `audit.rules`를 다시 만듦), 디렉터리가
  **없으면** `absent`("rules.d is missing: augenrules loads nothing at boot") — 그 옆에 손으로 쓴
  `audit.rules`는 다음 부팅에 죽은 파일이며, 그것을 영속으로 읽으면 두 집 절이 잡으려는 바로 그
  경우를 PASS시킵니다. `/etc/audit/audit.rules`는 systemd가 없는 호스트에서만 영속 소스입니다.
  각 persisted 봉투의 source는 읽은 파일(들)을 적고, `audit.immutable`의 `winner`는 결정적인
  줄을 담은 파일을 적습니다.
- `audit.immutable` — `setting<bool>`. runtime: `auditctl -s`가 `enabled 2`를 보고. persisted:
  영속 소스에서 적재 순서로 **마지막** `-e` 줄이 `-e 2`(`auditctl(8)`: `-e 2`가 설정되면 재부팅까지
  설정이 잠기고 뒤의 `-e` 줄은 효력이 없으므로, 마지막에 적힌 것이 관리자의 의도).
- `audit.status.enabled`, `audit.status.failure`, `audit.status.lost`,
  `audit.status.backlog_limit` — `int`, `auditctl -s`의 네 필드 그대로, 근거.
- `audit.conf.log_file`, `audit.conf.log_group`, `audit.conf.max_log_file_action`,
  `audit.conf.space_left_action`, `audit.conf.admin_space_left_action`,
  `audit.conf.disk_full_action`, `audit.conf.disk_error_action` — `string`, 값을
  소문자로(`auditd.conf(5)`는 대소문자를 가리지 않고 읽음). 줄이 없는 키는 키 이름을 적은
  `absent`입니다. `auditd.conf(5)`가 각각의 컴파일된 기본값을 문서화하지만 그 기본값은 관리자가 아닌
  데몬의 결정이며 3B의 코어덤프 규칙이 적용됩니다 — muster는 아무도 내리지 않은 결정을 데몬의
  기본값으로 대신하지 않습니다. 예외 하나가 `log_file`입니다. 줄이 없으면 수집기는 문서화된 기본
  경로 `/var/log/audit/audit.log`를 보고 source를 `auditd.conf`에서 `derived`로 적으며, 파일
  자체의 존재가 증거입니다. 경로 문자열에 대한 판정은 없고 그것이 가리키는 파일에 대한 판정만
  있습니다.
- `audit.log_file.*`와 `audit.log_dir.*` — `log_file`이 가리키는 파일과 그 부모 디렉터리의 권한
  leaf 아홉 개씩(`mode, uid, gid, group, group_readable, group_writable, other_readable,
  other_writable, acl_present`). 선언된 stat 패턴 밖의 `log_file`은 C4입니다: 이유에 경로를 적은
  `absent`, 결코 `error`가 아님.
- 상태 규칙(J-1). 호스트에 `auditctl`이 없음: runtime 쪽은 `absent`("auditctl is not
  installed"), 결코 `unsupported`가 아님 — 커널이 아무도 나열할 수 없는 규칙을 갖고 있을 수 있고,
  runtime 쪽이 필요한 컨트롤은 어차피 데몬 설치에 게이트됩니다. `auditctl`은 유효
  `CAP_AUDIT_CONTROL`로 문을 지키므로(`audit_can_control()`) `You must be root to run this
  program.`과 exit 4는 비root 실행에서 `denied`, root 실행에서 `unsupported`("no
  CAP_AUDIT_CONTROL: an unprivileged container")입니다. 커널은 capability를 보기 전에 초기가 아닌
  모든 pid 네임스페이스의 `AUDIT_GET`·`AUDIT_LIST_RULES`를 거부하고, `auditctl`은 그것을 `Error
  sending status request (Operation not permitted)`(또는 `… rule list data request …`)와 exit
  255로 보고합니다: `unsupported`("kernel audit is not reachable from this pid namespace") —
  특권이든 아니든 모든 컨테이너가 그렇게 읽힙니다. init이 아닌 사용자 네임스페이스는
  ECONNREFUSED를 받고 `auditctl -s`는 그것을 삼킵니다(`The audit system is disabled`, exit 0,
  `enabled` 줄 없음): `enabled` 줄 없는 exit 0은 `unsupported`("the kernel gave no audit
  status")이지 결코 값이 아닙니다. `audit support not in kernel` / `Cannot open netlink audit
  socket`(`audit=0`, `CONFIG_AUDIT` 없는 커널)은 `unsupported`. 그 밖의 0 아닌 종료는 `error`.
  `/etc/audit`와 `rules.d`는 두 계열 다 0750 root; `/var/log/audit`는 EL에서 0700 root, Ubuntu에서
  0750 root:adm(Ubuntu 패치의 `log_group = adm`, 로그 파일은 0640 root:adm)이라 adm 그룹 밖의
  비root 실행은 auditd가 있는 호스트에서 모든 영속·권한 leaf를 `denied`로 읽고, auditd가 없는
  호스트에서는 `absent`입니다. capability matrix의 비root 행(§6)을 auditd가 설치된 곳에서만
  assert하는 이유입니다.

### I-4 — `fim` 수집기

선언: stat `/usr/bin/aide`, `/usr/sbin/aide`, `/usr/sbin/tripwire`, `/usr/sbin/samhain`,
`/usr/bin/osqueryd`, `/opt/osquery/bin/osqueryd`, `/usr/sbin/integrit`,
`/var/ossec/bin/wazuh-agentd`, `/var/ossec/bin/ossec-agentd`; 읽기 `/etc/aide/aide.conf`,
`/etc/aide.conf`, `/etc/aide/aide.conf.d/*`(이름만), `/etc/default/aide`,
`/etc/cron.daily/*`(이름과 모드), `/etc/cron.d/*`, `/etc/crontab`; stat `/var/lib/aide/*`; 고정
명령 하나 `systemctl list-timers --all --no-legend --no-pager` — 그 행에는 다음 실행 시각이
있습니다. `cron` 수집기가 쓰는 unit-file 목록은 타이머가 enabled인지를 말하지 무장(armed)됐는지를
말하지 않고, 타깃이 끌어오는 `static` 타이머는 enabled가 아니어도 무장됩니다.

- `fim.tool` — `string`: AIDE 실행파일이 있으면 `aide`; 목록의 실행파일이 하나도 없으면 `none`;
  AIDE가 없고 다른 도구의 실행파일이 하나 이상 있으면 그것들을 이유에 적은 **`absent`**("aide is
  not installed; other tools present: osqueryd (/usr/bin/osqueryd)"). 컨트롤의 mechanisms가
  고르는 leaf가 이것이고, 그 `absent`가 그런 호스트를 MANUAL로 만듭니다(§4) — 이 키의 뜻은 "이
  호스트에서 muster가 모델링하는 파일 무결성 도구"이며 그 호스트엔 도구는 있어도 그것이 없습니다.
- `fim.aide.installed` — `bool`. `fim.aide.config_path` — `string`, `/etc/aide/aide.conf`
  (Debian 계열)와 `/etc/aide.conf`(EL) 중 먼저 존재하는 것; 둘 다 없으면 `absent`.
- `fim.aide.database_path` — `string`: 설정 파일의 `database_in=`(aide ≥ 0.17), 없으면
  `database=`(옛 형식)의 `file:` 값에 `@@define NAME value` 매크로를 `@@{NAME}` 참조에 치환한 것
  (EL9의 `aide.conf`가 쓰고 Ubuntu의 것은 리터럴 경로); 그 밖의 `@@` 지시자(`@@include`,
  `@@x_include`, `@@x_include_setenv`)는 무시; 파일이 정의한 적 없는 매크로 참조는 적힌 대로 두고
  이유에 그렇게 말합니다.
  `fim.aide.database_present` — `bool`, 그 경로의 일반 파일. `fim.aide.database_modified` —
  `string`, 그 mtime을 RFC 3339 UTC로, 근거.
- `fim.aide.schedules` — `list<record>` `{kind, path, armed, detail}`, `kind` ∈ cron_daily |
  cron_d | crontab | timer; `armed`는 그 행이 실제로 돌 것인지, `detail`은 아니라면 왜인지(J-5).
  이름에 `aide`가 들어간 `/etc/cron.daily/` 아래 파일은 실행 비트가 있고(`run-parts`는 나머지를
  건너뜀), `/etc/default/aide`가 `CRON_DAILY_RUN`을 `yes` 아닌 값으로 두지 않았고(파일은 그 줄을
  주석으로 싣고 두 스크립트 모두 기본을 `yes`로 두므로 stock 호스트는 armed), `/run/systemd/system`이
  있으면 곧바로 끝나는 Ubuntu 24.04 shim이 아닐 때(파일 속 그 리터럴로 식별; systemd 호스트에서 그
  행은 `armed: false`, `detail: "runs only without systemd"`) armed입니다. 명령에 `aide`가 있는
  `/etc/cron.d/*` 또는 `/etc/crontab`의 주석 아닌 줄은 armed(주석 처리된 줄은 점검을 끄는 흔한
  방식이라 행이 아님). 이름에 `aide`가 들어간 타이머 — Ubuntu 24.04의 `dailyaidecheck.timer`(패키지가
  enable), EL9의 `aide-check.timer`(배포되나 preset으로 비활성), 관리자 자신의 것 — 는 `systemctl
  list-timers --all`이 다음 실행 시각을 보이고 `CRON_DAILY_RUN` 게이트가 성립할 때 armed(24.04의
  서비스도 같은 파일을 읽음). `fim.aide.scheduled` — `bool`, armed 행이 하나 이상. systemd 없는
  호스트는 cron 행만 싣고, 타이머 목록을 읽을 수 없는 호스트는 두 leaf가 이유를 적은
  `unsupported`입니다.
- `fim.other_tools` — `list<record>` `{name, path}`, 발견된 다른 실행파일 전부.

### I-5 — `pkgverify` 수집기

선언: 명령 `/usr/bin/rpm -Va`와 `/usr/bin/dpkg --verify`(타임아웃 `--verify-timeout`, 각 64
MiB; 어느 것을 돌릴지는 `patch.go`가 정하듯 계열이 정함); 아래 커버리지 계수를 위해
`/var/lib/dpkg/info/*.md5sums`와 `*.list`의 이름만, `path-exclude` glob을 위해
`/etc/dpkg/dpkg.cfg`와 `/etc/dpkg/dpkg.cfg.d/*` 읽기. 수집기는 `--no-verify` 없이 `--deep`이
주어지고 실행이 root일 때만 돕니다(원칙 5): 아니면 아무것도 쓰지 않되, root 없이는
`packages.verify.complete`를 `denied`("package verification needs root: an unprivileged rpm
-Va marks every file it cannot read as untestable")로 씁니다.

- `packages.verify.complete` — `bool`: 명령이 0으로 끝났거나, 파싱된 행이 하나 이상인 채 1로
  끝났고, 출력이 잘리지 않았으면 true. 파싱된 행이 **없는** exit 1은 stderr의 첫 줄들을 담은
  `error` — 잠기거나 깨진 데이터베이스의 `rpm -Va`는 불평을 stderr에 찍고 1로 끝나며 그 밖엔
  아무것도 찍지 않는데, 자기 패키지 데이터베이스를 읽지 못하는 호스트가 무수정으로 PASS해서는
  결코 안 됩니다. 죽은 명령은 `timeout`; 그 밖의 종료 코드는 코드를 적은 `error`; 상한에 닿은 출력은
  상한을 적은 이유와 `truncated: true`를 단 `ok` false이며 deep 게이트가 행 10으로 읽습니다(I-9).
  `packages.verify.tool` — `string`, `rpm` 또는 `dpkg`.
- `packages.verify.modified` — `list<record>` `{path, attributes, file_type}`(`internal`,
  5000행 상한, `subject_kind: file`): 필터 뒤에 남은 행. `attributes`는 달랐던 열의 목록으로,
  도구의 순서대로 이름으로: `rpm(8)`의 아홉 열 `S M 5 D L U G T P`에 대해 `size, mode, digest,
  device, link, user, group, mtime, caps`, `missing` 줄에는 `missing`; `dpkg --verify`는 같은
  아홉 열 형식을 출력하고(`--verify-format rpm`이 유일한 형식) `digest`와, 더는 일반 파일이 아닌
  경로에 `mode`만 채웁니다. 두 도구는 공백 하나가 다릅니다: rpm은 열과 유형 문자 사이에 공백 둘,
  dpkg는 하나(J-4), 그리고 둘 다 괄호 메모를 붙일 수 있습니다 — 호출자가 stat하지 못한 파일의
  ` (Permission denied)`, 정상 아닌 rpm 상태의 ` (not installed)` / ` (replaced)` — 행은 그것을
  `note`에 둡니다. `file_type`은 유형 문자를 단어로(`config, doc, ghost, license, readme,
  artifact` — rpm ≥ 4.14는 `%artifact`에 `a`를 찍음) 또는 빈 문자열; 파서가 모르는 문자(`s`, `m`,
  `n`)는 그 문자 그대로 두고 그것 때문에 행을 버리지 않습니다.
- `packages.verify.modified_config` — 같은 레코드 모양과 민감도, 설정 파일 행(유형 `c`, dpkg의
  conffile도 `c`로 표시됨) — 판정하지 않는 독자용 근거: 바뀐 설정 파일이 곧 운영의 모습입니다.
- `packages.verify.filter` — `list<string>`, 적용한 규칙을 순서대로, 항상 여섯: `config`(유형
  `c` → `modified_config`), `doc`(유형 `d`, `l`, `r`, **또는 `/usr/share/doc/`,
  `/usr/share/man/`, `/usr/share/info/`, `/usr/share/locale/` 아래 경로** → 버림: dpkg에는 문서
  유형 문자가 없고, lab의 `missing` 행 1199개는 전부 최소 설치가 쓴 적 없는 문서였음),
  `dpkg_excluded`(`dpkg.cfg` / `dpkg.cfg.d`의 `path-exclude` glob에 맞는 경로 → 버림: 관리자가
  dpkg에 설치하지 말라고 한 것), `ghost`(유형 `g` → 버림: 배포되지 않는 파일), `mtime_only`(다른
  열이 `T`뿐 → 버림: 내용·모드·소유자가 그대로인 채 touch된 파일), `unverifiable`(다른 열이 없고
  `?`가 하나 이상 → 버림: 도구가 검사할 수 없었음). 상수인데도 목록을 기록하는 것은 나중의 필터
  변경을 스냅샷의 날짜에서 볼 수 있게 하기 위함입니다.
- `packages.verify.filtered_counts` — `record` `{config, doc, dpkg_excluded, ghost, mtime_only,
  unverifiable}`(각 `int`). `packages.verify.stats` — `record` `{lines, exit_code, duration_ms,
  truncated, stderr_head, packages_without_digests, dpkg_path_excludes}`; `stderr_head`는
  stderr의 첫 세 줄(없으면 빈 값); `packages_without_digests`는 dpkg 호스트에서 옆에
  `*.md5sums`가 없는 `/var/lib/dpkg/info/*.list` 파일 수 — `dpkg --verify`가 말없이 검사하지
  못하는 패키지 — 이고 rpm 호스트에선 0; `dpkg_path_excludes`는 `dpkg_excluded` 규칙이 적용한
  glob.
- 아홉 열 형식에도 `missing`에도 맞지 않는 verify 줄은 `stats.lines`에 세고 처음 세 줄을
  `complete`의 이유에 남기되 키를 실패시키지 않습니다(어떤 호스트에서 rpm은 경고를 stdout에 찍음).

### I-6 — 확장 둘

- **`files_sudo`**에 `sudo.log.syslog`(`bool`: 범위 없는 `Defaults` 줄이 `!syslog`로 부정할
  때만 false; `sudoers(5)`에서 이 옵션은 기본 켜짐이고 `syslog=facility` 값은 켠 채로 둠),
  `sudo.log.logfile`(`string`, 범위 없는 `logfile=` 값에서 따옴표를 뗀 것, 없으면 `""`),
  `sudo.defaults.scoped_count`(`int`: `Defaults:user`, `Defaults@host`, `Defaults>runas`,
  `Defaults!command` 줄을 세기만 하고 해석하지 않음 — 범위 지정 기본값은 한 persona를 바꾸고
  leaf는 호스트가 기본으로 무엇을 하는지 말하며, 이 수는 그런 줄이 있음을 독자에게 알림).
  `Defaults` 줄은 따옴표 값을 가진 쉼표 구분 옵션 목록입니다(`Defaults env_reset, !syslog,
  logfile="/var/log/sudo.log"`). 줄은 `/etc/sudoers`와 `@includedir` / `#includedir` 디렉터리의
  모든 파일을 `sudoers(5)`의 순서(사전순, `.`가 들거나 `~`로 끝나는 이름은 건너뜀)로 읽고, 백슬래시
  이어짐을 합치며, 뒤의 줄이 이깁니다. `/etc/sudoers`는 두 계열 다 0440 root이므로(`sudoers.d`는 EL에서
  0750, Debian 계열에서는 릴리스와 이미지에 따라 0755 또는 0750, 그 안의 파일은 0440) 비root 실행은
  세 leaf를 그 읽기의 상태로 읽고(C3) matrix의 비root 행이 그것을 싣습니다.
- **`logging`**에 `logging.rsyslog.forwards_remote`(`bool`: 파싱한 rsyslog 액션 중 원격 대상 —
  `@host`, `@@host`, `:omfwd:`, `action(type="omfwd")`, 파서가 이미 `remote`로 분류하는 것 —
  **의 호스트가 루프백이 아닌 것**(`127.0.0.0/8`, `::1`, `localhost`: 로컬 shipper로의 중계는 그
  자체로는 아무것도 내보내지 않으므로 근거 목록에만 남음)이 하나 이상; rsyslog가 설치되지 않았으면
  false, 그러면 아무것도 전송하지 않으므로; 구현이 syslog-ng("not modelled")나 `none`(sysklogd,
  BusyBox: U-65가 같은 이유로 MANUAL로 읽음)이면 `absent`), `logging.rsyslog.remote_targets`
  (`list<record>` `{rule, target, loopback}`, `internal`, 근거; `rule`은 파서가 남긴 액션 텍스트),
  `logging.journal_upload.url`(`string`, `internal`: `/etc/systemd/journal-upload.conf`와
  `journal-upload.conf.d/*.conf`의 `[Upload]` `URL=`, 뒤가 이기고 적힌 그대로 —
  `systemd-journal-upload(8)`는 호스트명만도 받고 스킴 기본은 https; 파일이나 줄이 없으면 `""` —
  파일 없음은 URL 없음이며 사실이지 기본값이 아님).
- **`services`** 표: `auditd` {`auditd.service`}와 `journal_upload`
  {`systemd-journal-upload.service`}, 둘 다 `provesInstall: true`, 표의 규칙대로 leaf 여덟
  `services.<name>.installed / active / enabled / unit_file_state`(systemd 없으면
  `unsupported`).

### I-7 — 사실이 아닌 것

특정 규칙이 있는지 말하는 `audit.rules.*` leaf는 없고, 데이터베이스가 최신인지 말하는 `fim.*`
leaf는 없으며, 패키지 이름을 적는 `packages.verify.*` leaf는 없습니다. 각각 §8에 있습니다.

## 4. 컨트롤 (I-8)

컨트롤 아홉 개, `category: beyond`, id `muster.beyond.<name>`, 파일은 `controls/beyond/` 아래,
모두 `applies_when: env.container eq none`이 첫 줄. 중요도는 1차 출처에서 매긴 muster 자신의
등급이고 설명이 그 이유를 말합니다.

| id | 중요도 | 자동화 | 추가 게이트 | 판정 | `absent_means` |
|---|---|---|---|---|---|
| `auditd_active` | 상 | auto | — | `services.auditd.installed`, `.active`, `.enabled` 모두 true | fail |
| `audit_rules_loaded` | 상 | auto | `services.auditd.installed eq true` | `audit.rules.present eq true`를 `runtime`과 `persisted`에서 — 손으로 넣은 규칙은 재부팅에 사라지므로 두 집 다 | fail |
| `audit_immutable` | 중 | auto | 같음 | `audit.immutable eq true`를 `runtime`과 `persisted`에서 | fail |
| `audit_disk_actions` | 중 | auto | 같음 | `space_left_action`과 `admin_space_left_action` `in ${allowed_space_actions}`(기본 `[syslog, email, exec, rotate, single, halt]`), `disk_full_action in ${allowed_disk_full_actions}`(기본 `[syslog, rotate, exec, single, halt]`), `disk_error_action in ${allowed_disk_error_actions}`(기본 `[syslog, exec, single, halt]`) — 각 기본값은 `auditd.conf(5)`의 그 키 값 목록에서 `ignore`(기록을 잃고 아무 말도 없음)와 `suspend`(syslog 한 줄 뒤 호스트는 계속 돌면서 기록을 잃음)를 뺀 것; `max_log_file_action in ${allowed_rotate_actions}`(기본 `[rotate, keep_logs, syslog]`) | manual — 줄이 없으면 데몬의 컴파일된 기본값이 정하며 그것은 아무도 고르지 않은 것 |
| `audit_log_permissions` | 중 | auto | 같음 | `audit.log_file.uid eq 0`, `audit.log_file.mode in ${allowed_modes}`(0640의 부분집합), `audit.log_dir.uid eq 0`, `audit.log_dir.mode in ${allowed_dir_modes}`(0750의 부분집합) | manual — 파일이 muster가 읽지 않는 곳에 있거나(C4가 경로를 적음) 쓰인 적이 없음; 둘 다 살펴봐야 하고, 데몬이 도는지는 `auditd_active`가 이미 말함 |
| `remote_log_forwarding` | 하 | auto | — | mechanisms: `logging.rsyslog.forwards_remote eq true` → `services.syslog.active eq true`; `logging.journal_upload.url ne ""` → `services.journal_upload.active eq true`와 `.enabled eq true`(부팅에 실패한 enabled 유닛은 아무것도 보내지 않음); `logging.rsyslog.forwards_remote eq false` → `logging.journal_upload.url ne ""`(실패: 호스트를 떠나는 것이 없음) | manual — syslog-ng나 sysklogd 호스트는 `forwards_remote`가 absent이고 URL이 비어 있어 어느 mechanism도 성립하지 않음 |
| `sudo_logging` | 중 | auto | `sudo.installed eq true` | mechanisms: `sudo.log.syslog eq true` → 그것으로 통과; `sudo.log.syslog eq false` → `sudo.log.logfile matches ^/` | fail |
| `file_integrity_tool` | 중 | auto | — | mechanisms: `fim.tool eq aide` → `fim.aide.database_present eq true`, `fim.aide.scheduled eq true`; `fim.tool eq none` → `fim.tool eq aide`(실패: 도구 없음) | manual — 모델링 안 된 도구만 있는 호스트는 `fim.tool`이 absent라 어느 mechanism도 고르지 않고 MANUAL; 행이 싣는 근거는 `fim.tool` 자체이며 그 이유가 발견된 도구를 적음(평가기는 `when` 사실을 붙이지 `fim.other_tools`를 붙이지 않음) |
| `package_files_unmodified` | 상 | auto | `--deep`(I-9) | `packages.verify.complete eq true`; `packages.verify.modified` `op: none, subject: path, where: {field: path, op: present}` | fail |

mechanism의 모양은 3B의 코어덤프 컨트롤을 따릅니다. 마지막 mechanism의 `when`은 판정되는 모든
호스트에서 성립하고 그 check는 실패하므로 "아무것도 설정 안 됨"은 FAIL입니다. `absent_means`에
닿는 것은 "어느 mechanism도 선택되지 않음"이며, 평가기는 `when` 사실이 absent였든 unsupported였든
그저 false로 평가됐든 그것을 적용합니다 — 메인 §6.5 행 5는 앞의 둘만 말하므로 D30이 구현된 대로
고칩니다. `remote_log_forwarding`의 MANUAL 경로(absent인 `forwards_remote` 옆의 `ok`인 빈
URL)가 셋째에 기대기 때문입니다. 감사 컨트롤의 `runtime` + `persisted` 두 절 모양은 의도된
것이며 한쪽만 있는 호스트를 WARN으로 읽는 §5.3의 `on: both`와 다릅니다. 데몬이 적재한 적 없는
파일 속 규칙도, 다음 부팅이 잊는 적재된 규칙도 여기선 각각 FAIL이고, 설명이 독자가 어느 집을
봐야 하는지 말합니다. 상한에 닿은 `packages.verify.modified` 목록은 워크 목록처럼 ERROR
(`truncated`, exit 2)로 읽히며 설명이 그렇게 말합니다. `audit=0`으로 부팅한 커널은 runtime
컨트롤 둘을 NOT_APPLICABLE(`unsupported`)로 읽습니다. 거기서 울리는 컨트롤은 `auditd_active`
이고(`ConditionKernelCommandLine=!audit=0`이 유닛을 비활성으로 둠) 그 설명이 그렇게 말합니다.

계획이 고정하는 stock 읽기(I-11): **Ubuntu 22.04**, auditd·AIDE 없음 — `auditd_active` FAIL,
감사 세부 컨트롤 넷 NOT_APPLICABLE(게이트), `remote_log_forwarding` FAIL, `sudo_logging` PASS,
`file_integrity_tool` FAIL, `package_files_unmodified`는 공개 이미지에서 PASS(GitHub 러너
VM은 FAIL로 읽히며 그것이 제공자가 손댄 이미지의 진실). **EL9**(Rocky, Alma), auditd 활성,
배포된 `rules.d/audit.rules`(`-D`, `-b`, `-f`, watch·syscall 규칙 없음, `-e` 없음),
`admin_space_left_action`·`disk_full_action`·`disk_error_action` 모두 `SUSPEND` —
`auditd_active` PASS, `audit_rules_loaded` FAIL, `audit_immutable` FAIL, `audit_disk_actions`
FAIL, `audit_log_permissions` PASS(0700 디렉터리, 0600 파일), 나머지는 Ubuntu와 같음. stock
EL9의 FAIL 셋은 사실을 말합니다: 데몬은 돌지만 아무것도 감사하지 않습니다.

커밋된 색인에 auditd 패키지와 서비스, 디스크 처리, 로그 파일·디렉터리의 소유·모드, AIDE
설치·예약, 불변 규칙, 원격 로그 전송의 `references.stig` 항목이 있습니다 — 모든 벤치마크에 모든
규칙이 있는 것은 아닙니다(24.04 색인엔 disk-full 규칙이, 22.04 색인엔 불변 규칙이 없음). 계획의
pre-flight가 3B처럼 색인과 대조해 id를 확정합니다. `references.nist_800_53`: 감사 컨트롤에
AU-2, AU-3, AU-4, AU-5, AU-9, AU-12, 전송에 AU-4(1)/AU-9(2), sudo에 AU-3, 무결성 둘에 SI-7.

## 5. deep 기반 규칙 (I-9, D30)

메인 §6.5의 행 9, 10, 10a는 워크가 실행되지 않았거나, 완료되지 않았거나, 실행될 수 없었을 때
**워크 기반** 컨트롤에 무슨 일이 생기는지 말합니다. 패키지 검증은 같은 이유로 같은 세 상태를
가지므로(`--deep`에서만, root로만 돌고, 타임아웃될 수 있음) 그 행들을 "워크 기반"에서 **deep
기반**으로 넓힙니다: `walk.*` 키나 `packages.verify.*` 키를 참조하는 컨트롤. 완료 사실은 앞쪽에
`walk.complete`, 뒤쪽에 `packages.verify.complete`; 이유 코드는 `walk_incomplete`와
`verify_incomplete`. 행 9–10a를 고정하는 평가기 테스트가 두 번째 계열을 얻고,
`verify_incomplete`는 메인 §7.2의 고정 이유 코드 어휘에 들어가며 JSON·table golden을 그것 때문에
한 번 재생성합니다. D30은 행 5도 구현된 규칙으로 고쳐 씁니다(§4). 이것이 3C-1의 유일한 평가기
변경입니다.

## 6. 환경 (I-10)

- **root.** 전부 답합니다. `auditctl`은 `CAP_AUDIT_CONTROL`이 필요; `rpm -Va` / `dpkg --verify`는
  올린 `--deep` 마감 안에서 `--verify-timeout` 아래 돌고(원칙 5) 소요 시간은
  `packages.verify.stats`에.
- **비root.** auditd가 있는 호스트에서 감사 세부 컨트롤 넷은 거부를 적은 ERROR(규칙 파일,
  `auditd.conf`, `auditctl`, 로그 디렉터리 — 두 계열 다 전부 root 전용); `services.auditd.*`는
  여전히 답함(`systemctl show`); `pkgverify`는 `denied` 완료 키만 씀; `sudo.log.*`는
  `/etc/sudoers` 읽기의 상태. capability matrix의 `nonroot.denied` 행에 `audit.*` 키 34개,
  `packages.verify.complete`, `sudo.log.*` / `sudo.defaults.*` 셋이 추가되고, 그 행이 빠진
  패키지가 아니라 거부에 관한 것이 되도록 CI의 비root 잡이 `auditd`를 설치합니다(I-11). AIDE
  경로는 릴리스에 따릅니다: Ubuntu 22.04에선 읽히지만 EL은 `/etc/aide.conf`를 0600으로,
  `/var/lib/aide`를 0700으로 설치하고 Ubuntu 24.04는 `/var/lib/aide`를 0700 `_aide:root`로 만드므로
  거기서 비root 실행은 `fim.aide.database_*`를 `denied`로, `file_integrity_tool`을 ERROR로
  읽습니다 — K-31이 `protected_*`를 뺐듯 matrix는 그 키들을 어느 쪽으로도 assert하지 않습니다. `journal-upload.conf`와 `cron.daily`는 root 없이 읽힙니다.
- **컨테이너.** 어떤 컨테이너도 `auditctl`에 답하거나 `auditd`를 돌릴 수 없습니다. 커널이 초기가
  아닌 모든 pid 네임스페이스의 audit netlink 요청을 거부하므로(J-1) 특권 init 컨테이너 — CI의 EL
  이미지 — 도 runtime 쪽을 `unsupported`로 읽고 그 `auditd.service`는 등록에 실패합니다
  (`services.auditd.installed` true, `.active` false); 비특권 컨테이너는 capability 게이트를 통해
  `unsupported`; init이 아닌 사용자 네임스페이스는 조용한 ECONNREFUSED를 통해. 어느 것도 capability
  행이 아닙니다: 아홉 컨트롤 모두 컨테이너 게이트로 NOT_APPLICABLE이므로 `container.unsupported`에는
  아무것도 더하지 않고, audit 수집기의 runtime 경로는 러너 VM에서 증명합니다(아래). `pkgverify`는
  컨테이너에서 돌고(패키지 데이터베이스가 거기 있음) CI가 그것으로 파서를 실제 도구와
  비교합니다(I-11).
- **systemd 없음.** `services.auditd.*`와 `services.journal_upload.*`는 표의 규칙대로
  `unsupported`; `fim.aide.schedules`는 cron 행만.
- **계열 차이.** 둘 다 `/usr/sbin/auditctl`이고, 배포되는 `rules.d/audit.rules`는 두 계열 다 같은
  `10-base-config` 텍스트(제어 줄만, `-e` 없음)라 auditd만 설치한 호스트는 어느 계열에서든
  `audit_rules_loaded`와 `audit_immutable`을 FAIL로 읽습니다. AIDE: Debian 계열은 `/usr/bin/aide`와
  `/etc/aide/aide.conf`, EL은 `/usr/sbin/aide`와 `/etc/aide.conf`(0600); 데이터베이스 이름은 설정이
  답함(거기선 `aide.db`, EL은 `@@define`을 거쳐 `aide.db.gz`); Ubuntu 22.04는
  `/etc/cron.daily/aide`, 24.04는 같은 이름의 cron.daily shim 옆에 `dailyaidecheck.timer`, EL9는
  preset으로 비활성인 `aide-check.timer`(J-5). `rpm -Va`는 아홉 열을 채우고 유형 문자를 찍음; `dpkg
  --verify`는 digest 열(과 일반 파일이 아닌 것에 `mode`)을 채우고 conffile을 `c`로 표시. sudo는 두
  계열 다 기본으로 syslog에 기록.
- **lab과 러너.** lab 호스트(Ubuntu 22.04, 커널 5.15, root)에는 auditd도 AIDE도 없어 §4의 stock
  Ubuntu 열, verify 경로(`dpkg --verify`, 10분 20초, 문서 행 1199개 필터), `pkgverify`의 비root
  거부를 증명합니다; 거기에 아무것도 설치하지 않습니다. 감사 컨트롤의 통과 경로는 fixture와 CI가
  증명하며, 이미지가 싣지 않는 것은 계획이 마련합니다(J-2): 러너 VM의 root 잡에서 `apt-get
  install auditd aide aide-common` — auditd가 돌고 `auditctl`이 답하는 유일한 환경 — 과 비root
  잡에서 `auditd`; EL init 컨테이너 둘에서 `dnf install audit aide`로 저하 형태를 증명
  (`services.auditd.installed` true와 `.active` false, runtime 쪽 `unsupported`, 데이터베이스 없는
  `fim.tool` `aide`). examples 워크플로는 아무것도 설치하지 않으므로 커밋되는 VM 예시는 stock 읽기를
  유지하며, 그 `--deep` 실행은 수정된 패키지 파일을 나열할 것이고 거기서
  `package_files_unmodified`의 FAIL은 예상된 것입니다.

## 7. 테스트, CI, 문서 (I-11, I-12)

**I-11 — 3F의 게이트가 게이트입니다.** 모든 컨트롤에 `pass-`·`fail-` fixture와 `na-` fixture
(컨테이너; 게이트된 감사 컨트롤 넷은 "auditd 미설치"도); `audit_disk_actions`,
`remote_log_forwarding`, `file_integrity_tool`에는 `manual-` fixture(빠진 action 줄; syslog-ng
호스트; osquery만 있고 AIDE 없는 호스트). 돌연변이 테스트는 생존 0을 유지하고 동치 돌연변이는
이유와 함께 `_mutants.yaml`로. `controls/testdata/_hosts/` 아래 합성 전체 호스트 스냅샷 둘 —
stock Ubuntu 22.04 읽기와, 새로, stock EL9 읽기 — 가 `hosts_test.go`로 §4의 두 열을 한 번에
고정합니다. 인벤토리 테스트가 강제하는 seed 달린 `Fuzz<Name>` 대상 일곱: 감사 규칙 파서,
`auditd.conf` 파서, `auditctl -s` 리더, verify 출력 파서, sudoers `Defaults` 리더, `aide.conf`
매크로 리더, `journal-upload.conf` 리더. `MUSTER_ORACLE=1` 아래 오라클 쌍 둘: `TestOracleVerify`는 계열의 도구 자체를 돌려(러너 VM과
lab에서 `dpkg --verify`, Rocky·Alma init 이미지에서 `rpm -Va`) 테스트 소유 코드로 파싱하고, 경로
집합이 수집기의 행과 필터 계수를 합한 것과 일치하고 모든 줄이 분류에 닿아야 하며, 패키지
데이터베이스가 있는 호스트에서는 결코 건너뛰지 않습니다. `TestOracleAudit`는 `auditctl -s`의
`enabled`와 `auditctl -l`의 규칙 수를 runtime 리더와 비교하며, `auditctl`이 커널에 닿지 못하는
곳(J-1)에서만 건너뜁니다 — 컨테이너는 그렇고, `auditd`를 설치한 러너 VM은 그래선 안 됩니다. 수집기는 `memAccess`로 present /
absent / denied / truncated 경로를 단위 테스트하고, lab(root와 비root)에서 stock Ubuntu 열에
대해 증명하며, `--deep` 실행의 행 수·필터 계수·소요 시간은 계획의 Execution notes에 기록합니다.

CI(J-2): EL init 잡 둘이 `audit aide`를 설치하고 `jq`로 `services.auditd.installed`가 true로,
`audit.rules.present`의 runtime 쪽이 `unsupported`로, `fim.tool`이 `aide`이고 `database_present`가
false로, `audit_rules_loaded`가 NOT_APPLICABLE로 읽힘을 assert(컨테이너 게이트이지
`unsupported_env`가 아님); 러너 root 잡은 `auditd aide aide-common`을 설치하고 `--deep
--verify-timeout 20m`을 넘겨 `services.auditd.active` true, `audit.rules.present`의 runtime 쪽
`ok`이고 false, `packages.verify.complete` true와 `tool` `dpkg`, `fim.tool` `aide`를 assert하며 그
오라클 단계는 audit·verify 쌍이 비교했음을 요구; 비root 잡은 `auditd`를 설치하고
`packages.verify.complete` `denied`와 `audit.conf.log_file` `denied`를 assert; capability matrix
테스트가 새 행을 덮음; `examples.yml`을 pull request에서 한 번 돌려 예시 파일 여섯을
갱신(제어집합이 바뀌므로 digest 게이트가 아니면 바이트 비교를 건너뜀).

**I-12 — 문서.** 메인 설계에 D30, §6.5의 넓힌 행 9–10a와 고쳐 쓴 행 5, §7.2의
`verify_incomplete`, §8의 플래그 둘, §10.2에 "3C-1 (merged)"와 남은 3C-2 목록 및 W-8을 닫는
문장("인자 고정의 전체 데이터베이스 검증; `CommandTemplate` 없음"). README(양어): 개수 문장 —
"67개 항목에 68개 컨트롤, 그리고 가이드 밖 28개" — 와 로드맵 줄. CHANGELOG Controls(아홉,
`controls/VERSION` → `kisa-unix-2026+2026.09.23`), Collectors(셋, 확장 둘, 표 행 둘),
Tooling(deep 기반 규칙). CONTRIBUTING(양어): 종료 코드가 데이터인 명령에 대한 한 문단.
CLAUDE.md: "Beyond the guide" 아래 두 줄(deep 기반 규칙; `fim.tool`의 `absent`가 뜻하는 것).
`coverage.md` 재생성. 계획은 앞선 계획들처럼 Execution notes를 유지합니다.

## 8. Parked

- 감사 규칙 내용 판정(신원 파일, 시각, 로그인 기록, 모듈, 특권 명령): 3D, CIS 프로파일과
  `references.cis`와 함께.
- 비어 있지 않은 규칙 집합에 대한 `auditctl` 오라클: 러너 VM의 규칙 집합은 배포되는 기본 설정이라
  쌍은 `enabled`와 0인 개수를 비교합니다.
- `sudo.log.input` / `sudo.log.output`의 사실과 판정; 범위 지정 `Defaults`의 해석.
- Tripwire, Samhain, osquery, Wazuh의 자동 판정(I-4의 `fim.other_tools`가 씨앗); AIDE
  데이터베이스의 나이를 `fim.aide.database_modified`로.
- `packages.verify.modified`와 워크 패키지 표의 결합(행마다 소유 패키지; `walk.suid_sgid`와
  교차): 3C-2의 프로세스 → 패키지 결합과 함께.
- journal-remote 수신 측; rsyslog 원격 대상의 TLS 여부.
- 분할된 3C-2: 프로세스 수집기, 노출 교차검사(방화벽 confidence full일 때만), root 등가 경로
  (컨테이너 런타임 소켓과 그룹, `ld.so.preload`, root 유닛의 쓰기 가능한 `ExecStart`, root의
  `PATH`, 워크의 file capability), 네트워크 sysctl, 미배정 stage-3 항목 넷(휴면 계정, `sudoers`
  `NOPASSWD`/`ALL`, 삭제된 실행파일을 돌리는 프로세스, `authorized_keys` 인벤토리).
