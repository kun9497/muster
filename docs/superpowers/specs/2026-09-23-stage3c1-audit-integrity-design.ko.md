# 3C-1 단계 — 감사 파이프라인 상태와 패키지 무결성

*[English](2026-09-23-stage3c1-audit-integrity-design.md) · 한국어*

이 문서는 muster 계획 3C-1의 설계입니다. 메인 설계(`2026-09-02-muster-design.md`, §10.2
"Stage 3")가 "3C 감사 / 노출 / root 등가 경로(그리고 패키지 검증, W-8)"로 남겨 둔 하위
프로젝트의 앞쪽 절반입니다. 2026-09-21에 이 하위 프로젝트를 주제별로 나눴습니다. **3C-1
"무결성"** — 호스트가 자신에게 일어난 일을 기록하는가, 자신의 파일이 바뀌지 않았음을 확인할 수
있는가 — 와 **3C-2 "노출·권한"** — 프로세스 수집기, 소켓 → 프로세스 → 패키지 → 방화벽
교차검사, root 등가 경로, 그리고 3A·3B가 3C로 넘긴 항목(네트워크 sysctl, 워크의 file
capability·ACL)입니다. 이 문서는 3C-1만 다루며 3C-2는 3C-1이 병합된 뒤 별도 설계를 갖습니다.
결정은 I-1 … I-12로 번호를 붙이고 계획을 구속합니다. 여기의 모든 점검은 1차 출처 —
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
표의 새 행 둘(`auditd`, `journal_upload`)로 먹입니다. 3C-1 뒤 제어집합은 컨트롤 96개(67개
항목의 68개는 그대로, 가이드 밖 28개), `controls/VERSION`은 `kisa-unix-2026+2026.09.23`,
`schema_version`은 그대로입니다(키와 레코드 필드를 더할 뿐 바꾸지 않음. 메인 §5.7).

범위 밖(계획이 흘러가지 않도록 이름을 적음): 3C-2의 전부(위); 호스트가 어떤 감사 규칙을
가져야 하는지 판정하는 것(그것은 벤치마크의 표이며 `references.cis`를 달 수 있는 3D의 CIS
프로파일 몫); AIDE 외 도구의 자동 판정; AIDE 데이터베이스의 최신성; verify 행과 워크의 패키지
표 결합(두 도구는 패키지 이름을 출력하지 않고, 결합은 3C-2의 프로세스 → 패키지 작업과 함께 옴);
sudo 세션 기록(`log_input`, `log_output`)의 판정; 원격 로그 경로의 암호화 여부. 메인 설계가
감사 파이프라인 상태 아래 적은 "journald 영속"은 여기서 컨트롤이 **아닙니다**. U-65
(`syslog_policy`)가 journald-only 호스트에서 그것을, rsyslog 호스트에서 파일 영속을 이미
판정하므로 두 번째 컨트롤은 다른 id 아래 같은 판정일 뿐입니다.

## 2. 3B에서 이어받은 원칙

1. **판정은 실행 중인 상태를 읽고, 영속 파일은 근거이자 "재부팅 뒤에도 남는가"의 답입니다.**
   감사 데몬의 규칙과 불변 플래그는 두 집 setting입니다. runtime 쪽은 `auditctl -l` /
   `auditctl -s`(인자 고정, root), persisted 쪽은 규칙 파일, `default_on: effective`이며
   effective는 3B의 sysctl처럼 runtime의 복사본입니다(K-3).
2. **명령은 인자가 고정이고 종료 코드는 데이터입니다.** `rpm -Va`와 `dpkg --verify`는 "무언가
   다르다"를 1로 말합니다 — `patch` 수집기가 `dnf check-update`의 100과 `needs-restarting`의 1을
   이미 그렇게 읽습니다. `auditctl`은 권한이 없을 때와 커널이 답하지 않을 때 1로 끝나며 둘은
   stderr로 구분합니다(I-3). 그 밖의 코드는 명령과 코드를 적은 `error`.
3. **데몬 설정이 가리키는 경로는 그 데몬의 수집기 몫입니다**(C1): `auditd.conf`의 `log_file`,
   `aide.conf`의 `database_in`. 권한 사실은 `writePermFacts`가 쓰는 아홉 leaf뿐입니다.
4. **노이즈는 걸러내고 필터는 사실입니다.** verify 출력에서 무엇이 어떤 규칙으로 몇 행 빠졌는지가
   스냅샷에 있습니다. 필터를 되읽을 수 없는 PASS는 누구도 검증할 수 없는 PASS입니다.
5. **모든 beyond 컨트롤은 `env.container eq none`으로 게이트됩니다.** 컨트롤 하나가 `--deep`에
   의존합니다. `--deep` 없는 실행은 워크가 `walk.*`를 두듯 `packages.verify.*` 키를 쓰지 않고,
   그 컨트롤은 I-9의 규칙으로 MANUAL("run collect --deep")로 읽힙니다. root 없이는
   `walk.complete`처럼 `packages.verify.complete`가 `denied`이고 나머지는 쓰지 않습니다.
6. **모든 파서는 fuzz하고, 데몬이 답할 수 있으면 데몬과 비교합니다.** 새 파서 셋(감사 규칙,
   `auditd.conf`, verify 출력)과 작은 셋(sudoers `Defaults`, `aide.conf` 매크로,
   `journal-upload.conf`)이 각각 seed 달린 `Fuzz<Name>` 대상을 갖고, verify 파서는 CI 컨테이너
   안에서 실제 `rpm -Va`·`dpkg --verify` 출력과 비교합니다(I-11).

## 3. 사실과 수집기 (I-3 … I-7)

레지스트리 키 66개: `audit.*` 34, `fim.*` 9, `packages.verify.*` 7, `sudo.*` 5, `logging.*` 3,
`services.*` 8. 달리 말하지 않으면 민감도는 `public`. 모든 목록은 정렬되고 상한이 있으며 상한에
닿으면 그 키에 `truncated: true`.

### I-3 — `audit` 수집기

선언: 읽기 `/etc/audit/auditd.conf`, `/etc/audit/audit.rules`, `/etc/audit/rules.d/*.rules`
(Glob), stat 전용 `/var/log/audit`, `/var/log/audit/*`, `/var/log/*`; 명령
`/usr/sbin/auditctl -l`과 `/usr/sbin/auditctl -s`(각 5초, 1 MiB. EL9의 `/sbin`은 `usr/sbin`
링크라 한 경로가 두 계열을 다 섬김).

- `audit.rules.present` — `setting<bool>`. runtime: `auditctl -l`이 규칙 줄을 하나 이상
  출력("No rules"는 false). persisted: 영속 소스에 규칙 줄(`-w`, `-a`, `-A`)이 하나 이상.
  `audit.rules.loaded_count`와 `audit.rules.persisted_count`는 두 개수(`int`), 근거.
  `audit.rules`는 `list<record>` `{file, line, kind, key, text}`(`internal`; `kind` ∈ watch |
  syscall | control | other; `key`는 `-k`/`key=` 값 또는 빈 문자열; 2000행 상한), 읽은 그대로의
  영속 규칙을 적재 순서로.
- **영속 소스는 `augenrules(8)`를 모델링합니다.** `/etc/audit/rules.d/`에 `*.rules` 파일이 하나
  이상 있으면 영속 답은 그것들을 C 로케일 사전순으로 연결한 것입니다(`augenrules --load`가 데몬
  시작 시 `audit.rules`에 쓰는 것이 그것이므로 생성된 `audit.rules`를 두 번 읽지 않음); 하나도
  없으면 `/etc/audit/audit.rules` 자체가 소스입니다. 각 persisted 봉투의 source는 읽은 파일(들)을
  적고, `audit.immutable`의 `winner`는 결정적인 줄을 담은 파일을 적습니다.
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
  경로 `/var/log/audit/audit.log`를 보고 source를 `default`로 적으며, 파일 자체의 존재가 증거입니다.
  경로 문자열에 대한 판정은 없고 그것이 가리키는 파일에 대한 판정만 있습니다.
- `audit.log_file.*`와 `audit.log_dir.*` — `log_file`이 가리키는 파일과 그 부모 디렉터리의 권한
  leaf 아홉 개씩(`mode, uid, gid, group, group_readable, group_writable, other_readable,
  other_writable, acl_present`). 선언된 stat 패턴 밖의 `log_file`은 C4입니다: 이유에 경로를 적은
  `absent`, 결코 `error`가 아님.
- 상태 규칙. 호스트에 `auditctl`이 없음: runtime 쪽은 `absent`("auditctl is not installed"),
  결코 `unsupported`가 아님 — 커널이 아무도 나열할 수 없는 규칙을 갖고 있을 수 있고, runtime 쪽이
  필요한 컨트롤은 어차피 데몬 설치에 게이트됩니다. `auditctl`이 stderr에 `Operation not
  permitted`를 내고 1로 끝남: 비root 실행이면 `denied`, root면 `unsupported`("kernel audit is
  not reachable from this environment") — 컨테이너의 audit netlink 소켓이 그렇게 답합니다;
  `Connection refused` 또는 `audit support not in kernel`: `unsupported`. `/etc/audit`는 두
  계열 다 0750 root이고 `/var/log/audit`는 0700이라 비root 실행은 모든 영속·권한 leaf를
  `denied`로 읽습니다.

### I-4 — `fim` 수집기

선언: stat `/usr/bin/aide`, `/usr/sbin/aide`, `/usr/sbin/tripwire`, `/usr/sbin/samhain`,
`/usr/bin/osqueryd`, `/opt/osquery/bin/osqueryd`, `/usr/sbin/integrit`,
`/var/ossec/bin/wazuh-agentd`, `/var/ossec/bin/ossec-agentd`; 읽기 `/etc/aide/aide.conf`,
`/etc/aide.conf`, `/etc/aide/aide.conf.d/*`(이름만), `/etc/cron.daily/*`(이름과 모드),
`/etc/cron.d/*`, `/etc/crontab`; stat `/var/lib/aide/*`; `cron` 수집기가 이미 선언한 고정 타이머
목록 명령(`systemctl list-unit-files --type=timer --no-legend --no-pager`)을 여기서 다시
선언해 어느 수집기도 다른 쪽의 순서에 의존하지 않게 합니다.

- `fim.tool` — `string`: AIDE 실행파일이 있으면 `aide`; 목록의 실행파일이 하나도 없으면 `none`;
  AIDE가 없고 다른 도구의 실행파일이 하나 이상 있으면 그것들을 이유에 적은 **`absent`**("aide is
  not installed; other tools present: osqueryd (/usr/bin/osqueryd)"). 컨트롤의 mechanisms가
  고르는 leaf가 이것이고, 그 `absent`가 그런 호스트를 근거 첨부 MANUAL로 만듭니다(§4) — 이 키의
  뜻은 "이 호스트에서 muster가 모델링하는 파일 무결성 도구"이며 그 호스트엔 도구는 있어도 그것이
  없습니다.
- `fim.aide.installed` — `bool`. `fim.aide.config_path` — `string`, `/etc/aide/aide.conf`
  (Debian 계열)와 `/etc/aide.conf`(EL) 중 먼저 존재하는 것; 둘 다 없으면 `absent`.
- `fim.aide.database_path` — `string`: 설정 파일의 `database_in=`(aide ≥ 0.17), 없으면
  `database=`(옛 형식)의 `file:` 값에 `@@define NAME value` 매크로를 `@@{NAME}` 참조에 치환한 것;
  파일이 정의한 적 없는 매크로 참조는 적힌 대로 두고 이유에 그렇게 말합니다.
  `fim.aide.database_present` — `bool`, 그 경로의 일반 파일. `fim.aide.database_modified` —
  `string`, 그 mtime을 RFC 3339 UTC로, 근거.
- `fim.aide.schedules` — `list<record>` `{kind, path, enabled}`, `kind` ∈ cron_daily | cron_d |
  crontab | timer: 이름에 `aide`가 들어간 `/etc/cron.daily/` 아래 실행 파일(`run-parts`는 실행
  비트 없는 파일을 건너뛰므로 `enabled`는 그 비트); 명령에 `aide`가 있는 `/etc/cron.d/*` 또는
  `/etc/crontab`의 줄(`enabled` true, 파일이 곧 스케줄); 이름에 `aide`가 들어간 타이머 유닛
  (Ubuntu 24.04의 `dailyaidecheck.timer`, 관리자의 `aidecheck.timer`; `enabled`는 unit-file
  상태). `fim.aide.scheduled` — `bool`, `enabled` true인 행이 하나 이상. 타이머 목록이 없는
  호스트(no systemd)는 cron 행만 싣습니다.
- `fim.other_tools` — `list<record>` `{name, path}`, 발견된 다른 실행파일 전부.

### I-5 — `pkgverify` 수집기

선언: 명령 `/usr/bin/rpm -Va`와 `/usr/bin/dpkg --verify`(각 10분, 64 MiB; 어느 것을 돌릴지는
`patch.go`가 정하듯 계열이 정함); 아래 커버리지 계수를 위해 `/var/lib/dpkg/info/*.md5sums`와
`*.list`의 이름만 읽기. 수집기는 `--deep`이 주어지고 실행이 root일 때만 돕니다(원칙 5):
`--deep` 없이는 아무것도 쓰지 않고, root 없이는 `packages.verify.complete`를 `denied`("package
verification needs root: an unprivileged rpm -Va marks every file it cannot read as
untestable")로 쓰고 나머지는 쓰지 않습니다.

- `packages.verify.complete` — `bool`: 명령이 0 또는 1로 끝나고 출력이 잘리지 않았으면 true;
  아니면 이유와 함께 false(명령이 죽으면 `timeout`, 코드를 적은 `error`, 출력이 상한에 닿으면
  `truncated` — 뒤의 둘은 `ok: false`가 아니라 봉투 자체의 상태). `packages.verify.tool` —
  `string`, `rpm` 또는 `dpkg`.
- `packages.verify.modified` — `list<record>` `{path, attributes, file_type}`(`internal`,
  5000행 상한, `subject_kind: file`): 필터 뒤에 남은 행. `attributes`는 달랐던 열의 목록으로,
  도구의 순서대로 이름으로: `rpm(8)`의 아홉 열 `S M 5 D L U G T P`에 대해 `size, mode, digest,
  device, link, user, group, mtime, caps`, `missing` 줄에는 `missing`; `dpkg --verify`는 같은
  아홉 열 형식을 출력하고(`--verify-format rpm`이 유일한 형식) `digest`만 채울 수 있어 그 행은
  `digest` 또는 `missing`을 갖습니다. `file_type`은 유형 문자를 단어로(`config, doc, ghost,
  license, readme`) 또는 빈 문자열.
- `packages.verify.modified_config` — 같은 레코드 모양, 설정 파일 행(유형 `c`, dpkg의
  conffile도 `c`로 표시됨) — 판정하지 않는 독자용 근거: 바뀐 설정 파일이 곧 운영의 모습입니다.
- `packages.verify.filter` — `list<string>`, 적용한 규칙을 순서대로, 항상 다섯: `config`(유형
  `c` → `modified_config`), `doc`(유형 `d`, `l`, `r` → 버림), `ghost`(유형 `g` → 버림: 배포되지
  않는 파일), `mtime_only`(다른 열이 `T`뿐 → 버림: 내용·모드·소유자가 그대로인 채 touch된 파일),
  `unverifiable`(다른 열이 없고 `?`가 하나 이상 → 버림: rpm이 검사할 수 없었음). 상수인데도 목록을
  기록하는 것은 나중의 필터 변경을 스냅샷의 날짜에서 볼 수 있게 하기 위함입니다.
- `packages.verify.filtered_counts` — `record` `{config, doc, ghost, mtime_only,
  unverifiable}`(각 `int`). `packages.verify.stats` — `record` `{lines, exit_code, duration_ms,
  truncated, packages_without_digests}`; 마지막은 dpkg 호스트에서 옆에 `*.md5sums`가 없는
  `/var/lib/dpkg/info/*.list` 파일 수 — `dpkg --verify`가 말없이 검사하지 못하는 패키지 — 이고
  rpm 호스트에선 0.
- 아홉 열 형식에도 `missing`에도 맞지 않는 verify 줄은 `stats.lines`에 세고 처음 세 줄을
  `complete`의 이유에 남기되 키를 실패시키지 않습니다(어떤 호스트에서 rpm은 경고를 stdout에 찍음).

### I-6 — 확장 둘

- **`files_sudo`**에 `sudo.log.syslog`(`bool`: 범위 없는 `Defaults` 줄이 `!syslog`로 부정할
  때만 false; `sudoers(5)`에서 이 옵션은 기본 켜짐이고 `syslog=facility` 값은 켠 채로 둠),
  `sudo.log.logfile`(`string`, 범위 없는 `logfile=` 값에서 따옴표를 뗀 것, 없으면 `""`),
  `sudo.log.input`과 `sudo.log.output`(`bool`, `log_input` / `log_output`),
  `sudo.defaults.scoped_count`(`int`: `Defaults:user`, `Defaults@host`, `Defaults>runas`,
  `Defaults!command` 줄을 세기만 하고 해석하지 않음 — 범위 지정 기본값은 한 persona를 바꾸고 leaf는
  호스트가 기본으로 무엇을 하는지 말함). 줄은 `/etc/sudoers`와 `@includedir` 디렉터리의 모든
  파일을 `sudoers(5)`의 순서(사전순, `.`나 `~`가 든 이름은 건너뜀)로 읽고, 백슬래시 이어짐을
  합치며, 뒤의 줄이 이깁니다; `/etc/sudoers.d`는 두 계열 다 0750 root라 비root 실행은 다섯 leaf를
  그 읽기의 상태로 읽습니다(C3).
- **`logging`**에 `logging.rsyslog.forwards_remote`(`bool`: 파싱한 rsyslog 액션 중 원격 대상 —
  `@host`, `@@host`, `:omfwd:`, `action(type="omfwd")`, 파서가 이미 `remote`로 분류하는 것 — 이
  하나 이상; rsyslog가 설치되지 않았으면 false, 그러면 아무것도 전송하지 않으므로; 구현이
  syslog-ng이면 `absent`("syslog-ng is not modelled")), `logging.rsyslog.remote_targets`
  (`list<record>` `{file, line, target}`, `internal`, 근거), `logging.journal_upload.url`
  (`string`, `internal`: `/etc/systemd/journal-upload.conf`와 `journal-upload.conf.d/*.conf`의
  `[Upload]` `URL=`, 뒤가 이김; 파일이나 줄이 없으면 `""` — 파일 없음은 URL 없음이며 사실이지
  기본값이 아님).
- **`services`** 표: `auditd` {`auditd.service`}와 `journal_upload`
  {`systemd-journal-upload.service`}, 둘 다 `provesInstall: true`, 표의 규칙대로 leaf 여덟
  `services.<name>.installed / active / enabled / unit_file_state`(systemd 없으면
  `unsupported`).

### I-7 — 사실이 아닌 것

특정 규칙이 있는지 말하는 `audit.rules.*` leaf는 없고, 데이터베이스가 최신인지 말하는 `fim.*`
leaf는 없으며, 패키지 이름을 적는 `packages.verify.*` leaf는 없습니다. 각각 §7에 있습니다.

## 4. 컨트롤 (I-8)

컨트롤 아홉 개, `category: beyond`, id `muster.beyond.<name>`, 파일은 `controls/beyond/` 아래,
모두 `applies_when: env.container eq none`이 첫 줄. 중요도는 1차 출처에서 매긴 muster 자신의
등급이고 설명이 그 이유를 말합니다.

| id | 중요도 | 자동화 | 추가 게이트 | 판정 | `absent_means` |
|---|---|---|---|---|---|
| `auditd_active` | 상 | auto | — | `services.auditd.installed`, `.active`, `.enabled` 모두 true | fail |
| `audit_rules_loaded` | 상 | auto | `services.auditd.installed eq true` | `audit.rules.present eq true`를 `runtime`과 `persisted`에서 — 손으로 넣은 규칙은 재부팅에 사라지므로 두 집 다 | fail |
| `audit_immutable` | 중 | auto | 같음 | `audit.immutable eq true`를 `runtime`과 `persisted`에서 | fail |
| `audit_disk_actions` | 중 | auto | 같음 | `space_left_action`, `admin_space_left_action`, `disk_full_action`, `disk_error_action` 각각 `in ${allowed_actions}`(기본 `[syslog, email, exec, rotate, single, halt]` — `ignore`와 `suspend`는 아무에게도 알리지 않고 기록을 버림); `max_log_file_action in ${allowed_rotate_actions}`(기본 `[rotate, keep_logs, syslog]`) | manual — 줄이 없으면 데몬의 컴파일된 기본값이 정하며 그것은 아무도 고르지 않은 것 |
| `audit_log_permissions` | 중 | auto | 같음 | `audit.log_file.uid eq 0`, `audit.log_file.mode in ${allowed_modes}`(0640의 부분집합), `audit.log_dir.uid eq 0`, `audit.log_dir.mode in ${allowed_dir_modes}`(0750의 부분집합) | manual — 파일이 muster가 읽지 않는 곳에 있거나(C4가 경로를 적음) 쓰인 적이 없음; 둘 다 살펴봐야 하고, 데몬이 도는지는 `auditd_active`가 이미 말함 |
| `remote_log_forwarding` | 하 | auto | — | mechanisms: `logging.rsyslog.forwards_remote eq true` → `services.syslog.active eq true`; `logging.journal_upload.url matches ^https?://` → `services.journal_upload.enabled eq true`; `logging.rsyslog.forwards_remote eq false` → `logging.journal_upload.url matches ^https?://`(실패: 호스트를 떠나는 것이 없음) | manual — syslog-ng 호스트는 어느 mechanism도 고르지 않음 |
| `sudo_logging` | 중 | auto | `sudo.installed eq true` | mechanisms: `sudo.log.syslog eq true` → 그것으로 통과; `sudo.log.syslog eq false` → `sudo.log.logfile matches ^/` | fail |
| `file_integrity_tool` | 중 | auto | — | mechanisms: `fim.tool eq aide` → `fim.aide.database_present eq true`, `fim.aide.scheduled eq true`; `fim.tool eq none` → `fim.tool eq aide`(실패: 도구 없음) | manual — 모델링 안 된 도구만 있는 호스트는 `fim.tool`이 absent라 어느 mechanism도 고르지 않고 `fim.other_tools`를 근거로 MANUAL |
| `package_files_unmodified` | 상 | auto | `--deep`(I-9) | `packages.verify.complete eq true`; `packages.verify.modified` `op: none, subject: path, where: {field: path, op: present}` | fail |

mechanism의 모양은 3B의 코어덤프 컨트롤을 따릅니다. 마지막 mechanism의 `when`은 판정되는 모든
호스트에서 성립하고 그 check는 실패하므로 "아무것도 설정 안 됨"은 FAIL이고, 고르는 사실이 정말
`absent`인 호스트만 `absent_means`에 닿습니다.

계획이 고정하는 stock 읽기(I-11): **Ubuntu 22.04**, auditd·AIDE 없음 — `auditd_active` FAIL,
감사 세부 컨트롤 넷 NOT_APPLICABLE(게이트), `remote_log_forwarding` FAIL, `sudo_logging` PASS,
`file_integrity_tool` FAIL, `package_files_unmodified`는 공개 이미지에서 PASS(GitHub 러너
VM은 FAIL로 읽히며 그것이 제공자가 손댄 이미지의 진실). **EL9**(Rocky, Alma), auditd 활성,
배포된 `rules.d/audit.rules`(`-D`, `-b`, `-f`, watch·syscall 규칙 없음, `-e` 없음),
`admin_space_left_action = SUSPEND`, `disk_full_action = SUSPEND` — `auditd_active` PASS,
`audit_rules_loaded` FAIL, `audit_immutable` FAIL, `audit_disk_actions` FAIL,
`audit_log_permissions` PASS(0700 디렉터리, 0600 파일), 나머지는 Ubuntu와 같음. stock EL9의
FAIL 셋은 사실을 말합니다: 데몬은 돌지만 아무것도 감사하지 않습니다.

커밋된 색인에 auditd 패키지와 서비스, 디스크 처리 넷, 로그 파일·디렉터리의 소유·모드, AIDE
설치·예약, 원격 로그 전송의 `references.stig` 항목이 다섯 벤치마크 모두에 있습니다. 계획의
pre-flight가 3B처럼 색인과 대조해 id를 확정합니다. `references.nist_800_53`: 감사 컨트롤에
AU-2, AU-3, AU-4, AU-5, AU-9, AU-12, 전송에 AU-4(1)/AU-9(2), sudo에 AU-3, 무결성 둘에 SI-7.

## 5. deep 기반 규칙 (I-9, D30)

메인 §6.5의 행 9, 10, 10a는 워크가 실행되지 않았거나, 완료되지 않았거나, 실행될 수 없었을 때
**워크 기반** 컨트롤에 무슨 일이 생기는지 말합니다. 패키지 검증은 같은 이유로 같은 세 상태를
가지므로(`--deep`에서만, root로만 돌고, 타임아웃될 수 있음) 그 행들을 "워크 기반"에서 **deep
기반**으로 넓힙니다: `walk.*` 키나 `packages.verify.*` 키를 참조하는 컨트롤. 완료 사실은 앞쪽에
`walk.complete`, 뒤쪽에 `packages.verify.complete`; 이유 코드는 `walk_incomplete`와
`verify_incomplete`. 행 9–10a를 고정하는 평가기 테스트가 두 번째 계열을 얻습니다. 이것이 메인
설계의 D30이며 3C-1의 유일한 평가기 변경입니다.

## 6. 환경 (I-10)

- **root.** 전부 답합니다. `auditctl`은 `CAP_AUDIT_CONTROL`이 필요; `rpm -Va` / `dpkg --verify`는
  `--deep` 타임아웃(예산 + 5분) 안에서 돌고 소요 시간은 `packages.verify.stats`에.
- **비root.** 감사 세부 컨트롤 넷은 거부를 적은 ERROR(규칙 파일, `auditd.conf`, `auditctl`, 로그
  디렉터리 — 두 계열 다 전부 root 전용); `services.auditd.*`는 여전히 답함(`systemctl show`);
  `pkgverify`는 `denied` 완료 키만 씀; `sudoers.d`를 나열할 수 없으면 `sudo.log.*`는 그 읽기의
  상태. capability matrix의 `nonroot.denied` 행에 `audit.*` 키 34개, `packages.verify.complete`,
  `sudo.log.*` / `sudo.defaults.*` 다섯이 추가됩니다. AIDE 경로, `journal-upload.conf`,
  `cron.daily`는 root 없이 읽힙니다.
- **컨테이너.** 커널 감사는 네임스페이스가 없습니다. `auditctl`은 `Operation not permitted`
  또는 `Connection refused`로 답하고 runtime 쪽은 `unsupported`; 어쨌든 아홉 컨트롤 모두
  컨테이너 게이트로 NOT_APPLICABLE. `pkgverify`는 컨테이너에서 돌 수 있고(패키지 데이터베이스가
  거기 있음) CI가 그것으로 파서를 실제 도구와 비교합니다(I-11). `container.unsupported`에
  `audit.rules.present`, `audit.immutable`, `audit.status.*` 넷이 추가됩니다.
- **systemd 없음.** `services.auditd.*`와 `services.journal_upload.*`는 표의 규칙대로
  `unsupported`; `fim.aide.schedules`는 cron 행만.
- **계열 차이.** 둘 다 `/usr/sbin/auditctl`. AIDE: Debian 계열은 `/usr/bin/aide`와
  `/etc/aide/aide.conf`, EL은 `/usr/sbin/aide`와 `/etc/aide.conf`; 데이터베이스 이름은 설정이
  답함(거기선 `aide.db`, EL은 `aide.db.gz`); Ubuntu 22.04는 `/etc/cron.daily/aide`, 24.04는 같은
  이름의 cron.daily 스크립트 옆에 `dailyaidecheck.timer`, EL은 스케줄을 싣지 않음. `rpm -Va`는
  아홉 열을 채우고 유형 문자를 찍음; `dpkg --verify`는 digest 열만 채우고 conffile을 `c`로 표시.
  sudo는 두 계열 다 기본으로 syslog에 기록.
- **lab과 러너.** lab 호스트(Ubuntu 22.04, 커널 5.15, root)에는 auditd도 AIDE도 없어 §4의 stock
  Ubuntu 열과 비root 열을 증명합니다; 감사 컨트롤의 통과 경로는 fixture와 CI의 EL init 컨테이너가
  증명하며, 거기서 `services.auditd.active`는 true이고 세부 컨트롤은 컨테이너 게이트로
  NOT_APPLICABLE — 따라서 `audit.rules.present`와 `audit.immutable`의 EL runtime 쪽은 fixture로만
  덮이고 §7이 그렇게 말합니다. 러너 VM의 `--deep` 실행은 수정된 패키지 파일을 나열할 것이고 예시
  스냅샷의 `package_files_unmodified` FAIL은 예상된 것입니다.

## 7. 테스트, CI, 문서 (I-11, I-12)

**I-11 — 3F의 게이트가 게이트입니다.** 모든 컨트롤에 `pass-`·`fail-` fixture와 `na-` fixture
(컨테이너; 게이트된 감사 컨트롤 넷은 "auditd 미설치"도); `audit_disk_actions`,
`remote_log_forwarding`, `file_integrity_tool`에는 `manual-` fixture(빠진 action 줄; syslog-ng
호스트; osquery만 있고 AIDE 없는 호스트). 돌연변이 테스트는 생존 0을 유지하고 동치 돌연변이는
이유와 함께 `_mutants.yaml`로. `controls/testdata/_hosts/` 아래 합성 전체 호스트 스냅샷 둘 —
stock Ubuntu 22.04 읽기와, 새로, stock EL9 읽기 — 가 `hosts_test.go`로 §4의 두 열을 한 번에
고정합니다. 인벤토리 테스트가 강제하는 seed 달린 `Fuzz<Name>` 대상 여섯: 감사 규칙 파서,
`auditd.conf` 파서, verify 출력 파서, sudoers `Defaults` 리더, `aide.conf` 매크로 리더,
`journal-upload.conf` 리더. `MUSTER_ORACLE=1` 아래 오라클 쌍 둘, 둘 다 lab이 아닌 CI 컨테이너에서:
Rocky·Alma init 이미지에서 verify 파서 대 `rpm -Va`, Ubuntu 이미지에서 `dpkg --verify` — 줄 수와
경로 집합이 일치하고 모든 줄이 분류에 닿아야 합니다. `auditctl -l` 오라클은 `auditctl`이 커널에
닿지 못하는 곳에선 돌 수 없어 parked(§8). 수집기는 `memAccess`로 present / absent / denied /
truncated 경로를 단위 테스트하고, lab(root와 비root)에서 stock Ubuntu 열에 대해 증명하며,
`--deep` 실행의 행 수·필터 계수·소요 시간은 계획의 Execution notes에 기록합니다.

CI: EL init 잡 둘이 `jq`로 `services.auditd.active`가 true로, `audit_rules_loaded`가
NOT_APPLICABLE로 읽힘을 assert(`unsupported_env`가 코드가 아님 — 게이트가 코드); 러너 root 잡은
이미 워크를 위해 `--deep`을 넘기고 이제 `packages.verify.*`도 만들어 `complete` true와 `tool`
`dpkg`를 assert; 비root 잡은 `packages.verify.complete` `denied`와 `audit.conf.log_file`
`denied`를 assert; capability matrix 테스트가 새 행을 덮음; `examples.yml`을 pull request에서 한
번 돌려 예시 파일 여섯을 갱신(제어집합이 바뀌므로 digest 게이트가 아니면 바이트 비교를 건너뜀).

**I-12 — 문서.** 메인 설계에 D30, §6.5의 넓힌 행 9–10a, §10.2에 "3C-1 (merged)"와 남은 3C-2
목록 및 W-8을 닫는 문장("인자 고정의 전체 데이터베이스 검증; `CommandTemplate` 없음"). README
(양어): 개수 문장 — "67개 항목에 68개 컨트롤, 그리고 가이드 밖 28개" — 와 로드맵 줄. CHANGELOG
Controls(아홉, `controls/VERSION` → `kisa-unix-2026+2026.09.23`), Collectors(셋, 확장 둘, 표 행
둘), Tooling(deep 기반 규칙). CONTRIBUTING(양어): 종료 코드가 데이터인 명령에 대한 한 문단.
CLAUDE.md: "Beyond the guide" 아래 두 줄(deep 기반 규칙; `fim.tool`의 `absent`가 뜻하는 것).
`coverage.md` 재생성. 계획은 앞선 계획들처럼 Execution notes를 유지합니다.

## 8. Parked

- 감사 규칙 내용 판정(신원 파일, 시각, 로그인 기록, 모듈, 특권 명령): 3D, CIS 프로파일과
  `references.cis`와 함께.
- `auditctl -l` 오라클: auditd가 있는 VM이 필요; 러너 root 잡이 그것을 위해 `auditd`를 설치할지
  (러너 VM의 패키지, 이미지 변경 없음)는 계획 pre-flight의 결정.
- Tripwire, Samhain, osquery, Wazuh의 자동 판정(I-4의 `fim.other_tools`가 씨앗); AIDE
  데이터베이스의 나이를 `fim.aide.database_modified`로.
- `packages.verify.modified`와 워크 패키지 표의 결합(행마다 소유 패키지; `walk.suid_sgid`와
  교차): 3C-2의 프로세스 → 패키지 결합과 함께.
- `sudo.log.input` / `sudo.log.output`의 판정; 범위 지정 `Defaults`의 해석.
- journal-remote 수신 측; rsyslog 원격 대상의 TLS 여부.
- 분할된 3C-2: 프로세스 수집기, 노출 교차검사(방화벽 confidence full일 때만), root 등가 경로
  (컨테이너 런타임 소켓과 그룹, `ld.so.preload`, root 유닛의 쓰기 가능한 `ExecStart`, root의
  `PATH`, 워크의 file capability), 네트워크 sysctl, 미배정 stage-3 항목 넷(휴면 계정, `sudoers`
  `NOPASSWD`/`ALL`, 삭제된 실행파일을 돌리는 프로세스, `authorized_keys` 인벤토리).
