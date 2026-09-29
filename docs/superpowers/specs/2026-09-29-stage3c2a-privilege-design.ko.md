# Stage 3C-2a — privilege: root가 아닌 채 root의 힘을 가진 것들

*[English](2026-09-29-stage3c2a-privilege-design.md) · 한국어*

이 문서는 muster 계획 3C-2a의 설계입니다: 3C-1 설계(`2026-09-23-stage3c1-audit-integrity-design.md`
§8)가 **3C-2 "exposure and privilege"** 로 남겨둔 것의 앞 절반. 2026-09-29에 그 절반을 다시 주제로
나눴습니다: **3C-2a "privilege"** — 어느 계정·파일·그룹이 root가 아닌 채 root의 힘을 갖는가 — 와
**3C-2b "exposure"** — process 수집기, 삭제된 실행파일로 도는 프로세스, socket → process → package →
firewall 교차 점검, 3B가 파킹한 네트워크 sysctl. 이 문서는 3C-2a만 다루고, 3C-2b는 3C-2a가 머지된 뒤
자기 설계를 갖습니다. 결정은 P-1 … P-12로 번호를 붙이고 계획을 구속합니다. 여기의 모든 점검은 1차
출처 — `shadow(5)`, `useradd(8)`, `lastlog(8)`, `sudoers(5)`, `capabilities(7)`, `cap_to_text(3)`,
`systemd.service(5)`, `systemd.unit(5)`, `ld.so(8)`, `sshd(8)`, `sshd_config(5)`, `ssh-keygen(1)`,
RFC 4253 §6.6, `acl(5)` — 에서 muster의 말로 쓰였고, CIS 권고 번호를 싣지 않으며, 벤치마크 본문을
재생산하지 않습니다(메인 설계 §11, D04). 2026-09-29의 새 리뷰 두 편(컨트롤 쪽 blocking 5 / medium 9 /
low 6; 수집기 쪽 blocking 4 / medium 10 / low 10)이 접혀 있으며, 첫 초안과 다른 곳 — 절 문법,
capability 선언 출처, walk의 xattr 프리미티브, lastlog 레코드, 유닛 검색 경로, sudoers 문법, 오라클
모양 — 은 그 리뷰의 것입니다.

브레인스토밍에서 일곱 가지를 정했고 아래 전부가 그 위에 있습니다: 위의 분할(Q1); 모든 컨트롤은
읽은 대로 판정하고 호스트가 있는 그대로면 FAIL을 읽으며, 완화는 컨트롤이 눈감는 것이 아니라
`params`와 waiver로 한다(Q2); 휴면 계정은 `shadow(5)`와 `useradd(8)`의 비활성 정책으로 판정하고
로그인 이력은 근거다(Q3); walk는 setuid 비트를 판정하듯 파일 capability를 패키지 선언과 비교해
판정하고 ACL은 판정 없이 기록한다(Q4); sudoers는 alias를 풀어 user specification 깊이까지 읽고, 풀지
못한 것은 MANUAL로 읽는다(Q5); 판정하는 systemd 유닛은 enabled 또는 active인 서비스다(Q6);
`authorized_keys` 파일은 키 본문 없이 인벤토리하고, root의 키는 `PermitRootLogin`에 대해 판정하며,
키 품질은 OpenSSH 자체 문서로 판정한다(Q7). 수집기는 확장 셋과 새 것 셋이다(Q8).

## 1. 목표

`beyond` 범주 컨트롤 여덟을 더합니다 — 비활성 잠금, sudoers의 암호 없는 `ALL`, 선언되지 않은 파일
capability, root 서비스의 쓰기 가능한 실행파일, `ld.so.preload`, 컨테이너 런타임 소켓과 그 그룹,
root의 authorized keys, SSH 키 품질 — 확장 수집기 셋(`accounts`, `files`(그 sudo 리더), `walk`)과 새
수집기 셋(`units`, `sshkeys`, `privilege`)이 먹입니다. 3C-2a 뒤 컨트롤 세트는 104개(67항목에 68개는
그대로, beyond 36개), `controls/VERSION`은 `kisa-unix-2026+2026.09.29`, `schema_version`은 그대로(키와
record 필드가 추가되고 바뀐 것은 없음; 메인 §5.7). 읽기 프리미티브 하나가 자랍니다: `ReadDir`가 나열하는
실행파일의 capability와 ACL 속성을 walk에 한해 읽을 수 있습니다(P-3).

범위 밖(계획이 흘러가지 않게 이름을 적음): 3C-2b 전부(위); root의 `PATH` — guide 컨트롤
`root_home_and_path`가 이미 `env.shell.root_path_entries`의 `.`과 world-writable 항목을 판정하며,
로드맵의 "root's PATH"는 그 컨트롤임; ACL 판정(기록만 — 일반 ACL에 등급을 매길 1차 출처가 없음); 실제
휴면 계정 목록의 판정(근거만, P-1); 특정 명령의 `NOPASSWD`(근거만); 암호와 함께 주는 `ALL` 명령(stock의
`%wheel` / `%sudo` 줄); `Host_Alias`와 user specification의 호스트 필드(모든 줄을 이 호스트의 것으로
셈); `Defaults!command` 범위; enabled도 active도 아닌 서비스; `.socket`, `.timer`, `.path` 유닛; 두
기본값 외 경로로 설정된 `AuthorizedKeysFile`, `AuthorizedKeysCommand`, 인증 기관; `from=`/`restrict`
없는 일반 사용자의 키(근거만); rootless podman의 사용자별 소켓; `/etc/security/access.conf`; shadow ≥
4.15의 `lastlog2`·`wtmpdb` 데이터베이스(sqlite; 없으면 로그인 이력만 `absent`, 판정은 아님); 릴리스별
capability 참조 목록 — 호스트 자신의 패키지 메타데이터가 선언하므로(P-3) `tools/suidindex`는 확장하지
않음.

## 2. 3B·3C-1에서 이어받는 원칙

1. **판정은 호스트를 있는 그대로 읽습니다.** stock 클라우드 이미지는 `sudo_nopasswd_all` FAIL(cloud-init이
   자기 사용자에게 `NOPASSWD:ALL`을 씀), stock 세 릴리스 모두 `account_inactivity_lock` FAIL(`INACTIVE`
   미설정), 관리자가 `docker` 그룹에 있는 docker 호스트는 `container_runtime_access` FAIL — GitHub 러너는
   뒤의 둘 다입니다. 설명이 각각 그렇게 말합니다. 조직의 선택은 `params` 값이나 waiver로 기록되지,
   컨트롤이 가정하지 않습니다(Q2).
2. **muster가 보지 못한 것은 경로를 적은 MANUAL이며, FAIL도 PASS도 아닙니다**(C4). 풀 수 없는 sudoers
   alias, 선언 밖 `@include`, 선언 패턴 밖의 홈 디렉터리, 존재하지만 읽을 수 없는 유닛 파일 — 각각 판정
   leaf를 이유와 함께 `absent`로 두고 컨트롤은 MANUAL. 선언된 파일을 못 읽으면 읽기 상태(C3) → ERROR;
   muster가 읽기를 거절한 경로만 `absent`.
3. **절이 판정하는 leaf는 각자 키**(C2). `where`는 조건 하나이므로 복합 조건("대화형이고 미설정")은
   수집기가 만든 목록이고, 관리자가 조정하는 임계값은 수집기가 기록한 필드와 비교되는 `params`
   값입니다(`inactive gt ${max_inactive_days}`). 판정 목록의 모든 행은 절이 부르는 모든 필드를 싣고, 행이
   존재하지 않는 것에 관한 것이면 중립값을 둡니다(R176: `exists: false` 행도 `other_writable: false`를
   가짐).
4. **같은 입력, 같은 바이트.** 모든 목록은 정렬(`path`, `name`, `unit`, 또는 `file, line`)·상한이 있고,
   상한에 닿으면 키에 `truncated: true`. 키 본문은 스냅샷에 절대 들어가지 않습니다: 키는 유형, 비트 길이,
   SHA256 지문, 옵션입니다.
5. **여기서 정책 엔진을 돌리는 것은 없습니다.** `sudo -l`은 정책을 평가하고 시도를 로그에 남기므로
   muster는 파일을 파싱합니다; `visudo -c`는 검증만 하며 오라클의 도구이지 수집기의 것이 아닙니다.
   새 명령은 고정 인자의 `systemctl list-units` 하나; 바뀌는 명령은 walk의 rpm 질의로, 열 하나가 늘어납니다.

## 3. 사실과 수집기 (P-1 … P-6)

새 레지스트리 키 19개(`accounts.*` 3, `sudo.*` 4, `walk.*` 2, `units.*` 3, `ssh.*` 4, `privilege.*` 3,
근거 전용 목록 포함), 전부 `since: 1`, 스키마 버전은 그대로. 민감도는 달리 말하지 않으면 `public`.
수집기가 읽는 새 경로는 전부 그 `Declaration.Reads`에 있습니다; guard가 그 밖의 것을 거절하므로
수집기마다 아래에 경로를 적습니다.

### P-1 — `accounts`에 비활성 정책과 로그인 이력

`Reads`에 `/etc/default/useradd`와 `/var/log/lastlog`가 더해집니다. shadow 필드는 이미 읽습니다:
`accounts.users` 행이 `inactive`(7번째 필드, 비어 있으면 -1)와 `expire`(8번째)를 싣습니다. leaf 셋을
더합니다.

- `accounts.login_capable` — `list<record>` `{name, uid, inactive, expire, inactive_unset, locked}`:
  비활성 정책이 덮어야 하는 계정 — `files_home`이 이미 쓰는 규칙(`interactive()`: 셸이 `/etc/shells`에
  있고 `nologin`이나 `false`가 아님 — EL의 `/etc/shells`는 `nologin`을 싣으므로 등재만으로는 판별이 안
  됨)으로 대화형 셸을 가진, 시스템 계정이 아닌 모든 계정. **root 포함**(`system`은 uid 0에 false이고
  root는 대화형 셸을 가짐): 필드는 계정에 속하며, 모든 사용자의 필드를 두고 root의 것만 두지 않은
  호스트는 root의 것도 둘 때까지 FAIL을 읽습니다; 설명이 그렇게 말합니다. **암호 잠긴 계정 포함**(`locked`가
  기록): `shadow(5)`는 그런 계정이 다른 수단으로 로그인할 수 있다 하고, `pam_unix`는 비활성 필드를 키
  로그인에도 적용하며, 클라우드 이미지의 기본 사용자 — `!` 암호와 authorized key — 가 정확히 이 컨트롤이
  말하는 계정입니다. `inactive_unset`은 `inactive == -1`. `/etc/shadow`가 없는 호스트(`password_status`
  `noshadow`)에선 필드가 존재할 수 없음: 그런 행은 전부 `inactive_unset: true`이고, 호스트는 U-04에서처럼
  여기서도 FAIL. `name` 정렬. `/etc/shadow`가 있는데 못 읽었으면 읽기 상태(C3): 비root 읽기는 `denied`.
- `accounts.useradd.inactive` — `int`: `/etc/default/useradd`(`useradd -D`의 파일)의 `INACTIVE` 값, 새
  계정에서 암호 만료 뒤 계정이 비활성화되기까지의 일수; 줄이 없거나, 주석이거나, 비었거나(`INACTIVE=`), 숫자가
  아니거나, -1 아래면 -1(이유가 어느 쪽인지 적음 — `useradd(8)`과 shadow의 `get_defaults`는 모두 "never"로
  봄); 값은 C `strtol`의 base 0처럼 읽고(`030`은 24), 줄은 첫 칸에서 시작해야 하며(`get_defaults`는
  접두를 비교), 뒤의 `INACTIVE=` 줄이 앞의 것을 덮어씀. 파일이 있는데 못 읽으면 읽기
  상태(C3): 파일은 Debian/Ubuntu와 배포된 Rocky 9에서 0644(측정; `shadow-utils` `%attr`을 0600으로 읽었던
  것)라 비root 읽기는 릴리스의 패키징에 따르고 capability matrix는 행 대신 `_notes` 항목을 둡니다. EL은 `INACTIVE=-1`을 써서 배포하고 Ubuntu는 줄을
  주석으로 배포; 둘 다 -1.
- `accounts.lastlog` — `list<record>` `{name, uid, last_login, line, host}`, 근거 전용, `sensitivity:
  internal`: `/var/log/lastlog`을 `ReadFileBinary`로 32 MiB 상한까지 읽어 uid로 색인된 고정 레코드로
  디코드 — glibc의 `struct lastlog`은 `ll_time`, `char ll_line[32]`, `char ll_host[256]`이고 `ll_time`은
  32비트 time ABI와 x86_64(`__WORDSIZE_TIME64_COMPAT32`)에서 `int32_t`, 그 밖에선 `__time_t`이므로 레코드는
  amd64·386·arm·ppc64le·riscv64·mips64(`__WORDSIZE_TIME64_COMPAT32`가 켜진 곳)에서 292바이트,
  arm64·s390x·loong64에서 296바이트; glibc 2.40이 32비트 필드를 부호 없는 것으로 바꿨으므로 `uint32`로
  읽음; 크기는 `runtime.GOARCH`에서 오고 `parseLastlog(data, recordSize)`에 넘기며 leaf의 이유에 기록. `accounts.users`의 uid만 디코드;
  `last_login`은 RFC 3339 UTC, 레코드가 0이면 `""`("로그인한 적 없음"). 읽기 상한 너머의 uid는 디코드하지
  않고 leaf는 `truncated: true`. 상한 2000행, `name` 정렬. 파일은 0664 `root:utmp`라 비root 실행도
  읽음. shadow < 4.15인 곳 — Ubuntu 22.04와 24.04, EL9, Debian 12 — 에 있고; Debian 13 / Ubuntu 24.10부터는
  없음(shadow 4.15가 `lastlog`를 버리고 `lastlog2`가 muster가 모델링하지 않는 sqlite 데이터베이스를 둠)
  — 그 이유를 적은 `absent`, 어느 컨트롤도 읽지 않음.

### P-2 — sudo 리더(`files` 수집기, `files_sudo.go`)에 규칙

sudo 리더는 이미 체인을 걷습니다 — `/etc/sudoers`, `@includedir` / `#includedir` 디렉터리, 선언된
경로의 `@include` — 그리고 include가 선언 밖을 가리키거나 drop-in이 심볼릭 링크면 경로를 적은
`absent`로 멈춥니다(`/dev/null` 링크는 마스크; 3C-1, J-40/J-49). 같은 걷기가 이제 읽는 모든 줄에서 두
가지를 더 파싱합니다(`sudoers(5)`): alias 정의(`User_Alias`, `Runas_Alias`, `Cmnd_Alias`;
`Host_Alias`는 읽고 무시)와 user specification. 렉서도 함께 바뀝니다: 숫자가 뒤따르는 `#`는
uid(`#1000`), `%#`는 gid, `#include` / `#includedir`는 지시자, 그 밖의 `#`는 주석 시작; 줄은 먼저
분류하고 그 다음 `\` 이음으로 합칩니다 — 주석 줄은 무엇으로 끝나든 그 줄바꿈에서 끝나고, 줄을 합치는
중에 만난 주석은 그 줄을 닫습니다(sudo의 렉서는 `\`-줄바꿈을 공백으로 읽은 뒤 주석을 끝까지 읽음);
`#1000 ALL = \` 줄은 규칙이라 그대로 이어집니다(지금의 Defaults 리더는 `#`로 시작하는 모든 줄을
주석으로 봄). 문법은 `sudoers(5)`에서:

- `User_List host_list = Cmnd_Spec_List [: host_list = Cmnd_Spec_List …]` — `User_List`는 쉼표로 구분된
  principal 여럿을 갖고, 각각 `user`, `%group`, `#uid`, `%#gid`, `+netgroup`, `%:nonunix_group`,
  `%:#nonunix_gid`, `User_Alias`, `ALL`이며 `!`로 부정될 수 있음; principal마다 한 행을 씀. `:`는 한 줄의
  privilege들을 구분하고 runas와 태그를 새로 시작.
- `Cmnd_Spec_List` 안에서 `(runas)` 스펙과 태그(`NOPASSWD:`, `PASSWD:`, 그 밖)는 자기가 앞선 명령 **그리고
  같은 종류의 다음 것이 나올 때까지의 모든 뒤 명령**에 적용 — `(root) NOPASSWD: /bin/a, /bin/b`는 둘 다
  root로 암호 없이. `(user)`, `(user:group)`, `(:group)`, `(ALL:ALL)`은 모두 runas 스펙; muster는 스펙
  텍스트를 기록하고 판정에서 구별하지 않음.
- 명령 목록 `ALL, !/usr/bin/su`는 여전히 `ALL`을 줌(man 페이지는 부정이 보안 수단이 아니라 함);
  `sudoedit`는 명령 단어.
- alias는 체인의 모든 파일을 읽은 뒤 치환으로 깊이 8까지 풉니다(sudo는 파싱 뒤에 풀므로 사용 뒤의
  정의도 셈); 순환, 미정의 alias, netgroup, 비Unix 그룹은 행을 `resolved: false`로 두고, 예산 —
  해석 한 번에 alias 멤버 65536과 행 65536 — 을 넘는 것도 그러하므로 조작된 파일은 부분 답이 아니라
  `absent`로 읽힙니다. 명령 앞의 `sha224:`…`sha512:` digest는 명령과 한 단어로 남습니다(그 `=` 패딩이
  줄을 가르지 않음).
- `Defaults` 줄: 범위 없음, `Defaults:User_List`, `Defaults>Runas_List`, `Defaults@Host_List`,
  `Defaults!Cmnd_List`; 같은 플래그에 대해 뒤의 줄이 앞의 줄을 이김(`sudo.log.*` 선례).

- `sudo.rules` — `list<record>` `{file, line, principal, kind, negated, runas, nopasswd, commands,
  resolved}`, `kind` ∈ user | group | uid | gid | all | alias | netgroup | nonunix(해석 뒤 alias는 멤버마다
  한 행으로 펼쳐지고 `kind`는 멤버의 것; `alias`, `netgroup`, `nonunix`는 풀지 못한 행에만 남음);
  `nopasswd`는 `NOPASSWD:` 태그가 명령 목록에 적용될 때 true; `commands`는 푼 명령 목록, `ALL`은
  `ALL`로, 부정 명령은 `!`를 붙인 채. 근거, `sensitivity: internal`, 상한 2000행, `file`, `line` 정렬.
- `sudo.nopasswd_all` — `list<string>`: `root`와 `#0`가 아닌 principal — `ALL`도 포함, `ALL`로 표기 — 중
  `NOPASSWD:` 아래 명령으로 `ALL`을(부정이 있어도) 받는 것, runas는 무엇이든 — cloud-init
  `90-cloud-init-users`의 `ubuntu`, `ALL`로 펼쳐지는 alias의 `%admins`, GitHub 러너의 `runner`. 정렬,
  중복 제거.
- `sudo.authenticate_disabled` — `bool`: 줄을 순서대로 적용한 뒤, 범위 없는 `Defaults`나 어떤
  `Defaults:User_List` 또는 `Defaults>Runas_List`에 대해 `!authenticate`가 유효함(둘 다 누가 무엇으로
  상승하는가에 관한 것 — `Defaults>ALL !authenticate`는 누구로든 도는 모든 명령의 암호를 끔).
  `Defaults@host`와 `Defaults!command` 범위는 읽어 지금처럼 `sudo.defaults.scoped_count`에 세고 이 값을
  세우지 않음(§1이 파킹).
- `sudo.rules_unresolved` — `int`, `resolved: false`인 규칙 수.

`sudo.rules_unresolved`가 0이 아니면 `sudo.nopasswd_all`과 `sudo.authenticate_disabled`는 `absent`("규칙
N개를 풀지 못함: ALIAS, +netgroup — 답에 그것이 필요함")이고 컨트롤은 MANUAL(원칙 2). 체인을 다 읽지
못했으면(선언 밖 include, 심볼릭 링크 drop-in) 네 leaf 모두 `sudo.log.*`처럼 경로를 적은 `absent`. sudo가
없으면 `sudo.rules`는 빈 목록, `nopasswd_all` 빈 목록, `authenticate_disabled` false, `rules_unresolved`
0 — 컨트롤은 어차피 `sudo.installed`에 게이트. 레지스트리 행은 다른 `sudo.*` 키처럼 `collector: files`.

### P-3 — walk에 파일 capability와 ACL

**프리미티브.** 지금의 `ReadDir`는 엔트리마다 `statx` 한 번으로 디렉터리를 나열하고 돌아오기 전에
디렉터리 fd를 닫습니다; walk는 fd를 들고 있지 않고, 경로 기반 xattr 읽기는 모두 walk에 없는 `Reads`에
guard됩니다. 그래서 `ReadDir`에 옵션이 자랍니다 — `ReadDir(path, expect, ReadDirOptions{Xattrs: true})` —
`Declaration.Walk`만이 허가하며, 그 아래서 디렉터리 fd가 열려 있는 동안 **실행 비트가 하나라도 있는 일반
엔트리**(`mode & 0o111 != 0`)마다 `openat(dirfd, name, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY|O_CLOEXEC)`로
열고, `fstat`로 `S_IFREG`이고 나열의 (dev, ino)와 같은지 확인하고, 정확히 두 이름 —
`security.capability`와 `system.posix_acl_access` — 을 `fgetxattr`로 읽고(직접 읽기 둘; `ENODATA`가 "그런
속성 없음"이라 `flistxattr`는 부르지 않음) 닫습니다. 결과는 `DirEntry`에 실림: `Caps []byte`, `ACL
[]byte`, `XattrErr error`. `NoWalkAccess`에 스텁이 자라고; `--list-actions`의 walk 행은 "그리고 실행파일의
capability와 ACL 속성을 읽음"이라 말합니다. 실행파일만 엽니다: 아무도 실행할 수 없는 파일의
capability는 힘이 없습니다(`capabilities(7)`). 비용은 가족별입니다: Debian/Ubuntu는 공유 객체를 0644로
배포해 일반 파일의 1/10쯤을 열지만, RPM 가족은 모든 `.so`를 0755로 배포해 라이브러리도 전부 엽니다.
계획의 첫 과제가 둘 다 — lab(Ubuntu 22.04)과 EL9 이미지 — 재고 walk 예산 대비 늘어난 시간을 기록합니다.

**오류.** 열기의 `EACCES` / `EPERM` → 경로를 `walk.skipped`에 `xattr_denied` 이유로; `ENOENT`, `ELOOP`,
`ENXIO`, 또는 `fstat` 뒤 정체 불일치 → `vanished`(errno를 `detail`에); 읽기의 `EOPNOTSUPP` / `ENODATA` →
속성 없음, 행 없음; `ERANGE` → `Getxattr`처럼 한 번 재조정. muster가 디코드하지 않는 버전의 capability
xattr → `walk.skipped` 이유 `xattr_undecoded`. `walk.skipped`의 닫힌 어휘에 그 둘이 더해지고 설명은
"walk가 들어가지 않은 모든 루트와 속성을 읽을 수 없었던 모든 실행파일"이 되며;
`walk.stats.truncated_counts`에 새 목록 둘의 키가 더해집니다. walk는 xattr 때문에 멈추지 않습니다.

**디코드.** VFS capability xattr(`include/uapi/linux/capability.h`): 버전 1(u32 한 쌍), 버전 2(permitted와
inheritable 두 쌍, 하위·상위 워드), 버전 3(버전 2 + capability가 유효한 사용자 네임스페이스 `rootid`),
effective 플래그는 `magic_etc`에. muster가 아는 이름표 너머의 capability 인덱스는 `cap_N`으로 표기. 행의
`caps`는 (permitted, inheritable, effective) 삼중에서 렌더한 **`cap_to_text(3)` 정규 문자열** —
`cap_net_raw=ep`, `cap_chown,cap_setuid=p` — 인데, 두 선언 출처와 `getcap`이 공유하는 형식이 그것이기
때문; 렌더러는 이름 있는 비트 수를 41(5.9+ 커널의 `cap_max_bits`)로 고정해 문자열이 호스트에 의존하지
않게 하고, 텍스트 파서는 libcap의 두 표기 — libcap ≥ 2.41의 `cap_net_raw=ep`와 옛 빌드의 `=
cap_net_raw+ep`(2020년 전에 빌드된 rpm 헤더가 아직 싣는 것) — 를 모두 받음; `rootid`는 기록되고(v1/v2는 0) `rootid`가 0이 아닌 v3 행은 결코 `package_declared`가 아닙니다: rpm 헤더도
`-n` 없는 postinst `setcap`도 그런 것을 쓰지 않으므로 사용자 네임스페이스에서 세워진 것 — 오늘 초기
네임스페이스에선 힘이 없어도, 패키지가 선언하지 않은 capability인 것은 그대로(이유에 적음).

**선언.** setuid join의 세 출처가 여기선 둘이 됩니다. capability는 패키지가 세우는 곳에서 선언되기
때문입니다:
- rpm: `%{FILECAPS}` 태그 — walk의 선언된 rpm 질의에 그 열이 더해지고(`--qf "[…\t%|FILECAPS?{%{FILECAPS}}|\n]"`
  — 조건식은 헤더에 capability가 하나도 없는 패키지에 `(none)`이 아닌 빈 필드를 찍음) `--list-actions`의
  명령 행이 바뀌며 계획이 그렇게 말합니다. `reference: rpmdb`; 태그의
  문자열이 같은 정규 `caps`로 렌더되면 `package_declared` true.
- dpkg: `.deb`는 xattr을 실을 수 없고; 패키지의 `postinst`가 설치 시 `setcap`으로 세웁니다. join은 소유
  패키지의 `/var/lib/dpkg/info/<pkg>[:<arch>].postinst`(그 glob이 walk의 `Reads`에 더해짐; postinst는 경로를
  소유한 `.list` 파일을 통해 찾으므로 multi-arch `libgstreamer1.0-0:amd64.postinst`도 풀림)를 읽어 네 형식을
  인식: 리터럴 경로의 `setcap <caps> <path>`; 스크립트 앞에서 `NAME=<path>`가 리터럴로 대입된 `setcap
  <caps> $NAME`; `NAME=$(dpkg-divert --truename <path>)`(`iputils-ping`의 `PROGRAM` — 안의 리터럴이 선언된
  경로이고, 우회(divert)된 파일에 맞을 수 있는 형식은 이것만); 그리고 `setcap [-q] - <path> < <file>`이나
  `setcap -`로의 파이프(snapd는 `snap-confine`의 집합을 배포된 파일에서 읽음). muster가 풀 수 없는 `setcap`
  호출(명령으로 대입된 변수)은 행을 "a setcap call muster could not resolve" 이유의 미선언으로 두고;
  없거나 읽을 수 없는 스크립트는 읽기 이유의 미선언으로 둠 — join 자체는 postinst 때문에 실패하지 않음. `reference: postinst`; 스크립트가 `setcap` 호출에서 그 경로를 부르고,
  caps 텍스트가 리터럴인 곳에서는 같은 정규 `caps`로 렌더되면 `package_declared` true;
  `declared_caps`는 그 텍스트이거나 세 번째 형식이면 `"(from file)"`. lab에서 `setcap`을 부르는 스크립트
  다섯 — `iproute2`, `iputils-ping`, `libgstreamer1.0-0`, `mtr-tiny`, `snapd` — 이 `getcap -r /usr`가
  나열하는 파일 넷을 덮으므로, stock Ubuntu 호스트는 자기 메타데이터로 PASS를 읽습니다.
- 어느 패키지도 소유하지 않는 파일은 `reference: unpackaged`, `package_declared: false` — 심어진
  바이너리가 취하는 모양, FAIL로 판정. 어휘는 walk의 기존 것(`rpmdb`, `dpkgdb`, `statoverride`, `list`,
  `unpackaged`, `unlisted`, `version_mismatch`, `postinst`, `none`); `list`, `unlisted`, `version_mismatch`는
  여기서 나오지 않으므로(참조 목록 없음) `capabilities_unverified` 목록도 unverified 컨트롤도 없음: 디코드된
  모든 capability가 판정됩니다.

- `walk.capabilities` — `list<record>` `{path, caps, rootid, package, package_declared, declared_caps,
  reference}`. `listCaps`(2000) 상한, `path` 정렬.
- `walk.acl_grants` — `list<record>` `{path, entries}`, 근거 전용: 접근 ACL이 mask 적용 뒤 named user/group에 소유 그룹의
  `group::` 항목보다 많은 쓰기나 실행을 주는 실행파일(`acl(5)`: named 항목이 있으면 모드의 그룹 부류가
  곧 mask이므로 "모드 너머"는 그룹 항목 너머를 뜻함); `entries`는 **숫자 id**의
  `getfacl` 표기(`user:1000:rwx` — 디코더는 이름을 풀지 않고, check 쪽은 풀 수 없음). 고정 경로
  `acl_entries` 사실이 이미 쓰는 POSIX ACL 디코더 `decodeACL([]byte)`로 디코드. 상한·정렬. 읽는 컨트롤
  없음(§1).

`walk.stats`에 두 목록의 상한 카운터가 `truncated_counts` 안에 더해집니다(열세 필드 레코드는 그대로;
레지스트리 설명이 두 카운터를 적음).

### P-4 — `units` 수집기

`Reads`: `systemd.unit(5)`의 시스템 유닛 검색 경로 — `/etc/systemd/system`, `/etc/systemd/system.control`,
`/run/systemd/system`, `/run/systemd/system.control`, `/run/systemd/transient`,
`/run/systemd/generator.early`, `/run/systemd/generator`, `/run/systemd/generator.late`,
`/usr/local/lib/systemd/system`, `/usr/lib/systemd/system` — 아래의 `*.service`, `*.service.d/*.conf`,
`*.wants/*`, `*.requires/*`(뒤의 둘은 `Readlink`로). `Commands`: 하나, `systemctl list-units
--type=service --state=active --plain --no-legend`(unit, load, active, sub, description 열;
`--state=active`는 `activating`과 `reloading`을 제외; 읽기 전용 D-Bus 질의라 권한 불필요), `services`가
`show` 호출을 선언하는 방식으로. `Needs: none`.

서비스는 enabled(어느 트리든 `.wants`/`.requires` 링크가 이름을 부름)이거나 active(`list-units`가
나열)일 때 **범위 안**입니다. 각각 유닛 파일을 systemd 우선순위로 트리에서 찾고; 인스턴스
`foo@bar.service`는 템플릿 `foo@.service`로 찾고; `/dev/null` 심볼릭 링크인 유닛 파일은 마스크라 범위
밖; 대상이 같은 디렉터리의 맨 유닛 이름인 심볼릭 링크(Ubuntu의 `sshd.service → ssh.service` alias)는
**이름으로** 한 번 따라감 — `Readlink` 뒤 그 이름을 찾음; 그 밖의 심볼릭 링크는 링크된 유닛, 어느 트리에도
없는 유닛은 missing: `unit_file: symlink` / `unit_file: missing` 행이고 `exec_unresolved`에 세며 실행파일은
판정하지 않음 — 그리고 링크된 유닛이나 ACTIVE인 missing 유닛은 `units.exec_writable`을 유닛을 적은
`absent`로 만듦(무엇이 도는지 모름; enabled만 되고 `.wants` 링크가 끊긴 유닛은 아무것도 돌지 않으니
unresolved에 그침). 크기 0의 유닛 파일은 systemd 마스크라 범위 밖. `Exec*=` 값의 홀로 선 `;` 단어는
명령을 나눔(`\;`는 리터럴 인자): 명령마다 exec 행 하나, 각각 판정. 유닛 파일과 모든 트리의 `.d/*.conf` drop-in을 systemd 순서로 읽어 자체 병합기로 합칩니다
(`mergeDropins`는 단일값이라 `Exec*=` 목록을 합칠 수 없음): `[Service]`의 `User=`(마지막이 이김; `0`은
root)와 `Exec*=` 지시자(`ExecStart`, `ExecStartPre`, `ExecStartPost`, `ExecCondition`, `ExecReload`,
`ExecStop`, `ExecStopPost`), 뒤 파일의 빈 `ExecStart=`는 앞의 목록을 초기화(`systemd.service(5)`). 각
지시자의 첫 토큰이 실행파일: 접두 문자 `@ - : + ! !! |`를 벗기고("Command lines"; `!!`는 systemd 258이
무시하고 `|`는 거기서 새로 생김), 인용을 제거; 절대 경로가
아닌 토큰(systemd 239부터 허용)이나 `%` 지정자(`%i`, `%I`, 템플릿)를 가진 토큰은 `resolved: false`이고
판정하지 않음. 수집기가 stat할 수 있는 실행파일은 고정 선언 집합 — `/usr/bin/*`, `/usr/sbin/*`, `/bin/*`,
`/sbin/*`, `/usr/local/bin/*`, `/usr/local/sbin/*`, `/usr/lib/*`, `/usr/lib/*/*`, `/usr/lib/*/*/*`,
`/usr/libexec/*`, `/usr/libexec/*/*`, `/lib/*`, `/lib/*/*`, `/opt/*/*`, `/opt/*/bin/*`, `/snap/bin/*`,
`/usr/share/*/*`, `/usr/share/*/*/*`(기본 Ubuntu는 `unattended-upgrade-shutdown`을 거기서 돌림, V-44) —
LXD의 `lxd-agent` 같은 `/run/*` 에이전트와 `/var/lib/*` 바이너리는 집합 밖이라 LXD 게스트는 MANUAL로 읽음 —
`/etc/init.d/*` — 이고, 그 밖의 경로는 C4: exec 행은 `stat_status: undeclared`이고 `units.exec_writable`은
경로를 적은 `absent`(MANUAL). 합친 `User=`가 `root`/`0`이 아닌 서비스는 범위 밖: 그 실행파일은 root의 힘
없이 돕니다.

- `units.root_services` — `list<record>` `{unit, enabled, active, user, unit_file, files, exec, read_status,
  reason}`(`read_status`는 `ok` | `denied` | `error`, `reason`은 유닛 파일이나 drop-in을 읽지 못한 경우가
  아니면 `""`): `unit_file` ∈ file | symlink | missing; `files`는 읽은 유닛 파일과 각 drop-in `{path, mode, uid, gid}`;
  `exec`는 `Exec*` 첫 토큰마다 한 행 `{directive, path, exists, kind, mode, uid, gid, group_writable,
  other_writable, resolved}`, 경로의 `Stat`에서(모든 행에 모든 필드 — 없는 파일은 `exists: false`에 `mode
  -1`, `uid -1`, `gid -1`, 두 writable 플래그 false; 경로의 심볼릭 링크는 한 홉 따라감: 선언 집합 안의 대상은
  stat하여 판정하고 `stat_path`에 적으며, 밖의 대상이나 두 번째 링크는 `units.exec_writable`을 링크를
  적은 `absent`로 만듦; `stat_status`는 `ok`, `undeclared`, `denied`, `error`; merged-`/usr` 별칭
  `/bin`, `/sbin`, `/lib`은 링크를 통해 `/usr`로 풀림). 근거, `sensitivity: internal`, 상한 500 유닛, `unit` 정렬.
- `units.exec_writable` — `list<record>` `{unit, path, why}`: 판정용 부분집합 — 디렉터리를 비root 사용자가
  쓸 수 있는 실행파일(`why: parent_writable` — 부모가 uid 0 소유가 아니거나 group/other-writable; Debian의
  `root:staff` 2775 `/usr/local/*`은 사실대로 FAIL을 읽음), 소유 uid가 0이 아니거나,
  group-writable이거나, other-writable인 실행파일(`why` ∈ `owner`, `group_writable`, `other_writable`),
  그리고 같은 세 성질의 유닛 파일이나 drop-in(`why`에 `unit_file:` 접두). `unit`, `path` 정렬. 범위 안의
  유닛 파일이나 drop-in이 존재하는데 읽을 수 없으면 유닛과 경로를 적은 **`absent`**: 읽을 수 없는 파일이
  결정하는 `ExecStart`를 품을 수 있으므로 답은 모르는 것이고 컨트롤은 MANUAL(원칙 2; J-40 모양).
- `units.exec_unresolved` — `int`: `resolved: false`인 행 수와 `unit_file`이 `symlink`나 `missing`인 유닛
  수. 근거.

systemd가 없으면(`env.has_systemd` false, `systemctl`이 시작되지 못함, 또는 "System has not been booted
with systemd"라 답함) 세 leaf는 `unsupported`(`fim` 타이머 목록의 모양, 3C-1 J-45); 시간을 넘긴
`list-units`는 `timeout`, 그 밖의 0 아닌 종료는 코드를 적은 `error`. CI의 init 컨테이너는 systemd가 PID
1이라 `ok`를 읽고; 일반 이미지는 `unsupported`를 읽으며 matrix의 `no-systemd.unsupported` 행에 세 키가
더해집니다.

### P-5 — `sshkeys` 수집기

`Reads`: `/etc/passwd`, `/etc/shells`, 그리고 `files` 수집기가 선언하는 홈 패턴 `/home/*`, `/home/*/*`,
`/root` 아래의 `/.ssh/authorized_keys`와 `/.ssh/authorized_keys2` — `sshd_config(5)`의
`AuthorizedKeysFile` 기본값 둘. `Needs: none`. 사용자는 `/etc/passwd`의 홈 경로가 있는 로컬 계정,
`files_home`이 고르는 대로; 선언 패턴 밖의 홈은 그 사용자 행을 경로와 함께 `unfollowed`로 두고(C4) **세
카운트를 그 경로를 적은 `absent`로 만듭니다** — 구멍 난 인벤토리는 인벤토리가 아니므로, `/srv` 아래에
홈을 둔 사용자가 있는 호스트는 두 키 컨트롤을 홈을 적은 MANUAL로 읽습니다.

- `ssh.authorized_keys` — `list<record>` `{user, uid, path, exists, mode, owner_uid, keys, unparsed,
  unfollowed, read_status, reason}`, `sensitivity: internal`: 존재하는 파일마다 한 행(그리고 파일 없는
  사용자마다 `exists: false` 행 하나 — 홈이 선언 밖인 사용자는 `unfollowed: true`와 이유를 가진 행, 읽지
  못한 파일은 `read_status: denied`/`error`와 이유를 가진 행; 모든 행이 모든 필드를 싣고 해당 없으면
  `""`/`false` —
  "키 없음"이 침묵이 아니라 읽기가 되게); `keys`는 `{line, type, bits, fingerprint, options, restricted}`
  목록. 디코드(`sshd(8)` AUTHORIZED_KEYS FILE FORMAT, RFC 4253 §6.6): 옵션 필드는 첫 단어가 키 유형이
  아닐 때만 존재하고 그 인용값은 `,`와 `\"`를 품을 수 있음; 키 blob은 base64이고 안쪽 유형 문자열이 유형
  단어와 같아야 하며(서명 전용 단어 `rsa-sha2-256` / `rsa-sha2-512`는 `ssh-rsa` blob을 싣고 sshd에겐 같은
  RSA 키) 아니면 그 줄은 `unparsed`; 뒤에 남는 바이트나 잘못된 필드가 있는 blob도 `unparsed`; `ssh-rsa`의 `bits`는 modulus `n`의 선행 `0x00`(최상위
  비트가 1이면 있음 — 2048비트 키는 `n`을 257바이트로 인코딩)을 벗긴 뒤의 비트 길이;
  `ecdsa-sha2-nistpXXX`는 안쪽 곡선 이름의 곡선 크기; `ssh-ed25519`와 `sk-*` 유형은 256; `ssh-dss`는 1024;
  인증서 유형(`*-cert-v01@openssh.com`)은 0(기록되고 컨트롤은 무시); `fingerprint`는 `SHA256:` + 디코드한
  blob의 SHA-256을 **패딩 없는** base64로(`ssh-keygen -l`이 찍는 것); `restricted`는 `restrict`나 `from=`이
  옵션에 있으면 true; `unparsed`는 주석·빈 줄·파싱 가능한 키 어느 것도 아닌 줄 수. 키 본문 자체는 절대
  저장하지 않음. 파일당 200키, 500행 상한.
- `ssh.root_key_count` — `int`: root의 두 파일의 키 수. 두 기본값을 모든 릴리스에서 읽음; EL은
  `AuthorizedKeysFile .ssh/authorized_keys`를 주석 없이 배포하므로 거기서 `authorized_keys2`의 키는 sshd가
  무시하는 것 — `root_authorized_keys`의 설명이 카운트에 그것이 포함된다고 말함(root의 오래된 키 파일은
  살펴볼 일이지 오탐이 아님).
- `ssh.dsa_key_count` — `int`: 읽은 모든 파일의 `ssh-dss` 키 수.
- `ssh.rsa_keys` — `list<record>` `{user, path, line, bits, fingerprint}`: modulus를 읽은 모든 RSA 키,
  두 계정이 공유하는 파일은 이름순 첫 계정 아래 한 번(blob이 디코드되지 않는 것은 `unparsed`에 있고 여기엔 없으므로 모든 행이 `bits`를 실음). `user`,
  `path`, `line` 정렬.

muster가 못 읽은 파일(C3)은 그 행과 세 카운트에 읽기 상태를
둡니다; sshd는 따라가고 muster는 따라가지 않는 심볼릭 링크 키 파일이나 `.ssh` 경로는 `unfollowed: true`
행이고 세 카운트를 그것을 적은 `absent`로 둡니다(MANUAL); 신뢰할 수 없는 `/etc/shells`(읽을 수 없음, 또는
libc 대체)은 그 상태를 세 카운트에 둡니다. 비root 실행에서 결정적인 거부는
`/root` 자체(0700; matrix 단계가 이미 `! test -r /root`를 확인)이므로 세 카운트는 `denied`이고 두 키
컨트롤은 그것을 적은 ERROR — 단 `root_authorized_keys`는 게이트를 읽을 수 없을 때 예외(§4).

### P-6 — `privilege` 수집기

`Reads`: `/etc/ld.so.preload`, `/etc/group`, `/etc/passwd`, 그리고 런타임 소켓 넷 `/run/docker.sock`,
`/run/containerd/containerd.sock`, `/run/podman/podman.sock`, `/run/crio/crio.sock`의 `Stat` — cri-o가
설정하는 `/var/run/crio/crio.sock`은 거기로 풀리고, `/var/run`은 읽기 프리미티브가 모든 릴리스에서
거절하는 심볼릭 링크이므로 물리 경로가 선언된 경로입니다. `Needs: none`.

- `privilege.ld_so_preload` — `list<string>`: `/etc/ld.so.preload`의 주석·빈 줄 아닌 항목(glibc 로더: 항목은 공백·탭·개행·`:`로
  구분되고 `#`는 줄 어디서든 주석을 시작함). 파일 없음은 `ok` 빈 목록 — 정상 상태; 있는데 못 읽으면 읽기 상태(C3).
- `privilege.runtime_sockets` — `list<record>` `{path, exists, kind, mode, uid, gid, group, group_writable,
  other_writable, owner_nonroot, acl_present}`: API가 root인 네 런타임의 제어 소켓(소켓에 쓸 수 있는
  클라이언트는 privileged 컨테이너를 띄울 수 있음); `owner_nonroot`(uid ≠ 0)와 `acl_present`(소켓의 접근
  ACL)는 그룹 없이 API에 닿는 다른 두 길을 적음. 소켓은 읽기로 열 수 없으므로 xattr은 `O_PATH` fd 자신의
  `/proc/self/fd` 항목 — 이미 열린 inode, 경로를 다시 푸는 것이 아님 — 을 통해 읽고; stat이 소켓을 찾은
  뒤 실패한 xattr 읽기는 leaf의 error이지 결코 "없음"이 아님. 모든 행이 모든 필드를 실음: 없는 소켓(경로나 어느 부모의 `ENOENT`)은 `exists:
  false`, `mode -1`, `uid -1`, `gid -1`, `group ""`, 두 writable 플래그 false; 그 밖으로 실패하는 stat(podman
  호스트의 비root 실행에서 0750 root인 `/run/podman`의 `EACCES`)은 leaf에 경로를 앞에 붙인 읽기
  상태(C3). `group`은 gid로 `/etc/group`에서. `/run/podman/podman.sock`은 root의 `podman.socket`이 활성일
  때만 존재.
- `privilege.runtime_group_members` — `list<record>` `{group, member, uid, socket}`: 존재하고
  group-writable인 소켓마다 그 그룹의 uid ≠ 0 멤버 — `/etc/group`의 보조 멤버와 primary gid가 그 그룹인
  `/etc/passwd` 사용자 — (group, member, socket)마다 한 행, 상한 2000행. `group`, `member` 정렬. 읽을 수 없는
  `/etc/passwd`는 이 leaf만 떨어뜨림(소켓 행의 `group`은 `/etc/group`에서 옴). 소켓이 없거나 모든 그룹이 비어
  있으면 빈 목록(lab의 `docker` 그룹이 그러함; GitHub 러너의 것은 아님 — `runner`가 들어 있음).

`/etc/group`이나 `/etc/passwd`를 못 읽으면 `runtime_sockets`의 `group`과 `runtime_group_members` 전체가
경로를 앞에 붙인 읽기 상태(C3). podman이 없는 호스트에선 비root 실행도 셋을 다 읽음: `ld.so.preload`는
0644, `/etc/group`과 `/etc/passwd`는 world-readable, `/run`은 stat 가능.

## 4. 컨트롤 (P-7)

컨트롤 여덟, `category: beyond`, id `muster.beyond.<name>`, 전부 `env.container eq none` 게이트, 전부
평범한 `checks` 컨트롤(mechanism 없음). 절 문법은 로더의 것: `none` 절은 언제나 `where`를 갖고;
`list<string>`에서 `where`는 `field`가 없고 절은 `subject`가 없으며(원소가 값); 모든 `where`는 조건
하나; `${param}`은 `int`와 `list<string>`의 `expected`에 치환됩니다.

`references.stig` 항목은 커밋된 인덱스에서 버전과 함께 찾았습니다: 비활성 규칙 RHEL-09-411050(`rhel9`
V2R9), UBTU-22-411035(`ubuntu2204` V2R9), UBTU-24-200260(`ubuntu2404` V1R6)과 재인증 규칙
RHEL-09-432025(`rhel9` V2R9), UBTU-22-432010(`ubuntu2204` V2R9), UBTU-24-300021(`ubuntu2404` V1R6).
나머지 여섯 컨트롤은 인용 규칙이 없어 설명에 1차 출처를 적은 muster 자체 등급을 답니다.
`references.nist_800_53`은 인덱스가 가진 id여야 합니다(`references_nist` lint): 인용 있는 둘은 규칙
매핑의 합집합(`AC-2(3)`, `IA-4` / `IA-11`, `SC-11`, `CM-6`); privilege 경로 컨트롤 넷은
`AC-6(10)`(인덱스 규칙 아홉: 비특권 사용자는 특권 기능을 실행하지 못해야 함); 키 컨트롤 둘은
`IA-5(2)`(공개키 기반 인증, 인덱스 규칙 열둘).

| id | 중요도 | 추가 게이트 | 판정 | `absent_means` |
|---|---|---|---|---|
| `account_inactivity_lock` | 중 | — | `{ fact: accounts.login_capable, op: none, subject: name, where: { field: inactive_unset, op: eq, expected: true } }`; `{ fact: accounts.login_capable, op: none, subject: name, where: { field: inactive, op: gt, expected: "${max_inactive_days}" } }`; `{ fact: accounts.useradd.inactive, op: gte, expected: 0 }`; `{ fact: accounts.useradd.inactive, op: lte, expected: "${max_inactive_days}" }` — `INACTIVE=0`(만료 즉시 비활성)은 둘 다 통과 | fail — `/etc/passwd`가 없을 때 닿음(`fail-no-passwd.json`); `_mutants.yaml` 행 없음 |
| `sudo_nopasswd_all` | 상 | `sudo.installed eq true` | `{ fact: sudo.nopasswd_all, op: none, where: { op: not_in, expected: "${allowed_nopasswd_principals}" } }`(기본 `[]`); `{ fact: sudo.authenticate_disabled, op: eq, expected: false }` | manual — 체인을 다 읽지 못했거나 규칙을 풀지 못함: 빠진 줄이 태그를 실을 수 있음(`manual-include-outside.json`, `manual-unresolved-alias.json`) |
| `file_capabilities_declared` | 상 | (deep 게이트: `walk.complete`) | `{ fact: walk.capabilities, op: none, subject: path, where: { field: package_declared, op: eq, expected: false } }` | manual — 패키지 데이터베이스가 없는 호스트는 join된 walk 목록 전부를 `absent`("no package database")로 만듦: 대조할 선언이 없음, setuid 선례(`manual-no-package-db.json`) |
| `root_unit_exec_writable` | 상 | `env.has_systemd eq true` | `{ fact: units.exec_writable, op: none, subject: path, where: { field: why, op: present } }` | manual — 범위 안 유닛 파일이나 drop-in이 존재하는데 읽을 수 없음(`manual-unit-unreadable.json`) |
| `ld_so_preload_empty` | 상 | — | `{ fact: privilege.ld_so_preload, op: none, where: { op: not_in, expected: "${allowed_preload}" } }`(기본 `[]`) | fail — 닿지 않음: 없는 파일은 `ok` 빈 목록(행 셋) |
| `container_runtime_access` | 상 | — | `{ fact: privilege.runtime_sockets, op: none, subject: path, where: { field: other_writable, op: eq, expected: true } }`; `owner_nonroot`와 `acl_present`에 같은 절; `{ fact: privilege.runtime_group_members, op: none, subject: member, where: { field: member, op: not_in, expected: "${allowed_runtime_group_members}" } }`(기본 `[]`) | fail — `/etc/group`이 없으면 멤버 leaf가 `absent`(`fail-no-group.json`); 소켓 없음은 `exists: false` 행 |
| `root_authorized_keys` | 중 | `sshd.options.permit_root_login ne no`(`default_on: effective`) | `{ fact: ssh.root_key_count, op: eq, expected: 0 }` | manual — root의 홈이 선언 패턴 밖, 또는 다른 사용자의 홈이 그러함(`manual-home-outside.json`) |
| `ssh_key_quality` | 중 | — | `{ fact: ssh.dsa_key_count, op: eq, expected: 0 }`; `{ fact: ssh.rsa_keys, op: none, subject: fingerprint, where: { field: bits, op: lt, expected: "${min_rsa_bits}" } }`(기본 2048) | manual — 사용자의 홈이 선언 패턴 밖(`manual-home-outside.json`); `unparsed` 줄은 근거만이며 설명이 판정은 파싱된 키에 대한 것이라 말함 |

`root_authorized_keys` 게이트의 결과는 셋이고 모두 NOT_APPLICABLE: `PermitRootLogin no`가 유효; sshd
미설치(사실 `absent`); `effective` 홈이 `absent` — `sshd -T`/`-G`도 답하지 않고 파일도 키워드를 두지
않음(EL9의 비root 실행, `sshd_config`가 0600; 답하지 않는 소켓 활성화 데몬) — 그런 호스트에서 컴파일
기본값 `prohibit-password`는 키를 받고 컨트롤은 그것을 보지 못합니다. 그 누락은 받아들이고 설명에 적습니다.
대안 — root 로그인이 꺼진 채 root의 키를 판정 — 은 아무것도 쓸 수 없는 키에 대한 FAIL이기 때문입니다.
`command="…"`나 `restrict`를 가진 root 키는 `PermitRootLogin forced-commands-only`의 문서화된 모양; 게이트가
그것을 들이고 컨트롤은 FAIL로 읽으며, 두 번째 게이트 조건을 쓸 수 없으므로 설명이 그것은 waive할 FAIL이라
말합니다.

`params`: `max_inactive_days`(`int`, 35 — 인용 규칙의 값; `shadow(5)` 7번째 필드),
`allowed_nopasswd_principals`, `allowed_preload`, `allowed_runtime_group_members`(`list<string>`, `[]`),
`min_rsa_bits`(`int`, 2048 — OpenSSH 9.1부터 있는 `sshd_config(5)`의 `RequiredRSASize` 기본이 1024이고
muster는 더 엄격하다고 말함). fixture는 파라미터 override를 싣지 않으므로 목록 파라미터의 완화는 fixture가
아니라 `internal/check/eval_test.go`의 `Options.Params`로 증명(P-9); `int` 파라미터의 경계는 정확한 값의
fixture로 증명(P-9).

설명이 muster의 말로 하는 것: `account_inactivity_lock` — `useradd(8)`의 `INACTIVE`와 `shadow(5)`의
비활성 필드는 암호 만료 뒤 정해진 일수에 계정을 잠그는, 기본 시스템이 아무도 쓰지 않는 계정을 닫는
유일한 장치; 인용 규칙은 35일을 요구; root도 다른 계정처럼 덮임; stock 호스트는 FAIL. `sudo_nopasswd_all`
— 어떤 명령이든 어떤 사용자로든 암호 없이 도는 principal은 한 단계 더 거친 root; 암호가 있는
`%sudo`/`%wheel` 줄은 배포 상태이고 통과; cloud-init의 `NOPASSWD:ALL`은 실패하며,
`allowed_nopasswd_principals`가 이미지의 서비스 계정을 의도적으로 적는 자리. `file_capabilities_declared`
— `capabilities(7)`: 파일 capability는 setuid 비트 없이 실행파일에 root 힘의 한 조각을 주고, 패키지가 —
rpm 헤더나 `postinst`에서 — 선언하지 않은 것은 아무도 모르는 setuid 바이너리; setuid 컨트롤의 쌍.
`root_unit_exec_writable` — root로 도는 서비스는 다음 시작에 경로가 가리키는 무엇이든 실행하고; 비root
사용자가 다시 쓸 수 있는 파일이나 편집할 수 있는 유닛 파일은 그 시작을 그들에게 넘김; muster가 읽지
못한 유닛 파일은 살펴볼 일. `ld_so_preload_empty` — `ld.so(8)`: 여기 적힌 라이브러리는 호스트의 동적
링크된 모든 프로그램에, root의 것도 포함해, 로드됨; stock 호스트에 파일은 없고 어떤 항목이든 최소한
살펴볼 일이라 기본 allowlist는 빔. `container_runtime_access` — 런타임의 API 소켓은 어떤 마운트와 어떤
capability로든 컨테이너를 만들고; 거기 쓸 수 있는 그룹은 root 그룹이며 런타임 자체 문서가 그렇게
말함(docker의 설치 후 안내가 `docker` 그룹을 root 동등이라 부름); GitHub 러너는 FAIL을 읽음.
`root_authorized_keys` — root 파일의 키는 `PermitRootLogin`이 키를 허용하는 곳 어디서든 암호 프롬프트
없는 root 로그인(`prohibit-password`가 정확히 그것을 허용); root 로그인이 꺼져 있을 때, sshd가 없을 때,
설정을 읽을 수 없을 때 NOT_APPLICABLE; `authorized_keys2`는 모든 릴리스에서 셈. `ssh_key_quality` —
OpenSSH는 7.0에서 DSA를 실행 시 기본 비활성화하고, 9.8에서 기본 빌드에서 빼고, 10.0에서 제거했으므로(EL9의
9.9p1은 아직 넣어 빌드함) `ssh-dss` 줄은 대부분의 서버에서 죽은 무게이고 아직 받는 서버에선 다운그레이드
표적; 2048비트 아래 RSA 키는 OpenSSH 자체 `ssh-keygen(1)`이 2014년부터
기본으로 만든 크기 아래; 인증서와 `sk-*` 키는 기록만 하고 판정하지 않음.

## 5. 환경 (P-8)

- **root.** 전부 답합니다. 새 명령 하나(`list-units`), 바뀐 명령 하나(rpm 질의의 `%{FILECAPS}` 열). walk의
  xattr 패스는 `--deep` 아래서만 돌고 실행파일만 엽니다; 계획의 첫 과제가 lab(Ubuntu 22.04)과 EL9
  이미지에서 재고 늘어난 시간을 러너의 15m 예산 대비 기록.
- **비root.** `accounts.login_capable` — `/etc/shadow`는 root 전용, `denied`(C3), 컨트롤은 ERROR;
  `accounts.useradd.inactive`는 파일이 0644인 곳(Debian/Ubuntu, 측정된 Rocky 9)에서 답하고 릴리스가 0600으로
  배포하는 곳에서 `denied` — 행이 아니라 matrix `_notes` 항목; `accounts.lastlog`는 답함(0664). `sudo.*` 규칙 leaf 넷은 `denied`(`/etc/sudoers`는 0440).
  `units.*`는 답함: 유닛 파일은 world-readable, `list-units`는 권한 불필요, 실행파일은 stat 가능; root
  전용 drop-in은 `units.exec_writable`을 그것을 적은 `absent`로(root 때처럼 MANUAL). `ssh.*`: `/root`가
  0700이라 행과 세 카운트가 `denied`; `ssh_key_quality`는 그것을 적은 ERROR, `root_authorized_keys`는
  게이트를 읽을 수 있는 곳(Ubuntu의 `sshd_config`는 0644)에서 ERROR, 없는 곳(EL9)에서 NOT_APPLICABLE.
  `privilege.*`는 podman 소켓 디렉터리가 없는 곳에서 전부 답함. capability matrix의 `nonroot.denied` 행에
  키 여덟 — `accounts.login_capable`, `sudo.rules`, `sudo.nopasswd_all`, `sudo.authenticate_disabled`,
  `sudo.rules_unresolved`, `ssh.root_key_count`, `ssh.dsa_key_count`, `ssh.rsa_keys` — 가 더해지고;
  `ssh.authorized_keys` 자체는 읽지 못한 행에 `read_status: denied`를 둔 채 `ok`로 남음(`_notes` 항목이
  그렇게 말함); `privilege.ld_so_preload`는 답하고; `privilege.runtime_sockets`와
  `privilege.runtime_group_members`는 비root 실행이 살필 수 없는 런타임 소켓이 있는 어느 호스트에서든 —
  랩에서 측정된 `/run/docker.sock`(root:docker 0660), `/run/podman`(0700) — `denied`로 읽고, 하나도 없는
  곳에서만 온전히 답함(사실이며 matrix 행은 아님); 비root CI 잡이 행을 증명.
- **컨테이너.** 모든 beyond 컨트롤은 게이트로 NOT_APPLICABLE. 수집기는 그래도 완료해 `run.complete`가
  참이어야 함: `units`는 일반 이미지에서 `unsupported`(`systemctl` 없음; R220이 답한 것으로 셈), init
  이미지에서 `ok`(거기선 systemd가 PID 1), `privilege`는 소켓을 못 찾음(`exists: false` 행), 파일 리더는
  파일을 읽음. 다섯 컨테이너 잡의 기존 `run.complete` 단계가 덮음; `no-systemd.unsupported` matrix 행에
  `units.*` 키 셋이 더해짐.
- **systemd 없음.** `units.*` `unsupported` → `root_unit_exec_writable`은 `env.has_systemd`로
  NOT_APPLICABLE. 다른 것은 의존하지 않음.
- **릴리스.** lastlog: Ubuntu 22.04와 24.04, EL9, Debian 12에 있음(shadow < 4.15); Debian 13 / Ubuntu
  24.10부터 없음. capability 선언: EL9는 rpm `%{FILECAPS}`, dpkg 가족은 `postinst` — 참조 목록 없음, 출처
  없는 릴리스 없음. `INACTIVE`: 셋 다 -1(EL은 쓰고 Ubuntu는 주석) — stock FAIL. sudoers: EL `%wheel
  ALL=(ALL) ALL`, Ubuntu `%sudo ALL=(ALL:ALL) ALL` — PASS; cloud-init의 `90-cloud-init-users`와 GitHub
  러너의 `runner` — FAIL. OpenSSH: 22.04는 8.9, 24.04는 9.6, EL9는 8.7이고 뒤 마이너에서 9.9로 리베이스 — 모두 실행 시
  기본으로 DSA를 거부하므로(EL9 빌드에는 아직 들어 있음) 컨트롤이 표시하는 `ssh-dss` 줄은 관리자가
  다시 켜지 않았다면 서버가 무시하는 것; `RequiredRSASize`는 9.1부터(24.04만), 기본
  1024; EL은 `AuthorizedKeysFile`을 첫 기본값 하나로 둠.
- **Stock 스냅샷.** `controls/testdata/_hosts/ubuntu-22.04-stock.json`과 `el9-stock.json`에 새 키를
  채우고(EL9 스냅샷은 빠져 있던 walk와 sshd 모양을 얻어 표가 아홉 행에서 열일곱 행으로 자람);
  `hosts_test.go`가 각 여덟 행을 고정: `account_inactivity_lock` FAIL, `sudo_nopasswd_all` PASS,
  `file_capabilities_declared` PASS(Ubuntu: `postinst`가 선언한 파일 넷; EL9: `%{FILECAPS}`가 선언한
  `arping`, `clockdiff`, `newuidmap`, `newgidmap` — 거기서 `ping`은 capability가 없음, V-58), `root_unit_exec_writable` PASS, `ld_so_preload_empty` PASS, `container_runtime_access` PASS(소켓
  없음), `root_authorized_keys` PASS(게이트 성립 — `prohibit-password` — 키 0), `ssh_key_quality` PASS.

## 6. 테스트, CI, 문서 (P-9 … P-12)

**P-9 fixture와 mutant.** 컨트롤마다: 절마다 `pass-*.json`과 `fail-*.json`, `na-container.json`, 추가
게이트마다 `na-*.json`(`na-no-sudo.json`, `na-no-systemd.json`, `na-root-login-off.json`,
`na-sshd-absent.json`), 표가 이름 붙인 곳에 `manual-*.json`, 수집기가 쓰는 비root 모양의
`error-*.json`(읽기가 실패한 leaf의 `denied`). 뮤테이션 생성기가 찔러보는 `int` 경계(`expected ±1`,
파라미터 기본값 ±1): `pass-inactive-exactly-35.json`(`inactive: 35`인 행과 `useradd.inactive: 35`),
`fail-inactive-36.json`, `pass-useradd-inactive-0.json`, `pass-rsa-2048.json`, `fail-rsa-2047.json`,
`fail-rsa-1024.json`. 목록 파라미터는 기본이 `[]`라 mutant도 fixture도 없음; 완화는 목록 파라미터마다
`eval_test.go` 도출 행 하나(`Options.Params`로 principal / 라이브러리 / 멤버를 적고 PASS를 기대). 모든
fixture는 `synthetic: true`, 컨트롤이 부르는 키 전부 존재, 판정 행마다 모든 필드(원칙 3). `_mutants.yaml`
행: `ld_so_preload_empty`의 `absent_means → pass | not_applicable | manual` 행 셋만(없는 파일은 `ok []`, 그
밖의 실패는 하드 상태 — leaf는 결코 `absent`가 아님); 다른 모든 컨트롤은 fixture로 `absent`에 닿음 —
`fail-no-passwd.json`(`account_inactivity_lock`), `manual-no-package-db.json`(`file_capabilities_declared`),
`fail-no-group.json`(`container_runtime_access`), 그리고 MANUAL 컨트롤 넷의 `manual-*` fixture. 뮤테이션
테스트: 생존 0.

**P-10 파서와 퍼즈 대상.** `[]byte` 진입점마다 단위 테스트와 시드가 있는
`Fuzz<Name>`(`TestEveryParserHasAFuzzTarget`가 강제): `parseSudoers`(alias 중첩 깊이 8, 순환, 미정의
alias, `#include` 대 `#uid`, `#uid` 줄의 이음, 태그와 runas 상속, `:` privilege 구분자, 다중 principal
목록, `ALL` principal, `%:` 그룹, `ALL, !cmd`, 뒤 줄이 이기는 `Defaults` 범위), `parseLastlog`(두 레코드
크기, 짧은 꼬리, 미래 시각, 0 레코드, 상한 너머 uid), `parseAuthorizedKeys`(쉼표 있는 인용 옵션,
`restrict`, 선행 0이 있고 없는 RSA modulus, ecdsa 곡선, `sk-*`, 인증서, 맞지 않는 안쪽 유형, 깨진 base64 →
`unparsed`, 상한보다 긴 줄), `parseUnitFile`과 그 `Exec*` 병합기(섹션, 접두, 인용, drop-in의 빈
`ExecStart=` 초기화, drop-in의 `User=`, `User=0`, `%i` 토큰), `decodeVfsCap`(v1, v2, rootid 있는 v3,
잘린 입력, 모르는 버전, 표 너머 인덱스), `parseListUnits`, `parsePostinstSetcap`(세 형식, 주석 속
`setcap`), `parseUseraddDefaults`. `decodeACL`은 재사용.

**P-11 오라클.** lab root와 CI root 잡(`MUSTER_ORACLE=1`)에서 모든 쌍은 guard 아래 in-process로 돌고
호스트 설정에 아무것도 쓰지 않습니다: units 쌍은 범위 안 유닛 표본 다섯의 `ExecStart` 첫 토큰과
`User`를 `systemctl show -p ExecStart,User,UnitFileState`와 비교; keys 쌍은 **파서 오라클** —
`t.TempDir()` 아래 RSA-2048 하나, ed25519 하나, `ssh-keygen -t dsa`가 아직 되는 곳에선 DSA 하나를 만들고,
옵션 있는 `authorized_keys`를 거기 쓰고, 파일 바이트를 `parseAuthorizedKeys`에 넘겨 유형·비트·지문을
`ssh-keygen -l -f`와 비교한 뒤 임시 디렉터리를 놓아둠 — 선언된 경로 아래는 건드리지 않고 키 재료는
스냅샷이나 아티팩트에 닿지 않음; lastlog 쌍은 uid 0과 호출 사용자의 `accounts.lastlog`를 `lastlog
-u`와 비교하며 `/usr/bin/lastlog`가 없을 때만(init 컨테이너) skip하고 러너에선 결코 skip하지 않음;
capabilities 쌍은 `Include: ["/usr"]`와 5분 예산으로 walk를 in-process로 돌려 그 `walk.capabilities` 행을
`getcap -r /usr`와 (path, 정규 caps) 집합으로 비교하며 `/usr/sbin/getcap`이 없을 때만 skip. sudoers 쌍은
검증만: `visudo -c -f /etc/sudoers`(include 체인 전체를 검사)가 0으로 끝나야 하고, 러너에서 수집기의
`rules_unresolved`는 0이어야 함 — 정책 비교엔 `sudo -l`이 필요하고 원칙 5가 그것을 배제함. 오라클
파일의 규칙 2는 "아무것도 쓰지 않는다"에서 "호스트 설정에 아무것도 쓰지 않는다"로 고쳐 씁니다.

**P-12 CI와 문서.** root 잡, "collect as root" **전에**: `setcap`은 러너 이미지에 있음(단계가 확인;
없으면 `apt-get install -y libcap2-bin`), `/bin/true`를 `/usr/local/bin/muster-cap-probe`(걷는 경로,
`.github/walk-excludes` 밖)로 복사해 `setcap cap_net_raw+ep`; 스냅샷 뒤 `walk.capabilities`에 `reference:
unpackaged`, `package_declared: false`로 실리는지 확인; `if: always()` 단계가 제거. `privilege.ld_so_preload`가
`ok` 빈 목록, `sudo.nopasswd_all`이 `["runner"]`, `privilege.runtime_group_members`가 `docker`의 `runner`를
적는지(둘 다 러너 이미지에서 예상; 첫 실행이 확인하고 이미지가 다르면 단계를 고침),
`accounts.useradd.inactive`가 -1인지 확인; "check the root snapshot" 단계는 `test $code -ne 2`를
유지(exit 1이 예상: `sudo_nopasswd_all`, `container_runtime_access`, `account_inactivity_lock`이 거기서
정직하게 FAIL). 비root 잡: 새 denied 키 여덟이 matrix 행과 같음. 컨테이너 잡: 지금처럼 `run.complete` 참;
일반 이미지의 `no-systemd.unsupported` 행에 `units.*`. 잊기 쉬운 산출물, 이름을 적음:
`cmd/muster/controls_test.go`의 `ok: 104 controls`(세 곳); `cmd/muster/e2e_test.go`의 전수 상태 표와
`testdata/full-pass.json` / `full-fail.json`에 여덟(deep 게이트 컨트롤은 `package_files_unmodified`처럼
거기서 MANUAL); `hosts_test.go`의 EL9 길이 검사(17); 머지 전 `examples.yml`로 `examples/` 갱신;
`docs/reference/coverage.md` 재생성.

문서: 이 스펙(EN/KO); 계획(EN); 메인 설계에 **D31 — root 밖에 놓인 root의 힘은 한 컨트롤 가족이며,
각각 읽은 대로 판정하고 `params`나 waiver로만 완화한다.** Stage 3C-2a는 그런 경로 여섯 — 선언되지 않은
파일 capability, 비root 사용자가 다시 쓸 수 있는 root 서비스의 실행파일, `ld.so.preload` 항목, 런타임
소켓의 그룹, sudoers의 암호 없는 `ALL`, 비활성 정책이 덮지 않는 계정 — 과 그 옆의 키 컨트롤 둘을
더한다; muster가 결정하는 파일을 읽지 못한 곳에서 컨트롤은 경로를 적은 MANUAL(C4)이고, 호스트가 배포된
그대로인 곳에서 판정은 배포 상태의 것이며 FAIL도 포함한다. 되돌림: 새 root 동등 경로는 이 가족의 행이지
새 규칙이 아니다. §10.2는 "3C-2a (merged): privilege — … then 3C-2b: …"로 재라벨하고, 그 3C-2 목록에서
"root's `PATH`"를 뺌(그것은 `root_home_and_path`)과 함께 휴면 계정은 정책으로 판정하고 이력은 근거라고
말함. CLAUDE.md에 `## Privilege (stage 3C-2a)`(sudoers 깊이와 unresolved → MANUAL 규칙, walk의 실행파일만
xattr 패스와 그 `walk.skipped` 이유 둘, capability 선언 출처 둘, lastlog 레코드 크기, `list-units` 명령);
README/README.ko 상태와 로드맵; CHANGELOG Controls(여덟, 세트 버전, stock FAIL), Collectors(확장 셋, 새 것
셋, `ReadDir` 옵션, rpm 질의 열), Tooling(D31, matrix 행, 오라클); `docs/reference/coverage.md`;
`docs/reference/capability-matrix.json`(`nonroot.denied`와 `no-systemd.unsupported` 행,
`useradd.inactive` 노트).

## 7. 사실이 아닌 것

수집하지 않으므로 계획이 더하지 않는 것: `sudo`/`wheel` 멤버(U-63 가족과 `accounts.admin_group_members`가
이미 실음); `sudo -l` 출력; 실행파일 아닌 것의 ACL(이미 `acl_entries`가 있는 고정 경로 너머); 키 본문;
`wtmp`와 `btmp`; `/var/log/auth.log` 내용; `.wants` 링크의 대상; 유닛의 환경; `Host_Alias` 정의;
`lastlog2.db`와 `wtmp.db`; 릴리스별 capability 참조 목록.

## 8. 파킹

- 판정으로서의 ACL, walk에서 실행파일 아닌 것의 ACL.
- 판정으로서의 실제 휴면 계정 목록; `lastlog2` / `wtmpdb` 리더(sqlite).
- 특정 명령의 `NOPASSWD`; user specification의 호스트 필드; `Host_Alias`; `Defaults@host`와
  `Defaults!command` 범위; `sudoers` LDAP(`sudoers.ldap(5)`).
- 다른 경로로 설정된 `AuthorizedKeysFile`(과 `authorized_keys2`를 셀지 결정하기 위해 유효값을 읽는 것);
  `AuthorizedKeysCommand`; `from=` / `restrict` 없는 일반 사용자의 키; 인증 기관(`TrustedUserCAKeys`);
  인증서 키 디코드.
- alias 이름 아래 놓인 drop-in(`ssh.service`에 대한 `sshd.service.d`); `User=` 없는 `DynamicUser=`(root로
  읽음 — 최악이 false FAIL); split-`/usr` 호스트(`/lib/systemd/system`은 검색 경로에 없음; 지원 릴리스에
  split-`/usr`는 없음); xattr 패스를 포함한 RPM 가족의 walk 비용(거기선 모든 `.so`가 0755 — EL VM이 생길
  때까지 미측정, 컨테이너는 자기 overlay 루트를 걷지 못함).
- enabled도 active도 아닌 서비스; `.socket`, `.timer`, `.path` 유닛의 실행파일; 실행파일 뒤에 쓰기 가능한
  스크립트를 부르는 `ExecStart` 인자(인터프리터 뒤의 경로); 상대 첫 토큰에 대한 systemd의 검색 경로.
- rootless podman의 소켓; `/etc/security/access.conf`; `pam_wheel`; U-45 너머의 `su` 제한.
- 3C-2b: process 수집기, 삭제된 실행파일로 도는 프로세스, 노출 교차 점검(방화벽 confidence full에서만),
  네트워크 sysctl, `packages.verify.modified`와 walk 패키지 표의 join.
