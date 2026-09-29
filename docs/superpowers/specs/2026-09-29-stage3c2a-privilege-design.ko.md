# Stage 3C-2a — privilege: root가 아닌 채 root의 힘을 가진 것들

*[English](2026-09-29-stage3c2a-privilege-design.md) · 한국어*

이 문서는 muster 계획 3C-2a의 설계입니다: 3C-1 설계(`2026-09-23-stage3c1-audit-integrity-design.md`
§8)가 **3C-2 "exposure and privilege"** 로 남겨둔 것의 앞 절반. 2026-09-29에 그 절반을 다시 주제로
나눴습니다: **3C-2a "privilege"** — 어느 계정·파일·그룹이 root가 아닌 채 root의 힘을 갖는가 — 와
**3C-2b "exposure"** — process 수집기, 삭제된 실행파일로 도는 프로세스, socket → process → package →
firewall 교차 점검, 3B가 파킹한 네트워크 sysctl. 이 문서는 3C-2a만 다루고, 3C-2b는 3C-2a가 머지된 뒤
자기 설계를 갖습니다. 결정은 P-1 … P-12로 번호를 붙이고 계획을 구속합니다. 여기의 모든 점검은 1차
출처 — `shadow(5)`, `useradd(8)`, `lastlog(8)`, `sudoers(5)`, `capabilities(7)`, `systemd.service(5)`,
`systemd.unit(5)`, `ld.so(8)`, `sshd(8)`, `ssh-keygen(1)`, `acl(5)` — 에서 muster의 말로 쓰였고, CIS
권고 번호를 싣지 않으며, 벤치마크 본문을 재생산하지 않습니다(메인 설계 §11, D04).

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
root의 authorized keys, SSH 키 품질 — 확장 수집기 셋(`accounts`, `files_sudo`, `walk`)과 새 수집기
셋(`units`, `sshkeys`, `privilege`)이 먹입니다. 3C-2a 뒤 컨트롤 세트는 104개(67항목에 68개는 그대로, beyond
36개), `controls/VERSION`은 `kisa-unix-2026+2026.09.29`, `schema_version`은 그대로(키와 record 필드가
추가되고 바뀐 것은 없음; 메인 §5.7). `tools/suidindex` 확장 하나가 공개 이미지가 배포하는 파일
capability를 기록해, dpkg 호스트도 setuid 비트처럼 capability의 참조를 갖게 합니다.

범위 밖(계획이 흘러가지 않게 이름을 적음): 3C-2b 전부(위); root의 `PATH` — guide 컨트롤
`root_home_and_path`가 이미 `env.shell.root_path_entries`의 `.`과 world-writable 항목을 판정하며,
로드맵의 "root's PATH"는 그 컨트롤임; ACL 판정(기록만 — 일반 ACL에 등급을 매길 1차 출처가 없음); 실제
휴면 계정 목록의 판정(근거만, §3 P-1); 특정 명령의 `NOPASSWD`(근거만); 암호와 함께 주는 `ALL`
명령(stock의 `%wheel` / `%sudo` 줄); `Host_Alias`와 user specification의 호스트 필드(모든 줄을 이
호스트의 것으로 셈); enabled도 active도 아닌 서비스; 두 기본값 외 경로로 설정된
`AuthorizedKeysFile`; `from=`/`restrict` 없는 일반 사용자의 키(근거만); `/etc/security/access.conf`;
Ubuntu 24.04의 `lastlog2`·`wtmpdb` 데이터베이스(sqlite; 없으면 로그인 이력만 `absent`, 판정은 아님).

## 2. 3B·3C-1에서 이어받는 원칙

1. **판정은 호스트를 있는 그대로 읽습니다.** stock 클라우드 이미지는 `sudo_nopasswd_all` FAIL(cloud-init이
   자기 사용자에게 `NOPASSWD:ALL`을 씀), stock 세 릴리스 모두 `account_inactivity_lock` FAIL(`INACTIVE`
   미설정), 관리자가 `docker` 그룹에 있는 docker 호스트는 `container_runtime_access` FAIL. 설명이 각각
   그렇게 말합니다. 조직의 선택은 `params` 값이나 waiver로 기록되지, 컨트롤이 가정하지 않습니다(Q2).
2. **muster가 보지 못한 것은 경로를 적은 MANUAL이며, FAIL도 PASS도 아닙니다**(C4). 풀 수 없는 sudoers
   alias, 선언 밖 `@include`, 선언 패턴 밖의 홈 디렉터리 — 각각 사실을 이유와 함께 `absent`로 두고
   컨트롤은 MANUAL.
3. **절이 판정하는 leaf는 각자 키**(C2). `where`는 조건 하나이므로 복합 조건("로그인 가능하고
   미설정")은 수집기가 만든 목록이고, 관리자가 조정하는 임계값은 수집기가 기록한 필드와 비교되는
   `params` 값입니다(`inactive gt ${max_inactive_days}`).
4. **같은 입력, 같은 바이트.** 모든 목록은 정렬(`path`, `name`, `unit`)·상한이 있고, 상한에 닿으면 키에
   `truncated: true`. 키 본문은 스냅샷에 절대 들어가지 않습니다: 키는 유형, 비트 길이, SHA256 지문,
   옵션입니다.
5. **여기서 정책 엔진을 돌리는 것은 없습니다.** `sudo -l`은 정책을 평가하고 시도를 로그에 남기므로
   muster는 파일을 파싱합니다; `visudo -c`는 검증만 하며 오라클의 도구이지 수집기의 것이 아닙니다.
   새 명령은 고정 인자의 `systemctl list-units` 하나.

## 3. 사실과 수집기 (P-1 … P-6)

새 레지스트리 키 20개(`accounts.*` 3, `sudo.*` 4, `walk.*` 3, `units.*` 3, `ssh.*` 4, `privilege.*` 3,
근거 전용 목록 포함), 전부 `since: 1`, 스키마 버전은 그대로. 민감도는 달리 말하지 않으면 `public`.

### P-1 — `accounts`에 비활성 정책과 로그인 이력

shadow 필드는 이미 읽습니다: `accounts.users` 행이 `inactive`(7번째 필드, 비어 있으면 -1)와
`expire`(8번째)를 싣습니다. leaf 셋을 더합니다.

- `accounts.login_capable` — `list<record>` `{name, uid, inactive, expire, inactive_unset}`: 비활성
  정책이 덮어야 하는 계정 — 시스템 계정이 아니고(`system` false 또는 uid 0), 셸이 `/etc/shells`에 있고,
  암호 상태가 `locked`가 아닌 것. `inactive_unset`은 `inactive == -1`. 판정용 부분집합(원칙 3);
  `accounts.users`는 그대로 전체. `name` 정렬. `/etc/shadow`를 못 읽었으면 읽기 상태(C3): 정책을 판정할
  수 없고 비root 읽기는 `denied`.
- `accounts.useradd.inactive` — `int`: `/etc/default/useradd`(`useradd -D`의 파일)의 `INACTIVE` 값, 새
  계정에서 암호 만료 뒤 계정이 비활성화되기까지의 일수; 줄이 없거나 주석이거나 파일이 없으면 -1(이유가
  어느 쪽인지 적음 — `useradd(8)`은 셋 다 "never"로 봄). 파일이 있는데 못 읽으면 읽기 상태(C3). EL은
  `INACTIVE=-1`을 써서 배포하고 Ubuntu는 줄을 주석으로 배포; 둘 다 -1.
- `accounts.lastlog` — `list<record>` `{name, uid, last_login, line, host}`, 근거 전용, `sensitivity:
  internal`: `/var/log/lastlog`을 `ReadFileBinary`로 읽음(uid마다 292바이트 레코드 — `int32 ll_time`,
  `char ll_line[32]`, `char ll_host[256]` — uid로 색인되어 희소 파일은 대부분 구멍이므로
  `accounts.users`의 uid만 디코드); `last_login`은 RFC 3339 UTC, 레코드가 0이면 `""`("로그인한 적
  없음"). 상한 2000행. Ubuntu 24.04에선 없음(`shadow` 4.15가 `lastlog`를 버리고 `lastlog2`가 muster가
  모델링하지 않는 sqlite 데이터베이스를 둠) — 그 이유를 적은 `absent`, 컨트롤은 읽지 않음. 파일은 0664
  `root:utmp`라 비root 실행도 읽음.

### P-2 — `files_sudo`에 규칙

sudo 리더는 이미 체인을 걷습니다 — `/etc/sudoers`, `@includedir` / `#includedir` 디렉터리, 선언된
경로의 `@include` — 그리고 include가 선언 밖을 가리키거나 drop-in이 심볼릭 링크면 경로를 적은
`absent`로 멈춥니다(3C-1, J-40). 같은 걷기가 이제 읽는 모든 줄에서 두 가지를 더 파싱합니다(`sudoers(5)`):
alias 정의(`User_Alias`, `Runas_Alias`, `Cmnd_Alias`; `Host_Alias`는 읽고 무시)와 user
specification(`principal host = (runas) tags: commands`). 이음 줄(`\`)은 파싱 전에 합치고,
`#include`/`#includedir`는 지시자, `#123`은 uid, `%#123`은 gid, `%group`은 그룹, `+netgroup`은
netgroup. alias는 치환으로 깊이 8까지 풀고; 순환, 미정의 alias, netgroup은 규칙을 `resolved: false`로
둡니다.

- `sudo.rules` — `list<record>` `{file, line, principal, kind, runas, nopasswd, commands, resolved}`,
  `kind` ∈ user | group | uid | gid | alias | netgroup(해석 뒤 alias는 멤버마다 한 행으로 펼쳐지고
  `kind`는 멤버의 것; `alias`와 `netgroup`은 풀지 못한 행에만 남음); `nopasswd`는 `NOPASSWD:` 태그가
  명령 목록에 적용될 때 true(태그는 뒤의 명령들에 다른 태그가 나올 때까지 적용; `PASSWD:`는 되돌림);
  `commands`는 푼 명령 목록, `ALL`은 `ALL`로. 근거, `sensitivity: internal`, 상한 2000행, `file`, `line`
  정렬.
- `sudo.nopasswd_all` — `list<string>`: `root`(와 `#0`)가 아닌 principal 중 `NOPASSWD:` 아래 명령으로
  `ALL`을 받는 것, runas는 무엇이든 — cloud-init `90-cloud-init-users`의 `ubuntu`, `ALL`로 펼쳐지는
  alias의 `%admins`. 정렬, 중복 제거.
- `sudo.authenticate_disabled` — `bool`: 범위 없는 `Defaults !authenticate`, 또는 `!authenticate`를 실은
  `Defaults:user` / `Defaults:%group` / `Defaults:User_Alias` 줄. `Defaults@host`와 `Defaults!command`
  범위는 읽되 이 값을 세우지 않음(범위 없음도, principal에 관한 것도 아님); 지금처럼
  `sudo.defaults.scoped_count`에 셈.
- `sudo.rules_unresolved` — `int`, `resolved: false`인 규칙 수.

`sudo.rules_unresolved`가 0이 아니면 `sudo.nopasswd_all`과 `sudo.authenticate_disabled`는 `absent`("규칙
N개를 풀지 못함: ALIAS, +netgroup — 답에 그것이 필요함")이고 컨트롤은 MANUAL(원칙 2). 체인을 다 읽지
못했으면(3C-1의 두 경우) 네 leaf 모두 `sudo.log.*`처럼 경로를 적은 `absent`. sudo가 없으면 `sudo.rules`는
빈 목록, `nopasswd_all` 빈 목록, `authenticate_disabled` false, `rules_unresolved` 0 — 컨트롤은 어차피
`sudo.installed`에 게이트.

### P-3 — walk에 파일 capability와 ACL

walk는 엔트리마다 `statx` 한 번으로 방문합니다. **실행 비트가 하나라도 있는 일반 파일**(`mode & 0o111
!= 0`)은 이제 디렉터리 fd에서 엔트리를 열고 — `openat(dirfd, name,
O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)`, 링크를 따라가지도 막히지도 않게 — `flistxattr`로 확장
속성을 나열하고, `security.capability`와 `system.posix_acl_access`가 나열되면 `fgetxattr`로 읽고 닫습니다.
실행파일만 엽니다: 아무도 실행할 수 없는 파일의 capability는 힘이 없고(`capabilities(7)`), 모든 일반
파일을 열면 walk의 시스템 콜이 두 배가 되는 반면 실행파일만 열면 1/10이 늘어납니다. 열기의
`EACCES`(소유자 읽기 없는 모드, root에겐 제한적 LSM 아래서만)는 경로를 `walk.skipped`에 `xattr_denied`
이유로 적고 넘어감; walk는 xattr 때문에 멈추지 않습니다.

- `walk.capabilities` — `list<record>` `{path, caps, effective, rootid, package, package_declared,
  declared_caps, reference}`: `caps`는 VFS capability xattr(버전 2와 3 — 3은 그 capability가 유효한 사용자
  네임스페이스 root를 `rootid`로 가짐; muster가 모르는 버전은 `caps: ["unknown"]` 행이고 결코 error가
  아님)에서 디코드한 permitted ∪ inheritable 집합의 정렬된 이름; `effective`는 v2/v3의 effective 플래그;
  join 열은 `walk.suid_sgid`와 같음 — 소유 패키지, 그 패키지가 정확히 이 capability들을 선언하는지, 무엇을
  선언하는지, 그리고 같은 어휘의 `reference`(`rpm`: `rpm -q --dump`의 `%caps` 열; `list`: 릴리스 참조
  파일; `none`: 이 릴리스의 참조 없음). `reference`가 `none`인 행은 setuid 행처럼
  `walk.capabilities_unverified`로 가서, 아무도 보증할 수 없는 파일에 판정이 내려지지 않게 합니다. 둘 다
  `listCaps`(2000) 상한, `path` 정렬.
- `walk.acl_grants` — `list<record>` `{path, entries}`, 근거 전용: 접근 ACL이 모드가 주는 것 너머로
  named user/group에 쓰기나 실행을 주는 실행파일(mask 적용, `acl(5)`); `entries`는 `getfacl`
  표기(`user:alice:rwx`). 고정 경로 `acl_entries` 사실이 이미 쓰는 POSIX ACL 디코더로 디코드. 상한·정렬.
  읽는 컨트롤 없음(§1).

참조: `tools/suidindex`가 고정된 이미지마다 setuid `find` 옆에서 `getcap -r /`도 돌려 `caps`
목록(`{path, caps, package}`)을 `docs/reference/suid/<release>.json`에 쓰고; `-check`는 파일의 나머지처럼
비교합니다. 임베드된 `suid` 패키지가 join에 노출. rpm은 참조가 필요 없음: `%caps`가 패키지 헤더에 있음.
lab(Ubuntu 22.04)의 `getcap -r /usr`는 넷을 나열 — `cap_net_raw`의 `ping`과 `mtr-packet`, gstreamer의
`gst-ptp-helper`, `cap_sys_admin`을 포함한 집합의 snapd `snap-confine`; 전부 그 패키지의 `postinst`가
선언하는 것이고, stock 호스트에서 컨트롤이 PASS를 읽으려면 참조가 알아야 하는 것이 정확히 그것입니다.

### P-4 — `units` 수집기

`Reads`: `/etc/systemd/system/*.service`, `/run/systemd/system/*.service`,
`/usr/lib/systemd/system/*.service`, 같은 셋에 `*.service.d/*.conf`, 그리고 셋 아래 `*.wants/*`와
`*.requires/*`(`Readlink`로 읽음 — `.wants` 항목은 이름이 유닛인 심볼릭 링크; 대상은 따라가지 않음).
`Commands`: 하나, `systemctl list-units --type=service --state=active --plain --no-legend`, `services`가
`show` 호출을 선언하는 방식으로. `Needs: none`.

서비스는 enabled(세 트리 어디든 `.wants`/`.requires` 링크가 이름을 부름)이거나 active(`list-units`가
나열)일 때 **범위 안**입니다. 각각 유닛 파일을 systemd 우선순위(`/etc`, `/run`, `/usr/lib`)로 세 트리에서
찾고(`/etc`의 파일이 `/dev/null` 심볼릭 링크면 마스크이고 유닛은 범위 밖; 유닛 경로의 다른 심볼릭 링크는
따라가지 않음 — 행이 `unit_file: symlink`를 적고 유닛은 `unresolved`로 읽힘), 세 트리 전부의 `.d/*.conf`
drop-in을 systemd 순서로 합치고, `[Service]`에서 `User=`와 `Exec*=` 지시자(`ExecStart`, `ExecStartPre`,
`ExecStartPost`, `ExecCondition`, `ExecReload`, `ExecStop`, `ExecStopPost`)를 읽습니다. drop-in의 빈
`ExecStart=`는 `systemd.service(5)`가 말하듯 앞의 목록을 초기화. 각 지시자의 첫 토큰이 실행파일: 접두
문자 `@ - : + ! !!`를 벗기고(`systemd.service(5)` "Command lines"), 인용을 제거하며, 절대 경로가 아닌
토큰(systemd 239부터 허용, systemd 자체 검색 경로로 해석)은 `resolved: false`로 적고 판정하지 않음.
`User=`가 `root` 아닌 무엇으로 설정된 서비스는 범위 밖: 그 실행파일은 root의 힘 없이 돕니다.

- `units.root_services` — `list<record>` `{unit, enabled, active, user, files, exec}`: `files`는 읽은
  유닛 파일과 각 drop-in `{path, mode, uid, gid}`; `exec`는 `Exec*` 첫 토큰마다 한 행 `{directive, path,
  exists, mode, uid, gid, group_writable, other_writable, resolved}`, 경로의 `Stat`에서(경로의 심볼릭
  링크는 `kind: symlink`로 적고 따라가지 않음; 없는 파일은 `exists: false`). 근거, `sensitivity:
  internal`, 상한 500 유닛, `unit` 정렬.
- `units.exec_writable` — `list<record>` `{unit, path, why}`: 판정용 부분집합 — 소유 uid가 0이 아니거나,
  group-writable이거나, other-writable인 실행파일(`why` ∈ `owner`, `group_writable`, `other_writable`),
  그리고 같은 세 성질의 유닛 파일이나 drop-in(`why`에 `unit_file:` 접두). `unit`, `path` 정렬.
- `units.exec_unresolved` — `int`: `resolved: false`인 행 수와 심볼릭 링크였던 유닛 경로 수. 근거.

systemd가 없으면(`env.has_systemd` false, 또는 `systemctl`이 시작되지 못함, 또는 "System has not been
booted with systemd"라 답함) 세 leaf는 `unsupported`; 시간을 넘긴 `list-units`는 `timeout`, 그 밖의 0 아닌
종료는 코드를 적은 `error`(3C-1의 J-45 모양). 존재하지만 못 읽는 유닛 파일은 그 유닛의 행이 읽기 상태를
싣고 유닛은 writable로도 clean으로도 세지 않음 — 컨트롤의 `none` 절은 목록을 보고, 설명은 거부된 유닛
파일은 살펴볼 일이라고 말합니다.

### P-5 — `sshkeys` 수집기

`Reads`: `files_home`이 읽는 홈 디렉터리(선언 패턴 — `/home/*`, `/root`, accounts 쪽이 이미 나열하는
릴리스별 것)에 `/.ssh/authorized_keys`와 `/.ssh/authorized_keys2` — `sshd_config(5)`의
`AuthorizedKeysFile` 기본값 둘. `Needs: none`. 사용자는 `/etc/passwd`의 홈 경로가 있는 로컬 계정,
`files_home`이 고르는 대로; 선언 패턴 밖의 홈은 그 사용자 행을 경로와 함께 `unfollowed`로 둠(C4).

- `ssh.authorized_keys` — `list<record>` `{user, uid, path, exists, mode, owner_uid, keys, unparsed}`,
  `sensitivity: internal`: 존재하는 파일마다 한 행(그리고 파일 없는 사용자마다 `exists: false` 행 하나 —
  "키 없음"이 침묵이 아니라 읽기가 되게); `keys`는 `{line, type, bits, fingerprint, options, restricted}`
  목록 — `type`은 키 유형 단어(`ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-dss`, `sk-…`),
  `bits`는 `ssh-rsa`의 RSA modulus 길이, ecdsa의 곡선 크기, ed25519는 256, `ssh-dss`는 1024,
  `fingerprint`는 `SHA256:` + 디코드한 키 blob의 SHA-256 base64(`ssh-keygen -l`이 찍는 것), `options`는
  유형 앞의 옵션 단어들(`from="…"`, `command="…"`, `restrict`, `no-pty`, …)을 인용값 그대로,
  `restricted`는 `restrict`나 `from=`이 있으면 true; `unparsed`는 주석·빈 줄·파싱 가능한 키 어느 것도 아닌
  줄 수(깨진 base64 본문, 모르는 유형). 키 본문 자체는 절대 저장하지 않음. 파일당 200키, 500행 상한.
- `ssh.root_key_count` — `int`: root의 두 파일의 키 수. root의 홈이 선언 밖이거나 파일을 못 읽으면
  `absent`(C4/C3).
- `ssh.dsa_key_count` — `int`: 읽은 모든 파일의 `ssh-dss` 키 수.
- `ssh.rsa_keys` — `list<record>` `{user, path, line, bits, fingerprint}`: 모든 `ssh-rsa` 키, 컨트롤이
  `bits`를 파라미터와 비교하도록. `user`, `path`, `line` 정렬.

muster가 못 읽은 파일(비root 실행에서 다른 사용자의 0600 파일)은 그 행과 세 카운트에 읽기 상태를
둡니다: 구멍 난 인벤토리는 인벤토리가 아니며, 두 키 컨트롤의 비root 읽기는 거부를 적은 ERROR(3C-1의
감사 세부 컨트롤처럼).

### P-6 — `privilege` 수집기

`Reads`: `/etc/ld.so.preload`, `/etc/group`, 그리고 런타임 소켓 넷의 `Stat`. `Needs: none`.

- `privilege.ld_so_preload` — `list<string>`: `/etc/ld.so.preload`의 주석·빈 줄 아닌 항목(`ld.so(8)`: 줄마다
  라이브러리 하나, 공백 구분). 파일 없음은 `ok` 빈 목록 — 정상 상태; 있는데 못 읽으면 읽기 상태(C3).
- `privilege.runtime_sockets` — `list<record>` `{path, exists, mode, uid, gid, group, group_writable,
  other_writable}`: `/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/podman/podman.sock`,
  `/var/run/crio/crio.sock` — API가 root인 네 런타임의 제어 소켓(소켓에 쓸 수 있는 클라이언트는 privileged
  컨테이너를 띄울 수 있음). 없는 소켓은 `exists: false` 행. `group`은 gid로 `/etc/group`에서.
- `privilege.runtime_group_members` — `list<record>` `{group, member, uid, socket}`: 존재하고
  group-writable인 소켓마다 그 그룹의 uid ≠ 0 멤버 — `/etc/group`의 보조 멤버와 primary gid가 그 그룹인
  `/etc/passwd` 사용자 — (group, member)마다 한 행. `group`, `member` 정렬. 소켓이 없거나 모든 그룹이 비어
  있으면 빈 목록(lab의 `docker` 그룹이 그러함).

비root 실행도 셋을 다 읽음: `ld.so.preload`는 0644, `/etc/group`은 world-readable, `/run`은 stat 가능.

## 4. 컨트롤 (P-7)

컨트롤 여덟, `category: beyond`, id `muster.beyond.<name>`, 전부 `env.container eq none` 게이트; 3B와
3C-1의 mechanism/`absent_means` 관행이 적용됩니다. `references.stig` 항목은 커밋된 인덱스에서 찾았습니다:
비활성 규칙(RHEL-09-411050, UBTU-22-411035, UBTU-24-200260)과 재인증 규칙(RHEL-09-432025, UBTU-22-432010,
UBTU-24-300021); 나머지 여섯 컨트롤은 인용 규칙이 없어 설명에 1차 출처를 적은 muster 자체 등급을 답니다.
NIST는 인용 규칙의 매핑 합집합(`AC-2(3)`, `IA-4`, `IA-11`, `SC-11`, `CM-6`)이고, 인용 없는 여섯에는
`AC-6`.

| id | 중요도 | 추가 게이트 | 판정 | `absent_means` |
|---|---|---|---|---|
| `account_inactivity_lock` | 중 | — | `accounts.login_capable` `op: none, subject: name, where: {field: inactive_unset, op: eq, expected: true}`; `accounts.login_capable` `op: none, subject: name, where: {field: inactive, op: gt, expected: "${max_inactive_days}"}`; `accounts.useradd.inactive gte 0`; `accounts.useradd.inactive lte ${max_inactive_days}` | fail — shadow를 읽었고 답이 거기 있음; 세 릴리스의 stock 호스트는 FAIL(`INACTIVE` 미설정)이고 설명이 그렇게 말함 |
| `sudo_nopasswd_all` | 상 | `sudo.installed eq true` | `sudo.nopasswd_all` `op: none, subject: value, where: {field: value, op: not_in, expected: "${allowed_nopasswd_principals}"}`(기본 `[]`); `sudo.authenticate_disabled eq false` | manual — 체인을 다 읽지 못했거나 규칙을 풀지 못함: 빠진 줄이 태그를 실을 수 있음; stock 클라우드 이미지는 cloud-init 사용자로 FAIL |
| `file_capabilities_declared` | 상 | (deep 게이트: `walk.complete`) | `walk.capabilities` `op: none, subject: path, where: {field: package_declared, op: eq, expected: false}`; `walk.capabilities_unverified`는 근거 | fail — deep 게이트가 완료성 사실을 먼저 읽음; 안 돌았으면 MANUAL, 불완전이면 ERROR, 모든 walk 컨트롤처럼 |
| `root_unit_exec_writable` | 상 | `env.has_systemd eq true` | `units.exec_writable` `op: none, subject: path` | manual — 읽지 못한 유닛 파일(그 실행파일을 모름) |
| `ld_so_preload_empty` | 상 | — | `privilege.ld_so_preload` `op: none, subject: value, where: {field: value, op: not_in, expected: "${allowed_preload}"}`(기본 `[]`) | fail — 없는 파일은 빈 목록 |
| `container_runtime_access` | 상 | — | `privilege.runtime_sockets` `op: none, subject: path, where: {field: other_writable, op: eq, expected: true}`; `privilege.runtime_group_members` `op: none, subject: member, where: {field: member, op: not_in, expected: "${allowed_runtime_group_members}"}`(기본 `[]`) | fail — 소켓 없음은 빈 목록 |
| `root_authorized_keys` | 중 | `sshd.options.permit_root_login ne no`(`effective` 홈) | `ssh.root_key_count eq 0` | manual — root의 홈이 선언 밖, 또는 파일을 못 읽음 |
| `ssh_key_quality` | 중 | — | `ssh.dsa_key_count eq 0`; `ssh.rsa_keys` `op: none, subject: fingerprint, where: {field: bits, op: lt, expected: "${min_rsa_bits}"}`(기본 2048) | manual — 못 읽은 파일은 카운트를 `absent`로; `unparsed` 줄은 근거만이며 설명이 판정은 파싱된 키에 대한 것이라 말함 |

`params`: `max_inactive_days`(`int`, 35 — 인용 규칙의 값; `shadow(5)` 7번째 필드),
`allowed_nopasswd_principals`, `allowed_preload`, `allowed_runtime_group_members`(`list<string>`, `[]`),
`min_rsa_bits`(`int`, 2048 — `sshd_config(5)`의 `RequiredRSASize` 기본이 1024이고 muster는 더 엄격하다고
말함). 목록 파라미터의 fixture 규칙은 J-19: 배포 원소마다 pass fixture 하나, 목록 파라미터마다 완화를
보이는 `pass-allowlisted-*.json` 하나.

설명이 muster의 말로 하는 것: `account_inactivity_lock` — `useradd(8)`의 `INACTIVE`와 `shadow(5)`의
비활성 필드는 암호 만료 뒤 정해진 일수에 계정을 잠그는, 기본 시스템이 아무도 쓰지 않는 계정을 닫는
유일한 장치; 인용 규칙은 35일을 요구; stock 호스트는 FAIL. `sudo_nopasswd_all` — 어떤 명령이든 어떤
사용자로든 암호 없이 도는 principal은 한 단계 더 거친 root; 암호가 있는 `%sudo`/`%wheel` 줄은 배포
상태이고 통과; cloud-init의 `NOPASSWD:ALL`은 실패하며, `allowed_nopasswd_principals`가 이미지의 서비스
계정을 의도적으로 적는 자리. `file_capabilities_declared` — `capabilities(7)`: 파일 capability는 setuid
비트 없이 실행파일에 root 힘의 한 조각을 주고, 패키지가 선언하지 않은 것은 아무도 모르는 setuid
바이너리; setuid 컨트롤의 쌍. `root_unit_exec_writable` — root로 도는 서비스는 다음 시작에 경로가
가리키는 무엇이든 실행하고; 비root 사용자가 다시 쓸 수 있는 파일이나 편집할 수 있는 유닛 파일은 그
시작을 그들에게 넘김. `ld_so_preload_empty` — `ld.so(8)`: 여기 적힌 라이브러리는 호스트의 동적 링크된 모든
프로그램에, root의 것도 포함해, 로드됨; stock 호스트에 파일은 없고 어떤 항목이든 최소한 살펴볼 일이라
기본 allowlist는 빔. `container_runtime_access` — 런타임의 API 소켓은 어떤 마운트와 어떤 capability로든
컨테이너를 만들고; 거기 쓸 수 있는 그룹은 root 그룹이며 런타임 자체 문서가 그렇게 말함(docker의 설치 후
안내가 `docker` 그룹을 root 동등이라 부름). `root_authorized_keys` — root 파일의 키는 `PermitRootLogin`이
키를 허용하는 곳 어디서든 암호 프롬프트 없는 root 로그인(`prohibit-password`가 정확히 그것을 허용);
root 로그인이 꺼져 있으면 컨트롤은 NOT_APPLICABLE. `ssh_key_quality` — OpenSSH는 7.0에서 DSA를 기본
비활성화하고 9.8에서 제거했으므로 `ssh-dss` 줄은 잘해야 죽은 무게이고 오래된 서버에선 다운그레이드
표적; 2048비트 아래 RSA 키는 OpenSSH 자체 `ssh-keygen(1)`이 2014년부터 기본으로 만든 크기 아래.

## 5. 환경 (P-8)

- **root.** 전부 답합니다. 새 명령 하나(`list-units`). walk의 xattr 패스는 `--deep` 아래서만 돌고
  실행파일만 엽니다; 계획의 첫 과제가 lab(Ubuntu 22.04, 수십만 엔트리)과 러너(60만 엔트리, 15m 예산)에서
  재고 늘어난 시간을 기록 — 예상은 walk의 1/10.
- **비root.** `accounts.login_capable`과 `accounts.useradd.inactive` — `/etc/shadow`는 root 전용이므로
  앞은 `denied`(C3)이고 컨트롤은 ERROR; `useradd` 기본값은 world-readable이라 답함. `accounts.lastlog`는
  답함(0664). `sudo.*` 규칙 leaf 넷은 `denied`(`/etc/sudoers`는 0440). `units.*`는 답함: 유닛 파일은
  world-readable, `list-units`는 권한 불필요, 실행파일은 stat 가능; `/etc` 아래 root 전용 drop-in은 그
  유닛 행에 읽기 상태. `ssh.*`: 다른 사용자의 `.ssh`는 0700이라 행과 세 카운트가 `denied`이고 두 키
  컨트롤은 거부를 적은 ERROR. `privilege.*`는 전부 답함. capability matrix의 `nonroot.denied` 행에
  `accounts.login_capable`, `sudo.*` 규칙 leaf 넷, `ssh.authorized_keys`, `ssh.root_key_count`,
  `ssh.dsa_key_count`, `ssh.rsa_keys`가 더해지고; 비root CI 잡이 행을 증명.
- **컨테이너.** 모든 beyond 컨트롤은 게이트로 NOT_APPLICABLE. 수집기는 그래도 완료해 `run.complete`가
  참이어야 함: `units`는 `unsupported`(systemd 없음; R220이 답한 것으로 셈), `privilege`는 소켓을 못
  찾음(빈 목록), 파일 리더는 파일을 읽음. 다섯 컨테이너 잡의 기존 `run.complete` 단계가 덮음.
- **systemd 없음.** `units.*` `unsupported` → `root_unit_exec_writable`은 `env.has_systemd`로
  NOT_APPLICABLE. 다른 것은 의존하지 않음.
- **릴리스.** lastlog: Ubuntu 22.04와 EL9에 있고 24.04엔 없음. dpkg capability 참조: Ubuntu 22.04, 24.04,
  Debian 12의 고정 이미지에서 생성(`caps` 목록); rpm은 불필요; 참조 없는 릴리스는 `reference: none`이고
  그 행은 unverified 근거. `INACTIVE`: 셋 다 -1(EL은 쓰고 Ubuntu는 주석) — stock FAIL. sudoers: EL
  `%wheel ALL=(ALL) ALL`, Ubuntu `%sudo ALL=(ALL:ALL) ALL` — PASS; cloud-init의 `90-cloud-init-users` —
  FAIL. OpenSSH: 22.04는 8.9, 24.04는 9.6, EL9는 8.7 — 모두 기본으로 DSA를 거부하므로 컨트롤이 표시하는
  `ssh-dss` 줄은 서버가 이미 무시하는 것; `RequiredRSASize`는 9.1부터(24.04만), 기본 1024.
- **Stock 스냅샷.** `controls/testdata/_hosts/ubuntu-22.04-stock.json`과 `el9-stock.json`에 새 키를 채우고;
  `hosts_test.go`가 각 여덟 행을 고정: `account_inactivity_lock` FAIL, `sudo_nopasswd_all` PASS,
  `file_capabilities_declared` PASS(Ubuntu 넷은 선언됨; EL9 stock은 rpm이 선언한 `cap_net_raw`의
  `ping`), `root_unit_exec_writable` PASS, `ld_so_preload_empty` PASS, `container_runtime_access` PASS(소켓
  없음), `root_authorized_keys` PASS(게이트 성립 — `prohibit-password` — 키 0), `ssh_key_quality` PASS.

## 6. 테스트, CI, 문서 (P-9 … P-12)

**P-9 fixture와 mutant.** 컨트롤마다: 절마다·목록 파라미터 원소마다 `pass-*.json`, 절마다 `fail-*.json`,
`na-container.json`, 표가 manual이라 하는 곳에 `manual-*.json`(sudo: 선언 밖 include, 풀지 못한 alias;
root 키: 선언 밖 root 홈), 수집기가 쓰는 비root 모양의 `error-*.json`(읽기가 실패한 leaf의 `denied`). 모든
fixture는 `synthetic: true`, 컨트롤이 부르는 키 전부 존재. `_mutants.yaml` 행은 수집기 불변식 때문에 어느
fixture도 구별할 수 없는 mutant에만, 쓰기 전에 수집기의 `absent` 분기와 대조(3C-1의 X-1). 뮤테이션
테스트: 생존 0.

**P-10 파서와 퍼즈 대상.** `[]byte` 진입점마다 단위 테스트와 시드가 있는 `Fuzz<Name>`(`TestEveryParserHasAFuzzTarget`가
강제): `parseSudoers`(alias 중첩 깊이 8, 순환, 미정의 alias, `#include` 대 `#uid`, 이음 줄, 태그 전환,
`Defaults:` 범위), `parseLastlog`(292바이트 정렬, 짧은 꼬리, 미래 시각, 0 레코드),
`parseAuthorizedKeys`(쉼표 있는 인용 옵션, `restrict`, blob에서 RSA modulus 길이, ecdsa 곡선, 모르는
유형, 깨진 base64 → `unparsed`, 상한보다 긴 줄), `parseUnitFile`(섹션, `Exec*` 접두, 인용, drop-in의 빈
`ExecStart=` 초기화, drop-in의 `User=`), `decodeVfsCap`(v2, rootid 있는 v3, 잘린 입력, 모르는 버전),
`parseListUnits`. POSIX ACL 디코더는 재사용.

**P-11 오라클.** lab root와 CI root 잡(`MUSTER_ORACLE=1`)에서: units 쌍은 범위 안 유닛 표본 다섯의
`ExecStart` 첫 토큰과 `User`를 `systemctl show -p ExecStart,User,UnitFileState`와 비교; keys 쌍은
`$RUNNER_TEMP` / `/tmp` 아래 임시 홈에 RSA-2048 하나, ed25519 하나, `ssh-keygen`이 아직 만들 수 있는 곳에선
DSA 하나를 만들고, 옵션 있는 `authorized_keys`를 써서 유형/비트/지문을 `ssh-keygen -l -f`와 비교한 뒤
디렉터리를 삭제 — 키 재료는 스냅샷이나 아티팩트에 닿지 않음; lastlog 쌍은 uid 0과 호출 사용자의
`accounts.lastlog`를 `lastlog -u`와 비교(`lastlog`가 없는 곳 — 24.04 — 는 skip); capabilities 쌍은
`walk.capabilities`의 `/usr` 행을 `getcap -r /usr`와 (path, caps) 집합으로 비교(deep 실행만, root 잡의 기존
스냅샷). sudoers 쌍은 검증만: 수집기가 읽은 모든 파일에 `visudo -c -f`가 0으로 끝나야 하고, 러너에서
수집기의 `rules_unresolved`는 0이어야 함 — 정책 비교엔 `sudo -l`이 필요하고 원칙 5가 그것을 배제함.

**P-12 CI와 문서.** root 잡: `/bin/true`를 걷는 루트 아래 `$RUNNER_TEMP/muster-cap`으로 복사해 `setcap
cap_net_raw+ep`를 주고, deep 스냅샷의 `walk.capabilities`에 `package_declared: false`로 실리는지
확인(그 뒤 제거 — 스냅샷 뒤, 시드 단계 전, sshd 오라클 drop-in을 다루는 방식대로); `privilege.ld_so_preload`가
`ok` 빈 목록, `sudo.nopasswd_all`이 `["runner"]`(러너 이미지의 sudoers가 자기 사용자에게 `NOPASSWD:ALL`을
줄 것으로 예상 — 예시가 보일 정직한 FAIL; 첫 실행이 예상을 확인하고 이미지가 다르면 단계를 고침),
`accounts.useradd.inactive`가 -1인지 확인. 비root 잡: 새 denied 키 아홉이 matrix 행과 같음. 컨테이너 잡:
지금처럼 `run.complete` 참. `tools/suidindex`는 확장해 maintainer가 dpkg 릴리스 셋에 대해 한 번 돌리고;
커밋된 `caps` 목록이 CI와 join이 읽는 것; `make suidindex-check`가 비교.

문서: 이 스펙(EN/KO); 계획(EN); 메인 설계에 **D31**("root 밖의 root 힘은 한 컨트롤 가족이다: 선언되지
않은 파일 capability, 비root 사용자가 다시 쓸 수 있는 root 서비스의 실행파일, `ld.so.preload` 항목, 런타임
소켓의 그룹, sudoers의 암호 없는 `ALL`, 비활성 정책이 덮지 않는 계정 — 각각 읽은 대로 판정하고 `params`나
waiver로만 완화하며; muster가 읽지 못한 것은 경로를 적은 MANUAL. 되돌림: 새 root 동등 경로는 이 가족의
행이지 새 규칙이 아니다.")과 §10.2를 "3C-2a (merged) … then 3C-2b"로 재라벨; CLAUDE.md에 `## Privilege
(stage 3C-2a)`(sudoers 깊이와 unresolved → MANUAL 규칙, walk의 실행파일만 xattr 패스, lastlog2 미모델,
`list-units` 명령); README/README.ko 상태와 로드맵; CHANGELOG Controls(여덟, 세트 버전, stock FAIL),
Collectors(확장 셋, 새 것 셋, 참조 `caps`), Tooling(`suidindex` `caps`, D31, matrix 행, 오라클);
`docs/reference/coverage.md` 재생성; `docs/reference/capability-matrix.json`; `docs/reference/suid/*.json`.

## 7. 사실이 아닌 것

수집하지 않으므로 계획이 더하지 않는 것: `sudo`/`wheel` 멤버(U-63 가족과 `accounts.admin_group_members`가
이미 실음); `sudo -l` 출력; 실행파일 아닌 것의 ACL(이미 `acl_entries`가 있는 고정 경로 너머); 키 본문;
`wtmp`와 `btmp`; `/var/log/auth.log` 내용; `.wants` 링크의 대상; 유닛의 환경; `Host_Alias` 정의;
`lastlog2.db`와 `wtmp.db`.

## 8. 파킹

- 판정으로서의 ACL, walk에서 실행파일 아닌 것의 ACL.
- 판정으로서의 실제 휴면 계정 목록; `lastlog2` / `wtmpdb` 리더(sqlite).
- 특정 명령의 `NOPASSWD`; user specification의 호스트 필드; `Host_Alias`; `Defaults!command` 범위; `sudoers`
  LDAP(`sudoers.ldap(5)`).
- 다른 경로로 설정된 `AuthorizedKeysFile`; `AuthorizedKeysCommand`; `from=` / `restrict` 없는 일반 사용자의
  키; 인증 기관(`TrustedUserCAKeys`).
- enabled도 active도 아닌 서비스; `.socket`, `.timer`, `.path` 유닛의 실행파일; 실행파일 뒤에 쓰기 가능한
  스크립트를 부르는 `ExecStart` 인자(인터프리터 뒤의 경로).
- `/etc/security/access.conf`; `pam_wheel`; U-45 너머의 `su` 제한.
- 3C-2b: process 수집기, 삭제된 실행파일로 도는 프로세스, 노출 교차 점검(방화벽 confidence full에서만),
  네트워크 sysctl, `packages.verify.modified`와 walk 패키지 표의 join.
