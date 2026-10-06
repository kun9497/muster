# 3C-2b 단계 — 노출: 실제로 닿는 것은 무엇이고, 누가 그것을 서비스하는가

**상태:** 설계, 2026-10-02 대화에서 승인되고 같은 날 fresh 리뷰 둘(수집기 측, 컨트롤 측)로 정정; 영어
원본은 `2026-10-02-stage3c2b-exposure-design.md`. 상위 문서: `2026-09-02-muster-design.md`(D01–D31; 이
단계가 D32를 더함). 선행: 2H(이 단계가 키우는 방화벽 수집기), 3C-1
(`2026-09-23-stage3c1-audit-integrity-design.md`), 3C-2a(`2026-09-29-stage3c2a-privilege-design.md`) — 두
문서 §8이 보류한 항목을 이 단계가 가져옵니다.

## 1. 범위와 의도

가이드는 불필요한 서비스가 도는지(U-52의 소켓 표)와 방화벽이 있는지(U-28)를 묻습니다. 둘 다 호스트가
실제로 네트워크에 무엇을 내놓는지는 말하지 않습니다: 설정된 방화벽을 통과해 호스트 밖의 패킷이 닿을 수
있는 listening 소켓은 무엇이고, 각각에 어느 프로세스가 답하며, 그 프로세스가 패키지 관리자가 둔 것인지.
3C-2b는 그 join을 읽고 읽은 대로 판정합니다: 호스트 밖에서 닿는 리스너는 호스트 자신의 허용 목록에
있어야 하고, 리스너는 패키지에 속해야 하며, 어떤 프로세스도 디스크의 파일이 더는 아닌 실행파일을 돌려선
안 됩니다. join 곁에, 커널의 네트워크 sysctl — 호스트가 포워딩하는지, ICMP 리다이렉트와 소스 라우트를
받아들이는지, 위조된 발신 주소를 거르는지를 정하는 손잡이들 — 이 3B의 `sysctl` 수집기에 합류합니다.

브레인스토밍과 리뷰에서 정한 결정(X-1 … X-9):

- **X-1 — 범위.** "노출" 묶음: 프로세스 수집기, 삭제된 실행파일을 도는 프로세스, 방화벽에 대한 노출
  교차검증, 네트워크 sysctl. 제외: `packages.verify.modified`와 패키지 색인의 join(3C-1 §8, 보류 유지),
  `fix --dry-run`, 프로파일과 CIS 참조(3D), `--anonymize`, `--max-age`(3E).
- **X-2 — join 위의 컨트롤 셋.** 허용 목록에 없는 노출 리스너는 FAIL; 호스트의 패키지 관리자가 설치하지
  않은 실행파일의 리스너는 FAIL; 삭제된 실행파일을 도는 프로세스는 FAIL. 각각 읽은 대로 판정하고
  `params`나 waiver로만 완화합니다(D31의 철학).
- **X-3 — 프로세스 수집기는 읽을 수 있는 만큼 읽습니다.** 모든 pid를 열거하고; 실행이 `exe`나 `fd`
  디렉터리를 읽지 못한 프로세스는 그렇다고 말하는 행이며, 그런 행을 빼야 할 판정 leaf는 스스로
  `denied`입니다. root는 전부 읽고; 비root 실행은 자기 프로세스만 읽어 컨트롤 셋을 ERROR로 읽습니다
  (`nonroot.denied` 행). deep 게이트 없음.
- **X-4 — 패키지 색인은 모든 collect에서 만듭니다.** walk가 이미 쓰는 dpkg 목록 또는 고정 rpm 질의를
  walk와 프로세스 수집기가 공유하는 패키지로 빼냅니다; 그 비용은 오늘 미측정이며 계획의 프리플라이트가
  아래 예산을 고정하기 전에 랩과 EL9 이미지에서 측정합니다.
- **X-5 — 네트워크 sysctl 여섯 주제**, sysctl이 둘을 가진 곳에서 `all`과 `default`를 각각 판정하되
  설정의 effective 면(runtime, B-3; persisted 면은 증거)으로; 포워딩은 있는 그대로 읽습니다(docker 호스트는
  FAIL이고 매개변수로 완화).
- **X-6 — "방화벽을 통과한다".** 정규화 신뢰도 full에서: inbound가 제한되지 않으면 루프백 외 모든
  리스너; 그렇지 않으면 프로토콜과 포트가 그 family의 accept 규칙에 맞는 리스너 — 규칙의 source는
  무엇이든(source는 기록; 한 서브넷에만 열린 관리 포트도 호스트 밖에서 닿는 서비스). X-8의 선택자를
  거친 뒤에도 정규화가 "프로토콜과 포트"로 표현하지 못하는 accept 규칙은 호스트의 노출 판정을 MANUAL로
  만들고, 신뢰도 partial도 그러합니다.
- **X-7 — IPv4와 IPv6는 별도 컨트롤.** 컨트롤은 `absent_means`가 하나이고; IPv6 키는 IPv6 없는
  커널에서 absent이고 IPv4 키는 결코 아닙니다. `mechanisms`로 여섯 주제를 유지할 수도 있지만 waiver나
  리포트 독자가 이름 대는 것은 family별 컨트롤이므로 여섯 주제는 컨트롤 열셋으로 나갑니다.
- **X-8 — 방화벽 정규화기를 키웁니다.** 2H의 규칙 표는 input base chain의 `{chain, proto, dport, saddr,
  action}`만 실었습니다. 그것으로는 노출 판정을 받칠 수 없습니다: ufw는 accept를 jump 둘 뒤의
  `ufw-user-input`에 두고, `iif lo accept`, `ct state established accept`, bare `accept`가 바이트까지 같은
  행이었습니다. 방화벽 수집기는 이제 규칙의 family, 선택자, 원문을 기록하고 input base chain이 jump하는
  사용자 체인을 접습니다(상한 있음). U-28 자신의 정규화 신뢰도는 X-9 외에는 변하지 않습니다.
- **X-9 — 설정되었지만 비활성인 백엔드는 방화벽이 아닙니다.** `ufw`가 설치되고 꺼진 호스트(기본 Ubuntu
  Server, GitHub 러너)는 `backend ufw`, 신뢰도 `partial`("input base chain 없음"), U-28 MANUAL로
  읽혔습니다. input base chain도 inbound 규칙도 없는 규칙 집합은 어떤 패키지가 설치돼 있든 아무것도
  제한하지 않습니다: 이제 `full`에 `restricts_inbound: false`로 정규화되어 U-28이 그 호스트에서 FAIL로
  읽히고 노출 판정도 읽을 수 있습니다. 기존 스냅샷 모양에서 판정이 바뀌므로 minor 릴리스(D16)이며
  CHANGELOG의 Controls에 U-28 fixture와 함께 적습니다.

## 2. 아키텍처

- **`processes`(신규 수집기)** — `/proc`를 열거하고, 각 listening 소켓을 그것을 가진 프로세스들과
  join하고, 각 실행파일을 패키지 색인과 join하고 — 방화벽 수집기가 이미 돌았으므로(수집기는 이름순,
  `firewall` < `processes`, 테스트가 고정) — 방화벽의 규칙 표에서 `exposure.*`를 파생합니다.
  `processes.*`와 `exposure.*`를 씁니다. `Builder`는 `Get(key) (facts.Envelope, bool)`를 얻고, 새
  `Declaration.Facts []string`(수집기가 읽을 수 있는 키의 glob; `processes`는 `firewall.*`와
  `net.sysctl.ipv6_bindv6only`를 선언)이 울타리입니다: 선언 밖 `Get`은 프로그래밍 오류(builder가 panic,
  선언 테스트가 잡음)이고 `--list-actions`는 선언된 사실을 `fact` 종류로 출력합니다. 기존의 헤더 읽기
  둘(`patch`와 `walk`가 `Header()`로 `os`의 `Env`를 읽음, J-31)은 선례로 이름 대고 그대로 둡니다.
- **`firewall`(2H, 확장 — X-8, X-9)** — 규칙 표의 레코드가 필드를 얻고, 파서가 버리던 선택자를 읽고,
  정규화기가 사용자 체인을 접고, 체인 없음 경우가 `full`로 정규화됩니다. 상세는 §3 P-2.
  `normalization_confidence`의 정의(full / partial / 읽기 상태)는 X-9의 확장 하나 외에 그대로.
- **`sysctl`(3B, 확장)** — `net.sysctl.*` 키 스물일곱을 얻어 커널 키처럼 읽고(B-3), persisted 면 파서가
  `sysctl.d`의 glob 키와 `-key` 제외를 배웁니다(systemd의 `50-default.conf`가 둘 다 씀).
- **`pkgindex`(신규 내부 패키지)** — dpkg 목록 리더(`/var/lib/dpkg/info/*.list`, `statoverride`, 소유자별
  `.list` 파일)와 rpm 파일 표 질의가 walk의 join에서 동작 그대로 옮겨옵니다; 조회는 오늘 walk처럼 후보
  집합에 대해 목록을 스트리밍합니다(메모리 안 전체 색인 없음). 추출은 계획의 첫 태스크; 프로세스 수집기의
  질의는 자체 타임아웃(30 s)과 출력 상한을 가지며 타임아웃은 그 실행에서 `index_source: none`.

평가기는 바뀌지 않습니다(§7). `--list-actions`는 프로세스 수집기의 행(glob, 선언된 사실, walk와 공유하는
rpm 질의)을 얻습니다. 리포트의 `scopes.beyond` 개수는 열셋 늘어납니다. exit code는 그대로입니다.

## 3. 사실

### P-1 `processes.*`

선언: `Reads` `/proc/[0-9]*/status`, `/proc/[0-9]*/cmdline`, `/proc/[0-9]*/exe`, `/proc/[0-9]*/fd/*`,
`/proc/[0-9]*/task/*/fd/*`(zombie 리더의 살아 있는 스레드, W-68), `/proc/[0-9]*/ns/mnt`, `/proc/[0-9]*/mountinfo`와
`/proc/[0-9]*/root`(실행파일을 내주는 마운트, W-65), `/proc/1/ns/mnt`, `/proc/sys/net/ipv6/bindv6only`와
`/proc/sys/net/ipv6/conf/{all,default}/disable_ipv6`(P-3), 패키지 색인의 읽기, 소켓 표 넷
`/proc/self/net/{tcp,udp,tcp6,udp6}`; `Commands` rpm 질의(walk와 공유); `Facts` `firewall.*`(`net.sysctl.*`은
`processes` 뒤에 정렬되므로 그 sysctl 셋은 여기서 `/proc`로 읽음, W-47). `Needs: none`. pid는
`Glob("/proc/[0-9]*/status")`로 열거하고; fd 표 하나는 `Glob("/proc/<pid>/fd/*")`로(호스트 `Glob`은 검색할
수 없는 디렉터리를 빈 매치가 아니라 `denied`로 보고); `exe`, `fd/*`, `ns/mnt`는 `Readlink`로만 — magic
link의 텍스트이고 대상은 결코 열지 않음(`ReadDir`는 `Walk`만의 면허라 쓰지 않음).

프로세스마다: `status`가 `Name`, `PPid`, `State`, real `Uid`를; `cmdline`이 NUL로 나눈 첫 토큰을(4 KiB
상한); `exe`가 링크 대상을; `ns/mnt`가 마운트 네임스페이스 id를. 종류: pid 2이거나 `PPid`가 2면
`kernel`(kthreadd의 자식; 거기서 `exe`는 ENOENT), `State`가 `Z`면 `zombie`(`exe` 없고 fd 없음 — 증거만),
그 밖은 `user`. 목록과 읽기 사이에 사라진 pid는 행 없이 `processes.stats.vanished`를 올립니다.

- `processes.list` — `list<record>` `{pid, ppid, uid, name, cmd, exe, exe_deleted, exe_read_status, kind,
  mnt_ns, package, package_status}`, `pid` 정렬, 상한 4096행(넘으면 `truncated: true`; 아래 부분집합은
  여전히 모든 프로세스를 봄). `exe`는 ` (deleted)`를 뗀 링크 대상; `exe_deleted`는 대상이 그것을 달고
  있었을 때 true — exec 뒤 unlink되거나 교체된 실행파일에 대한 `proc(5)`의 표기: 업그레이드되고 아직
  재시작 안 된 데몬, 시작 뒤 디스크에서 지워진 바이너리, `memfd:` 실행파일이 같게 읽히며 설명은 memfd를
  의심스러운 경우로 이름 댑니다. `exe_read_status`는 `ok`, `denied`(비root 실행에서 다른 계정의 프로세스,
  EACCES), `error`. `mnt_ns`는 프로세스의 `exe`를 내주는 마운트가 같은 경로에 대한 pid 1의 것과 같은 키 — 가장 긴 마운트
  지점 접두의 장치·루트 기준 경로·타입·소스, 부모 체인의 모든 조상이 제 마운트 지점의 최상위(W-63, W-65,
  W-72; 한 지점의 마운트들 중 마지막 나열이 이김, W-73) — 를 가지고 `Readlink /proc/<pid>/root`가 `/`이면
  `host`, 아니면 `foreign`(overlay 루트를 가진, 호스트에서 본 컨테이너, `/usr` 위의 bind, chroot — 그 `exe`
  경로는 다른 루트의 경로라 호스트 색인에 물어선 안 됨). `ns/mnt`의 동일성은 기준이 아닙니다: systemd의
  `PrivateTmp`/`ProtectSystem`은 수십 개의 기본 서비스에 호스트 자신의 파일 위로 자기 마운트 네임스페이스를
  줍니다. `mountinfo`나 root 링크 읽기 실패는 `ns_read_status: error`와 소유자 실패이지 조용한 `foreign`이
  아닙니다. `package`는
  `host` 프로세스에 대한 색인의 `exe` 소유자, 또는 `/snap/<name>/<revision>/` 아래 `exe`에 대한 `snap:<name>`(접두가 색인보다 먼저 정함, W-64);
  `package_status`는 `packaged`, `unpackaged`, `snap`(`/snap/*`), `flatpak`(`/var/lib/flatpak/*`,
  `~/.local/share/flatpak/*`), `appimage`(`/tmp/.mount_*`), `foreign_ns`, `no_index`(색인을 만들 수
  없었음). `deleted` 실행파일도 다른 것처럼 조회(경로가 여전히 소유될 수 있음). `sensitivity: internal`.
- `processes.deleted_executables` — `list<record>` `{pid, uid, name, exe}`: 판정용 부분집합(C2) —
  `exe_deleted`인 `user` 종류 프로세스. `user` 프로세스 중 하나라도 `exe`를 읽지 못했으면 leaf는 그
  읽기의 상태(비root 실행에선 `denied`)이고, 읽을 수 있던 것의 부분집합이 아닙니다. 이 leaf는 `/proc`만으로
  쓰여 `ok`, `denied`, `unsupported`, `error`, `truncated`이고 결코 `absent`가 아닙니다.
- `processes.listeners` — `list<record>` `{proto, family, addr, port, loopback, link_local, inode, owner_status,
  owners}`: 호스트의 모든 listening 소켓 — `sockets.listening`이 싣는 행을 여기서 다시 읽음(R232: 수집기마다
  한 번) — `proto`는 `tcp`/`udp`로 접고 `family`는 표에서 `v4`/`v6`, `owners`는 소켓을 가진 프로세스들:
  `list<{pid, uid, name, exe, exe_deleted, mnt_ns, package, package_status}>`, `pid` 정렬, 상한 64(소켓
  활성화 서비스는 pid 1과 서비스가 가짐; prefork 서버는 모든 워커가). `owner_status`는 `ok`; 모든 fd 표를
  온전히 읽었는데 — denied도 예산 초과도 없고, pid 1의 행과 그 `ns/mnt`·`mountinfo`를 읽었고, 커널 스레드가
  적어도 하나 보이는데(커널 스레드는 최초 pid 네임스페이스에서만 보이고 `hidepid`가 숨김) — inode를 가진
  표가 없으면 `kernel`: 커널 소유 소켓(nfsd, ksmbd, WireGuard, rpc 콜백)도 다른 소켓처럼 0이 아닌 inode를
  가지기 때문(측정: WireGuard의 `udp/51820`이 inode 363387305로 읽힘; W-66, W-69) — `owners` 빔,
  `owners_count` 0, 본성상 패키지로 판정; 표를 온전히 읽지 못했거나 pid 시야가 부분적이면 — 컨테이너,
  `hidepid`(W-67) — `unmatched`; inode `-1`(파싱 안 된 열)은 `error`. `owners_count`가 전체이고 `owners`는
  pid 순 처음 64. 살아 있는 스레드가 소켓을 가진 zombie 리더는 한 예산 아래 `task/*/fd/*`로 읽고(W-68),
  살아 있는 스레드 없는 zombie 리더는 소유자 실패(W-70). fd 표가 하나라도 `denied`면 leaf가 `denied`;
  소켓이 하나라도 `unmatched`이거나 소유자가 하나라도 실패하면 leaf는 그것을 적은 `absent`(컨트롤 2는
  MANUAL — 아무도 갖지 않은 소켓은 인벤토리의 구멍이지 통과가 아님). 상한
  2000행; `proto`, `port`, `addr` 정렬. 소켓 표나 색인이 잘렸으면 `truncated: true`.
- `processes.unpackaged_listeners` — `list<record>` `{proto, family, addr, port, pid, name, exe,
  package_status}`: 판정용 부분집합 — 소유자의 `package_status`가 `unpackaged`, `snap`, `flatpak`,
  `appimage`, `foreign_ns`인 (리스너, 소유자)마다 한 행(`deleted` 실행파일은 컨트롤 3의 것이라 여기 반복
  안 함). `processes.listeners`의 상태가 `ok`가 아니면 그 상태를, 색인을 만들 수 없었으면 색인 읽기의
  상태를(dpkg도 rpm도 없는 호스트의 `absent` "no package database" — 컨트롤 2는 MANUAL, setuid 선례),
  위처럼 `truncated`를 싣습니다.
- `processes.stats` — 레코드 `{count, kernel_threads, zombies, foreign_ns, denied, vanished, fd_reads,
  index_source, index_ms, elapsed_ms}`; `index_source`는 `dpkg`, `rpm`, `none`.

예산: 프로세스당 fd 항목 65536(각 `readlink` 하나; 넘으면 leaf는 pid를 적은 `error` — 조용한 `unmatched`가
아니라), 전체 열거 5 s(넘으면 `processes.list`는 `truncated`이고 모든 판정 leaf가 `truncated: true`를 실어
평가기가 `ERROR(truncated)`로 읽음), 색인 자체의 상한(§2).

상태(C3/C4): 가려진 `/proc`(`ErrProcfsMasked`)는 모든 `processes.*` 키에 `unsupported`; `exe`/`fd`/`ns/mnt`의
EACCES는 행의 `exe_read_status`/`owner_status`이고 판정 leaf의 `denied`; 잘린 `.list`나 rpm 출력은
`processes.listeners`, `processes.unpackaged_listeners`, `exposure.exposed`에 `truncated`.

### P-2 확장된 `firewall.rules`(방화벽 수집기, X-8과 X-9)

레코드: `{chain, via_chain, depth, family, proto, dport, saddr, daddr, iif, ctstate, action, unmodelled, raw}` —
레코드 필드 추가는 `schema_version` 유지(C2); 모든 행이 모든 필드를 실음(선택자가 없으면 빈 문자열과
`false`).

- `family`: nft `ip` → `v4`, `ip6` → `v6`, `inet` → `inet`; iptables-save의 dump → `v4`, ip6tables-save의
  → `v6`. `bridge`, `arp`, `netdev` 테이블은 input base chain에 결코 합류하지 않음(오늘 `parseNftRuleset`은
  family로 거르지 않음; 이제 거름).
- `proto`: `tcp`, `udp`, 다른 리터럴(`icmp`, `icmpv6`, `esp`, …), 또는 빔. 프로토콜 집합(`meta l4proto {
  tcp, udp }`, `ip protocol { tcp, udp }`)이나 vmap은 `unmodelled`를 켬(오늘 파서는 집합의 마지막 원소
  `udp`만 남겨 그런 규칙 뒤의 `tcp/53`이 filtered로 읽혔음).
- `dport`: 포트, 범위(nft `1000-2000`, iptables `1000:2000`), 집합(nft `{ 22, 80 }`, iptables `-m multiport
  --dports 22,80,443`) — 각각 256 포트까지 열거 가능; 심볼릭 서비스 이름, named set(`@ports`), vmap은
  `unmodelled`.
- `saddr`, `daddr`: 쓰인 대로의 주소나 집합 텍스트. `iif`: `-i X` / `iif X` / `iifname X`. `ctstate`:
  `--ctstate` / `ct state` 목록, 소문자.
- `action`: `accept`, `drop`, `reject`, `return`, `jump <chain>`, `goto <chain>`, `continue`, `queue`, `log`,
  또는 빔(인식된 verdict 단어 없음).
- `unmodelled`: 파서가 모델링하지 않는 토큰이 규칙의 매치 부분에 남았을 때 true(`-m owner`, `meta mark`,
  `tcp flags`, `icmp type`, 필드 없는 `-d`, 열거 못 한 집합; `counter`/`comment`/`-m tcp`는 무해로 제외).
- `raw`: dump된 규칙 줄, 512바이트 상한.
- `chain`, `via_chain`, `depth`: 행을 읽은 체인, 그 체인에 jump로 닿은 input base chain(base chain 행은
  자신), jump 깊이(base chain은 0).

접기: 모든 input base chain에 대해, 그것이 jump/goto하는 모든 체인의 규칙을 dump 순서로 `depth + 1`로
덧붙임 — 깊이 4, base chain당 접힌 규칙 2000까지(ufw의 accept는 깊이 2: `INPUT → ufw-before-input →
ufw-user-input`); 두 번 방문되는 체인은 한 번만; 깊이나 행 예산을 넘는 jump는 jump 행 자체에
`unmodelled`를 켜 분류기가 `opaque`로 읽음. 만든 대로: 체인은 전체에 한 번이 아니라 거기 닿는 조건 집합마다
한 번 접힘(ufw의 포트별 jump 여섯이 각각 대상의 DROP을 접음; W-60); jump 행 자신의 선택자 — `proto`,
`dport`, `saddr`, `daddr`, `iif`, `ctstate` — 는 그 행을 거쳐 접힌 모든 행의 빈 필드에 물려지고, 둘 다 있고
다르면 `unmodelled`(W-54); 따라간 jump 행은 `unmodelled`를 지우고 `irrelevant`로, 따라가지 못한 것은
그대로(W-51); verdict가 없는 규칙(ufw `limit`의 `-m recent --set`)은 `action: none` → `irrelevant`로,
인식 안 된 verdict 단어와 구별되며 그쪽은 `opaque`(W-55); `.` 연결 피연산자는 필드를 비운 `unmodelled`(W-56);
`ct state dnat`/`snat`은 `opaque`(W-58); 레코드는 `table`도 실어 열네 필드(W-59). 체인 안·체인 간 규칙
순서는 무시(drop이 앞서든 accept를 셈 —
보수적; §8). `restricts_inbound`와 `normalization_confidence`는 오늘처럼 base chain의 정책과 규칙 유무로
계산하되 확장 하나(X-9): 백엔드가 설정됐지만 input base chain도 inbound 규칙도 없는 family — 꺼진 `ufw`,
테이블이 비워진 채 멈춘 firewalld, 빈 규칙 집합의 `nftables` 서비스 — 는 `partial` "no input base chain
found"가 아니라 `restricts_inbound: false`의 `full`. 빈 nft 규칙 집합은 먼저 `iptables-legacy-save`와 교차
확인합니다: nft dump가 볼 수 없는 legacy 규칙, iptables-nft의 "iptables-legacy tables present" 경고, 잘린
legacy dump는 `partial`(W-57, W-61) — 모두-accept-규칙-없음 가지에서도. 그래서 U-28의 둘째 메커니즘(`restricts_inbound eq
true`)은 MANUAL이던 곳에서 FAIL로 읽힘: 호스트에 방화벽이 없고 컨트롤이 그렇게 말함. 방화벽 자체의
fixture에 `fail-ufw-inactive.json`; CHANGELOG는 판정 변화를 Controls에 기록(D16).

### P-3 `exposure.*`(`processes`가 씀)

입력: `processes.listeners`, `firewall.normalization_confidence`, `firewall.restricts_inbound`, `firewall.rules`,
`firewall.backend`(`Builder.Get`으로, 선언됨), 그리고 `net.sysctl.ipv6_bindv6only`(`sysctl`이 쓰는데
`processes` 뒤에 정렬되므로 이것만 `/proc/sys/net/ipv6/bindv6only`를 직접 읽음, `Reads`에 선언; IPv6 없는
커널엔 그 파일도 판정할 v6 리스너도 없음). 같은 종류의 읽기 둘 더, `/proc/sys/net/ipv6/conf/{all,default}/
disable_ipv6`: 둘 다 `1`이면 v6는 켜진 family가 아니고 — `tcp6` 표는 있어도 커널이 거기서 inbound IPv6를
버림 — `::`나 v6 리스너는 `via: ipv6_disabled`, `exposure.stats.ipv6_disabled` true(W-76; P-4의
`ipv6_disabled`와 같은 술어). input base chain의 family는 행이 아니라 방화벽의 `raw_dumps`를 다시 파싱해
얻습니다(W-74).

모든 input base chain의 접힌 모든 행을 분류:

- `deny`: `action` `drop`/`reject` — 기록만, 들어오는 길이 아님;
- `port_rule`: `action` `accept`, `unmodelled` 아님, `proto` `tcp`/`udp`, `dport` 열거 가능, `iif` 빔 또는
  `lo` 아님, `ctstate` 빔 또는 `new`/`untracked` 포함;
- `any_port`: `accept`, `unmodelled` 아님, `proto`와 `dport` 빔, `iif` 빔, `ctstate` 빔 또는 `new`/`untracked`
  포함, `daddr` 빔;
- `loopback_only`: `iif` `lo`인 `accept`(호스트 밖에서 온 것은 `lo`로 도착하지 않음);
- `state_only`: `ctstate`에 `new`도 `untracked`도 없는 `accept`(established/related 트래픽은 호스트가 시작했거나
  이미 받아들인 연결에 답함);
- `irrelevant`: `proto`가 `tcp`/`udp` 외 리터럴인 `accept`(ICMP, ESP, IGMP — TCP/UDP 리스너에 닿을 수 없음);
  `log`, `return`, `continue` 행; 접힌 `jump`/`goto` 행;
- `opaque`: 그 밖 — `unmodelled` accept, 포트 없이 `daddr`만 있는 accept, 접기 예산을 넘은 jump, 빈
  `action`.

노출은 `normalization_confidence`가 `full`이고 리스너 family의 input base chain에 `opaque` 행이 없을
때만 정합니다(`inet`은 두 family에 모두 셈) — 불투명은 family별이라 v6에만 있는 `opaque` 행은 v4 리스너를
정하게 둡니다(W-75); 정해지지 않은 리스너는 `exposure.listeners`에서 `via: undecided`. 그다음 루프백 외
리스너마다(루프백은 `127.0.0.0/8`과 `::1`;
링크로컬 — `fe80::/10`, `169.254.0.0/16` — 은 링크의 모든 이웃이 닿을 수 있으므로 후보이고 `link_local:
true`로 기록):

- 호스트의 family는 소켓 표가 있는 것(`tcp6`/`udp6` 있음 → v6 활성); 활성인데 input base chain(`ip6`나
  `inet`)이 없고 다른 family에는 있는 family — 흔한 "iptables만, ip6tables 규칙 없음" 호스트 — 는 그
  family의 모든 리스너를 노출, `via: no_chain_in_family`;
- `restricts_inbound: false` → 노출, `via: open_policy`;
- 그 밖엔 family에 `any_port` 행이 있으면(`via: any_port_rule`) 또는 `port_rule`이 프로토콜·포트에 맞으면
  노출 — 범위는 포함, 집합은 소속으로(`via: rule`, 행의 `chain`, `saddr`, `raw` 기록); 아니면 `filtered`;
- `0.0.0.0`의 소켓은 v4 후보; `::`의 소켓은 v6 후보이고 `bindv6only`가 `0`이면 v4 후보이기도 — 어느
  family가 노출이라 하면 노출; 특정 주소는 자기 family의 후보.

키:

- `exposure.listeners` — `list<record>` `{service, proto, family, addr, port, link_local, owners, exposed, via,
  rule_chain, rule_source, rule_raw}`, 루프백 외 모든 리스너; `service`는 `proto` `tcp`/`udp`의
  `"<proto>/<port>"`(`tcp/22`, 결코 `tcp6/22` 아님), 허용 목록이 쓰는 문자열; `owners`는
  `processes.listeners`와 같음. `proto`, `port`, `addr` 정렬. 증거.
- `exposure.exposed` — `list<record>` `{service, proto, family, addr, port, pid, name, package, via, rule_chain,
  rule_source}`: 노출된 부분집합, 리스너마다 한 행(보이는 소유자는 가장 낮은 pid; `exposure.listeners`에
  전부 있음). 판정을 읽을 수 없으면 `absent`(컨트롤 1 MANUAL): 신뢰도 partial, 또는 `opaque` 행. 평가기는
  absent 판정 leaf를 수집기의 이유 없이 "`<fact>` is absent on this host"로 그리므로, 원인은 리포트 독자가
  찾는 곳에도 씁니다: `exposure.stats.confidence`와 `exposure.stats.manual_reason`, 그리고
  `exposure.opaque_rules`. 방화벽을 읽지 못했으면 그 읽기의 상태(`unsupported` — root인데 `nft`/`iptables`
  바이너리 없음; `denied`); `processes.listeners`가 `ok`가 아니면 그 상태; 어느 입력이든 잘렸으면
  `truncated`.
- `exposure.opaque_rules` — `list<record>` `{chain, via_chain, table, family, action, raw}`.
- `exposure.stats` — 레코드 `{confidence, manual_reason, listeners, exposed, filtered, loopback, link_local,
  kernel_owned, opaque_rules, folded_rules, ipv6_disabled}`.

방화벽 바이너리가 전혀 없는 호스트는 `firewall.* unsupported`로 읽혀 컨트롤 1이 NOT_APPLICABLE이면서
모든 것이 닿습니다 — U-28이 그 호스트를 읽는 방식과 같고, 설명이 그렇게 적습니다. 백엔드는 설정됐지만
아무것도 제한하지 않는 호스트(X-9)는 컨트롤 1이 전부-노출, U-28이 FAIL: 원인과 결과, 두 설명에 적음.

### P-4 `net.sysctl.*`(`sysctl` 수집기)

키 스물여덟, `since: 1`. 스물여섯은 `setting<int>`에 `default_on: effective`(= runtime, B-3), `sysctl.d`의
두 홈이 persisted 면(스물넷은 `checks`가 판정, `disable_ipv6` 둘은 파생 게이트의 입력); 둘은 평범한 `int`:

| 키 | sysctl |
|---|---|
| `ipv4_ip_forward` | `net.ipv4.ip_forward` |
| `ipv6_all_forwarding`, `ipv6_default_forwarding` | `net.ipv6.conf.{all,default}.forwarding` |
| `ipv4_all_accept_redirects`, `ipv4_default_accept_redirects` | `net.ipv4.conf.{all,default}.accept_redirects` |
| `ipv4_all_secure_redirects`, `ipv4_default_secure_redirects` | `net.ipv4.conf.{all,default}.secure_redirects` |
| `ipv4_all_send_redirects`, `ipv4_default_send_redirects` | `net.ipv4.conf.{all,default}.send_redirects` |
| `ipv6_all_accept_redirects`, `ipv6_default_accept_redirects` | `net.ipv6.conf.{all,default}.accept_redirects` |
| `ipv4_all_accept_source_route`, `ipv4_default_accept_source_route` | `net.ipv4.conf.{all,default}.accept_source_route` |
| `ipv6_all_accept_source_route`, `ipv6_default_accept_source_route` | `net.ipv6.conf.{all,default}.accept_source_route` |
| `ipv4_all_rp_filter`, `ipv4_default_rp_filter` | `net.ipv4.conf.{all,default}.rp_filter` |
| `ipv4_all_log_martians`, `ipv4_default_log_martians` | `net.ipv4.conf.{all,default}.log_martians` |
| `ipv4_icmp_echo_ignore_broadcasts` | `net.ipv4.icmp_echo_ignore_broadcasts` |
| `ipv4_icmp_ignore_bogus_error_responses` | `net.ipv4.icmp_ignore_bogus_error_responses` |
| `ipv4_tcp_syncookies` | `net.ipv4.tcp_syncookies` |
| `ipv6_all_accept_ra`, `ipv6_default_accept_ra` | `net.ipv6.conf.{all,default}.accept_ra` |
| `ipv6_all_disable_ipv6`, `ipv6_default_disable_ipv6` | `net.ipv6.conf.{all,default}.disable_ipv6`(`ipv6_disabled`의 입력) |
| `ipv6_bindv6only`(`int`, 증거) | `net.ipv6.bindv6only`(P-3를 위해 `processes`가 읽음) |
| `ipv6_disabled`(`int`, 파생) | 두 `disable_ipv6` runtime 값이 모두 `1`이면 `1`, 아니면 `0`; 어느 한쪽이 `ok`가 아니면 더 나쁜 읽기의 상태; `source`는 `/proc` 경로 둘. IPv6 컨트롤의 유일한 게이트이자 P-3 `via: ipv6_disabled`의 술어(W-79) |

`all`은 지금의 모든 인터페이스에, `default`는 이후 생기는 모든 인터페이스에 적용됩니다(`ip-sysctl.rst`);
`all`은 조이고 `default`는 느슨한 호스트는 새 인터페이스 — 컨테이너의 veth, VPN — 에 느슨한 값을
주므로 둘을 모두 판정합니다. 인터페이스별 값은 수집하지 않습니다(§8). IPv6 없는 커널
(`/proc/sys/net/ipv6` 없음 — `ipv6.disable=1` 부트 매개변수)은 모든 `ipv6_*` 키를 "IPv6 is not built or is
disabled" 이유의 `absent`로 만들고(`readProcSys`의 "does not exist"를 `/proc/sys/net/ipv6` 접두로 특별
처리); 흔한 방식으로 꺼진 IPv6 — `all`과 `default`의 `disable_ipv6 = 1` — 는 파일을 기본값으로 남기므로
IPv6 컨트롤은 파생 키 `ipv6_disabled`가 `0`임을 게이트로 둡니다 — 키 하나인 이유는 `applies_when` 절이
AND로 묶이고, `default`만 끈 호스트는 지금 있는 인터페이스에서 여전히 IPv6를 말하기 때문(W-79; §4).

persisted 파서는 systemd가 `/usr/lib/sysctl.d/50-default.conf`를 배포하는 곳(Ubuntu 22.04, EL9; Ubuntu
24.04는 배포하지 않고 네트워크 기본값은 procps의 `10-network-security.conf`나 커널에서 옴 — W-77)에서 그
파일이 쓰는 것을 배웁니다: glob 키
(`net.ipv4.conf.*.rp_filter = 2`, 맞는 모든 키에 적용)와 `-key` 줄(`-net.ipv4.conf.all.rp_filter`, 그 키를
glob에서 제외). glob은 점으로 나눈 성분마다 맞춥니다(`*`는 성분 하나, `[!…]`는 glob(3)의 표기); 구체적인
줄은 파일 순서와 무관하게 어떤 glob보다 이기고; 한 키에 대한 제외 줄이 여럿이면 마지막이 이기며(W-78);
되풀이된 glob은 처음 자리를 지킵니다. 없으면 `rp_filter`와 `accept_source_route`의 persisted 면이 모든 systemd 호스트에서 "no
sysctl.d line sets …"로 읽힘 — 틀린 증거, 판정 아님(B-3). 그 파일이 §5의 기본 가설이 커널 기본값과 다른
이유이기도 합니다.

## 4. 컨트롤

`category: beyond` 컨트롤 열셋, id `muster.beyond.<name>`, `controls/beyond/` 아래, 모두
`env.container eq none` 게이트(컨테이너의 프로세스·방화벽·네트워크 네임스페이스는 호스트의 정책이 아님),
`automation: auto`, 모든 beyond 컨트롤처럼 `title_en`/`title_ko`와 `remediation` 블록을 지님. 중요도는 각
설명이 이름 댄 1차 원문에서 muster가 매긴 것입니다.

| # | id | 중요도 | 절(`checks`) | absent_means |
|---|---|---|---|---|
| 1 | `exposed_listeners_allowed` | 상 | `{ fact: exposure.exposed, op: none, subject: service, where: { field: service, op: not_in, expected: "${allowed_ports}" } }`; `params.allowed_ports: list<string>` 기본 `["tcp/22", "udp/68", "udp/546"]` — sshd, 그리고 DHCP로 주소를 받는 모든 호스트가 `0.0.0.0:68` / `:::546`에 바인딩하는 DHCP·DHCPv6 클라이언트 소켓 | manual — 신뢰도 partial, opaque 규칙 |
| 2 | `listeners_packaged` | 중 | `{ fact: processes.unpackaged_listeners, op: none, subject: exe, where: { field: exe, op: not_in, expected: "${allowed_executables}" } }`; `params.allowed_executables: list<string>` 기본 `[]` | manual — 패키지 데이터베이스 없음, unmatched 소켓 |
| 3 | `no_deleted_executables` | 중 | `{ fact: processes.deleted_executables, op: none, subject: pid, where: { field: pid, op: gte, expected: 0 } }` | fail — 닿지 않음: leaf는 `ok`거나 하드 상태, 결코 `absent` 아님(그 불변식을 적은 `_mutants.yaml` 행 셋) |
| 4 | `ip_forwarding_disabled` | 중 | `{ fact: net.sysctl.ipv4_ip_forward, op: in, expected: "${allowed_forward}" }`; `params.allowed_forward: list<int>` 기본 `[0]` | fail |
| 5 | `ipv6_forwarding_disabled` | 중 | `ipv6_all_forwarding in ${allowed_forward}`, `ipv6_default_forwarding in ${allowed_forward}`(같은 매개변수) | not_applicable |
| 6 | `icmp_redirects_ignored` | 중 | ipv4 키 여섯 `eq 0`: accept·secure·send redirects × all/default | fail |
| 7 | `ipv6_redirects_ignored` | 중 | ipv6 accept_redirects 키 둘 `eq 0` | not_applicable |
| 8 | `source_routing_rejected` | 중 | ipv4 accept_source_route 키 둘 `eq 0` | fail |
| 9 | `ipv6_source_routing_rejected` | 중 | ipv6 accept_source_route 키 둘 `eq 0` | not_applicable |
| 10 | `reverse_path_filtering` | 중 | `ipv4_all_rp_filter in [1, 2]`, `ipv4_default_rp_filter in [1, 2]`, `ipv4_all_log_martians eq 1`, `ipv4_default_log_martians eq 1` | fail |
| 11 | `icmp_broadcast_and_bogus_ignored` | 하 | `ipv4_icmp_echo_ignore_broadcasts eq 1`, `ipv4_icmp_ignore_bogus_error_responses eq 1` | fail |
| 12 | `syn_cookies_enabled` | 중 | `ipv4_tcp_syncookies eq 1` | fail |
| 13 | `ipv6_router_advertisements_ignored` | 중 | `ipv6_all_accept_ra in ${allowed_accept_ra}`, `ipv6_default_accept_ra in ${allowed_accept_ra}`; `params.allowed_accept_ra: list<int>` 기본 `[0]`(SLAAC 주소의 서버는 `1`을 이름 댐; `2`는 포워딩 호스트에서 RA를 받는 유일한 값) | not_applicable |

IPv6 컨트롤 넷(5, 7, 9, 13)은 `applies_when` 절 하나를 더 가집니다: `net.sysctl.ipv6_disabled eq 0`(P-4;
W-79) — 권장 방식으로, `all`과 `default`에서 함께 IPv6를 끈 호스트는 쓰지 않는 기본값으로 FAIL이 아니라
NOT_APPLICABLE로 읽히고; 둘 중 하나만 끈 호스트는 여전히 IPv6를 말하므로 판정됩니다. `rp_filter`는 1(strict)과 2(loose — systemd의 배포 값, 비대칭 라우팅에
맞음)를 받고; 0은 FAIL. `secure_redirects`는 `accept_redirects`가 0이면 무의미하지만 벤치마크들처럼 그래도
판정하며 설명이 그렇게 적습니다.

컨트롤 1의 `service` 계약: 소문자 `<tcp|udp>/<port>`, 정확 일치, 범위나 와일드카드 없음(`TCP/22`, `tcp/*`는
아무것에도 맞지 않음 — lint는 오타와 포트를 구분할 수 없어 시도하지 않음). 한 데몬의 `0.0.0.0`과 `::`
소켓은 하나의 `service`라 waiver 하나가 둘을 덮습니다. 컨트롤 2의 `allowed_executables`는 `/proc/<pid>/exe`가 풀어 주는 대로의 경로를 이름
댑니다(`/usr/local/sbin/mydaemon`; snap의 `/snap/lxd/<revision>/bin/lxd`는 refresh마다 바뀌므로 자기 snap은
경로보다 컨트롤에 대한 waiver로 허용하는 쪽이 낫습니다 — W-80); snap 데몬은 있는 그대로 정직한 FAIL(호스트의
패키지 관리자가 설치하지 않음)이고 설명이 그렇게 적으며, `foreign_ns`는 호스트의 네트워크 네임스페이스에서
서비스하는 컨테이너의 프로세스를 뜻한다고도 적습니다.

설명(muster의 말, KISA·CIS 원문 없음): 1차 원문과 중요도의 이유; 기본 판독(§5); MANUAL/NOT_APPLICABLE/ERROR
경우; 컨트롤 1에는 U-28·U-52와의 관계(중복이 아니라 원인과 결과)와 허용 목록이 호스트가 무엇을
서비스하는지 스스로 선언하는 것이라는 점; 컨트롤 2에는 `/usr/local` 데몬이 흔한 정직한 FAIL이고
`allowed_executables`가 그것을 이름 댄다는 점; 컨트롤 3에는 보통의 답이 업그레이드 뒤 재시작(`needrestart`,
`dnf needs-restarting`)이고 드문 답이 도는 프로세스 아래서 지워진 바이너리라는 점.

참조(모든 id가 커밋된 인덱스에 있음; lint가 모르는 id를 거부): `nist_800_53` — 컨트롤 1 `CM-7`, `CM-6`;
컨트롤 2 `CM-7(5)`; 컨트롤 3 `CM-7(5)`, `SI-2(6)`; 컨트롤 4–13 `CM-6`, 컨트롤 12는 `SC-5`, `SC-5(2)`도.
`references.stig`(rhel9 V2R9, ubuntu2204 V2R9, ubuntu2404 V1R6): 4 `RHEL-09-253075`; 5 `RHEL-09-254025`; 6
`RHEL-09-253015`, `-253040`, `-253065`, `-253070`; 7 `RHEL-09-254015`, `-254035`; 8 `RHEL-09-253020`, `-253045`;
9 `RHEL-09-254020`, `-254040`; 10 `RHEL-09-253025`, `-253030`, `-253035`, `-253050`(W-81); 11 `RHEL-09-253055`, `-253060`; 12
`RHEL-09-253010`, `UBTU-22-253010`, `UBTU-24-600190`; 13 `RHEL-09-254010`, `-254030`; 컨트롤 1–3은 없음.
`subject_kind`: 어느 subject도 사용자나 그룹이 아니라 어떤 컨트롤도 원격 NSS WARN을 일으키지 않습니다.

## 5. 환경과 기본 판독

- **비root.** `processes.deleted_executables`, `processes.listeners`, `processes.unpackaged_listeners`, 따라서
  `exposure.exposed`가 `denied`(다른 계정의 `exe`, `fd`, `ns/mnt`)이므로 컨트롤 1–3은 ERROR; `processes.list`는
  다른 계정 행에 `exe_read_status: denied`를 둔 채 `ok`(`_notes` 항목); `net.sysctl.*`는 답함(`/proc/sys/net`과
  `sysctl.d` 체인은 world-readable). `nonroot.denied`에 키 넷.
- **systemd 없음.** 변화 없음.
- **컨테이너.** 모든 컨트롤이 게이트로 NOT_APPLICABLE. 수집기는 그래도 돕니다: `processes.*`는 컨테이너의
  pid 네임스페이스를 읽어 `ok`; 가려진 `/proc`는 `unsupported`(`sockets` 선례 — 새 `container.unsupported`
  행 없음); `net.sysctl.*`는 네임스페이스 값(`ok`); 모든 프로세스가 컨테이너의 pid 1 기준 `mnt_ns: host`. 비특권 컨테이너에선 다른 uid의 프로세스만
  `exe`/`fd` 링크를 거절합니다(`ubuntu:24.04`에서 측정): 프로세스 leaf가 `denied`로 읽히고, 수집기의 최악
  상태가 `run.complete`를 정하는 기존 규칙에 따라 그런 다중 uid 컨테이너의 `docker exec` collect는 컨트롤이
  NOT_APPLICABLE인데도 종료 코드 1(W-83); 계약 잡은 muster를 유일한 프로세스로 돌려 complete로 남습니다.
- **기본 Ubuntu 22.04 / 24.04(가설; 랩이 측정, 3C-2a의 V-18).** `ufw` 설치·비활성 → X-9 → `full`,
  `restricts_inbound: false` → 루프백 외 모든 리스너 노출: sshd `tcp/22`와 DHCP 클라이언트 `udp/68` →
  컨트롤 1은 기본 허용 목록으로 PASS; U-28은 그 호스트에서 FAIL(D16). systemd-resolved(`127.0.0.53`)와
  chrony(`udp/323`)는 루프백. 컨트롤 2 PASS(모든 리스너가 dpkg 소유; 24.04 서버의 `ssh.socket` 리스너는
  pid 1과 sshd가 가지며 둘 다 패키지); 컨트롤 3은 재부팅된 호스트에서 PASS. sysctl(커널 기본값, 그 위에 이름 순의 `sysctl.d` 체인 — `all`과 `default`에 `rp_filter 2`를 두는 Ubuntu의
  `/etc/sysctl.d/10-network-security.conf`, 그다음 `default.rp_filter 2`를 다시 두고
  `default.accept_source_route 0`을 두는 systemd의 `/usr/lib/sysctl.d/50-default.conf`): `ip_forward 0` PASS(docker 호스트는 1); `accept_redirects` 1/1 FAIL;
  `secure_redirects` 1/1 FAIL; `send_redirects` 1/1 FAIL; `accept_source_route` 0/0 PASS; `rp_filter` 2/2 PASS,
  `log_martians` 0/0 → 컨트롤 10 FAIL; `echo_ignore_broadcasts 1`, `bogus 1` PASS; `syncookies 1` PASS; ipv6
  `accept_redirects 1` FAIL, `accept_source_route 0` PASS, `accept_ra 1` FAIL, `forwarding 0` PASS. 열셋 중
  넷이 기본 호스트에서 FAIL(6, 7, 10, 13), docker 호스트에선 다섯(4); 설명이 그렇게 적고 랩 측정이 핀. 측정(Task 7, 랩의 22.04 — 기본이 아님: docker, kubelet, ufw 활성):
  `normalization_confidence partial`(docker 체인) → 컨트롤 1 MANUAL; 리스너 24, 소유자 모두 맞음, 커널 소유
  없음; sysctl runtime 값은 `ip_forward 1`과 `all.accept_redirects 0`(포워딩이 켜지면 커널이 지움)을 빼고
  가설대로; `all.rp_filter`는 `10-network-security.conf` 5행(4행은 `default`), `default.rp_filter`는
  `50-default.conf` 25행, `default.accept_source_route`는 그 30행이 persisted. 랩이 보여 줄 수 없는 기본
  행 — 꺼진 ufw, DHCP 클라이언트, 외부 리스너 없음, 삭제된 실행파일 없음 — 은 가설로 남고 `_notes`가
  어느 쪽인지 밝힘. **Ubuntu 24.04**는 `50-default.conf`를 배포하지 않으므로(W-77)
  `default.accept_source_route`를 persisted하는 것이 없고 커널 기본값은 `1`(`ipv4_devconf_dflt`): 기본
  24.04는 컨트롤 8도 FAIL — 열셋 중 다섯(6, 7, 8, 10, 13). GitHub 러너(24.04)는 브랜치가 푸시된 뒤 examples 실행이 읽고(W-84), 그 판독은 계획의 Execution notes에 적습니다.
- **기본 EL9(가설).** firewalld 활성(`backend firewalld`, 그 nft 규칙 집합): `filter_INPUT` 체인이 규칙을
  가진 채 기본 accept라 정규화기가 오늘 `partial`로 분류하고 앞으로도 그러함 — 기본 EL9에서 컨트롤 1은
  MANUAL이고 설명이 그렇게 적음; firewalld 존 모델의 1급 정규화는 보류(§8). 프로세스 사실은
  `rockylinux/rockylinux:9-ubi-init`(sshd)에서 측정; sysctl의 runtime 면은 컨테이너에서 측정 불가(네임스페이스
  값)이고 persisted 면은 측정 가능: EL9 `_hosts` 행은 persisted 판독을 runtime의 가설로 싣고 `_notes`가 EL
  VM이 생길 때까지 그렇다고 밝힘. 측정(Task 7): 이미지는 `50-default.conf`를 배포하지 않고 — VM에서는
  `systemd-udev`가 제공 — `rocky-release`의 `50-redhat.conf`가 그 뒤에 읽혀 `default.rp_filter 1`(6행), glob
  `*.rp_filter 1`, `all` 제외를 두므로 `default.rp_filter`는 `2`가 아니라 `1`, `all.rp_filter`는 커널의 `0` —
  컨트롤 10은 어느 쪽이든 `log_martians`로 FAIL. firewalld의 규칙 집합은 25행으로 접히고 그중 7이
  `opaque`(자체의 `ct status dnat accept`, 정책 jump 다섯, `meta l4proto { icmp, ipv6-icmp } accept`)라
  정규화기가 `full`이어도 거기선 컨트롤 1이 MANUAL. sshd는 `tcp/22` v4·v6, 둘 다 패키지.
- **GitHub 러너(root 잡).** `ufw` 비활성 → X-9 → 노출 판정됨: sshd `tcp/22`와 DHCP 클라이언트
  `udp/68`(둘 다 기본 목록에), 그리고 이미지의 에이전트가 listen하는 것 — examples 실행이 말해 주고 CI
  단언은 첫 실행 뒤에 씀(수집기는 절대 아님); 컨트롤 2는 PASS 예상; 컨트롤 3은 측정 뒤 단언(빌드되고
  재부팅 안 된 이미지는 업그레이드된 데몬을 돌릴 수 있음); sysctl 컨트롤은 위 Ubuntu 모양.
- **알려진 한계(만든 대로).** docker 호스트(`DOCKER-USER`/`FORWARD` 체인은 규칙을 가진 input 아닌 inbound
  체인)와 firewalld 호스트(규칙을 가진 기본 accept `filter_INPUT`)는 2H 단계 정규화기 아래
  `normalization_confidence partial`로 읽혀 컨트롤 1이 둘 다 MANUAL — 랩과 EL9 컨테이너에서 측정; 설명이
  그렇게 적고 존 모델은 보류로 남습니다(§8). `bindv6only` 1인 호스트에서 데몬이 스스로 `IPV6_V6ONLY`를 끈
  `::` 소켓은 v6만으로 읽힙니다(family 하나만큼 과소 노출). v4는 nft 규칙, v6는 legacy `ip6tables` 규칙인
  호스트는 v6가 `no_chain_in_family`로 읽힙니다 — legacy 교차 확인은 빈 nft 규칙 집합만 덮습니다. 패키지
  색인은 필요한 수집기마다 다시 만들며 약 130 ms(dpkg) 또는 110 ms(rpm) — X-4가 섭니다, 캐시 없음.

## 6. 테스트, CI, 문서

- **Fixture.** 컨트롤 1: `pass-ssh-only`(X-9 모양), `pass-filtered`(drop 정책, `port_rule` 22만, 5432 리스너,
  22에서 듣는 것은 없음 — 거기 sshd가 있으면 노출이라 목록이 비지 않음),
  `pass-state-and-loopback-rules`(수제 규칙: `iif lo accept`, `ct state established,related accept`, `tcp dport
  22 accept`, 정책 drop — 5432는 filtered), `pass-ufw-folded`(ufw 체인 접음, `ufw-user-input`이 22만 허용),
  `fail-ufw-folded-http`(… 그리고 80, nginx listen), `fail-open-policy-dns`, `fail-any-port-rule`,
  `fail-v6-unfiltered`(v4 규칙, v6 체인 없음, `::` 리스너), `fail-link-local`, `manual-partial-confidence`,
  `manual-opaque-rule`(`unmodelled` accept), `manual-proto-set`(`meta l4proto { tcp, udp }`),
  `error-firewall-denied`, `na-no-firewall-binary`(`exposure.exposed`가 방화벽의 `unsupported`를 실어 평가기가
  어느 leaf에서든 NOT_APPLICABLE로 읽음), `error-nonroot`, `na-container`. 허용 목록 매개변수는
  `internal/check`에서 증명(`fail-ufw-folded-http`가 `["tcp/22", "udp/68", "udp/546", "tcp/80"]`로 PASS),
  fixture로는 아님(3C-2a V-13). 컨트롤 2: `pass-all-packaged`, `pass-socket-activated`(pid 1과 sshd가
  소유자), `pass-kernel-socket`(nfsd, inode 0), `fail-usr-local-daemon`, `fail-snap-daemon`, `fail-foreign-ns`,
  `manual-no-package-db`, `manual-unmatched-owner`, `error-nonroot`, `error-index-timeout`, `na-container`;
  매개변수 테스트는 `/usr/local` 경로를 허용. 컨트롤 3: `pass-none`, `fail-one`, `fail-memfd`, `error-nonroot`,
  `na-container`. sysctl 컨트롤마다: `pass-*`, 절마다 `all`과 `default`가 각각 한 번 어긋나는 `fail-*`, 기본
  판독이 FAIL인 곳의 `fail-stock-ubuntu`, `fail-all-absent`(판정 키 전부 absent — IPv4 컨트롤의 `absent_means`
  변이를 죽이는 3B 선례), `pass-persisted-drift`(runtime은 맞고 `sysctl.d`는 틀림 — 설정의 effective 면은
  runtime이므로 PASS; 3B처럼 drift는 보고하되 판정하지 않음), `na-container`; IPv6 컨트롤은
  `na-no-ipv6`(키 absent), `na-ipv6-disabled-both`(`ipv6_disabled` 1), 그리고 `disable_ipv6` leaf 하나만 켠 판정
  PASS/FAIL 쌍(leaf 하나로는 게이트가 닫히지 않음을 증명, W-79)을 더함. 방화벽 수집기의 fixture는 U-28을 위한
  `fail-ufw-inactive.json`을 얻음(X-9). 모든 fixture `synthetic: true`; 판정되는 모든 행이 모든 필드를
  실음(3C-2a V-9).
- **변이 테스트.** 생존 0. `_mutants.yaml`에 행 열일곱: 컨트롤 3의 `absent_means` 셋과 `where` 경계 ±1(leaf는 `/proc`만으로
  쓰여 결코 `absent`가 아님; pid는 음수가 아님), 그리고 IPv6 컨트롤 넷의 `absent_means` 행 열둘(게이트
  `ipv6_disabled`는 판정 키와 같은 `/proc/sys/net/ipv6/conf` 표에서 파생되고 커널은 그 표를 한 번에 만들므로
  게이트가 `ok 0`인데 판정 키가 `absent`일 수 없음 — W-20, W-79); 그 밖의 모든 컨트롤은 fixture로 `absent`에
  닿음.
- **오라클(랩 root; CI root 잡).** `TestOracleListeners`: `processes.listeners`를 `ss -tulpnH`(iproute2, 고정
  인자; 오라클 자신의 명령)와 비교 — 모든 행의 proto/port가 맞고 `ss`가 `users:(…)`에 이름 대는 모든
  pid가 `owners`에 있음; `compared N` 로그. 기존 `TestOracleSysctl`이 설정 스물여섯과 `bindv6only`도 비교 — 3B의 열둘과 함께 39 키, 통과하는 어느
  커널에서나 키 목록의 길이이므로 CI는 정확한 수를 grep. `TestOracleListeners`는 역방향도 확인 — `ss`가
  나열하는 모든 소켓이 행 — 하고 root가 아니거나 `processes.listeners`가 `absent`(컨테이너의 부분 pid
  시야)면 skip; 랩은 24를 비교. `TestOracleDeletedExecutable`: 테스트가 자기 테스트 바이너리를 `t.TempDir()`에 복사해 사본을
  sleeper로 실행하고(`MUSTER_ORACLE_SLEEPER=1`, helper-process 패턴) 사본을 unlink한 뒤 수집기를 돌려 자기
  자식의 행이 `exe_deleted: true`로 읽히는지 단언; 자식은 테스트가 종료(호스트의 어떤 것도 바뀌지 않음).
  `/bin/sleep`이 아닌 이유: EL9에서 그것은 `coreutils --coreutils-prog-shebang`으로 가는 52바이트 shebang
  스크립트(`coreutils-single`)라 그 사본은 결코 삭제된 `exe`를 갖지 않음(rocky·alma init 이미지에서 측정;
  W-85). 랩 레시피에 `docker run --net=host` 프로브를 더해 `mnt_ns: foreign`과
  overlayfs가 도는 컨테이너의 `exe`에 `(deleted)`를 찍지 않음을 측정. 방화벽 접기는 랩에서 아무것도 켜지
  않고 증명: 랩의 규칙 집합을 읽기 전용으로 dump하고 접힌 행을 계획의 측정 태스크에서
  `iptables-save`/`nft list ruleset`과 손으로 비교. `exposure.*`에는 물을 데몬이 없고; 분류기는 확장된 파서가
  내는 모든 행 모양 — 리뷰의 바이트 동일 accept 여섯(`-i lo`, `-m conntrack`, `ct state`, `iif "lo"`, `ip
  daddr … accept`, `-d … -j ACCEPT`)과 프로토콜 집합 포함 — 에 대해 단위 테스트됨.
- **Fuzz.** `FuzzParseProcStatus`, `FuzzParseCmdline`, `FuzzParseFdLink`, `FuzzClassifyRule`,
  `FuzzParsePortSpec`, `FuzzFoldChains`, 그리고 확장된 `FuzzParseNftRuleset` / `FuzzParseIptablesSave` 시드
  (`meta l4proto { tcp, udp }`, `--dports 22,80`, `1000:2000`, `tcp dport vmap { 22 : accept }`).
- **Capability matrix.** `nonroot.denied` += `processes.deleted_executables`, `processes.listeners`,
  `processes.unpackaged_listeners`, `exposure.exposed`; `_notes` += `processes.list`(denied 행을 가진 ok),
  방화벽 바이너리 없는 호스트의 `exposure.exposed`(unsupported → NOT_APPLICABLE, U-28처럼; docker나 firewalld 호스트에선 `partial` → MANUAL);
  비특권 컨테이너의 `processes.listeners`(`ubuntu:24.04`에서 측정: 다른 uid의 프로세스만 `exe`/`fd` 링크를
  거절해 leaf를 `denied`로 만듦).
- **CI.** root 잡: `processes.stats.index_source == "dpkg"`, `exposure.listeners`의 `tcp/22` 행, 오라클
  `compared`/행 grep 셋에 대한 `jq` 단언; 노출 단언(`exposure.stats.confidence`와 러너가 실제로 읽는 `via`)은
  §5대로 첫 실행이 정함. 비root 잡은 matrix로 `denied` 키 넷을 단언; 컨테이너 잡은 새것 없음.
  `cmd/muster/collect_test.go`의 list-actions는 프로세스 수집기의 행(glob, `fact firewall.*`, 공유 rpm 질의)을
  얻음.
- **문서.** 메인 설계가 **D32** — *노출은 리스너·프로세스·설정된 방화벽의 join으로 읽고, 허용 목록은
  호스트 자신의 선언이다* — 를 얻고 §10.2의 3C-2b 항목을 다시 적음(여기 들어온 것; `fix --dry-run`,
  프로파일/CIS, `--anonymize`, `--max-age`는 3D/3E로). CLAUDE.md에 "Exposure (stage 3C-2b)". README와
  README.ko는 beyond 49. CHANGELOG: Controls(`+2026.10.xx`, 열셋, 기본 FAIL들, 비활성 백엔드에서 U-28의
  판정 — D16), Collectors(`processes`, 색인 패키지, `net.sysctl.*`와 glob 키, 확장된 방화벽 규칙 표와 접기),
  Tooling(D32, matrix 행, 오라클 셋). `docs/reference/coverage.md` 재생성; `hosts_test.go`의 표 둘(Ubuntu 표에
  beyond 49; EL9 표는 17에서 자라고 그 스냅샷은 새 계열을 실어 표의 어느 컨트롤도 ERROR가 아님).
  레지스트리의 `sockets.listening` 설명에서 "pid and executable"을 뺌(결코 싣지 않았음; 프로세스 수집기가
  싣음). 한국어 쌍은 같은 커밋에.

## 7. 평가기와 스키마

- 새 연산자 없음. 컨트롤 3의 "어느 행이든" 절은 모든 행이 싣는 필드에 `pid gte 0`을 씁니다(없는 필드에
  대한 `where`는 `present`에선 조용한 비적중, 비교에선 `missingFieldError` — 비교가 더 안전한 관용구).
  컨트롤 1의 `subject`는 수집기가 쓰는 `service` 문자열을 이름 대므로 reason이 `tcp/8080`으로 읽히고
  observation 키는 서비스마다 하나.
- `Builder.Get(key)`와 `Declaration.Facts`가 `internal/collect`의 추가: 앞선 수집기가 쓴 사실의 읽기, 선언된
  glob에만 허용, 벗어나면 선언 테스트가 잡는 panic, 선언된 사실은 `--list-actions`에 출력. 실행 순서
  의존은 `TestDeclaredFactsAreWrittenBeforeTheyAreRead`(선언된 모든 사실의 수집기가 읽는 쪽 앞에 정렬)가
  고정; 선언된 사실이 없을 때 쓰인 `exposure.*` 키는 그것을 적은 `error`(프로그래밍 오류이지 호스트 상태가
  아님).
- 스키마 버전 불변: `net.sysctl.*` 키 스물여덟과 `processes.*`/`exposure.*` 키 아홉, 모두 `since: 1`;
  `firewall.rules` 행에 필드 여덟(C2). 사실 골든은 새 항목으로 재생성; `sockets.listening`의 설명 변경은 설명
  전용.
- X-9의 확장은 비활성 백엔드 호스트에서 U-28의 판정을 바꿈(MANUAL → FAIL): Controls CHANGELOG 항목,
  U-28 fixture, `controls/VERSION` 올림(D16).

## 8. 보류

- 규칙 순서(drop이 앞서든 accept를 셈 — 보수적, FAIL이 늘 뿐 false PASS는 없음); 깊이 4 또는 2000행 너머의
  사용자 체인(`opaque` → MANUAL).
- firewalld 존 모델의 1급 정규화(규칙을 가진 기본 accept `filter_INPUT`은 `partial` → 기본 EL9에서 컨트롤 1
  MANUAL); `nat`/DNAT(docker의 공개 포트 — `docker-proxy` 리스너는 여전히 리스너라 `exposure.*`에 나타남);
  여러 네트워크 네임스페이스(`ip netns`); 포트 선택자로서의 named set; `tcp flags`, `meta mark`, `-m owner`
  선택자(오늘은 `opaque`).
- 인터페이스별 sysctl(`conf.<if>.*`); `net.ipv4.conf.*.arp_*`; `tcp_timestamps`, `tcp_rfc1337`;
  `bpf_jit_harden` 외의 `net.core.*`.
- UDP: 비연결 UDP 소켓은 서비스하든 응답을 기다리든 listening으로 읽힘(chrony의 `udp/323`은 루프백;
  클라이언트의 임시 소켓은 아님) — 높은 포트의 UDP 리스너는 있는 그대로 보고됨.
- 리스너가 아닌 프로세스의 패키지 판정(컨트롤 2는 리스너만 판정; `processes.list`는 모든 프로세스의
  `package_status`를 증거로 실음); 둘째 선언 원천으로서의 snap/flatpak 매니페스트(오늘 `snap`은
  `allowed_executables`로 완화하는 정직한 FAIL).
- 판정 원천으로서의 `needrestart` / `needs-restarting`; `packages.verify.modified`와 패키지 색인의 join(3C-1
  §8); 컨트롤 3의 이유로서 삭제된 실행파일 경로의 소유 패키지.
