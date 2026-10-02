# 3C-2b 단계 — 노출: 실제로 닿는 것은 무엇이고, 누가 그것을 서비스하는가

**상태:** 설계, 2026-10-02 대화에서 승인; 영어 원본은 `2026-10-02-stage3c2b-exposure-design.md`.
상위 문서: `2026-09-02-muster-design.md`(D01–D31; 이 단계가 D32를 더함). 선행: 3C-1
(`2026-09-23-stage3c1-audit-integrity-design.md`)과 3C-2a(`2026-09-29-stage3c2a-privilege-design.md`) —
두 문서 §8이 보류한 항목을 이 단계가 가져옵니다.

## 1. 범위와 의도

가이드는 불필요한 서비스가 도는지(U-52의 소켓 표)와 방화벽이 있는지(U-28)를 묻습니다. 둘 다 호스트가
실제로 네트워크에 무엇을 내놓는지는 말하지 않습니다: 설정된 방화벽을 통과해 호스트 밖의 패킷이 닿을 수
있는 listening 소켓은 무엇이고, 각각에 어느 프로세스가 답하며, 그 프로세스가 패키지 관리자가 둔 것인지.
3C-2b는 그 join을 읽고 읽은 대로 판정합니다: 호스트 밖에서 닿는 리스너는 호스트 자신의 허용 목록에
있어야 하고, 리스너는 패키지에 속해야 하며, 어떤 프로세스도 디스크의 파일이 더는 아닌 실행파일을 돌려선
안 됩니다. join 곁에, 커널의 네트워크 sysctl — 호스트가 포워딩하는지, ICMP 리다이렉트와 소스 라우트를
받아들이는지, 위조된 발신 주소를 거르는지를 정하는 손잡이들 — 이 3B의 `sysctl` 수집기에 합류합니다.

브레인스토밍에서 정한 결정(X-1 … X-6):

- **X-1 — 범위.** "노출" 묶음: 프로세스 수집기, 삭제된 실행파일을 도는 프로세스, 방화벽에 대한 노출
  교차검증, 네트워크 sysctl. 제외: `packages.verify.modified`와 walk 패키지 표의 join(3C-1 §8, 보류
  유지), `fix --dry-run`, 프로파일과 CIS 참조(3D), `--anonymize`, `--max-age`(3E).
- **X-2 — join 위의 컨트롤 셋.** 허용 목록에 없는 노출 리스너는 FAIL; 실행파일이 어느 패키지에도 속하지
  않는 리스너는 FAIL; 삭제된 실행파일을 도는 프로세스는 FAIL. 각각 읽은 대로 판정하고 `params`나
  waiver로만 완화합니다(D31의 철학).
- **X-3 — 프로세스 수집기는 읽을 수 있는 만큼 읽습니다.** 모든 pid를 열거하고; 실행이 `exe`나 `fd`
  디렉터리를 읽지 못한 프로세스는 `denied` 행이며, 그런 행을 빼야 할 판정 leaf는 스스로 `denied`입니다.
  root는 전부 읽고; 비root 실행은 자기 프로세스만 읽어 컨트롤 셋을 ERROR로 읽습니다(`nonroot.denied`
  행). deep 게이트 없음.
- **X-4 — 패키지 색인은 모든 collect에서 만듭니다.** walk가 이미 쓰는 dpkg 목록 또는 고정 rpm 질의를
  walk와 프로세스 수집기가 공유하는 패키지로 빼내어 둘이 함께 돌 때 한 번만 만듭니다; 비용은 측정하고
  상한을 둡니다.
- **X-5 — 네트워크 sysctl 컨트롤 여섯 주제**, 각각 `all`과 `default`, 설정의 양면을 판정; 포워딩은 있는
  그대로 읽습니다(docker 호스트는 FAIL이고 매개변수로 완화).
- **X-6 — "방화벽을 통과한다".** 정규화 신뢰도 full에서: inbound가 제한되지 않으면 루프백 외 모든
  리스너; 그렇지 않으면 프로토콜과 포트가 accept 규칙에 맞는 리스너 — 규칙의 source는 무엇이든(source는
  기록하며, 한 서브넷에만 열린 관리 포트도 호스트 밖에서 닿는 서비스). 정규화가 "프로토콜과 포트"로
  표현하지 못하는 accept 규칙 — 인터페이스, 연결 상태, 규칙 표가 싣지 않는 그 밖의 것으로 고르는 규칙
  — 은 호스트의 노출 판정을 MANUAL로 만들고(X-6의 안전장치), 신뢰도 partial도 그러합니다.

## 2. 아키텍처

수집기 둘이 바뀌고 정렬된 실행 목록에 새로 더해지는 것은 하나입니다:

- **`processes`(신규)** — `/proc`를 열거하고, 호스트의 각 listening 소켓을 소유 프로세스와 join하고
  (`/proc/<pid>/fd` 링크), 각 실행파일을 패키지 색인과 join하고 — 방화벽 수집기가 이미 돌았으므로
  (수집기는 이름순으로 돌고 `firewall` < `processes`; 테스트가 그 순서를 고정) — 방화벽의 정규화된
  규칙으로부터 `exposure.*` 사실을 파생합니다. 두 계열 `processes.*`, `exposure.*`를 쓰고 그 밖은 쓰지
  않습니다. `Builder`는 읽기 접근자 하나 `Get(key) (facts.Envelope, bool)`를 얻어 수집기가 앞선 수집기가
  쓴 사실을 읽을 수 있습니다; builder의 다른 것은 바뀌지 않습니다.
- **`sysctl`(3B, 확장)** — `net.sysctl.*` 키 스물셋을 얻고, 커널 키와 똑같이 읽습니다(B-3: runtime은
  `/proc/sys`, persisted는 `sysctl.d` 체인, 명령 없음).
- **`firewall`(2H, 레코드 필드 하나)** — `firewall.rules`의 각 행이 `family`(`v4`, `v6`, `inet`)를 얻습니다;
  파서는 이미 dump마다·nft 테이블마다 이를 알고 있습니다; 레코드 필드 추가는 `schema_version`을 유지
  (C2).
- **`pkgindex`(신규 내부 패키지)** — walk의 join이 오늘 쓰는 dpkg 목록 리더(`/var/lib/dpkg/info/*.list`,
  `statoverride`, postinst 이름)와 rpm 파일 표 질의가 그대로 여기로 옮겨지고; walk의 join과 프로세스
  수집기가 호출합니다. 이 추출은 동작을 보존하는 리팩터이며 계획의 첫 태스크입니다.

평가기는 §7이 말하는 곳 외에는 바뀌지 않습니다(`where` 필드 op는 이미 있음). 리포트의 `scopes.beyond`
개수는 열셋 늘어납니다. exit code는 그대로입니다.

## 3. 사실

### P-1 `processes.*`

선언: `Reads` `/proc/[0-9]*/status`, `/proc/[0-9]*/cmdline`, `/proc/[0-9]*/exe`, `/proc/[0-9]*/fd`,
`/proc/[0-9]*/fd/*`(`/proc/self`와 `/proc/thread-self`는 절대 아님; `/proc/self`로 읽은 pid는 수집기
자신일 것), 더해서 패키지 색인의 선언(`/var/lib/dpkg/info/*.list`, `/var/lib/dpkg/statoverride`, 고정
`rpm -qa --qf` 질의)과 소켓 표 `/proc/self/net/{tcp,udp,tcp6,udp6}`(`sockets`와 `services`가 읽는 같은
파일 넷 — R232: 표는 수집기마다 한 번, 소켓마다가 아니라). `Needs: none`. `exe`와 `fd/*`는 `Readlink`로만
읽고; 링크 대상은 절대 열지 않습니다.

열거: `/proc`의 숫자 항목 전부(`task/` 아래 스레드는 `/proc`의 항목이 아님; 목록과 읽기 사이에 사라진
pid는 행을 남기지 않고 `processes.stats.vanished`를 올림). 프로세스마다: `status`가 `Name`, `PPid`, real
`Uid`를; `cmdline`이 NUL로 나눈 첫 토큰을(4 KiB 상한; 커널 스레드는 `cmdline`이 빔); `exe`가 링크 대상을.
커널 스레드 — `exe` ENOENT이고 `cmdline`이 빈 것 — 는 `kind: kernel` 행이며 아무것도 판정하지 않습니다.

- `processes.list` — `list<record>` `{pid, ppid, uid, name, cmd, exe, exe_deleted, exe_read_status,
  kind, package, package_status}`, `pid` 정렬, 상한 4096행(넘으면 `truncated: true`; 아래 카운트는 여전히
  모든 프로세스를 봄). `exe_deleted`는 `readlink`가 ` (deleted)`로 끝나는 대상을 돌려줄 때 true —
  exec 뒤 unlink되거나 교체된 실행파일에 대한 `proc(5)` 자신의 표기이며, 업그레이드되고 아직 재시작
  안 된 데몬과 시작 뒤 디스크에서 지워진 바이너리가 같게 읽힙니다. `exe_read_status`는 `ok`,
  `denied`(비root 실행에서 다른 계정의 프로세스, EACCES), `error`. `kind`는 `user` 또는 `kernel`.
  `package`는 색인이 아는 `exe` 경로의 소유자(` (deleted)`를 먼저 떼고; 삭제된 실행파일의 경로가 여전히
  소유될 수 있음 — 그때 행은 `package_status: deleted`), `package_status`는 `packaged`, `unpackaged`,
  `deleted`, `no_index`(색인을 만들 수 없었음 — 아래 leaf가 색인 읽기의 상태를 실음). `sensitivity:
  internal`(명령 이름과 경로).
- `processes.deleted_executables` — `list<record>` `{pid, uid, name, exe}`: 판정용 부분집합(C2). user
  종류 프로세스 중 하나라도 `exe`를 읽지 못했으면 leaf는 그 읽기의 상태(비root 실행에선 `denied`)이고,
  읽을 수 있던 것의 부분집합이 아닙니다 — 실행이 볼 수 있던 프로세스에 대한 PASS는 읽지 않은 증거에
  대한 PASS일 것입니다.
- `processes.listeners` — `list<record>` `{proto, addr, port, loopback, inode, pid, uid, name, exe, package,
  package_status, owner_status}`: 호스트의 모든 listening 소켓(`sockets.listening`이 싣는 같은 행을 여기서
  다시 읽음)에 `socket:[<inode>]` 꼴의 `/proc/<pid>/fd/*` 링크로 찾은 소유 프로세스를 붙인 것.
  `owner_status`는 `ok`, `unmatched`(모든 `fd` 디렉터리를 읽었는데 inode를 가진 프로세스가 없음 — 다른
  네트워크 네임스페이스의 소켓, 또는 두 읽기 사이에 닫힌 소켓), `denied`(`fd` 디렉터리를 읽지 못했으므로
  소유자가 실행이 볼 수 없던 프로세스일 수 있음); 뒤의 둘에선 `pid`가 -1. `fd` 디렉터리가 하나라도
  `denied`였으면 leaf 자체가 `denied`. 상한 2000행; `proto`, `port`, `addr` 정렬.
- `processes.unpackaged_listeners` — `list<record>` `{pid, name, exe, proto, addr, port, reason}`: 판정용
  부분집합 — 루프백 포함 리스너 중 색인이 소유하지 않는 실행파일(`reason: unpackaged`)이거나 실행파일이
  삭제된 것(`reason: deleted` — 답하는 파일이 패키지가 배포한 파일이 아님). 색인을 만들 수 없었으면 그
  읽기의 상태; `processes.listeners`가 그렇듯 `denied`.
- `processes.stats` — 레코드 `{count, kernel_threads, denied, vanished, index_source, index_ms, fd_reads,
  elapsed_ms}`; `index_source`는 `dpkg`, `rpm`, `none`.

예산: 프로세스당 `fd` 항목 4096개(넘으면 그 프로세스의 소켓은 읽은 것으로만 맞추고 맞지 않은 소켓의
`owner_status`는 `unmatched`로 남음), 전체 열거 5 s(넘으면 `processes.list`는 `truncated`이고 판정
leaf들은 `truncated: true`를 실어 평가기가 `ERROR(truncated)`로 읽음). 패키지 색인은 오늘 walk가 두는
상한 그대로.

상태(C3/C4): 가려진 `/proc`(`ErrProcfsMasked`, `sockets` 수집기의 검사)는 모든 `processes.*` 키에
`unsupported`; `/proc/<pid>/exe`나 `fd`의 EACCES는 행의 `exe_read_status`/`owner_status`이고 판정 leaf의
`denied`; 만들 수 없는 색인(dpkg 목록 denied, rpm 질의 실패)은 `processes.unpackaged_listeners`에 그
읽기의 상태를, 모든 행에 `package_status: no_index`를 둡니다.

### P-2 `exposure.*`(`processes`가 씀)

입력: `processes.listeners`(위)와 `Builder.Get`으로 읽는 방화벽 수집기의 사실
`firewall.normalization_confidence`, `firewall.restricts_inbound`, `firewall.rules`, `firewall.backend`.
테스트가 `firewall`이 `processes` 앞에 정렬됨을 고정하고; 장래 수집기가 순서를 깨면 `exposure.*`는 빠진
사실을 적은 `error`로 읽힙니다.

규칙 분류 — `action`이 accept인 모든 `firewall.rules` 행을 분류합니다:

- `port_rule`: `proto`가 `tcp`/`udp`이고 `dport`가 파서가 열거할 수 있는 포트, 범위 `a-b`, 집합 `{a, b, c}`
  (최대 256개 포트의 집합; named set은 `opaque`);
- `any_port`: `proto`와 `dport`가 둘 다 빔 — 체인이 보는 모든 것의 accept;
- `opaque`: 그 밖 — 규칙 표가 싣지 않는 선택자(인터페이스, 연결 상태, ICMP 타입, named set, 포트 없는
  주소만의 매치)를 가진 accept.

노출은 `normalization_confidence: full`이고 리스너 family의 input 체인에 `opaque` 규칙이 없을 때만 정합니다:

- `restricts_inbound: false` → 루프백 외 모든 리스너가 노출, `via: open_policy`;
- `restricts_inbound: true` → 그 family에 `any_port` 규칙이 있으면 노출(`via: any_port_rule`), 또는
  `port_rule`이 프로토콜·포트에 맞으면 노출(`via: rule`, 규칙의 `chain`과 `saddr`를 기록); 아니면
  `filtered`.
- `0.0.0.0`이나 `::`에 바인딩된 소켓은 그 family의 후보; `::`는 v4 후보이기도 함(dual-stack 바인딩, 커널
  기본 `bindv6only=0`); 특정 주소는 루프백(`127.0.0.0/8`, `::1`)이나 링크로컬(`fe80::/10`,
  `169.254.0.0/16`)이 아니면 후보 — 루프백·링크로컬은 기록만 하고 결코 노출로 보지 않음. `family`가 없는
  `firewall.rules` 행(이전 스냅샷)은 두 family에 모두 적용.

키:

- `exposure.listeners` — `list<record>` `{proto, addr, port, service, pid, name, exe, package, exposed, via,
  rule_chain, rule_source, reason}`, 루프백 외 모든 리스너; `service`는 `"<proto>/<port>"`(`tcp/22`), 허용
  목록이 쓰는 문자열; `proto`, `port`, `addr` 정렬. 증거.
- `exposure.exposed` — `list<record>` `{service, proto, addr, port, pid, name, package, via, rule_chain,
  rule_source}`: 노출된 부분집합(판정용). 판정을 읽을 수 없으면 원인을 적은 `absent` —
  `normalization confidence is partial`, `opaque accept rule in <chain>: <raw>` — 로 컨트롤은 MANUAL;
  방화벽을 읽지 못했으면 그 읽기의 상태(`unsupported`, `denied`); `processes.listeners`가 `denied`면
  `denied`.
- `exposure.opaque_rules` — `list<record>` `{chain, family, action, raw}`: 판정을 막은 것의 증거.
- `exposure.stats` — 레코드 `{listeners, exposed, filtered, loopback, link_local, opaque_rules, confidence}`.

방화벽이 없는 호스트(`firewall.backend: none`)는 신뢰도 full에서 `restricts_inbound: false`이므로 루프백
외 모든 리스너가 노출이고 컨트롤은 U-28 곁에서 FAIL합니다: 둘은 원인과 결과를 말하며, 설명이 그렇게
적습니다.

### P-3 `net.sysctl.*`(`sysctl` 수집기)

`setting<int>` 키 스물셋, `default_on: effective`(= runtime, B-3), 각각 `sysctl.d`의 두 홈을 persisted
면으로, `since: 1`:

| 키 | sysctl |
|---|---|
| `ipv4_ip_forward` | `net.ipv4.ip_forward` |
| `ipv6_all_forwarding` | `net.ipv6.conf.all.forwarding` |
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

`all`은 지금의 모든 인터페이스에, `default`는 이후 생기는 모든 인터페이스에 적용됩니다(`ip-sysctl.rst`);
`all`은 조이고 `default`는 느슨한 호스트는 새 인터페이스 — 컨테이너의 veth, VPN — 에 느슨한 값을
주므로 둘을 모두 판정합니다. 인터페이스별 값은 수집하지 않습니다(§8). IPv6 없는 커널(`/proc/sys/net/ipv6`
없음)은 모든 `ipv6_*` 키를 "IPv6 is not built or is disabled" 이유의 `absent`로 만들고, 컨트롤은 그것을
NOT_APPLICABLE로 읽습니다(§4).

## 4. 컨트롤

`category: beyond` 컨트롤 열셋, id `muster.beyond.<name>`, `controls/beyond/` 아래, 모두
`env.container eq none` 게이트(컨테이너의 프로세스·방화벽·네트워크 네임스페이스는 호스트의 정책이 아님),
`automation: auto`. 중요도는 각 설명이 이름 댄 1차 원문에서 muster가 매긴 것입니다.

| # | id | 중요도 | 절(`checks`) | absent_means |
|---|---|---|---|---|
| 1 | `exposed_listeners_allowed` | 상 | `{ fact: exposure.exposed, op: none, subject: service, where: { field: service, op: not_in, expected: "${allowed_ports}" } }`; `params.allowed_ports: list<string>` 기본 `["tcp/22"]` | manual — 신뢰도 partial, opaque accept 규칙(`manual-*` fixture) |
| 2 | `listeners_packaged` | 중 | `{ fact: processes.unpackaged_listeners, op: none, subject: exe, where: { field: exe, op: not_in, expected: "${allowed_executables}" } }`; `params.allowed_executables: list<string>` 기본 `[]` | fail — 닿지 않음: leaf는 `ok`거나 읽기 상태(`_mutants.yaml` 행 셋) |
| 3 | `no_deleted_executables` | 중 | `{ fact: processes.deleted_executables, op: none, subject: pid, where: { field: pid, op: present } }` | fail — 위와 같이 닿지 않음(행 셋) |
| 4 | `ip_forwarding_disabled` | 중 | `{ fact: net.sysctl.ipv4_ip_forward, op: in, expected: "${allowed_forward}" }`; `params.allowed_forward: list<int>` 기본 `[0]` | fail |
| 5 | `ipv6_forwarding_disabled` | 중 | `net.sysctl.ipv6_all_forwarding in ${allowed_forward}`(같은 매개변수 이름과 기본값) | not_applicable(IPv6 없음) |
| 6 | `icmp_redirects_ignored` | 중 | ipv4 키 여섯 `eq 0`: accept·secure·send redirects × all/default | fail |
| 7 | `ipv6_redirects_ignored` | 중 | ipv6 accept_redirects 키 둘 `eq 0` | not_applicable |
| 8 | `source_routing_rejected` | 중 | ipv4 accept_source_route 키 둘 `eq 0` | fail |
| 9 | `ipv6_source_routing_rejected` | 중 | ipv6 accept_source_route 키 둘 `eq 0` | not_applicable |
| 10 | `reverse_path_filtering` | 중 | `ipv4_all_rp_filter in [1, 2]`, `ipv4_default_rp_filter in [1, 2]`, `ipv4_all_log_martians eq 1`, `ipv4_default_log_martians eq 1` | fail |
| 11 | `icmp_broadcast_and_bogus_ignored` | 하 | `ipv4_icmp_echo_ignore_broadcasts eq 1`, `ipv4_icmp_ignore_bogus_error_responses eq 1` | fail |
| 12 | `syn_cookies_enabled` | 중 | `ipv4_tcp_syncookies eq 1` | fail |
| 13 | `ipv6_router_advertisements_ignored` | 중 | ipv6 accept_ra 키 둘 `eq 0` | not_applicable |

**IPv4와 IPv6를 왜 별도 컨트롤로 두나(X-7).** 컨트롤은 `absent_means`가 하나이고, IPv6 키는 IPv6 없는
커널에서 `absent`인데 IPv4 키는 결코 absent가 아닙니다; 둘을 섞은 컨트롤은 IPv6 없는 커널에서의
FAIL과 없는 IPv4 파일에서의 NOT_APPLICABLE 사이에서 골라야 합니다. 그래서 브레인스토밍의 여섯 주제는
컨트롤 열셋으로 나갑니다: beyond 36 → 49. `rp_filter`는 1(strict)과 2(loose — Ubuntu의 배포 값, 비대칭
라우팅에 맞음)를 받습니다 — 둘 다 위조 발신을 거르므로; 0은 FAIL.

설명(muster의 말, KISA·CIS 원문 없음): 1차 원문과 중요도의 이유; 기본 판독(§5: 기본 Ubuntu는
리다이렉트·소스 라우팅·martian·RA에서 FAIL; docker나 libvirt 호스트는 포워딩을 있는 그대로 FAIL하고
`allowed_forward: [0, 1]`로 완화); MANUAL/NOT_APPLICABLE/ERROR 경우; 컨트롤 1에는 U-28·U-52와의
관계(중복이 아니라 원인과 결과)와 허용 목록이 호스트가 무엇을 서비스하는지 스스로 선언하는 것이라는
점; 컨트롤 2에는 `/usr/local` 데몬이 흔한 정직한 FAIL이고 `allowed_executables`가 그것을 이름 댄다는 점;
컨트롤 3에는 보통의 답이 업그레이드 뒤 재시작(`needrestart`, `dnf needs-restarting`)이고 드문 답이 도는
프로세스 아래서 지워진 바이너리라는 점.

참조: `nist_800_53` — 컨트롤 1 `CM-7`, `SC-7`; 컨트롤 2 `CM-7(5)`; 컨트롤 3 `SI-2`, `CM-7(5)`; sysctl
컨트롤 `SC-7`, `SC-5`(syncookies), `CM-6`. `references.stig`는 커밋된 인덱스에 맞는 id가 있는 곳에(계획의
프리플라이트가 각각 확인; lint가 모르는 id를 거부). `subject_kind`: 컨트롤 1–2는 `exe`/`service`
문자열(NSS 아님), 컨트롤 3은 `pid`; 어느 것도 원격 NSS WARN을 일으키지 않습니다.

## 5. 환경과 기본 판독

- **비root.** `processes.deleted_executables`, `processes.listeners`, `processes.unpackaged_listeners`,
  따라서 `exposure.exposed`가 `denied`(다른 계정의 `exe`와 `fd`)이므로 컨트롤 1–3은 ERROR;
  `processes.list`는 다른 계정 행에 `exe_read_status: denied`를 둔 채 `ok`(`_notes` 항목);
  `net.sysctl.*`는 답함(`/proc/sys/net`은 world-readable, `sysctl.d` 체인도). `nonroot.denied`에 키 넷.
- **systemd 없음.** 변화 없음: `/proc`와 `/proc/sys`만.
- **컨테이너.** 모든 컨트롤이 게이트로 NOT_APPLICABLE. 수집기는 그래도 돕니다: `processes.*`는
  컨테이너의 pid 네임스페이스를 읽어 `ok`, 가려진 `/proc`는 `unsupported`(`sockets` 선례 — 새
  `container.unsupported` 행 없음); `net.sysctl.*`는 컨테이너 네임스페이스 값(`ok`).
- **기본 Ubuntu 22.04(가설; 랩이 측정, 3C-2a의 V-18).** 리스너: sshd `tcp/22`(`0.0.0.0`, `::`),
  systemd-resolved `127.0.0.53`(루프백), chrony `udp/323`(루프백)과 설정 시 `udp/123`; 기본 서버에서
  `ufw` 비활성 → `firewall.backend none` → 루프백 외 모든 리스너 노출 → 컨트롤 1은 `tcp/22` 외에 닿는
  것이 없을 때만 PASS — 랩 호스트(docker 프록시, kubelet)는 있는 그대로 FAIL이고 `_hosts` 스냅샷은
  sshd만 있는 기본 모양을 PASS로 핀. 컨트롤 2 PASS, 컨트롤 3 PASS(갓 부팅). sysctl(Ubuntu의
  `10-network-security.conf`는 `rp_filter 2`만 둠): forwarding 0 PASS(docker 호스트는 1); `accept_redirects`
  all 0 / default 1 FAIL; `secure_redirects` 1 FAIL; `send_redirects` 1 FAIL; `accept_source_route` all 0 /
  default 1 FAIL; `rp_filter` 2/2와 `log_martians` 0 → FAIL; `echo_ignore_broadcasts 1` / `bogus 1` PASS;
  `syncookies 1` PASS; ipv6 `accept_redirects 1` FAIL, `accept_source_route 0` PASS, `accept_ra 1` FAIL,
  `forwarding 0` PASS. 열셋 중 여섯이 기본 호스트에서 FAIL(6, 8, 10, 7, 13, 그리고 docker 호스트에선 4);
  설명이 그렇게 적습니다.
- **기본 EL9(가설).** 프로세스 사실은 `rockylinux/rockylinux:9-ubi-init`에서 측정(컨테이너 안 sshd);
  네트워크 sysctl은 컨테이너에서 측정할 수 **없음**(값이 컨테이너 네트워크 네임스페이스의 것)이므로
  EL9 `_hosts`의 그 행들은 커널 문서의 기본값에 firewalld의 `net.ipv4.ip_forward` 거동을 적은 것이고,
  스냅샷 `_notes`가 EL VM이 생길 때까지 sysctl 행은 미측정이라고 밝힙니다. `public` 존(ssh 허용)의
  firewalld 활성이 기본 방화벽: `backend nft`, 신뢰도 — 계획이 랩의 EL9 이미지에서 firewalld가 생성한
  규칙 집합이 `full`로 정규화되는지 확인(그 `filter_INPUT` 체인은 존 체인으로 jump하여 accept하므로
  정규화기가 `partial`로 분류할 수 있음); `partial`이면 기본 EL9는 컨트롤 1을 MANUAL로 읽고 설명이
  그렇게 적습니다.
- **GitHub 러너(root 잡).** 방화벽 없음(`backend none`) → 컨트롤 1은 sshd 곁에 listen하는 것이 있으면
  FAIL(examples 실행이 말해 줌; CI 단언은 첫 실행 뒤에 쓰고 수집기는 절대 고치지 않음); 컨트롤 2는 PASS
  예상(러너 에이전트는 리스너가 아님); 컨트롤 3은 측정 뒤 단언(빌드되고 재부팅 안 된 이미지는
  업그레이드된 데몬을 돌릴 수 있음); sysctl 컨트롤은 위 Ubuntu 24.04 모양.

## 6. 테스트, CI, 문서

- **Fixture.** 컨트롤 1: `pass-ssh-only`, `fail-http-exposed`, `fail-open-policy-dns`(`backend none`,
  `0.0.0.0`의 `udp/53`), `pass-filtered`(어느 리스너에도 닿지 않는 `port_rule` 집합),
  `pass-open-policy-ssh-only`, `manual-partial-confidence`, `manual-opaque-rule`, `error-firewall-denied`,
  `error-nonroot`(`processes.listeners` denied), `na-container`. 허용 목록 매개변수는 `internal/check`에서
  증명(`fail-http-exposed`가 `allowed_ports: ["tcp/22", "tcp/80"]`로 PASS), fixture로는 아님(3C-2a V-13).
  컨트롤 2: `pass-all-packaged`, `fail-usr-local-daemon`, `fail-deleted-listener`, `error-nonroot`,
  `error-no-index`, `na-container`; 매개변수 테스트는 `/usr/local` 경로를 허용. 컨트롤 3: `pass-none`,
  `fail-one`, `error-nonroot`, `na-container`. sysctl 컨트롤마다: `pass-*`, 절마다 `all`과 `default`가
  각각 한 번 어긋나는 `fail-*`, 기본 판독이 FAIL인 곳의 `fail-stock-ubuntu`, `pass-persisted-drift`
  (runtime은 맞고 `sysctl.d`는 틀림 — 설정의 effective 면은 runtime이므로 PASS; 3B처럼 drift는 보고하되
  판정하지 않는다고 설명이 적음), `na-container`; IPv6 컨트롤은 `na-no-ipv6`를 더함. 모든 fixture
  `synthetic: true`; 판정되는 모든 행이 모든 필드를 실음(3C-2a V-9).
- **변이 테스트.** 생존 0. `_mutants.yaml`에 컨트롤 2·3의 `absent_means` 행(각 셋 — leaf는 `ok`거나 하드
  상태, 결코 `absent`가 아님); 그 밖의 모든 컨트롤은 fixture로 `absent`에 닿음.
- **오라클(랩 root; CI root 잡).** `TestOracleListeners`: `processes.listeners`를 `ss -tulpnH`(iproute2,
  고정 인자; 오라클 자신의 명령, 수집기의 것이 아님)와 비교 — 모든 행의 proto·port·pid를 비교하고
  `compared N`을 로그. `TestOracleSysctlNet`: 기존 sysctl 오라클의 `sysctl -n` 비교를 스물세 키로 확장.
  `TestOracleDeletedExecutable`: 테스트가 `/bin/sleep`을 `t.TempDir()`에 복사해 실행하고 사본을 unlink한
  뒤 수집기를 돌려 자기 자식의 행이 `exe_deleted: true`로 읽히는지 단언; 자식은 테스트가 종료(호스트의
  어떤 것도 바뀌지 않음). `exposure.*`에는 물을 데몬이 없고; 그 규칙 분류기는 방화벽 파서가 내는 모든 행
  모양에 대해 단위 테스트됨.
- **Fuzz.** `FuzzParseProcStatus`, `FuzzParseCmdline`, `FuzzParseFdLink`, `FuzzClassifyRule`,
  `FuzzParsePortSpec`, 시드 포함; 나머지는 nightly.
- **Capability matrix.** `nonroot.denied` += `processes.deleted_executables`, `processes.listeners`,
  `processes.unpackaged_listeners`, `exposure.exposed`; `_notes` += `processes.list`(denied 행을 가진 ok),
  방화벽 없는 호스트의 `exposure.exposed`.
- **CI.** root 잡: `processes.stats.index_source == "dpkg"`, `exposure.listeners`의 `tcp/22` 행이
  `exposed true, via open_policy`, 오라클 `compared` grep 다섯에 대한 `jq` 단언; 비root 잡은 matrix로
  `denied` 키 넷을 단언; 컨테이너 잡은 새것 없음. `cmd/muster/collect_test.go`의 list-actions는 변화
  없음(새 수집기 명령 없음; rpm 질의는 이미 목록에 있음).
- **문서.** 메인 설계가 **D32** — *노출은 리스너·프로세스·설정된 방화벽의 join으로 읽고, 허용 목록은
  호스트 자신의 선언이다* — 를 얻고 §10.2의 3C-2b 항목을 다시 적음(여기 들어온 것; `fix --dry-run`,
  프로파일/CIS, `--anonymize`, `--max-age`는 3D/3E로). CLAUDE.md에 "Exposure (stage 3C-2b)". README와
  README.ko는 beyond 49. CHANGELOG: Controls(`+2026.10.xx`, 열셋, 기본 FAIL들), Collectors(`processes`,
  색인 패키지, `net.sysctl.*`, 규칙의 `family` 필드), Tooling(D32, matrix 행, 오라클 셋). 레지스트리의
  `sockets.listening` 설명에서 "pid and executable"을 뺌(결코 싣지 않았음; 프로세스 수집기가 싣음).
  한국어 쌍은 같은 커밋에.

## 7. 평가기와 스키마

- 새 연산자 없음. 컨트롤 3의 "어느 행이든" 절은 모든 행이 싣는 필드에 기존 `where` 필드 op `present`를
  씁니다. 컨트롤 1의 `subject`는 수집기가 쓰는 `service` 문자열을 이름 대므로 reason이 두 번째 필드
  조회 없이 `tcp/8080 (pid 1234 nginx)`로 읽힙니다.
- `Builder.Get(key)`가 `internal/collect`의 유일한 추가: 정렬된 실행에서 앞선 수집기가 쓴 트리의 읽기.
  실행 순서 의존(`firewall`이 `processes` 앞)은 `TestCollectorOrderHasFirewallBeforeProcesses`가 고정;
  방화벽 사실이 없을 때 쓰인 `exposure.*` 키는 그것을 적은 `error`(프로그래밍 오류이지 호스트 상태가
  아님).
- 스키마 버전 불변: `net.sysctl.*` 키 스물셋, `processes.*`/`exposure.*` 키 아홉, 모두 `since: 1`;
  `firewall.rules` 행에 `family`(C2). 사실 골든은 새 항목으로 재생성.
- `sockets.listening`은 모양이 그대로; 설명만 고침(설명 전용 골든 변경).

## 8. 보류

- 인터페이스별 sysctl(`conf.<if>.*`); `net.ipv4.conf.*.arp_*`; `tcp_timestamps`, `tcp_rfc1337`;
  `bpf_jit_harden` 외의 `net.core.*`.
- 포트 선택자로서의 nftables named set; 정규화기가 이미 접는 범위 밖의 사용자 체인 jump; `nat`/DNAT
  (docker의 공개 포트는 거기 있음 — `docker-proxy` 리스너는 여전히 리스너라 `exposure.*`에 나타남);
  여러 네트워크 네임스페이스(`ip netns`); 인터페이스나 연결 상태로 매치하는 규칙(오늘은 `opaque` →
  MANUAL).
- UDP: 비연결 UDP 소켓은 서비스하든 응답을 기다리든 listening으로 읽힘(chrony의 `udp/323`은 루프백;
  클라이언트의 임시 소켓은 아님) — 높은 포트의 UDP 리스너는 있는 그대로 보고됨.
- 리스너가 아닌 프로세스의 패키지 판정(컨트롤 2는 리스너만 판정; `processes.list`는 모든 프로세스의
  `package_status`를 증거로 실음).
- 판정 원천으로서의 `needrestart` / `needs-restarting`; `packages.verify.modified`와 패키지 색인의
  join(3C-1 §8); 컨트롤 3의 이유로서 삭제된 실행파일 경로의 소유 패키지.
- firewalld의 존 모델을 1급 정규화로(오늘은 생성된 규칙 집합을 다른 nft 규칙 집합처럼 정규화).
