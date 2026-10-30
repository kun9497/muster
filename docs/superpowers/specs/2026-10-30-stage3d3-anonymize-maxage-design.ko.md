# 3D-3단계 — `snapshot anonymize`와 `--max-age`

영어 원본: `2026-10-30-stage3d3-anonymize-maxage-design.md`. 메인 설계: `2026-09-02-muster-design.md`(§5.1 스냅샷,
§5.6 마스킹, §5.7 스키마, §7.2와 §7.5 종료 코드와 거부, §8 `:426` 스냅샷 기밀성, §9 출력, §10.2 로드맵, D11, D13,
D34). 이 설계의 결정은 AX 목록입니다(한 글자 접두어는 앞 단계와 겹침). 바탕이 된 범위 지도는 사이클의 무시되는 작업
공간(`scope-{identifiers,verdicts,age,surface,prior,critic}.md`)에 있고, 구속력 있는 결론은 여기에 다시 적습니다. 첫
리뷰(`design-review-r1.md`, 33건)는 자유 텍스트를 토큰 치환에서 자리표시자로 바꾸고, 사이트 파일 매핑을 보류하고,
주소의 cycle-walk를 대체했습니다. 둘째(`design-review-r2.md`, 20건)는 AX-6의 이름 위치를 넓히고 읽기 규칙을 필드와
연산자 단위로 고정했고, 셋째(`design-review-r3.md`, 8건)는 호스트-또는-주소 분기를 순서 있는 한 규칙으로 만들었습니다.
구현 중 내린 결정(계획의 원장)도 반영했습니다: 경로 위의 모든 홈을 다시 쓰고, 경로는 제자리에서 다시 쓰며, 마운트
대상은 경로이고, 분류 넷(`host_or_netgroup`, `unit`, `blank`, 옵션 문법)을 더했습니다.

## 1. 범위와 의도

로드맵은 3단계를 "3D-3: 불변식 테스트를 갖춘 `--anonymize`, `--max-age`"로 마칩니다. 메인 설계는 앞의 것에 한 문장 —
"공유용 `--anonymize` 모드(호스트명, 주소, 사용자명의 안정적 해싱)가 익명화한 스냅샷과 원본 스냅샷이 같은 판정을
낸다는 불변식 테스트와 함께 3단계에 들어온다" — 을, 뒤의 것에는 이름만 줍니다. 이 사이클은 둘 다 만듭니다:

- **익명화**는 소유자가 스냅샷을 외부 — 벤더, 컨설턴트, muster 버그 리포트 — 에 넘기면서 그것이 어느 호스트와 어느
  사람들을 묘사하는지는 넘기지 않게 하며, 받는 쪽은 내장 프로파일에서 소유자와 같은 판정을 얻습니다.
- **`--max-age`**는 파이프라인이 한도보다 오래된 스냅샷을 판정하거나 그것으로 fix를 계획하기를 거부하게 하여, 오래된
  스냅샷이 호스트의 현재 상태로 오인되지 않게 합니다(§5.1).

범위 조사가 확인한 것, 그리고 아래 모양을 정한 것:

- 평가기는 두 팩트를 결코 조인하지 않습니다: 사용자 정의 함수가 없고(`internal/check/custom.go:11`), `${param}`이
  유일한 치환이며(`internal/check/value.go:40`), 식별자 간의 모든 비교는 수집기에서 끝나 bool이나 분류로
  저장됩니다(`uid_duplicate`, `owner_ok`, `has_plus`, `loopback`, `exposed` …). 그래서 **완성된** 스냅샷 위에서 도출
  필드를 건드리지 않는 변환은 조인을 깰 수 없습니다.
- 깰 수 있는 것: 식별자를 리터럴이나 파라미터와 비교하는 절 — `root`(`root_only_uid_zero`), `ftp`(`ftp_account_shell`,
  FAIL을 공허한 PASS로 바꿀 수 있음), lp/uucp/nuucp, root/adm/syslog/utmp 그룹; 메커니즘이 비어 있음을 검사하는 값
  (`logging.journal_upload.url ne ""`가 `remote_log_forwarding`의 메커니즘을 고름); 그리고 뜻을 모르는 문자열의 재작성
  (`log`라는 사용자가 마운트 대상을 바꾸면 `separate_partitions`가 PASS에서 MANUAL이 됨).
- 레지스트리의 `sensitivity` 표시로는 할 수 없습니다: 키 511개 중 465개가 `public`이고 그중 다수가 사용자명, 경로,
  주소를 싣습니다; 오늘 마스킹되는 것은 SNMP 키 둘뿐입니다. 레지스트리는 레코드 필드를 나열하지 않으므로
  (`internal/facts/registry.go:22-31`), 익명화기 자신의 표가 그것들의 기준입니다.

- **AX-1 — 익명화는 완성된 스냅샷 위의 오프라인 명령 `muster snapshot anonymize`다.** 이 단계에서 `collect` 플래그가
  아닙니다: collect는 컨트롤·튜닝·waiver 파일을 결코 파싱하지 않고(THREAT_MODEL, 메인 설계 `:424`), 키 파일은 수집기
  레지스트리 밖의 읽기가 되며, 원본은 위협이 아닙니다 — 원본은 자신이 묘사하는 호스트에 0600으로 있습니다. 공유는 그
  뒤에 일어나고, 변환은 거기서 돕니다. D36이 메인 설계 `:426`을 고쳐 쓰고, `collect --anonymize`는 보류합니다.
- **AX-2 — 키를 쓴 가명이며, 키 없는 해시는 결코 쓰지 않는다.** 256비트 키 아래 HMAC-SHA256, 분류마다 파생 하위 키
  하나(`HMAC(key, "muster/anon/v1/<class>")`), 표준 라이브러리만(D28). 사용자명, 호스트 라벨, IPv4 주소의 키 없는
  해시는 열거로 되돌릴 수 있습니다(`collectors/snmp.go:30-33`이 커뮤니티 문자열에 대해 그렇게 말함). 키는 원본
  스냅샷만큼 민감합니다.
- **AX-3 — 키는 입력이고, 일회용 키는 명시적 선택이다.** `--key <file>`(정확히 32바이트, root일 때 `trustedFile`로
  읽음)은 출력을 결정적으로 만듭니다 — 같은 입력, 같은 키, 같은 바이트. `--ephemeral`은 `crypto/rand`에서 32바이트를
  뽑아 결코 쓰지 않으며, 일회성 공개 리포트용입니다; 헤더가 그렇게 말하고 바이트는 실행마다 다릅니다. 둘 중 정확히
  하나가 필요합니다.
- **AX-4 — 값 분류마다 규칙이 하나이고, 빈 문자열은 모든 분류에서 자기 자신으로 간다.**

  | 분류 | 규칙 |
  |---|---|
  | account(사용자와 그룹 이름, 한 이름공간) | `u` + HMAC의 base32 12자(소문자, 패딩 없음); 대소문자 구분; 앞의 시길(`%`, `+`, `-`, `@`, 숫자가 아닌 것 앞의 `#`)은 유지 |
  | host(DNS 이름) | 소문자로, 라벨마다 `h` + base32 10자; 마지막 라벨 유지; 라벨 하나인 이름은 통째로 매핑 |
  | address | 아래 §1.1 |
  | host-or-address(둘 중 하나를 담는 필드: NTP 서버, syslog 대상, NFS 클라이언트, lastlog 호스트) | 순서 있는 한 결정: (1) §1.1의 주소 형태; (2) 호스트 형태 — 문자·숫자·하이픈 라벨의 DNS 이름(끝의 점 유지), `host:port`, `transport:host[:port]`, syslog의 `[@\|@@][(opts)]host[:port]`, `*.`로 시작하는 와일드카드(`*` 유지), `@netgroup`(이름은 account 규칙) — 호스트 부분은 host 규칙, 나머지는 문법으로 유지; (3) 그 밖은 `[anonymised]` |
  | host-or-netgroup(hosts.equiv의 호스트, NFS 클라이언트) | 앞의 `@`는 account 규칙으로 매핑하는 넷그룹; 그 밖은 host-or-address 규칙 |
  | unit(유닛 이름) | `@` 없는 이름은 유지; 템플릿 인스턴스 `<name>@<instance>.<suffix>`는 `<name>@`와 `.<suffix>`를 유지하고 인스턴스를 `i` + HMAC의 base32 12자로 매핑 |
  | blank(`boot_id`, `uptime_s`, 방화벽 원본 덤프) | 문자열은 `""`, 숫자는 `0`; 존재는 유지 |
  | option list(마운트와 NFS export 옵션) | 쉼표 토큰은 바이트 그대로, 단 `username`, `user`, `uname`, `domain`, `addr`, `ip`, `clientaddr`, `mountaddr`, `srcaddr`, `mounthost`, `credentials`, `cred`, `prefixpath`, `aname`, export의 `mp`, `mountpoint`, `refer`, `replicas` 값은 각 분류로 매핑하고 `password`, `pass` 값은 자리표시자 |
  | url | 스킴, 포트, `user@`는 문법으로 유지, 쿼리·프래그먼트·비밀번호는 `[anonymised]`, 호스트는 host 또는 address 규칙, 사용자는 account 규칙, 경로는 AX-6 |
  | fingerprint(SSH 키 지문) | `SHA256:` + HMAC의 base64 43자(패딩 없음) |
  | machine id hash | 키를 쓴 소문자 16진 64자(AX-11) |
  | path | AX-6 |
  | placeholder(어떤 절도 읽지 않는 자유 텍스트) | AX-7 |
  | kept | uid, gid, 포트, 모드, 패키지 이름과 버전, 커널 릴리스, 인터페이스 이름, 열거값, bool, 숫자, `collected_at`, 상태, 목록 길이, 모든 도출 필드 |

  kept 행은 계약의 일부입니다: 판정이 그 값들을 읽습니다(`uid eq 0`, 숫자 ACL 한정자, `target eq "/tmp"` — 마운트 대상은 경로이고, AX-6은 컨트롤이 이름 짓는 것을 결코 다시 쓰지 않음 —, 패키지
  조인, `--max-age`). 그것들은 준식별자이며, 문서가 그렇게 말합니다(§5).
- **AX-5 — 유지 집합은 닫힌 목록이고, 컨트롤 세트에 고정된다.** 이름은 `internal/anonymize`의 닫힌 목록에 있을 때만
  유지됩니다: `root`; 컨트롤 세트가 이름 짓는 시스템 계정과 그룹(`ftp`, `lp`, `uucp`, `nuucp`, `adm`, `syslog`,
  `utmp`, `wheel`, `sudo`, `admin` …); sudo와 NFS 토큰 `ALL`, `*`. 그 밖의 계정·그룹 이름은 모두 매핑됩니다 — 사이트
  자신의 시스템 계정과 두 번째 uid-0 계정도 포함(백도어 `toor`는 공개되지 않으며, `root_only_uid_zero`는 여전히
  `root`가 아닌 이름을 봄). 유지가 분류를 넘어 매핑을 이깁니다. `internal/controls`의 테스트는 account 분류 값 —
  스칼라 팩트, 목록 원소, 레코드 필드 — 과 비교되는 리터럴이나 기본값이 컨트롤 세트나 내장 프로파일에서 목록에 없으면
  실패하므로, 새 리터럴은 공유된 리포트가 아니라 CI에서 실패합니다. 헤더는 `keep_set: v1`을 기록합니다.
- **AX-6 — 경로는 알려진 위치에서만, 한 함수로 다시 쓴다.** 매핑된 계정 이름은 account 규칙이 스냅샷 어디서든
  매핑한 모든 값(시길 제거)이며, 경로를 다시 쓰기 전 첫 패스에서 모읍니다 — 그래서 `/etc/passwd`에 없는 sudo 주체나
  crontab 소유자도 셉니다. 매핑된 계정 이름과 같은 구성 요소는, 유지되지 않는 계정의 홈의 마지막 구성 요소일 때(홈이
  `/`, `/tmp`, `/var/tmp`, `/dev/null`, `/nonexistent`, 어떤 컨트롤이 이름 짓는 마운트 대상이거나 구성 요소가 둘보다
  적으면 제외), `/home/` 다음 구성 요소일 때, `/var/spool/cron/crontabs/<n>`, `/var/spool/cron/<n>`, `/var/mail/<n>`,
  `/var/spool/mail/<n>`, `/var/lib/systemd/linger/<n>`, `/var/lib/AccountsService/users/<n>`의 이름 위치일 때, 그리고
  `/etc/sudoers.d/`나 `/etc/cron.d/` 바로 아래 파일의 기본 이름이 매핑된 계정 이름과 같을 때 그 가명으로 바뀝니다;
  그런 홈 아래의 경로는 접두어로 다시 씁니다. 경로 위의 모든 적격 홈이 그 마지막 구성 요소를 다시 쓰고, 구성 요소의 위치는 그 앞의 정리된 접두어로 정하며, 경로는
  정리된 형태로 돌려주지 않고 제자리에서 다시 쓰고; 매핑된 어느 계정 이름과 같은 홈의 마지막
  구성 요소는 그 이름의 가명으로 바뀌며; `<x>`가 계정이 아닌 `/home/<x>`는 `<x>`를 account 분류로 매핑합니다. 마운트
  대상은 결코, 다른 곳에서 구성 요소 일치로는 결코 다시 쓰지 않습니다. 같은 함수가 스냅샷의 모든 경로를 매핑하므로
  파일의 주체는 한 문자열로 남습니다. 호스트 식별자에도 위치가 있습니다: 원본 machine id(`/var/log/journal/`나
  `/run/log/journal/` 아래의 16진 32자 구성 요소 전체나 journald 이름공간 `<id>.<namespace>`의 앞 16진 32자, `/boot/`, `/boot/loader/entries/`, `/efi/`, `/efi/loader/entries/`
  아래의 그런 구성 요소 전체나 `<id>-<rest>`의 앞 16진 32자, EL 복구 이미지 `/boot/vmlinuz-0-rescue-<id>`와
  `/boot/initramfs-0-rescue-<id>.img`의 끝 16진 32자)는 `id:`와 그 id에 대한 machine-id 하위 키의 16진 32자로,
  `/tmp/`나 `/var/tmp/` 아래 `systemd-private-<16진 32자>-<rest>`의 boot id는 `boot:`와 그 id에 대한 16진 32자로
  매핑하고 구성 요소의 나머지는 유지합니다 — 그래서 어떤 구성 요소도 원래의 `machine_id_hash`로 해시되지 않습니다.
- **AX-7 — 어떤 절도 읽지 않는 자유 텍스트는 훑지 않고 바꾼다.** `text` 값 — 엔벨로프 `reason`, 모든 `Source`(최상위,
  `winner`, 설정의 각 측면, 중첩 `inputs`)의 `raw`와 `cmd`, `run.collectors[].reason`, `partial_failures`, 그리고 표가
  표시한 모든 원문 레코드 필드 — 는 고정 문자열 `[anonymised]`가 되며 비어 있음은 유지됩니다(`""`는 `""`).
  `firewall.raw_dumps[].content`는 `truncated`를 유지한 채 `""`가 됩니다. 자유 텍스트의 토큰 치환은 완전해질 수
  없고(산문에만 있는 호스트 이름, 영역 표기가 붙은 주소, 잘림 표시에서 끊긴 이름), 산문 안에서 매핑된 경로와 그 원본이
  짝지어지면 키의 작업이 공개됩니다. 대가는 증거의 가독성이며 README가 그렇게 말합니다; 컨트롤의 `evidence:` 목록에만
  이름이 있는 키도 다른 것처럼 자리표시자가 됩니다(어떤 판정도 그 텍스트를 읽지 않음). 자리표시자는 존재를 그대로
  둡니다: 없는 필드는 없는 채로, 있는 필드는 있는 채로, `""`는 `""`로. 절이 값으로 읽는 텍스트 값(`eq`, `ne`, `in`,
  `not_in`, `matches`, `not_matches`, `contains`, 비교: `hosts.equiv` 줄과 그 `^\+`, securetty의 `^pts/`)은 표가 그
  필드에 선언한 문법으로 토큰마다 다시 씁니다(공백 토큰; 각 토큰은 선언된 분류로; 시길 유지, 앞에 이어진 `!`도 그중 하나); AX-8의 고정 테스트가
  그것들을 나열합니다.
- **AX-8 — 문서의 모든 경로는 분류되고, 분류되지 않은 경로는 입력을 거부한다.** `internal/anonymize`의 표는 모든 실행
  헤더 필드, 모든 엔벨로프 필드(`status`, `value`, `source.*`, `truncated`, `reason`; 설정의 `runtime`, `persisted`,
  `effective` 측면, 그 `winner`와 페르소나 키), 모든 레지스트리 키의 값, 그리고 레코드의 모든 필드 경로(중첩 레코드
  포함)의 분류를, 읽히는 텍스트면 그 문법을, 목록이면 매핑되는 필드로 정렬되는지 아니면 순서를 유지하는지
  (`firewall.rules`, root의 PATH, 관리자 그룹 멤버 순서)를 적습니다. 정렬된 목록은 표에 명시적 정렬 명세 — 순서 있는
  키 필드, 각각의 문자열 또는 숫자 비교, 중복 제거 여부 — 를 싣고 매핑 뒤 그것으로 다시 정렬됩니다(이름으로 정렬된
  `accounts.lastlog`가 하나; 매핑 전에 이름 순서로 한 선택, 예컨대 공유 파일을 이름순 첫 계정 아래 두는
  `ssh.rsa_keys`는 수집된 그대로). 표의 경로는 트리의 모양이 아니라 레지스트리의 점 구분 키로 해석합니다. 표는
  수집기의 코드에서 채웁니다. 테스트: 모든 레지스트리 키가 표에 있음; 어느 코퍼스 스냅샷(§4, 합집합)에 나오는 모든 필드
  경로가 분류됨; 수집기 패키지의 Linux 태그 테스트가 그 단위 테스트가 내보내는 모든 레코드를 표에 대조하고, 정렬된
  목록마다 그 명세로 다시 정렬해 아무것도 움직이지 않음을 확인; `facts.Run`, `facts.Envelope`, `facts.Setting`에 대한
  리플렉션 테스트가 헤더와 엔벨로프(`truncated` 포함)를 덮음; 어떤 절, `applies_when`, 메커니즘 `when`이 **값으로**
  읽는 필드 경로는 결코 `placeholder`가 아님(`present`/`absent` 읽기는 허용, AX-7). 픽스처의 최상위 키도 분류합니다:
  `synthetic`, `_expect.*`, `_provenance.*`는 유지, `_notes`는 `placeholder`. 실행 시 표 밖의 경로를 실은 입력은
  거부됩니다: 스냅샷의 `muster_version`이 바이너리보다 새로우면 "anonymise with muster ≥ <its muster_version>",
  아니면 "unclassified field <path>: a muster bug, please report it"(둘 다 테스트로 고정). 더 새 수집기의 필드는
  누출되지도 버려지지도 않습니다.
- **AX-9 — 가명은 단사이고, 충돌은 거부한다.** 한 분류와 한 실행 안에서 서로 다른 입력은 서로 다른 출력으로 갑니다;
  충돌, 또는 유지된 값이나 같은 필드의 다른 분류 출력과 같은 매핑 값은 분류를 밝히며 명령을 실패시킵니다.
- **AX-10 — 출력은 자신이 무엇인지 말한다.** `run.anonymization {scheme: "muster-anon-v1", mode: "keyed" |
  "ephemeral", key_id, keep_set, classes, replaced}`(omitempty): `key_id`는 `HMAC(key, "muster/anon/v1/key-id")`의
  앞 16진 16자(ephemeral 모드에서는 비어 있음)로, 받는 쪽이 두 파일이 키를 공유하는지 알 수 있게 합니다; `classes`는
  토큰 `account`, `host`, `address`, `url`, `fingerprint`, `machine_id_hash`, `path`, `unit` 중 값을 하나라도 매핑한 분류의
  정렬된 목록; `replaced`는 자리표시자가 되거나 비워진 값의 문서 경로를 목록 인덱스마다 `[]`로 쓴 정렬된 목록입니다 —
  예: `facts.cron.files.value[].reason`, `facts.firewall.raw_dumps.value[].content`, `run.collectors[].reason`.
  `check`와 `fix`는 `run`을 실어 나르듯 그것을 실어 나르고, 이미 표시된 입력은 거부합니다. 이 필드를 더해도
  `schema_version`은 그대로입니다(§5.7).
- **AX-11 — 호스트 가드는 닫힌 쪽으로 실패한다.** `machine_id_hash`는 키를 쓴 16진 64자가 되므로, 헤더를 모르는 이전
  muster도 모든 호스트를 거부하는 가드를 렌더링합니다. 이 muster의 `fix --format script`는 익명화한 스냅샷을
  거부합니다(exit 2, stdout 없음: "plan the script from the original snapshot"); `--format table`과 `json`은 검토자를
  위해 남습니다. `run.host.hostname`은 host 규칙으로 매핑하고, `boot_id`와 `uptime_s`(읽는 곳 없음)는 비웁니다.
- **AX-12 — 불변식을 정직하게 말한다.** 코퍼스(§4)의 모든 스냅샷과 모든 내장 프로파일에서, 튜닝도 waiver 파일도
  없을 때, 원본과 익명화한 스냅샷은 모든 행에 대해 같은 `(id, status, reason_code)`, 같은 메커니즘 선택, 행마다 같은
  관찰 판정 다중집합, 같은 종료 코드를 냅니다. 사이트 파일 — 튜닝 파일, waiver 파일, 사이트 프로파일 — 은 이 단계에서
  매핑하지 않습니다: 실제 사용자, 경로, 주소를 이름 짓는 사이트 값은 익명화한 스냅샷에서 판정을 뒤집을 수 있고, 문서가
  그렇게 말합니다. 소유자는 자기 결과를 갖고, 받는 쪽은 내장 질문을 판정합니다.
- **AX-13 — `check`와 `fix`의 `--max-age <duration>`: 평가 전의 거부.** 기본값은 꺼짐(플래그가 없으면 바이트 단위로
  변화 없음). 플래그가 있으면 나이가 한도를 넘는 스냅샷을 거부합니다 — exit 2, stdout 없음, `muster: snapshot
  collected at <ts> is <age> old, older than --max-age <d>` — 거부된 프로파일이나 스키마 불일치와 같은
  모양입니다(§7.2, §7.5). `--allow-error`와 `--fail-on none`은 그것을 풀지 않고, `fix`는 "결코 1로 끝나지 않음"을
  지킵니다. 컨트롤도 reason 코드도 아닙니다: 나이는 입력 전체의 속성이고, 판정은 스냅샷의 순수 함수로 남습니다.
- **AX-14 — 시간은 한 번, 엄격하게 읽는다.** `cmd/muster`에서 명령마다 시계를 한 번 읽어 waiver 만료와 나이 검사가
  공유합니다(주입 가능한 `now`). `collected_at`은 정확히 `YYYY-MM-DDTHH:MM:SSZ`(왕복 동일)여야 하고, `--max-age`
  아래에서 비었거나 형식이 틀린 값은 거부하며("no usable collected_at; cannot judge --max-age"), 5분보다 더 미래인
  값도 거부합니다(고정된 시계 오차 허용; 그 안이면 나이 0). 나이는 정수 초입니다: 초로 자른 `now`에서
  `collected_at`을 뺀 것; 한도는 포함입니다. 문법: 하나 이상의 정수 항을 단위의 내림차순으로, 단위마다 한 번만, 단위
  `w`, `d`, `h`, `m`, `s`(`7d`, `2w`, `1d12h`, `90m`); 소수 없음, `ms`/`us`/`ns` 없음; 최소 1초, 최대 100년; 그 밖은
  거부. 결과는 나이가 아니라 한도를 기록합니다: `check.max_age_s`(check 블록의 마지막 필드)와 계획의
  `fix.max_age_s`(fix 블록의 마지막 필드), omitempty, 정수 초. max-age는 두 기계의 시계를 재며 아무것도 증명하지
  않습니다; THREAT_MODEL이 그렇게 말합니다.

### 1.1 주소

- **그대로 유지**(신원 없음): IPv4 `0.0.0.0/8`, `127.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255`, 문서용
  대역 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; IPv6 `::`, `::1`, `ff00::/8`, `2001:db8::/32`.
- **자기 대역 안에서 매핑**(대역 접두어 유지, 나머지 비트는 키를 쓴 Crypto-PAn 구성): IPv4 `10.0.0.0/8`,
  `100.64.0.0/10`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `198.18.0.0/15`; IPv6 `fc00::/7`, `fe80::/10`.
  `::ffff:a.b.c.d`(`::ffff:0:0/96`)와 `64:ff9b::a.b.c.d`(`64:ff9b::/96`)는 IPv4 부분을 IPv4 규칙으로 매핑하고 접두어를
  유지하며, 둘 다 아래 IPv6 트리의 경계입니다.
- **공인**(그 밖 전부): 고정 비트 트리 구성 — 각 비트에서, 그 접두어 아래 하위 트리에 유지 또는 대역 매핑의 경계가
  없을 때만 접두어의 키 PRF로 비트를 뒤집고, 그렇지 않으면 유지합니다. 이 매핑은 접두어를 보존하고 공인 공간에서
  전단사이므로 주소가 분류를 바꾸지 않으며, CIDR은 네트워크 비트로 매핑되어 포함 관계가 유지됩니다. 호스트 비트가 켜진
  채 쓰인 CIDR은 주소 부분을 주소로 매핑하고 길이를 유지합니다. 새는 것: 특수 대역 근처에서 유지되는 조상 비트
  (THREAT_MODEL).
- **파싱하는 형태**(address 또는 host-or-address 필드): 주소, CIDR, 점 표기 넷마스크가 붙은 주소
  (`a.b.c.d/255.255.255.0`), `addr:port`와 `[v6]:port`, 전송 접두어(`udp:`, `tcp:`, `udp6:`, `tcp6:`), 영역
  (`fe80::1%eth0`: 영역은 인터페이스 이름이라 유지), 범위 `a-b`(양 끝 각각 매핑; 순서는 뒤집힐 수 있음, 증거 전용), nft
  집합 `{ a, b }`(원소마다). address 필드에서 어떤 형태에도 맞지 않는 값은 `[anonymised]`가 되고, host-or-address
  필드에서는 AX-4의 호스트 형태를 먼저 시도해 주소 형태에도 호스트 형태에도 맞지 않는 값만 `[anonymised]`가 됩니다 —
  어떤 판정도 주소 잎을 읽지 않습니다(도출된 bool이 분류를 실음).

## 2. 명령

```
muster snapshot anonymize --facts <in|-> (--key <file> | --ephemeral) --out <file|-> [--force]
```

- 문서 전체를 `json.Number`로 한 번에 트리로 디코드하므로(최상위, `run`, `facts`), 2^53보다 큰 정수와 픽스처 키
  `synthetic`, `_provenance`, `_expect`가 살아남고, 비었거나 일부만 있는 `run` 블록은 그대로 다시 씁니다(없는 키는 없는
  채로; 픽스처는 `synthetic: true`를 유지, D02). `facts.Load`는 스키마와 크기 관문으로만 돕니다. 출력은 `collect`가
  스냅샷을 쓰는 방식으로 인코딩합니다.
- 무엇이든 쓰기 전에 거부: 이 `schema_version`의 스냅샷이 아닌 입력; 이미 익명화된 입력; `run.redaction.include_secrets`가
  true인 입력; 표 밖의 경로(AX-8); 충돌(AX-9); 정확히 32바이트가 아니거나 (root일 때) 신뢰할 수 없는 키 파일; 입력
  파일을 가리키는 `--out`(정리한 경로나 `os.SameFile`로).
- 출력은 `O_CREATE|O_EXCL`과 모드 0600으로 씁니다(`--force`는 모든 거부를 통과한 뒤 기존 일반 파일을 먼저 지움; 키
  파일이나 입력을 가리키는 `--out`은 `--force`가 있어도 거부), 쓰기 오류 시 일부만 쓰인 파일은 지웁니다; 이것은
  `cmd/muster`에 있어 모든 플랫폼에서 빌드됩니다. `-`는 stdout입니다. 썼으면 exit 0, 거부면 2. root로 돌면 `check`처럼
  경고합니다.
- 변환은 순수합니다: `internal/anonymize`는 `os`, `os/exec`, `net`, `syscall`을 가져오지 않고(테스트가 강제) 키와
  디코드된 트리를 받으며, `cmd/muster`가 읽고 씁니다. 모든 `[]byte` 진입점은 `Fuzz<Name>` 타깃을 갖고, 패키지는
  `fuzz.yml`의 목록에 들어갑니다.

## 3. `--max-age`

- `check --max-age <d>`와 `fix --dry-run --max-age <d>`; `fixValueFlags`가 그것을 얻습니다(테스트가 그 맵을 파서에
  묶음). `collect`, `snapshot extract`, `snapshot anonymize`, `controls`에는 없습니다.
- 검사는 스냅샷을 읽고 스키마를 받아들인 뒤, 프로파일을 해석하기 전에 돕니다 — 그래서 프로파일 파일이 깨져 있어도
  오래된 스냅샷은 거부되고 다른 것은 아무것도 돌지 않습니다.
- `snapshot anonymize`는 `collected_at`을 바이트 그대로 두므로, 익명화한 스냅샷은 원본처럼 나이를 먹습니다.

## 4. 테스트와 CI

- **불변식 코퍼스:** 모든 `controls/testdata/<id>/*.json`, `controls/testdata/_hosts/*`,
  `cmd/muster/testdata/full-{pass,fail}.json`, `examples/ubuntu-24.04-{vm,container}.json`, 그리고 새 합성 픽스처:
  비교되는 이름이 매핑되는 비시스템 이름인 유지 집합 절마다 하나와 같은 픽스처의 유지된 이름판; `log`라는 사람
  계정의 홈이 `/tmp`인 마운트 표; 중첩·공유 홈; 활성·enable된 업로드 유닛과 rsyslog 전달 없이 `""`인
  `journal_upload.url`. 비교: status, reason_code, 메커니즘, 관찰 판정 다중집합, 종료 코드 — 모든 내장 프로파일에서.
  `snapshot_digest`, 주체, 증거 텍스트는 비교하지 않습니다.
- **호출을 지우면 빨개짐:** 유지 집합에서 `root`나 `ftp`를 뺌; 경로 규칙이 구성 요소 일치로 다시 쓰게 함; `""`를
  가명으로 매핑함; `exposure`가 도출되기 전에 주소를 매핑함(합성 테스트).
- **카나리 쓸기:** 분류된 모든 위치에 분류마다 고유 카나리 하나를 둔 합성 호스트 — 호스트 자신의 짧은 이름, `…`로
  끝나게 잘린 `source.raw`, 모든 텍스트 필드, 모든 헤더 필드, 계정 이름의 `/etc/sudoers.d/` 드롭인과 EL의
  `/var/spool/mail/` 스풀 — 그리고 익명화한 스냅샷과 그로부터 만든 check JSON, 계획 JSON, 표에 그중 어느 것도 없음.
- **익명화한 스냅샷의 fix:** `fix --dry-run --format script`는 stdout 없이 exit 2, `table`과 `json`은 성공; 거부를
  지우면 빨개짐.
- **호스트-또는-주소 형태:** 주소 형태마다, 호스트 형태마다(맨 이름, `host:port`, syslog 대상, 와일드카드, 넷그룹)
  카나리 하나.
- **존재:** `reason`이 있는 `cron.files` 행과 없는 행; 익명화 뒤 앞의 것은 여전히 (자리표시자가 된) `reason`을 갖고
  뒤의 것은 없음.
- **속성:** 키마다 결정적; 분류마다 단사; 모든 주소의 분류 유지; 익명화된 입력 거부; 출력이 `facts.Load`를 통과; 분류
  테스트(AX-8)와 유지 집합 고정(AX-5).
- **`--max-age`:** 문법 표; 포함 한도; 5분 안과 밖의 미래; 비었거나 형식이 틀린 `collected_at`; 깨진 프로파일보다 앞선
  거부; stdout 없음과 exit 2; `--allow-error`/`--fail-on none`이 풀지 않음; 플래그 없이는 출력이 바이트 단위로 같음
  (골든과 예제 불변); `remedy.Build`가 `max_age_s`를 계획에 복사(테스트로 고정).
- CI: 오늘처럼 `go test`; fuzz 목록; 예제 변경 없음(예제 실행에 플래그 없음).

## 5. 문서

메인 설계 쌍(줄 정렬): §5.6 정정(authorized_keys는 코멘트를 저장하지 않음, `sshkeys_parse.go:21-28`), §7.2와
§7.5(max-age 거부와 `fix --format script`의 익명화 스냅샷 거부), §8 `:426` 고쳐 쓰기, §9(`check.max_age_s`,
`fix.max_age_s`, `run.anonymization`), §10.2(3D-3 병합), D36(AX-1, AX-2, AX-7, AX-11, AX-12, AX-13, AX-14).
THREAT_MODEL(방식; 버티는 것 — 사전 역산, 알려진 이름 검색, 키 간 연결; 버티지 못하는 것 — 키 유출, 준식별자, 특수
대역 근처에 남는 주소 구조, 한 키 안의 연결, 사이트 파일, 시점; max-age는 아무것도 증명하지 않음; `:71`의 낡은
`--include-secrets` 문장). SECURITY.md(정책상 실으면 안 되는 신원을 실은 익명화 스냅샷은 범위 안). README 쌍(명령,
불변식, 자리표시자가 된 증거, 익명화 스냅샷이 아닌 것: 비밀이 없는 것, 식별 불가능한 것, 무해한 것). CLAUDE.md(3D-3
메모). CHANGELOG. `check`, `fix`, `snapshot`의 사용법 텍스트.

## 6. 보류

- `collect --anonymize`(원격으로 `--out -` 파이프만 쓰는 용도).
- 사이트 파일 — 튜닝, waiver, 사이트 프로파일 — 을 같은 키로 매핑하기, 각 파라미터와 주체의 분류 규칙과 함께.
- 증거를 읽을 수 있게 두는 자유 텍스트 토큰 치환.
- 경고만 하는 나이 모드(`--warn-age`)와 표 첫 줄의 나이 표시.
- check JSON이나 계획 JSON을 직접 익명화하기(받는 쪽이 익명화한 스냅샷에서 다시 만듦).
- 4단계 보존(`snapshot prune --keep-days`)이 기간 파서와 엄격한 `collected_at` 리더를 재사용.
