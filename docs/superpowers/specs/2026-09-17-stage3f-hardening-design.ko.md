# 3F단계 — 테스트 강화: 뮤턴트, 퍼저, 오라클, 예시

*[English](2026-09-17-stage3f-hardening-design.md) · 한국어*

이 문서는 muster 플랜 3F의 설계입니다. 본 설계(`2026-09-02-muster-design.ko.md`, §11 "파서
오라클(2단계)", "3단계", D21)가 예약하고 2단계가 "테스트 강화"로 미뤄 둔 네 가지 테스트 하위 시스템
— 컨트롤 YAML의 뮤테이션 테스트, 모든 파서의 네이티브 퍼징, 파서에 대한 데몬 오라클, 공개
이미지에서 캡처한 예시 스냅샷 — 을 다룹니다. 3단계의 두 번째 하위 프로젝트입니다(3A 워크는 병합됨;
3F는 3B보다 먼저 돌리기로 합의). 결정은 F-1 … F-12로 번호를 붙이며 플랜을 구속합니다. 어느 것도
수집기가 읽는 것이나 컨트롤이 판정하는 방식을 바꾸지 않습니다. 3F는 기존 동작이 테스트된 동작임을
보이는 근거를 더하며, 바꿀 수 있는 코드는 퍼저가 깨뜨린 파서와 뮤턴트가 틀렸음을 증명한 컨트롤뿐
— 각각 별도 커밋으로, CHANGELOG에 이름을 적습니다.

## 1. 목표와 범위

오늘의 스위트가 답하지 못하는 질문 셋: 모든 픽스처가 정말 곁에 있는 절을 판정하는가(엉뚱한 이유로
통과하는 픽스처는 보이지 않음); 픽스처가 보여 준 적 없는 입력에 어떤 파서가 패닉·루프·무한 성장을
하는가; 파서가 자기가 읽는 파일의 데몬과 일치하는가. 그리고 README가 보여 주지 못하는 것 하나: 실제
스냅샷과 리포트가 어떻게 생겼는가. 3F는 각각을 낡을 수 없는 가장 값싼 장치로 답합니다. `go test`로
도는 뮤테이션 테스트(F-1…F-4), 커밋된 코퍼스를 갖고 밤마다 도는 파서 진입점당 퍼즈 타깃 하나(최소 30개 — F-5 표가 바닥, F-6
인벤토리 규칙이 천장: 수집기 26, `pkgfiles` 4, 그리고 인벤토리가 다른 이름으로 찾아내는 모든 파서마다
하나)(F-5…F-7),
이미 데몬을 가진 CI 잡에서 도는 오라클 테스트(F-8…F-10), 리포트를 갖춘 커밋된 예시 스냅샷 둘
(F-11…F-12).

범위 밖: gremlins 등 Go 수준 뮤테이션(설계는 custom 함수에만 예약했고 어느 컨트롤도 쓰지 않음);
Lynis(4단계); 뮤턴트가 증명하는 범위를 넘는 평가기 속성 테스트; 상한·예산·키·판정의 변경.

## 2. 컨트롤 YAML 뮤테이션 테스트 (F-1 … F-4)

**F-1 — 도구가 아니라 테스트. kill 오라클은 픽스처 집합.** `internal/controls/mutation_test.go`의
`TestEveryMutantIsKilled`. 내장 셋의 모든 컨트롤에 대해 그 컨트롤의 픽스처(`controls/testdata/<id>/
*.json`, 픽스처 하네스와 같은 로더와 `check.Evaluate`)를 평가해 픽스처별 관측 `(status, reason_code)`를
기록합니다. 그 다음 컨트롤의 뮤턴트를 고정 순서로 생성하고(F-2) 뮤턴트마다 모든 픽스처를 다시
평가합니다. 픽스처 하나라도 `(status, reason_code)`가 원본과 다르면 **kill**, 모든 픽스처가 이전과 똑같이
답하면 **생존**입니다. 비교 대상은 픽스처의 기대 접두가 아니라 원본의 *관측* 결과이므로, 변형된 절과
무관한 이유로 상태에 이른 픽스처는 kill로 셀 수 없습니다. 뮤턴트는 디코드된 컨트롤의 깊은 복사본
위에 메모리에서 만들며 `controls/` 아래에 아무것도 쓰지 않습니다. 모든 뮤턴트는 다시 lint합니다(픽스처 하네스가 쓰는 레지스트리와 custom 함수 집합으로
`controls.Lint`). lint가 거부하는 뮤턴트(리스트가 아닌 팩트의 collection 연산자, `list<string>`의
`not_matches`, 타입이 틀린 param 기본값)는 **invalid**로 세고 건너뜁니다 — 픽스처가 볼 수 있는 판정
변화가 아닙니다. 달라진 픽스처가 전부 `ERROR(internal_error)`로 옮겨 간 뮤턴트도 kill이 아니라
invalid입니다 — 평가기는 모든 패닉을 그 상태로 회수하므로 그런 "kill"은 아무것도 증명하지 못합니다. 테스트는 로그 한 줄에
합계 — 생성, invalid, kill, 생존, 예외 — 를 남깁니다.

**F-2 — 뮤테이션 연산자.** 뮤턴트는 정확히 하나만 바꾸고, 실행마다 안정적이고 사람이 읽을 수 있는
**서명**을 가집니다. 서명 문법은 `<path> <operator>`이며 `<path>`는 컨트롤 안의 JSON-pointer 비슷한
위치(`checks[1]`, `checks[0].where`, `mechanisms[2].when[0]`, `mechanisms[1].checks[0].require`,
`applies_when[0]`, `params.<name>.default`, `absent_means`), `<operator>`는 아래 행 중 하나입니다.

| 부류(설계 §11) | 연산자 | 적용 대상 |
|---|---|---|
| 연산자 뒤집기 | `op eq->ne`, `op ne->eq`, `op in->not_in`, `op not_in->in`, `op lt->gte`, `op lte->gt`, `op gt->lte`, `op gte->lt`, `op matches->not_matches`, `op not_matches->matches`, `op contains->not_contains`, `op not_contains->contains`, `op present->absent`, `op absent->present` | 모든 절과 모든 `where`/`require` 하위 절 |
| 연산자 뒤집기 | `op each->none` | `where`를 가진 `each` 절(`none`은 그 `where`를 유지하고 `require`는 버림); `none->each`는 결코 유효하지 않으므로 — `each`는 `none`이 갖지 않는 `require`가 필요 — 생성하지 않음 |
| 기대값 치환 | `expected not`(bool), `expected +1`, `expected -1`(int), `expected "__mutant__"`(string), `expected drop[i]`(리스트 원소 하나), `expected []`(빈 리스트) | 리터럴 `expected`; `${param}` 참조는 같은 행으로 파라미터의 `default`를 변형하되 **파라미터마다 한 번**(참조하는 절마다가 아님) 생성, 서명은 `params.<name>.default …` |
| 절 제거 | `remove` | `checks`와 mechanism `checks`의 각 절(그 목록에 절이 둘 이상일 때) |
| 조건 제거 | `remove` | 각 `applies_when` 절; 각 mechanism `when` 절; 컨트롤에 mechanism이 둘 이상일 때 mechanism 통째 |
| 조건 제거 | `absent_means -><value>` | `absent_means`의 다른 세 값 |

`on`, `persona`, `subject`는 변형하지 않습니다(페르소나 집합과 subject 키는 구조이지 판정이 아님).
모든 연산자는 적용되는 모든 자리에 생성되며, 서명이 자리 하나와 변화 하나를 이름 짓기 때문에 두
뮤턴트가 겹치는 일은 없습니다. 뮤턴트는 디코드된 컨트롤을 YAML로 다시 인코드해 엄격 로더로 다시
디코드한 깊은 복사본 위에 만드므로, 뮤턴트는 로더가 파일에서 받아들였을 바로 그것입니다.

*비용과 `absent_means` 행.* 대략 절 350개, 기대값 300개, 제거들, 그리고 판정 컨트롤 64개 × `absent_means`
값 3개로 약 1,100개의 뮤턴트이며 여전히 초 단위입니다. `absent_means` 뮤턴트는 판정하는 모든 팩트가
absent인 픽스처로만 kill되므로, 그런 배치가 도달 가능한 모든 판정 컨트롤은 그런 픽스처를 하나
얻습니다(접두는 컨트롤의 `absent_means`를 따름: `manual-`, `na-`, `pass-`). 워크 기반 컨트롤 다섯은 워크
게이트가 `absent_means`보다 먼저 답하므로 도달 가능한 모양은 `walk.complete` ok true에 판정 리스트
absent이고(`manual-no-package-db` 픽스처들이 이미 그 모양), absent 모양이 설계상 도달 불가능한
컨트롤은 자기 `absent_means` 뮤턴트 셋을 그 사유를 가진 예외 부류 하나로 적습니다.

**F-3 — 예외.** 살아남은 뮤턴트는 `controls/testdata/_mutants.yaml`에 있을 때만 통과합니다.
`- {control: muster.x.y, mutant: "checks[0].where expected +1", reason: …}`, 엄격 YAML. 사유는 왜 어떤
픽스처도 그 뮤턴트를 구별할 수 없는지 말해야 합니다(*등가* 뮤턴트 — 모든 픽스처 값이 정수일 때의
`lte 3` 대 `lt 4` — 또는 *설계상* 어떤 픽스처 쌍도 양쪽을 다루지 않는 배포판 조건). 실제로는 kill되는
뮤턴트를 담은 예외, 생성되지 않는 뮤턴트를 이름 짓는 예외는 테스트를 실패시킵니다 — 예외는 썩을
수 없습니다. 목표는 검토자가 한 자리에서 읽을 수 있는 예외 목록을 가진 100% kill이며, 픽스처가
없어서 살아남은 뮤턴트는 픽스처를 더해 고치지 예외로 고치지 않습니다. 예외는 컨트롤별·서명별이며
와일드카드는 없습니다.

**F-4 — 출력과 비용.** 실패 시 테스트는 살아남은 뮤턴트마다 한 줄 —
`muster.file.suid_sgid checks[0].require op eq->ne: 12 fixtures unchanged` — 을, 더는 성립하지 않는
예외에는 `excluded mutant … is now killed by <fixture>`를 출력합니다. 전체 테스트는 대략 컨트롤 68 ×
뮤턴트 10~20 × 픽스처 6을 평가하며 보통의 `go test ./internal/controls/`에서(초 단위) 플래그 없이
돕니다. 테스트의 첫 실행은 플랜 3F의 일부입니다. 살아남은 뮤턴트를 하나씩 살펴 절이 판정되지 않은
곳에 픽스처를 더하고, 남는 예외 목록은 플랜을 닫기 전에 행마다 검토합니다.

## 3. 파서의 네이티브 퍼징 (F-5 … F-7)

**F-5 — 파서 진입점마다 타깃 하나.** `internal/collect/collectors/fuzz_test.go`(패키지처럼 Linux 빌드
태그)와 `internal/pkgfiles/fuzz_test.go`(크로스플랫폼)가 `Fuzz<Name>` 타깃을 담습니다. 진입점은 수집기가
호스트 데이터로 호출하는 `parse*` 함수입니다. 부모만 호출하는 헬퍼(`parseNftRule`, `parseIptablesRule`,
`parseAptInstLine`, `parseRsyslogAction`, `parseRsyslogActionCall`, `parseProcAddr`, `parseKVInto`)는
부모를 통해 다루며 F-6의 커버리지 표에 그렇게 적습니다. 타깃과 어댑터:

| 타깃 | 호출 | 어댑터 |
|---|---|---|
| `FuzzParsePasswd`, `FuzzParseGroup`, `FuzzParseShadow` | 계정 파서 셋 | `[]byte` |
| `FuzzParseSubIDs` | `parseSubIDs(data, known)` | `known`은 `alice`에 참, 그 밖에 거짓 |
| `FuzzParseMountinfo` | `parseMountinfo` | `[]byte` |
| `FuzzParseDpkgStatus`, `FuzzParseAptSimulation`, `FuzzParseDnfCheckUpdate`, `FuzzParseRpmQa` | 패치 파서 | `[]byte` |
| `FuzzParseProcNet` | `parseProcNet(data, "tcp")`와 `"tcp6"` | 입력당 두 프로토콜 |
| `FuzzParseDaemonDump` | `parseDaemonDump` | `[]byte` |
| `FuzzParseSshdConfig` | `sshdOptions`의 키워드마다 `parseSshdConfig(a, "/etc/ssh/sshd_config", kw, 0)` 한 번 | 작은 인메모리 `Access`(`memAccess`, 테스트 파일에 새로: `ReadFile`/`Stat`/`Glob` 뒤의 `map[path][]byte`, `NoWalkAccess` 내장)가 입력을 주 파일이자 모든 `Include` 일치로 제공해 `Include` 루프를 밟게 함 |
| `FuzzParsePAMFile` | `parsePAMFile(data, "sshd", "/etc/pam.d/sshd")` | `[]byte` |
| `FuzzParseKV`, `FuzzParseDropin` | `parseKV`, `parseDropin(data, map)` | 호출마다 새 map |
| `FuzzParseShellFile` | `parseShellFile(data, "/etc/profile")` | `[]byte` |
| `FuzzParseNftRuleset`, `FuzzParseIptablesSave` | 방화벽 파서 | `string(data)`; iptables는 패밀리 `v4`와 `v6` |
| `FuzzParseVsftpdInto`, `FuzzParsePureFtpdInto`, `FuzzParsePostfixInto` | `*Into` ftp·메일 파서 | 호출마다 새 map |
| `FuzzParsePamListfiles`, `FuzzParseSendmailPrivacy` | `parsePamListfiles(data)`, `parseSendmailPrivacy(data)` | `[]byte` |
| `FuzzParseRsyslogSelector` | `parseRsyslogSelector(string)`와 같은 입력의 action 파서들 | 입력 하나, 호출 셋 |
| `FuzzParseExportsContent`, `FuzzParseChronySources` | nfs와 timesync | `[]byte` |
| `FuzzParseRPMFileLine`, `FuzzParseTarTV`, `FuzzParseStatLine`, `FuzzCanonicalUsr` | 내보내진 `internal/pkgfiles` 파서 | `string(data)`; `CanonicalUsr`는 타깃이 만드는 여섯 항목 표(`/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32` → `/usr/…`)로 |

타깃 본문은 세 성질만 검사하고 의미는 검사하지 않습니다. **패닉 없음**(퍼저 자체의 규칙 — 복구된
패닉은 입력과 함께 실패); **결정성** — 같은 입력으로 파서를 두 번 불러 결과가 `reflect.DeepEqual`
(map 어댑터는 map을 비교); **출력 유계** — 파서가 `sourceRaw`로 채우는 모든 필드는 `rawCap` 바이트
이하(토큰을 그대로 복사하는 필드 — 계정 이름, 마운트 지점 — 는 입력에 의해 유계이며 상한을 두지
않음), 파서가 돌려주는 모든 리스트는 입력 바이트 수 이하(행을 지어내는 파서는 버그; 한 줄을 여러
문장이나 레코드로 나누는 파서도 이 한계 안에 있음). 씨앗 코퍼스는 퍼즈 파일에 적은 타깃별
`testdata/` glob 목록에서 `f.Add`로 등록하며 — 플랜이 각 목록을 파서의 단위 테스트가 읽는 파일로
채움 — 그래서 씨앗은 테스트가 아는 픽스처이고, Go는 `go test`에서 이를 보통의 단위 테스트로
돌립니다(그것이 PR 회귀).

**F-6 — 코퍼스와 완전성.** 퍼저가 찾은 입력은 Go가 네이티브 형식으로 `testdata/fuzz/Fuzz<Name>/`에
씁니다. 야간 실패는 그 디렉터리를 아티팩트로 올리고 유지보수자가 파일을 커밋해 크래시를 PR
스위트가 도는 회귀로 만듭니다. `TestEveryParserHasAFuzzTarget`(같은 패키지)은 패키지 소스를 `go/ast`로
파싱해 첫 매개변수가 `[]byte`이거나 `content`, `line`, `sel`, `act`라는 이름의 `string`인 모든 최상위
함수를 나열합니다 — 이름 접두 `parse`는 규칙이 아닙니다. `nssSources`, `decodeACL`, `dnsTokenize`,
`rsyslogLogicalLines`, `rpmFileTable` 등 열 몇 개가 다른 이름으로 호스트 바이트를 파싱하기 때문입니다.
그런 함수 각각은 `Fuzz<Name>` 타깃의 피호출자이거나 이를 다루는 부모를 이름 짓는 `coveredThrough`
표의 행이어야 하며, 둘 다 없는 새 파서는 테스트를 실패시킵니다.

**F-7 — 어디서 도는가.** 새 워크플로 `.github/workflows/fuzz.yml` — 하루 한 번 `schedule`과
`workflow_dispatch` — `ubuntu-24.04`, 샤드 4개 매트릭스. 각 샤드는 자기 몫의 타깃 목록에 대해
`go test -run '^$' -fuzz '^Fuzz<Name>$' -fuzztime 60s ./internal/collect/collectors/`를 돌리며
(`pkgfiles` 타깃도 같은 분할에 참여) 타깃 50개 기준 샤드당 약 12분입니다. 실패한 타깃은 `testdata/fuzz/`를 올리고 잡을
실패시킵니다. 샤드 배정은 커밋하지 않고 계산합니다. 각 샤드가 `go test -list '^Fuzz' ./...`를 돌려 인덱스 mod 4가
자기 것인 타깃을 맡으므로 새 타깃은 존재하는 것만으로 순환에 합류합니다. `make fuzz TARGET=<name>
TIME=<duration>`은 같은 플래그로 타깃 하나를 로컬에서 돌립니다. PR 워크플로는 아무것도 얻지
않습니다. 씨앗 코퍼스는 이미 `go test ./...` 안에서 돕니다. 이는 본 설계 §11의 "PR에서 파서당
30초" 문장을 고칩니다. PR 예산은 씨앗 코퍼스이고 퍼징은 야간 실행입니다(§6에 기록).

## 4. 파서 오라클 (F-8 … F-10)

**F-8 — 네 쌍, 그것을 돌리는 머신 위에서 비교.** `internal/collect/collectors/oracle_test.go`(Linux)는
`MUSTER_ORACLE=1`이 아니면 skip합니다. 수집기 자신의 선언으로 `collect.Guard`를 씌운 `collect.Host()`로
호스트를 읽고, 오라클 명령을 테스트 안에서 `collect.RunCommand`(절대 경로, 셸 없음, 타임아웃과
출력 상한)로 돌려 비교합니다.

| 파서 | 오라클 | 규칙 |
|---|---|---|
| `/etc/ssh/sshd_config`에 대한 `parseSshdConfig`, `sshdOptions`의 키워드마다 한 번(파싱 경로, 직접 호출하므로 `-G`/`-T`는 참조하지 않음) | root로 `sshd -T` | 파서가 값으로 해석한 모든 키워드에 대해, 테스트가 소유한 별칭 표(`without-password`와 `prohibit-password`는 양쪽 모두 한 토큰으로 접음 — `sshd -T`는 어느 철자든 `without-password`로 출력하므로; 설정되지 않은 `banner` → `none`; 대소문자 접음)를 거친 뒤 `-T`가 같은 키워드에 같은 값을 가짐; 파일이 설정하지 않은 키워드는 비교하지 않음(기본값은 데몬의 것) |
| `/etc/passwd`, `/etc/group`에 대한 `parsePasswd`, `parseGroup` | `getent passwd`, `getent group` | 파서의 모든 행 `(name, uid, gid, home, shell)` / `(name, gid, members)`가 `getent` 출력에 같은 값으로 나타남(members는 파서의 trim·중복 제거 후 비교); `getent`에만 있는 행은 systemd 동적 범위 61184–65519의 id를 가져야 함(Ubuntu 24.04와 EL9는 `passwd: files systemd`) — 그 밖은 불일치 |
| `/proc/self/mountinfo`에 대한 `parseMountinfo` | `findmnt -A -J -o ID,FSTYPE,TARGET`(`-A`는 mountinfo의 모든 행을 유지; 없으면 findmnt가 중복을 제거) | `findmnt`의 중첩 `children`을 펴고 같은 8진 이스케이프 해제 후 `(id, fstype, target)` 집합이 같음 |
| services 표의 모든 행에 대한 `services.<name>.enabled`와 `.active`(수집기의 팩트는 논리 서비스 단위이며 행의 유닛들에 대한 OR) | 행의 유닛마다 `systemctl show -p LoadState,ActiveState,UnitFileState,SubState <unit>` | `enabled`는 행의 유닛들에 대한 `enabledFromUnitFile(state, active)`의 OR와 비교(수집기 자신의 함수를 재사용): 수집기 `false` 대 systemd `true`는 항상 불일치, 수집기 `true` 대 systemd `false`는 inetd 이름도 슈퍼서버 항목도 없는 행에서만 불일치(수집기는 슈퍼서버 적중도 세는데 오라클은 그것을 보지 못함); `active`는 `ports`와 슈퍼서버 이름이 없는 행에서만 비교(나머지는 수집기가 도달 가능한 포트나 inetd 항목도 세는데 오라클은 그것을 보지 못함) |

불일치는 쌍·키·양쪽 값을 이름 지어 실패합니다. 오라클 바이너리가 없는 쌍(openssh 없는 컨테이너의
`sshd`)은 바이너리 이름과 함께 skip하며, 테스트의 요약 줄이 몇 쌍이 돌았는지 말합니다.

**F-9 — 어디서 도는가.** 러너 VM의 root 잡이 `sudo env PATH="$PATH" GOFLAGS="$GOFLAGS" MUSTER_ORACLE=1 go test
./internal/collect/collectors/ -run Oracle -count=1`(기존 sudo-run 스텝의 모양)을 돌리고 skip 0을
단언합니다(러너에는 `sshd`, `getent`, `findmnt`, `systemctl`이 있음). init 컨테이너(Rocky, Alma)에는 Go
툴체인이 없으므로 러너가 테스트 바이너리를 정적으로 한 번 빌드해(`CGO_ENABLED=0 go test -c
./internal/collect/collectors/ -o bin/collectors.test`) 컨테이너 스텝이 매트릭스가 이미 가진 `bin`
마운트에서 실행합니다(`MUSTER_ORACLE=1`로 `/m/collectors.test -test.run Oracle`; 테스트는 `testdata`를
읽지 않음). 거기서는 이미지에 `sshd`가 없으면 sshd 쌍이 skip되고, 로그가 어느
쌍이 돌았는지 기록합니다. init 아닌 컨테이너는 돌리지 않습니다(systemd 없음, 오라클이 될 데몬 없음).

**F-10 — 이미지의 실제 파일에서 나온 씨앗 코퍼스.** 테스트 코드가 아니라 네 줄짜리 셸 스텝입니다.
오라클 스텝 뒤에 root 잡과 각 init 컨테이너가 `/etc/ssh/sshd_config`(과 `/etc/ssh/sshd_config.d/*`),
`/etc/passwd`, `/etc/group`, `/proc/self/mountinfo`를 아티팩트 `seeds-<image>`로 복사합니다.
유지보수자가 이를 한 번 Go 코퍼스 형식으로 바꿔 `testdata/fuzz/Fuzz<Name>/`에 커밋합니다(설계 §11:
"seed corpora taken from the CI images' real files"). 파일에 비밀은 없습니다 — 공개 이미지의 계정 이름,
러너의 마운트 표 — 그리고 shadow 파일은 결코 복사하지 않습니다. 이 스텝은 게이트가 아니며 네 파일에만
돕니다.

## 5. 예시 스냅샷 (F-11 … F-12)

**F-11 — 파일.** `examples/`에 `ubuntu-24.04-container.json`(`ubuntu:24.04` 컨테이너 안에서 수집: overlay
루트, 워크 리스트 `unsupported`), `ubuntu-24.04-vm.json`(러너 VM에서 `--deep`과 root 잡이 쓰는 같은 제외로
수집해 워크 리스트에 실제 행이 있음), 각각의 `…-report.json`과 `…-report.txt`(`check --format json` / 표),
그리고 각 파일의 출처·정확한 명령·run id·"여기 어떤 파일도 누군가의 호스트에서 오지 않았다"를 적은
`examples/README.md`. 스냅샷 헤더가 이미 provenance(`muster_version`, `commit`, `collected_at`,
`host.os_release`)를 담습니다. `check`가 돌기 전에 워크플로가 각 스냅샷의 두 가지를 `jq`로 고쳐 써서
호스트 모양의 리터럴이 커밋되지 않게 합니다. `run.host.hostname`은 `github-runner` /
`ubuntu-container`가 되고, `sockets.*` 레코드의 루프백·와일드카드가 아닌 모든 `addr`는 `192.0.2.1`(RFC
5737 주소)이 됩니다. `run.host.boot_id`(원본 부트 UUID), `run.host.kernel`, `run.host.uptime_s`는
비웁니다(이미지가 아니라 러너의 커널을 식별함). `machine_id_hash`는 해시라 그대로 둡니다. 리포트는 고쳐 쓴 파일에서
생성합니다. 4 MiB를 넘는 예시는 워크플로가 거부합니다(VM의 워크 리스트는 root 잡의 제외 뒤 상한
아래에 있음).

**F-12 — 생성과 테스트.** 새 워크플로 `.github/workflows/examples.yml`(`workflow_dispatch`, 그리고 이 워크플로 파일을 고치는 풀 리퀘스트)이 바이너리를
빌드하고 스냅샷 둘과 리포트 둘을 수집해 아티팩트 `examples-<run id>`로 올립니다. `make examples-fetch
RUN=<id>`가 `gh run download`로 `examples/`에 내려받고 사람이 커밋합니다. `cmd/muster/examples_test.go`는
커밋된 스냅샷을 각각 로드해 내장 셋으로 `check`를 돌리고 어떤 결과도 `ERROR(internal_error)`가 아님을
단언하며 리포트 둘을 메모리에서 재생성합니다. JSON 리포트는 `check` 블록의 `muster_version`, `commit`,
`controls_version`, `controls_digest`를 마스킹한 뒤(인프로세스 테스트는 `dev`/`none`을 채움) 커밋된 것과
바이트 단위로 같아야 하고, 표도 첫 헤더 줄을 마스킹한 뒤 마찬가지 — 실제 스냅샷 위의
같은-입력-같은-바이트 계약입니다. 낡음은 게이트하지 않습니다. 더 오래된 `controls_version`으로
수집한 예시도 로드·평가되는 한 통과합니다. README 양쪽이 이 파일들을 가리키는 "출력 예시" 문단을
얻습니다.

## 6. 그 밖의 변경

- `internal/controls/mutation_test.go`, `controls/testdata/_mutants.yaml`; 픽스처가 없어 뮤턴트가
  살아남은 곳마다 새 픽스처.
- `internal/collect/collectors/fuzz_test.go`(`memAccess` 포함), `oracle_test.go`,
  `testdata/fuzz/**`; `internal/pkgfiles/fuzz_test.go`.
- `.github/workflows/fuzz.yml`, `examples.yml`; `ci.yml`: `collect-root`의 오라클 스텝, init
  컨테이너의 정적 테스트 바이너리 실행, 씨앗 파일 아티팩트 스텝.
- `Makefile`: `fuzz`, `examples-fetch`. `examples/`(파일 다섯).
- `CONTRIBUTING.md`/`.ko.md`: 픽스처는 자기 절의 뮤턴트를 죽여야 하고 살아남은 뮤턴트는 사유를 가진
  예외; 새 파서는 퍼즈 타깃·씨앗·샤드 줄이 필요; 예시 갱신 방법. `CLAUDE.md` Tests 두 줄.
  `CHANGELOG.md` Tooling 아래. 본 설계 §11 "3단계" 문장이 넷을 3F로 표시하고 고쳐짐: 퍼징은 씨앗 코퍼스를 PR 회귀로 두고
  밤마다 돌며(F-7), PR마다 파서당 30초가 아님. `controls/VERSION`은
  컨트롤이 바뀔 때만 올림(픽스처만의 변경은 유지).

## 7. 오류와 저하

- 3F의 어느 것도 수집기의 읽기, 키, 상한, 판정을 바꾸지 않습니다. 퍼저가 깨뜨린 파서는 크래시
  입력을 씨앗으로 커밋하며 별도 커밋으로 고치고, 뮤턴트가 틀렸음을 증명한 컨트롤은 CHANGELOG 줄과
  VERSION bump를 갖춘 별도 커밋으로 고칩니다.
- 뮤테이션 테스트는 `controls/` 아래에 쓰지 않습니다. 픽스처를 `ERROR(internal_error)`로만 바꾸는
  뮤턴트는 kill이 아니라 invalid입니다(F-1).
- 오라클 테스트는 기본이 꺼짐(`MUSTER_ORACLE` 미설정 → skip)이며, 개발자 머신에서 부르지 않는 한
  돌지 않고 랩 호스트에서 체크아웃으로 돌지 않습니다.
- 예시 워크플로는 요청할 때만 돌고, 커밋된 예시는 사람이 갱신합니다.

## 8. 테스트와 성공 기준

- 뮤턴트: 100% kill, 예외는 플랜의 Execution notes에서 행마다 검토; 테스트는 보통의 스위트에서 초
  단위로 돕니다.
- 퍼징: 모든 진입점 파서에 타깃과 씨앗(`TestEveryParserHasAFuzzTarget` 초록); 첫 야간 실행은 브랜치에서
  수동으로(`workflow_dispatch`) 촉발하고 결과 — 크래시 유무 — 를 기록; 크래시는 수정 커밋과 커밋된
  씨앗.
- 오라클: 러너 잡이 네 쌍을 skip 0으로 돌림; init 컨테이너는 바이너리가 있는 세 쌍을 돌림; 첫 실행에서
  발견된 불일치는 기록하고 파서 버그로 고치거나(별도 커밋) 테스트에서 고치는 정규화 빈틈임을 보임.
- 예시: `workflow_dispatch` 실행에서 스냅샷 둘과 리포트를 커밋; `TestExamplesLoadAndCheck` 초록; README
  쌍이 이를 가리킴.
- CLAUDE.md의 모든 게이트가 초록으로 유지; 어떤 파일에도 호스트명·주소·별칭·조직명 없음(예시의
  hostname과 소켓 주소는 고쳐 씀, F-11); 랩 호스트에서 캡처한 것은 커밋하지 않음.
