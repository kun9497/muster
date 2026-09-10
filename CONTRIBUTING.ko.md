# muster에 기여하기

muster는 Linux 호스트를 KISA 2026 Unix 서버 가이드에 대조해 점검합니다. 기여는 대개
셋 중 하나입니다. 컨트롤, 수집기 팩트, 또는 평가기·렌더러 수정. 이 문서는 각각이
어떻게 들어오는지를 말합니다. 설계와 결정 기록은
`docs/superpowers/specs/2026-09-02-muster-design.ko.md`에 있습니다. 바꾸려는 절을
바꾸기 전에 읽으세요. 영문 원본: `CONTRIBUTING.md`.

## 무엇보다 먼저

- Go 1.25. `go build ./...`, `make test`(C 툴체인이 없는 호스트에서는 `go test ./...`),
  `make lint`, `make lint-controls`, `make coverage`.
- `collect`는 Linux 전용이며 빌드 태그 뒤에 있습니다. 다른 플랫폼에서는 크로스 컴파일로
  확인하고(`GOOS=linux GOARCH=amd64 go vet ./... && GOOS=linux GOARCH=amd64 go test -c
  ./internal/collect/collectors/ -o /dev/null`) 실행은 CI에 맡깁니다.
- KISA 가이드나 CIS Benchmark의 문장을 어떤 파일에도 옮기지 않습니다.
  `docs/reference/kisa/`는 항목 코드·이름·분류·중요도·페이지 번호만 담고, 컨트롤 설명은
  muster의 말로 씁니다. `ATTRIBUTION.md`를 보세요.
- 조직명, 호스트명, 주소, 별칭, 자격증명이 들어간 것은 절대 커밋하지 않습니다. 픽스처는
  `example.org`/`example.net` 이름과 RFC 5737 주소만 씁니다. 사설 호스트에서 수집한
  스냅샷은 전체든 일부든 커밋하지 않습니다.

## 컨트롤 추가

1. **뼈대 만들기.** `go run ./cmd/muster controls new muster.<area>.<name> --kisa-id U-NN`
   이 `controls/<area>/<name>.yaml`을 항목의 중요도와 KISA 참조(2026, 그리고 매핑의 2021
   번호)를 채워 쓰고, `controls/testdata/<id>/`에 그 automation이 도달할 수 있는 픽스처
   스텁(`auto`·`partial`은 `pass-`/`fail-` 한 쌍, `manual`은 `manual-` 하나)을 만듭니다. area는
   `account`, `file`, `service`, `patch`, `log`, `beyond`입니다. 다른 컨트롤이 이미 등재한
   항목과 `docs/reference/kisa/kisa_deferred.json`에 유예된 항목은 거부합니다. 유예 항목을
   등재하려면 먼저 유예 항목에서 지우세요. 현재 인벤토리의 항목은 모두 둘 중 하나이므로,
   이 뼈대는 다음 판의 항목이나 단계가 도래한 유예 항목을 위한 것입니다.
2. **팩트 이름 붙이기.** 모든 절은 등록된 키(`internal/facts/registry.yaml`)를 읽습니다.
   팩트가 아직 없다면 그 팩트를 소유하는 수집기에 먼저 추가합니다(아래). 절은 원시 JSON
   경로를 읽지 않습니다.
3. **판정 쓰기.** 판정이 하나면 `checks`, 호스트를 여러 경로로 판정할 수 있으면
   `mechanisms`, 6.3절 문법으로 표현할 수 없을 때만 `custom`. 부재한 팩트의 의미는
   `absent_means`(`pass`, `fail`, `not_applicable`, `manual`)로, 게이트는 `applies_when`으로
   정합니다. `manual` 컨트롤은 `manual_reason`과, 검토자가 앞에 두어야 할 팩트의
   `evidence:` 목록을 가집니다.
4. **픽스처.** 판정(`checks`나 `mechanisms`)이 있는 컨트롤은 `controls/testdata/<id>/pass-*.json`과
   `fail-*.json`이 필요하고, `manual` 컨트롤은 모든 `evidence:` 리프를 담은 `manual-*.json`이
   필요하며 `applies_when` 게이트가 있으면 `na-*.json`도 둡니다(컨트롤에 따라 `error-*`;
   파일 이름 접두사가 기대 상태입니다). 각각은 컨트롤이 읽는 키만 담은 부분 스냅샷이며
   `"synthetic": true`로 표시합니다. `go run ./cmd/muster snapshot extract --facts <스냅샷>
   --control <id> --out <파일>`이 실제 스냅샷에서 정확히 그 키들만 잘라 냅니다. 값을
   검토하고 호스트를 식별하는 것을 지운 뒤 synthetic으로 표시하세요. `_expect`로
   `reason_code`와 `exit_code`를 고정할 수 있습니다. 픽스처 테스트가 읽는 키는 이 둘뿐이며,
   기대 상태는 `_expect` 필드가 아니라 파일 이름 접두사입니다. YAML 설명문은 일반 스칼라라서
   따옴표 없이 `: ` 순서를 담을 수 없으니, 필요하면 설명문을 따옴표로 감싸세요.
5. **lint, 테스트, 재생성.** `make lint-controls`(KISA 교차 검사, STIG/NIST 인덱스, 픽스처
   쌍, 문법), `go test ./...`, 그리고 `make coverage` 후 재생성된
   `docs/reference/coverage.md`를 커밋합니다. 등재 수가 바뀌었다면 두 README의 로드맵
   문장을 갱신하세요. 숫자가 맞을 때까지 `-check`가 실패합니다.
6. **참조.** `references.stig` 항목은 `{benchmark, version, id}`이며
   `docs/reference/stig/*.json`에 있어야 합니다. `references.nist_800_53` id는 인덱스된 어떤
   규칙에든 나타나야 합니다. `make refindex`가 고정된 DISA 파일에서 인덱스를 재생성하고
   (네트워크 필요), CI는 커밋된 인덱스만 읽습니다.

## 팩트 추가

- 키를 먼저 등록합니다. `{key, type, description, since, sensitivity, collector}`(설정은
  `default_on`, 리스트는 `subject_kind` 추가). 키나 레코드 필드 추가는 `schema_version`을
  유지하고, 키의 타입이나 의미 변경은 올립니다. 팩트 스키마 골든
  (`go test ./internal/facts -run TestFactsSchemaGolden -update`)이 변경을 기록합니다.
  diff를 검토하세요.
- 모든 리프는 상태가 있는 봉투입니다. `ok`, `absent`, `denied`, `unsupported`, `timeout`,
  `error`. `ok`가 아닌 상태는 결코 PASS를 만들지 않습니다. 스냅샷에 없는 등록 키는
  `missing`으로 읽히고 `ERROR(missing_fact)`이며, `absent_means`로 면제되지 않습니다.
- 수집기는 건드리는 모든 경로와 명령을 선언합니다(`Declare.Reads`, `Declare.Commands`).
  선언 밖 읽기는 위반입니다. 설정 파일에서 발견한 경로는 선언이 덮을 때만 읽고, 아니면
  기록만 하고 열지 않습니다.
- `CLAUDE.md`의 규약이 모든 수집기를 구속합니다.
  - **C1** — `files.*`가 고정 경로 목록의 권한 팩트를 소유합니다. 데몬 설정에서 발견한
    경로는 그 데몬의 수집기 몫입니다.
  - **C2** — 절이 판정하는 모든 리프는 자기 점 키를 가집니다. `record` 팩트는
    `present`/`absent`의 근거일 뿐입니다.
  - **C3** — 존재하지만 읽을 수 없는 설정 파일은 그 파일이 정할 수 있었던 모든 값의
    답(경로를 앞에 붙인 읽기 상태)이며, 모듈 기본값이 아닙니다.
  - **C4** — 모델이 읽지 않기로 한 경로는 사유에 경로를 담은 `absent`입니다. 선언되었고
    존재하지만 읽을 수 없는 파일은 읽기 상태입니다. 관리자가 선언된 주 설정 파일 자리에
    둔 심링크는 의도적으로 `error`입니다(muster는 심링크를 따라가지 않고 읽습니다.
    배포판이 심링크를 제공하는 곳은 수집기가 모델링합니다).
- 정직한 저하. 그런 메커니즘이 없는 환경은 `unsupported`, root 전용 읽기를 비root로 하면
  `denied`, 권한이 필요 없는 수집기는 결코 `error`를 내지 않습니다. 수집기에서 `time.Now`를
  쓰지 않습니다. 나이는 `collected_at`으로 계산합니다.
- 같은 입력, 같은 바이트. 모든 리스트를 정렬하고, map 순서가 값이나 사유에 닿지 않게
  합니다.

## 테스트

- 헬퍼 테스트보다 호출자를 움직이는 테스트를 먼저 씁니다. 호출 지점을 추가한 뒤 그 호출을
  지우고 스위트가 빨개지는지 확인하세요. 초록으로 남으면 기능이 아니라 구현을 테스트한
  것입니다.
- 기능이 사라졌을 때 달라지는 것을 단언하세요. 부분 문자열보다 구조적 단언을 우선합니다.
- 골든: `go test ./internal/report -run TestJSON -update`, `-run TestTableGolden -update`,
  위의 팩트 골든. 재생성된 골든은 커밋 전에 모두 검토합니다.
- CI는 race 빌드, lint, coverage 검사, 러너 VM에서의 root 수집, 비root 수집, 컨테이너
  매트릭스(Ubuntu 22.04/24.04, Rocky 9, AlmaLinux 9, Debian 12는 카나리), 읽기 전용 계약
  실행, 그리고 capability matrix(`docs/reference/capability-matrix.json`: root 없이
  `denied`여야 하는 팩트와 systemd 없이 `unsupported`여야 하는 팩트)를 돌립니다.

## 문서

영문이 정본입니다. 사용자를 향한 문서 — README, 이 문서, 설계 스펙, 그리고 모든 컨트롤의
제목과 설명 — 는 같은 커밋에서 갱신되는 `X.ko.md`(또는 `_ko`) 쌍을 가지며, `CHANGELOG.md`,
`CLAUDE.md`, 계획 문서, 보안·저작권 고지는 영문 전용입니다. 식별자, 플래그, 경로는 양쪽
모두 영문으로 둡니다. 기존 스냅샷의 판정을 바꾸는 변경은 changelog의 **Controls** 아래에
기록하고 `controls/VERSION`을 올립니다.

## 커밋과 리뷰

본인의 이름과 이메일로 커밋합니다. 프로젝트는 조직 신원을 두지 않습니다. 커밋 하나는
한 가지 변경이며 제목이 하는 일을 말합니다. 풀 리퀘스트는 CI 매트릭스 전체를 돌리고,
시크릿 스캔(`gitleaks`)이 범위의 모든 커밋을 훑으므로 테스트 픽스처의 사설 호스트명
모양이나 RFC 1918 주소는 실패합니다. 공개 예시 범위를 쓰세요.
