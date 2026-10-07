# 3D-1단계 — 프로파일과 튜닝

영어 원본: `2026-10-07-stage3d1-profiles-design.md`. 여기의 결정은 Y-1 … Y-9이며, 메인 설계의 §6.6을 이
문서가 실현하고 D33을 더합니다.

## 1. 범위와 의도

로드맵의 3D(메인 설계 §10.2)는 독립된 세 조각 — 프로파일과 튜닝(§6.6), `fix --dry-run`, 플래그 둘
(`--anonymize`, `--max-age`) — 을 묶고 있습니다. 이 사이클은 그 첫째입니다. **프로파일**은 muster가 호스트에
묻는 질문의 목록 — 어느 컨트롤을, 어떤 파라미터 값으로, 어떤 심각도로 — 이고, **튜닝 파일**은 한 사이트의
그 파라미터 값입니다. 둘 다 `check`만 읽습니다; `collect`는 둘을 모르고, 모든 수집기는 여전히 돌며, 나중에
어떤 프로파일이 읽든 스냅샷은 같습니다.

먼저 하는 이유: §6.6의 계약(D18 — 적용된 값은 결과에 남는다)을 닫고, 어느 플랫폼에서나 도는 순수 check 쪽
작업이며, 그 뒤 `fix --dry-run`(3D-2)이 `check`와 같은 도우미(§5)로 얻는 "적용 중인 프로파일의 실패"라는
정의된 의미를 얻습니다.

- **Y-1 — 메커니즘만; CIS 프로파일은 색인을 기다린다.** 내장 프로파일은 `default`(모든 컨트롤;
  `kisa-unix-2026`은 그 별칭)이고, `cis-<distro>-l1`은 `docs/reference/cis/` 아래 CIS 권고 ↔ 컨트롤 색인(번호와
  버전만 — CIS 본문은 결코 복사하지 않음, ATTRIBUTION.md)이 생기는 다음 사이클입니다. 이 문서는 그 이름 규약과
  "그런 프로파일의 컨트롤은 `references.cis`를 먼저 인용한다"는 규칙만 정합니다.
- **Y-2 — 제외된 컨트롤은 평가하지 않고 싣지도 않는다.** 결과는 프로파일(이름, 출처, 다이제스트, 체인)과
  제외된 id를 기록합니다; 새 상태 없음, 렌더러의 행 계약과 종료 코드 규칙 불변. waiver 규칙은 한 곳만
  바뀝니다: 제외된 컨트롤을 대는 waiver는 `unknown`이 아니라 `not_applied`(excluded by profile)입니다.
- **Y-3 — 선택은 컨트롤 id 글롭으로만.** id가 이미 범주와 범위를 담습니다(`muster.<category>.<name>`,
  `muster.beyond.<name>`); `include`/`exclude`는 패턴 목록입니다. 이름 있는 차원도, 표현식 언어도 없습니다.
- **Y-4 — 심각도는 같은 글롭으로 컨트롤별로 덮어쓰고, 뒤의 항목이 이긴다.** 중요도 → 심각도 유도(상 → high,
  중 → medium, 하 → low)는 기본으로 남고, 결과는 행마다 심각도와 그 출처를 싣습니다.
- **Y-5 — 튜닝은 사이트 값만 담고 프로파일 뒤에 적용된다.** 우선순위: 컨트롤 기본값 < 프로파일 `params` <
  튜닝. 정확한 id, 컨트롤의 `params` 선언에 대한 엄격한 타입 검증.
- **Y-6 — 각각 플래그 하나, 내장 또는 파일.** `--profile <name|path>`, `--tuning <path>`; `extends`는
  내장 이름이나 파일 기준 상대 경로를 댑니다; 프로파일 디렉터리도, waiver 파일 안의 프로파일도 없습니다.
- **Y-7 — 프로파일은 평가 전에 해결되고 평가기는 순수하게 남는다.** `internal/profile`이 적재된 컨트롤
  세트에 대해 프로파일을 선택 id 집합·병합된 파라미터·심각도 맵으로 풀고, `check`는 세트의 부분집합 뷰를
  평가하며, 리포트가 심각도 맵을 적용합니다.
- **Y-8 — 로드는 엄격하게, 경계는 너그럽게.** 미지 키, 안 맞거나 잘못된 패턴, 미지 컨트롤·파라미터, 타입이
  틀린 값, 미지 심각도, 순환, 파일 넷을 넘는 체인, 빈 선택은 파일을 거부합니다. 프로파일이 제외한 컨트롤을
  대는 프로파일·튜닝 파라미터는 경고라, 프로파일을 바꿔 끼워도 튜닝 파일이 살아남습니다.
- **Y-9 — 결과의 모든 변경은 추가이며 `check` 아래 산다.** 결과의 `check` 블록 안 기존 필드 옆에 새 필드;
  `run`(스냅샷의 출처, §9)은 손대지 않음; JSON·표 골든은 검토한 diff로 재생성; examples는 브랜치의 실행에서
  갱신합니다.

## 2. 아키텍처

```
controls.LoadDefault()  ──►  profile.Resolve(set, src, warn)  ──►  Resolved{IDs, Params, Severity, Digest, Chain}
                                       │                                      │
                                       │        tuning.Load(set, path, warn) ──► params 병합(기본 < 프로파일 < 튜닝)
                                       ▼                                      ▼
                       cmd/muster resolveSelection(flags, set, warn)  ──►  Selection{subset, params, sources, severity, blocks}
                                       │
                                       ▼
              check.Evaluate(snap, subset, reg, Options{Params}) ──► waiver.Apply(results, known, excluded, …)
                                       │
                                       ▼
                       report.Build(snap, results, cb, severity)  ──►  JSON / 표 / 종료 코드
```

- **`internal/profile`(신규).** `Parse([]byte) (*File, error)` — 엄격한 YAML. `Resolve(set
  *controls.Set, src Source, warn func(string)) (*Resolved, error)` — `Source{Name string; Path
  string}`은 내장(`Name`)이나 파일(`Path`, 받은 그대로)을 대고; `Resolve`는 `extends`를 따라가고
  include/exclude를 적용하며 params·severity를 세트에 대해 검증하고 다이제스트를 계산. `Builtins()`는 임베드된
  `default`를 Go 리터럴로 돌려줌(그것의 YAML 파일은 없음). `internal/controls`(세트, 파라미터 타입 검사)에만
  의존; stderr에 직접 쓰지 않음 — waiver 패키지처럼 `warn`이 경고를 나름(§7.4).
- **`internal/tuning`(신규, 작음).** `Parse([]byte)`, `Load(set, path, warn)` — 같은 검증의 `params:` 맵;
  컨트롤별 맵과 파일의 다이제스트를 돌려줌.
- **`internal/controls`.** `Set.Subset(ids []string) *Set` — 세트 순서의 뷰이며 전체 세트의 `Version`과
  `Digest`(컨트롤 다이제스트는 임베드된 YAML의 이름이지 선택의 이름이 아님)와 다시 만든 자기 id 색인을 가짐.
  `CheckParamValue(typ string, v any) error` — lint가 기본값에 이미 하는 타입 검사를 내보내 프로파일·튜닝
  검증기가 공유. `internal/controls` 안에는 프로파일 검사 없음(`internal/profile`을 import할 수 없음):
  `Resolve`가 거부를 돌려주고 `cmd/muster`가 보고.
- **`internal/waiver`.** `Apply`가 제외 id 집합을 받음: 거기 든 id는 경고 `waiver for <id> not applied:
  excluded by profile`과 함께 `not_applied`로 셈; 어느 집합에도 없는 id는 `unknown` 그대로. 메모를 실을 행은
  없음(그 컨트롤은 행이 없음).
- **`internal/check`.** 동작 불변; `Options.Params`가 병합된 맵. `Result` 불변(심각도는 오늘처럼 리포트의
  관심사: `report.Row.Severity`).
- **`internal/report`.** `Build(snap, results, cb, severity map[string]string)`가 행마다
  `severity_source`를 기록; `CheckBlock`에 `Profile`, `Tuning`, `ParamSources`; 표는 프로파일 줄 하나를 찍음.
- **`cmd/muster`.** 도우미 하나 `resolveSelection(flags, set, warn) (*Selection, error)`가 신뢰 파일 검사,
  프로파일 해결, 튜닝 로드, 병합, 부분집합을 맡음; `check`, examples 테스트(G-14: 구현 하나), 그리고 3D-2의
  `fix`가 이것을 부름. `check --profile`, `check --tuning`; `controls lint --profile`;
  `controls list --profile`.

## 3. 프로파일 파일

```yaml
profile: site-web-2026            # [a-z0-9][a-z0-9-]*, 필수; 내장 이름을 되풀이할 수 없음
extends: default                  # 내장 이름 또는 이 파일 기준 상대 경로; 선택
include: ["muster.*"]             # id 글롭, extends 뒤에 적용
exclude: ["muster.beyond.*", "muster.file.ip_port_restriction"]
params:                           # 정확한 id → 파라미터 → 값
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, tcp/443]
severity:                         # 순서 있음: 뒤 항목이 이김
  - { controls: "muster.beyond.*", level: low }
  - { controls: muster.file.world_writable, level: high }
```

- **글롭.** 패턴은 `path.Match`로 컨트롤 id에 맞추며 `*`는 `.`을 가로지릅니다(`Builder.Get`이 사실 글롭에
  쓰는 규칙, `internal/collect/facts.go`). 그래서 `muster.beyond.*`는 beyond 컨트롤 전부, `muster.file.*`는 한
  범주입니다. `?`와 `[…]`를 허용합니다. `path.Match`가 거절하는 패턴은 패턴을 이름 대며 파일을 거부하고,
  적재된 세트의 어느 컨트롤에도 맞지 않는 올바른 패턴도 거부합니다(오타가 조용히 아무것도 안 고르는 일은
  없음). 패턴은 선택이 아니라 적재된 세트에 대해 검증합니다: 아무것도 빼지 않는 `exclude`는 합법이고
  조용합니다.
- **이름과 경로.** 내장 이름은 `/`도 `\`도 `.yaml`/`.yml` 접미도 없는 `[a-z0-9][a-z0-9-]*`; 그 밖은 경로(모든
  플랫폼에서 `filepath` 규칙). 규칙은 `--profile`과 `extends`에 같습니다: 이름은 내장에서 찾고, 그중 어느
  것도 아니면 내장 목록을 대며 거부; 경로는 파일로 읽되 — 플래그는 작업 디렉터리 기준, `extends`는 참조하는
  파일 기준 상대 경로. `profile:`이 내장 이름을 되풀이하는 파일은 거부. 되풀이된 플래그는 `check`의 모든
  플래그처럼 마지막 값을 씁니다.
- **해결.** `extends` 체인을 뿌리부터 걷습니다; 체인은 내장을 포함해 최대 파일 넷(더 긴 체인, 순환, 없는
  파일, 미지 이름은 거부). 파일마다 이 순서로: `선택 = 부모.선택 ∪ include 매치 − exclude 매치` — 부모의
  `exclude`는 자식이 물려받는 규칙이 아니라 자식이 다시 더할 수 있는 선택일 뿐; `params`는 (컨트롤, 파라미터)
  단위로 병합하되 자식이 이김; `severity` 항목은 부모 것 뒤에 덧붙임. `extends` 없는 파일은 빈 선택에서 시작.
  내장 `default`는 `{profile: default, include: ["muster.*"]}`; `kisa-unix-2026`은 같은 객체의 이름이며 그것으로
  풀립니다(결과에는 `default`로 보임).
- **Params.** 값은 컨트롤이 선언한 `params.<name>.type`(`int`, `string`, `bool`, `list<int>`,
  `list<string>` — 기존 어휘, `controls.CheckParamValue`를 통해)으로 디코딩; 틀린 타입, 미지 파라미터, 미지
  컨트롤은 파일 거부. 해결된 선택이 제외한 컨트롤의 파라미터는 경고(Y-8).
- **Severity.** `level` ∈ {high, medium, low}; 마지막으로 맞는 항목이 이김; 어느 컨트롤에도 안 맞는 글롭의
  항목은 파일 거부; 제외된 컨트롤에만 맞는 항목은 경고.
- **빈 선택**은 파일 거부("profile selects no control").
- **다이제스트.** 해결된 내용만의 정규 JSON — `{ids: 정렬, params: 컨트롤·파라미터 순 정렬, severity:
  [{controls, level}…] 순서대로}` — 의 `sha256`. 이름·출처·체인은 그 옆에 기록되지 안에 들어가지 않으므로,
  같은 컨트롤을 같은 값·같은 심각도 항목으로 고르는 두 파일은 이름·경로·`include` 순서가 달라도 같은
  다이제스트를 가지고, 값이 바뀌면 달라집니다.

## 4. 튜닝 파일

```yaml
params:
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, udp/68, udp/546, tcp/443]
  muster.account.password_policy:
    min_len: 12
```

정확한 id, 같은 타입 검증, 프로파일 params 뒤에 적용. 프로파일이 제외한 컨트롤 → 경고. `include`,
`exclude`, `severity`, `extends` 없음: 튜닝 파일은 사이트의 숫자만 싣고 묻는 질문을 바꾸는 것은 싣지
않습니다. 다이제스트는 파일 바이트의 것.

## 5. 통합

- **플래그.** `check --profile <name|path>`(기본 `default`)와 `check --tuning <path>`;
  `controls lint --profile <name|path>`는 기존 lint를 돌린 뒤 임베드된 세트에 대해 프로파일을 해결하고 기존
  `ok:` 줄 뒤에 `ok: profile <name> selects N of M controls, K excluded`를 찍음(거부는 종료 2, 경고는 stderr에
  종료 0; 전체 lint가 요구하는 디렉터리는 여전히 필요 — 유지보수자와 CI의 명령); `controls list --profile
  <name|path>`는 해결해서 선택된 id만 나열(운영자가 사이트 프로파일을 검증하는 길; 거부는 종료 2). CI는
  `test` 잡에서 기존 lint 호출 옆에 `controls lint --profile default`를 돌림(`ci.yml`, Makefile만이 아님).
- **신뢰 파일.** `check`가 root로 돌 때 프로파일, 그 `extends` 체인이 닿는 모든 파일, 튜닝 파일은 waiver
  파일처럼 root 소유이고 그룹·기타 쓰기 불가여야 함(`trustedFile`, D12); 비root에선 아무것도 검사하지 않음.
  심볼릭 링크 규칙 없음.
- **흐름.** `resolveSelection`: 세트 적재 → 프로파일 해결 → 튜닝 로드 → params 병합(기본 < 프로파일 < 튜닝)과
  값마다 출처 기록 → `set.Subset(ids)`. 그다음 `check.Evaluate(snap, subset, reg, Options{Params})` →
  `waiver.Apply(results, known, excluded, …)` → `report.Build(snap, results, cb, severity)` → 렌더 → 평가된
  결과로 종료 코드. 두 파일의 로드 실패는 waiver 파일 실패처럼 `muster: <reason>`을 찍고 `exitError`(2)를
  돌려줌.
- **결과(추가, `check` 아래; `run`은 불변).**

  ```json
  "check": {
    "controls_version": "kisa-unix-2026+2026.10.02", "controls_digest": "sha256:…",
    "profile": {"name": "site-web-2026", "source": "file:site.yaml", "digest": "sha256:…",
                "extends": ["builtin:default", "file:site.yaml"],
                "selected": 68, "excluded": 49, "excluded_ids": ["muster.beyond.…", "…"]},
    "tuning": {"path": "tuning.yaml", "digest": "sha256:…"},
    "params": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": ["tcp/22", "tcp/443"]}},
    "param_sources": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": "profile"}},
    "waivers": {"…": "…"}
  }
  ```

  `source`는 `builtin` 또는 `file:<받은 그대로의 경로>`(waiver 선례); `extends`는 같은 표기로 체인을
  뿌리부터 나열; `excluded_ids`는 제외가 없으면 `[]`이지 생략되지 않음. `params`는 모양을 유지(평가된 모든
  컨트롤의 적용값); `param_sources`가 파라미터마다 `default`, `profile`, `tuning`을 댐. 각 행은 기존
  `severity` 옆에 `severity_source`(`importance` | `profile`)를 얻음. `--profile` 없이는 블록이 `{"name":
  "default", "source": "builtin", "extends": ["builtin:default"], …, "excluded": 0, "excluded_ids": []}`로
  읽히고, `--tuning` 없이는 `tuning` 키가 없음.
- **표.** 머리글 아래 한 줄, 경로는 파일에서 온 다른 머리글 문자열처럼 이스케이프:
  `profile default (117 controls)`, `profile default (117 controls; tuning tuning.yaml)` 또는
  `profile site-web-2026 (68 of 117, 49 excluded; tuning tuning.yaml)`.
- **순서와 종료 코드.** 행은 오늘처럼 범위, 심각도, id로 정렬되므로 프로파일의 심각도가 행을 옮김;
  `--fail-on`과 종료 코드는 심각도가 아니라 상태를 읽음 — 불변. 요약의 high/medium/low 버킷은 적용 중인
  심각도를 셈.
- **결정성.** `excluded_ids` 정렬; `param_sources`는 `params`와 같은 정렬 경로로 렌더; 다이제스트는 정규
  JSON; 심각도 맵은 정렬된 id 순으로 적용.

## 6. 테스트, CI, 문서

- **`internal/profile`**: `testdata/*.yaml` 위 표 테스트 — extends 체인(파일 넷, 다섯째 거부, 순환, 없는
  파일, 미지 이름, 별칭), include 뒤 exclude, 부모가 뺀 것을 자식이 다시 넣기, 점을 가로지르는 글롭, 잘못된
  패턴, 안 맞는 패턴, 아무것도 빼지 않는 exclude, 선언된 타입별 params 타입 검증, severity 순서, 내장, 내장
  이름을 쓴 파일, 빈 선택, 다이제스트 결정성(`include` 순서 바꿈·프로파일 이름 바꿈·파일 옮김 → 같은
  다이제스트; 값 바꿈 → 다른 값); `warn`을 통한 경고. 시드를 가진 `FuzzParseProfile`과 `FuzzParseTuning`; 새
  패키지마다 자기 fuzz 타깃을 고정하는 한 줄 테스트(`go test -list ^Fuzz`), `fuzz.yml`의 패키지 목록에
  `./internal/profile`과 `./internal/tuning` 추가 — 그 파일을 고치는 PR이 샤드를 돌림(G-27); `make fuzz
  TARGET=… FUZZPKG=./internal/profile/`을 CONTRIBUTING에 적음.
- **`internal/controls`**: `Subset`이 순서·버전·다이제스트·`ByID`를 유지; `CheckParamValue`가 lint의 타입
  검사를 공유(lint의 기본값 검사가 이것을 부름).
- **`internal/waiver`**: 제외된 id → `not_applied`와 경고, 결코 `unknown`도 조용한 누락도 아님; 집계가
  맞아떨어짐.
- **`internal/report`**: 심각도 맵을 가진 `Build` — 행, 출처, 정렬, 요약 버킷; JSON·표 골든을 `-update`로
  재생성하고 diff 검토: 새 필드뿐.
- **`cmd/muster` e2e**: `full-pass.json`과 `full-fail.json`에 `testdata/profiles/exclude-beyond.yaml` →
  117 중 68 평가, `excluded_ids` 49, 평가된 집합에 대해 종료 코드 불변; `fail-ufw-folded-http`의 FAIL을
  PASS로 뒤집는 튜닝 파일과 `param_sources` = `tuning`(exposure 파라미터 선례); 제외된 컨트롤의 waiver →
  `not_applied` 집계와 경고 문구; 그런 내장이 없는 `--profile site` → 내장 목록을 대는 오류; 오타가 든
  `controls lint --profile` → 패턴을 이름 대는 오류; `controls list --profile`. examples 테스트는
  `resolveSelection`으로 `default`를 해결 — 그 게이트의 유일한 변경; list-actions 테스트는 손대지 않음.
- **Examples.** 컨트롤 세트가 바뀌지 않아 컨트롤 다이제스트가 유지되고 examples 게이트는 바이트를 비교하는데,
  리포트에 `check.profile`이 생기므로 머지 전에 브랜치의 `examples.yml` 실행에서 examples를 갱신(3C-2b 선례,
  W-84).
- **CI.** 새 잡 없음: `test` 잡에 `controls lint --profile default` 추가; `fuzz.yml`에 패키지 둘 추가.
- **문서.** 메인 설계: §6.6을 실현된 대로 다시 쓰고, **D33**(프로파일은 묻는 질문의 목록이고 튜닝 파일은
  사이트의 값; 둘 다 출처와 함께 결과에 기록; 제외된 컨트롤은 평가하지 않음), §10.2의 3D를 3D-1/3D-2/3D-3으로
  나누고 이 사이클을 병합으로 표시. CLAUDE.md에 "## Profiles (stage 3D-1)". README 쌍: `--profile`,
  `--tuning`, 예시 프로파일 `docs/examples/profiles/exclude-beyond.yaml`과 §4의 튜닝 예시. CHANGELOG:
  Added(프로파일, 튜닝, 결과 필드), Controls 항목 없음(세트 불변, `controls/VERSION` 유지). 한국어 쌍은 같은
  커밋에.

## 7. 평가기와 스키마

- `check.Evaluate`와 `check.Result` 불변; `Options.Params`에 병합된 맵을 넣음. `report.Row.Severity`의
  의미 유지; `severity_source`는 새것. 사실·레지스트리·스냅샷 변경 없음 — `schema_version`, `run` 블록,
  컨트롤 다이제스트 유지.
- 결과 JSON은 추가적: 옛 모양의 독자가 새것도 파싱함. D16 상향 없음: 어느 컨트롤의 판정도 바뀌지 않음.

## 8. 보류

- `cis-<distro>-l1`과 그 색인(3D-1b); 프로파일이 쓸 수 없는 수집기 건너뛰기; 패키지 설치용 프로파일
  디렉터리(4단계); 프로파일 범위의 waiver; 컨트롤별 글롭이 너무 장황하면 심각도 클래스(`importance → level`
  재매핑); `automation`이나 `importance`로 `include`; 신뢰 파일의 심볼릭 링크 규칙(waiver에도 적용될 것).
