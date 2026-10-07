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
작업이며, 그 뒤 `fix --dry-run`(3D-2)이 "적용 중인 프로파일의 실패"라는 정의된 의미를 얻습니다.

- **Y-1 — 메커니즘만; CIS 프로파일은 색인을 기다린다.** 내장 프로파일은 `default`(모든 컨트롤,
  `kisa-unix-2026`은 별칭)이고, `cis-<distro>-l1`은 `docs/reference/cis/` 아래 CIS 권고 ↔ 컨트롤 색인(번호와
  버전만 — CIS 본문은 결코 복사하지 않음, ATTRIBUTION.md)이 생기는 다음 사이클입니다. 이 문서는 그 이름 규약과
  "그런 프로파일의 컨트롤은 `references.cis`를 먼저 인용한다"는 규칙만 정합니다.
- **Y-2 — 제외된 컨트롤은 평가하지 않고 싣지도 않는다.** 결과는 프로파일(이름, 출처, 다이제스트, 체인)과
  제외된 id를 기록합니다; 새 상태 없음, 렌더러의 행 계약·종료 코드 규칙·waiver 규칙 불변.
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
- **Y-8 — 로드는 엄격하게, 경계는 너그럽게.** 미지 키, 안 맞는 패턴, 미지 컨트롤·파라미터, 타입이 틀린 값,
  미지 심각도, 순환, 깊이 4 초과, 빈 선택은 파일을 거부합니다. 프로파일이 제외한 컨트롤을 대는 프로파일·튜닝
  파라미터는 경고라, 프로파일을 바꿔 끼워도 튜닝 파일이 살아남습니다.
- **Y-9 — 결과의 모든 변경은 추가다.** 기존 필드 옆에 새 필드; JSON·표 골든은 검토한 diff로 재생성; examples는
  브랜치의 실행에서 갱신합니다.

## 2. 아키텍처

```
controls.LoadDefault()  ──►  profile.Resolve(set, source)  ──►  Resolved{IDs, Params, Severity, Digest…}
                                       │                                   │
                                       │        tuning.Load(set, path) ──► params 병합(기본 < 프로파일 < 튜닝)
                                       ▼                                   ▼
                              set.Subset(IDs)  ──►  check.Evaluate(snap, subset, reg, Options{Params})
                                                                │
                                                                ▼
                                        report.Build(snap, results, cb, Severity)  ──►  JSON / 표 / 종료 코드
```

- **`internal/profile`(신규).** `Parse([]byte) (*File, error)` — 엄격한 YAML. `Resolve(set, Source)
  (*Resolved, error)` — `extends`를 따라가고 include/exclude를 적용하며 params·severity를 세트에 대해
  검증하고 다이제스트를 계산. `Builtins()` — 내장 `default`. `internal/controls`(세트, 파라미터 선언)에만
  의존.
- **`internal/tuning`(신규, 작음).** `Parse([]byte)`, `Load(set, path)` — 같은 검증의 `params:` 맵;
  컨트롤별 맵과 파일 다이제스트를 돌려줌.
- **`internal/controls`.** `Set.Subset(ids []string) *Set` — 세트 순서의 뷰이며 전체 세트의 `Version`과
  `Digest`를 그대로 가짐(컨트롤 다이제스트는 임베드된 YAML의 이름이지 선택의 이름이 아님).
  검증기를 위한 `Set.ParamType(id, name)`. `lint`에 프로파일 검사 추가.
- **`internal/check`.** 동작 불변; `Options.Params`가 병합된 맵. `Result` 불변(심각도는 오늘처럼 리포트의
  관심사: `report.Row.Severity`).
- **`internal/report`.** `Build`가 심각도 덮어쓰기를 받아 행마다 `severity_source`를 기록; `CheckBlock`에
  `Profile`, `Tuning`, `ParamSources`; 표는 프로파일 줄 하나를 찍음.
- **`cmd/muster`.** `check --profile`, `check --tuning`; `controls lint --profile`;
  `controls list --profile`.

## 3. 프로파일 파일

```yaml
profile: site-web-2026            # [a-z0-9][a-z0-9-]*, 필수
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

- **글롭.** 패턴은 `path.Match`로 컨트롤 id에 맞추며 `*`는 `.`을 가로지릅니다(Facts 글롭 규칙, W-49). 그래서
  `muster.beyond.*`는 beyond 컨트롤 전부, `muster.file.*`는 한 범주입니다. `?`와 `[…]`를 허용하고, 적재된
  세트의 어느 컨트롤에도 맞지 않는 패턴은 오류입니다(오타가 조용히 아무것도 안 고르는 일은 없음).
- **해결.** `extends` 체인을 뿌리부터 걷습니다(깊이 ≤ 4; 순환, 없는 파일, 미지 내장은 거부). 파일마다 이
  순서로: `선택 = 부모.선택 ∪ include 매치 − exclude 매치`; `params`는 (컨트롤, 파라미터) 단위로 병합하되
  자식이 이김; `severity` 항목은 부모 것 뒤에 덧붙임. `extends` 없는 파일은 빈 선택에서 시작. 내장 `default`는
  `{profile: default, include: ["muster.*"]}`; `kisa-unix-2026`은 같은 객체의 이름.
- **Params.** 값은 컨트롤이 선언한 `params.<name>.type`(`int`, `string`, `bool`, `list<int>`,
  `list<string>` — 기존 어휘)으로 디코딩; 틀린 타입, 미지 파라미터, 미지 컨트롤은 파일 거부. 해결된 선택이
  제외한 컨트롤의 파라미터는 stderr 경고(Y-8).
- **Severity.** `level` ∈ {high, medium, low}; 마지막으로 맞는 항목이 이김; 어느 컨트롤에도 안 맞는 글롭의
  항목은 파일 거부; 제외된 컨트롤에만 맞는 항목은 경고.
- **빈 선택**은 파일 거부("profile selects no control").
- **다이제스트.** 정규 JSON `{name, chain: [source…], ids: 정렬, params: 정렬, severity: [{controls,
  level}…]}`의 `sha256`. 같은 파일·같은 세트 → 같은 값; 같은 컨트롤·값·심각도 항목을 같은 순서로 고르는
  두 파일은 `include` 목록 순서가 달라도 같은 다이제스트.

## 4. 튜닝 파일

```yaml
params:
  muster.beyond.exposed_listeners_allowed:
    allowed_ports: [tcp/22, udp/68, udp/546, tcp/443]
  muster.account.password_min_length:
    min_length: 12
```

정확한 id, 같은 타입 검증, 프로파일 params 뒤에 적용. 프로파일이 제외한 컨트롤 → 경고. `include`,
`exclude`, `severity`, `extends` 없음: 튜닝 파일은 사이트의 숫자만 싣고 묻는 질문을 바꾸는 것은 싣지
않습니다. 다이제스트는 파일 바이트의 것.

## 5. 통합

- **플래그.** `check --profile <name|path>`(기본 `default`; 이름은 먼저 내장에서 찾고, 구분자를 포함하거나
  `.yaml`/`.yml`로 끝나면 경로로), `check --tuning <path>`. 두 파일 모두 waiver 파일처럼 `trustedFile`을
  거침(world-writable 아님, 심볼릭 링크 아님). `controls lint --profile <path>`는 임베드된 세트에 대해 파일을
  해결하고 `ok: profile <name> selects N of M controls, K excluded`를 찍으며 lint 종료 코드는 기존 것.
  `controls list --profile <path>`는 선택된 id만 나열.
- **흐름(`runCheck`).** 세트 적재 → 프로파일 해결 → 튜닝 로드 → params 병합 → `set.Subset(ids)` →
  `check.Evaluate(snap, subset, reg, Options{Params})` → waiver 적용(제외된 id를 대는 waiver는 `unknown`이
  아니라 이유 `excluded by profile`의 `not_applied`로 기록) → 심각도 맵으로 `report.Build` → 렌더 → 평가된
  결과로 종료 코드. 두 파일의 로드 실패는 waiver 파일 실패처럼 `muster: <reason>`을 찍고 `exitError`를
  돌려줌.
- **결과(추가).**

  ```json
  "run": {
    "profile": {"name": "site-web-2026", "source": "file:/etc/muster/site.yaml",
                "digest": "sha256:…", "extends": ["builtin:default"],
                "selected": 90, "excluded": 27, "excluded_ids": ["muster.beyond.…", "…"]},
    "tuning": {"path": "/etc/muster/tuning.yaml", "digest": "sha256:…"},
    "params": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": ["tcp/22", "tcp/443"]}},
    "param_sources": {"muster.beyond.exposed_listeners_allowed": {"allowed_ports": "profile"}}
  }
  ```

  `params`는 모양을 유지(평가된 모든 컨트롤의 적용값); `param_sources`가 파라미터마다 `default`, `profile`,
  `tuning`을 댐. 각 행은 기존 `severity` 옆에 `severity_source`(`importance` | `profile`)를 얻음.
  `--profile` 없이는 블록이 `{"name": "default", "source": "builtin", …, "excluded": 0}`으로 읽히고,
  `--tuning` 없이는 `tuning` 키가 없음.
- **표.** 머리글 아래 한 줄: `profile default (117 controls)` 또는
  `profile site-web-2026 (90 of 117, 27 excluded; tuning /etc/muster/tuning.yaml)`.
- **순서와 종료 코드.** 행은 오늘처럼 범위, 심각도, id로 정렬되므로 프로파일의 심각도가 행을 옮김;
  `--fail-on`과 종료 코드는 심각도가 아니라 상태를 읽음 — 불변. 요약의 high/medium/low 버킷은 적용 중인
  심각도를 셈.
- **결정성.** `excluded_ids` 정렬; `param_sources`는 `params`와 같은 정렬 경로로 렌더; 다이제스트는 정규
  JSON.

## 6. 테스트, CI, 문서

- **`internal/profile`**: `testdata/*.yaml` 위 표 테스트 — extends 체인(깊이 4, 순환, 없는 파일, 미지 내장),
  include 뒤 exclude, 점을 가로지르는 글롭, 안 맞는 패턴, 선언된 타입별 params 타입 검증, severity 순서, 내장과
  별칭, 빈 선택, 다이제스트 결정성(`include` 순서만 바뀜 → 같은 다이제스트; 값이 바뀜 → 다른 값);
  시드를 가진 `FuzzParseProfile`과 `FuzzParseTuning`(인벤토리 테스트와 나이틀리 fuzz가 집어 감 — `[]byte`를
  받는 모든 함수에 타깃).
- **`internal/controls`**: `Subset`이 순서·버전·다이제스트를 유지; `lint --profile` 오류.
- **`internal/report`**: 심각도 맵을 가진 `Build` — 행, 출처, 정렬, 요약 버킷; JSON·표 골든을 `-update`로
  재생성하고 diff 검토: 새 필드뿐.
- **`cmd/muster` e2e**: `full-pass.json`과 `full-fail.json`에 `testdata/profiles/exclude-beyond.yaml` →
  117 중 68 평가, `excluded_ids` 나열, 평가된 집합에 대해 종료 코드 불변; `fail-ufw-folded-http`의 FAIL을
  PASS로 뒤집는 튜닝 파일과 `param_sources` = `tuning`(exposure 파라미터 선례); 제외된 컨트롤의 waiver →
  `not_applied`; 오타가 든 `controls lint --profile` → 패턴을 이름 대는 오류; `controls list --profile`.
  list-actions와 examples 게이트는 손대지 않음.
- **Examples.** 컨트롤 세트가 바뀌지 않아 컨트롤 다이제스트가 유지되고 examples 게이트는 바이트를 비교하는데,
  리포트에 `run.profile`이 생기므로 머지 전에 브랜치의 `examples.yml` 실행에서 examples를 갱신(3C-2b 선례,
  W-84).
- **CI.** 새 잡 없음. `make lint-controls`가 내장 default에 대해서도 `controls lint --profile`을 돌림
  (`--profile builtin:default` 표기 또는 임베드 경로).
- **문서.** 메인 설계: §6.6을 실현된 대로 다시 쓰고, **D33**(프로파일은 묻는 질문의 목록이고 튜닝 파일은
  사이트의 값; 둘 다 출처와 함께 결과에 기록; 제외된 컨트롤은 평가하지 않음), §10.2의 3D를 3D-1/3D-2/3D-3으로
  나누고 이 사이클을 병합으로 표시. CLAUDE.md에 "## Profiles (stage 3D-1)". README 쌍: `--profile`,
  `--tuning`, 예시 프로파일 `docs/examples/profiles/exclude-beyond.yaml`. CHANGELOG: Added(프로파일, 튜닝,
  결과 필드), Controls 항목 없음(세트 불변, `controls/VERSION` 유지). 한국어 쌍은 같은 커밋에.

## 7. 평가기와 스키마

- `check.Evaluate`와 `check.Result` 불변; `Options.Params`에 병합된 맵을 넣음. `report.Row.Severity`의
  의미 유지; `severity_source`는 새것. 사실·레지스트리·스냅샷 변경 없음 — `schema_version`과 컨트롤
  다이제스트 유지.
- 결과 JSON은 추가적: 옛 모양의 독자가 새것도 파싱함. D16 상향 없음: 어느 컨트롤의 판정도 바뀌지 않음.

## 8. 보류

- `cis-<distro>-l1`과 그 색인(3D-1b); 프로파일이 쓸 수 없는 수집기 건너뛰기; 패키지 설치용 프로파일
  디렉터리(4단계); 프로파일 범위의 waiver; 컨트롤별 글롭이 너무 장황하면 심각도 클래스(`importance → level`
  재매핑); `automation`이나 `importance`로 `include`.
