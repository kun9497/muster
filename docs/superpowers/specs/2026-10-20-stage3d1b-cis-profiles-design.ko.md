# 3D-1b단계 — 권고 번호 색인 위의 CIS Level 1 프로파일

영어 원본: `2026-10-20-stage3d1b-cis-profiles-design.md`. 메인 설계: `2026-09-02-muster-design.md`(§3 참조,
§6.2 스키마, §6.8 lint, §10.2 로드맵, §12 경계, D04, D33). 이 사이클이 딛는 앞 사이클:
`2026-10-07-stage3d1-profiles-design.md`(Y-1..Y-9; Y-1이 이 단계를 지목). 이 설계의 결정은 CB 목록입니다(한 글자
접두어는 모두 앞 단계와 겹침). 이 설계의 바탕이 된 범위 지도는 사이클의 무시되는 작업 공간
(`scope-{cac,muster,join,legal,critic}.md`)에 있고, 구속력 있는 결론은 여기에 다시 적습니다. 첫 리뷰
(`design-review-r1.md`, 35건), 둘째(`design-review-r2.md`, 15건, 수정 일곱 가지), 셋째(`design-review-r3.md`,
9건, 수정 다섯 가지)를 반영했습니다.

## 1. 범위와 의도

`check --profile`은 한 실행이 평가할 muster 컨트롤을 고릅니다(3D-1). 로드맵이 다음 프로파일을 지목합니다:
"CIS 권고 번호 색인 위의 `cis-<distro>-l1` 프로파일, 고른 모든 컨트롤이 `references.cis` 항목을 가짐". 이
사이클은 그중 셋 — Ubuntu 22.04, Ubuntu 24.04, RHEL 9 계열의 Level 1 – Server — 을 공개 자료만으로 만들고,
muster가 이미 싣고 있는 CIS 참조를 색인에 대조해 검사할 수 있게 합니다.

CIS 프로파일은 **muster 자신의 컨트롤을 고른 것**이며, 각 컨트롤은 muster 자신의 절(clause)로 판정합니다. 그
아래의 PASS는 muster 컨트롤에 대한 muster의 판정이지 CIS 평가가 아니며, muster는 어떤 CIS Benchmark에 대해서도
준수나 일치의 정도를 주장하지 않습니다. 운영자에게 주는 가치는, CIS Level 1이 묻는 것 중 muster가 답할 수 있는
질문에 답하는 실행이고, 모든 결과가 운영자가 가진 Benchmark에서 찾아볼 수 있는 권고 번호로 이어진다는 점입니다.

- **CB-1 — 내장 프로파일 셋: `cis-ubuntu2204-l1`, `cis-ubuntu2404-l1`, `cis-rhel9-l1`.** 각각은 그 벤치마크의
  Level 1 – Server 권고를 싣는 컨트롤에서, 커밋된 검토 목록(CB-7)을 뺀 것을 고릅니다. `default` 옆의 내장이며,
  이름은 식별자일 뿐 제품명이 아닙니다. 면책 문장은 CB-13이 지목한 문서들이 싣고, 프로파일 줄·알 수 없는 프로파일
  메시지·`controls list`는 되풀이하지 않습니다. `cis-rhel9-l1`은 RHEL 9 계열의 것입니다(CB-3).
- **CB-2 — 번호는 고정된 ComplianceAsCode에서 오고, 원천의 다른 것은 아무것도 남기지 않는다.** 원천은
  ComplianceAsCode/content(BSD-3-Clause, CB-15; SCAP Security Guide와 Ubuntu USG 뒤의 프로젝트)의 릴리스
  `v0.1.82`(커밋 `3da954fbccfb4ca611da86c9be9205d83c38bfc7`)입니다: `controls/cis_ubuntu2204.yml`(CIS Benchmark
  v2.0.0), `controls/cis_ubuntu2404.yml`(v1.0.0), `products/rhel9/controls/cis_rhel9.yml`(v2.0.0),
  `controls/cis_almalinux9.yml`(v2.0.0). 이 파일들은 CIS 제목을 싣고 있습니다. 새 생성기 `tools/cisindex`는 각
  파일에서 정확히 헤더의 `version`과 각 항목의 `id`, `levels`, `rules`만 디코드합니다; `title`, `notes`, `status`,
  `related_rules`와 그 밖의 모든 필드는 디코더 밖으로 나가지 않습니다(이 문장은 NOTICE가 되풀이하는 그
  문장입니다, CB-15). 파일이 필드 이름이 암시하는 것과 다르므로, 남기는 필드의 두 가지 읽기를 여기서 고정합니다:
  - `id`가 권고 문법 `^[0-9]+(\.[0-9]+){1,4}$`에 맞지 않는 항목은 도우미이며, 무엇이든 세기 전에 버립니다(고정
    시점: `reload_dconf_db`와 `enable_authselect`, EL9 두 파일에만). 문법 위반이 크게 실패하는 것은 `map.yaml`에
    적힌 번호뿐입니다(§2).
  - `=`를 포함한 `rules:` 원소는 **변수 선택**(`var_password_pam_minlen=14`, `sshd_idle_timeout_value=5_minutes`)
    이지 규칙 id가 아닙니다: 도달 가능성, 커버리지(CB-6), 규칙 id 검증(CB-5)에서 빠지며, 프로파일 값이 오는
    유일한 곳입니다(CB-8). `rules:`에 규칙 id가 없는 항목 — 없음, 빈 목록, 선택만 — 은 `recs:`로만 도달할 수
    있고, 그런 항목만 그렇습니다(CB-5). 한 항목의 `rules:` 안에서 되풀이된 규칙 id는 집합으로 읽습니다.
  벤치마크 키, 표시 이름, `applies_to`는 muster 자신의 것으로 `sources.json`에 있으며(CB-3) 파일에서 읽지 않습니다
  (파일의 `title`은 표시 이름이 아닙니다). 내려받은 것은 `.cache/cisindex/`(git 무시)에 캐시합니다. CIS PDF는
  읽지도, 저장하지도, 필요로 하지도 않습니다.
- **CB-3 — 벤치마크와 그 키, STIG 색인의 모양으로.** 벤치마크 셋을 STIG 색인이 제품을 키 매기듯 키 매깁니다 —
  `product: ubuntu2204`(CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0), `ubuntu2404`(CIS Ubuntu Linux 24.04 LTS
  Benchmark v1.0.0), `rhel9`(CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0)와 `applies_to: [alma9, rocky9]`
  (STIG처럼 별칭만). RHEL 9 파일이 `rhel9`의 번호, 레벨, 규칙 id, 변수 선택의 유일한 원천입니다. AlmaLinux OS 9
  파일은 증명 하나에만 읽습니다: 그 권고 id와 문자 그대로의 레벨 집합이 RHEL 9의 것과 같지 않으면 생성기가
  실패하며(고정 시점에는 같음), `alma9`는 그 증명으로 인정됩니다. 그 `rules:`와 선택은 고정 시점에 32개 항목에서
  RHEL 9과 다릅니다; 그 차이는 생성기가 로그로 남길 뿐 치명적이지 않고 읽지도 않습니다: AlmaLinux 파일에만 있는
  규칙 id는 `map.yaml`에 알려지지 않은 것이고, AlmaLinux나 Rocky 호스트의 `cis-rhel9-l1`은 RHEL 9의 커버리지
  단어와 파라미터 값을 싣습니다 — 색인 파일의 `equal_to` 주석, 문서, coverage.md가 그렇게 말합니다. `rocky9`는
  추론이며, STIG 참조의 것처럼 ATTRIBUTION에 추론이라고 적습니다(CIS는 Rocky 9 Benchmark를 내지만 공개 원천이
  색인하지 않음). 버전은 고정된 파일 자신의 것입니다; cisecurity.org에는 더 새 버전(22.04 v3.0.0, 24.04 v2.0.0)이
  있고, 문서는 색인이 어느 것을 담는지 말합니다.
- **CB-4 — 색인은 muster가 매핑한 권고와 개수 하나만 담는다.** Benchmark의 순서 있는 전체 번호 체계는 그 구조입니다
  (메인 설계 §12는 "본문과 구조"의 복사를 금함). `docs/reference/cis/<product>-<version>.json`은 제품 키, 표시
  이름, 버전, 원천 고정값, `equal_to` 증명, `applies_to`, `counts.l1_server` — 문자 그대로의 `levels` 목록에
  `l1_server`가 있는 권고 항목의 수; 파일은 `l2_server`가 `l1_server`를 상속한다고 선언하며, 상속된 개수는 내지
  않음 — 그리고 매핑된 권고마다 한 행 `{rec, levels, controls, rules}`를 싣습니다. `levels`는 항목의 문자 그대로의
  목록입니다. 제목도, 상태 단어도, 매핑되지 않은 번호도, 다른 레벨의 개수도 없습니다(프로파일이 쓰지 않는 개수는
  내지 않음; Level 2 프로파일은 상속 규칙을 적고 자기 개수를 더할 것).
- **CB-5 — 매핑은 muster의 작업이고, 조인은 그 씨앗일 뿐이다.** `docs/reference/cis/map.yaml`은 muster 컨트롤마다
  그 컨트롤이 판정하는 것을 검사하는 ComplianceAsCode 규칙 id를 적습니다(규칙 id는 제품 간에 공유되므로 한 행이
  세 벤치마크 모두에 쓰임; 각 id는 `^[a-z0-9][a-z0-9_-]*$`에 맞음 — 패키지·서비스·모듈 id는 하이픈을 가짐,
  `kernel_module_usb-storage_disabled` — 그래서 `=`를 포함하는 선택은 결코 규칙 id로 적힐 수 없음). 그리고
  벤치마크마다 규칙 id가 도달할 수 없는 권고를 적습니다(`recs:`, 한 줄 이유와 함께). 범위 지도의 자동 조인(컨트롤
  → 그 STIG id → ComplianceAsCode STIG 파일이 나열한 규칙 → CIS 파일의 번호)이 씨앗입니다; STIG 참조가 있는 58개
  컨트롤 중 약 45개를 복원하고 참조가 없는 59개에는 아무것도 주지 못하며, 쌍의 약 4분의 3이 맞으므로, 모든 행은
  커밋 전에 컨트롤의 절이 판정하는 것에 대조해 검토합니다. 생성기는 모든 규칙 id를 세 원천 파일 규칙 id의 합집합에
  대조하고(AlmaLinux 파일 제외, CB-3), 모든 `recs:` 번호를 그 벤치마크 파일에 대조하며, 항목이 규칙 id를 하나라도
  가진 `recs:` 번호는 (그 id들을 밝히며) 거부합니다: 이 덮어쓰기는 규칙 id가 없는 항목을 위한 것이고 그 밖의 용도는
  없습니다. 색인 행의 `controls`는 그 규칙 id가 도달한 컨트롤과 `recs:`가 그 행을 지목한 컨트롤의 합집합이며, id
  순으로 정렬합니다.
- **CB-6 — 커버리지는 계산하며, 주장하지 않는다.** 색인 행마다 `rules: all | some | none`을 싣고, 고정된 파일만을
  기준으로 정의합니다: 매핑된 컨트롤 규칙 id의 합집합이 항목의 모든 규칙 id(선택 제외)를 담으면 `all`, 하나 이상을
  담으면 `some`, 규칙 id가 없는 항목이면 `none`. CB-5 덕분에 세 단어가 빠짐없이 정의됩니다: 규칙 id가 있는 항목은
  규칙 id로만 도달하고, `none` ⇔ `recs:`로 도달. `rules` 단어는 손으로 쓰지 않으며, 어떤 `recs:` 이유도 컨트롤이
  권고와 같다거나 권고를 덮는다고 주장하지 않고(그것은 Benchmark 본문에 대한 진술), muster의 어떤 출력도 "full"이라는
  단어나 백분율을 내지 않습니다; coverage.md는 `some`과 `none`을 표시합니다.
- **CB-7 — 소속: 프로파일 벤치마크의 `l1_server` 번호에서 검토 목록을 뺀 것, 테스트로 맞춰 둔다.** 색인이 문자
  그대로의 레벨에 `l1_server`가 있는 권고(그 `rules` 단어가 무엇이든)에서 컨트롤을 지목하면, 그 컨트롤은
  `cis-<product>-l1`에 들어갑니다. `docs/reference/cis/review.yaml`은 컨트롤의 판정이 권고를 정직하게 대신할 수
  없는 곳에서 그 컨트롤을 프로파일에서 빼며, 각각 이유 하나를 답니다(CB-8). 내장 프로파일 파일은 정확한 컨트롤 id를
  나열하고, `TestCISProfilesMatchTheIndex`가 각 목록을 후보에서 검토 목록을 뺀 것과 같게 붙듭니다. `map.yaml`과
  `review.yaml`은 손으로 고치고 생성기는 네트워크가 필요하므로, 둘째 오프라인 테스트
  (`TestCISMapAndReviewMatchTheIndex`)가 커밋된 파일들을 서로 맞춰 둡니다: `map.yaml`의 모든 id가 어떤 색인 행의
  `controls`에 나오고 그 역도 성립, 모든 `recs:` 번호가 색인 행, 모든 `review.yaml`의 `{profile, id}`가 생성된
  프로파일이 빼는 그 벤치마크의 후보를 지목, `params` 항목은 프로파일이 고른 컨트롤을 지목. 규칙 id의 유효성과
  `rules` 단어는 고정된 파일이 필요하므로 관리자가 돌립니다(`cisindex -check`): `map.yaml`이나 `review.yaml`의
  변경은 재생성한 색인과 프로파일과 같은 커밋에 실립니다.
- **CB-8 — 프로파일은 선택이 일대일로 대응하는 곳에서만 파라미터를 정하고, 그 밖에는 컨트롤을 검토한다.**
  일대일이란 muster 파라미터가, 도달한 항목의 매핑된 규칙 id가 검사하는 사실의 절에만 쓰인다는 뜻입니다: 다른 절도
  움직이는 파라미터는 그곳에서 `param: none`이며, 아래의 검토 목록 규칙이 컨트롤을 정합니다
  (`password_policy.min_len`은 login.defs 길이와 pwquality 길이를 함께 정하는데 5.3.3.2.2의 규칙은 pwquality만
  검사하므로, muster가 파라미터를 나눌 때까지 `password_policy`는 모든 벤치마크에서 검토로 빠짐, 보류). `map.yaml`의
  `vars:` 행은 ComplianceAsCode 변수, muster 파라미터, 변환을 적습니다. 값은 벤치마크 파일에서 컨트롤의 규칙 id가
  도달한 `l1_server` 항목에서 읽습니다: 여러 항목의 같은 선택은 한 값; 한 벤치마크에서 다른 두 값은 생성기 실패;
  그런 항목 어디에서도 선택되지 않은 변수는 그 프로파일의 파라미터를 muster 기본값에 둡니다. 파일은 숫자만큼이나
  자주 옵션 단어를 선택하고(`var_accounts_tmout=15_min`, `sshd_idle_timeout_value=5_minutes`,
  `var_accounts_user_umask=027`) 단어 뒤의 숫자는 결코 가져오지 않는 ComplianceAsCode의 `.var` 파일에 있으므로,
  변환은 열거된 어휘입니다. 변환은 둘입니다: `as: int`(십진 숫자만; `027`은 거부)와 `as: {selected: value}` —
  `map.yaml`에 적는 muster 자신의 표로, 고정된 파일의 선택 문자열에서 임의의 YAML 값으로 가며, 파라미터의 선언된
  타입에 대해 타입 검사합니다(`controls.CheckParamValue`, 호출자가 넘김, §2). 표의 키는 자기 철자가 값을 말하는
  선택뿐입니다 — 십진 숫자, umask `0?[0-7]{3}`, 또는 `<n>_min`, `<n>_minutes`, `<n>_seconds` — 생성기는 그 밖의
  키를 거부합니다: `var_password_hashing_algorithm=cis_ubuntu2204`나 `var_pam_wheel_group_for_su=cis` 같은 단어는
  `.var` 파일이나 Benchmark가 말하는 뜻이고 muster는 둘 다 읽지 않으므로 `param: none`이며, 컨트롤이 그 양에 대한
  파라미터를 가지면 컨트롤은 그 벤치마크의 검토 목록에 오릅니다("선택의 값이 디코드한 원천에 없음").
  `session_timeout`(`15_min`, `5_minutes`)과 `umask_policy`가 첫 사례입니다: 고정 시점에 8진처럼 보이는 유일한
  선택은 umask `var_accounts_user_umask=027`이고, 그 행은 muster가 적어도 그만큼 엄격하다고 보는 umask의 목록
  (`"027": ["027", "077", "0027", "0077"]`)이지 027의 부분집합이 아닙니다 — 부분집합은 더 약한 값입니다. 고정
  시점에 파일 모드를 정하는 선택은 없으므로, 어떤 CIS 프로파일도 `allowed_modes`를 정하지 않습니다. 컨트롤의 규칙
  id가 도달한 `l1_server` 항목에서 선택된 모든 변수는 그 컨트롤의 `vars:` 행이 — 변환과 함께, 또는 `param: none`과
  컨트롤을 설명하는 이유와 함께 — 지목하므로, 생성기가 작업 목록을 만들고 아무것도 조용히 빠지지 않습니다. 변환은
  그 벤치마크에서 `review.yaml`을 통과한 컨트롤에서만 돕니다: 표 항목이 없는 선택이나 어떤 변환도 해석하지 못하는
  선택은, 컨트롤이 그곳의 검토 목록에 있지 않으면 생성기를 실패시키고, 있으면 검토 행이 그 실패를 누르며 색인 행은
  그대로 씁니다(CB-4의 행은 값을 싣지 않음). 그래서 생성기는 프로파일에 남는 컨트롤에만 `params`를 씁니다(제외된
  컨트롤의 값은 실행마다 `profile.Merge`가 경고하게 만듦). 프로파일의 `params`/`param_sources`는 값을 `profile`로
  보고합니다(3D-1). muster 기본값이 선택보다 약하고 그 값을 실을 파라미터가 없으면 컨트롤은 검토 목록에 오릅니다:
  권고가 말하는 것보다 약한 기준에 PASS를 주는 프로파일은 오해를 부릅니다. 고정 시점에 이 규칙은 약 열다섯 개의
  `vars:` 행을 낳고, 그 절반쯤이 `param: none`입니다.
- **CB-9 — 컨트롤은 `references.cis`를 색인의 렌더링으로 싣는다.** 모양은 `{benchmark, version, rec}` 그대로이고,
  `benchmark`는 정규 제품 키뿐입니다(`rhel9`, 결코 `alma9`가 아님: lint가 별칭을 거부하며 키를 밝힘). 항목은 키,
  그다음 `rec`을 구성 요소별 정수로 비교해 정렬합니다(`5.1.7`이 `5.1.20`보다 앞). YAML은 손으로 고친 채로 둡니다
  (어떤 도구도 컨트롤 파일을 다시 쓰지 않음); `TestEveryCISReferenceIsTheIndex`가 모든 컨트롤의 `references.cis`를
  그 컨트롤을 지목한 색인 행과 같게 붙들고, 다르면 그 컨트롤의 기대 `cis:` 블록을 출력합니다. 오늘의 손으로 쓴
  항목(13개 컨트롤, 모두 `ubuntu-22.04`로 표기)은 그 렌더링으로 바뀝니다; 검토에서 그중 일부가 틀렸음을 찾았습니다
  — `session_timeout`에는 TMOUT 권고가 빠져 있습니다. beyond 컨트롤도 CIS 참조를 실을 수 있습니다(CB-12).
- **CB-10 — lint가 참조와 프로파일을 검사한다.** `references_cis`가 얻는 것: rec 문법 `^[0-9]+(\.[0-9]+){1,4}$`;
  `--references`가 있으면 항목이 CIS 색인에 있음(정규 키, 색인된 버전, 번호); 중복 항목 없음. Y-1의 규칙 — 프로파일이
  고른 모든 컨트롤은 색인된 레벨에 `l1_server`가 있는, 그 프로파일 벤치마크의 `references.cis` 항목을 가짐 — 은
  `cmd/muster`에서 `resolveSelection` 뒤에 `profile.CISBenchmark(name)`(§4의 내보낸 표; `internal/controls`는
  `internal/profile`을 가져올 수 없음) 위로 돕니다. `--references`가 없으면 규칙은 그 벤치마크의 항목이 있는지만
  검사하고, `shapeOnlyNote`가 CIS 레벨을 검사하지 않았다고 말합니다; `--references` 도움말은 `stig`, `nist_800_53`
  옆에 `cis`를 적습니다. `make lint-controls`와 CI(`ci.yml`)는 `default`와 세 CIS 내장에 대해 `--references`와 함께
  `--profile`을 돌립니다.
- **CB-11 — `check`와 `fix --dry-run`은 프로파일의 벤치마크가 다루지 않는 호스트에서 경고한다.** 체인의 뿌리가
  정합니다(`Resolved.Chain[0]`이 `builtin:cis-…`), 그래서 CIS 내장을 `extends`하는 사이트 파일도 같은 식으로
  경고합니다. 대조는 `internal/profile`의 내장→벤치마크 표 옆의 표이며 `run.host.os_release` 위에서 합니다:
  `ubuntu2204` ⇔ `id` `ubuntu`이고 `version_id` `22.04`; `ubuntu2404` ⇔ `ubuntu`이고 `24.04`; `rhel9` ⇔ `id`가
  `rhel`, `rocky`, `almalinux` 중 하나이고 `version_id`의 첫 점 구분 요소가 `9`(CentOS Stream은 이름에 없으므로
  경고). 스냅샷이 맞지 않거나 `id`나 `version_id`가 비어 있으면(수집기는 읽을 수 없는 os-release에 빈 문자열을 씀),
  명령은 `warnTo`로 한 줄을 씁니다: `muster: warning: profile cis-rhel9-l1 is built for rhel9, alma9, rocky9; the
  snapshot is ubuntu 24.04` 또는 `…; the snapshot's os release is unknown`. 결과 바이트와 종료 코드는 바뀌지
  않습니다; 프로파일은 요청된 곳에서 여전히 평가합니다.
- **CB-12 — beyond 컨트롤도 CIS 참조를 실을 수 있다(D35).** muster가 판정할 수 있는 CIS Level 1의 요구 대부분 —
  마운트 옵션, 커널 파라미터, 모듈 블랙리스트, auditd, AIDE, 부트로더 — 은 49개 `beyond` 컨트롤에 있습니다. 메인
  설계 §12는 이미 "매핑이 독립적으로 도출된 것이 아니라면"이라는 조건으로 CIS 번호를 허용합니다; 여기의 매핑은
  muster 자신의 것(CB-5: muster의 절에 대조해 판정한 BSD 라이선스 규칙 id)이므로, CONTRIBUTING의 "beyond 컨트롤은 CIS
  권고 번호를 싣지 않는다"를 그 규칙으로 고쳐 씁니다. `category: beyond`는 여전히 "KISA 항목 없음"을 뜻하며 CIS에
  대해서는 아무것도 말하지 않습니다.
- **CB-13 — 어디에서도 준수를 주장하지 않으며, 면책은 한 문장 한 표현으로.** 어떤 출력, 문서, 테스트도 "CIS
  compliant", "CIS score", 백분율, "passes CIS Level 1"을 말하지 않습니다. 프로파일 줄은
  `profile cis-ubuntu2204-l1 (<n> of <total>, …)` 그대로입니다. 면책은 문서들이 베끼도록 여기 적는 한 문장입니다:
  *The `cis-<distro>-l1` profiles select muster's own controls that carry a CIS Benchmark recommendation number at
  Level 1 – Server; their results are muster's verdicts on muster's controls, not a CIS assessment, and muster is an
  independent publication not authorized, sponsored or otherwise approved by the Center for Internet Security.* 이
  문장은 README.md, NOTICE, ATTRIBUTION.md에 그 표현 그대로 서고(메인 설계 §12는 셋이 경계를 같은 말로 밝히라고
  함), README.ko.md에는 그 한국어 번역이, 내장을 나열하는 `check` 사용법 텍스트에도 섭니다; README 조각을 이미 붙드는
  `tools/coverage -check`가 영어 사본 셋을 붙듭니다. "Center for Internet Security®"와 "CIS Benchmarks®"는 처음
  두드러지게 나오는 곳에서 정확한 형태로 표기합니다.
- **CB-14 — 판정은 바뀌지 않는다.** `checks`, 사실, 파라미터 기본값은 바뀌지 않으며, `default`는 고르던 것을
  고릅니다. `controls/VERSION`은 바뀝니다(참조 수정이 세트의 다이제스트를 바꿈). `guide_edition`은 어떤 프로파일이
  적용되든 `kisa-unix-2026`입니다(선택이 아니라 컨트롤 세트가 딛는 가이드를 가리킴).
- **CB-15 — ComplianceAsCode는 그 라이선스 아래 보수적으로 재배포한다.** 색인, `map.yaml`의 규칙 id, 생성된
  프로파일은 고정된 파일 데이터의 수정된 재배포로 취급하며(저장소가 KISA에 대해 이미 취하는 읽기, ATTRIBUTION),
  프로파일은 바이너리에 포함됩니다. NOTICE에 ComplianceAsCode 절이 생기고, BSD-3-Clause 저작권 줄
  (`Copyright (c) 2012-2017, Red Hat, Inc.`), 세 조건과 보증 부인을 원문 그대로, 저장소·태그·커밋, 그리고 무엇을
  디코드했고 무엇을 하지 않았는지에 대한 CB-2의 문장을 싣습니다; ATTRIBUTION의 CIS 절은 그곳을 가리킵니다. muster를
  SCAP Security Guide가 보증했거나 그 위에 지었다고 내세우는 것은 없습니다: "via ComplianceAsCode <tag>"는 출처
  표시이지 주장이 아닙니다.
- **CB-16 — CIS 색인은 STIG 색인 옆에, 자기 이름공간으로 적재한다.** `controls.LoadReferenceIndex`는
  `cis/*.json`을 globbing해 자기 제품·별칭·버전 맵에 넣고(M-4의 계열별 유일성: `ubuntu2204`는 STIG 제품이면서 CIS
  제품, `rhel9`의 CIS 별칭은 그 자신의 것), `internal/cisindex`의 색인 타입 위에서 `DisallowUnknownFields`로
  디코드하며(`title`이 있으면 적재 실패), `HasSTIG` 옆에 `HasCIS`와, Y-1·별칭 거부·테스트가 쓰는 접근자 둘
  `CISLevels(product, version, rec) ([]string, bool)`과 `CISRows(product)`(행과 그 `controls`)를 얻습니다.
  `cis/*.json`이 없는 참조 디렉터리는 오류가 아니므로(`HasCIS` false; `--references` 아래에서 모든 `cis` 항목이
  색인되지 않은 것) 기존 색인 픽스처는 그대로 돌고, `internal/controls/testdata/refs/`에 lint 테스트용
  `cis/mini-1.0.0.json`이 생깁니다.

## 2. 색인

**생성기** `tools/cisindex`(`go run ./tools/cisindex [-check]`; `make cisindex`, `make cisindex-check`).
`tools/refindex`처럼 관리자가 돌립니다: 네트워크로 가져오고, 캐시는 git 무시이며, CI는 결코 돌리지 않습니다(CB-7의
오프라인 테스트가 CI의 관문). `tools/cisindex`는 얇은 `main`이고, 원천 디코더, `map.yaml`과 `review.yaml` 디코더,
색인 JSON 타입, 후보 계산, `vars:` 변환은 `internal/cisindex`에 있으며, 생성기·두 `cmd/muster` 테스트·
`internal/controls`가 이를 가져오므로 어떤 테스트도 구조체를 중복하지 않습니다. `internal/cisindex`는 muster의
어떤 패키지도, `os`, `os/exec`, `net`, `syscall`도 가져오지 않으며(`TestCISIndexImportsNoHostPackages`),
`internal/controls`는 그 색인 타입만 가져옵니다. 컨트롤 세트가 필요한 것은 넘겨받습니다: 변환은
`ParamType func(control, param string) (string, bool)`과 `Check func(typ string, v any) error`를 받고,
`tools/cisindex`가 적재한 세트와 `controls.CheckParamValue`로 채우며, 후보 검사와 검토 검사는 세트의 id를 받습니다.
가져오기, SHA-256 고정값 검사, 캐시, 모든 쓰기는 `main`에 남습니다.

- `tools/cisindex/sources.json`: 벤치마크마다 `{product, benchmark, version, applies_to, repo, tag, commit, path,
  sha256}`, 그리고 AlmaLinux 파일을 `equal_to: rhel9` 항목으로. SHA-256이 고정값과 다른 내려받기는 거부하며, 캐시는
  `.cache/cisindex/<sha256>`(git 무시)입니다.
- 디코더(`internal/cisindex`)는 정확히 남기는 필드(CB-2)만 가진 타입 있는 구조체이고, YAML 디코드가 나머지를
  버립니다. `[]byte`를 받으므로 시드가 있는 `FuzzDecodeControls`를 가지며, 테스트는 합성 YAML만 먹입니다(실제
  파일은 제목을 싣고 있어 트리에 들어오지 않음) — 도우미 둘 사례와 `rules:` 안의 선택을 포함해서.
- 고정된 파일 말고의 입력: `docs/reference/cis/map.yaml`과 `docs/reference/cis/review.yaml`(§3).
- 출력: 벤치마크마다 `docs/reference/cis/<product>-<version>.json` 하나, 정렬되고 결정적이며
  (`json.MarshalIndent` + 개행), 그리고 색인·검토 목록·`vars:` 행에서 생성한 내장 프로파일 파일 셋
  (`internal/profile/builtin/cis-*.yaml`), 그래서 드리프트 테스트(CB-7)는 생성된 산출물을 검사합니다.
- `-check`는 캐시(또는 네트워크)에서 다시 렌더링해 모든 출력을 바이트 비교하며, 다르면 exit 1.
- 실패는 크게 냅니다: 세 파일의 합집합에 없거나 CB-5 문법을 벗어난 `map.yaml` 규칙 id; 고정된 파일에 없거나 문법을
  벗어나거나 항목이 규칙 id를 가진 `recs:` 번호; 후보가 아닌 `review.yaml` id; RHEL 9과 다른 AlmaLinux 파일의 id나
  문자 그대로의 레벨 집합; 도달한 `l1_server` 항목에서 선택됐지만 컨트롤의 어떤 `vars:` 행도 지목하지 않는 변수;
  파라미터 타입이 거부하는 표 값; 그리고 그 벤치마크에서 검토로 빠지지 않은 컨트롤의 경우, 어떤 변환도 해석하지
  못하는 선택, 표 항목이 없는 선택, 한 변수의 두 값.

**색인 파일**(`docs/reference/cis/ubuntu2204-2.0.0.json`, 모양):

```json
{
  "product": "ubuntu2204",
  "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
  "version": "2.0.0",
  "applies_to": [],
  "source": {"repo": "ComplianceAsCode/content", "tag": "v0.1.82", "commit": "3da954f…", "path": "controls/cis_ubuntu2204.yml", "sha256": "…"},
  "counts": {"l1_server": 0},
  "recs": [{"rec": "5.3.3.1.1", "levels": ["l1_server", "l1_workstation"], "controls": ["muster.account.lockout_threshold"], "rules": "all"}]
}
```

`rhel9` 파일은 `"applies_to": ["alma9", "rocky9"]`와 `"equal_to": {"path": "controls/cis_almalinux9.yml",
"sha256": "…", "compared": "ids and levels"}`를 더합니다.

**로더.** CB-16.

## 3. 매핑과 검토 목록

`docs/reference/cis/map.yaml`(엄격한 YAML; 컨트롤 id 순 정렬):

```yaml
- id: muster.account.lockout_threshold
  rules: [accounts_passwords_pam_faillock_enabled, accounts_passwords_pam_faillock_deny]
  vars:
    - { var: var_accounts_passwords_pam_faillock_deny, param: max_attempts, as: int }
- id: muster.log.time_sync
  rules: [service_chronyd_enabled]
  vars:
    - { var: var_timesync_service, param: none, reason: "the control judges that a time-sync service is enabled, not which one" }
  recs:
    ubuntu2204: [{ rec: "2.3.2.2", reason: "the control judges that a time-sync service is enabled" }]
```

고정 시점에 Ubuntu 22.04의 5.3.3.1.1은 `var_accounts_passwords_pam_faillock_deny=4`와
`accounts_passwords_pam_faillock_deny`를, 5.3.2.2는 `accounts_passwords_pam_faillock_enabled`를 나열합니다: 두 행
모두 `rules: all`로 렌더링되고, `cis-ubuntu2204-l1`은 `lockout_threshold.max_attempts`를 4로 정합니다(EL9 파일은
5를 선택). Ubuntu 22.04의 2.3.2.2는 규칙 id를 싣지 않으므로(그 `l1_server` 항목 중 열다섯이 그렇다) `recs:`로
도달하고 `rules: none`으로 렌더링됩니다. `service_chronyd_enabled`는 두 Ubuntu 파일의 2.3.1.1에도 도달하는데, 그
행은 `rules: some`으로 렌더링되고 `var_timesync_service`를 선택하므로 `param: none` 행이 있습니다; `rhel9`에서는
아무 데도 도달하지 않으며, 그 2.3.2는 `chronyd_specify_remote_server`를 나열합니다.

- `rules:`는 컨트롤의 절이 검사하는 ComplianceAsCode 규칙 id입니다. 컨트롤마다 그 사실과 절에 대조해 검토하며,
  조인의 씨앗 행은 출발점일 뿐 검토 없이 커밋하지 않습니다.
- `vars:`는 CB-8의 행입니다: `{var, param, as}`이고 `as`는 `int` 또는 `{selected: value}` 표, 아니면 컨트롤의
  어떤 파라미터도 일대일로 싣지 않는 선택된 변수에 대한 `{var, param: none, reason}`(CB-8).
- `recs:`(벤치마크마다)는 항목이 규칙 id를 나열하지 않는 번호를 이유와 함께 더합니다. 이유는 컨트롤을 설명하며 결코
  권고를 설명하지 않습니다(CONTRIBUTING이 그렇게 말함).

`docs/reference/cis/review.yaml`: 후보를 프로파일에서 빼는 `{profile, id, reason}` 행(CB-7, CB-8).

## 4. 프로파일

- 내장은 Go 리터럴에서 포함된 엄격한 YAML로 옮깁니다(`//go:embed`로 `internal/profile/builtin/*.yaml`;
  `internal/profile`은 여전히 `os`, `os/exec`, `net`, `syscall`을 가져오지 않음): `default.yaml`(오늘처럼
  `include: [muster.*]`, `kisa-unix-2026` 별칭과 함께)과 생성된 `cis-*.yaml` 셋, 각각 정확한 id의 `include` 목록과 그
  `params`. Go 표 하나가 각 CIS 내장을 그 벤치마크 키와 os-release 대조(CB-11)에 잇고, `cmd/muster`를 위해
  `profile.CISBenchmark(name)`으로 내보냅니다(사용자에게 보이는 `benchmark:` 키 없음; D33 불변). `Builtins()`는 이름
  넷과 별칭을 돌려주고, "알 수 없는 프로파일" 메시지가 그것을 나열합니다.
- 파일 프로파일은 다른 내장처럼 `extends: cis-ubuntu2204-l1`을 할 수 있고, 파일은 내장 이름을 다시 쓸 수 없습니다.
- `controls list --profile cis-…`는 오늘처럼 선택을 출력하며, 참조는 리포트와 fix 출력에 나오지 않습니다(그곳의
  CIS 열은 보류).

## 5. 커버리지와 문서

- **`docs/reference/coverage.md`**(`tools/coverage`): 두 표에 "CIS recs" 열(벤치마크별 번호, `some`과 `none` 표시)과
  벤치마크마다 한 줄 — "N controls map M of K Level 1 – Server recommendations (<display> v<version>, via
  ComplianceAsCode <tag>)", M은 `l1_server`가 있는 색인 행, K는 `counts.l1_server`. 백분율도 점수도 없습니다.
- **문서**(쌍이 있는 곳은 영어와 한국어를 같은 커밋에): 메인 설계 §3 `:50`(CIS 참조는 3D-1b부터 CB-3의 키로 존재;
  "STIG 참조는 식별자와 제목, CIS 참조는 식별자만"), `:66`, §6.2 예 `:238`(`benchmark: ubuntu2204`로 다시 표기),
  §6.6 `:352`와 D33 `:551`("색인을 기다린다" 문장), §12 `:509`와 `:510`(경계 문장과 beyond 규칙), §10.2(3D-1b
  병합), 결정 항목 **D35**(CB-4의 매핑된 것만 담는 색인, CB-9의 색인이 원천, CB-12의 beyond 규칙) — 쌍은 줄 정렬을
  유지; 3D-1 프로파일 설계의 Y-1과 보류 목록; CONTRIBUTING(beyond 규칙; 컨트롤을 매핑하는 법: 절에 대조해 검토한 규칙
  id, 컨트롤을 설명하는 이유를 단 `recs:`, 결코 제목이나 권고가 아님; 매핑 변경과 함께 재생성한 색인을 실음);
  README(상태, 프로파일, 면책, `:156-158`의 낡은 개수 — 117개 컨트롤, STIG 58, NIST 65 — 와 `:165-167`, `:241-243`의
  "3D-1b를 기다린다" 문장); CLAUDE.md(Profiles 메모: CIS 내장, 색인, 생성기, 테스트); NOTICE(CB-13의 문장; CB-15의
  절); ATTRIBUTION의 "CIS Benchmarks" 절 교체(발행자와 상표; 참조한 벤치마크, 포함하지 않고 링크; 라이선스와 조건;
  재현하는 것 — 매핑된 권고의 버전·번호·문자 그대로의 레벨과 `l1_server` 개수는 고정된 ComplianceAsCode 파일에서
  디코드(CB-2)하고, 제품 키·표시 이름·`applies_to`는 `sources.json`에 있는 muster 자신의 것; 재현하지 않는 것 — 제목,
  설명, 근거, 점검이나 조치 본문, 전체 목록이나 순서; Rocky 9 추론과 AlmaLinux 동일성 증명; CB-13의 문장; NOTICE의
  ComplianceAsCode 절을 가리키는 포인터); CHANGELOG; `check`와 `fix`의 사용법 텍스트(`fix.go:21`);
  `controls lint --references` 도움말과 `shapeOnlyNote`(`controls.go:25-28`, `:131`).
- **예제**: 세트의 다이제스트가 바뀌므로, 병합 전에 브랜치의 `examples.yml` 실행에서 예제를 새로 받습니다(예제는
  `default`로 돌므로 판정은 움직이지 않음).

## 6. 테스트와 CI

- `internal/cisindex`: 합성 YAML 위의 디코더(입력의 제목은 출력에 닿지 않음; 도우미 id 둘은 버려지고 세지 않음;
  `rules:` 안의 선택은 규칙 id가 아님; AlmaLinux 동일성 검사는 같은 id와 레벨에서 통과하고 규칙 차이는 무시),
  `FuzzDecodeControls`, `rules` 단어, `vars:` 읽기(한 값, 충돌, 선택 없음, 지목되지 않은 선택, `param: none`, 각
  변환과 그 거부, CB-8 문법을 벗어난 표 키, 대역 `Check`가 거부하는 표 값, 다른 절도 움직이는 파라미터, 검토로 빠진
  컨트롤의 해석되지 않은 선택), §2의 모든 실패, 그리고 `TestCISIndexImportsNoHostPackages`.
- `internal/controls`: CIS 로더(엄격, 자기 맵, 제품마다 버전 하나, 디렉터리 없음 허용, 파일 바이트 위의
  `FuzzLoadCISIndex`), `HasCIS`, lint 규칙(문법, 정규 키, 색인 존재, 중복), `TestEveryCISReferenceIsTheIndex`.
- `internal/profile`: 포함된 내장이 엄격하게 적재됨; `default`는 전처럼 해석됨; 각 CIS 내장이 출하 세트에 대해
  해석되고 모든 `params` 값을 그 컨트롤이 받아들임; 네 이름에 대한 `CISBenchmark`.
- `cmd/muster`: `TestCISProfilesMatchTheIndex`와 `TestCISMapAndReviewMatchTheIndex`(CB-7; 트리의
  `../../docs/reference/cis/`와 embed의 내장을 읽음), 각 CIS 내장에 대한 Y-1 규칙(`--references` 있음과 없음),
  `check`와 `fix --dry-run`의 CB-11 줄(확장하는 파일, 맞는 호스트, 맞지 않는 호스트, 빈 os-release; stdout과 종료
  코드 불변), 알 수 없는 프로파일 메시지의 내장 목록.
- `tools/coverage`: README.md, NOTICE, ATTRIBUTION.md에 걸친 CB-13 문장; "CIS recs" 열과 벤치마크별 줄.
- 각 테스트는 그 호출 지점보다 먼저, 호출자부터 씁니다(CLAUDE.md). 컨트롤 참조 수정은 뮤테이션 테스트를 생존자
  0으로 둡니다(참조는 변이되지 않고 픽스처는 바뀌지 않음).
- CI: `make lint-controls`(lint 실행 둘과 `default`·세 CIS 내장에 대한 `--profile`, 모두 `--references`와 함께;
  `Makefile`과 `ci.yml`이 그 줄을 얻음), 오늘처럼 `go test`, `coverage -check`; 패키지를 손으로 나열하는
  `fuzz.yml`은 타깃을 더하는 커밋에서 `internal/cisindex`와 `internal/controls`를 얻음; `cisindex -check`는 관리자
  실행으로 남습니다.

## 7. 보류

- 더 많은 벤치마크: Debian 12/13, Amazon Linux 2023, SLE, Fedora(ComplianceAsCode에 파일이 있음; 생성기는 새
  `sources.json` 행을 받음), 그리고 ComplianceAsCode가 내놓으면 더 새 CIS 버전.
- Level 2와 Workstation 프로파일(레벨 상속 규칙과 그 개수와 함께); CIS 자신의 Rocky 9 Benchmark(공개 색인 없음);
  AlmaLinux 자체 색인(그 파일의 규칙 목록이 RHEL 9과 다름).
- 사용자에게 보이는 프로파일 `benchmark:` 키나 참조 기반 선택자(D33 번복).
- 리포트나 fix 출력의 CIS 번호.
- 일대일 ComplianceAsCode 선택이 없거나 선택된 단어에 변환이 없는 파라미터(그 컨트롤은 검토 목록에 남음); 벤치마크가
  파일 모드를 선택할 때까지의 모드 변환; `password_policy.min_len`을 login.defs 길이와 pwquality 길이로 나누기.
