# 3D-2단계 — `fix --dry-run`: 교정 계획과 검토용 스크립트

영어 원본: `2026-10-07-stage3d2-fix-dry-run-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`
(§4.1 명령, §6.2 스키마, §6.5 상태, §6.6 프로파일, §7 출력, §10.2 로드맵, D24, D33). 프로파일:
`2026-10-07-stage3d1-profiles-design.ko.md`. 리뷰 이력: fresh 리뷰 워크플로 두 번(261, 115 에이전트)을 이 개정판에
접어 넣었습니다. 접은 판정은 아래 X 목록과 §2–§7의 "만들어진 대로" 문장들입니다.

## 1. 범위와 의도

로드맵의 3D(메인 설계 §10.2)는 독립된 세 조각이고, 3D-1(프로파일과 튜닝)은 병합되었습니다. 이 사이클은
둘째인 `muster fix --dry-run`입니다. 메인 설계의 범위 표는 D24 이래 교정에 대해 "절대 적용하지 않는다.
검토용 교정 스크립트를 위험도와 롤백과 함께 생성할 수 있다"고 말하고, 로드맵은 조각을 이름 댑니다:
"`fix --dry-run` — 위험도 순서, 백업, 검증 명령, 롤백."

`fix --dry-run`은 `check` 리포트를 막 읽은 운영자의 한 가지 질문에 답합니다: **무엇을, 어떤 순서로
바꾸고, 어떻게 되돌리는가.** `check`와 같은 입력 — 스냅샷, 적용 중인 프로파일, 튜닝 파일, waiver 파일 —
을 같은 평가기로 평가해 실패만 남기고, 각 컨트롤의 `remediation` 블록과 조인합니다. 그 조인에서
**계획**(사람용 표, 기계용 JSON)을, 요청하면 **검토용 스크립트** — 운영자가 읽고 직접 실행하는 POSIX `sh`
파일 하나 — 를 렌더링합니다. muster 자신은 교정을 실행하지 않고, 호스트에 쓰지 않으며, 호스트의 값을
명령에 치환하지 않습니다.

- **X-1 — `fix`는 적용하지 않는다.** 유일한 모드는 `--dry-run`이고 필수입니다: 그것 없는 `muster fix`와
  인수 중 어디든 위치 단어(`apply` 같은 모드 단어)가 있는 `fix`는 종료 2와 `fix never applies a remediation
  (D24); run fix --dry-run`으로 거부하며 — 다른 어떤 플래그 오류보다 먼저 검사합니다(§6). 플래그를 필수로 두는 이유는 훗날 누가 "fix"를 읽어도 조용히 적용될 수 없게 하기 위함입니다.
  스크립트는 stdout의 파일이고 muster는 그것을 실행하지 않으며, `internal/remedy`는 `os/exec`를 결코
  임포트하지 않습니다.
- **X-2 — 적용 중인 프로파일의 실패, 평가기가 분류한 대로.** 계획의 항목은 waiver 파일이 적용된 뒤 상태가
  `FAIL`이나 `WARN`인 `check` 행 — 같은 `resolveSelection`, 같은 `newCheckBlock`, 같은 `waiver.Apply` —
  이되, 평가기 자신이 표시하는 두 예외가 있습니다: 절이 모두 성립했고 유일한 발견이 저하된 수집인
  `WARN`(메인 설계 §6.5 13행)은 호스트의 실패가 아니라 `not_planned`에 상태 `warn_degraded`로 실리고;
  컨트롤이 `absent_means: fail`로 도달한 `FAIL`은 스크립트가 손댈 것이 없어 텍스트 전용 항목입니다. 둘은
  평가기가 내보내는 reason 접두사(§4)로 가르고, `remedy`가 산문을 파싱하는 일은 없습니다. 제외된 컨트롤은
  결코 계획되지 않고, 면제된 컨트롤은 세기만 하며, `MANUAL`과 `ERROR` 행은 `not_planned`라 독자가 계획할
  수 없었던 것을 봅니다. "실패"의 둘째 정의는 어디에도 없습니다.
- **X-3 — 위험도가 먼저.** 계획은 교정 위험도(`none` < `restart_service` < `reboot_required` <
  `lockout_risk`) 순, 그다음 적용 중인 심각도(high, medium, low — 프로파일의 덮어쓰기 포함), 그다음 id 순입니다.
  스크립트는 계획의 순서를 블록 단위로 따릅니다.
- **X-4 — 컨트롤당 블록 하나, 독립, 백업 먼저, 실패 시 되돌릴 길.** 스크립트는 컨트롤의 교정을 각각 자기
  함수로 돌립니다: 선언된 백업을 먼저 복사하고 어느 사본이든 실패하면 거기서 멈춥니다; 그다음 컨트롤의
  `script`; 그다음 `validate` 명령. 0이 아닌 단계는 컨트롤의 선언된 `rollback`(있으면)을 돌리고 그다음 선언된
  백업을 모두 복원하며, 블록은 1을 돌려줍니다. 실패한 블록은 다음 블록을 막지 않습니다. 스크립트는 모든
  블록이 깨끗이 돌면 0, 어느 블록이든 실패하면 1(그 백업은 보존), 백업 디렉터리를 만들 수 없거나 root가
  아니면 2로 끝나며 — 그때는 아무것도 돌지 않았습니다.
- **X-5 — 선언하지 추론하지 않는다.** 무엇을 백업할지(`backup`), 어떻게 확인할지(`validate`), 어떻게
  되돌릴지(`rollback`)는 컨트롤의 `remediation` 블록의 필드이고 `controls lint`가 검사합니다. 생성기는
  스크립트 본문에서 경로를 유도하지 않고, 스냅샷 값이나 파라미터를 명령에 치환하지 않습니다. 컨트롤의
  파라미터가 판정을 완화만 하는 곳에서 스크립트는 가이드의 기본값을 적용합니다(파일 권한 스크립트 다섯은
  가이드의 모드를 정함); 컨트롤의 파라미터가 프로파일이나 튜닝 파일에서 와 적용 중이면 항목은 텍스트
  전용(`text_only_reason: params_tuned`)이라, 계획이 사이트가 의도적으로 완화한 것을 조이는 일이 없습니다. 명령이 파라미터
  값을 실어야 하는 교정은 이번 사이클에 `script`를 갖지 않습니다(§8).
- **X-6 — 되돌릴 길이 없으면 스크립트도 없다.** 린트는 `rollback`도 비어 있지 않은 `backup`도 없는
  `script`, `idempotent`가 아닌 컨트롤의 `script`, `script` 없는 `backup`이나 `validate`, 여러 줄
  `validate`, here-document가 든 본문, 스크립트가 맨 단어로 실을 수 없는 backup 경로를 거부합니다. 선언된
  경로를 만들어 낼 수 있는 스크립트는 그것을 지우는 `rollback`을 선언합니다: `restore`는 있었던 것만
  되돌립니다. 되돌리거나 재실행할 수 없는 교정은 스크립트가 아니라 텍스트입니다.
- **X-7 — 메커니즘과 열여섯, 템플릿에 맞게 재작성.** 이 사이클은 스키마 필드, 린트 규칙, 계획, 렌더러 셋,
  명령, 라운드트립 증명을 배포하고, 이미 `script`를 가진 컨트롤 열여섯의 본문을 템플릿의 규율(§3: `set -e`
  안전, 유닛마다 보호된 한 줄, shellcheck 통과, `backup`/`validate`/`rollback` 포함)에 맞게 다시 씁니다.
  나머지 컨트롤의 스크립트 작성은 각자 호스트 증명이 필요한 콘텐츠 작업이라 다음 사이클입니다(§8).
- **X-8 — `--max-risk`가 유일한 손잡이.** 운영자는 스크립트가 실행할 위험도의 상한을 정할 수 있습니다:
  상한 밖 항목은 표시된 채 계획에 남고 스크립트에는 주석 처리된 블록으로 들어갑니다. 그 밖에 계획을
  거르는 것은 없습니다 — waiver와 프로파일이 상류에서 이미 거릅니다.
- **X-9 — 같은 바이트, 세 형식.** 표·JSON·스크립트는 같은 입력에 각각 결정적입니다. 어떤 `map`도
  렌더러에 닿지 않고, 생성기는 시계를 읽지 않습니다(백업 디렉터리의 타임스탬프는 스크립트가 실행될 때
  안의 `date`가 만듭니다). 골든 파일이 셋을 고정하고, 예시 게이트는 두 예시 스냅샷의 셋을 check 리포트가
  이미 따르는 다이제스트 규칙 아래 비교합니다.
- **X-10 — `validate`는 단계를 증명하지 판정을 증명하지 않는다.** 블록의 `done`은 그 명령이 돌았고 그
  검사가 성립했다는 뜻이고, 컨트롤이 이제 통과하는지는 `check`가 말합니다. 스크립트의 꼬리말이 그렇게 말하고
  다음에 돌릴 두 명령을 댑니다. 라운드트립 잡(§7)은 지정 이미지에서 심어 둔 컨트롤의 스크립트가 그것을
  고친다는 것을 증명하고, 열여섯의 나머지 본문은 구문으로 증명되며(`sh -n`, 전체 스크립트 골든에 대한
  shellcheck) 호스트 증명은 3D-2b에서 받습니다(§8).

## 2. 아키텍처

```
snapshot.json + profile + tuning + waivers
   ──(cmd/muster fix: openFacts, resolveSelection, loadWaivers, newCheckBlock, report.Build — check 자신의 경로)──▶ *report.Report
Report + controls.Set + options ──remedy.Plan──▶ *remedy.Plan
Plan ──remedy.Table / remedy.JSON / remedy.Script──▶ stdout
```

- **`internal/remedy`(신규).** 계획 모델과 렌더러 셋: `Plan(rep *report.Report, set *controls.Set, opts
  Options) (*Plan, error)`(어휘 밖의 `MaxRisk`에만 오류), `Table(p *Plan, color bool) []byte`, `JSON(p *Plan)
  []byte`, `Script(p *Plan) []byte`. 모두 순수. 임포트: `internal/check`, `internal/controls`,
  `internal/facts`, `internal/report`와 표준 라이브러리; 테스트(`internal/profile`의 것처럼 `go list -f
  '{{.Imports}}'`)가 `os`, `os/exec`, `net`, `syscall`, `time`을 거부합니다. 패키지는 stderr·stdout에 쓰지
  않습니다.
- **`internal/report`(확장, 내보내기만).** fix 렌더러가 공유하는 조각을 동작 그대로 내보냅니다: `Escape`(제어
  문자를 글자로 적고 `MaxCell`에서 `…`로 자름), `EscapeNoCut`(자르기 없는 같은 switch — 계획의 본체인
  컨트롤 텍스트용), `MaxCell`, `Paint`, `StatusColor`, `ProfileLine(p ProfileBlock, t *TuningBlock) string`,
  `ReasonLine(row Row) string`, `Title(row Row) string`(`title_ko`, 없으면 `title_en`; 지금은 `WriteTable` 안에
  인라인), `HeaderLine(run facts.Run, musterVersion, controlsVersion, guideEdition string) string` — check 표의
  첫 줄을 `WriteTable`에서 끌어낸 것으로, 두 표가 함수 하나를 불러 줄이 바이트 동일하게 남고, fix 표는 둘 다를
  자기 `FixBlock`에서 채웁니다. `Row`, `Report`, `Build`는 그대로; `report`는 `remedy`를 임포트하지 않습니다.
- **`internal/check`(확장, 상수만).** 평가기가 이미 쓰는 reason 모양 셋을 내보낸 상수로: `ReasonDegradedPrefix
  = "collection was degraded: "`, `ReasonSideOnlyPrefix = "setting holds on one side only: "`,
  `ReasonAbsentFailPrefix = "absent counts as fail: "`; `eval.go`가 reason을 만드는 곳에서 그것을 쓰고,
  테스트가 저하 통과 `WARN`의 reason이 정확히 `ReasonDegradedPrefix + Degraded`임을 고정합니다. 상태·스키마·
  판정 변경 없음.
- **`internal/controls`(확장).** `Remediation`에 `Backup []string`(`yaml:"backup,omitempty"`)과 `Validate
  string`(`yaml:"validate,omitempty"`); `Lint`에 §3의 규칙; strict 로더는 변경 없음(미지 키는 이미 거부).
- **`cmd/muster`(확장).** `fix` 디스패치; `runFix`는 `fixFlags`를 파싱한 뒤 `runCheck`가 부르는 헬퍼를 같은
  순서로 정확히 부릅니다 — `openFacts`, 컨트롤 세트와 레지스트리 적재, `resolveSelection`, waiver 적재(`runCheck`에서 `loadWaivers(path
  string) (*waiver.File, error)`로 끌어올리고 `runCheck`도 같은 커밋에서 그것으로 바꿈), `newCheckBlock`(예시
  테스트도 쓰는 G-14 심), `report.Build` — 그리고 `*report.Report`를 `remedy.Plan`에 넘깁니다. 새 평가 함수
  없음, 심을 건너는 플래그 구조체 없음. euid 0에서 `fix`는 check가 자기 root 경고를 찍는 곳인 stderr에
  `muster: warning: fix does not need root`를 찍습니다.
- 구조상 순환 없음: `remedy → report → check`, `remedy → check`; `remedy`를 임포트하는 것은
  `cmd/muster`뿐.

## 3. remediation 블록과 린트

선언된 블록(`Remediation`의 필드, 모두 `remediation:` 아래; 여섯은 지금도 있고 `backup`과 `validate`가
새것):

```yaml
remediation:
  text_en: Set PermitRootLogin no in a file under /etc/ssh/sshd_config.d/, validate with sshd -t, …
  text_ko: /etc/ssh/sshd_config.d/ 아래 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤 …
  risk: lockout_risk               # none | restart_service | reboot_required | lockout_risk
  idempotent: true
  backup: [/etc/ssh/sshd_config.d/00-muster.conf, /etc/securetty]
  script: |
    …
  validate: if command -v sshd >/dev/null 2>&1; then sshd -T 2>/dev/null | grep -qx 'permitrootlogin no'; fi
  rollback: |
    …
```

**린트 규칙** — 각각 규칙이 `remediation`(제목 규칙은 `titles`)이고 메시지가 아래와 같은 문제(`Problem.String`이
`path: rule: message`를 찍으므로 메시지에는 접두사가 없음), 각각 `TestLintRules` 케이스 하나(다른 모든 린트
규칙처럼 `lintOne`을 통한 인라인 YAML)로 규칙 이름과 메시지 부분 문자열을 단언. "한 줄"은 끝 개행 하나를
잘라낸 뒤 줄바꿈이 없다는 뜻이고, 빈 `script`/`validate`/`rollback` 문자열은 없는 것으로 읽으며, "비어 있음"은
공백뿐이라는 뜻:

- `remediation`이 있으면 `text_en`과 `text_ko`가 필수이고, C0·C1 제어 문자나 DEL(개행과 캐리지 리턴 포함)이 없으며, 1000룬
  이하 — `text_%s is blank` / `text_%s carries a line break or control character` / `text_%s is longer than
  1000 runes`. 같은 제어 문자 금지 규칙이 규칙 `titles` 아래 `title_en`/`title_ko`에도 — `title_%s carries a
  line break or control character`(배포된 모든 컨트롤이 이미 따름; 고정).
- `risk`는 네 단어 중 하나(변경 없음).
- `script`는 `idempotent: true`를 요구 — `script requires idempotent: true`(비멱등 컨트롤 둘,
  `file/dev_no_stale_files`와 `file/ip_port_restriction`은 스크립트가 없음).
- `script`는 되돌릴 길을 요구: `rollback`이 비어 있지 않거나 `backup`이 비어 있지 않음 — `script without rollback or
  backup`.
- `backup`과 `validate`는 `script`를 요구 — `backup without script` / `validate without
  script`.
- 모든 `backup` 항목은 절대 경로이고 자기 `path.Clean`과 같으며(그래서 끝에 `/`가 없음)
  `^/[A-Za-z0-9._@:+/-]+$`에 맞으며(그래서 `sh`에서 맨 단어로 안전; 공백·따옴표·`$`·백틱·`;`·글롭 문자 없음)
  목록 안에서 유일 — `backup path %q is not absolute` / `backup path %q is not clean` / `backup path %q carries
  a character the script cannot carry` / `backup path %q is repeated`. 순서는 작성자의 것이고 생성기가
  지킵니다. 항목은 일반 파일이나 심볼릭 링크를 이름 대고 디렉터리는 아닙니다(`restore`는 디렉터리인 대상을
  거부함, §5); 아직 없을 수 있는 경로는 허용(`backup`은 건너뛰고 `restore`는 `rollback`에 맡김).
- `validate`는 한 줄 — `validate must be one line`. 여러 조건은 `&&`로 잇고, 부정 조건은 그 한
  AND 목록 안에 `! cmd`로 쓰며, 목록의 상태가 판정입니다.
- `script`, `validate`, `rollback`은 있으면 비어 있지 않고 — `%s is blank` — here-document(`<<`)가 없음 —
  `%s carries a here-document`(생성기가 본문을 들여쓰므로
  종결자가 0열에서 밀려남).
- 린트는 셸을 파싱하지 않습니다. 전체 스크립트 골든(§7)에 대한 CI의 `shellcheck`와 `sh -n`이 본문의
  게이트입니다.

**본문 규율**(CONTRIBUTING; CI가 전체 스크립트 골든으로 강제):

- 본문은 `set -e` 아래 서브셸에서 돕니다(§5). 정당하게 실패할 수 있는 모든 명령은 자기 줄에서 그렇게
  말하고(`cmd || true`), 끝의 `; true`로는 안 됩니다. 운영자가 봐야 할 오류를 숨기는 `2>/dev/null` 없음.
- 유닛을 다루는 본문은 유닛마다, 존재 확인을 하고 하므로 이 배포판이 싣지 않는 유닛은 건너뛰고 진짜
  실패는 드러납니다: `for u in telnet.socket telnet.service telnetd.service; do systemctl cat "$u" >/dev/null
  2>&1 || continue; systemctl disable --now "$u"; systemctl mask "$u"; done`. 서비스 컨트롤의 script·validate·
  rollback의 유닛 목록은 `internal/collect/collectors/services.go`에서 그 논리 서비스 행의 유닛 중
  `provesInstall`이 true인 것(서비스 자신인 유닛; `tftp_talk_disabled`는 `tftp`와 `talk` 행)입니다 —
  `inetd.service`/`xinetd.service`는 서비스의 호스트로서 조사되며 스크립트에 결코 들어가지 않습니다. 그것을
  고정하는 테스트는 `internal/collect/collectors`에 있고(표처럼 Linux 태그; 임베드된 컨트롤 세트를 읽음), 행의
  `provesInstall: true` 유닛이 모두 컨트롤의 script·validate·rollback에 있고 `provesInstall: false` 유닛은
  하나도 없음을 단언합니다. 슈퍼서버가 띄우는 서비스는 스크립트가 교정하지 않습니다; `text_en`이 그렇게 말하고 블록 뒤에도 `reachable` 리프가 컨트롤을
  `FAIL`로 둘 수 있습니다.
- 파일을 다루는 본문은 먼저 파일이 있는지 확인하고 없으면 블록을 실패시킵니다(첫 명령 `[ -f /etc/hosts ]`)
  — 없는 파일은 잘못된 모드와 다른 발견이고, 계획이 그런 행을 이미 텍스트 전용으로 만들었으므로(X-2) 이
  보호는 손으로 고친 계획만 지킵니다.
- 본문은 컨트롤 자신의 판정이 존재를 함의하는 명령만 부르거나, 호출을 보호합니다: `if command -v setfacl
  >/dev/null 2>&1; then setfacl -b /etc/passwd; fi`(`acl` 패키지는 모든 최소 이미지에 있지 않음).
- 스크립트는 `umask 077` 아래 돕니다: 남이 읽어야 하는 파일을 만드는 본문은 모드를 명시적으로 정하고
  (`chmod 644`) validate가 그것을 검사합니다.
- `validate`는 스크립트가 정한 것 중 `stat`이나 데몬 질의가 보여 줄 수 있는 것을 검사하고, 스크립트가 정하지
  않은 것은 검사하지 않습니다: 파일 컨트롤은 숫자 소유자, 그룹(스크립트가 정하는 곳에서), 모드를 `stat -c`로
  비교하고, 서비스 컨트롤은 종료 코드가 아니라 찍힌 활성화 상태를 읽으며(`systemctl is-enabled`는 `static`,
  `indirect`, `alias`에도 0으로 끝남), sshd 컨트롤은 `sshd -T`에 묻습니다. ACL 제거와 `/etc/securetty` 편집은
  validate가 다시 검사하지 않습니다: `check`가 증명합니다(X-10).
- 본문은 POSIX `sh`이고 기본 심각도에서 shellcheck를 통과합니다(`A && B || C`는 `if`로); `make shellcheck`가
  전체 스크립트 골든에 대해 로컬에서 같은 것을 돌립니다.
- 선언된 `rollback`은 스크립트가 만들었거나 한 것을 되돌립니다(드롭인 제거, 유닛 재활성화); 생성기의
  `restore`가 그 뒤에 선언된 백업을 되돌리므로 rollback이 파일을 복원할 필요는 없습니다.
- sshd 본문에는 동작하는 `sshd -t`가 필요합니다: 호스트 키가 있고, 소켓 활성화 호스트에서는 권한 분리
  디렉터리(`[ -d /run/sshd ] || mkdir -p /run/sshd`, `command -v sshd`로 보호)가 있어야 하며, 그래도
  `sshd -t`가 실패하는 곳에서는 블록이 안전하게 실패하고 롤백합니다. sshd는 키워드마다 처음 읽은 값을 지키고
  드롭인을 사전 순으로 포함하므로 드롭인은 `00-muster.conf`입니다; 그보다 앞에 정렬되는 드롭인이나
  `sshd_config`의 `Include` 앞에 있는 `PermitRootLogin` 줄은 여전히 이깁니다 — `text_en`이 그렇게 말하고, 그때
  validate가 실패하고 블록이 롤백합니다.

**열여섯(X-7), 이번 사이클에 재작성된 대로.** 표는 각 본문의 형태 — 명령, 그 순서, 보호, validate의 절 —
를 정합니다. 문자 그대로의 본문은 계획에 쓰이고, `all-scripted.sh`가 렌더링하며 그 골든이 고정합니다.

| 컨트롤 | backup | script(형태) | validate | rollback |
|---|---|---|---|---|
| `file/hosts_permissions` (risk `restart_service`, Z-27: at 0600 non-root processes cannot read /etc/hosts) | `/etc/hosts` | `[ -f /etc/hosts ]`; `chown root:root /etc/hosts`; `chmod 600 /etc/hosts` | `stat -c '%u %g %a' /etc/hosts \| grep -qx '0 0 600'` | restore_backup |
| `file/services_permissions` | `/etc/services` | 위와 같되 `644` | `… \| grep -qx '0 0 644'` | restore_backup |
| `file/hosts_lpd_permissions` | `/etc/hosts.lpd` | 위와 같되 `600` | `… \| grep -qx '0 0 600'` | restore_backup |
| `file/passwd_permissions` | `/etc/passwd` | `[ -f /etc/passwd ]`; `chown root:root`; `chmod 644`; 보호된 `setfacl -b` | `stat -c '%u %g %a' /etc/passwd \| grep -qx '0 0 644'` | restore_backup |
| `file/shadow_permissions` | `/etc/shadow` | `[ -f /etc/shadow ]`; `chown root`; `chmod 400`; 보호된 `setfacl -b`(그룹은 배포판의 것: Debian은 `shadow`, EL은 `root` — 판정하지도 정하지도 않음) | `stat -c '%u %a' /etc/shadow \| grep -qx '0 400'` | restore_backup |
| `service/*_disabled`(10) | 없음(유닛 상태는 파일이 아님) | 행의 `provesInstall` 유닛에 대한 유닛별 루프: `systemctl cat` 보호, `disable --now`, 최선 노력 `mask`(`|| true`: 유닛 파일이 `/etc/systemd/system`에 있으면 마스크할 수 없음) | 같은 유닛에 대한 AND 목록 하나: `for` 없이, 예: `! systemctl is-active --quiet telnet.socket && case "$(systemctl is-enabled telnet.socket 2>/dev/null)" in enabled\|enabled-runtime) false;; esac && …`(유닛마다 절 한 쌍) | 선언: 유닛에 대한 두 패스, 각각 `systemctl cat` 보호 — 모든 유닛을 `unmask`한 뒤 모든 유닛을 `enable --now`(systemd는 서비스가 아직 마스크된 소켓을 시작하지 않음); 스크립트가 이름 대는 모든 유닛을 다시 켬(변경 전 상태는 기록하지 않음, §8) |
| `account/root_remote_login` | `/etc/ssh/sshd_config.d/00-muster.conf`, `/etc/securetty` | `command -v sshd`로 보호: `/run/sshd` 보호, `printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/00-muster.conf`, 거기에 `chmod 644`, `sshd -t`, 그다음 활성인 `sshd.service`/`ssh.service`를 `systemctl reload`(Z-30: 실행 중인 데몬이 변경을 받아야 함); 보호된 `sed -i '/^[[:space:]]*pts\//d' /etc/securetty` | `if command -v sshd >/dev/null 2>&1; then sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null \| grep -qx 'permitrootlogin no'; fi` (persona root, as the judgment reads it, Z-30) | 선언: `rm -f /etc/ssh/sshd_config.d/00-muster.conf`, 보호된 `sshd -t`와 reload; `restore`가 `/etc/securetty`를 되돌림 |

`controls/VERSION`이 움직이고(열여섯이 바뀜) 세트 다이제스트도 움직입니다; 판정은 바뀌지 않으므로 어느
픽스처의 기대 상태도 바뀌지 않고 `TestEveryMutantIsKilled`도 영향 없음(필드가 모든 판정 밖). CHANGELOG가
Controls 아래 기록합니다.

## 4. 계획

`remedy.Plan`은 모든 렌더러가 읽는 모델입니다. 필드 순서가 JSON 순서입니다. `Plan`은 `map`을 갖지 않습니다
(`by_risk`와 `not_planned` 수는 구조체; 리플렉션 테스트가 고정).

```
Plan
  schema_version  int                  remedy.PlanSchemaVersion(= 1; 계획 자신의 것, 계획 모양이 바뀔 때만 올림)
  run             facts.Run            스냅샷의 run 블록, check의 것과 바이트 동일
  fix             FixBlock             muster_version, commit, controls_version, controls_digest, snapshot_digest,
                                       guide_edition, profile(ProfileBlock), tuning(*TuningBlock, --tuning 없으면
                                       생략), waivers(report.WaiversBlock), max_risk
  items           []Item               순서: risk 순위 ↑, 심각도 순위(high, medium, low), id
  not_planned     []NotPlanned         {id, status: error | manual | warn_degraded, reason} id 순
  summary         Summary              planned, above_max_risk, with_script, text_only, waived, clean,
                                       not_planned {error, manual, warn_degraded},
                                       by_risk {none, restart_service, reboot_required, lockout_risk}
Item
  id, title_en, title_ko
  status            fail | warn           소문자, 계획 자신의 어휘
  severity, severity_source             check가 찍는 그대로
  risk, idempotent, automation
  reason            report.ReasonLine(row): 코드 접두사가 있으면 그것, 그다음 reason
  text_en, text_ko
  script            bool                  컨트롤이 스크립트를 선언했고 항목이 그것을 쓸 수 있음(아래)
  text_only_reason  "" | no_script | absent | params_tuned
  rollback          none | declared | restore_backup | both      (none ⇔ script false)
  backup            []string              선언된 경로; script가 false면 []
  validate          bool
  planned           bool                  risk 순위 ≤ max_risk 순위
```

- **어느 행이 무엇이 되는가.** `FAIL`/`WARN` → 항목, 단 reason이 정확히 `check.ReasonDegradedPrefix +
  row.Degraded`인 `WARN`(저하 통과) → `not_planned`의 `warn_degraded`. `ERROR` → `not_planned/error`;
  `MANUAL` → `not_planned/manual`; `WAIVED` → `summary.waived`; `PASS`/`NOT_APPLICABLE` → `summary.clean`.
  리포트의 모든 행이 items, not_planned, waived, clean 중 정확히 하나에 들어가므로 `len(items) +
  len(not_planned) + waived + clean == selected`이고, 표의 독자가 더해 볼 수 있습니다.
- **어느 항목이 스크립트를 갖는가.** 컨트롤이 하나를 선언했고, 행의 reason이 `check.ReasonAbsentFailPrefix`로
  시작하지 않고(`text_only_reason: absent` — chmod할 것이 없음), `rep.Check.ParamSources`에서 컨트롤의 어느
  파라미터도 출처가 `default` 아닌 것이 없을 때(`text_only_reason: params_tuned` — 스크립트가 조일 값을
  사이트가 완화했음). 그 밖엔 `script: false`이고 이유가 왜인지 말합니다; 컨트롤에 스크립트가 없으면
  `no_script`.
- `rollback`: 컨트롤에 `rollback`이 있고 `backup`이 없으면 `declared`; `backup`이 있고 `rollback`이 없으면
  `restore_backup`; 둘 다 있으면 `both`(실패 경로가 rollback 다음 restore를 돌림); `script`가 false면
  `none`.
- `planned`는 `summary.planned`에 셉니다; 상한 밖 항목은 `above_max_risk`에 세고 `status`를 유지하며
  `by_risk`에 셉니다. `with_script`와 `text_only`는 계획된 항목을 나눕니다.
- 항목은 컨트롤 하나입니다. 실패 주체가 여럿인 `each` 컨트롤은 `reason`이 행의 것인 항목 하나이고, 주체별
  세부는 `check`의 몫입니다. 주체가 모두 면제된 컨트롤은 `WAIVED`.
- `not_planned[].reason`은 `Item.reason`처럼 `report.ReasonLine(row)`.
- 항목은 모든 항목에 걸쳐 계획 순서로 1..N 번호를 받고(N = `len(items)`), 상한 밖 항목도 번호를 유지합니다.
  `by_risk`는 모든 항목을 세므로 네 수의 합은 `len(items)` = `planned + above_max_risk`.
- 빈 목록은 `null`이 아니라 `[]`; `not_planned`는 비어도 있음.

## 5. 스크립트

`remedy.Script(p)`는 고정 템플릿을 렌더링합니다: 머리말, 계획 순서의 항목 블록, 꼬리말. 스냅샷이나
컨트롤에서 온 것은 명령에 들어가지 않습니다: run 데이터와 컨트롤 텍스트는 `#` 주석 줄에만 — 스냅샷 유래
값(host, collected_at, 다이제스트, 프로파일 이름, reason)은 `report.Escape`(제어 문자를 글자로, 개행은 두
글자 `\n`, `MaxCell`에서 자름)를, 컨트롤 유래 텍스트(id, 제목, `text_en`, `text_ko`)는
`report.EscapeNoCut`(자르지 않음: 텍스트가 항목의 본체; 린트가 이미 한 줄로 유지)을 거칩니다. 선언된 backup
경로는 맨 단어로 나오고, 린트의 문자 집합이 그것을 안전하게 합니다. 본문은 YAML 리터럴을 줄마다 네 칸
들여쓰고 끝 개행을 잘라낸 것입니다.

```sh
#!/bin/sh
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host <host>, collected <collected_at>; controls <controls_version> <controls_digest>
# profile <name> (<digest>); max-risk <level>
# planned <n> (script <a>, text only <b>); above max-risk <c>; not planned: error <d>, manual <e>, warn_degraded <f>
set -u
umask 077
[ "$(id -u)" -eq 0 ] || { printf 'muster-fix: run as root\n' >&2; exit 2; }
MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
case "$MUSTER_BACKUP" in
  /|//*|*/.|*/..|*/./*|*/../*) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
  /?*) ;;
  *) printf 'muster-fix: MUSTER_BACKUP must be a clean absolute path\n' >&2; exit 2;;
esac
mkdir -p "$MUSTER_BACKUP" || exit 2
[ -n "$(find "$MUSTER_BACKUP" -maxdepth 0 -type d -user 0 ! -perm /022 2>/dev/null)" ] || { printf 'muster-fix: MUSTER_BACKUP must be a root-owned directory that only root can write\n' >&2; exit 2; }
log() { printf 'muster-fix: %s\n' "$*"; }
backup() {
  for p in "$@"; do
    { [ -e "$p" ] || [ -L "$p" ]; } || continue
    if [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
    mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p" || return 1
  done
}
restore() {
  rc=0
  for p in "$@"; do
    { [ -e "$MUSTER_BACKUP$p" ] || [ -L "$MUSTER_BACKUP$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; rc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; rc=1; continue; }; fi
    cp -a "$MUSTER_BACKUP$p" "$p" || { log "restore: $p failed"; rc=1; }
  done
  return $rc
}
failed=0
```

- 존재는 내내 `-e || -L`이므로, 심볼릭 링크(끊겼든 상대 대상이든)는 링크로 백업되고 복원됩니다. `backup`은
  없는 선언 경로를 건너뛰고, 백업 디렉터리에 이미 있는 사본은 덮어쓰지 않으며, 첫 실패한 복사에서 1을
  돌려줍니다. `restore`는 사본이 있는 모든 경로를 되돌리고, 디렉터리인 대상(디렉터리를 가리키는 링크 포함)은
  거부하고, 심볼릭 링크가 된 대상은 복사 전에 지우며(링크를 통해 쓰지 않음, Z-25), 하나라도 되돌릴 수 없으면 1을 돌려줍니다. `MUSTER_BACKUP` 디렉터리를 다시 쓰면 첫 실행의 사본이
  남습니다: 나중 실행에서 실패한 블록은 파일을 첫 실행 전 상태로 되돌리고 그 사이의 편집은 버립니다 — 의도된
  것이며(첫 사본이 원본), 꼬리말이 어느 디렉터리를 썼는지 말합니다. `/`, `//…`, `.`이나 `..` 구성 요소가 있는
  경로는 거부합니다.

`remedy.Build`는 id가 린트의 id 문법에 맞지 않는 항목을 거부합니다(Z-26, 다중 방어); 헤더는 id를
`report.EscapeNoCut`으로 렌더링합니다. 스크립트가 있는 계획 항목(`<fn>`은 `fix_` + id의 모든 `.`을 `_`로; id 문법이 그 밖은 허용하지 않음):

```sh
# ---- 1/8 muster.file.hosts_permissions [risk none] [fail, high]
# why: clause does not hold: files.etc_hosts.mode in [0 128 256 384]
# do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
# ko:  chown root:root /etc/hosts; chmod 600 /etc/hosts
fix_muster_file_hosts_permissions() {
  backup /etc/hosts || { log "muster.file.hosts_permissions: backup failed, nothing changed"; return 1; }
  ( set -e
    [ -f /etc/hosts ]
    chown root:root /etc/hosts
    chmod 600 /etc/hosts
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_permissions: script failed (rc $rc), rolling back"
    restore /etc/hosts || log "muster.file.hosts_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  ( set -e
    stat -c '%u %g %a' /etc/hosts | grep -qx '0 0 600'
  ); rc=$?
  if [ "$rc" -ne 0 ]; then
    log "muster.file.hosts_permissions: validate failed, rolling back"
    restore /etc/hosts || log "muster.file.hosts_permissions: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"
    return 1
  fi
  log "muster.file.hosts_permissions: done"
}
fix_muster_file_hosts_permissions
[ "$?" -eq 0 ] || failed=$((failed+1))
```

- **서브셸도 호출도 조건이 아닌 이유.** `( set -e … ); rc=$?`는 본문을 평범한 명령으로 돌리므로 안에서
  `set -e`가 살아 있습니다. POSIX는 명령이 `||`/`&&`의 피연산자, `if`/`while`의 조건이거나 `!`로 부정될 때 그
  명령이 돌리는 모든 것에 대해 `-e`를 무시합니다 — 그 자리의 서브셸도, 마찬가지로 그 자리에서 불린 함수도
  그렇고, 함수는 안의 모든 서브셸을 함께 끌고 갑니다. 그래서 블록 함수는 자기 줄에서 평범한 명령으로 부르고
  그 상태는 다음 줄에서 읽으며(`[ "$?" -eq 0 ] || failed=…`), 어떤 호출 줄도 `||`, `&&`, `if`, `!`를 싣지
  않습니다. validate와 선언된 rollback 서브셸도 같은 서브셸 모양입니다.
- `backup` 줄은 컨트롤이 경로를 선언할 때만 나오고(그러면 블록은 실패한 복사에서 멈춤), validate 서브셸은
  선언될 때만 나옵니다. 실패 경로는: 선언된 `rollback` 본문을 자기 `( set -e … ); rc=$?` 서브셸에서(실패는
  `rollback failed (rc N)`으로 로그, 재시도 없음), 그다음 백업이 선언됐으면 `restore <경로들>` — `both`는
  둘을 그 순서로 돌립니다.
- `lockout_risk` 항목은 헤더 뒤에 주석 한 줄이 더 붙습니다: `# keep a second session open; a lockout here
  needs console access`.
- 스크립트 없는 계획 항목은 주석 블록만: 헤더, `why:`, `do:`, `ko:`, 그리고 `# text only: <phrase>` — phrase는
  `text_only_reason`에서 일대일로 대응(`no_script` → `no script declared`, `absent` → `the finding is an absent
  file`, `params_tuned` → `params tuned, see muster check --format json: check.param_sources`); 함수도 호출도
  없음.
- `--max-risk` 밖 항목은 헤더 줄을 접두사 없이 한 번, `-- above max-risk <level>, NOT RUN`으로 끝나게
  렌더링하고, 블록의 이어지는 모든 줄은 빈 줄 포함 `#` 다음 공백과 그 줄(줄이 비어 있지 않을 때), 비어
  있으면 `#`만; 이미 주석인 줄은 다시 접두사를 붙이지 않습니다. 상한 밖 텍스트 전용 항목은 헤더 접미사만
  바뀝니다.

꼬리말:

```sh
if [ "$failed" -eq 0 ]; then
  log "done; backups in $MUSTER_BACKUP"
else
  log "$failed block(s) failed; backups in $MUSTER_BACKUP"
fi
log "a block's done means its commands ran and its check held; run muster collect and muster check again for the verdict"
[ "$failed" -eq 0 ] || exit 1
```

빈 계획은 머리말, `# nothing to fix` 한 줄, 꼬리말을 렌더링하므로 여전히 0으로 끝나는 유효한 스크립트입니다.

테스트로 고정하는 안전 계약(§7): 어떤 블록 호출 줄도 `||`/`&&`/`if`/`!`의 피연산자가 아님; 출력의 모든 줄은 템플릿 텍스트, 선언된 본문의 줄, 또는 `#` 주석 중
하나 — 스냅샷이나 컨트롤에서 온 것은 그 밖 어디에도 없음; 두 번 렌더가 바이트 동일; 생성기는 시계를
부르지 않음; 모든 골든의 출력이 기본 심각도의 `sh -n`과 `shellcheck -s sh`를 통과; 독 계획(host·reason·
제목·텍스트에 ESC·개행·`#`)의 모든 유래 바이트가 주석 줄 안에 있음.

## 6. 통합

**명령.**

```
usage: muster fix --dry-run --facts <snapshot.json|-> [flags]

flags:
  --format table|json|script   output format (default table)
  --waivers <file>             waiver file, as check
  --profile <name|path>        the profile in force, as check (default: the built-in default)
  --tuning <file>              site parameter values, as check
  --max-risk none|restart_service|reboot_required|lockout_risk
                               the highest risk the script will run (default lockout_risk: everything)
  --color auto|always|never    colour (default auto); --no-color = never
```

- `--dry-run`은 다른 플래그와 같은 플래그이고 인수 중 어디에나 올 수 있습니다. 플래그 파싱 전에, `-`로
  시작하지 않고 플래그의 값도 아닌 인수(어디에 있든 `apply`나 `run` 같은 모드 단어)나 `--dry-run`의 부재는
  정확한 텍스트의 X-1 거부입니다. 그 밖의 미지 플래그는 모두 `unknown flag <x>`, 종료 2.
- `--profile`, `--tuning`, `--waivers`는 check와 정확히 같은 의미·거부·경고(`profile.Resolve`,
  `tuning.Load`, root에서의 신뢰 파일 규칙, `warnTo(stderr)`). 빈 `--profile`/`--tuning` 값은 check가
  거부하듯 거부(CLAUDE.md, Profiles).
- 네 단어 밖의 `--max-risk`는 단어들을 이름 대며 종료 2로 거부.
- `--fail-on`, `--allow-error`, `--quiet`, `--all` 없음: `fix`는 판정하지 않고 모든 항목을 보여 줍니다.

**흐름.** `runFix`, `runCheck`의 순서로: 플래그 파싱(X-1 검사가 먼저) → `openFacts`(스냅샷은 신뢰하지 않는
입력으로 check처럼 읽음; `facts.Load`가 거부하는 스냅샷은 종료 2) → 컨트롤 세트와 레지스트리 적재 →
`resolveSelection` → `loadWaivers` → root 경고 → `newCheckBlock` → `report.Build` → `remedy.Plan` →
`--format`의 렌더러 → stdout. 경고는 `muster: warning: ` 접두사의 stderr 줄입니다: fix의 root 경고, 그리고
`resolveSelection`, `profile.Merge`, `newCheckBlock`이 이미 내보내는 프로파일·튜닝·waiver 경고가 같은
`warnTo(stderr)`를 거칩니다.

**종료 코드.** `0`: 계획을 만들었음(항목이 있든 없든). `2`: 만들 수 없음 — 플래그 오류, X-1 거부,
`facts.Load`가 거부하는 스냅샷, 프로파일·튜닝·waiver 거부, 목록 밖의 `--max-risk` 단어, 또는 stdout 쓰기 실패(`muster: write: <err>`,
메인 설계 §7.4) — 부분 스크립트를 성공으로 보고하는 일은 없습니다. **`1`은 없음**:
`fix`는 호스트를 판정하지 않고 `check`가 합니다. 메인 설계의 종료 코드 계약(D11)은 `check`와 `collect`의
것이고 그대로입니다; 문서가 한 문장으로 `fix`는 발견이 있어도 0으로 끝난다고 말해 어떤 CI도 그것으로
발견을 세지 않게 합니다. `ERROR` 행은 `fix`의 종료 코드를 바꾸지 않고 `not_planned`입니다.

**표**(`remedy.Table`): 머리 네 줄, 빈 줄, 항목들, 그리고 — `not_planned`가 비어 있지 않을 때만 — 빈 줄과
`not planned:` 줄들.

```
muster <version> · controls <controls_version> · guide <guide_edition> · host <host> · collected <collected_at>
fix --dry-run · <report.ProfileLine, 두 형태 중 하나> · max-risk <level>
planned 7 (script 4, text only 3) · above max-risk 1 · waived 1 · clean 92 · not planned: error 1, manual 14, warn_degraded 1
by risk: none 6 · restart_service 1 · reboot_required 0 · lockout_risk 1

#  risk             id                              status  sev   script  rollback        title
1  none             muster.file.hosts_permissions   fail    high  yes     restore_backup  <title_ko>
   why: clause does not hold: files.etc_hosts.mode in [0 128 256 384]
   do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
2  none             muster.account.password_policy  fail    high  no      -               …
   why: …
   do:  … (text only: params_tuned)
…
6  lockout_risk     muster.account.root_remote_login  fail  high  yes     both            … (above max-risk)
   why: …
   do:  …

not planned:
  muster.beyond.audit_rules_loaded     error          [missing_fact] …
  muster.service.nfs_export_access     manual         …
  muster.account.lockout_threshold     warn_degraded  collection was degraded: …
```

- 1행은 `report.HeaderLine`, check의 것과 바이트 동일. 2행의 프로파일 부분은 `report.ProfileLine`. `title`
  칸은 `report.Title`(`title_ko`, 없으면 `title_en` — check의 표처럼)이고 `do:`는 `text_ko`, 없으면
  `text_en` — 표는 check처럼 한국어 우선; JSON은 두 언어를 다 싣고 스크립트의 주석도 둘을 싣습니다(`do:`
  영어, `ko:` 한국어). 텍스트 전용 항목의 `do:` 줄은 `(text only: <text_only_reason>)`로, enum 단어 그대로
  끝납니다; `script` 칸은 `yes`/`no`를, `rollback` 칸은 enum 단어를(`none`이면 `-`) 찍고, `#` 열은 항목의
  번호입니다(§4).
- 색이 켜지면 `risk` 칸(`lockout_risk` 빨강, `reboot_required` 자홍, `restart_service` 노랑, `none` 무색)과
  `status` 칸(check의 상태 색)을 칠합니다.
- 스냅샷 유래 문자열은 `report.Escape`(`MaxCell`에서 자름), 컨트롤 텍스트는 `report.EscapeNoCut`을 거칩니다.
  `not planned:` 행은 각각 한 줄: id, status, `report.Escape(reason)`(check의 표가 자르듯 `MaxCell`에서 자름);
  행들이 한 칸으로 합쳐지지 않습니다.
- 빈 계획은 머리 네 줄, 빈 줄, `nothing to fix`.

**JSON**(`remedy.JSON`): `{"schema_version": …, "run": …, "fix": …, "items": […], "not_planned": […],
"summary": …}` 그 순서로, 두 칸 들여쓰기, 끝 개행, `SetEscapeHTML(false)` — check의 JSON처럼.

## 7. 테스트, CI, 문서

**테스트.**

- `internal/remedy`: `TestPlanOrdersByRiskSeverityID`(프로파일의 심각도 덮어쓰기를 포함한 섞인 행 집합),
  `TestPlanClassifiesEveryRow`(모든 상태를 가진 리포트 — 평가기로 만든 저하 통과 `WARN`, 부재 실패 행,
  파라미터 튠된 컨트롤 포함 — 에서 items + not_planned + waived + clean == selected),
  `TestPlanMarksItemsAboveMaxRisk`, `TestPlanRollbackVocabulary`, `TestPlanEmpty`, `TestPlanHasNoMap`(`Plan`
  리플렉션), `TestScriptGolden`(`-update`; 골든: `full.sh`, `empty.sh`, `capped.sh`, `poison.sh`,
  `all-scripted.sh` — 임베드 세트의 모든 스크립트 컨트롤이 실패한 계획 항목인 합성 계획이라 모든 본문이
  렌더링됨), `TestScriptBlocksAreIndependent`(스크립트 있는 계획 항목마다 함수 하나·맨 호출 줄 하나, 어떤 호출 줄도
  `||`, `&&`, `if`, `!`를 싣지 않음; 상한 밖 블록의 모든 줄이 주석),
  `TestScriptBodyFailureReachesTheFailurePath`(Linux: 첫 본문 명령이 `false`인 렌더링된 블록이 1을 돌려주고,
  이어지는 본문 명령은 돌지 않으며, rollback과 restore는 돎), `TestScriptFailurePathRollbackThenRestore`(`both` 블록은 rollback 서브셸이 `restore` 줄
  앞), `TestScriptEveryLineIsTemplateBodyOrComment`(안전 계약, 컨트롤 텍스트도 독인 계획에 대해),
  `TestScriptIsDeterministic`, `TestTableGolden`, `TestJSONGolden`(`-update`), `TestTablePoisoned`,
  `TestJSONEmptyListsAreArrays`, `TestRemedyImports`.
- `internal/report`: 내보낸 헬퍼는 골든을 유지(출력 변화 없음); `TestHeaderLineIsCheckLineOne`.
- `internal/check`: `TestWarnReasonShapes`가 세 접두사를 평가기 출력에 대해 고정.
- `internal/controls`: §3 규칙마다 `TestLintRules` 케이스 하나; 배포 세트는 린트 통과.
- `cmd/muster` e2e, `full-fail.json`으로(그 `FAIL` 행에 `root_remote_login`과 서비스 컨트롤 아홉이 있어
  lockout과 서비스 모양을 덮음; 파일 권한 실패는 `t.TempDir()` 아래 픽스처 사본에 더해 파일 모양을 덮음):
  세 형식; `--dry-run` 없는 `fix` → 2와 X-1 텍스트; `fix apply --dry-run`과 `fix --dry-run apply` → 2와 X-1
  텍스트; `fix --facts f.json --dry-run` → 0; 미지 플래그 → 2; 실패하는 stdout writer → 2; `--max-risk
  restart_service`가 lockout 항목을 표시; 실패 컨트롤을 제외하는 `--profile`이 계획에서 뺌; `--waivers`가
  하나를 `waived`로; `--format script`가 `sh -n` 통과(Linux만, 그 밖에선 스킵); `TestFixAgreesWithCheck`:
  `check --format json`의 `FAIL`/`WARN` 행 id가 계획의 항목 더하기 `warn_degraded` 행과 같고 그 밖엔 없음.
  `TestServiceScriptsNameTheCollectorsUnits`는 `internal/collect/collectors`에 있음(§3).
- 예시: 두 스냅샷의 `examples/<snapshot>-fix-report.json`, `-fix-report.txt`, `-fix-report.sh`를
  `examples.yml`이 `--max-risk lockout_risk`와 `NO_COLOR=1`로 만듦. 접미사 `-report.json`이 게이트의 스냅샷
  글롭이 계획을 스냅샷으로 읽는 것을 막습니다. 게이트는 `runFix`가 쓰는 같은 함수로 fix 출력 셋을 렌더링하고,
  `check` 아래와 같은 네 프로비넌스 키를 `fix` 아래에서 마스크하고, `tableBody`처럼 표의 첫 줄을 버리고,
  스크립트는 통째로 비교하며, 커밋된 `fix.controls_digest`에서 읽은 같은 다이제스트 조건으로 셋을 건너뜁니다
  (G-24). 리프레시 전까지 커밋된 check 리포트는 G-24로 건너뛰고(열여섯과 함께 다이제스트가 움직임) fix
  파일은 없어 게이트가 리프레시를 이름 대며 실패로 보고하므로, 3D-1처럼 예시 런까지 브랜치는 red이고(로컬은
  `-skip TestExamplesLoadAndCheck`) 리프레시는 머지 전 필수입니다.

**CI.**

- `test` 잡이 `internal/remedy/testdata/*.sh`와 `examples/*-fix-report.sh`에 `sh -n`과 `shellcheck -s sh`
  (기본 심각도)를 돌리고, 러너 이미지에 없으면 설치합니다(`command -v shellcheck || sudo apt-get install -y
  shellcheck`). `make shellcheck`가 로컬의 같은 명령.
- 새 `fix-roundtrip` 잡은 실패를 심은 뒤 스크립트가 고치는 것을 증명합니다 — 컨테이너 매트릭스의 init
  이미지(`rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`, `systemctl`이 답하는 곳)와 `ubuntu:22.04`에서;
  호스트는 건드리지 않습니다. 컨테이너마다: (1) 심기 — init 이미지에선 `dnf install -y rpcbind
  openssh-server acl`, `ssh-keygen -A`, `systemctl enable --now rpcbind.socket sshd`, `printf 'PermitRootLogin
  yes\n' > /etc/ssh/sshd_config.d/99-ci.conf`(스크립트의 `00-muster.conf` 뒤에 정렬되므로 스크립트의 값이
  이김: sshd는 처음 읽은 값을 지킴), `chmod 644 /etc/hosts`; `ubuntu:22.04`에선 `apt-get update -qq &&
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq acl`, `chmod 644 /etc/hosts`(`/etc/shadow`는 거기서 이미 `0640`); (2) `collect` → `fix --dry-run --format script
  > /tmp/fix.sh`; (3) 계획이 심은 id를 `script: true`인 계획 항목으로 나열함을 단언(init 이미지:
  `muster.service.rpcbind_disabled`, `muster.account.root_remote_login`, `muster.file.hosts_permissions`;
  ubuntu: `hosts_permissions`, `shadow_permissions`) — 아무것도 계획하지 않은 실행은 아무것도 증명하지 않는
  대신 잡을 실패시킴; (4) `sh /tmp/fix.sh`(잡이 돌리지 muster는 결코 아님)가 0으로 끝남; (5) `collect` →
  `check --format json`: 심은 모든 id가 `PASS`나 `NOT_APPLICABLE`. 심은 집합은 설계의 가설이고, 첫 실행이
  바로잡으며 계획의 Execution notes가 이미지마다 실제로 계획된 것을 기록합니다.
- `make lint-controls` 변경 없음(새 규칙이 그 안에서 돎).

**문서**(영어와 한국어를 같은 커밋에).

- 메인 설계: §4.1 서브커맨드 문장이 `fix --dry-run`을 "이후에"에서 목록으로 옮기고 예시 블록에
  `muster fix --dry-run --facts host.json --format script > fix.sh`; §4.3 데이터 흐름 그림에 계획; §4.4가
  `check`와 `fix`를 프로파일·튜닝·waiver 파일의 독자로 이름 대고, 둘 다 root에서 같은 신뢰 파일 규칙 아래;
  §8 "쓰기"에: `fix --dry-run`은 stdout에만 쓰고, 그것이 찍는 검토용 스크립트는 muster가 결코 실행하지
  않음; §6.2 스키마 예시와 필드 목록에
  `backup`과 `validate`와 린트 규칙; 새 §7.5 "`fix --dry-run`"(입력, 형식, 종료 코드, 템플릿 계약, "fix는
  발견이 있어도 0으로 끝남"); §10.2가 3D-2 병합을 표시; **D34** — "`fix`는 적용하지 않는다: 산출물은 검토용
  스크립트이고, 블록은 컨트롤당 하나로 독립이며 백업 먼저·실패 시 롤백 다음 복원이다; 무엇을 백업·검증·
  되돌릴지는 컨트롤에 선언하지 추론하지 않으며, 어떤 호스트 값도 명령에 치환하지 않고, `validate`는 단계를
  증명하지 판정을 증명하지 않는다."
- `CLAUDE.md`: "## Fix (stage 3D-2)" 절(X 판정을 작업 노트 꼴로, 본문 규율).
- README 쌍: 사용법 줄 `muster fix --dry-run --facts host.json --format script > fix.sh`, 로드맵 항목,
  "출력 예시"에 예시 파일 여섯을 이름 대는 문장.
- `CHANGELOG.md`: Added(`fix --dry-run`, 세 형식, `--max-risk`), Changed(린트 규칙; 컨트롤 세트 버전),
  Controls(열여섯을 `backup`/`validate`/`rollback`과 함께 재작성; 판정 변경 없음).
- `CONTRIBUTING` 쌍: §3의 본문 규율(backup, validate, rollback, idempotent, POSIX sh, `set -e` 안전, 유닛별
  루프, shellcheck, 전체 스크립트 골든, 라운드트립 잡).
- `THREAT_MODEL.md`: 한 줄 — `fix --dry-run`이 쓰는 스크립트를 muster는 결코 실행하지 않는다.

## 8. 보류

- 라운드트립이 심지 않는 재작성 본문 열둘의 호스트 증명(서비스 컨트롤 아홉과 `passwd`, `services`,
  `hosts_lpd` 권한 스크립트, 그리고 첫 실행이 심기지 않았다고 보여 주는 것); 이번 사이클에는 구문으로
  증명합니다(3D-2b).
- 열여섯 밖 컨트롤의 스크립트(3D-2b, 컨트롤마다 호스트 증명이 붙는 콘텐츠): sysctl 설정, 나머지 파일
  권한, PAM과 sshd 옵션. 명령이 파라미터 값(`min_len`, `allowed_ports`)을 실어야 하는 교정은 치환 규칙이
  먼저 필요하고, 그때까지 텍스트(X-5).
- 스냅샷 대신 `check` 결과 JSON 읽기(`fix --dry-run --result`): 같은 다이제스트의 컨트롤 세트가 필요;
  계획의 모양은 바뀌지 않음.
- 충실한 롤백을 위한 서비스의 변경 전 상태(enabled/active) 기록; 오늘은 롤백이 스크립트가 이름 대는 모든
  유닛을 다시 켬.
- `each` 컨트롤의 주체별 계획(예: world-writable 파일마다 블록 하나).
- `check.Result`의 구조적 판정 표지(내보낸 reason 접두사 대신), 넷째 소비자가 생기면.
- `explain`(메인 설계 §4.1)은 별도 사이클.
