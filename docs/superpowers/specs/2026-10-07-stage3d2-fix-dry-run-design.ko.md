# 3D-2단계 — `fix --dry-run`: 교정 계획과 검토용 스크립트

영어 원본: `2026-10-07-stage3d2-fix-dry-run-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`
(§4.1 명령, §6.2 스키마, §6.6 프로파일, §7 출력, §10.2 로드맵, D24, D33). 프로파일: `2026-10-07-stage3d1-profiles-design.ko.md`.

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
  다른 모드 단어가 붙은 `fix`는 종료 2와 `fix never applies a remediation (D24); run fix --dry-run`으로
  거부합니다. 플래그를 필수로 두는 이유는 훗날 누가 "fix"를 읽어도 조용히 적용될 수 없게 하기 위함입니다.
  스크립트는 stdout의 파일이고 muster는 그것을 실행하지 않으며, `internal/remedy`는 `os/exec`를 결코
  임포트하지 않습니다.
- **X-2 — 적용 중인 프로파일의 실패.** 계획의 행은 waiver 파일이 적용된 뒤 상태가 `FAIL`이나 `WARN`인
  `check` 행입니다: 같은 `resolveSelection`, 같은 평가기, 같은 `waiver.Apply`. 제외된 컨트롤은 결코
  계획되지 않고, 면제된 컨트롤은 세기만 하며, `MANUAL`과 `ERROR` 행은 계획할 수 없었던 것으로 나열되어
  독자가 봅니다. "실패"의 둘째 정의는 어디에도 없습니다.
- **X-3 — 위험도가 먼저.** 계획은 교정 위험도(`none` < `restart_service` < `reboot_required` <
  `lockout_risk`) 순, 그다음 적용 중인 심각도(high, medium, low — 프로파일의 덮어쓰기 포함), 그다음 id 순입니다.
  스크립트는 계획의 순서를 블록 단위로 따릅니다.
- **X-4 — 컨트롤당 블록 하나, 독립, 백업 먼저.** 스크립트는 컨트롤의 교정을 각각 자기 함수로 돌립니다:
  선언된 백업을 먼저 복사하고, 컨트롤의 `script`, 그다음 `validate` 명령; 0이 아닌 단계는 선언된
  `rollback`이 있으면 그것을, 없으면 백업 복원을 실행하고 블록은 1을 돌려줍니다. 실패한 블록은 다음
  블록을 막지 않고, 스크립트의 종료 코드는 실패 블록이 하나라도 있으면 1, 아니면 0입니다.
- **X-5 — 선언하지 추론하지 않는다.** 무엇을 백업할지(`backup`), 어떻게 확인할지(`validate`), 어떻게
  되돌릴지(`rollback`)는 컨트롤의 `remediation` 블록의 필드이고 `controls lint`가 검사합니다. 생성기는
  스크립트 본문에서 경로를 유도하지 않고, 스냅샷 값이나 파라미터를 명령에 치환하지 않습니다. 명령이
  파라미터에 의존하는 교정은 이번 사이클에 `script`를 갖지 않고 텍스트로 남습니다(§8).
- **X-6 — 되돌릴 길이 없으면 스크립트도 없다.** 린트는 `rollback`도 비어 있지 않은 `backup`도 없는
  `script`, `idempotent`가 아닌 컨트롤의 `script`, `script` 없는 `backup`이나 `validate`를 거부합니다.
  되돌리거나 재실행할 수 없는 교정은 스크립트가 아니라 텍스트입니다.
- **X-7 — 메커니즘과 열여섯.** 이 사이클은 스키마 필드, 린트 규칙, 계획, 스크립트, 렌더러, 명령,
  라운드트립 증명을 배포하고, 이미 `script`를 가진 컨트롤 열여섯에 `backup`/`validate`/`rollback`을
  채웁니다. 나머지 컨트롤의 스크립트 작성은 각자 호스트 증명이 필요한 콘텐츠 작업이라 다음
  사이클입니다(§8).
- **X-8 — `--max-risk`가 유일한 손잡이.** 운영자는 스크립트가 실행할 위험도의 상한을 정할 수 있습니다:
  상한 밖 항목은 표시된 채 계획에 남고 스크립트에는 주석 처리된 블록으로 들어갑니다. 그 밖에 계획을
  거르는 것은 없습니다 — waiver와 프로파일이 상류에서 이미 거릅니다.
- **X-9 — 같은 바이트, 세 형식.** 표·JSON·스크립트는 같은 입력에 각각 결정적입니다. 어떤 `map`도
  렌더러에 닿지 않고, 생성기는 시계를 읽지 않습니다(백업 디렉터리의 타임스탬프는 스크립트가 실행될 때
  안의 `date`가 만듭니다). 골든 파일이 셋을 고정합니다.

## 2. 아키텍처

```
snapshot.json + profile + tuning + waivers
   ──(cmd/muster fix: check 파이프라인 — 적재, resolveSelection, Evaluate, waiver.Apply)──▶ []Row
[]Row + controls.Set + options ──remedy.Plan──▶ Plan
Plan ──report.FixTable / report.FixJSON──▶ stdout       Plan ──remedy.Script──▶ stdout (sh)
```

- **`internal/remedy`(신규).** 순수: `Plan(run facts.Run, cb report.CheckBlock, rows []report.Row,
  set *controls.Set, opts Options) *Plan`과 `Script(p *Plan) []byte`. `Options{MaxRisk string}`; `Plan`은
  어휘 밖의 `MaxRisk`에만 오류를 돌려줍니다(`Plan(…) (*Plan, error)`). `internal/check`,
  `internal/controls`, `internal/report`(`Row`와 run 블록)와 표준 라이브러리만 임포트하고, 테스트가 `os`,
  `os/exec`, `net`, `syscall`, `time`을 거부합니다. 패키지는 stderr·stdout에 쓰지 않습니다.
- **`internal/report`(확장).** check 렌더러 옆에 `FixTable(p *remedy.Plan, color bool) []byte`와
  `FixJSON(p *remedy.Plan) []byte`; `escape`, `paint`, `maxCell`, 색 정책을 공유합니다. `Row`는 그대로.
- **`internal/controls`(확장).** `Remediation`에 `Backup []string`(`yaml:"backup,omitempty"`)과
  `Validate string`(`yaml:"validate,omitempty"`); `Lint`에 §3의 규칙; strict 로더는 변경 없음(미지 키는
  이미 거부).
- **`cmd/muster`(확장).** `fix` 디스패치; `runFix`는 `fixFlags` 구조체로 `parseCheckArgs`의 플래그
  형태를, 적재·`resolveSelection`·waiver에는 `runCheck`와 같은 헬퍼를 씁니다. check 파이프라인을 복제하는
  새 헬퍼는 없습니다: `runCheck`의 평가 순서를 두 명령이 함께 부르는 함수 하나(`evaluate(f checkFlags, …)
  (*facts.Snapshot, []report.Row, CheckBlock, error)`)로 끌어올려 실패의 정의가 한 곳에 남습니다(X-2).
- 순환 없음: `remedy`가 `report`에 의존하고 반대는 없습니다. 렌더러는 `*remedy.Plan`을 받습니다.

## 3. remediation 블록과 린트

선언된 블록(`Remediation`의 필드, 모두 `remediation:` 아래; 앞의 넷은 지금도 있음):

```yaml
remediation:
  text_en: Set PermitRootLogin no in a file under /etc/ssh/sshd_config.d/, validate with sshd -t, …
  text_ko: /etc/ssh/sshd_config.d/ 아래 파일에 PermitRootLogin no 를 넣고 sshd -t 로 검증한 뒤 …
  risk: lockout_risk               # none | restart_service | reboot_required | lockout_risk
  idempotent: true
  backup: [/etc/ssh/sshd_config.d/90-muster.conf, /etc/securetty]
  script: |
    …
  validate: sshd -t
  rollback: |
    …
```

규칙 — 각각 컨트롤과 필드를 이름 대는 린트 문제(지금처럼 `add("remediation", …)`):

- `remediation`이 있으면 `text_en`과 `text_ko`가 필수(지금은 `risk`만 검사; 배포된 모든 컨트롤이 이미
  둘 다 가지므로 변경이 아니라 고정).
- `risk`는 네 단어 중 하나(변경 없음).
- `script`는 `idempotent: true`를 요구 — `remediation: script requires idempotent: true`(비멱등 컨트롤
  둘, `file/dev_no_stale_files`와 `file/ip_port_restriction`은 스크립트가 없음).
- `script`는 되돌릴 길을 요구: `rollback`이 비어 있지 않거나 `backup`이 비어 있지 않음 — `remediation:
  script without rollback or backup`.
- `backup`과 `validate`는 `script`를 요구 — `remediation: backup without script` / `remediation:
  validate without script`.
- 모든 `backup` 항목은 절대 경로이고 자기 `path.Clean`과 같으며 `*`, `?`, `[`가 없고 목록 안에서 유일 —
  `remediation: backup path %q is not absolute` / `is not clean` / `is a glob` / `is repeated`. 순서는
  작성자의 것이고 생성기가 지킵니다.
- `script`, `validate`, `rollback`은 리터럴 `sh` 텍스트이고, 있으면 트림 뒤 비어 있지 않음 —
  `remediation: %s is blank`. 린트는 셸을 파싱하지 않습니다; 생성된 스크립트에 대한 CI의 `shellcheck`(§7)가
  본문의 게이트입니다.

픽스처: 기존 린트 픽스처 하네스를 통한 `controls/testdata/_lint/remediation-*.yaml`(규칙마다 빨간 파일
하나). `controls/VERSION` 올림: 열여섯 컨트롤이 바뀌므로(새 필드) 세트 버전과 다이제스트가 움직이고,
판정은 바뀌지 않으므로 어느 픽스처의 기대 상태도 바뀌지 않고 `TestEveryMutantIsKilled`도 영향 없음(필드가
모든 판정 밖).

이번 사이클에 완성하는 열여섯(X-7):

| 묶음 | 컨트롤 | backup | validate | rollback |
|---|---|---|---|---|
| 파일 권한(5) | `file/{passwd,shadow,hosts,services,hosts_lpd}_permissions` | 그 파일 | `stat -c '%U:%G %a' <file>`을 스크립트가 정한 쌍과 `grep -qx`로 비교 | restore_backup(선언 없음) |
| 서비스 비활성화(10) | `service/{telnet,finger,rservices,dos_services,nfs_server,automount,rpcbind,nis,tftp_talk,snmp}_disabled` | 없음(파일이 아니라 유닛 상태) | 유닛마다 `! systemctl is-enabled --quiet <unit>`, `! systemctl is-active --quiet <unit>` | 선언: 스크립트가 끈 유닛마다 `systemctl enable --now <unit>`(원래 상태는 기록하지 않음 — 운영자가 실행 전에 블록을 읽고, 계획의 `why:` 줄이 무엇이 켜져 있었는지 말함) |
| root 원격 로그인(1) | `account/root_remote_login` | `/etc/ssh/sshd_config.d/90-muster.conf`, `/etc/securetty` | `sshd -t` | 선언(이미 있음) |

정확한 유닛 이름과 기대 모드는 각 컨트롤의 판정이 이미 담고 있는 것입니다. 구현자는 컨트롤에서 읽지
지어내지 않습니다. 서비스 컨트롤의 스크립트가 유닛을 둘 이상 끄면 validate 줄이 전부 검사합니다.

## 4. 계획

`remedy.Plan`은 모든 렌더러가 읽는 모델입니다. 필드 순서가 JSON 순서입니다.

```
Plan
  run         facts.Run            스냅샷의 run 블록, check의 것과 바이트 동일
  fix         FixBlock             {profile ProfileBlock, tuning *TuningBlock, max_risk string}
  items       []Item               순서: risk 순위 ↑, 심각도 순위(high, medium, low), id
  not_planned []NotPlanned         ERROR·MANUAL 행마다 {id, status}, id 순
  summary     Summary              planned, above_max_risk, with_script, text_only, waived,
                                   not_planned {error, manual}, by_risk {none, restart_service,
                                   reboot_required, lockout_risk}
Item
  id, title_en, title_ko
  status          fail | warn           (소문자, 계획 자신의 어휘)
  severity, severity_source           check가 찍는 그대로
  risk, idempotent, automation
  reason          check가 찍는 행의 reason(한 줄; 렌더 시 escape)
  text_en, text_ko
  script          bool                  컨트롤이 스크립트를 선언함
  rollback        declared | restore_backup | none   (none ⇔ script false)
  backup          []string              선언된 경로; 스크립트 없으면 []
  validate        bool
  planned         bool                  risk 순위 ≤ max_risk 순위
```

- `planned`는 `summary.planned`에 셉니다; 상한 밖 항목은 `above_max_risk`에 세고 `planned`에는 세지
  않습니다. `with_script`와 `text_only`는 계획된 항목을 나눕니다. `waived`는 `WAIVED` 행의 수.
  `by_risk`는 계획 여부와 무관하게 모든 항목을 셉니다.
- 항목은 컨트롤 하나입니다. 실패 주체가 여럿인 `each` 컨트롤은 `reason`이 행의 것인 항목 하나이고, 주체별
  세부는 `check`의 몫입니다. 주체가 모두 면제된 컨트롤은 `WAIVED`라 항목이 아닙니다.
- 빈 목록은 `null`이 아니라 `[]`; `tuning`은 `--tuning` 없으면 생략; `not_planned`는 비어도 있음.
- `Plan`은 `map`을 갖지 않습니다. `by_risk`는 int 넷의 구조체.

## 5. 스크립트

`remedy.Script(p)`는 고정 템플릿을 렌더링합니다. 머리말, 계획 순서의 항목 블록, 꼬리말. 스냅샷에서 온 것은
명령에 들어가지 않습니다: run 데이터는 `#` 주석 줄에만, 값마다 표의 `escape`를 거쳐(개행을 두 글자 `\n`으로
적으므로 적대적 reason이 주석을 끝낼 수 없음) `maxCell`에서 잘립니다.

```sh
#!/bin/sh
# muster fix --dry-run: review before running. muster never runs this file.
# snapshot: host <host>, collected <collected_at>; controls <controls_digest>
# profile <name> (<digest>); max-risk <level>
# planned <n> (script <a>, text only <b>); above max-risk <c>; not planned: error <d>, manual <e>
set -u
umask 077
MUSTER_BACKUP="${MUSTER_BACKUP:-/var/backups/muster/$(date +%Y%m%dT%H%M%S)}"
mkdir -p "$MUSTER_BACKUP" || exit 2
log()     { printf 'muster-fix: %s\n' "$*"; }
backup()  { for p in "$@"; do [ -e "$p" ] && mkdir -p "$MUSTER_BACKUP$(dirname "$p")" && cp -a "$p" "$MUSTER_BACKUP$p"; done; return 0; }
restore() { for p in "$@"; do [ -e "$MUSTER_BACKUP$p" ] && cp -a "$MUSTER_BACKUP$p" "$p"; done; return 0; }
failed=0
```

스크립트가 있는 계획 항목(`<fn>`은 `fix_` + id의 모든 `.`을 `_`로):

```sh
# ---- 1/7 muster.file.hosts_permissions [risk none] [fail, high]
# why: mode is 0664, expected one of 0600 0400 0644
# do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
# ko:  chown root:root /etc/hosts; chmod 600 /etc/hosts
fix_muster_file_hosts_permissions() {
  backup /etc/hosts
  ( set -e
    chown root:root /etc/hosts && chmod 600 /etc/hosts
  ) || { log "muster.file.hosts_permissions: script failed, rolling back"; restore /etc/hosts; return 1; }
  ( set -e
    stat -c '%U:%G %a' /etc/hosts | grep -qx 'root:root 600'
  ) || { log "muster.file.hosts_permissions: validate failed, rolling back"; restore /etc/hosts; return 1; }
  log "muster.file.hosts_permissions: done"
}
fix_muster_file_hosts_permissions || failed=$((failed+1))
```

- `backup` 줄은 컨트롤이 경로를 선언할 때만, `validate` 서브셸은 선언될 때만 나옵니다. 실패 경로는
  선언된 `rollback` 본문(자기 `( set -e … )` 서브셸에서, 자기 실패는 로그만 남기고 재시도 없음)이 있으면
  그것, 없으면 `restore <경로들>`.
- script·rollback 본문은 YAML 리터럴을 줄마다 네 칸 들여쓴 것이고 끝 개행은 잘립니다. 트림 뒤 빈 본문은
  린트 오류(§3)이지 빈 서브셸이 아닙니다.
- `lockout_risk` 항목은 헤더 뒤에 주석 한 줄이 더 붙습니다: `# keep a second session open; a lockout here
  needs console access`.
- 스크립트 없는 계획 항목은 주석 블록만(헤더, `why:`, `do:`, `ko:`, `# text only: no script declared`),
  함수도 호출도 없음.
- `--max-risk` 밖 항목은 모든 줄 앞에 `# `가 붙은 전체 블록(함수와 호출 포함)이고, 헤더 줄은 `-- above
  max-risk <level>, NOT RUN`으로 끝납니다.

꼬리말:

```sh
[ "$failed" -eq 0 ] || { log "$failed block(s) failed; backups in $MUSTER_BACKUP"; exit 1; }
log "done; backups in $MUSTER_BACKUP"
```

빈 계획은 머리말, `# nothing to fix` 한 줄, 꼬리말을 렌더링하므로 여전히 0으로 끝나는 유효한 스크립트입니다.

테스트로 고정하는 안전 계약: `#` 주석 밖의 어떤 줄도 스냅샷에서 온 텍스트를 싣지 않음; 두 번 렌더가 바이트
동일; 생성기는 시계를 부르지 않음; 모든 골든과 두 예시 스냅샷의 출력이 `sh -n`과 `shellcheck -s sh`를
통과; 독 스냅샷(host·reason·제목에 ESC와 개행)의 스크립트에서 스냅샷 유래 바이트가 모두 주석 줄 안에 있음.

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

- `--dry-run`은 인수 어딘가에 있어야 합니다(X-1). `fix` 뒤의 다른 첫 단어(`apply`, `run`, …)나 부재는 X-1
  거부입니다.
- `--profile`, `--tuning`, `--waivers`는 check와 정확히 같은 의미·거부·경고(`profile.Resolve`,
  `tuning.Load`, root에서의 신뢰 파일 규칙, `warnTo(stderr)`). 빈 `--profile`/`--tuning` 값은 check처럼
  거부(Z-30).
- 네 단어 밖의 `--max-risk`는 단어들을 이름 대며 종료 2로 거부.
- `--fail-on`, `--allow-error`, `--quiet`, `--all` 없음: `fix`는 판정하지 않고 모든 항목을 보여 줍니다.

**흐름.** `runFix`: 플래그 파싱 → 컨트롤 세트와 레지스트리 적재 → 스냅샷 읽기(check처럼 신뢰하지 않고)
→ `resolveSelection` → 공유 `evaluate`(check의 평가와 waiver 순서, controls 다이제스트 불일치 경고 포함)
→ `remedy.Plan` → `--format`의 렌더러 → stdout. 경고는 `muster: warning: ` 접두사의 stderr 줄.

**종료 코드.** `0`: 계획을 만들었음(항목이 있든 없든). `2`: 만들 수 없음 — 플래그 오류, X-1 거부, 읽을 수
없거나 신뢰할 수 없는 스냅샷, 프로파일·튜닝·waiver 거부, 목록 밖의 `--max-risk` 단어. **`1`은 없음**:
`fix`는 호스트를 판정하지 않고 `check`가 합니다. 메인 설계의 종료 코드 계약은 그대로이고, 문서가 한
문장으로 말해 어떤 CI도 `fix`로 결과를 세지 않게 합니다. `ERROR` 행은 `fix`의 종료 코드를 바꾸지 않고
`not_planned`입니다.

**표**(`report.FixTable`): 머리 네 줄, 빈 줄, 항목들, `not planned:` 줄.

```
muster <version> · controls <controls_version> · guide <guide_edition> · host <host> · collected <collected_at>
fix --dry-run · profile <name> (<selected> of <total>, <excluded> excluded[; tuning <path>]) · max-risk <level>
planned 7 (script 4, text only 3) · above max-risk 1 · waived 1 · not planned: error 0, manual 14
by risk: none 5 · restart_service 1 · reboot_required 0 · lockout_risk 1

#  risk             id                              status  sev   script  rollback        title
1  none             muster.file.hosts_permissions   fail    high  yes     restore_backup  /etc/hosts …
   why: mode is 0664, expected one of 0600 0400 0644
   do:  chown root:root /etc/hosts; chmod 600 /etc/hosts
…
6  lockout_risk     muster.account.root_remote_login  fail  high  yes     declared        … (above max-risk)
   why: …
   do:  …

not planned: muster.beyond.audit_rules_persisted (error) · muster.service.nfs_exports (manual) · …
```

- 1행은 check의 첫 줄과 바이트 동일(같은 함수). 2행의 프로파일 부분은 check의 `profileLine` 텍스트.
  `title` 칸은 check의 표처럼 `title_en`; `do:`는 `text_en`. 한국어 텍스트는 JSON과 스크립트에.
- 색이 켜지면 `risk` 칸만 칠합니다: `lockout_risk` 빨강, `reboot_required` 자홍, `restart_service` 노랑,
  `none` 무색; `status`는 check의 상태 색.
- 스냅샷이나 컨트롤에서 온 모든 문자열은 `escape`를 거칩니다. 칸은 `maxCell`에서 잘립니다.
- 빈 계획은 머리 네 줄, 빈 줄, `nothing to fix`; 내용이 있으면 `not planned:` 줄이 뒤따릅니다.

**JSON**(`report.FixJSON`): `{"schema_version": …, "run": …, "fix": …, "items": […], "not_planned":
[…], "summary": …}` 그 순서로, 두 칸 들여쓰기, 끝 개행 — check의 JSON처럼. `schema_version`은 결과
스키마의 것(변경 없음: 계획은 check 결과의 변경이 아니라 새 문서).

## 7. 테스트, CI, 문서

**테스트.**

- `internal/remedy`: `TestPlanOrdersByRiskSeverityID`(프로파일의 심각도 덮어쓰기를 포함한 섞인 행 집합),
  `TestPlanExcludesWaivedAndCountsThem`, `TestPlanListsErrorAndManualAsNotPlanned`,
  `TestPlanMarksItemsAboveMaxRisk`, `TestPlanEmpty`, `TestPlanHasNoMap`(check처럼 타입 리플렉션),
  `TestScriptGolden`(`-update`; 픽스처마다 골든 하나: 전체, 빈, 상한 적용, 독), `TestScriptBlocksAreIndependent`
  (구조: 스크립트 있는 계획 항목마다 함수 하나와 호출 하나, 상한 밖 블록의 모든 줄이 `# `로 시작),
  `TestScriptRollbackDeclaredElseRestore`, `TestScriptCommentsCarryEverySnapshotByte`(독 계획),
  `TestScriptIsDeterministic`, `TestRemedyImports`(`go list` 임포트; `os`, `os/exec`, `net`, `syscall`,
  `time` 거부).
- `internal/report`: `TestFixTableGolden`, `TestFixJSONGolden`(`-update`), `TestFixTablePoisoned`,
  `TestFixJSONEmptyListsAreArrays`, no-map 정적 검사를 fix 렌더러로 확장.
- `internal/controls`: §3 규칙마다 빨간 픽스처 하나; 배포 세트를 린트하는 기존 테스트가 열여섯을 덮음.
- `cmd/muster` e2e, `full-fail.json`으로: 세 형식; `--dry-run` 없는 `fix` → 2와 X-1 텍스트; `fix apply
  --dry-run` → 2; 미지 플래그 → 2; `--max-risk restart_service`가 lockout 항목을 표시; 실패 컨트롤을
  제외하는 `--profile`이 계획에서 뺌; `--waivers`가 하나를 `waived`로; `--format script`가 `sh -n` 통과
  (Linux만, 그 밖에선 스킵); check와 fix의 일치: `check --format json`의 모든 `FAIL`/`WARN` id가 항목이고
  그 밖엔 없음(`TestFixAgreesWithCheck`).
- 예시: 두 스냅샷의 `examples/*-fix.txt`, `*-fix.json`, `*-fix.sh`를 `examples.yml`이 `--max-risk
  lockout_risk`와 `NO_COLOR=1`로 만들고 `TestExamplesLoadAndCheck`가 바이트 비교; 게이트는 3D-1처럼 첫
  렌더러 커밋부터 리프레시까지 red(`-skip TestExamplesLoadAndCheck` 로컬).

**CI.**

- `test` 잡이 `examples/*-fix.sh`와 스크립트 골든(`internal/remedy/testdata/*.sh`)에 `shellcheck -s sh`를
  돌림; 우분투 러너에 shellcheck가 있음.
- 컨테이너 매트릭스의 init 이미지(`rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`)와 `ubuntu:22.04`
  에서 새 `fix-roundtrip` 잡: 컨테이너 안에서 `collect` → `fix --dry-run --format script > /tmp/fix.sh` →
  `sh /tmp/fix.sh`(잡이 돌리지 muster가 아님) → `collect` → `check --format json`; 첫 계획이 `planned`이고
  `script: true`로 나열한 모든 항목이 이제 `PASS`나 `NOT_APPLICABLE`이고 스크립트가 0으로 끝났음을 잡이
  단언. 서비스 비활성화 스크립트는 init 이미지(`systemctl`이 답하는 곳)에서 증명하고 `ubuntu:22.04`에선
  첫 계획의 `not_planned`/`ERROR` 행을 읽는 단언이 건너뜀. 생성된 스크립트가 실행되는 유일한 곳이고,
  일회용 공개 컨테이너 안에서만.
- `make lint-controls` 변경 없음(새 규칙이 그 안에서 돎).

**문서**(영어와 한국어를 같은 커밋에).

- 메인 설계: §4.1 명령 표에 `fix --dry-run`; §4.3 데이터 흐름 그림에 계획; §6.2 스키마 예시와 필드
  목록에 `backup`과 `validate`와 린트 규칙; 새 §7.5 "`fix --dry-run`"(입력, 형식, 종료 코드, 템플릿 계약);
  §10.2가 3D-2 병합을 표시; **D34** — "`fix`는 적용하지 않는다: 산출물은 검토용 스크립트이고, 블록은
  컨트롤당 하나로 독립이며 백업 먼저·실패 시 롤백이다; 무엇을 백업·검증·되돌릴지는 컨트롤에 선언하지
  추론하지 않으며, 어떤 호스트 값도 명령에 치환하지 않는다."
- `CLAUDE.md`: "## Fix (stage 3D-2)" 절(X 판정을 작업 노트 꼴로).
- README 쌍: 사용법 줄 `muster fix --dry-run --facts host.json --format script > fix.sh`, 로드맵 항목,
  "출력 예시"에 예시 파일 여섯을 이름 대는 문장.
- `CHANGELOG.md`: Added(`fix --dry-run`, 세 형식, `--max-risk`), Changed(린트 규칙; 컨트롤 세트 버전),
  Controls(열여섯이 필드를 얻음; 판정 변경 없음).
- `CONTRIBUTING` 쌍: `script` 작성법(backup, validate, rollback, idempotent, POSIX sh, shellcheck,
  라운드트립 잡).
- `THREAT_MODEL.md`: 한 줄 — `fix --dry-run`이 쓰는 스크립트를 muster는 결코 실행하지 않는다.

## 8. 보류

- 열여섯 밖 컨트롤의 스크립트(3D-2b, 컨트롤마다 호스트 증명이 붙는 콘텐츠): sysctl 설정, 나머지 파일
  권한, PAM과 sshd 옵션. 명령이 파라미터(`min_len`, `allowed_ports`)에 의존하는 교정은 치환 규칙이
  먼저 필요하고, 그때까지 텍스트.
- 스냅샷 대신 `check` 결과 JSON 읽기(`fix --dry-run --result`): 같은 다이제스트의 컨트롤 세트가 필요;
  계획의 모양은 바뀌지 않음.
- 충실한 롤백을 위한 서비스의 변경 전 상태(enabled/active) 기록; 오늘은 롤백이 스크립트가 끈 것을
  다시 켬.
- `each` 컨트롤의 주체별 계획(예: world-writable 파일마다 블록 하나).
- `explain`(메인 설계 §4.1)은 별도 사이클.
