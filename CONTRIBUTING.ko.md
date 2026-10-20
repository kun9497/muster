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
   (네트워크 필요), CI는 커밋된 인덱스만 읽습니다. 워크의 기준 목록도 같은 방식으로
   삽니다. `make suidindex`가 고정된 공개 이미지에서 재생성하고(docker와 네트워크 필요),
   `make suidindex-check`가 검증하며, CI는 커밋된 파일을 읽습니다.

### 가이드 밖의 컨트롤

KISA 항목이 아닌 컨트롤은 `category: beyond`, id `muster.beyond.<name>`이고
`references.kisa`가 없으며(lint 규칙 `beyond_scope`가 둘을 나란히 유지) CIS 권고 번호도
달지 않습니다. 1차 출처 — 커널 문서, man 페이지, 배포판 자체 문서 — 에서 muster의
표현으로 쓰고, 설명이 그 중요도를 매긴 이유를 한 문장으로 말합니다. 이런 컨트롤은 모두
`env.container eq none`을 문지기로 둡니다: 컨테이너 안에서 이 팩트들은 호스트를
묘사합니다. `go run ./cmd/muster controls new muster.beyond.<name> --importance 중`이
뼈대를 만듭니다(`--kisa-id` 없음). `setting` 키를 읽는 픽스처는 부재를 뜻할 때 키를 두되
`effective` 쪽을 `absent`로 둡니다.

### 조치 본문

`fix --dry-run`은 컨트롤의 `script`, `validate`, `rollback`을 검토용 스크립트로 렌더링하므로
이들은 코드입니다. `script`에는 `idempotent: true`, `validate`, 그리고 여섯 종류 중 하나의 되돌릴
길이 필요합니다: `rollback`, 비어 있지 않은 `backup`, 본문이 바꾸는 상태의 기록 — `modes`(경로와
`/*`·`/*/*` 전개의 소유자·그룹·모드), `sysctl`(커널 키의 런타임 값), `modules`(각 모듈의 적재
여부) — 이들의 조합, 또는 서비스 컨트롤이라면 `units` 하나(`units`는 다른 다섯과 함께 쓸 수
없음). 템플릿은 본문이 돌기 전에 선언된 종류를 블록 자신의 디렉터리(`$MUSTER_BACKUP/blocks/<fn>/`)
아래 기록하고, 본문이나 validate가 실패하면 선언된 `rollback`을 실행한 뒤 유닛, 모드, 파일, sysctl
값, 모듈을 이 순서로 복원합니다. 블록이 도는 동안 데몬이나 시스템이 쓰는 경로(살아 있는 로그)는
`backup`이 아니라 `modes` 항목입니다. `backup`은 그 내용을 되돌려 복사하기 때문입니다. 본문이
모드만 바꾸는 경로는 어느 쪽을 써도 됩니다. 본문은 서브셸에서 `set -e` 아래 돕니다. 정당하게
실패할 수 있는 명령은 자기 줄에 `|| true`로 그렇다고 말하고, 끝에 붙인 `; true`는 결코
쓰지 않으며, 운영자가 봐야 할 오류를 `2>/dev/null`로 숨기지 않습니다. 파일에 작용하는
본문은 먼저 그 파일이 있는지 확인하고 — 호스트에 없을 수 있는 디렉터리는 `if [ -d <dir> ] &&
[ ! -L <dir> ]; then …; fi` 안에서, 경로 하나는 `if [ -f <p> ] && [ ! -L <p> ]` 안에서 — 선택적
도구를 부르는 본문은 `command -v`로 감쌉니다. 서비스 컨트롤은 자기 유닛을 `units`에 선언합니다 — `services.go`에 있는 논리
서비스의 `provesInstall` 유닛이며, 각 `<name>.socket`은 그 `<name>.service`보다 앞에 둡니다
(Linux 테스트가 그 집합을 고정하고, validate도 같은 유닛을 이름으로 적습니다). 스크립트는
유닛 이름을 직접 쓰지 않습니다. 템플릿이 `UNITS`를 설정하고, 본문 전에 각 유닛의 상태를
기록했다가 실패하면 되돌려 놓으므로 손으로 쓴 rollback은 없습니다. 그 기록은 활성화와 mask를
되돌려 놓지만 유닛을 멈추지는 않습니다. enable하는 본문(지금은 `auditd_active` 하나)은 동작
중이 아닌 유닛만 unmask하고 enable하고 시작하며, 그 텍스트는 실패한 블록이 시작된 유닛을 동작
중인 채로 남긴다고 말합니다. disable하는 본문은 유닛이 하나여도 `$UNITS`를 두 번에 걸쳐 돕니다:

```sh
todo=
for u in $UNITS; do
  systemctl cat "$u" >/dev/null 2>&1 || continue
  [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
  todo="$todo $u"
done
for u in $todo; do
  systemctl --quiet disable --now "$u"
  systemctl --quiet mask "$u" || true
done
```

첫 번째 루프는 무엇이든 mask하기 전에 모든 이름을 해석하고, 목록에 있는 유닛의 별칭은
건너뜁니다(Debian의 `nfs-kernel-server.service`는 `nfs-server.service`의 별칭이며, mask 뒤에
그것을 disable하면 실패합니다). 목록에 없는 유닛의 별칭도 건너뛰므로 실제 유닛을
선언하세요. 모듈 본문도 같은 이유로(shellcheck는 한 단어짜리 문자 그대로의 목록을 지적함)
`mods='<모듈들>'`로 시작해 `for m in $mods`로 돕니다. 파일 본문은 금지된 비트를 기호 모드로 지우고(`chmod u-xs,g-rwxs,o-rwxt`; 절대
모드를 쓰지 않으므로 더 엄격한 파일은 그대로 남음). ACL을 제거하는 본문(그렇게 하는 두 개:
`passwd_permissions`, `shadow_permissions`)은 `chmod` 전에 `setfacl -b`를 실행합니다. 모드나
소유자를 바꾸는 `find`는 `! -type l` 또는 컨트롤이 판정하는 종류(`-type f`)를 달아, `chmod`가
심볼릭 링크를 따라가지 않게 합니다. root가 아닌 누군가가 소유할 수 있는 디렉터리(데몬의 로그
디렉터리, `at`의 스풀) 아래 파일을 바꾸는 본문은 템플릿의 `modes_trusted "$d/." 0`이 성립하는
곳에서만 작용합니다 — 모든 상위 디렉터리가 root 소유이고 other 쓰기가 불가능해야 하며, Ubuntu의
`/var/log`처럼 root 소유이면서 그룹 쓰기가 가능한 디렉터리는 받아들입니다. 그 밖의 디렉터리는
로그를 남기고 운영자에게 맡깁니다. 그 validate도 같은 집합을 확인하므로 블록은 `done`으로 끝나고
다음 `check`가 여전히 그 경로를 짚습니다. muster가 소유하는 파일(`99-muster-*.conf` 드롭인)을
쓰는 본문이 그 자리에서 심볼릭 링크 — 운영자의 마스크 — 를 만나면, 로그를 남기고 그대로 둔 채
아무것도 쓰기 전에 블록을 실패시킵니다. 그 파일을 지우는 rollback은 심볼릭 링크를 건너뜁니다.

본문은 현재 값이 컨트롤의 조건이 받아들이는 집합 밖에 있을 때만 값을 씁니다. 현재 값은
수집기가 읽는 방식대로 읽습니다(`login.defs`는 첫 줄, `faillock.conf`는 마지막 줄,
`pwquality`는 병합된 체인, 키는 대소문자를 가리지 않음). 그래서 더 엄격한 호스트를 느슨하게
하지 않고 이미 통과하는 값을 다시 쓰지 않습니다. 써야 할 때 쓰는 값은 가이드의 값이거나 적용
중인 목록의 첫 원소입니다. 쓰기가 판정되는 다른 키에 미치는 부작용은 쓴 쪽이 되돌려 놓습니다.
`net.ipv4.ip_forward`를 쓰면 커널이 `net.ipv4.conf.all.accept_redirects`를 다시 설정하므로,
`ip_forwarding_disabled`는 그 키를 먼저 읽고 나중에 되돌려 놓으며 `sysctl`에 적습니다. 자기가 쓴
파일을 데몬이 다시 읽는 컨트롤의 rollback은 그 파일을 직접 되돌려 놓거나 지운 뒤 데몬을 시험하고
reload합니다. 템플릿의 `restore`는 rollback 다음에 돌므로 reload에는 늦습니다.

스크립트가 적용 중인 파라미터 값을 필요로 하는 컨트롤은 그것을 `script_params`에 선언합니다. 그러면
블록은 `P_<name>='<value>'`로 시작합니다(목록은 공백 하나로 이어지며, 첫 원소는
`first=${P_<name>%% *}`로 꺼냄). 값은 타입별 문자 집합(`int`는 부호가 붙을 수 있는 정수 `^-?[0-9]+$`, `bool`, `string`이나 목록
원소는 `[A-Za-z0-9._/@:+,=-]`)을 통과해야 하며, 그렇지 않으면 항목은 텍스트 전용(`params_unsafe`)이
됩니다. 값은 데이터로만 씁니다: `=` 뒤(`n=$P_max`), 옵션의 피연산자(`chage -M "$P_max_days"`)나
`--` 뒤, 뒤쪽 피연산자, awk의 `-v`/`VAR=` 대입. 줄의 맨 앞에 오지 않고 `sed` 식 안에 들어가지
않습니다. 보통 변수에 옮겨 담고 구분자로 `|`를 씁니다(`sed -i "s|^deny .*|deny = $n|"`).
`TestShippedBodiesPlaceParametersSafely`가 배포되는 모든 본문을 그렇게 묶습니다. 고침이
`absent_means: fail` 발견이 가리키는 바로 그 줄을 쓰는 컨트롤은 `script_on_absent: true`를
선언합니다. 그 밖의 absent 발견은 텍스트 전용으로 남습니다.

`validate`는 한 줄이며 스크립트가 설정한 것만 확인하되, 쓴 값과 같은지가 아니라 집합에 드는지를
증명합니다. 모양은 셋입니다: `&&`로 이은 조건, 마지막 갈래가 `*) false`인 `case` 하나(아무것도
맞지 않는 `case`는 0으로 끝남), 또는 조건이 `exit 1`로 루프를 끝내는, 문자 그대로의 목록에 대한
`for` 하나. 호스트에서 적용될 수 없는 본문은 validate도 같은 방식으로 감쌉니다(`if command -v
sshd …; then …; fi`). 파일 validate는 컨트롤의 기본 허용 모드를 나열하고, validate 안의 `find`는
허용 비트의 여집합 — 07777에서 가장 큰 허용 모드를 뺀 것(0640이면 `-perm /7137`, 0600이면
`/7177`, 0440이면 `/7337`) — 과, 소유자를 판정하는 곳에서는 `! -user root`를 시험합니다.
`backup` 경로와 `modes` 항목은 절대·정규 경로이고 `[A-Za-z0-9._@:+/-]` 안의 문자만 씁니다(항목은
`/*`나 `/*/*`로 끝날 수 있음). `sysctl` 키는 `^[a-z0-9_]+(\.[a-z0-9_-]+)+$`에 맞고 결코 정렬하지
않습니다(그 순서가 쓰기와 복원의 순서). `modules` 이름은 `^[a-z0-9][a-z0-9_-]*$`에 맞습니다.
here-document는 쓰지 않습니다. 스크립트는
`umask 077` 아래 돌므로, 다른 사람이 읽는 파일을 만드는 본문은 그 모드를 설정합니다.
`make shellcheck`와 `go test ./internal/remedy -run TestScriptGolden -update`
(`all-scripted.sh` 골든이 배포되는 모든 본문을 렌더링)가 변경을 검사합니다.
새 스크립트 컨트롤은 같은 커밋에서 `controls/testdata/_roundtrip.yaml`에도 들어갑니다:
`ci/roundtrip/<key>.sh` 시드 스크립트가 그것을 느슨하게 하고 `seeded` 목록이 그것을 적는
`fix-roundtrip` 행(`images`), 또는 어떤 행도 증명할 수 없는 이유(systemd 유닛 없음, 이미지의
활성 저장소에 패키지 없음, 컨테이너에서 유닛을 돌릴 수 없음, 커널이 그 모듈을 배포하지 않음)를
적은 `unproven:`입니다. `beyond` 컨트롤은 컨테이너를 제외하므로 `runner` 행(`ci/roundtrip/runner.sh`가
시드하는 GitHub 러너 VM)만 적습니다. `TestEveryScriptedControlIsInTheRoundtripTable`이 그 표,
배포되는 집합, CI 매트릭스를 같게 유지합니다.

파일이 말하는 내용을 고치는 본문(3D-2d 단계)은 다음 규칙을 더합니다:

- **일방향 런타임 변경 금지.** 본문은 재부팅만 되돌리는 변경을 결코 하지 않으며 — `-e 2`도,
  `--loginuid-immutable`도 없음 — 커널의 잠금 상태가 무엇이든, 어느 규칙 파일에든 그런 설정이
  대기 중이면 그 위에 감사 규칙을 적재하거나 auditd를 시작하지 않습니다. 그 밖의 모든 런타임
  효과는 `$MB` 아래 기록되어 rollback이 되돌려 놓거나, 실패한 블록 뒤에도 남는다고 컨트롤의
  텍스트에 적힙니다.
- **데몬은 이번 실행이 기록한 것에 대해서만 건드립니다.** 본문은 무엇이든 고치기 전에 데몬이
  돌고 있으면 `$MB/<daemon>.was-running`을 쓰고, 첫 쓰기 직전에 `$MB/<daemon>.edited`를
  만듭니다. 본문의 reload나 restart, 그리고 rollback의 그것은 두 표식이 모두 있어야 합니다.
  rollback은 프롤로그의 `restore <path>`를 먼저 부를 수 있습니다. 한 번의 실행을 서술하는
  기록(이 표식들, 쓴 키의 목록, 바꾼 계정의 목록)은 본문의 첫 동작으로 지우고 새로 씁니다.
  파일 백업과 rollback이 다시 재생하는 목록만 첫 사본을 유지합니다.
- **쓰는 값**은 적용 중인 목록에서 대상이 받아들이고 호스트를 살려 두는 첫 원소입니다
  (`audit_disk_actions`는 `email`, `exec`, `single`, `halt`를 결코 쓰지 않음). 내용을 금지하기만
  하는 절은 고정된 중립 문자열(`FTP server ready.`)로 충족할 수 있으며, 법적 고지문으로는 결코
  충족하지 않습니다.
- **지우지 말고 주석 처리.** 본문이 부적격으로 판정한 줄에는 `# muster: `를 앞에 붙이고, 그
  파일은 `backup`에 둡니다. 자기 파일을 쓰는 도구는 수집기와 같은 방식으로 파일을 읽는 곳에서
  씁니다(`postconf -e`). 키 하나보다 많이 다시 쓰는 도구(`useradd -D`)는 쓰지 않습니다.
- **안전하게 덧붙이기.** 끝 줄바꿈이 없을 수 있는 파일에 덧붙이기 전에:
  `if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi`.
- **수집기의 방식으로 읽고, 그것을 증명하기.** 본문의 읽기는 한 줄짜리
  `rd_<what>() { LC_ALL=C …; }` 함수입니다. validate가 그 판정을 다시 증명할 때는 같은 프로그램을
  되풀이하며, `internal/collect/collectors/remediation_parity_test.go`(Linux)가 각 읽기를 파서의
  fixture에 대해 실행해 Go 파서와 비교합니다. 본문, validate, rollback이 텍스트 출력을 파싱하는
  모든 명령은 `LC_ALL=C` 아래 돕니다(로캘과 무관한 출력 — `date +%s`, 숫자 `stat -c` 필드, `tail -c1`
  검사 — 은 필요 없음).
- **가드된 validate.** 세 모양 외에, validate는 본문이 로그로 남기는 남겨 둠을 한 줄의
  `[ guard ] || …`나 `{ …; } || { …; }` 묶음으로 받아들일 수 있습니다. 블록은 `done`으로 끝나고
  다음 `check`가 남겨 둔 것을 짚습니다.
- **SELinux.** `restorecon`은 도구가 바꿔 놓았거나 만든 파일(`postconf -e`, 새로 만든 파일)에서만
  돌고, `sed -i`나 `restore` 뒤에는 결코 돌지 않으며, `if command -v selinuxenabled >/dev/null
  2>&1 && selinuxenabled && command -v restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi`로
  씁니다.
- **업그레이드.** 본문이 제자리에서 고친 벤더 설정 파일은 다음 업그레이드 때 드러납니다 — dpkg(또는
  ucf)는 고친 conffile에 대해 묻고, rpm은 고친 내용을 두고 `.rpmnew`를 씁니다 — 그리고 패키지가
  설정 파일로 표시한 파일에 대해서는 텍스트가 그렇게 말합니다.
- **행이 줄 수 없는 증명.** 어떤 왕복 검증 행도 restart 경로를 돌릴 수 없는 데몬은 계획과 그
  단계의 설계에서 증명되지 않은 것으로 적고 stub 테스트를 두며, `_roundtrip.yaml`에는 적지
  않습니다(그 `unproven_units`는 선언된 유닛만 적음).

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
- 워크(`collect --deep`)는 고정 선언 밖을 읽도록 허가된 유일한 수집기입니다.
  `Declaration.Walk: true`는 어떤 경로든 `ReadDir`를 허용하지만, 이름으로 여는 모든
  파일(`/proc/self/mountinfo`, id 파일들, 컨테이너 런타임 설정 파일, dpkg 데이터베이스)은
  여전히 선언하며, 심링크는 결코 따라가지 않습니다. 발견 리스트는 상한이 있고 워크를
  멈추지 않으며 `truncated: true`로 말합니다. 들어가지 않은 루트는 닫힌 어휘의 사유를 가진
  `walk.skipped` 행입니다. dpkg 결합은 setuid 비트를
  `docs/reference/suid/<id>-<version_id>.json` — 공개 이미지의 대상 패키지가 가진 모든
  파일과 모드의 기준 목록 — 에 대조해 결정합니다. `go run ./tools/suidindex`(docker와
  네트워크. `-check`는 비교)로 재생성하고, 그 패키지 목록을 가이드나 벤치마크의 바이너리
  목록에서 가져오지 않습니다. 패키지는 이미지가 배포하는 것에서 오며 `sources.json`에
  사유를 하나씩 적습니다.

### 종료 코드가 데이터인 명령

수집기는 명령의 종료 코드만으로 성공·실패를 읽지 않습니다. `rpm -Va`는 "무언가
다르다"를 1로, `dnf check-update`는 "갱신이 대기 중"을 100으로 말하고, `needs-restarting
-r`은 "재부팅 필요"에 1을 내며, 인자 없는 `dpkg --verify`는 무엇을 찍었든 0으로 끝나고,
`auditctl`은 호출자에게 CAP_AUDIT_CONTROL이 없으면 4, 커널이 요청을 거부하면 255로
끝납니다. 이 순서로 분류하십시오 — 타임아웃, 시작 실패, 그다음 도구가 문서화한 코드와
메시지, 그 밖은 명령과 코드를 적은 `error` — 그리고 판정은 코드만이 아니라 출력에서
쓰십시오. 타임아웃은 `Command`에, 종료 코드는 봉투의 source(`Output.Source`)에
기록합니다.

## 테스트

- 헬퍼 테스트보다 호출자를 움직이는 테스트를 먼저 씁니다. 호출 지점을 추가한 뒤 그 호출을
  지우고 스위트가 빨개지는지 확인하세요. 초록으로 남으면 기능이 아니라 구현을 테스트한
  것입니다.
- 기능이 사라졌을 때 달라지는 것을 단언하세요. 부분 문자열보다 구조적 단언을 우선합니다.
- 골든: `go test ./internal/report -run TestJSON -update`, `-run TestTableGolden -update`,
  위의 팩트 골든, 그리고
  `go test ./internal/remedy -run 'TestScriptGolden|TestTableGolden|TestJSONGolden' -update`. 재생성된 골든은 커밋 전에 모두 검토합니다.
- 픽스처는 제 몫을 해야 합니다. `go test ./internal/controls -run
  TestEveryMutantIsKilled`는 모든 컨트롤을 변이시키고(연산자 뒤집기, 기대값 이동, 절과
  메커니즘 제거, `absent_means` 변경) 변이체마다 다르게 답하는 픽스처를 요구합니다.
  살아남은 변이체는 빠진 픽스처입니다 — 보여 주는 것을 이름으로 삼아 하나 추가하세요.
  수집기 불변식이나 닫힌 값 어휘 때문에 어떤 픽스처도 구별할 수 없는 변이체만
  `controls/testdata/_mutants.yaml`에 넣습니다. 한 줄에 하나, 그 불변식을 이름으로 부르는
  이유와 함께. 변이체가 죽었거나 더 이상 생성되지 않는 행이 있으면 테스트가 실패합니다.
- `internal/collect/collectors`와 `internal/pkgfiles`의 모든 파서 진입점에는 그 파서의
  testdata에서 시드를 얻는 `Fuzz<Name>` 타깃이 있고, `[]byte`를 받는 새 함수나 메서드에
  타깃이 없으면 `TestEveryParserHasAFuzzTarget`이 실패합니다(부모를 통해서만 닿는 헬퍼는
  `coveredThrough`에, 호스트 입력이 아닌 바이트는 이유와 함께 `notParsers`에 선언). `internal/profile`과 `internal/tuning`의 프로파일·튜닝 파서에도
  타깃이 하나씩 있습니다(`FuzzParseProfile`, `FuzzParseTuning`). 풀 리퀘스트는 시드만 돌리고,
  밤마다 도는 `fuzz.yml`이 모든 타깃을 하나에 1분씩 샤드 4개로 퍼징합니다.
  `make fuzz TARGET=<name> TIME=<duration>`은 하나를 로컬에서 돌리며, 수집기 밖의 타깃은
  `FUZZPKG=./internal/profile/`(또는 다른 패키지)로 고릅니다. 크래시는 Go가 `testdata/fuzz/` 아래에 쓰는 코퍼스 파일로 들어가고, 수정은
  별도 커밋입니다.
- `MUSTER_ORACLE=1 go test ./internal/collect/collectors -run Oracle`(Linux, root)은
  sshd·passwd/group·mountinfo·services 파서를 그 호스트의 `sshd -T`, `getent`, `findmnt`,
  `systemctl`과 비교합니다. CI는 root 잡과 init 컨테이너 안에서 돌립니다. 불일치는 파서
  결함이거나 테스트에 기록할 데몬 동작이지, 느슨하게 할 규칙이 아닙니다.
- `examples/`에는 `examples.yml` 워크플로가 수집한 스냅샷 두 개 — `ubuntu:24.04` 컨테이너와
  러너 VM — 가 호스트 정체를 지운 형태로 있고, `cmd/muster`의 예시 테스트가 끝까지
  검사합니다. `make examples-fetch RUN=<id>`가 워크플로 실행에서 갱신합니다. 사설 호스트의
  스냅샷으로 바꿔 넣지 마세요.
- CI는 race 빌드, lint, coverage 검사, 러너 VM에서의 root 수집, 비root 수집, 컨테이너
  매트릭스(Ubuntu 22.04/24.04, Rocky 9, AlmaLinux 9, Debian 12는 카나리), 읽기 전용 계약
  실행, 데몬 오라클, 검토용 스크립트와 `ci/roundtrip/*.sh`에 대한 `sh -n`과 shellcheck, `fix-roundtrip` 잡(시드한
  실패를 생성된 스크립트가 Rocky 9, AlmaLinux 9, 잡 안에서 빌드한 Debian 12 init 이미지,
  Ubuntu 22.04의 일회용 컨테이너와, 컨테이너가 판정할 수 없는 `beyond` 컨트롤까지 증명하는
  러너 VM 자체에서 고침. 각 init 행에서는 두 번째 컨테이너가 guard 실행 —
  첫 컨테이너에서 계획한 스크립트가 거부됨 — 과 failure 실행 — 모든 블록의 validate를 강제로
  실패시키면 유닛, 파일, 모드, sysctl 값, 모듈이 기록한 대로 되돌아가야 함 — 을 증명. 러너
  행에는 guard 실행이 없고, failure 실행을 위해 같은 VM에 다시 시드함), 그리고 capability matrix(`docs/reference/capability-matrix.json`:
  root 없이 `denied`여야 하는 팩트와 systemd 없이 `unsupported`여야 하는 팩트)를 돌립니다.

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
