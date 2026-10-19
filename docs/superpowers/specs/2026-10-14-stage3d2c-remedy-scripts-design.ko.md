# 3D-2c단계 — 열여섯 너머의 스크립트: 파라미터, 상태 기록, runner 행

영어 원본: `2026-10-14-stage3d2c-remedy-scripts-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`(§6.2
스키마, §6.8 lint, §7.5 `fix --dry-run`, §10.2 로드맵, D24, D34). 이 사이클이 딛고 서는 설계:
`2026-10-07-stage3d2-fix-dry-run-design.ko.md`(X-1..X-10)와 `2026-10-13-stage3d2b-remedy-proof-design.ko.md`
(Q-1..Q-6). 이 설계의 판정은 E 목록이며, E-8..E-12는 1차 스펙 리뷰(렌즈 다섯, 발견마다 반박자 셋, 크리틱)에서,
E-13은 2차 리뷰(접은 초안에 대한 렌즈 넷)에서 나왔고 둘 다 제자리에 접어 넣었습니다. 본문을 쓸 때 참고한 묶음별 지도는 이 사이클의 무시되는 작업 공간 파일
`family-map.md`이며, 구속력이 있는 사실은 여기에 다시 적었습니다. 8절은 구현이 이 글과 달라진 곳을 적으며, 둘이 어긋나면 8절이
구현된 설계입니다.

## 1. 범위와 의도

control 16개가 `script`를 가집니다. 없는 101개 중 88개가 `auto`이고, 그중 32개의 본문은 정형입니다. sysctl 줄을
쓰고 적용하기, modprobe 줄을 쓰고 모듈을 내리기, 모드 비트 지우기, 설정 줄 바꾸기, sshd drop-in 쓰기입니다.
나머지는 호스트마다 판단이 필요해(어느 파티션을 나눌지, 어느 리스너를 허용할지, 어느 계정을 잠글지) 텍스트로
남습니다. 이 사이클은 그 32개에 스크립트를 붙이고(scripted control은 모두 48개), 그것들이 필요로 하는 기제 둘을
만듭니다. 파라미터 값이 스크립트에 닿는 길과, 파일 내용이 아닌 상태(모드, sysctl 값, 올라간 모듈)를 기록하고
되돌리는 길입니다.

- **E-1 — 파라미터는 텍스트 치환이 아니라 블록 변수로 스크립트에 닿는다.** control이 `script_params`를
  적습니다. 템플릿은 블록 함수의 첫 줄들로 `P_<name>='<값>'`을 내보내므로 본문, validate, 선언된 rollback이 모두
  봅니다. 값은 적용 중인 값(기본값, 프로파일, 튜닝)이고, 그 타입의 문자 집합에 맞을 때만 줄에 들어갑니다. 아니면
  그 항목은 텍스트만 됩니다(`params_unsafe`). `params_tuned` 규칙은 `script_params`를 선언하지 않은 scripted
  control에만 적용됩니다(§2).
- **E-2 — 상태는 블록마다 기록한다.** 블록이 남기는 모든 기록(파일 복사본, 유닛 상태, 경로의 모드, sysctl 값,
  모듈 적재 상태)은 `$MUSTER_BACKUP/blocks/<fn>/` 아래에 있습니다. 그래서 블록은 앞선 블록이 본 상태가 아니라
  자기가 본 상태로 되돌립니다. `backup_path_shared`와 `units_shared` lint는 없어집니다. 두 블록이 같은 경로나
  유닛을 선언할 수 있고, 뒤의 블록은 앞의 블록이 남긴 상태로 되돌립니다. 선언된 백업 경로가 없었으면 없었다고
  기록하고 복원 때 지웁니다(§3).
- **E-3 — 상태 종류 셋을 더한다.** `modes`(경로의 소유자·그룹·모드·종류. `dir/*` 패턴은 `find`로 펼치며 숨김 파일
  포함, 심볼릭 링크 제외), `sysctl`(키의 runtime 값), `modules`(올라가 있는지). 각각 프롤로그에
  `save_`/`restore_` 헬퍼가 있고, 실패 경로는 파일 복원 앞뒤로 정해진 순서로 이들을 실행합니다(§3).
- **E-4 — 본문.** sysctl 16개, 모듈 3개, 파일 권한 9개, 계정 3개, sshd 1개를 3D-2b의 규율로 씁니다. 비트는
  지우기만 하고 설정하지 않습니다. drop-in을 쓰고 배포판 파일은 건드리지 않습니다. 호스트가 대야 하는
  값(계정 이름, `/var/log` 아래 경로)은 스크립트가 호스트에서 열거하지 스냅샷에서 읽지 않습니다(§4). 기존
  스크립트 하나(`root_remote_login`)는 rollback을 그대로 둡니다(E-11).
- **E-5 — absent가 늘 절망은 아니다.** control은 `script_on_absent: true`를 선언할 수 있습니다. 그러면 평가기가
  `absent_means: fail`로 이른 FAIL도 스크립트와 함께 계획됩니다. 스크립트가 쓰는 것이 바로 그 없는
  줄(`PASS_MIN_LEN`, `ClientAliveInterval`)이기 때문입니다. 다른 모든 control에는 3D-2 규칙(X-2, Z-6)이
  그대로입니다(§2).
- **E-6 — 컨테이너가 못 하는 증명은 러너가 한다.** 모든 `beyond` control은 `env.container eq none`으로
  가드되므로 sysctl·모듈·bootloader·audit log 스크립트는 호스트에서만 판정됩니다. `fix-roundtrip`에 docker 없이
  GitHub 러너 VM 자체에서 시드·수리·실패를 하는 `runner` 행이 생깁니다. 가드 실행은 없고(호스트가 하나), 실패
  실행은 같은 VM을 다시 시드하고 계획을 새로 세웁니다(§5).
- **E-7 — 판정은 바뀌지 않는다.** `checks`와 fact는 바뀌지 않습니다. 리스트 파라미터 하나의 기본 순서를 바꿔
  첫 요소가 가이드가 말하는 값이 되게 합니다(`umask_policy.acceptable`). `op: in`은 순서를 보지 않습니다.
  `controls/VERSION`이 올라갑니다. 위험도 넷이 바뀝니다. 포워딩 control 둘과 `usb_storage_disabled`는
  `restart_service`로, `password_policy`는 `lockout_risk`로. plan JSON에 `script_params`, `script_on_absent`,
  `modes`, `sysctl`, `modules`와 롤백 값 `state`가 추가되고, plan 스키마는 1을 유지합니다.
- **E-8 — 본문은 현재 값이 절의 허용 집합 밖일 때만 쓴다.** `in [1,2]`나 `gte 2`로 판정되는 sysctl 키가 이미
  절을 만족하면 그대로 둡니다. `login.defs` 줄, `faillock` 줄, `pwquality` 키, 계정의 ageing 필드는 조이는
  방향으로만 바꾸고, 게이트는 collector가 읽는 방식대로 값을 읽습니다(`login.defs`는 첫 줄, `faillock.conf`는
  마지막 줄, `pwquality`는 합친 체인). 써야 할 때 쓰는 값은 가이드의 값이거나 적용 중인 목록의 첫 요소입니다.
  단, 가이드 값이 일방향이면 목록에서 되돌릴 수 있는 값을 씁니다(`unprivileged_bpf_disabled` 2, §4.1). 그래서
  본문은 더 엄격한 호스트를 절대
  느슨하게 하지 않고, 절이 이미 받아들이는 키를 조이지 않으며(`rp_filter` 2는 2로 남음), 이미 통과하는 일방향
  값(`unprivileged_bpf_disabled` 1, `ptrace_scope` 3)을 건드리지 않습니다. validate는 쓴 값과의 일치가 아니라
  집합 소속을 증명합니다(§4.1, §4.4).
- **E-9 — `find` 규율.** 호스트에 없을 수 있는 디렉터리에 대한 `find`나 `chmod`는
  `if [ -d <dir> ] && [ ! -L <dir> ]; then …; fi` 아래에서, 단일 경로는 `if [ -f p ] && [ ! -L p ]` 아래에서
  실행합니다. 모드를 바꾸는 모든 `find`는 `! -type l`이나 control이 판정하는 종류(스풀에는 `-type f`)를 가집니다.
  validate의 `find`는 허용 비트의 여집합 — 07777에서 허용되는 가장 큰 모드를 뺀 것(`≤ 0640` → `-perm /7137`,
  `≤ 0600` → `/7177`, `≤ 0440` → `/7337`) — 과, uid를 판정하는 곳에는 `! -user root`를 검사합니다. 본문은
  심볼릭 링크를 통해 chmod하지 않습니다(§4.3).
- **E-10 — `password_policy`는 `lockout_risk`이고 조이기만 한다.** ageing 루프는 collector의 규칙(비어 있지 않고
  `!`나 `*`로 시작하지 않는 shadow 필드)으로 계정을 열거하고, 최대값이 비었거나 파라미터보다 클 때만 `-M`을,
  최소값이 더 작을 때만 `-m`을 적용하며, 비밀번호가 이미 `max_days`보다 오래된 계정(쓰면 그 자리에서 만료)은
  건너뛰고 로그에 남기고, 계정마다 이전 필드를 `$MB` 아래에 기록해 선언된 rollback이 `chage`로 되돌립니다.
  `/etc/shadow`는 절대 복사하지 않습니다. 필드는 처음부터 끝까지 `:`로 구분해 나르므로 빈 필드를 잃지
  않습니다(§4.4).
- **E-11 — 데몬이 다시 읽는 파일을 스크립트가 쓰는 control의 선언된 rollback은 그 파일을 스스로 지우고 나서
  검사·reload한다.** `restore`의 absent 표지 처리는 그러면 무해한 두 번째 처리입니다. sshd control 둘은
  `rm -f` 줄을 유지하고(새 것은 얻고), 3D-2의 실패 경로 순서(선언된 rollback 먼저, `restore` 나중)는
  그대로입니다(§3, §4.4).
- **E-12 — modules 헬퍼는 `--ignore-install`로 다시 올린다.** 기록은 모듈이 올라가 있었다고 말합니다.
  `restore`가 방금 되돌려 놓은 `install … /bin/false` 줄을 따르는 `restore_modules`는 결코 다시 올릴 수
  없습니다. 그래서 runner 실패 실행은 재시드 뒤에 다시 수집하고 계획을 새로 세우며, 시드는 같은 블록이 계획되도록
  muster의 drop-in을 지웁니다(§3, §5).
- **E-13 — 다른 판정 키에 대한 쓰기의 부작용은 쓰는 쪽이 책임진다.** `net.ipv4.ip_forward`를 쓰면 커널이
  `net.ipv4.conf.all.accept_redirects`를 반대 값으로 바꿉니다. `ip_forwarding_disabled` 본문은 쓰기 전에 그 키를
  읽고 쓴 뒤에 되돌려 놓습니다. runtime으로, 그리고 자기 drop-in에서 `ip_forward` 다음 줄로. 그 키는 그 control의
  `sysctl` 목록에 있고, 고정 테스트는 그것을 선언된 유일한 동반 키로 인정합니다. 플랜의 사전 점검은 열여섯
  control의 키 사이의 다른 부작용을 기록합니다(§4.1).

## 2. 스크립트의 파라미터 (E-1, E-5)

**스키마.** `Remediation`에 `ScriptParams []string`(`yaml:"script_params,omitempty"`)과 `ScriptOnAbsent bool`
(`yaml:"script_on_absent,omitempty"`)이 추가됩니다. 항목은 파라미터 이름입니다. 리스트 파라미터는 요소를 공백
하나로 이어 통째로 나릅니다. 첫 요소가 필요한 본문은 `first=${P_<name>%% *}`로 꺼내고(shellcheck가 SC2086으로
잡는 `set --`는 쓰지 않음), 소속이 필요한
validate는 `case " $P_<name> " in *" $(…) "*) ;; *) false;; esac`라는 `case` 하나 관용구를 씁니다. 블록 변수는
`P_<name>`입니다.

**lint**(control 단위. 각각 `TestLintRules` 케이스):
- `script_params_declared` — 모든 항목이 control의 `params` 키를 한 번씩 가리켜야 합니다.
- `script_params_used` — `script`, `validate`, `rollback`의 모든 `$P_<name>`/`${P_<name>`가 선언되어 있고,
  선언된 모든 항목이 `script`에서 쓰여야 합니다.
- `script_params_needs_script`, `script_on_absent_needs_script`.
- `script_params_default_safe` — 항목이 가리키는 기본값이 모두 문자 집합(아래)을 통과해야 합니다.

**타입별 문자 집합.** `int`: `^-?[0-9]+$`. `bool`: `true` 또는 `false`. `string`과 `list<string>`의 각 요소:
`^[A-Za-z0-9._/@:+,=-]+$`. `list<int>`의 각 요소: `int`와 같음. 리스트 전체는 요소를 공백 하나로 이은 것이라
본문이 `for x in $P_<name>`으로 돕니다. 어떤 값도 따옴표, (요소 안의) 공백, `$`, 백틱, `;`, `|`, `&`, `\`를
담을 수 없으므로 `'…'`가 그것을 데이터로 지킵니다.

**값이 설 수 있는 자리.** `P_` 값은 (a) `key=$P_x` 단어의 `=` 뒤, (b) 옵션 글자의 피연산자(`-M "$P_max_days"`)나
`--` 뒤, (c) 첫 번째가 아닌 피연산자, (d) awk `-v` 변수, (e) 구분자가 `|`인 `sed` `s` 명령의 치환문(문자 집합
밖. `&`와 `\`도 밖이라 치환문은 리터럴)으로만 명령에 들어갑니다. 값은 줄의 첫 자리나 앞의 `-`가 옵션으로 읽힐
자리에 절대 서지 않습니다. CONTRIBUTING이 그렇게 말하고, Linux 테스트가 배포되는 모든 본문에서 `$P_`를 나르는
`s/` 명령과 `$P_`나 `"$P_`로 시작하는 줄을 grep합니다.

**계획.** `Item`에 `ScriptParams []ParamValue`(`json:"script_params"`, 항상 있고 `Script`가 false이거나 선언이
없으면 `[]`. `ParamValue{Name, Value string}`, json `name`/`value`, 이름 순 정렬 — map 없음, 같은 입력 같은
바이트)와 `ScriptOnAbsent bool`(`json:"script_on_absent"`: control의 선언을 `Script`가 true일 때만 복사, 아니면
`false`)이 추가됩니다. 항목의 필드 순서는 `…, script, text_only_reason, script_params, script_on_absent,
rollback, backup, units, modes, sysctl, modules, validate, planned`입니다. `remedy.Build`는 적용 중인 값을 check
블록의 `Params[id][name]`(3D-1이 기록하는 합쳐진 값)에서 읽고, 문자열로 만들고(리스트는 공백 하나로 이음), 문자
집합을 검사합니다. 문자 집합에 어긋나면 그 항목은 텍스트만 되고 `text_only_reason: params_unsafe`입니다
(스크립트의 문구: `a parameter value cannot be carried safely; see muster check --format json: check.params`).
그때 `script_params`는 `[]`라서 안전하지 않은 값은 JSON에도 닿지 않습니다. `params_tuned` 분기는 control이
`script_params`를 선언하지 않았고 어떤 출처가 `default`가 아닐 때만 적용됩니다.

**absent.** 행의 reason이 `check.ReasonAbsentFailPrefix`로 시작하고 control이 `script_on_absent: true`를
선언했으면 그 항목은 스크립트를 가집니다. 아니면 3D-2의 `absent` 텍스트 전용 사유가 그대로입니다.

**렌더링.** 블록 함수는 항목마다 이름 순으로 `P_<name>='<값>'` 한 줄씩으로 열리고(`MB=` 앞), 본문 subshell,
validate subshell, 선언된 rollback subshell이 이를 물려받습니다. `UNITS='…'`는 본문 subshell의 첫 줄로
남습니다. `templateLines`는 정확히 렌더된 `P_` 줄만 인정합니다. poison 계획에는 `script_params: [bad]`를 선언하고
적용 중인 값이 `'; id; '`인 control이 들어갑니다. 그 항목은 텍스트만으로 렌더되고, 그 값은 주석이 아닌 어느
줄에도, JSON 어디에도 나오지 않습니다.

**D34, 한 번 더 수정.** "호스트 값은 명령에 치환되지 않는다"는 예외 하나(machine-id 해시)를 그대로 둡니다.
파라미터 값은 호스트 값이 아닙니다. 운영자가 프로파일이나 튜닝 파일에 선언한 정책이고, 위 문자 집합에 묶여
`P_` 대입으로만 명령에 들어갑니다. 메인 설계의 `internal/remedy` 행은 해시와 `P_` 대입을 인정되는 두 비리터럴
부류로 적고, 둘 다 `templateLines`가 강제합니다.

## 3. 상태 기록 (E-2, E-3, E-11, E-12)

**블록별 디렉터리.** 블록 함수는 무엇이든 기록하기 전에 `MB="$MUSTER_BACKUP/blocks/<fn>"`을 정하고 만듭니다
(`mkdir` 실패는 `backup failed, nothing changed`). 그 아래:

| 종류 | 위치 | 기록 |
|---|---|---|
| 파일 복사본 | `$MB/files<경로>` | 3D-2처럼 경로의 `cp -a` |
| 없던 파일 | `$MB/absent<경로>` | 빈 표지: 선언된 경로가 없었음 |
| 유닛 | `$MB/units/<u>`, `<u>.deps` | 3D-2b처럼 |
| 모드 | `$MB/modes.list` | 경로마다 한 줄: `<uid> <gid> <mode> <type> <경로>`(`type`은 `f`, `d`, `o`) |
| sysctl | `$MB/sysctl.list` | 키마다 한 줄: `<키> <값>`(읽을 수 없으면 `absent`) |
| 모듈 | `$MB/modules.list` | 모듈마다 한 줄: `<이름> loaded\|not-loaded` |
| ageing | `$MB/ageing.list` | `password_policy` 본문이 씀: `<계정> <min> <max>`(§4.4) |

경로, 유닛, 키, 모듈의 첫 기록은 전처럼 같은 `MUSTER_BACKUP`으로 실행해도 유지되지만, 블록마다입니다. 블록 B의
기록은 A가 실행된 뒤 B가 본 것입니다. absent 표지는 대체되는 유일한 기록입니다. 뒤의 실행에서 경로가 있으면
`backup`은 표지를 지우고 복사본을 뜹니다(`save_units`가 유닛이 생기면 `absent absent`를 대체하듯).
`backup_path_shared`, `units_shared`, `backup_reserved` lint는 지웁니다. `units_exclusive`는 `units` 옆에
`rollback`, `backup`, `modes`, `sysctl`, `modules`를 두는 것을 막도록 넓어집니다(서비스 블록의 되돌릴 길은 유닛
상태 하나입니다).

**`backup`과 `restore`**, 그대로(복사 분기는 3D-2의 것):

```sh
backup() {
  for p in "$@"; do
    if [ -e "$p" ] || [ -L "$p" ]; then
      if [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then log "$p: backup exists, keeping the first"; continue; fi
      rm -f "$MB/absent$p"
      mkdir -p "$MB/files$(dirname "$p")" && cp -a "$p" "$MB/files$p" || return 1
    else
      if [ -e "$MB/absent$p" ] || [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; then continue; fi
      mkdir -p "$MB/absent$(dirname "$p")" && : > "$MB/absent$p" || return 1
    fi
  done
}
restore() {
  brc=0
  for p in "$@"; do
    if [ -e "$MB/absent$p" ]; then
      if [ -d "$p" ] && [ ! -L "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
      rm -f "$p" || { log "restore: $p failed"; brc=1; }
      continue
    fi
    { [ -e "$MB/files$p" ] || [ -L "$MB/files$p" ]; } || continue
    if [ -d "$p" ]; then log "restore: $p is now a directory, left as is"; brc=1; continue; fi
    if [ -L "$p" ]; then rm -f "$p" || { log "restore: $p failed"; brc=1; continue; }; fi
    cp -a "$MB/files$p" "$p" || { log "restore: $p failed"; brc=1; }
  done
  return $brc
}
```

한 경로에 표지와 복사본이 함께 있는 일은 없습니다. 1회차에 복사되고 2회차에 사라진 경로는 복사본을 유지하고
표지를 받지 않으므로, 실패하면 복원됩니다. drop-in을 만드는 스크립트는 실패 때 `restore`가 파일을
지워 줍니다. 데몬이 그 파일을 다시 읽는 control은 자기 rollback에서 먼저 지웁니다(E-11). 선언된 rollback이
`restore`보다 먼저 실행되고, reload는 파일이 사라진 것을 봐야 하기 때문입니다.

**`modes`.** 항목은 절대·정규 경로에 `/*`가 0~2개 붙은 것입니다(lint `modes_charset`:
`^/[A-Za-z0-9._@:+/-]+(/\*){0,2}$`, 중복 없음. `script` 없는 `modes`, `sysctl`, `modules` 목록은
`state_needs_script`). lint `modes_backup_overlap`: 같은 control의
`backup` 경로가 `modes` 항목과 같거나 그 항목에 매치되면 안 됩니다(`modes: [/etc/sudoers.d/*]` 옆의
`/etc/sudoers`는 괜찮고, `/etc/sudoers.d/x`는 안 됨). 그 밖에는 두 필드가 함께 있을 수 있습니다. 헬퍼는 항목을
`find <dir> -mindepth k -maxdepth k ! -type l`로 펼칩니다. `k`는 `/*`의 개수입니다(`k = 0`: 경로가 있고 심볼릭
링크가 아니면 그 자체). 숨김 파일은 포함되고 심볼릭 링크는 제외되는데, 이것이 collector의 시각입니다. 템플릿은
모든 항목을 작은따옴표로 묶어 내보내므로(`save_modes '/etc/cron.d/*' '/etc/crontab'`. 문자 집합은 `'`를 허용하지
않음) 셸이 `*`를 펼치는 일이 없습니다. `templateLines`는 따옴표 묶인 줄을 인정하고, CI의 `record()`도 헬퍼의
펼치기를 같은 방식으로 부릅니다.

```sh
modes_paths() { # one path per line for one entry
  case "$1" in
    */\*/\*) find "${1%/\*/\*}" -mindepth 2 -maxdepth 2 ! -type l 2>/dev/null;;
    */\*) find "${1%/\*}" -mindepth 1 -maxdepth 1 ! -type l 2>/dev/null;;
    *) if [ -e "$1" ] && [ ! -L "$1" ]; then printf '%s\n' "$1"; fi;;
  esac
  return 0
}
modes_type() { if [ -f "$1" ]; then echo f; elif [ -d "$1" ]; then echo d; else echo o; fi; }
save_modes() {
  [ -f "$MB/modes.list" ] || : > "$MB/modes.list" || return 1
  for spec in "$@"; do
    modes_paths "$spec" | while IFS= read -r p; do
      P="$p" awk '{ q=$0; sub(/^[^ ]+ [^ ]+ [^ ]+ [^ ]+ /, "", q); if (q == ENVIRON["P"]) f=1 } END { exit !f }' "$MB/modes.list" && continue
      if s=$(stat -c '%u %g %a' -- "$p" 2>/dev/null); then
        printf '%s %s %s\n' "$s" "$(modes_type "$p")" "$p" >> "$MB/modes.list" || exit 1
      elif [ -e "$p" ]; then
        exit 1
      else
        log "save_modes: $p vanished, not recorded"
      fi
    done || return 1
  done
}
restore_modes() {
  mrc=0
  while read -r uid gid mode t p; do
    if [ ! -e "$p" ] && [ ! -L "$p" ]; then continue; fi
    if [ -L "$p" ] || [ "$(modes_type "$p")" != "$t" ]; then log "restore_modes: $p changed type, left as is"; mrc=1; continue; fi
    if chown -- "$uid:$gid" "$p"; then chmod -- "$mode" "$p" || mrc=1; else mrc=1; fi
  done < "$MB/modes.list"
  return $mrc
}
```

이름에 줄바꿈이 있거나 공백으로 끝나는(`read`가 잘라냄) 경로는 지원하지 않습니다(문서에 한계로 적음. 선언된
트리 어디에도 없습니다). 경로 안의 공백은 경로가 마지막 필드라서 `read -r`을 살아남습니다. 중복 검사는 경로를
백슬래시 이스케이프를 처리하는 `awk -v`가 아니라 `ENVIRON`으로 넘깁니다. `find`와 `stat` 사이에 사라진 경로(`/var/log` 아래의
logrotate)는 로그로 남기고 건너뛰지, 백업 실패가 아닙니다. `restore_modes`는 심볼릭 링크를 통해 쓰지 않고, 파일의
기록을 디렉터리에(또는 그 반대로) 적용하지 않습니다. 블록 중에 호스트가 바꿔치운 기록 항목은 로그로 남기고
미완료로 셈하므로, 스풀의 소유자가 기록을 `/etc/shadow`에 대한 `chmod`로 바꿀 수 없습니다.

**`sysctl`.** 항목은 커널 키입니다(lint `sysctl_charset`: `^[a-z0-9_]+(\.[a-z0-9_-]+)+$`, 중복 없음). `sysctl`과 `backup`은 함께 갑니다. 파일은 persisted 쪽, 기록은 runtime 쪽입니다.

```sh
save_sysctl() {
  [ -f "$MB/sysctl.list" ] || : > "$MB/sysctl.list" || return 1
  for k in "$@"; do
    awk -v k="$k" '$1 == k { f=1 } END { exit !f }' "$MB/sysctl.list" && continue
    v=$(sysctl -n -- "$k" 2>/dev/null) || v=absent
    printf '%s %s\n' "$k" "$v" >> "$MB/sysctl.list" || return 1
  done
}
restore_sysctl() {
  src=0
  for k in "$@"; do
    v=$(awk -v k="$k" '$1 == k { $1=""; sub(/^ /, ""); print; exit }' "$MB/sysctl.list")
    case "$v" in ''|absent) continue;; esac
    sysctl -q -w -- "$k=$v" || src=1
  done
  return $src
}
```

**`modules`.** 항목은 모듈 이름입니다(lint `modules_charset`: `^[a-z0-9_-]+$`, 중복 없음).
헬퍼는 `-`를 `_`로 접고(kmod의 규칙) 첫 필드가 이미 접혀 있는 `/proc/modules`를 읽습니다. `restore_modules`는
`--ignore-install`로 다시 올립니다(E-12). 기록은 "loaded"라고 말하고, modprobe.d가 지금 무엇을 말하든 상관
없습니다. 블록 시작 때 파일이 있었다면 `restore`가 방금 muster 자신의 `install … /bin/false` 줄을 되돌려
놓았고, 벤더의 `install` 줄도 같은 방식으로 건너뜁니다(문서에 적음).

```sh
save_modules() {
  [ -f "$MB/modules.list" ] || : > "$MB/modules.list" || return 1
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    awk -v m="$n" '$1 == m { f=1 } END { exit !f }' "$MB/modules.list" && continue
    if grep -q "^$n " /proc/modules; then s=loaded; else s=not-loaded; fi
    printf '%s %s\n' "$n" "$s" >> "$MB/modules.list" || return 1
  done
}
restore_modules() {
  orc=0
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    [ "$(awk -v m="$n" '$1 == m { print $2; exit }' "$MB/modules.list")" = loaded ] || continue
    modprobe --ignore-install -- "$n" || orc=1
  done
  return $orc
}
```

**프롤로그.** 3D-2b의 줄들 뒤 순서: `backup()`, `restore()`, `save_units()`, `restore_units()`,
`modes_paths()`, `modes_type()`, `save_modes()`, `restore_modes()`, `save_sysctl()`, `restore_sysctl()`,
`save_modules()`, `restore_modules()`, `failed=0`. 모든 헬퍼 줄은 기본 심각도에서 shellcheck를 통과합니다(면제
형태 밖의 `A && B || C` 없음).

**블록.** 머리는 순서대로 `P_` 줄들, `MB=…; mkdir -p "$MB"`, `backup <p…>`, `save_units <u…>`,
`save_modes '<e>'…`, `save_sysctl <k…>`, `save_modules <m…>`이고 각각 `|| { log "<id>: backup failed, nothing
changed"; return 1; }`가 붙습니다. 그다음 본문 subshell입니다. 실패 경로는 순서대로 선언된 `rollback`,
`restore_units <u…>`, `restore_modes`(인자 없이: 블록의 목록을 읽음), `restore <p…>`(파일과 absent 표지),
`restore_sysctl <k…>`, `restore_modules <m…>`입니다. 스크립트의 값을 지속시킬 파일이 사라진 뒤에 runtime 값을
다시 적용하고, `install … /bin/false` 줄이 사라지거나 되돌아간 뒤에 모듈을 다시 올립니다. 실패한 복원마다
`ROLLBACK INCOMPLETE`를 남기고 다음 복원은 계속 실행합니다. 헬퍼는 자기 변수(`spec`, `p`, `s`, `t`, `k`, `v`,
`m`, `n`, `mrc`, `src`, `orc`)만 쓰고 블록의 `rc`는 쓰지 않습니다. `TestScriptEveryLineIsTemplateBodyOrComment`는
`P_` 줄, `MB` 줄, 기록 줄 다섯(`backup`, `save_units`, `save_modes`, `save_sysctl`, `save_modules`), 복원 줄
다섯(`restore_units`, `restore_modes`, `restore`, `restore_sysctl`, `restore_modules`)을 각각의 접미어와 함께
인정합니다.

**계획.** `Item`에 `Modes`, `Sysctl`, `Modules []string`(json `modes`, `sysctl`, `modules`, `units` 뒤. 없으면
`[]`, `Script`가 true일 때만 채움)이 추가됩니다. `Build`는 항목마다 lint 패턴으로 다시 검사하고 어긋나면 계획을
거부합니다(id와 유닛처럼). `Item.Rollback`은 control의 선언으로 정해지는 여섯 단어 중 하나가 됩니다.

| 단어 | 선언 |
|---|---|
| `none` | 없음(텍스트 전용 항목) |
| `declared` | `rollback`만 |
| `restore_backup` | `backup`만 |
| `units` | `units`(옆에 아무것도 설 수 없음) |
| `state` | `modes`, `sysctl`, `modules` 중 하나 이상, 그 밖에 없음 |
| `both` | `rollback`, `backup`, 상태(`modes`/`sysctl`/`modules`는 하나로 셈) 중 둘 이상 |

표의 열은 그 단어를 보여 줍니다.

**테스트.** stub 없는 테스트가 임시 트리에서 `save_modes`/`restore_modes`를 돌립니다(숨김 파일, 심볼릭 링크,
디렉터리 항목, 두 단계 패턴, 아무것도 안 맞는 패턴, 공백이 든 경로, 재실행에서 첫 기록 유지, 기록된 파일이
심볼릭 링크나 디렉터리로 바뀌면 그대로 두고 `ROLLBACK INCOMPLETE`, 쓸 수 없는 경로에서 `ROLLBACK INCOMPLETE`),
그리고 표지 경우들에 `backup`/`restore`를 돌립니다(1회차 없고 2회차 있음 → 복사, 두 번 다 없음 → 복원 때 제거,
1회차 복사·2회차 없음 → 표지 없음, 복사본 복원, 표지의 경로가 지금 디렉터리 → 로그). stub `sysctl`과
`modprobe`(3D-2b의 `systemctl` stub처럼 `PATH` 맨 앞에 두고, 인자를 로그로 남기며, stub만 읽는 환경변수를 통해
fixture 파일로 답함)가 나머지 둘을 돕니다. 배포되는 헬퍼는 리터럴 `/proc/modules`를 유지하고, 테스트는 Go
상수에서 뽑아낸 헬퍼 텍스트의 그 리터럴을 fixture로 바꿔 씁니다(`strings.ReplaceAll`). 경우: 읽히는 키, `absent` 키, 쓰기를 거부하는 키. argv에 `--ignore-install`을 달고 다시 올라가는 모듈, 그대로
두는 모듈, 실패하는 `modprobe`. 실패 경로 순서 테스트는 모든 종류를 선언한 블록에서 실패 경로 여섯 단계(rollback
subshell과 복원 다섯)의 순서를 확인합니다. 3D-2b의 유닛 테스트는 `$MB/units/`로 옮깁니다.

## 4. 본문 (E-4, E-8, E-9, E-10, E-11)

모든 본문은 POSIX `sh`이고, 기본 심각도에서 shellcheck를 통과하며, 본문 subshell 안에서 `set -e`에 안전하고,
리터럴 경로와 `P_` 변수와 호스트에서 열거한 것만 씁니다. 존재 가드는 `if [ -f p ] && [ ! -L p ]; then …; fi`로
쓰고 `[ -f p ] && …`로 쓰지 않습니다(마지막 줄의 거짓 검사는 subshell을 실패시킵니다). validate는 `&&`로 이은
조건들, 마지막 arm이 `*) false`인 `case` 하나, 또는 각 조건이 `|| exit 1`로 끝나는 리터럴 목록에 대한 `for`
하나입니다(모듈 validate. CONTRIBUTING은 이 사이클에서 세 번째 모양을 인정합니다). 모든 control은
`idempotent: true`(이미 모두 그렇습니다)와 적용 중인 값에 대해 그 단계를 증명하는 한 줄 `validate`를 가집니다.
텍스트는 문장을 유지하고, 스크립트가 생긴 곳은 쓰는 파일을 이름 붙입니다.

### 4.1 sysctl (16)

이 묶음의 fact는 runtime 쪽으로 판정됩니다(`default_on: effective`). 판정은 `/proc/sys`입니다. persisted 쪽은
증거입니다. 그래서 본문은 둘 다 합니다. 다음 부팅을 위해 파일을 쓰고, 지금 값을 적용합니다. 단, 현재 값이 절의
허용 집합 밖인 키에만 합니다(E-8). 파일: `/etc/sysctl.d/99-muster-<name>.conf`. `<name>`은 control 이름의 `_`를
`-`로 바꾼 것입니다(`99-muster-syn-cookies-enabled.conf`. control마다 하나라서 블록마다 자기 백업을 가짐).
systemd의 `50-default.conf`·`50-coredump.conf`와 Ubuntu의 `10-*.conf` 뒤, `99-sysctl.conf` →
`/etc/sysctl.conf` 앞에 정렬됩니다. `/etc/sysctl.conf`가 같은 키를 두는 호스트는 그 persisted 값을 유지하고,
텍스트가 그렇게 말합니다. 키마다 한 줄, 값 줄에 주석 없음(collector에게 끝의 `#`은 값의 일부입니다). 파일에는
본문이 쓴 키의 줄만 씁니다(파일에 이미 그 키가 있으면 바꾸고, 없으면 덧붙임). 지금 통과하는 키의 줄은
유지하므로 파일은 절대 비워지지 않습니다. 표가 달리 말하지 않으면 위험도 `none`. `syn_cookies_enabled`의 모양:

```yaml
  sysctl: [net.ipv4.tcp_syncookies]
  backup: [/etc/sysctl.d/99-muster-syn-cookies-enabled.conf]
  script: |
    f=/etc/sysctl.d/99-muster-syn-cookies-enabled.conf
    case "$(sysctl -n net.ipv4.tcp_syncookies)" in
      1) ;;
      *) sysctl -q -w net.ipv4.tcp_syncookies=1
         if grep -q '^net.ipv4.tcp_syncookies ' "$f" 2>/dev/null; then sed -i 's|^net.ipv4.tcp_syncookies .*|net.ipv4.tcp_syncookies = 1|' "$f"
         else printf '%s = %s\n' net.ipv4.tcp_syncookies 1 >> "$f"; fi;;
    esac
    if [ -f "$f" ]; then chmod 644 "$f"; fi
  validate: "case \"$(sysctl -n net.ipv4.tcp_syncookies)\" in 1) ;; *) false;; esac"
```

여러 키의 본문은 키마다 `case`를 되풀이하고(허용 arm은 절의 목록이거나, `gte`이면 `[2-9]|[1-9][0-9]*`),
파라미터로 움직이는 본문은 §2의 리스트 관용구를 씁니다. 목표는 `first=${P_allowed_sysrq%% *}`, 검사는
`case " $P_allowed_sysrq " in *" $(sysctl -n kernel.sysrq) "*)`.

| control | 키 → 허용 집합 → 밖일 때 쓰는 값 | params / 위험도 |
|---|---|---|
| `aslr_and_link_protection` | `kernel.randomize_va_space` `{2}` → 2; `fs.protected_symlinks` `{1}` → 1; `fs.protected_hardlinks` `{1}` → 1; `fs.protected_fifos` `{1,2}` → 1; `fs.protected_regular` `{1,2}` → 2 | — |
| `icmp_broadcast_and_bogus_ignored` | `net.ipv4.icmp_echo_ignore_broadcasts` `{1}` → 1; `net.ipv4.icmp_ignore_bogus_error_responses` `{1}` → 1 | — |
| `icmp_redirects_ignored` | `net.ipv4.conf.{all,default}.{accept,secure,send}_redirects` `{0}` → 0(키 6개) | — |
| `ip_forwarding_disabled` | `net.ipv4.ip_forward` `allowed_forward` → 첫 요소; 동반 키 `net.ipv4.conf.all.accept_redirects`는 쓰기 전에 읽고 뒤에 되돌림(E-13) | `script_params: [allowed_forward]`; `sysctl`에 두 키; 위험도 `restart_service` |
| `ipv6_forwarding_disabled` | `net.ipv6.conf.{all,default}.forwarding` `allowed_forward` → 첫 요소 | `script_params: [allowed_forward]`; 위험도 `restart_service` |
| `ipv6_redirects_ignored` | `net.ipv6.conf.{all,default}.accept_redirects` `{0}` → 0 | — |
| `ipv6_router_advertisements_ignored` | `net.ipv6.conf.{all,default}.accept_ra` `allowed_accept_ra` → 첫 요소 | `script_params: [allowed_accept_ra]` |
| `ipv6_source_routing_rejected` | `net.ipv6.conf.{all,default}.accept_source_route` `{0}` → 0 | — |
| `kernel_pointer_exposure` | `kernel.kptr_restrict` `{1,2}` → 1; `kernel.dmesg_restrict` `{1}` → 1 | — |
| `ptrace_restriction` | `kernel.yama.ptrace_scope` `{1,2,3}` → 1; `kernel.perf_event_paranoid` `≥ 2` → 2 | — |
| `reverse_path_filtering` | `net.ipv4.conf.{all,default}.rp_filter` `{1,2}` → 1; `net.ipv4.conf.{all,default}.log_martians` `{1}` → 1 | — |
| `source_routing_rejected` | `net.ipv4.conf.{all,default}.accept_source_route` `{0}` → 0 | — |
| `suid_dumpable_disabled` | `fs.suid_dumpable` `{0}` → 0 | — |
| `syn_cookies_enabled` | `net.ipv4.tcp_syncookies` `{1}` → 1 | — |
| `sysrq_restricted` | `kernel.sysrq` `allowed_sysrq` → 첫 요소 | `script_params: [allowed_sysrq]` |
| `unprivileged_bpf_restricted` | `kernel.unprivileged_bpf_disabled` `{1,2}` → 2; `net.core.bpf_jit_harden` `{1,2}` → 2 | — |

- 각 키의 허용 집합은 절의 목록이나 경계이고, `TestSysctlScriptsNameTheControlsKeys`(§5)가 키 집합과 함께
  고정합니다. 일방향 값을 안전하게 하는 것이 E-8입니다. `unprivileged_bpf_disabled = 1`(control의 텍스트가
  말하고 STIG가 요구하는 값. 커널은 이후 모든 쓰기를 거부)이나 `yama.ptrace_scope = 3`인 호스트는 그 키를
  통과하고 본문은 절대 쓰지 않으므로, `bpf_jit_harden`이나 `perf_event_paranoid` 하나 때문에 실행되는 블록이
  성공합니다. `unprivileged_bpf_disabled`를 써야 할 때 본문은 계속 쓸 수 있고 목록에 있는 `2`를 씁니다. 텍스트는
  `1`과 `3`을 스크립트가 건드리지 않는 값으로 적습니다.
- 튜닝된 `in` 목록은 허용 집합이자 목표 목록입니다. 본문은 첫 요소를 쓰고 validate는 어느 요소든 받아들입니다.
  그래서 `0`인 호스트의 `allowed_sysrq: [176]`은 check를 FAIL시키고 본문이 `176`을 씁니다. 프로파일이 그렇게
  말했고, 행의 reason이 적용 중인 값을 보여 줍니다.
- `core_dump_policy`는 텍스트로 남습니다. `partial`이고, 메커니즘으로 판정되며, runtime 쪽(`core_pattern`)에는
  persisted 읽기가 없습니다.
- IPv6 control 넷은 `ipv6_disabled eq 0`으로 가드되어 본문에 가드가 필요 없습니다. Yama가 없는 호스트는
  `script_on_absent` 없는 `absent_means: fail`이라 지금처럼 텍스트만입니다. `unprivileged_bpf_restricted`는
  `absent_means: not_applicable`이라 BPF JIT 키가 없는 호스트는 NOT_APPLICABLE이고 계획되지 않습니다.
- `ip_forwarding_disabled`와 `ipv6_forwarding_disabled`의 위험도는 이제 `restart_service`입니다. 라우터나
  컨테이너 호스트에서 `0`을 쓰면 포워딩이 바로 끊깁니다. 나머지는 `none`입니다.
- E-13: 커널은 `ip_forward`가 바뀔 때마다 `net.ipv4.conf.all.accept_redirects`를 `!forwarding`으로 바꿉니다.
  docker 호스트에서는 `all.accept_redirects`가 0이라(포워딩이 켜져 있음) `icmp_redirects_ignored`는 그 키를
  통과하고 E-8에 따라 그대로 둡니다. 계획에서 뒤에 실행되는 포워딩 블록이 그것을 1로 바꿀 것입니다. 그래서 포워딩
  본문은 키를 저장하고, `ip_forward`를 쓰고, 저장한 값을 다시 쓰고, 자기 drop-in에서 `ip_forward` 다음 줄로
  지속시킵니다(부팅 때 `sysctl.d` 처리는 줄 순서대로 적용하므로 거기서도 뒤집힘이 되돌려짐). 고정 테스트는 그 동반
  키 하나를 인정합니다.

### 4.2 모듈 (3)

`disabled`는 올라가 있지 않고, 내장이 아니고, modprobe.d 체인에 `install … /bin/false`가 있거나 배포되지
않았다는 뜻입니다. 그래서 본문은 줄을 쓰고 모듈을 내립니다. 파일: `/etc/modprobe.d/99-muster-<name>.conf`
(`<name>`은 §4.1과 같음). kmod는 modprobe.d를 파싱할 때와 `--showconfig`를 출력할 때 모듈 이름을 밑줄로 접으므로,
control의 `where` 목록이 어떻게 적혀 있든 본문은 접힌 이름(`usb_storage`)을 쓰고 validate는 접힌 이름을
읽습니다. kmod는 디렉터리를 가로질러 기본 이름 순으로 처음 읽은 `install`을 지키므로, 그 모듈에 `install` 줄을
가진 벤더 파일이 `99-muster-…`를 이깁니다. validate는 유효한(첫) `install` 줄을 읽으므로 그런 블록은 validate에
실패해 롤백되고, 텍스트가 그 경우를 말합니다(측정한 이미지에서 열한 모듈 중 그런 것은 없음). 위험도:
`usb_storage_disabled`는 `restart_service`로 바뀝니다(내려간 `usb-storage`는 마운트된 USB 디스크를 떨어뜨림).
uncommon 모듈 control 둘은 `none`으로 남습니다. 사용 중인 모듈은 `modprobe -r`을 실패시켜 블록이 롤백되기
때문입니다.

```yaml
  modules: [cramfs, freevxfs, jffs2, hfs, hfsplus, udf]
  backup: [/etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf]
  script: |
    f=/etc/modprobe.d/99-muster-uncommon-filesystems-disabled.conf
    for m in cramfs freevxfs jffs2 hfs hfsplus udf; do
      n=$(printf '%s' "$m" | tr - _)
      grep -q "^install $n " "$f" 2>/dev/null || printf 'install %s /bin/false\n' "$n" >> "$f"
      if grep -q "^$n " /proc/modules; then modprobe -r -- "$n"; fi
    done
    chmod 644 "$f"
  validate: "for m in cramfs freevxfs jffs2 hfs hfsplus udf; do n=$(printf '%s' \"$m\" | tr - _); [ \"$(modprobe --showconfig 2>/dev/null | awk -v m=\"$n\" '$1 == \"install\" && $2 == m { print $3; exit }')\" = /bin/false ] || exit 1; ! grep -q \"^$n \" /proc/modules || exit 1; done"
```

실패하는 `modprobe -r`(모듈 사용 중)은 본문을 실패시킵니다. 호스트가 그 모듈을 쓰는 것이니 블록은 롤백됩니다.
내장 모듈은 control을 FAIL로 두고, 텍스트는 다른 커널만이 길이라고 말합니다. initramfs는 다시 만들지
않습니다(텍스트). 본문의 모듈 이름은 control 자신의 `where` 목록을 리터럴로 되풀이한 것이고, §5의 고정 테스트가
접은 뒤 둘이 같은지 지킵니다. 어느 CI 행도 돌릴 수 없는 `usb-storage` 본문(§5)에는 stub `modprobe` 테스트가
`--showconfig`에 접힌 철자로 답합니다.

### 4.3 파일 권한 (9)

3D-2b처럼 control이 소유자를 판정하는 곳은 `chown root:root`, 비트만 지우는 기호식 `chmod`, 경로 하나를 판정하는
곳은 기본 모드에 대한 `case` validate입니다. 글롭 집합은 E-9 아래에서 `modes`와 `find`를 씁니다. 없을 수 있는
디렉터리는 `if [ -d ]`로 가드하고, 모드를 바꾸는 모든 `find`는 `! -type l`(control이 파일만 판정하면 `-type f`)을
가지며, validate의 `find`는 허용 비트의 여집합을 검사합니다. 표에서 "`find F …`"는 그 가드 아래의
`find <dir> -mindepth 1 -maxdepth 1 -type f …`를 뜻합니다.

| control | 기록 | 본문 | validate |
|---|---|---|---|
| `sudoers_permissions` | `backup: [/etc/sudoers]`, `modes: [/etc/sudoers.d/*]` | `chown root /etc/sudoers; chmod u-wxs,g-wxs,o-rwxt /etc/sudoers`; `find F /etc/sudoers.d ! -name '*.*' ! -name '*~' -exec chmod go-w {} +` | `[0,40,400,440]`에 대한 `case`(control은 uid만 판정: 형식 `%u %a`, 접두어 `0`) `&&` `find F … -perm /g+w,o+w`가 비어 있음 |
| `nfs_export_access` | `backup: [/etc/exports]` | `if [ -f ] && [ ! -L ]`: `chown root; chmod u-xs,g-wxs,o-wxt`(control은 uid만 판정) | `[ ! -f p ] \|\| [ -L p ] \|\|` 16개 모드에 대한 `case`, `%u %a`, `0` — 가드 덕분에 exports가 `/etc/exports.d`에만 있는 호스트가 validate에 실패하지 않음 |
| `bootloader_config_permissions` | `backup: [/boot/grub/grub.cfg, /boot/grub2/grub.cfg]` | 정규 파일이고 심볼릭 링크가 아닌 것마다: `chown root:root; chmod u-xs,g-rwxs,o-rwxt` | 경로마다 `[ ! -f p ] \|\| [ -L p ] \|\|` `[0,200,400,600]`에 대한 `case`, `0 0`, `&&`로 이음 |
| `inetd_conf_permissions` | `backup: [/etc/inetd.conf, /etc/xinetd.conf]`, `modes: [/etc/xinetd.d/*]` | 있는 conf마다: `chown root; chmod u-xs,g-rwxs,o-rwxt`; `find F /etc/xinetd.d -exec chmod go-w {} +` | `/etc/inetd.conf`는 있으면 `stat` 비트(`g-w`, `o-r`, uid 0), `/etc/xinetd.conf`는 있으면 `[0,200,400,600]`에 대한 `case`(`%u %a`, `0`), 조각은 `find F … -perm /g+w,o+w`가 비어 있음 |
| `audit_log_permissions` | `modes: [/var/log/audit/audit.log, /var/log/audit]` — `backup` 없음: 살아 있는 로그는 절대 복사하지 않음 | `if [ -f ]`: `chown root /var/log/audit/audit.log; chmod u-xs,g-wxs,o-rwxt …`; `if [ -d ]`: `chown root /var/log/audit; chmod g-w,o-rwx /var/log/audit` | 8개 모드에 대한 `case`(`%u %a`, `0`) `&&` 디렉터리 비트 |
| `syslog_conf_permissions` | `backup: [/etc/rsyslog.conf, /etc/systemd/journald.conf, /etc/syslog-ng/syslog-ng.conf]`, `modes: [/etc/rsyslog.d/*, /etc/systemd/journald.conf.d/*, /etc/syslog-ng/conf.d/*]` | 있는 파일마다: `chown root; chmod u-xs,g-wxs,o-rwxt`; 있는 디렉터리마다: `find F … -name '*.conf' -exec chown root {} + -exec chmod u-xs,g-wxs,o-rwxt {} +` | 파일마다 `[ ! -f p ] \|\|` `stat` 검사; 디렉터리마다 `find F … -name '*.conf' \( -perm /7137 -o ! -user root \)`가 비어 있음 |
| `cron_permissions` | `modes: [/etc/crontab, /etc/anacrontab, /etc/cron.allow, /etc/cron.deny, /etc/at.allow, /etc/at.deny, /etc/cron.d/*, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, /etc/cron.hourly/*, /etc/cron.daily/*, /etc/cron.weekly/*, /etc/cron.monthly/*, /var/spool/cron/*, /var/spool/cron/crontabs/*, /var/spool/cron/atjobs/*, /var/spool/at/*, /etc/cron.d, /var/spool/cron, /var/spool/cron/crontabs, /var/spool/cron/atjobs, /var/spool/at]` | 시스템·접근 파일(`if [ -f ]`, `find F /etc/cron.d`): `chown root; chmod u-xs,g-wxs,o-rwxt`; 주기 스크립트(네 디렉터리에 `find F`): `chown root; chmod o-w`(`+x`는 유지: run-parts는 실행 비트 없는 파일을 건너뜀); cron 스풀(`find F /var/spool/cron`, `find F /var/spool/cron/crontabs`): `chmod u-xs,g-wxs,o-rwxt`(uid ≥ 1000이 소유한 스풀은 맞는 것. `/var/spool/cron` 아래의 `crontabs`/`atjobs` 디렉터리는 스풀 처리가 절대 건드리지 않음); at 스풀(`find F /var/spool/cron/atjobs`, `find F /var/spool/at`): `chmod g-wxs,o-rwxt`만 — at는 `u+x`로 작업이 실행 가능함을 표시하므로 이를 지우면 작업이 취소됨; 디렉터리 아홉(`if [ -d ]`): `chmod o-w` | 시스템·접근 집합 `-perm /7137` 비어 있음 `&&` `! -user root` 비어 있음; 주기 `-perm /o+w -o ! -user root` 비어 있음; cron 스풀 `-perm /7137` 비어 있음; at 스풀 `-perm /7037` 비어 있음; 디렉터리 `-perm /o+w` 비어 있음 — 각각 `find F`/`[ -d ]`로 가드된 절 |
| `log_dir_permissions` | `modes: [/var/log, /var/log/*, /var/log/*/*]` | `find /var/log -maxdepth 2 ! -type l -perm /o+w -exec chmod o-w {} +` — other 쓰기 가능 쪽만. 그룹 쪽(`allowed_groups` 밖 그룹의 그룹 쓰기 가능 항목)은 텍스트로 남음: `/var/log/postgresql` root:postgres 1775는 데몬 자신의 디렉터리이고, 거기서 `chmod g-w`는 그 로깅을 멈춤 | 같은 `find`가 비어 있음 |
| `ftpusers_permissions` | `backup: [/etc/ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd/user_list, /etc/vsftpd.user_list, /etc/vsftpd.ftpusers]` | 있는 것마다: `chown root:root; chmod u-xs,g-wxs,o-rwxt`; 절대 만들지 않음(빈 허용 목록은 모든 로그인을 막음) | 경로마다 `[ ! -f p ] \|\|` 8개 모드에 대한 `case`, `&&`로 이음 |

- `sudoers_permissions`는 `u-w`도 지웁니다. 목표가 `0440`이고, `visudo`는 제자리가 아니라 임시 복사본을 통해
  파일을 씁니다.
- `log_dir_permissions`는 `script_params`를 선언하지 않습니다. 본문이 `allowed_groups`를 읽지 않으므로 튜닝된
  목록에는 3D-2의 `params_tuned` 텍스트 전용 규칙이 그대로입니다. 스크립트 뒤에도 목록 밖 그룹의 그룹 쓰기 가능
  항목이 있는 호스트에서는 control이 FAIL로 남을 수 있고, 블록의 `done`은 다음 `check`로 그렇게 말합니다(X-10).
  텍스트는 두 선택지(chgrp, 또는 파라미터에 그룹을 적기)를 유지합니다.
- `bootloader_config_permissions`는 정규 파일이고 심볼릭 링크가 아닌 `grub.cfg`에만 손댑니다. UEFI에서 업그레이드한
  EL 호스트(`/boot/grub2/grub.cfg` → EFI 시스템 파티션, K-28)와 collector가 `/boot/efi/EFI/*/grub.cfg`를 읽은
  곳에서는 파일이 vfat 위에 있어 모드가 마운트의 `umask`/`fmask`이고 `chmod`를 조용히 무시합니다. 본문은 그대로
  두고, validate는 건너뛰고, 텍스트는 ESP의 모드는 `chmod`가 아니라 `fstab`(`fmask=0177`)으로 고친다고 말합니다.
- `audit_log_permissions`는 리터럴 기본 경로에 손댑니다. collector는 `auditd.conf`의 `log_file`이 이름 붙이는
  경로를 판정합니다. 다른 `log_file`을 가진 호스트에서는 리터럴이 없어 본문은 아무것도 하지 않고(가드), control은
  FAIL로 남고, 텍스트가 그 파일을 운영자의 것으로 이름 붙입니다.
- `cron_permissions`: 대기 중인 at 작업(at의 계약상 0700)은 스크립트 뒤에도 control을 FAIL로 둡니다. at 스풀의
  판정은 판정 사이클로 미룹니다(§7).
- `files.*` collector가 읽는 고정 경로의 심볼릭 링크는 설계상 `error`이므로(C4) 그 항목은 ERROR이고 계획되지
  않습니다. 3D-2b의 파일 본문 다섯은 `[ -f ]` 가드를 유지합니다. 새 단일 경로 본문은 collector가 심볼릭 링크가
  가리키는 경로를 판정할 수 있으므로 모두 E-9 가드를 씁니다.
- `TestFileValidatesAcceptTheDefaultModes`는 카테고리가 아니라 명시적 id 표로 고르고 3D-2b의 다섯(`hosts`,
  `hosts_lpd`, `passwd`, `services`, `shadow`)에 머뭅니다 — validate가 정확히 `backup[0]`과 기본 `allowed_modes`에
  대한 `case` 하나인 control들입니다. `nfs_export_access`(가드 있음), `sudoers_permissions`(`case`에 `find`를 더한
  것), `bootloader_config_permissions`(경로 둘)는 lint와 왕복 검증으로 확인합니다. 테스트는 배포되는 다른 어떤
  scripted control도 순수 `case` validate를 갖지 않음을 단언합니다. 두 번째 테스트는 모든 validate `find` 마스크를
  control의 `allowed_modes`에서 유도해(07777에서 허용되는 가장 큰 모드를 뺀 것) 배포 텍스트와 비교합니다.
  `TestFileScriptsRepairOnARealFile`에 `nfs_export_access`와 심볼릭 링크 경로 경우(그대로 두고 validate가
  건너뜀)가 들어갑니다.

### 4.4 계정과 sshd (새 넷, 바뀐 하나)

| control | 기록 | 본문 | params / absent / 위험도 |
|---|---|---|---|
| `password_policy` | `backup: [/etc/login.defs, /etc/security/pwquality.conf.d/99-muster.conf]`; `rollback`은 `$MB/ageing.list`를 재생 | `login.defs`: `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_MIN_LEN`마다 주석 아닌 모든 줄을 다시 씀(`sed -i -E "s\|^([[:space:]]*PASS_MAX_DAYS)[[:space:]].*\|\1 $P_max_days\|"`. shadow-utils는 마지막을, muster는 첫 줄을 읽음) 없으면 덧붙임 — 현재 첫 값이 없거나 더 느슨할 때만(E-8); `pwquality`: `mkdir -p /etc/security/pwquality.conf.d`와 `chmod 755`(Debian은 배포하지 않음), 그다음 키마다 합친 값(`pwquality.conf`, 그다음 `conf.d/*.conf`를 이름 순으로, 마지막이 이김 — collector의 읽기)이 없거나 더 작을 때만 `99-muster.conf`에 `minlen = $P_min_len` / `minclass = $P_min_classes`를 쓰고 `chmod 644`; 그다음 `today=$(( $(date +%s) / 86400 ))`로 두고 `awk -F: -v OFS=: '$2 != "" && $2 !~ /^[!*]/ { print $1, $3, $4, $5 }' /etc/shadow`가 나열하는 모든 계정을 `IFS=: read -r name last min max`로 읽어: `last`가 비었거나 `0`이거나 `[ $((today - last)) -gt "$P_max_days" ]`이면 건너뛰고 로그(쓰면 지금 만료됨); 아니면 `$MB/ageing.list`에 `name:min:max`를 기록(빈 필드는 chage의 "제한 없음"인 `-1`로 씀; 첫 기록 유지)하고 `max`가 비었거나 더 크면 `chage -M "$P_max_days"`, `min`이 비었거나 더 작으면 `chage -m "$P_min_days"` | `script_params: [max_days, min_days, min_len, min_classes]`; `script_on_absent: true`; 위험도 `lockout_risk`(`keep a second session open` 머리글); validate: 주석 아닌 첫 `PASS_MAX_DAYS` ≤ `$P_max_days`, `PASS_MIN_DAYS` ≥ `$P_min_days`, `PASS_MIN_LEN` ≥ `$P_min_len`, 합친 `minlen` ≥ `$P_min_len`, `minclass` ≥ `$P_min_classes` — `&&`로 이음; ageing 루프는 검증하지 않음(건너뛴 계정은 다음 check에서 WARN, X-10) |
| `umask_policy` | `backup: [/etc/login.defs]` | `first=${P_acceptable%% *}`; 주석 아닌 첫 `UMASK` 값이 `$P_acceptable`에 없으면 주석 아닌 모든 `UMASK` 줄을 `UMASK $first`로 다시 씀(없으면 덧붙임) | `script_params: [acceptable]`; 기본 목록을 `["027", "022", "077", "0027", "0022", "0077"]`로 재배열; validate: 주석 아닌 첫 값이 목록에 있음(`case " $P_acceptable "` 관용구) |
| `lockout_threshold` | `backup: [/etc/security/faillock.conf]` | 주석 아닌 마지막 `deny` 값(collector와 pam_faillock의 읽기)이 없거나, 1보다 작거나, `$P_max_attempts`보다 크면 주석 아닌 모든 `deny` 줄을 `deny = $P_max_attempts`로 다시 씀(없으면 덧붙임) | `script_params: [max_attempts]`; `script_on_absent` 없음(`deny`가 absent이면 faillock이 PAM에 없는 것); validate: 마지막 값이 ≥ 1이고 ≤ `$P_max_attempts`; pam_faillock 줄의 `deny=` 인자는 파일을 이기며 텍스트로 남음 |
| `session_timeout` | `backup: [/etc/ssh/sshd_config.d/00-muster-session.conf]`; `rollback`: drop-in `rm -f`, `sshd -t`, reload(E-11) | `root_remote_login`처럼 `command -v sshd`로 가드하고 `ClientAliveInterval $P_max_interval`과 `ClientAliveCountMax $P_max_count`를 쓰고 `chmod 644`, `sshd -t`, 실행 중인 `sshd`/`ssh` reload | `script_params: [max_interval, max_count]`; `script_on_absent: true`(적용되는 메커니즘이 없음 ⇒ drop-in이 하나를 적용되게 함); validate: `command -v sshd` `&&` 평범한 `sshd -T`(`-C` 없음: 판정되는 fact에 persona가 없음)가 두 값을 ≥ 1이고 ≤ 파라미터로 읽음 — 그래서 sshd가 없는 호스트(TMOUT 메커니즘만 길이고 그것은 텍스트)와, 더 앞의 값(`Include` 앞이나 `00-`보다 먼저 정렬되는 drop-in)이 drop-in을 이기는 호스트는 `done` 대신 validate에 실패함 |
| `root_remote_login` | 그대로. rollback은 `rm -f`를 유지(E-11) | — | — |

- `password_policy`의 runtime 쪽(`pass_max_days`/`pass_min_days`는 양쪽을 판정)은 `chage` 루프가 필요하고,
  없으면 행은 WARN(`not applied`)으로 끝나지 PASS가 되지 않습니다. 비밀번호가 이미 `max_days`보다 오래되어
  루프가 건너뛴 계정은 runtime 쪽을 파라미터 위에 머물게 하므로 행은 WARN으로 끝나고 로그가 계정을 이름 붙입니다.
  운영자가 그 비밀번호를 먼저 바꾸고 스크립트를 다시 실행합니다. 선언된 rollback은 `$MB/ageing.list`를 읽어
  줄마다 `chage -m <min> -M <max>`를 실행합니다(빈 필드는 chage의 "제한 없음"인 `-1`). `pam.pwquality.enabled`는
  호스트의 PAM 스택이 말하는 대로입니다. `libpam-pwquality`가 없는 Debian 계열 호스트에서는 스크립트 뒤에도
  control이 FAIL로 남고, 텍스트는 계속 설치하라고 말합니다.
- `password_hash_algorithm`과 `account_inactivity_lock`은 텍스트로 남습니다(재해시. `login_capable`에 대한
  계정별 `chage`는 runner 행이 증명할 수 있지만 audit 묶음과 함께 3D-2d로 읽는 편이 낫습니다).
- `lockout_threshold` 본문은 EL 행에서 증명합니다. 시드가 `authselect enable-feature with-faillock`으로
  faillock을 쌓습니다. Debian 12는 faillock용 `pam-auth-update` 프로파일을 배포하지 않아 그 이미지에서 뺍니다.
- `session_timeout`과 `root_remote_login`은 둘 다 sshd가 다시 읽는 파일을 씁니다. 그 rollback은 `sshd -t`와
  reload 앞에 drop-in을 지우므로, 실행 중인 데몬이 파일에 더는 없는 설정을 유지하는 일이 없습니다(E-11). init
  행의 실패 실행은 reload가 제거 뒤에 일어났음을 단언합니다(저널이 `rm` 뒤의 reload를 보여 주고, `sshd -T`가
  시드 전 값을 읽음).

## 5. 증명 (E-6, E-12, E-13)

**runner 행.** `fix-roundtrip`의 matrix에 `{key: runner, kind: host, seeded: …}`가 생기고, 컨테이너 행에는
`kind: container`가 붙습니다. run 블록의 `x()`는 컨테이너 행에서 `docker exec "$cid"`를, 호스트 행에서 `sudo`를
실행하고, 경로는 접두어만 다릅니다(`/m/muster` ↔ `./bin/muster`, `/out` ↔ `$d/repair`, `/ci` ↔
`ci/roundtrip`). 수리 실행은 같습니다. 실패 실행에는 두 번째 컨테이너가 없습니다. job은
`ci/roundtrip/runner.sh`를 다시 실행하고(멱등: muster가 쓴 모든 파일 — `/etc/sysctl.d/99-muster-*.conf`,
`/etc/modprobe.d/99-muster-*.conf`, `/etc/ssh/sshd_config.d/00-muster-session.conf`,
`/etc/security/pwquality.conf.d/99-muster.conf` — 를 지우고, 모든 sysctl 시드를 `sysctl -w`로 다시 적용하고,
시드한 모듈을 `modprobe --ignore-install`로 다시 올리고, 모든 파일 시드를 무조건 적용함), 다시 수집하고 계획을 새로 세우고(3D-2b 규칙: 수리
실행의 스크립트를 절대 재사용하지 않음), 기록하고, 깨뜨린 사본을 실행하고, 비교합니다. job은 실패 계획의 scripted
id가 수리 계획의 것과 같음을 단언합니다. 이 행에는 가드 실행이 없고, job은 `fix.host_guard`가 `on`인지
확인합니다(VM에는 machine id가 있습니다). 이 행은 docker를 절대 띄우지 않고(`ip_forward`와 `rp_filter`
스크립트가 docker 브리지가 필요로 하는 것을 바꿈), `audit_log_permissions`를 위해 `auditd`를 설치합니다.

**`record()`**에 계획된 scripted 항목마다 추가됩니다. 모든 `.sysctl[]` 키의 `sysctl -n`, 모든 `.modules[]` 이름의
적재 상태, 모든 `.modes[]` 항목이 펼쳐지는 경로의 `stat -c '%u %g %a'`(스크립트에서 뽑아낸 프롤로그 자신의
`modes_paths`로, 항목을 따옴표로 묶어). `.backup[]` 체크섬은 그대로입니다. 계획되는 어떤 control도 데몬이
덧붙여 쓰는 파일을 백업하지 않습니다.

**runner 시드**(`ci/roundtrip/runner.sh`), control마다:

| control | 시드 |
|---|---|
| sysctl control 열여섯 | control마다 실패 값 하나를, stock 읽기와 상관없이 두 실행 모두에서 `sysctl -w`로 씀(이미지에 무관): `kernel.randomize_va_space=0`, `net.ipv4.icmp_echo_ignore_broadcasts=0`, `net.ipv4.conf.default.accept_redirects=1`, `net.ipv4.ip_forward=1`, `net.ipv6.conf.all.forwarding=1`, `net.ipv6.conf.default.accept_redirects=1`, `net.ipv6.conf.default.accept_ra=1`, `net.ipv6.conf.all.accept_source_route=1`, `kernel.kptr_restrict=0`, `kernel.yama.ptrace_scope=0`, `net.ipv4.conf.default.log_martians=0`, `net.ipv4.conf.default.accept_source_route=1`, `fs.suid_dumpable=2`, `net.ipv4.tcp_syncookies=0`, `kernel.sysrq=176`, `net.core.bpf_jit_harden=0` — 사전 점검이 각각 쓸 수 있고 control을 FAIL시키는지 확인 |
| `uncommon_filesystems_disabled`, `uncommon_network_protocols_disabled` | `modprobe udf`, `modprobe sctp`, `modprobe tipc`(러너 커널이 배포하는 모듈. 나머지는 `unproven_units`) |
| `usb_storage_disabled` | 없음: `unproven`(커널이 `usb-storage`를 배포하지 않음) |
| `bootloader_config_permissions` | `chmod 644 /boot/grub/grub.cfg` |
| `audit_log_permissions` | `chmod 644 /var/log/audit/audit.log`(0640은 허용 모드. 모드만: 본문은 그룹을 바꾸지 않음) |
| `session_timeout` | 이미지 자신의 가장 이른 `ClientAliveInterval` 줄을 제자리에서 900으로 다시 씀(러너 이미지는 `00-muster-session.conf`보다 뒤에 정렬되는 `/etc/ssh/sshd_config.d/50-cloudimg-settings.conf`에 120을 둠). 사전 점검이 값이 있는 곳을 기록하고, 값이 `Include` 앞에 있는 이미지는 시드할 수 없고 증명할 수 없음(어떤 drop-in도 이길 수 없음) |
| `umask_policy` | `UMASK 002` |
| `cron_permissions`, `syslog_conf_permissions`, `sudoers_permissions`, `inetd_conf_permissions` | 컨테이너 행과 같음(아래) |
| `password_policy` | 시드가 `libpam-pwquality`를 설치할 때만 — 사전 점검이 정함 |

**컨테이너 시드**(`ci/roundtrip/<key>.sh`), 새 control마다 — 사전 점검이 각각 확인:

| control | 시드 |
|---|---|
| `sudoers_permissions` | 모든 이미지에 `sudo` 설치; `chmod 644 /etc/sudoers` |
| `cron_permissions` | EL 행은 `cronie` 설치; `chmod 644 /etc/crontab` |
| `syslog_conf_permissions` | 이미지에 없으면 `rsyslog` 설치, 또는 `ubuntu2204`에 `/etc/rsyslog.conf`를 심음; 그것에 `chmod 644` |
| `inetd_conf_permissions` | `install -m 644 /dev/null /etc/inetd.conf` |
| `nfs_export_access` | `install -m 666 /dev/null /etc/exports`(init 행) |
| `ftpusers_permissions` | `vsftpd` 설치(control이 FTP 데몬으로 가드됨); 그 접근 파일에 `chmod 644`(init 행) |
| `log_dir_permissions` | `install -m 666 /dev/null /var/log/ci.log` |
| `umask_policy` | `/etc/login.defs`에 `UMASK 002` |
| `password_policy` | EL 행: 오늘 바꾼 해시 있는 계정; `PASS_MAX_DAYS 99999` |
| `lockout_threshold` | EL 행: `authselect enable-feature with-faillock`, `deny = 99` |
| `session_timeout` | EL 행: `00-muster-session.conf`보다 뒤에 정렬되는 drop-in에 `ClientAliveInterval 900` |

**표.** 새 scripted control은 모두 `_roundtrip.yaml`에 들어갑니다. 플랜의 사전 점검이 확정할 가설:

| control | 행 |
|---|---|
| sysctl 16, 모듈 3, `bootloader_config_permissions`, `audit_log_permissions` | `runner`만(`beyond` 가드). bootloader control의 ESP 부류는 증명되지 않음(러너의 `/boot`는 ext4) |
| `usb_storage_disabled` | `unproven`: 러너 커널은 `usb-storage`를 배포하지 않아 거기서는 통과함. uncommon 모듈 control 둘은 커널이 배포하지 않는 모듈마다 `unproven_units`를 가짐 |
| `cron_permissions`, `syslog_conf_permissions`, `sudoers_permissions`, `inetd_conf_permissions` | 컨테이너 행 넷(EL 행은 `cronie`/`sudo` 설치. inetd는 파일로 심음. EL9에는 패키지 없음)과 `runner` |
| `nfs_export_access`, `ftpusers_permissions` | init 행(모드만 시드. `ubuntu2204`에는 systemd 없음) |
| `log_dir_permissions` | 컨테이너 행 넷(`install -m 666 /dev/null /var/log/ci.log`). 러너는 아님 — `/var/log/postgresql`의 그룹 비트, 본문이 텍스트에 남기는 쪽으로 stock에서 FAIL |
| `umask_policy` | 다섯 행 모두(시드 `UMASK 002`) |
| `password_policy` | EL 행(authselect가 pwquality를 쌓음. 오늘 바꾼 해시 있는 계정을 시드)과, 시드가 `libpam-pwquality`를 설치할 때만 `runner` — 사전 점검이 정함 |
| `lockout_threshold` | EL 행(`authselect enable-feature with-faillock`, `deny = 99`) |
| `session_timeout` | EL 행과 `runner` |

**표 테스트.** `TestEveryScriptedControlIsInTheRoundtripTable`은 `kind`를 읽습니다. `host` 행에는 `init`이
없습니다. `muster.beyond.*` id는 `host` 행만 적을 수 있습니다. `muster.service.*` id는 `init: "false"`인 행을 적을
수 없습니다. `unproven_units`의 키는 control의 `units`, `modules`, `sysctl` 중 하나에 선언되어 있어야 합니다.

**고정 테스트.** `TestSysctlScriptsNameTheControlsKeys`(Linux, sysctl 리프 표 옆): control의 `sysctl` 목록은
집합으로서 그 절들이 판정하는 fact의 커널 키와 같아야 하며, 리프 표에 `coredump.suid_dumpable →
fs.suid_dumpable`(coredump collector의 상수)을 더해 대응시키고, `net.ipv4.conf.all.accept_redirects`를
`ip_forwarding_disabled`의 선언된 유일한 동반 키로 인정합니다(E-13). 테스트는 본문도 렌더해 각 키의 `case`의 허용
arm이 절의 목록이나 경계인지 확인합니다. `TestModuleScriptsNameTheControlsModules`: control의 `modules` 목록은
`-`를 `_`로 접은 뒤 그 `where` 목록과 같아야 합니다. 둘 다 무엇을 대체하지 않는 새 테스트입니다.

## 6. lint, 테스트, 문서

**lint 요약.** 새 control 단위 규칙: `script_params_declared`, `script_params_used`,
`script_params_needs_script`, `script_params_default_safe`, `script_on_absent_needs_script`, `modes_charset`,
`modes_backup_overlap`, `sysctl_charset`, `modules_charset`, `state_needs_script`. `units_exclusive`는 기록 종류
셋으로 넓어집니다. 삭제: `backup_path_shared`, `units_shared`, `backup_reserved`. 되돌릴 길 규칙은 이렇게
읽힙니다. `script`에는 `rollback`, `backup`, `units`, `modes`, `sysctl`, `modules` 중 하나가 있어야 합니다.

**테스트.** lint 케이스들. 계획 테스트(모든 타입의 `script_params` 형식, 리스트 잇기, JSON에서 `script_params`가
비는 문자 집합 거부, `script_on_absent`, 롤백 단어 여섯, 종류별 `Build` 거부). §3의 스크립트 테스트. 다시 만드는
골든(`full.sh`에 파라미터 control과 상태 control이 생김. `all-scripted.sh`는 새 본문을 모두 렌더). `P_` 줄, `MB`
줄, 따옴표 묶인 `save_modes` 줄, 기록 줄들을 인정하는 `TestScriptEveryLineIsTemplateBodyOrComment`. 새 경로의
3D-2b 유닛 테스트. id 표로 control 여섯에 대한 파일 validate 테스트. `nfs_export_access`가 들어가는
`TestFileScriptsRepairOnARealFile`(심볼릭 링크 경로 포함). 마스크 유도 테스트. 배포되는 모든 본문에 대한
파라미터 자리 grep. 종류 술어 없는 모드 변경
`find`를 거부하는 grep. 고정 테스트 둘. 표 테스트. mutation 테스트는 살아남는 mutant가 0이어야 합니다.

**CI.** runner 행, `ci/roundtrip/runner.sh`, `record()`의 세 가지 추가, 새 스크립트에 대한 shellcheck. 브랜치의
`examples.yml` 실행에서 받는 examples 갱신(`make examples-fetch RUN=<id>`)은 머지 전에 필수입니다. plan 필드, 새
본문, 프롤로그 변경이 모든 fix 보고서를 바꿉니다.

**문서**(영어와 한국어를 같은 커밋에). 메인 설계: D34 수정(§2)과 §4.2의 `internal/remedy` 행(해시와 `P_` 대입을
인정되는 두 비리터럴 부류로), §6.2에 필드 다섯과 규칙, §6.8에서 세트 단위 규칙 둘 삭제, §7.5에 기록 종류와 롤백
단어 여섯과 실패 순서, §10.2에서 3D-2c를 merged로 표시하고 3D-2d(audit 묶음, `account_inactivity_lock`, 내용 쪽
절반)를 적음. `CLAUDE.md` Fix 절. `CONTRIBUTING` 쌍(본문 쓰는 법: 파라미터는 `P_`와 그것이 설 수 있는 자리, E-8의
밖일 때만 쓰기 규칙, E-9의 `find` 규율과 마스크 공식, 세 번째 validate 모양(리터럴 이름에 대한 `for` 하나, 각
조건 `|| exit 1`), E-13의 부작용 규칙, 되돌릴 길은 기록 종류로, 본문이 모드만 바꾸는 경로는 `backup`이 아니라
`modes` 항목으로, 데몬의 파일에는 E-11). README 쌍. `THREAT_MODEL.md`(파라미터 값은 문자 집합 아래에서만 명령에
들어감. 유닛 상태 경로는 `$MUSTER_BACKUP/blocks/<fn>/units/`). `CHANGELOG` — Unreleased의 3D-2b 항목을 제자리에서
다시 씀(블록별 기록 경로. lint 셋은 릴리스에 배포된 적 없음). Changed 줄로 모순을 내지 않음. 항목에 추가: Added —
스크립트의 파라미터, 기록 종류 셋, runner 행, 스크립트 32개. Changed — 블록별 백업 디렉터리, 복원 때 없던 경로
제거, 기본 목록 순서 하나, 포워딩 control 둘·`usb_storage_disabled`·`password_policy`의 위험도. Controls:
`kisa-unix-2026+2026.10.14`, 판정 변화 없음.

## 7. 미룬 항목

- 호스트마다 판단이 필요한 control의 스크립트(마운트, 파티션, swap, secure boot, 리스너, sudo, 키,
  `nfs.exports` 내용, `password_hash_algorithm`, `account_inactivity_lock`, audit 묶음) — 안전한 모양이 있으면
  3D-2d, 아니면 텍스트.
- `log_dir_permissions`의 그룹 쪽(호스트의 판단)과 `cron_permissions`의 at 스풀 판정(대기 중인 작업은 계약상
  0700) — 판정 사이클.
- PAM 스택 편집(`pwquality`, `faillock`, `pam_umask`): 텍스트.
- 모듈을 끈 뒤의 initramfs 재빌드.
- `/etc/sysctl.conf`나 더 늦은 파일이 덮는 persisted sysctl 값. EFI 시스템 파티션의 `grub.cfg`(모드는 마운트의
  것).
- runner 행의 가드 실행(호스트 하나).
- `modes` 트리에서 이름에 줄바꿈이 있는 경로.

## 8. 구현된 모습

구현 계획(`docs/superpowers/plans/2026-10-14-stage3d2c-remedy-scripts.md`, 판정 S-1..S-50)과 그 리뷰가 다음을
바꿨습니다. 줄마다 고치는 절을 적습니다.

- §2 파라미터는 구분자가 무엇이든 `sed`의 `s` 식 안에 나타나지 않습니다. 본문은 값을 먼저 평범한 변수에
  복사합니다. `TestShippedBodiesPlaceParametersSafely`가 이것과 줄 첫머리 규칙을 강제하며, 이 테스트는
  `internal/controls`에 있고 모든 플랫폼에서 돕니다(S-30).
- §3 기간 기록의 행은 `name:min:max`입니다.
- §4.3, §6 `TestFileScriptsRepairOnARealFile`은 `nfs_export_access`만 더합니다. 심볼릭 링크 경로 사례는
  `TestFileBodiesRepairATempTree`의 `links`와 `Test*BodiesLeaveASymlinkedDropIn` 테스트에 있습니다.
- §3 `restore_modes`는 소유자·그룹·모드·종류가 이미 기록과 같은 항목은 건너뛰고, root 소유가 아니거나 다른
  사용자가 쓸 수 있는 상위 디렉터리를 가진 항목과, 부모를 그룹이나 다른 사용자가 쓸 수 있을 때 기록된 소유자가
  root가 아닌 항목을 거부합니다. root 소유이면서 그룹이 쓸 수 있는 디렉터리(Ubuntu의 `root:syslog 0775
  /var/log`)는 받아들이며 그 그룹을 신뢰합니다. 이 규칙은 프롤로그 헬퍼 `modes_trusted`이고, 거부하면 더 엄격한
  모드가 남고 블록은 `ROLLBACK INCOMPLETE`를 보고합니다(S-24).
- §3 같은 `MUSTER_BACKUP`으로 나중에 실행할 때 경로가 있으면 `backup`은 absent 표식을 사본으로 바꾸므로, 그
  실행의 기록은 경로가 없었다는 사실이 아니라 앞선 실행의 파일을 담습니다.
- §3, §6 실패 순서 테스트는 한 블록에서 롤백과 기록 복원 넷을, 유닛은 기록 종류와 함께 쓸 수 없으므로
  `restore_units`는 따로 확인합니다.
- §4.1 `gte 2` arm은 명확하게 `[2-9]|[1-9][0-9]|[1-9][0-9][0-9]*`로 씁니다. 셸 glob `[1-9][0-9]*`도 이미 두
  글자가 필요했으므로 받아들이는 숫자는 같습니다(S-21).
- §4.1, E-13 forwarding 본문은 쓰기 전에 읽은 값이 0일 때만 짝 키 `net.ipv4.conf.all.accept_redirects` 줄을
  저장하므로, 저장된 1이 부팅 때 `icmp_redirects_ignored`를 덮지 않습니다(S-43). `net.ipv6.conf.all.forwarding`을
  쓰면 그 값이 `default.forwarding`에도 복사되므로, forwarding의 목록·쓰기·drop-in 줄·복원은 `all`을 `default`보다
  앞에 두고, 어떤 `sysctl` 목록도 정렬하지 않습니다(S-46). 모든 sysctl 안내문은 `/etc/sysctl.conf`나 뒤에 정렬되는
  파일의 값이 부팅 때 여전히 이긴다고 말합니다.
- §4.1, §4.2, §4.4 자기 drop-in 경로가 심볼릭 링크(운영자의 `/dev/null` 마스크)인 것을 발견한 본문은 그것을
  로그로 남기고 무엇이든 쓰기 전에 블록을 실패시킵니다. drop-in을 지우는 롤백은 심볼릭 링크를 건너뜁니다(S-27).
- §4.2 모듈 본문과 validate는 글자 그대로의 한 낱말 목록이 아니라 `mods='…'`를 돌며(S-22), 둘 다 수집기의
  no-op install 명령 전체를 받아들이고, 본문은 그중 하나가 이미 끈 모듈에는 줄을 덧붙이지 않습니다(S-25). 빌트인
  모듈은 내릴 수 없으므로 그 블록은 `done`으로 끝나고 컨트롤은 FAIL로 남습니다.
- §4.3 `log_dir_permissions`와 `cron_permissions`의 at 스풀 단계는 셸 glob으로 훑은, `modes_trusted`가 받아들이는
  디렉터리 안의 파일만 바꿉니다. `modes_trusted`가 거부하는 디렉터리(`/`까지 root 소유가 아니거나 다른 사용자가 쓸 수 있는 것)는 로그로 남기고 운영자에게
  맡기며, validate도 같은 집합을 확인하므로 블록은 `done`으로 끝나고 컨트롤은 FAIL로 남습니다(S-47).
- §4.3 root 소유가 아닌 시스템 crontab(`/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d/*`)이나 sudoers 파일
  (`/etc/sudoers`, 활성 `/etc/sudoers.d/*`)은 chown하거나 모드를 바꾸지 않습니다. cron과 sudo는 그런 파일을
  무시하며, 그 파일을 넘겨받으면 다른 사용자가 쓴 내용이 활성화됩니다. 본문은 `<id>: <path> is owned by uid N;
  review it before chown root, left as is`를 로그로 남기고, validate가 실패해 블록이 되돌아갑니다. root 소유
  파일은 전처럼 고칩니다(S-49).
- §4.3 `cron_permissions`는 자기 디렉터리의 `o-w`를 먼저 지우고, `audit_log_permissions`는 로그보다
  `/var/log/audit`를 먼저 고칩니다. 그다음 파일 단계는 `modes_trusted "$d/." 0`이 성립할 때만 돌고(그렇지 않으면
  로그로 남기고 둠), validate도 같은 조건을 따릅니다(S-50).
- §4.1 `reverse_path_filtering`은 계속 1(strict)을 쓰고 `restart_service`입니다. strict 필터링은 비대칭으로
  라우팅되는 트래픽을 버리며, 그런 호스트는 2를 설정합니다(최종 리뷰 F2).
- §4.1 실패한 forwarding 블록은 전역 스위치(`net.ipv4.ip_forward`, IPv6이면 `all`과 `default`)만 되돌립니다.
  커널이 전역 값을 복사하므로 각 인터페이스의 forwarding은 그 값을 따릅니다. 두 안내문이 그렇게 말합니다(최종
  리뷰 F5).
- §3 `restore_modes`는 소유자나 그룹이 기록과 다를 때만 `chown -h`를 실행하므로, 모드만 되돌릴 때 파일의
  `security.capability`가 남습니다(최종 리뷰 M1).
- §4.4 `umask_policy`와 `password_policy`는 심볼릭 링크인 `/etc/login.defs`를 거부합니다. 블록은 그것을 로그로
  남기고 무엇이든 쓰기 전에 실패합니다(최종 리뷰 K2).
- §4.3 `cron_permissions`는 그룹이 root인 접근 파일에, 그것을 읽는 setgid 프로그램이 도는 그룹(cron이면
  `crontab`, setgid `daemon`인 `at`이면 `daemon`)을 줍니다(S-26). at 스풀 단계는 `chmod u-s,g-wxs,o-rwxt`입니다(S-40).
- §4.3 `audit_log_permissions`는 validate의 파일 절반을 가드하고, 그 안내문과 `ftpusers_permissions`의 안내문은
  다른 곳에 있는 파일을 운영자의 몫으로 적습니다(S-39). `ftpusers_permissions`와 `nfs_export_access`는
  `chown root`만 합니다(S-13).
- §4.3, §6 파일 validate 테스트는 소유자 표로 고른 3D-2b의 다섯 컨트롤에 머물며, "다른 단순 stat case 없음"
  단언은 stat `case` 하나뿐인 validate만 잡습니다(S-8, S-23). 마스크 도출 테스트는 `allowed_modes`에서 나온
  마스크(syslog, cron)를 다룹니다.
- §4.4 `lockout_threshold`: 없는 `deny`와 없는 `faillock.conf`는 양쪽에서 3으로 읽으며, 본문은 `[1, max]` 밖일
  때만 쓰고, 본문이 만든 `faillock.conf`는 모드 0644입니다(S-9, S-41).
- §4.4 `password_policy`는 합친 파일 사슬로 수집기의 `required_classes`를 계산합니다(S-10). 두 계정 본문은
  수집기처럼 키를 대소문자 구분 없이 읽고, 기간 루프는 비밀번호가 이미 `max_days` 이상 된 계정(그 자리에서
  만료될 것)과 `/etc/passwd`에 없는 이름을 로그를 남기고 건너뜁니다(S-42). 또한 무엇이든 기록하기 전에 `/etc/passwd`의 uid가 0인 이름을
  건너뛰고, root의 기간은 운영자에게 맡긴다고 로그로 남깁니다. 어떤 계정이든 비밀번호가 만료되면 그 계정의 cron과 at
  작업이 멈춥니다. 안내문도 그렇게 말합니다(S-48).
- §4.4, E-11 `session_timeout`은 키워드마다 이미 `[1, max]` 안에 있는 값을 유지하고, validate는 `command -v
  sshd`로 가드되므로 sshd가 없는 호스트는 `done`으로 끝납니다(S-11, 2차 리뷰의 문구를 뒤집음). 롤백은 `sshd -t`와
  reload 전에 기록된 drop-in을 되돌리거나 새 것을 지웁니다(S-35). 실패 실행은 데몬의 reload가 아니라 파일이
  복원되었음을 증명합니다(S-31).
- §5 runner의 재시드는 수리 실행이 조인 기본 FAIL 스크립트 경로(`/etc/hosts`, `/etc/shadow`)의 기본 모드도
  되돌리며, 호스트 행은 두 계획의 스크립트 id가 같은지가 아니라 시드한 id가 모두 실패 계획의 스크립트 항목인지와
  실패 계획의 스크립트 id가 수리 계획의 부분집합인지를 확인합니다(S-18). `sudoers_permissions`는 자기 `sudo`가
  `/etc/sudoers`를 읽는 runner에서 시드하지 않습니다(S-33).
- §5 EL 시드는 `authselect`와 `passwd`를 설치하고 `authselect select minimal with-faillock --force`를 실행합니다.
  이미지에는 선택된 구성이 없고 rocky9에는 `/etc/pam.d/passwd`가 없기 때문입니다(S-29). `umask_policy`는
  `pam_umask`를 쌓지 않는 debian12-init에서 증명하지 않으며, debian12-init과 ubuntu2204에는 `cron`을 설치하고,
  왕복 검증 스크립트의 하한은 6입니다(S-15, S-44).
- §6 블록이 도는 동안 데몬이나 시스템이 쓰는 경로(동작 중인 로그)는 `backup`이 아니라 `modes` 항목입니다. 본문이
  모드만 바꾸는 경로는 둘 중 무엇이든 됩니다(S-38). inetd와 감사 디렉터리 본문은 절이 받아들일 비트도 지우므로,
  E-8이 요구하는 것보다 엄격한 결과를 냅니다.
