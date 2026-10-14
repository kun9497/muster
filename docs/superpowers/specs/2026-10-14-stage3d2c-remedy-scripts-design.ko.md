# 3D-2c단계 — 열여섯 너머의 스크립트: 파라미터, 상태 기록, runner 행

영어 원본: `2026-10-14-stage3d2c-remedy-scripts-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`(§6.2
스키마, §6.8 lint, §7.5 `fix --dry-run`, §10.2 로드맵, D24, D34). 이 사이클이 딛고 서는 설계:
`2026-10-07-stage3d2-fix-dry-run-design.ko.md`(X-1..X-10)와 `2026-10-13-stage3d2b-remedy-proof-design.ko.md`
(Q-1..Q-6). 이 설계의 판정은 E 목록입니다. 본문을 쓸 때 참고한 묶음별 지도는 이 사이클의 무시되는 작업 공간
파일 `family-map.md`이며, 구속력이 있는 사실은 여기에 다시 적었습니다.

## 1. 범위와 의도

control 16개가 `script`를 가집니다. 없는 101개 중 87개가 `auto`이고, 그중 38개의 본문은 정형입니다. sysctl 줄을
쓰고 적용하기, modprobe 줄을 쓰고 모듈을 내리기, 모드 비트 지우기, 설정 줄 바꾸기, sshd drop-in 쓰기입니다.
나머지는 호스트마다 판단이 필요해(어느 파티션을 나눌지, 어느 리스너를 허용할지, 어느 계정을 잠글지) 텍스트로
남습니다. 이 사이클은 그 38개에 스크립트를 붙이고, 그것들이 필요로 하는 기제 둘을 만듭니다. 파라미터 값이
스크립트에 닿는 길과, 파일 내용이 아닌 상태(모드, sysctl 값, 올라간 모듈)를 기록하고 되돌리는 길입니다.

- **E-1 — 파라미터는 텍스트 치환이 아니라 블록 변수로 스크립트에 닿는다.** control이 `script_params`를
  적습니다. 템플릿은 `UNITS=`를 내보내듯 본문 subshell의 첫 줄들로 `P_<name>='<값>'`을 내보냅니다. 값은 적용
  중인 값(기본값, 프로파일, 튜닝)이고, 그 타입의 문자 집합에 맞을 때만 줄에 들어갑니다. 아니면 그 항목은 텍스트만
  됩니다(`params_unsafe`). `params_tuned` 규칙은 `script_params`를 선언하지 않은 scripted control에만
  적용됩니다(§2).
- **E-2 — 상태는 블록마다 기록한다.** 블록이 남기는 모든 기록(파일 복사본, 유닛 상태, 경로의 모드, sysctl 값,
  모듈 적재 상태)은 `$MUSTER_BACKUP/blocks/<fn>/` 아래에 있습니다. 그래서 블록은 앞선 블록이 본 상태가 아니라
  자기가 본 상태로 되돌립니다. `backup_path_shared`와 `units_shared` lint는 없어집니다. 두 블록이 같은 경로나
  유닛을 선언할 수 있고, 뒤의 블록은 앞의 블록이 남긴 상태로 되돌립니다. 선언된 백업 경로가 없었으면 없었다고
  기록하고 복원 때 지우므로, drop-in을 만드는 스크립트에 `rm -f` 롤백이 필요 없습니다(§3).
- **E-3 — 상태 종류 셋을 더한다.** `modes`(경로의 소유자·그룹·모드. `dir/*` 패턴은 `find`로 펼치며 숨김 파일
  포함, 심볼릭 링크 제외), `sysctl`(키의 runtime 값), `modules`(올라가 있는지). 각각 프롤로그에
  `save_`/`restore_` 헬퍼가 있고, 실패 경로는 파일 복원 앞뒤로 정해진 순서로 이들을 실행합니다(§3).
- **E-4 — 본문.** sysctl 17개, 모듈 3개, 파일 권한 9개, 계정 4개, sshd 1개를 3D-2b의 규율로 씁니다. 비트는
  지우기만 하고 설정하지 않습니다. drop-in을 쓰고 배포판 파일은 건드리지 않습니다. 호스트가 대야 하는
  값(계정 이름, `/var/log` 아래 경로)은 스크립트가 호스트에서 열거하지 스냅샷에서 읽지 않습니다(§4).
- **E-5 — absent가 늘 절망은 아니다.** control은 `script_on_absent: true`를 선언할 수 있습니다. 그러면 평가기가
  `absent_means: fail`로 이른 FAIL도 스크립트와 함께 계획됩니다. 스크립트가 쓰는 것이 바로 그 없는
  줄(`PASS_MIN_LEN`, `ClientAliveInterval`)이기 때문입니다. 다른 모든 control에는 3D-2 규칙(X-2, Z-6)이
  그대로입니다(§2).
- **E-6 — 컨테이너가 못 하는 증명은 러너가 한다.** 모든 `beyond` control은 `env.container eq none`으로
  가드되므로 sysctl·모듈·bootloader·audit log 스크립트는 호스트에서만 판정됩니다. `fix-roundtrip`에 docker 없이
  GitHub 러너 VM 자체에서 시드·수리·실패를 하는 `runner` 행이 생깁니다. 가드 실행은 없고(호스트가 하나), 실패
  실행은 같은 VM을 다시 시드합니다(§5).
- **E-7 — 판정은 바뀌지 않는다.** `checks`와 fact는 바뀌지 않습니다. 리스트 파라미터 세 개의 기본 순서를 바꿔
  첫 요소가 가이드가 말하는 값이 되게 합니다(`umask_policy.acceptable`). `op: in`은 순서를 보지 않습니다.
  `controls/VERSION`이 올라갑니다. plan JSON에 `script_params`, `script_on_absent`, `modes`, `sysctl`,
  `modules`와 롤백 값 `state`가 추가되고, plan 스키마는 1을 유지합니다.

## 2. 스크립트의 파라미터 (E-1, E-5)

**스키마.** `Remediation`에 `ScriptParams []string`(`yaml:"script_params,omitempty"`)과 `ScriptOnAbsent bool`
(`yaml:"script_on_absent,omitempty"`)이 추가됩니다. 항목은 파라미터 이름이거나, 리스트 파라미터의 `n`번째
요소(0부터)를 뜻하는 `name[<n>]`입니다. 블록 변수는 어느 쪽이든 `P_<name>`입니다.

**lint**(control 단위. 각각 `TestLintRules` 케이스):
- `script_params_declared` — 모든 항목이 `params` 키를 가리켜야 합니다. 인덱스가 있는 항목은 `list<…>`
  파라미터를 가리키고 `n`은 기본 목록 길이 안이어야 합니다. 리스트 전체 항목도 허용됩니다(공백 하나로 이음).
- `script_params_used` — `script`의 모든 `$P_<name>`/`${P_<name>`가 선언되어 있고, 선언된 모든 항목이
  `script`에서 쓰여야 합니다. `validate`와 `rollback`은 `$P_`를 쓸 수 없습니다(자기 subshell에서 돌아 설정되지
  않음).
- `script_params_needs_script`, `script_on_absent_needs_script`.
- `script_params_default_safe` — 항목이 가리키는 기본값이 모두 문자 집합(아래)을 통과해야 합니다.

**타입별 문자 집합.** `int`: `^-?[0-9]+$`. `bool`: `true` 또는 `false`. `string`과 `list<string>`의 각 요소:
`^[A-Za-z0-9._/@:+,=-]+$`. `list<int>`의 각 요소: `int`와 같음. 리스트 전체는 요소를 공백 하나로 이은 것이라
본문이 `for x in $P_<name>`으로 돕니다. 어떤 값도 따옴표, (요소 안의) 공백, `$`, 백틱, `;`를 담을 수 없으므로
`'…'`가 그것을 데이터로 지킵니다.

**계획.** `Item`에 `ScriptParams []ParamValue`(`json:"script_params"`, 항상 있고 없으면 `[]`.
`ParamValue{Name, Value string}`, json `name`/`value`, 이름 순 정렬 — map 없음, 같은 입력 같은 바이트)와
`ScriptOnAbsent bool`(`json:"script_on_absent"`)이 추가됩니다. `remedy.Build`는 적용 중인 값을 check 블록의
`Params[id][name]`(3D-1이 기록하는 합쳐진 값)에서 읽고, 인덱스 항목이면 요소를 고르고, 문자열로 만들어 문자
집합을 검사합니다. 문자 집합에 어긋나거나 인덱스가 적용 중인 목록 밖이면 그 항목은 텍스트만 되고
`text_only_reason: params_unsafe`입니다(스크립트의 문구: `a parameter value cannot be carried safely; see
muster check --format json: check.params`). `params_tuned` 분기는 control이 `script_params`를 선언하지 않았고
어떤 출처가 `default`가 아닐 때만 적용됩니다.

**absent.** 행의 reason이 `check.ReasonAbsentFailPrefix`로 시작하고 control이 `script_on_absent: true`를
선언했으면 그 항목은 스크립트를 가집니다. 아니면 3D-2의 `absent` 텍스트 전용 사유가 그대로입니다.

**렌더링.** 본문 subshell은 `( set -e`로 열리고, 유닛이 선언됐으면 `UNITS='…'`, 그다음 항목마다 이름 순으로
`P_<name>='<값>'` 한 줄씩, 그다음 본문입니다. `templateLines`는 정확히 렌더된 `P_` 줄만 인정합니다. poison
계획에는 `script_params: [bad]`를 선언하고 적용 중인 값이 `'; id; '`인 control이 들어갑니다. 그 항목은
텍스트만으로 렌더되고, 그 값은 주석이 아닌 어느 줄에도 나오지 않습니다.

**D34, 한 번 더 수정.** "호스트 값은 명령에 치환되지 않는다"는 예외 하나(machine-id 해시)를 그대로 둡니다.
파라미터 값은 호스트 값이 아닙니다. 운영자가 프로파일이나 튜닝 파일에 선언한 정책이고, 위 문자 집합에 묶여
`P_` 대입으로만 명령에 들어갑니다.

## 3. 상태 기록 (E-2, E-3)

**블록별 디렉터리.** 블록 함수는 무엇이든 기록하기 전에 `MB="$MUSTER_BACKUP/blocks/<fn>"`을 정하고 만듭니다
(`mkdir` 실패는 `backup failed, nothing changed`). 그 아래:

| 종류 | 위치 | 기록 |
|---|---|---|
| 파일 복사본 | `$MB/files<경로>` | 3D-2처럼 경로의 `cp -a` |
| 없던 파일 | `$MB/absent<경로>` | 빈 표지: 선언된 경로가 없었음 |
| 유닛 | `$MB/units/<u>`, `<u>.deps` | 3D-2b처럼 |
| 모드 | `$MB/modes.list` | 경로마다 한 줄: `<uid> <gid> <mode> <경로>` |
| sysctl | `$MB/sysctl.list` | 키마다 한 줄: `<키> <값>`(읽을 수 없으면 `absent`) |
| 모듈 | `$MB/modules.list` | 모듈마다 한 줄: `<이름> loaded\|not-loaded` |

경로, 유닛, 키, 모듈의 첫 기록은 전처럼 같은 `MUSTER_BACKUP`으로 실행해도 유지되지만, 블록마다입니다. 블록 B의
기록은 A가 실행된 뒤 B가 본 것입니다. `backup_path_shared`, `units_shared`, `backup_reserved` lint는 지웁니다.
`units_exclusive`는 `units` 옆에 `rollback`/`backup`을 두는 것을 계속 막습니다.

**`backup`과 `restore`.** `backup`은 없는 선언 경로를 건너뛰는 대신 없었다고 기록합니다(`: > "$MB/absent$p"`).
`restore`는 absent 표지가 있는 경로를 지우고(`rm -f`. 지금 디렉터리이면 로그로 남기고 미완료로 셈), 복사본이
있는 경로는 전처럼 되돌립니다. 그래서 drop-in을 만드는 스크립트에 `rm -f` 롤백이 필요 없고,
`root_remote_login`의 롤백은 `sshd -t`와 reload 줄로 줄어듭니다.

**`modes`.** 항목은 절대·정규 경로에 `/*`가 0~2개 붙은 것입니다(lint `modes_charset`:
`^/[A-Za-z0-9._@:+/-]+(/\*){0,2}$`, 중복 없음, `script` 필요, `backup`과 배타). 헬퍼는 항목을 `find <dir>
-mindepth k -maxdepth k ! -type l`로 펼칩니다. `k`는 `/*`의 개수입니다(`k = 0`: 경로가 있으면 그 자체).
숨김 파일은 포함되고 심볼릭 링크는 제외되는데, 이것이 collector의 시각입니다.

```sh
modes_paths() { # one path per line for one entry
  case "$1" in
    */\*/\*) find "${1%/\*/\*}" -mindepth 2 -maxdepth 2 ! -type l 2>/dev/null;;
    */\*) find "${1%/\*}" -mindepth 1 -maxdepth 1 ! -type l 2>/dev/null;;
    *) [ -e "$1" ] && [ ! -L "$1" ] && printf '%s\n' "$1";;
  esac
  return 0
}
save_modes() {
  [ -f "$MB/modes.list" ] || : > "$MB/modes.list" || return 1
  for spec in "$@"; do
    modes_paths "$spec" | while IFS= read -r p; do
      awk -v p="$p" '{ q=$0; sub(/^[^ ]+ [^ ]+ [^ ]+ /, "", q); if (q == p) f=1 } END { exit !f }' "$MB/modes.list" && continue
      s=$(stat -c '%u %g %a' -- "$p") || exit 1
      printf '%s %s\n' "$s" "$p" >> "$MB/modes.list" || exit 1
    done || return 1
  done
}
restore_modes() {
  mrc=0
  while read -r uid gid mode p; do
    [ -e "$p" ] || continue
    chown -- "$uid:$gid" "$p" && chmod -- "$mode" "$p" || mrc=1
  done < "$MB/modes.list"
  return $mrc
}
```

이름에 줄바꿈이 있는 경로는 지원하지 않습니다(문서에 한계로 적음. 선언된 트리 어디에도 없습니다). 경로 안의
공백은 경로가 마지막 필드라서 `read -r`을 살아남습니다.

**`sysctl`.** 항목은 커널 키입니다(lint `sysctl_charset`: `^[a-z0-9_]+(\.[a-z0-9_-]+)+$`, 중복 없음, `script`
필요). `sysctl`과 `backup`은 함께 갑니다. 파일은 persisted 쪽, 기록은 runtime 쪽입니다.

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
    [ -n "$v" ] && [ "$v" != absent ] || continue
    sysctl -q -w -- "$k=$v" || src=1
  done
  return $src
}
```

**`modules`.** 항목은 모듈 이름입니다(lint `modules_charset`: `^[a-z0-9_-]+$`, 중복 없음, `script` 필요).
헬퍼는 `-`를 `_`로 접고(kmod의 규칙) `/proc/modules`를 읽습니다.

```sh
save_modules() {
  [ -f "$MB/modules.list" ] || : > "$MB/modules.list" || return 1
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    awk -v m="$n" '$1 == m { f=1 } END { exit !f }' "$MB/modules.list" && continue
    if awk -v m="$n" '{ gsub(/-/, "_", $1) } $1 == m { f=1 } END { exit !f }' /proc/modules; then s=loaded; else s=not-loaded; fi
    printf '%s %s\n' "$n" "$s" >> "$MB/modules.list" || return 1
  done
}
restore_modules() {
  orc=0
  for m in "$@"; do
    n=$(printf '%s' "$m" | tr - _)
    [ "$(awk -v m="$n" '$1 == m { print $2; exit }' "$MB/modules.list")" = loaded ] || continue
    modprobe -- "$n" || orc=1
  done
  return $orc
}
```

**블록.** 머리는 순서대로 `MB=…; mkdir -p "$MB"`, `backup`, `save_units`, `save_modes`, `save_sysctl`,
`save_modules`이고 각각 `|| { log "<id>: backup failed, nothing changed"; return 1; }`가 붙습니다. 그다음 본문
subshell입니다. 실패 경로는 순서대로 선언된 `rollback`, `restore_units`, `restore_modes`, `restore`(파일과
absent 표지), `restore_sysctl`, `restore_modules`입니다. 스크립트의 값을 지속시킬 파일이 사라진 뒤에 runtime
값을 다시 적용하고, `install … /bin/false` 줄이 사라진 뒤에 모듈을 다시 올립니다. 실패한 복원마다 `ROLLBACK
INCOMPLETE`를 남기고 다음 복원은 계속 실행합니다. 헬퍼는 자기 변수(`spec`, `p`, `s`, `k`, `v`, `m`, `n`, `mrc`,
`src`, `orc`)만 쓰고 블록의 `rc`는 쓰지 않습니다.

**계획.** `Item`에 `Modes`, `Sysctl`, `Modules []string`(json `modes`, `sysctl`, `modules`, `units` 뒤. 없으면
`[]`, `Script`가 true일 때만 채움)이 추가됩니다. `Build`는 항목마다 lint 패턴으로 다시 검사하고 어긋나면 계획을
거부합니다(id와 유닛처럼). `Item.Rollback`은 `none | declared | restore_backup | units | state | both`가
됩니다. `units`는 유닛만 선언된 경우, `state`는 `modes`·`sysctl`·`modules`가 선언되고 다른 것은 없는 경우,
`both`는 파일 백업이나 선언된 롤백이 어떤 기록 종류 옆에 있는 경우입니다. 표의 열은 그 단어를 보여 줍니다.

**테스트.** stub 없는 테스트가 임시 트리에서 `save_modes`/`restore_modes`를 돌립니다(숨김 파일, 심볼릭 링크,
디렉터리 항목, 두 단계 패턴, 아무것도 안 맞는 패턴, 공백이 든 경로, 재실행에서 첫 기록 유지, 쓸 수 없는 경로에서
`ROLLBACK INCOMPLETE`). stub `sysctl`과 `modprobe`(3D-2b의 `systemctl` stub처럼 인자를 로그로 남기고 fixture
파일로 답하며, stub이 읽는 fixture `/proc/modules` 경로는 환경변수로 넘김)가 나머지 둘을 돕니다. 읽히는 키,
`absent` 키, 쓰기를 거부하는 키. 다시 올라가는 모듈, 그대로 두는 모듈, 실패하는 `modprobe`. 실패 경로 순서
테스트는 모든 종류를 선언한 블록에서 복원 줄 여섯의 순서를 확인합니다. 3D-2b의 유닛 테스트는 `$MB/units/`로
옮깁니다.

## 4. 본문 (E-4)

모든 본문은 POSIX `sh`이고, 기본 심각도에서 shellcheck를 통과하며, 본문 subshell 안에서 `set -e`에 안전하고,
리터럴 경로와 `P_` 변수와 호스트에서 열거한 것만 씁니다. 모든 control은 `idempotent: true`(이미 모두 그렇습니다)와
그 단계를 증명하는 한 줄 `validate`를 가집니다. 텍스트는 문장을 유지하고, 스크립트가 생긴 곳은 쓰는 파일을
이름 붙입니다.

### 4.1 sysctl (17)

이 묶음의 fact는 runtime 쪽으로 판정됩니다(`default_on: effective`). 판정은 `/proc/sys`입니다. persisted 쪽은
증거입니다. 그래서 본문은 둘 다 합니다. 다음 부팅을 위해 파일을 쓰고, 지금 값을 적용합니다. 파일:
`/etc/sysctl.d/99-muster-<name>.conf`(control마다 하나. 그래서 블록마다 자기 백업을 가짐). systemd의
`50-default.conf`·`50-coredump.conf`와 Ubuntu의 `10-*.conf` 뒤, `99-sysctl.conf` → `/etc/sysctl.conf` 앞에
정렬됩니다. `/etc/sysctl.conf`가 같은 키를 두는 호스트는 그 persisted 값을 유지하고, 텍스트가 그렇게 말합니다.
키마다 한 줄, 값 줄에 주석 없음(collector에게 끝의 `#`은 값의 일부입니다). 위험도 `none`.
`syn_cookies_enabled`의 모양:

```yaml
  sysctl: [net.ipv4.tcp_syncookies]
  backup: [/etc/sysctl.d/99-muster-syn-cookies.conf]
  script: |
    printf '%s = %s\n' net.ipv4.tcp_syncookies 1 > /etc/sysctl.d/99-muster-syn-cookies.conf
    chmod 644 /etc/sysctl.d/99-muster-syn-cookies.conf
    sysctl -q -w net.ipv4.tcp_syncookies=1
  validate: "[ \"$(sysctl -n net.ipv4.tcp_syncookies)\" = 1 ]"
```

| control | 키 → 값(리스트이면 첫 요소) | params |
|---|---|---|
| `aslr_and_link_protection` | `kernel.randomize_va_space=2`, `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`, `fs.protected_fifos=1`, `fs.protected_regular=2` | — |
| `icmp_broadcast_and_bogus_ignored` | `net.ipv4.icmp_echo_ignore_broadcasts=1`, `net.ipv4.icmp_ignore_bogus_error_responses=1` | — |
| `icmp_redirects_ignored` | `net.ipv4.conf.{all,default}.{accept,secure,send}_redirects=0`(키 6개) | — |
| `ip_forwarding_disabled` | `net.ipv4.ip_forward=$P_allowed_forward` | `allowed_forward[0]` |
| `ipv6_forwarding_disabled` | `net.ipv6.conf.{all,default}.forwarding=$P_allowed_forward` | `allowed_forward[0]` |
| `ipv6_redirects_ignored` | `net.ipv6.conf.{all,default}.accept_redirects=0` | — |
| `ipv6_router_advertisements_ignored` | `net.ipv6.conf.{all,default}.accept_ra=$P_allowed_accept_ra` | `allowed_accept_ra[0]` |
| `ipv6_source_routing_rejected` | `net.ipv6.conf.{all,default}.accept_source_route=0` | — |
| `kernel_pointer_exposure` | `kernel.kptr_restrict=1`, `kernel.dmesg_restrict=1` | — |
| `ptrace_restriction` | `kernel.yama.ptrace_scope=1`, `kernel.perf_event_paranoid=2` | — |
| `reverse_path_filtering` | `net.ipv4.conf.{all,default}.rp_filter=1`, `net.ipv4.conf.{all,default}.log_martians=1` | — |
| `source_routing_rejected` | `net.ipv4.conf.{all,default}.accept_source_route=0` | — |
| `suid_dumpable_disabled` | `fs.suid_dumpable=0` | — |
| `syn_cookies_enabled` | `net.ipv4.tcp_syncookies=1` | — |
| `sysrq_restricted` | `kernel.sysrq=$P_allowed_sysrq` | `allowed_sysrq[0]` |
| `unprivileged_bpf_restricted` | `kernel.unprivileged_bpf_disabled=2`, `net.core.bpf_jit_harden=2` | — |

- `unprivileged_bpf_disabled`는 텍스트의 `1`이 아니라 `2`로 씁니다. 커널은 값이 `1`이 되면 더는 쓰기를 받지
  않아 `1`은 되돌릴 수 없고, `2`는 절의 목록에 있으면서 계속 쓸 수 있습니다. 텍스트가 그렇게 말하도록 바뀝니다.
  `yama.ptrace_scope`가 `1`인 것도 같은 이유입니다(`3`은 되돌릴 수 없음).
- `core_dump_policy`는 텍스트로 남습니다. `partial`이고, 메커니즘으로 판정되며, runtime 쪽(`core_pattern`)에는
  persisted 읽기가 없습니다.
- IPv6 control 넷은 `ipv6_disabled eq 0`으로 가드되어 본문에 가드가 필요 없습니다. 호스트에 없는 키(Yama 없음,
  BPF JIT 없음)는 `script_on_absent` 없는 `absent_means: fail`이라 지금처럼 텍스트만입니다.
- `ip_forwarding_disabled`의 위험도는 이제 `restart_service`입니다. 라우터나 컨테이너 호스트에서 `0`을 쓰면
  포워딩이 바로 끊깁니다. 나머지는 `none`입니다.

### 4.2 모듈 (3)

`disabled`는 올라가 있지 않고, 내장이 아니고, modprobe.d 체인에 `install … /bin/false`가 있거나 배포되지
않았다는 뜻입니다. 그래서 본문은 줄을 쓰고 모듈을 내립니다. 파일: `/etc/modprobe.d/99-muster-<name>.conf`.
kmod는 디렉터리를 가로질러 기본 이름 순으로 처음 읽은 `install`을 지키므로, 그 모듈에 `install` 줄을 가진 벤더
파일이 이깁니다. 측정한 이미지에서 열한 모듈 중 그런 것은 없고, 텍스트가 그 경우를 말합니다. 위험도
`restart_service`(내려간 `usb-storage`는 마운트된 USB 디스크를 떨어뜨림).

```yaml
  modules: [cramfs, freevxfs, jffs2, hfs, hfsplus, udf]
  backup: [/etc/modprobe.d/99-muster-uncommon-filesystems.conf]
  script: |
    : > /etc/modprobe.d/99-muster-uncommon-filesystems.conf
    for m in cramfs freevxfs jffs2 hfs hfsplus udf; do
      printf 'install %s /bin/false\n' "$m" >> /etc/modprobe.d/99-muster-uncommon-filesystems.conf
      if awk -v m="$m" '{ gsub(/-/, "_", $1) } $1 == m { f=1 } END { exit !f }' /proc/modules; then modprobe -r -- "$m"; fi
    done
    chmod 644 /etc/modprobe.d/99-muster-uncommon-filesystems.conf
  validate: "for m in cramfs freevxfs jffs2 hfs hfsplus udf; do modprobe --showconfig 2>/dev/null | grep -q \"^install $m /bin/false\" || exit 1; ! awk -v m=\"$m\" '{ gsub(/-/, \"_\", $1) } $1 == m { f=1 } END { exit !f }' /proc/modules || exit 1; done"
```

실패하는 `modprobe -r`(모듈 사용 중)은 본문을 실패시킵니다. 호스트가 그 모듈을 쓰는 것이니 블록은 롤백됩니다.
내장 모듈은 control을 FAIL로 두고, 텍스트는 다른 커널만이 길이라고 말합니다. initramfs는 다시 만들지
않습니다(텍스트). 본문의 모듈 이름은 control 자신의 `where` 목록을 리터럴로 되풀이한 것이고, §6의 고정 테스트가
둘이 같은지 지킵니다.

### 4.3 파일 권한 (9)

3D-2b처럼 control이 소유자를 판정하는 곳은 `chown root:root`, 비트만 지우는 기호식 `chmod`, 경로 하나를 판정하는
곳은 기본 모드에 대한 `case` validate입니다. 글롭 집합은 `modes`와 `find`를 씁니다.

| control | 기록 | 본문 | validate |
|---|---|---|---|
| `sudoers_permissions` | `backup: [/etc/sudoers]`, `modes: [/etc/sudoers.d/*]` | `chown root /etc/sudoers; chmod u-wxs,g-wxs,o-rwxt /etc/sudoers`; `find /etc/sudoers.d -mindepth 1 -maxdepth 1 -type f ! -name '*.*' ! -name '*~' -exec chmod go-w {} +` | `[0,40,400,440]`에 대한 `case`(control은 uid만 판정: 형식 `%u %a`, 접두어 `0`) `&&` `find … -perm /g+w,o+w`가 비어 있음 |
| `nfs_export_access` | `backup: [/etc/exports]` | `[ -f ]; chown root:root; chmod u-xs,g-wxs,o-wxt` | 16개 모드에 대한 `case`, `%u %g %a`, `0 0` |
| `bootloader_config_permissions` | `backup: [/boot/grub/grub.cfg, /boot/grub2/grub.cfg]` | 있는 것마다 `chown root:root; chmod u-xs,g-rwxs,o-rwxt` | 있는 경로마다 `[0,200,400,600]`에 대한 `case`, `0 0` |
| `inetd_conf_permissions` | `backup: [/etc/inetd.conf, /etc/xinetd.conf]`, `modes: [/etc/xinetd.d/*]` | 있는 conf마다 `chown root; chmod u-xs,g-rwxs,o-rwxt`; `find /etc/xinetd.d -mindepth 1 -maxdepth 1 -type f -exec chmod go-w {} +` | conf 쪽은 `stat` 비트(`g-w`, `o-r`, uid 0), 조각은 `find -perm /g+w,o+w`가 비어 있음 |
| `audit_log_permissions` | `backup: [/var/log/audit/audit.log]`, `modes: [/var/log/audit]` | `chown root /var/log/audit/audit.log; chmod u-xs,g-wxs,o-rwxt …; chown root /var/log/audit; chmod g-w,o-rwx /var/log/audit` | 8개 모드에 대한 `case`(`%u %a`, `0`) `&&` 디렉터리 비트 |
| `syslog_conf_permissions` | `backup: [/etc/rsyslog.conf, /etc/systemd/journald.conf]`, `modes: [/etc/rsyslog.d/*, /etc/systemd/journald.conf.d/*, /etc/syslog-ng/syslog-ng.conf, /etc/syslog-ng/conf.d/*]` | 있는 것마다 `chown root; chmod u-xs,g-wxs,o-rwxt`(디렉터리는 `find … -name '*.conf' -type f`) | 같은 집합에 `find … -perm /o+r,g+w,u+x`가 비어 있음 `&&` `! -user root`가 비어 있음 |
| `cron_permissions` | `modes: [/etc/crontab, /etc/anacrontab, /etc/cron.allow, /etc/cron.deny, /etc/at.allow, /etc/at.deny, /etc/cron.d/*, /etc/cron.hourly, /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly, /etc/cron.hourly/*, /etc/cron.daily/*, /etc/cron.weekly/*, /etc/cron.monthly/*, /var/spool/cron/*, /var/spool/cron/crontabs/*, /var/spool/cron/atjobs/*, /var/spool/at/*, /etc/cron.d, /var/spool/cron, /var/spool/cron/crontabs, /var/spool/cron/atjobs, /var/spool/at]` | 시스템·접근 파일: `chown root; chmod u-xs,g-wxs,o-rwxt`; 주기 스크립트: `chown root; chmod o-w`(`+x`는 유지: run-parts는 실행 비트 없는 파일을 건너뜀); 사용자 스풀: `chmod u-xs,g-wxs,o-rwxt`만(uid ≥ 1000이 소유한 스풀은 맞는 것); 디렉터리 아홉: `chmod o-w` | 시스템·접근 집합에 `find … -perm /o+rwx,g+w,u+x`가 비어 있음 `&&` 주기 `-perm /o+w` 비어 있음 `&&` 스풀 `-perm /o+rwx,g+w` 비어 있음 `&&` 디렉터리 `-perm /o+w` 비어 있음 |
| `log_dir_permissions` | `modes: [/var/log, /var/log/*, /var/log/*/*]` | `find /var/log -maxdepth 2 -perm /o+w -exec chmod o-w {} +`; 그다음 그룹 쓰기 가능이고 그룹이 `$P_allowed_groups`에 없는 항목에 `chmod g-w`(`set --` 루프가 목록에서 `! -group g`를 만듦) | 두 `find` 모두 비어 있음 |
| `ftpusers_permissions` | `backup: [/etc/ftpusers, /etc/vsftpd/ftpusers, /etc/vsftpd/user_list, /etc/vsftpd.user_list, /etc/vsftpd.ftpusers]` | 있는 것마다 `chown root:root; chmod u-xs,g-wxs,o-rwxt`; 절대 만들지 않음(빈 허용 목록은 모든 로그인을 막음) | 있는 경로마다 8개 모드에 대한 `case` |

- `sudoers_permissions`는 `u-w`도 지웁니다. 목표가 `0440`이고, `visudo`는 제자리가 아니라 임시 복사본을 통해
  파일을 씁니다.
- `log_dir_permissions`는 파라미터 리스트를 도는 유일한 본문입니다. `script_params: [allowed_groups]`. 절대
  `chgrp`하지 않습니다. 어느 그룹이 맞는지는 호스트의 판단이고, `chmod g-w`가 텍스트의 두 선택지 중 안전한
  쪽입니다.
- `TestFileValidatesAcceptTheDefaultModes`는 판정하는 파일이 `allowed_modes` 목록을 가진 `backup` 경로 하나인
  control 여덟으로 늘어납니다(`hosts`, `hosts_lpd`, `passwd`, `services`, `shadow`, `sudoers`,
  `nfs_export_access`, `bootloader_config_permissions`). 섞인 것들은 lint와 왕복 검증으로만 확인합니다.

### 4.4 계정과 sshd (5)

| control | 기록 | 본문 | params / absent |
|---|---|---|---|
| `password_policy` | `backup: [/etc/login.defs, /etc/security/pwquality.conf.d/99-muster.conf, /etc/shadow]` | `login.defs`: `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_MIN_LEN`마다 주석 아닌 첫 줄을 `sed`로 바꾸고 없으면 덧붙임(collector는 첫 줄을 읽음); `pwquality.conf.d/99-muster.conf`: `minlen = $P_min_len`, `minclass = $P_min_classes`; 그다음 shadow 2번 필드가 `$`로 시작하는 모든 계정(호스트에서 `awk -F:`로 열거)에 `chage -M $P_max_days -m $P_min_days` | `script_params: [max_days, min_days, min_len, min_classes]`; `script_on_absent: true` |
| `umask_policy` | `backup: [/etc/login.defs]` | 주석 아닌 첫 `UMASK` 줄을 `UMASK $P_acceptable`로 바꿈(없으면 덧붙임) | `script_params: [acceptable[0]]`; 기본 목록을 `["027", "022", "077", "0027", "0022", "0077"]`로 재배열 |
| `lockout_threshold` | `backup: [/etc/security/faillock.conf]` | `deny` 줄을 `deny = $P_max_attempts`로 바꿈(없으면 덧붙임) | `script_params: [max_attempts]`; `script_on_absent` 없음(`deny`가 absent이면 faillock이 PAM에 없는 것) |
| `session_timeout` | `backup: [/etc/ssh/sshd_config.d/00-muster-session.conf]` | `root_remote_login`처럼 `command -v sshd`로 가드하고 `ClientAliveInterval $P_max_interval`과 `ClientAliveCountMax $P_max_count`를 쓰고 `chmod 644`, `sshd -t`, 실행 중인 `sshd`/`ssh` reload | `script_params: [max_interval, max_count]`; `script_on_absent: true`(적용되는 메커니즘이 없음 ⇒ drop-in이 하나를 적용되게 함) |
| `root_remote_login` | 그대로, 롤백은 줄어듦(E-2) | — | — |

- `password_policy`의 runtime 쪽(`pass_max_days`/`pass_min_days`는 양쪽을 판정)은 `chage` 루프가 필요하고,
  없으면 행은 WARN(`not applied`)으로 끝나지 PASS가 되지 않습니다. 루프는 스크립트가 실행 시점에
  `/etc/shadow`에서 읽은 계정을 이름 붙이고, `/etc/shadow`의 `backup`이 그 되돌릴 길입니다.
  `pam.pwquality.enabled`는 호스트의 PAM 스택이 말하는 대로입니다. `libpam-pwquality`가 없는 Debian 계열
  호스트에서는 스크립트 뒤에도 control이 FAIL로 남고, 텍스트는 계속 설치하라고 말합니다.
- `password_hash_algorithm`과 `account_inactivity_lock`은 텍스트로 남습니다(재해시. `login_capable`에 대한
  계정별 `chage`는 runner 행이 증명할 수 있지만 audit 묶음과 함께 3D-2d로 읽는 편이 낫습니다).
- `lockout_threshold` 본문은 EL 행에서 증명합니다. 시드가 `authselect enable-feature with-faillock`으로
  faillock을 쌓습니다. Debian 12는 faillock용 `pam-auth-update` 프로파일을 배포하지 않아 그 이미지에서 뺍니다.

## 5. 증명 (E-6)

**runner 행.** `fix-roundtrip`의 matrix에 `{key: runner, kind: host, seeded: …}`가 생기고, 컨테이너 행에는
`kind: container`가 붙습니다. run 블록의 `x()`는 컨테이너 행에서 `docker exec "$cid"`를, 호스트 행에서 `sudo`를
실행하고, 경로는 접두어만 다릅니다(`/m/muster` ↔ `./bin/muster`, `/out` ↔ `$d/repair`, `/ci` ↔
`ci/roundtrip`). 수리 실행은 같습니다. 실패 실행에는 두 번째 컨테이너가 없습니다. job은 `ci/roundtrip/runner.sh`를
다시 실행하고(멱등), 기록하고, 깨뜨린 사본을 실행하고, 비교합니다. 이 행에는 가드 실행이 없고, job은
`fix.host_guard`가 `on`인지 확인합니다(VM에는 machine id가 있습니다). 이 행은 docker를 절대 띄우지 않고
(`ip_forward`와 `rp_filter` 스크립트가 docker 브리지가 필요로 하는 것을 바꿈), `audit_log_permissions`를 위해
`auditd`를 설치합니다.

**`record()`**에 계획된 scripted 항목마다 추가됩니다. 모든 `.sysctl[]` 키의 `sysctl -n`, 모든 `.modules[]` 이름의
적재 상태, 모든 `.modes[]` 항목이 펼쳐지는 경로의 `stat -c '%u %g %a'`(헬퍼가 펼치는 대로).

**표.** 새 scripted control은 모두 `_roundtrip.yaml`에 들어갑니다. 플랜의 사전 점검이 확정할 가설:

| control | 행 |
|---|---|
| sysctl 17, 모듈 3, `bootloader_config_permissions`, `audit_log_permissions` | `runner`만(`beyond` 가드) |
| `usb_storage_disabled` | `unproven`: 러너 커널은 `usb-storage`를 배포하지 않아 거기서는 통과함. uncommon 모듈 control 둘은 커널이 배포하지 않는 모듈마다 `unproven_units`를 가짐 |
| `cron_permissions`, `syslog_conf_permissions`, `sudoers_permissions`, `inetd_conf_permissions` | 컨테이너 행 넷(EL 행은 `cronie`/`sudo` 설치. inetd는 파일로 심음. EL9에는 패키지 없음)과 `runner` |
| `nfs_export_access`, `ftpusers_permissions` | init 행(모드만 시드. `ubuntu2204`에는 systemd 없음) |
| `log_dir_permissions` | 다섯 행 모두(`install -m 664 -g games /dev/null /var/log/ci.log`) |
| `umask_policy` | 다섯 행 모두(시드 `UMASK 002`) |
| `password_policy` | EL 행(authselect가 pwquality를 쌓음. 해시 있는 계정을 시드)과, 시드가 `libpam-pwquality`를 설치할 때만 `runner` — 사전 점검이 정함 |
| `lockout_threshold` | EL 행(`authselect enable-feature with-faillock`, `deny = 99`) |
| `session_timeout` | EL 행과 `runner`(`99-ci-session.conf`에 `ClientAliveInterval 900`을 시드) |

**표 테스트.** `TestEveryScriptedControlIsInTheRoundtripTable`은 `kind`를 읽습니다. `host` 행에는 `init`이
없습니다. `muster.beyond.*` id는 `host` 행만 적을 수 있습니다. `muster.service.*` id는 `init: "false"`인 행을 적을
수 없습니다. `unproven_units`의 키는 control의 `units`, `modules`, `sysctl` 중 하나에 선언되어 있어야 합니다.

**고정 테스트.** `TestSysctlScriptsNameTheControlsKeys`(Linux, sysctl 리프 표 옆): control의 `sysctl` 목록은
집합으로서 그 절들이 판정하는 fact의 커널 키와 같아야 합니다. `TestModuleScriptsNameTheControlsModules`:
control의 `modules` 목록은 그 `where` 목록과 같아야 합니다. 둘 다 무엇을 대체하지 않는 새 테스트입니다.

## 6. lint, 테스트, 문서

**lint 요약.** 새 control 단위 규칙: `script_params_declared`, `script_params_used`,
`script_params_needs_script`, `script_params_default_safe`, `script_on_absent_needs_script`, `modes_charset`,
`modes_excludes_backup`, `sysctl_charset`, `modules_charset`, `state_needs_script`. 삭제: `backup_path_shared`,
`units_shared`, `backup_reserved`. 되돌릴 길 규칙은 이렇게 읽힙니다. `script`에는 `rollback`, `backup`, `units`,
`modes`, `sysctl`, `modules` 중 하나가 있어야 합니다.

**테스트.** lint 케이스들. 계획 테스트(모든 타입의 `script_params` 형식, 인덱스, 문자 집합 거부,
`script_on_absent`, 롤백 단어 `state`, 종류별 `Build` 거부). §3의 스크립트 테스트. 다시 만드는 골든(`full.sh`에
파라미터 control과 상태 control이 생김. `all-scripted.sh`는 새 본문을 모두 렌더). `P_` 줄과 기록 줄 넷을
인정하는 `TestScriptEveryLineIsTemplateBodyOrComment`. 새 경로의 3D-2b 유닛 테스트. control 여덟에 대한 파일
validate 테스트. 새 단일 경로 파일 본문에 대한 `TestFileScriptsRepairOnARealFile`. 고정 테스트 둘. 표 테스트.
mutation 테스트는 살아남는 mutant가 0이어야 합니다.

**CI.** runner 행, `ci/roundtrip/runner.sh`, `record()`의 세 가지 추가, 새 스크립트에 대한 shellcheck.

**문서**(영어와 한국어를 같은 커밋에). 메인 설계: D34 수정(§2), §6.2에 필드 다섯과 규칙, §6.8에서 세트 단위 규칙
둘 삭제, §7.5에 기록 종류와 실패 순서, §10.2에서 3D-2c를 merged로 표시하고 3D-2d(audit 묶음,
`account_inactivity_lock`, 내용 쪽 절반)를 적음. `CLAUDE.md` Fix 절. `CONTRIBUTING` 쌍(본문 쓰는 법: 파라미터는
`P_`, 되돌릴 길은 기록 종류로, 글롭은 `find`로). README 쌍. `THREAT_MODEL.md`(파라미터 값은 문자 집합 아래에서만
명령에 들어감). `CHANGELOG`(Added: 스크립트의 파라미터, 기록 종류 셋, runner 행, 스크립트 38개. Changed: 블록별
백업 디렉터리, 복원 때 없던 경로 제거, 삭제된 lint 셋, 기본 목록 순서 셋, `ip_forwarding_disabled` 위험도.
Controls: `kisa-unix-2026+2026.10.14`, 판정 변화 없음).

## 7. 미룬 항목

- 호스트마다 판단이 필요한 control의 스크립트(마운트, 파티션, swap, secure boot, 리스너, sudo, 키,
  `nfs.exports` 내용, `password_hash_algorithm`, `account_inactivity_lock`, audit 묶음) — 안전한 모양이 있으면
  3D-2d, 아니면 텍스트.
- PAM 스택 편집(`pwquality`, `faillock`, `pam_umask`): 텍스트.
- 모듈을 끈 뒤의 initramfs 재빌드.
- `/etc/sysctl.conf`나 더 늦은 파일이 덮는 persisted sysctl 값.
- runner 행의 가드 실행(호스트 하나).
- `modes` 트리에서 이름에 줄바꿈이 있는 경로.
