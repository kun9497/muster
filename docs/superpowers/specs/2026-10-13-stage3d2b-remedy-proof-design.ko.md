# 3D-2b단계 — 검증된 검토용 스크립트: 호스트 가드, 유닛 상태, 라운드트립

영어 원본: `2026-10-13-stage3d2b-remedy-proof-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`
(§4.2 패키지, §6.2 스키마, §7.5 `fix --dry-run`, §10.2 로드맵, D24, D34). 이 사이클이 마무리하는 설계:
`2026-10-07-stage3d2-fix-dry-run-design.ko.md`(X-1..X-10, §8 미룬 항목)와 그 플랜의 미룬 항목 목록. 리뷰
이력: fresh 리뷰 워크플로 두 번(에이전트 145개: 살아남은 발견 29개와 critic 발견 7개. 에이전트 118개: 28개와 6개)을
이 개정판에 접어 넣었습니다. 두 번 모두 관점 다섯, 발견마다 반박자 셋, critic 하나로 돌렸습니다. 이 설계의 판정은 Q
목록입니다.

## 1. 범위와 의도

3D-2는 `fix --dry-run`과 계획, 검토용 스크립트를 내놓았고, `script`를 가진 control 16개를 다시 썼습니다. 그중
4개(`rpcbind_disabled`, `root_remote_login`, `hosts_permissions`, `shadow_permissions`)는 `fix-roundtrip` job이
실제 시스템에서 증명합니다. 나머지 12개(서비스 control 9개와 `passwd`, `services`, `hosts_lpd` 권한 스크립트)는
문법으로만 증명되었습니다. 서비스 롤백 10개는 이전 상태와 상관없이 이름을 적은 유닛을 모두 다시 켜고, 한
호스트의 스냅샷으로 만든 스크립트가 다른 호스트에서 실행되는 것을 막는 장치도 없습니다. 3D-2b는 16개에 대해 이
빈틈을 메웁니다. 스크립트가 있는 control을 새로 추가하지는 않습니다. 다른 control의 스크립트와 그에 필요한
파라미터 치환 규칙은 3D-2c입니다.

- **Q-1 — 스크립트는 계획된 호스트에서 실행된다.** 스크립트는 스냅샷의 `host.machine_id_hash`를 담고, 무엇이든
  바꾸기 전에 machine id의 해시가 다른 호스트를 거부합니다(exit 2). `MUSTER_ANY_HOST=1`은 경고를 남기고 이를
  우회합니다. 형식이 맞는 해시가 없는 스냅샷에서는 가드가 꺼지고, 프롤로그가 가드가 있었을 자리에서 그렇게
  말합니다(§2).
- **Q-2 — 서비스 롤백은 원래 있던 것을 되돌려 놓는다.** 서비스 control은 유닛을 선언합니다
  (`remediation.units`). 템플릿은 본문이 돌기 전에 유닛마다 활성화 상태와 동작 상태, 그리고 그 유닛을 멈추면 함께
  멈출 활성 유닛들을 기록합니다. 실패하면 기록한 영속 상태를 되돌립니다. masked였던 것은 다시 mask하고,
  enabled였던 것만 enable하고, active였던 것은 멈춘 의존 유닛까지 포함해 start합니다. 그런 다음 활성화 상태를 다시
  읽어 되돌리지 못한 유닛을 모두 로그로 남깁니다. 손으로 쓴 서비스 롤백 10개는 지웁니다(§3).
- **Q-3 — 스크립트가 있는 control은 모두 호스트에서 증명되거나, 증명할 수 없는 이유를 말한다.**
  `controls/testdata/` 아래의 표가 16개마다 라운드트립이 시드하고 고치는 matrix 행을, 아니면 어느 행도 그럴 수
  없는 이유를 적습니다. 테스트가 이 표와 내장 세트, CI matrix가 같은지 지킵니다. matrix에는 job 안에서 공식
  이미지로 빌드하는 Debian 12 init 컨테이너가 추가됩니다. init 행마다 두 가지를 더 증명합니다. 하나는 실패
  경로(일부러 실패시킨 블록이 유닛과 파일을 원래대로 남긴다)이고, 다른 하나는 호스트 가드(다른 컨테이너에서 계획한
  스크립트를 거부한다)입니다(§4).
- **Q-4 — 파일 스크립트는 비트를 빼기만 한다.** 권한 스크립트 5개는 가이드가 금지하는 비트만 지우는 기호식
  `chmod`를 씁니다. 그래서 이미 가이드보다 엄격한 파일을 느슨하게 만드는 일이 없고, validate는 control의 기본값에
  있는 모드를 모두 받아들입니다. 이것으로 3D-2의 미룬 항목 "다른 leaf에서 실패한 행에도 파일 스크립트가 가이드의
  모드를 설정한다"도 닫힙니다(§5).
- **Q-5 — 작은 미룬 항목들.** lint가 같은 백업 경로나 같은 유닛을 공유하는 두 scripted control을 거부합니다.
  `Escape`가 모든 서식 문자, 줄·문단 구분자, 한글 채움 문자를 풀어 씁니다. 서비스 본문과 유닛 헬퍼는 `systemctl`의
  결과 줄을 억누르도록 `--quiet`를 넘깁니다(§5).
- **Q-6 — 판정은 바뀌지 않는다.** `checks`, `params`, 판정은 바뀌지 않습니다. remediation 블록이 바뀌므로
  `controls/VERSION`이 올라가고, 그에 따라 controls digest, 골든, examples도 바뀝니다. plan JSON에는 `fix.host_guard`,
  항목마다의 `units`, 롤백 값 `units`가 추가됩니다(추가만 하므로 plan 스키마는 1을 유지합니다). 스냅샷 헤더의
  `host.machine_id_hash`는 소문자 16진수 32자가 아닌 id에서 빈 값이 됩니다(§2). 이스케이프 변경으로 check나 fix 표가
  바뀌는 것은 스냅샷, waiver, 프로파일, 튜닝 경로, control 텍스트가 새로 이스케이프하는 문자를 담은 경우뿐입니다(§5).

## 2. 호스트 가드 (Q-1)

**Collector.** `internal/collect/collectors`는 `MachineIDHash(data []byte) string`을 뽑아냅니다. 이 함수는
ASCII 공백(공백, `\t`, `\n`, `\r`, `\v`, `\f` — 헬퍼가 지우는 C 로캘의 `[:space:]`)만 다듬고, 그 결과가 `^[0-9a-f]{32}$`에 맞을 때만 그 sha256 16진수를 돌려주고, 아니면 `""`를
돌려줍니다. `runOS`가 그것을 부릅니다. 그래서 `/etc/machine-id`에 `uninitialized`, 대문자, 짧은 id, 잡문자가 있으면
해시가 생기지 않습니다. 지금은 비어 있지만 않으면 무엇이든 해시합니다(Q-6). `FuzzMachineIDHash`(시드: LF가 붙은
올바른 id, CRLF가 붙은 id, `uninitialized`, 빈 값, 16진수 31자, 중간에 공백이 있는 id)는 출력이 `""`이거나 소문자
16진수 64자인지 확인하고, `fuzzTargets`에 들어갑니다.

**계획.** `remedy.Build`는 `rep.Run.Host.MachineIDHash`를 읽어, `^[0-9a-f]{64}$`에 맞으면
`FixBlock.MachineIDHash`(`json:"-"`)에 복사하고 맞지 않으면 비워 둡니다. JSON에는 `fix.max_risk` 뒤에
`fix.host_guard: "on" | "off"`가 추가됩니다. 해시는 `fix` 아래에 다시 적지 않습니다. 모든 리포트처럼 plan JSON의
`run.host.machine_id_hash`에 이미 있습니다. 표는 바뀌지 않습니다.

**프롤로그 순서.** 프롤로그는 이 순서가 됩니다: `set -u`, `umask 077`, `log()`, 해시 헬퍼, 루트 확인, 가드,
`MUSTER_BACKUP` 기본값과 case, `mkdir`, 소유자 확인, `backup()`, `restore()`, `save_units()`, `restore_units()`,
`failed=0`. `log()`를 앞으로 옮겨도 동작은 바뀌지 않습니다(출력만 합니다). 가드가 켜져 있으면:

```sh
muster_machine_id_hash() {
  id=$( { tr -d '[:space:]' < "$1"; } 2>/dev/null ) || id=
  case "$id" in *[!0-9a-f]*|'') return 0;; esac
  [ "${#id}" -eq 32 ] || return 0
  { printf '%s' "$id" | sha256sum | cut -d' ' -f1; } 2>/dev/null
}
```

```sh
MUSTER_SNAPSHOT_HOST=<hash>
here=$(muster_machine_id_hash /etc/machine-id)
if [ "$here" != "$MUSTER_SNAPSHOT_HOST" ]; then
  if [ "${MUSTER_ANY_HOST:-}" = 1 ]; then
    log "warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1"
  else
    printf 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n' >&2
    exit 2
  fi
fi
```

가드가 꺼져 있으면 헬퍼도 가드도 내보내지 않고, 가드가 있었을 자리에 주석 한 줄
`# host guard: off (the snapshot has no machine id)`만 둡니다. 두 경우 모두 헤더 줄은 그대로입니다.

- **collector와 헬퍼는 일치한다.** 둘 다 정확히 소문자 16진수 32자인 id만 받아들이고, 같은 ASCII 여섯 바이트를
  공백으로 봅니다. 유니코드 공백(U+00A0, U+0085)은 다듬지도 지우지도 않으므로, 그런 id는 양쪽 모두에서 해시가
  생기지 않습니다. collector는 양 끝을 다듬고, 헬퍼는 ASCII 공백 문자를 모두 지웁니다. 둘이 달라질 수 있는 경우는 중간에 공백이 있는 id뿐입니다. 그때는
  collector가 해시를 내지 않으므로 가드가 꺼지고 헬퍼도 내보내지 않습니다. 가드가 켜져 있다면 스냅샷의 id가
  올바랐다는 뜻이고, 같은 호스트에서 헬퍼는 같은 값을 계산합니다. 헬퍼가 읽거나 해시할 수 없는 경우(파일이 없음,
  읽을 수 없음, 빈 파일, `uninitialized`, `sha256sum` 없음)에는 `here`가 비어 거부되고, stderr에는 거부 문구 말고는
  아무것도 나가지 않습니다. collector는 심볼릭 링크를 따라가지 않고 읽으므로, `/etc/machine-id`가 심볼릭 링크이면
  스냅샷에 해시가 없고 가드가 꺼집니다.
- **가드의 한계.** 첫째, 스냅샷에 해시가 없으면(id 없는 컨테이너, 심볼릭 링크인 id 파일, 손으로 고친 스냅샷)
  가드는 열린 채로 실패합니다. 이때 스크립트에는 가드가 없고, 주석으로 그렇게 말합니다. 둘째, 한 이미지에서 id를
  다시 만들지 않고 복제한 호스트들은 같은 id를 공유하고, 가드는 그들을 구별하지 못합니다. 셋째, 가드가 막는 것은
  잘못된 스냅샷의 스크립트를 실행하는 일이지, 조작된 스냅샷이나 복제된 id가 아닙니다. `THREAT_MODEL.md`는 세 가지를
  모두 적습니다.
- **D34 수정.** 메인 설계와 §4.2의 `internal/remedy` 행에서 "호스트 값은 명령에 들어가지 않는다"에 예외가 하나
  생깁니다. machine-id 해시이며, 셸 문법을 담을 수 없는 소문자 16진수 64자일 때만 허용합니다.
- **exit 2의 사유는 이제 세 가지입니다**(루트 아님, 다른 호스트, 쓸 수 없는 백업 디렉터리). 어느 경우에도 아무것도
  실행되지 않았습니다. `MUSTER_ANY_HOST`는 해시가 다를 때만 읽습니다.
- **헬퍼는 공유 문자열이다.** `internal/remedy`는 헬퍼 텍스트를 `MachineIDHashHelper`로 export하고 그 상수에서
  렌더합니다. `TestHostGuardHashMatchesTheCollector`(`internal/remedy`, Linux 빌드 태그)는 헬퍼를 `sh`로 임시 파일에
  돌립니다. `collectors`는 테스트에서만 import하고, purity 테스트는 `.TestImports`가 아니라 `.Imports`를 읽으므로
  허용됩니다. 끝에 줄바꿈, CRLF, 앞쪽 공백, 앞쪽 줄바꿈이 있는 id에서는 collector의 값과 같아야 합니다.
  `uninitialized`, 대문자, 31자, 공백뿐인 파일, 빈 파일, 없는 경로에서는 collector와 헬퍼가 모두 빈 출력이어야
  합니다. 중간에 공백이 있는 id에서는 collector가 해시를 내지 않는다는 것만 확인합니다. 둘은 그 입력에서 설계상 다르고,
  그런 스냅샷에는 헬퍼를 내보내지 않기 때문입니다.
- **가드 테스트.** `internal/remedy`의 Linux 테스트로, 렌더한 스크립트에서 `strings.Replace`로 `/etc/machine-id`를
  임시 machine-id 경로로 바꾸고 바뀌었는지 확인한 뒤 실행합니다. 확인하는 동작은 다음과 같습니다.
  - 해시가 같으면 통과합니다.
  - 다르면 exit 2로 끝나고, stderr에 정확히 거부 문구 한 줄만 나오며, `MUSTER_BACKUP`을 만들지 않습니다.
  - 다르고 `MUSTER_ANY_HOST=1`이면 경고를 출력하고 실행합니다.
  - id 파일이 없으면 정확히 거부 문구와 함께 exit 2입니다.

  `runScriptStreams`는 물려받은 환경에서 `MUSTER_ANY_HOST`를 뺍니다. `fullPlan`에 형식이 맞는 해시를 넣어 `full.sh`
  골든이 가드가 켜진 프롤로그를 렌더하게 하고, `empty.sh`는 가드를 끈 채로 둡니다. `cmd/muster` e2e는 해시가 있는
  스냅샷에서 `host_guard: on`, 없는 스냅샷에서 `off`를 확인합니다.
- **줄 계약.** D34를 강제하는 `TestScriptEveryLineIsTemplateBodyOrComment`는 헬퍼 줄, 가드 줄, 그리고 값이 정확히
  소문자 16진수 64자인 `MUSTER_SNAPSHOT_HOST=` 한 줄을 템플릿 텍스트로 인정합니다. poison 계획은 형식이 틀린
  해시를 담고, 그 값은 주석이 아닌 어느 줄에도 나오지 않아야 합니다.

## 3. 유닛 상태 (Q-2)

**스키마와 lint.** `Remediation`에 `Units []string`(`yaml:"units,omitempty"`)이 추가됩니다. control 단위 lint
규칙은 다음과 같고, 규칙마다 `TestLintRules` 케이스가 있습니다.

- `units_charset` — 항목마다 `^[A-Za-z0-9][A-Za-z0-9._:-]*(@[A-Za-z0-9._:-]+)?\.(service|socket)$`에 맞아야
  하고(템플릿 유닛은 비어 있지 않은 인스턴스가 있어야 합니다), 중복은 없어야 합니다.
- `units_order` — `units`에서 `<name>.socket`은 모두 `<name>.service`보다 앞에 와야 합니다. 소켓이 서비스를
  활성화하기 때문입니다. collector의 행은 rpcbind를 service 먼저 적으므로, 순서는 collector가 아니라 control이
  정합니다.
- `units_needs_script` — `units`에는 `script`가 있어야 합니다.
- `script_way_back`(확장) — `script`에는 `rollback`, `backup`, `units` 중 하나가 있어야 합니다.
- `units_exclusive` — `units`는 `rollback`과도 `backup`과도 함께 쓸 수 없습니다. 유닛 control은 유닛 상태로만
  되돌리므로, 유닛을 다시 시작한 뒤에 설정 파일 복원이 도는 일이 없습니다.
- `units_variable` — `$UNITS`나 `${UNITS`는 `script` 안에서만, 그리고 `units`가 선언된 경우에만 쓸 수 있습니다.
  그것을 담은 `validate`(`set -u` 아래에서 `UNITS`가 설정되어 있지 않은 곳)나 `rollback`은 거부합니다.
- `backup_reserved` — `backup` 경로는 `/muster-units`이거나 `/muster-units/` 아래이면 안 됩니다(템플릿의 상태
  디렉터리, 아래 참조).
- `script_needs_validate` — `script`에는 `validate`가 있어야 합니다(16개 모두 있습니다. §4의 실패 실행이 모든 블록의
  validate를 고칩니다).

세트 단위 lint는 control 단위 검사가 끝난 뒤 세트 전체에 한 번 돕니다. 위반이 있으면 id 순으로 뒤에 오는
control에 Problem 하나를 남기고 앞의 control을 적습니다. 규칙은 `backup_path_shared`(scripted control 두 개가 같은
`backup` 경로를 선언)와 `units_shared`(두 개가 같은 유닛을 선언)입니다. `TestLintSetRules`가 control 두 개짜리
세트로 둘 다 다룹니다.

**계획.** `Item`에 `Units []string`이 추가됩니다. JSON 이름은 `units`이고, 위치는 `backup` 뒤입니다(…, `rollback`,
`backup`, `units`, `validate`, `planned`). 항상 있고, 없으면 `[]`이며, `Backup`처럼 `Script`가 true일 때만 채웁니다.
`remedy.Build`는 id를 다시 확인하듯(Z-26) 모든 유닛을 `units_charset` 패턴으로 다시 확인하고, 맞지 않으면 계획을
거부합니다. `Item.Rollback`은 `none | declared | restore_backup | units | both`가 됩니다. `both`는 여전히
`rollback`과 `backup`이 함께 있는 경우입니다(lint가 이제 `units`와 그 둘의 조합을 금지합니다). 표의 롤백 열도 같은
단어를 보여 줍니다.

**템플릿.** 유닛을 선언한 블록은 `backup` 줄이 있었을 자리에
`save_units <u…> || { log "<id>: backup failed, nothing changed"; return 1; }`를 부르고, 실패 경로마다
`restore_units <u…> || log "<id>: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`를 부릅니다. 유닛 이름은 선언된
리터럴입니다. 기록은 `$MUSTER_BACKUP/muster-units/` 아래의 파일 두 개입니다. `<u>`에는
`<is-enabled> <is-active>`가 들어가고, `<u>.deps`에는 `<u>`를 멈추면 함께 멈추는 활성 유닛들(systemd의 역방향
`Requires=`, `BindsTo=`, `PartOf=`)이 한 줄에 하나씩 들어갑니다. 프롤로그의 헬퍼는 다음과 같습니다.

```sh
save_units() {
  mkdir -p "$MUSTER_BACKUP/muster-units" || return 1
  for u in "$@"; do
    f="$MUSTER_BACKUP/muster-units/$u"
    if [ -f "$f" ] && ! grep -qx 'absent absent' "$f"; then log "$u: unit state exists, keeping the first"; continue; fi
    if systemctl cat -- "$u" >/dev/null 2>&1; then
      ue=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
      ua=$(systemctl is-active -- "$u" 2>/dev/null) || :
      printf '%s %s\n' "${ue:-unknown}" "${ua:-unknown}" > "$f" || return 1
      : > "$f.deps" || return 1
      for d in $(systemctl show -p RequiredBy -p BoundBy -p ConsistsOf --value -- "$u" 2>/dev/null); do
        if systemctl is-active --quiet -- "$d"; then printf '%s\n' "$d" >> "$f.deps" || return 1; fi
      done
    else
      printf 'absent absent\n' > "$f" || return 1
    fi
  done
}
restore_units() {
  urc=0
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    [ "$ue" = absent ] || systemctl --quiet unmask -- "$u" || urc=1
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      enabled) systemctl --quiet enable -- "$u" || urc=1;;
      enabled-runtime) systemctl --quiet enable --runtime -- "$u" || urc=1;;
      linked|linked-runtime) log "$u: was $ue; the link is not restored"; urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      disabled) now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
        case "$now" in
          enabled) systemctl --quiet disable -- "$u" || urc=1;;
          enabled-runtime) systemctl --quiet disable --runtime -- "$u" || urc=1;;
        esac;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in
      masked) systemctl --quiet mask -- "$u" || urc=1;;
      masked-runtime) systemctl --quiet mask --runtime -- "$u" || urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in masked|masked-runtime) continue;; esac
    case "$ua" in active|activating|reloading) systemctl --quiet start -- "$u" || urc=1;; esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u.deps" ] || continue
    while read -r d; do
      systemctl is-active --quiet -- "$d" || systemctl --quiet start -- "$d" || urc=1
    done < "$MUSTER_BACKUP/muster-units/$u.deps"
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    [ "$ue" = absent ] && continue
    now=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
    [ "${now:-unknown}" = "$ue" ] || { log "$u: enablement not restored (was $ue, now ${now:-unknown})"; urc=1; }
  done
  return $urc
}
```

- **각 단계.**
  1. *unmask* — `absent`를 뺀 모든 기록된 유닛을 unmask합니다. 본문은 `/etc`에 영속 mask를 걸고, 그것이 `/run`의
     runtime mask보다 우선합니다. 이 단계가 없으면 `masked-runtime`으로 기록된 유닛에 본문의 영속 mask가 남습니다.
  2. *enable* — `enabled`/`enabled-runtime`이었던 것을 enable합니다(뒤의 것은 `--runtime`으로). `linked*`는
     되돌리지 못했다고 로그로 남깁니다. 본문의 `disable`이 링크를 지우고, 템플릿은 그것을 다시 만들 수 없습니다.
  3. *다시 disable* — `disabled`로 기록되었는데 `enable`이 `Also=` 짝을 통해 켜 버린 유닛을 다시 끕니다(EL의
     `rpcbind.service`에는 `Also=rpcbind.socket`이 있습니다).
  4. *다시 mask* — `masked`/`masked-runtime`이었던 것을 다시 mask합니다. 모든 enable 뒤에 오므로, 방금 mask한 짝
     때문에 enable이 거부되는 일이 없습니다.
  5. *start* — `active`, `activating`, `reloading`이었던 것을 start합니다. 다시 mask한 유닛은 예외입니다(masked
     유닛은 start할 수 없고, 기록된 동작 상태는 되돌리지 않습니다).
  6. *의존 유닛 start* — 기록된 의존 유닛 가운데 다시 active가 아닌 것을 start합니다.
  7. *다시 읽기* — 활성화 상태를 다시 읽습니다. `is-enabled`가 기록과 달라진 유닛은 `enablement not restored`로
     로그를 남기고 호출이 1을 돌려줍니다. `[Install]` 섹션이 없는 유닛에서는 `enable`이 exit 0이므로, 그런 유닛(손으로
     만든 `.wants` 링크로만 활성화된 유닛)이 꺼진 채로 남았다는 것은 이 단계에서만 드러납니다.
- **순서.** 필요한 유닛이 아직 masked인 동안에는 어떤 유닛도 enable하거나 start하지 않습니다. 단, 그 필요한 유닛
  자체가 masked로 기록된 경우는 예외입니다. masked 소켓 뒤에 active 서비스가 있는 경우는 미룹니다(§7).
- **단계가 끝난 뒤의 상태.** 그 밖의 상태(`disabled`, `static`, `indirect`, `generated`, `transient`, `alias`,
  `bad`, `unknown`)는 unmask 뒤에 본문이 남긴 그대로 두고, 7단계가 확인합니다. `inactive`는 멈추지 않습니다(본문이
  이미 멈췄습니다).
- **첫 기록 유지.** 같은 `MUSTER_BACKUP`으로 여러 번 실행해도 첫 파일 복사본처럼 첫 기록을 유지합니다. 단,
  `absent` 기록은 예외로, 유닛이 생기면 다시 씁니다. 그래서 실행 사이에 설치된 유닛은 그때의 상태로 기록됩니다.
- **상태 디렉터리.** `$MUSTER_BACKUP/muster-units/`는 백업과 겹칠 수 없습니다(`backup_reserved`). 헬퍼는 자기
  변수 이름(`u`, `f`, `d`, `ue`, `ua`, `now`, `urc`)을 쓰고 블록의 `rc`를 건드리지 않습니다. 의존 유닛의 이름은 실행
  시점에 systemd에서 옵니다. 경로가 아니라 파일 내용으로만 저장하고, `--` 뒤에 따옴표로 감싸 넘깁니다.
- **본문은 선언된 목록을 읽는다.** 유닛을 선언한 블록은 본문 subshell 안의 첫 줄로 `UNITS='<u1> <u2> …'`를
  내보냅니다. 본문 10개는 모두 `$UNITS`를 도는 루프이고, 유닛이 하나인 본문도 마찬가지입니다. SC2043은 단어
  하나짜리 리터럴 목록에서만 경고하므로 `if` 형태는 없앱니다. validate는 지금처럼 유닛 이름을 명시합니다(한 줄,
  루프 없음).
- **만들어진 대로: 본문은 무엇이든 바꾸기 전에 모든 이름을 확인한다.** 왕복 검증(§4)은 3D-2의 본문이 모든 Debian과
  Ubuntu NFS 서버에서 실패한다는 것을 찾았습니다. `nfs-kernel-server.service`는 `nfs-server.service`의 별칭이고,
  루프가 실제 유닛을 mask하고 나면 별칭에 대한 `disable --now`가 실패했습니다(`Unit … not loaded`). 그래서 모든
  본문은 두 번 돕니다. 1차는 `systemctl cat`이 찾고 `systemctl show -p Id --value`가 자기 자신과 같은 이름만
  `todo`에 모읍니다. 무엇이든 mask하기 전에 확인하므로, 별칭은 아직 실제 유닛으로 풀릴 때 건너뛰고, 그 실제 유닛은
  같은 목록에 있습니다. 2차는 `todo`에 대해 `systemctl --quiet disable --now`와 `systemctl --quiet mask … || true`를
  실행합니다. debian12-init 실패 실행은 별칭을 `alias active`로 기록하고 바이트 단위로 그대로 복원합니다.
- **collector와 validate에 고정한다.** `TestServiceScriptsNameTheCollectorsUnits`(Linux, 서비스 표 옆)는 서비스
  control마다 `units`를 집합으로서 `services.go`에서 그 control이 대응하는 행들의 `provesInstall` 유닛과
  비교합니다(`tftp_talk_disabled`는 두 행에 대응합니다). control의 `validate`에 있는 `.service`/`.socket` 토큰도 그
  집합과 같아야 하고, 유닛을 선언한 control의 `script`는 유닛 이름을 리터럴로 적으면 안 됩니다. 이것으로 3D-2 Task
  3 N1은 `units`와 validate에 대해서 닫힙니다. 토큰 검사는 여전히 `.service`/`.socket` 단어만 봅니다. 10개 control은
  `automount_disabled`, `dos_services_disabled`, `finger_disabled`, `nfs_server_disabled`, `nis_disabled`,
  `rpcbind_disabled`, `rservices_disabled`, `snmp_disabled`, `telnet_disabled`, `tftp_talk_disabled`이고, 테스트가 개수를
  확인합니다.
- **stub에 대해서만 실행한다.** 유닛을 선언한 렌더 스크립트를 실행하는 Go 테스트는 `PATH` 맨 앞에 stub
  `systemctl`을 둡니다. stub은 임시 디렉터리의 스크립트로, 인자를 로그로 남기고 `cat`, `is-enabled`, `is-active`,
  `show`에 fixture 파일로 답하며, `enable`, `disable`, `mask`, `unmask`, `start`에 따라 fixture 상태를 바꿉니다. 테스트
  스위트의 어떤 것도 러너의 systemd에 닿지 않습니다.
- **`TestUnitHelpersRestoreRecordedState`**(Linux)는 다음 기록 상태마다 실패한 블록을 거치게 합니다: `enabled`,
  `enabled-runtime`, `disabled` + `active`, `masked`, `masked-runtime`, `masked` + `active`, `linked`, `static`,
  `absent`, `unknown`, 두 번째 실행에서 유닛이 생긴 `absent` 기록, `enable`이 켜 버린 `Also=` 짝, exit 0이지만 유닛을
  꺼진 채로 두는 `enable`, enabled 서비스 앞의 masked 소켓, active 의존 유닛. 확인하는 것은 다음과 같습니다.
  - 로그된 호출 순서와 일곱 단계의 순서
  - 두 번째 실행에서 첫 기록 유지
  - 모든 `not restored` 줄
  - stub 호출이 실패할 때의 `ROLLBACK INCOMPLETE`
- **D34 줄 계약은 유닛도 다룬다.** `fullPlan`에 `units`를 선언한 control을 넣어, `UNITS=`, `save_units`,
  `restore_units` 줄이 렌더되고 `TestScriptEveryLineIsTemplateBodyOrComment`에서 명시적으로 인정되게 합니다. 유닛
  `x';id;'`를 선언한 poison control이 있으면 `remedy.Build`는 계획을 거부해야 합니다.

## 4. 호스트 증명 (Q-3)

**표.** `controls/testdata/_roundtrip.yaml`(`_mutants.yaml`처럼 fixture 하네스가 무시합니다)에는 스크립트가 있는
control마다 항목이 하나씩, id 순으로 들어갑니다. 항목은 어떤 행에서 증명되거나(`images`) — 이때 그 행들이 다루지
않는 선언 유닛을 `unproven_units`로 적을 수 있습니다 — 아니면 통째로 `unproven`입니다.

```yaml
- id: muster.service.finger_disabled
  unproven: no matrix image ships a systemd unit for a finger server
- id: muster.service.tftp_talk_disabled
  images: [almalinux9-init, rocky9-init]
  unproven_units:
    talk.socket: no package in the image's enabled repositories
- id: muster.service.telnet_disabled
  images: [almalinux9-init, rocky9-init]
```

사유는 자유 텍스트이며, 다음 세 원인 중 하나를 밝힙니다.

- systemd 유닛이 없음(서버가 inetd용으로만 나옴)
- 이미지의 활성 저장소에 패키지가 없음
- 컨테이너에서 유닛을 실행할 수 없음

`TestEveryScriptedControlIsInTheRoundtripTable`(`internal/controls`)은 이 표와
`.github/workflows/ci.yml`의 `fix-roundtrip` job을 읽습니다(`yaml.v3`, 이미 모듈 의존성입니다). 그리고 다음을
확인합니다.

- 표가 id 순으로 정렬되어 있습니다.
- 표의 id가 내장 세트에서 스크립트가 있는 id와 정확히 같습니다.
- 항목마다 비어 있지 않고 중복 없는 `images`와 `unproven` 사유 중 정확히 하나가 있습니다.
- `unproven_units`는 `images` 옆에만 오고, 그 키는 모두 그 control이 선언한 유닛입니다.
- `images`가 적은 키가 모두 matrix 행의 `key`입니다.
- matrix 행마다 `key`와 비어 있지 않은 `seeded`가 있습니다.
- 행마다 공백으로 나눈 `seeded`를 집합으로 비교했을 때, `images`에 그 행을 적은 id들과 같습니다.
- `muster.service.*` id는 `init`이 `"false"`인 행을 적지 않습니다.

**사전 점검.** 이미지 배정은 플랜이 정합니다. 플랜의 첫 작업이 일회용 컨테이너에서 이미지마다 사전 점검을 하고,
선언된 유닛마다 다음을 기록합니다.

- 이미지의 활성 저장소에 그 유닛을 담은 패키지가 있는지
- `enable --now`로 `active`가 되는지
- `Also=`가 있는지, 그리고 어떤 유닛이 그것을 `Requires=`, `BindsTo=`, `PartOf=`로 걸고 있는지

이미지마다 `/etc/machine-id`에 무엇이 들어 있는지도 기록합니다. 표에는 사전 점검이 찾은 결과를 적습니다. inetd
서비스로만 패키지된 서버(Debian의 `telnetd`, `fingerd`, `rsh-server`, `talkd`)는 스크립트가 닿지 않습니다.
스크립트는 systemd 유닛을 끄고 inetd는 그대로 두기 때문입니다. 그런 서버는 그 사유와 함께 `unproven`입니다. 한
행에서 제공 유닛과 그 의존 유닛을 함께 시드하는 것은, 그 의존 유닛을 6단계가 다시 시작한다는 것을 사전 점검이
보였을 때만 허용합니다.

**matrix.** 행에 `key`(`rocky9-init`, `almalinux9-init`, `ubuntu2204`, `debian12-init`)가 생기고, 빌드하는 행에는
로컬 태그 `muster-ci/debian12-init`을 가리키는 `build: debian12-init`이 붙습니다. 이미지는 job 안에서
`ci/roundtrip/debian12-init.Dockerfile`로 커밋된 다음 Dockerfile로 빌드합니다.

```dockerfile
FROM debian:12
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv netbase acl \
 && systemctl mask getty@tty1.service console-getty.service \
 && : > /etc/machine-id && rm -f /var/lib/dbus/machine-id
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
```

`/etc/machine-id`를 비워 두면 systemd가 컨테이너마다 첫 부팅에서 새 id를 만듭니다. 사전 점검은 init 이미지마다
id를 기록합니다. 만들어진 대로: `almalinux9-init`은 그 파일을 비운 채로 배포하지만 `rocky9-init`은 채워진 id를
배포하므로, 그 시드 스크립트가 무엇이든 수집하기 전에 id를 다시 만듭니다(`rm -f /etc/machine-id;
systemd-machine-id-setup`). Debian 이미지는 inline Dockerfile이 아니라 커밋된 파일에서 `docker build -f
ci/roundtrip/debian12-init.Dockerfile`로 빌드합니다.

- **부팅.** init 행은 빌드했든 받아 왔든 모두 `--privileged --cgroupns=host`로 띄우고 `ci/roundtrip/wait.sh <cid> <key>`로
  기다립니다. 이 스크립트는 `timeout 60 docker exec <cid> systemctl is-system-running --wait`를 최대 30번 돕니다. 상태가
  끝내 `running`이나 `degraded`가 되지 않으면 `systemctl --failed`를 출력하고 job을 실패시킵니다.
- **시드 스크립트.** 시드 명령은 workflow에서 `ci/roundtrip/<key>.sh`로 옮깁니다. checkout의 `ci/roundtrip/`은
  `/m`의 `bin/` 옆에 `/ci`로 읽기 전용 마운트되고, 스크립트는 그 안에서 실행됩니다.
- **shellcheck.** `make shellcheck`와 CI의 shellcheck 단계가 `ci/roundtrip/*.sh`도 검사하고, glob이 비면 실패합니다.

**시드.** `ci/roundtrip/<key>.sh`는 패키지를 설치하고 유닛을 시작합니다. Debian 계열 행에서는 exit 101을 돌려주는 임시
`/usr/sbin/policy-rc.d` 아래에서 설치하므로 패키지 스크립트가 아무것도 시작하지 않습니다. 설치 뒤에는 그것을 지우고
`systemctl reset-failed`를 실행합니다. 그런 다음 사전 점검의 결정을 유닛마다 명시적으로 적용합니다. `enable --now`,
또는 컨테이너에서 시작할 수 없는 유닛이면 `enable`만 합니다. 파일 권한은 다음과 같이 느슨하게 만듭니다.

- `chmod 664 /etc/passwd`
- `chmod 666 /etc/services` (파일이 없는 이미지에서는 먼저 `netbase`를 설치)
- `install -m 644 /dev/null /etc/hosts.lpd`
- `chmod 644 /etc/hosts`

init 행의 시드 스크립트는 각자의 두 목록 `START_UNITS`와 `ENABLE_ONLY_UNITS`에 대한 안정 확인으로 끝납니다. 앞의 목록에 있는
유닛은 `active`, 뒤의 목록에 있는 유닛은 `inactive`여야 하고, 그 밖의 상태면 유닛 이름을 적고 job이 실패합니다.
호스트 자신의 접근을 빼앗는 시드는 범위 밖이고, 16개 중 그런 시드가 필요한 것은 없습니다.

**컨테이너 배치.** 행마다의 작업 디렉터리 `$d` 아래에 컨테이너마다 하위 디렉터리 `$d/repair`와 `$d/fail`이 있고,
각자의 컨테이너에 `/out`으로 마운트됩니다. `trap` 하나가 두 컨테이너를 모두 지웁니다.

**수리 실행**(모든 행, 첫 컨테이너)은 3D-2의 job과 같습니다. collect, 계획, 시드한 id가 모두 스크립트가 있는 계획
항목인지 확인, 스크립트 실행(exit 0), 다시 collect, 시드한 id가 모두 `PASS`나 `NOT_APPLICABLE`인지 확인합니다.

**실패 실행**(init 행만)은 첫 컨테이너처럼 띄우고 시드한 두 번째 컨테이너에서 합니다.

1. 이 컨테이너 안에서 collect하고 계획합니다. 수리 실행의 스크립트는 다시 쓰지 않습니다. 두 계획 모두
   `fix.host_guard`가 `on`이고 두 계획의 `run.host.machine_id_hash`가 비어 있지 않으며 서로 다른지 확인합니다. 아니면
   행 이름을 적고 실패합니다.
2. 다음을 기록합니다.
   - 계획된 scripted 서비스 항목이 선언한 유닛과, 그 유닛들을 `Requires=`, `BindsTo=`, `PartOf=`로 거는 유닛마다
     `systemctl is-enabled`와 `is-active`
   - 계획된 scripted 항목이 선언한 백업 경로마다 `stat -c '%u %g %a'`, `sha256sum`, 그리고 `getfacl`이 있으면
     `getfacl -cp`. 경로가 없으면 `absent`로 적습니다. sshd 블록은 drop-in을 만들고, 롤백은 그것을 다시 지워야
     합니다.
3. **가드 실행:** 수리 실행의 스크립트를 `$d/repair`에서 `$d/fail`로 `repair-fix.sh`라는 이름으로 복사해 이
   컨테이너에서 실행합니다. 거부 문구와 함께 exit 2여야 하고, 그 뒤에도 2단계의 기록이 그대로여야 합니다.
4. 이 컨테이너의 스크립트를 복사하고, muster의 출력이 아니라 사본만 고칩니다. 렌더러는 validate subshell 바로 앞에
   고정된 주석 줄 `  # validate`를 내보냅니다(줄 계약이 인정합니다). 계획된 scripted 블록마다 그 표지 다음 줄의 다음
   줄, 즉 validate subshell 안의 첫 명령을 `    false`로 바꿉니다. 한 단계가 사본이 원본과 계획된 scripted 블록마다
   정확히 한 줄씩만 다른지 확인합니다(`script_needs_validate`로 모든 scripted 블록에 validate가 있습니다).
5. 사본을 `set +e`로 실행합니다. exit 1, 블록마다 `validate failed, rolling back` 한 줄, 그리고
   `ROLLBACK INCOMPLETE`, `not restored`, `rollback failed` 줄이 없을 것을 요구합니다.
6. 유닛 상태, stat, 체크섬, ACL이 모두 2단계의 기록과 같아야 합니다.

시드했든 안 했든 계획된 scripted 블록은 모두 실패 실행에 참여합니다(예를 들어 Debian의 `shadow_permissions`).
그래서 기록은 스크립트가 건드릴 모든 것을 다룹니다. job의 `timeout-minutes`는 40으로 올립니다. 플랜은 브랜치의 첫
실행에서 Debian 빌드와 두 번째 컨테이너에 걸린 시간을 재고, 그 결과를 Execution notes에 기록합니다.

## 5. 파일 스크립트와 작은 항목들 (Q-4, Q-5)

**기호식 모드.** 파일 스크립트 5개는 모드를 지정하는 대신 금지된 비트를 지웁니다.

| control | 이전 | 이후 |
|---|---|---|
| `hosts_permissions`, `hosts_lpd_permissions` | `chmod 600` | `chmod u-xs,g-rwxs,o-rwxt` |
| `passwd_permissions`, `services_permissions` | `chmod 644` | `chmod u-xs,g-wxs,o-wxt` |
| `shadow_permissions` | `chmod 400` | `chmod u-wxs,g-rwxs,o-rwxt` |

`passwd_permissions`와 `shadow_permissions`에서는 `setfacl -b` 줄(`command -v` 가드 뒤)이 `chmod` 앞으로 옮겨집니다.
확장 ACL이 있는 파일에서는 그룹 비트가 ACL mask입니다. 그래서 `chmod`를 먼저 하면 mask만 바뀌고, 이어지는
`setfacl -b`가 넓은 `group::` 항목을 그룹 비트로 되살립니다.

`validate`는 control의 validate가 지금 쓰는 것과 같은 `stat -c` 형식(`%u %g %a`, shadow는 `%u %a`)에 대한 한 줄이
됩니다.

```sh
case "$(stat -c '%u %g %a' /etc/hosts)" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac
```

- **패턴.** control의 기본 `allowed_modes`에 있는 모드를 그 목록 순서대로 씁니다. 파라미터가 없는 `passwd`는 그 모드
  clause의 리터럴 목록을 씁니다. 패턴마다 소유자 접두어 뒤에 `strconv.FormatInt(mode, 8)`(`%a`가 출력하듯 앞에 0을
  붙이지 않음)로 씁니다. 끝의 `*) false` 갈래는 반드시 있어야 합니다. 아무것에도 맞지 않는 `case`는 exit 0이기
  때문입니다.
- **`TestFileValidatesAcceptTheDefaultModes`**(`internal/controls`)는 다섯 id를 고정하고 개수를 확인합니다. 소유자
  표는 테스트 안에 고정합니다(네 control은 `%u %g %a`와 `0 0`, shadow는 `%u %a`와 `0`). 그리고 `backup[0]`, 형식,
  접두어, 패턴 목록으로 validate를 바이트 단위로 다시 만들어 내장된 validate와 비교합니다.
- **`TestFileScriptsRepairOnARealFile`**(`internal/remedy`, Linux, euid가 0이 아니면 건너뜀. CI의 root 단계가 돌림).
  control마다 임시 파일을 만들어 `chown 0:0`하고, 그 경로를 본문과 validate에 넣습니다. 허용된 모드에서는 validate가
  exit 0이어야 합니다. 느슨해진 모드(특수 비트가 있는 경우, 그리고 `setfacl`이 있으면 `g::rw`와 이름 있는 항목을 담은
  확장 ACL이 있는 경우)마다 validate가 exit 1이고, 본문을 실행한 뒤에는 validate가 exit 0이어야 합니다. 가이드보다
  엄격한 파일은 모드가 그대로여야 합니다.
- **텍스트.** `text_en`/`text_ko`는 가이드의 목표 모드를 유지하고 "(스크립트는 비트를 지우기만 하므로 더 엄격한
  파일은 그대로 둡니다)"를 덧붙입니다. 소유자 줄은 바뀌지 않습니다.

**공유된 백업 경로와 유닛**은 §3의 세트 단위 규칙 두 개입니다.

**Escape.** `escapeRune`이 다음을 풀어 씁니다.

- `unicode.Cf`의 모든 문자(서식 문자: soft hyphen, 양방향 제어 문자 U+061C, U+200E, U+200F, U+202A–U+202E,
  U+2066–U+2069, 폭 없는 문자 U+200B–U+200D, U+2060–U+2064, U+FEFF, U+FFF9–U+FFFB, tag 블록)
- `unicode.Zl`과 `unicode.Zp`(U+2028, U+2029)
- 한글 채움 문자 U+115F, U+1160, U+3164, U+FFA0

표기는 `\u%04x`이고, U+FFFF보다 큰 문자는 `\U%08x`입니다. `Escape`와 `EscapeNoCut`을 부르는 곳은 모두 바뀝니다.
check와 fix의 표, 스크립트의 주석 줄, waiver·프로파일·튜닝 텍스트, control 텍스트입니다. 출력이 바뀌는 것은 새로
이스케이프하는 문자가 나오는 곳뿐입니다(CHANGELOG "Changed". 내장 control 텍스트에는 그런 문자가 없습니다).

- **`TestEscapeSpellsOutBidiAndSeparators`**는 문자 분류와 경계 사례(U+00AD, U+061C, U+200D, U+2028, U+3164, U+E0001,
  그리고 그대로 남는 일반 한글 음절)를 고정하고, poison 테스트를 위해 문자 목록을 export합니다.
- **poison 테스트.** remedy의 `poison.sh`/`poison.table` 골든에 그 문자들이 추가됩니다. report의
  `TestTablePoisonedSnapshotWritesNoRawControlBytes`는 그 문자들을 poison 문자열에 넣고 목록 전체에 대해
  `!strings.ContainsRune(out, r)`을 확인합니다. remedy의 `TestTablePoisoned`도 같은 문자 검사를 얻습니다.

**`--quiet`.** 서비스 본문은 `systemctl --quiet disable --now`와 `systemctl --quiet mask`를 부르고, 유닛 헬퍼도 상태를
바꾸는 호출마다 `--quiet`를 넘깁니다. `--quiet`는 systemctl의 결과 줄을 억누를 뿐, 다시 실행했을 때 아무것도
출력하지 않는다는 약속은 아닙니다(systemd 자체의 경고와 템플릿의 `keeping the first` 줄은 남습니다).

## 6. 테스트, CI, 문서

**테스트.** §2–§5에 적은 새 테스트에 더해 다음이 있습니다.

- `TestLintRules`에 §3의 control 단위 규칙마다 케이스가 추가됩니다.
- `TestPlanRollbackVocabulary`에 `units`가 추가됩니다.
- `TestScriptGolden`은 골든 5개를 다시 만듭니다. `full.sh`에는 켜진 가드, 유닛 control, `# validate` 표지가 들어가고,
  `all-scripted.sh`는 `UNITS=` 본문 10개를 렌더합니다.
- `TestScriptUnitsBlockOrder`는 `save_units`가 본문 subshell 앞에 있는지, `restore_units`가 모든 실패 경로에 있는지,
  모든 validate subshell 앞에 `# validate` 표지가 있는지 확인합니다.
- `TestJSONGolden`에 `host_guard`와 `units`가 정해진 위치로 추가됩니다.
- `FuzzMachineIDHash`가 `fuzzTargets`에 들어갑니다.
- mutation 테스트는 살아남는 mutant가 0이어야 합니다.

**CI.** §4의 `fix-roundtrip` matrix와 그 수리·실패·가드 실행, `ci/roundtrip/wait.sh`와 시드 스크립트, 그리고
`ci/roundtrip/*.sh`에 대한 shellcheck 단계입니다. fix 리포트가 바뀌므로 머지 전에 examples 갱신이 반드시
필요합니다.

**문서**(영어와 한국어를 같은 커밋에).

- **메인 설계.**
  - D34를 수정하고, 그에 따라 §4.2의 `internal/remedy` 행도 고칩니다(§2).
  - §6.2에 `units`와 control 단위 lint 규칙을 넣습니다.
  - §6.8에 세트 단위 규칙 두 개를 넣습니다.
  - §7.5에 가드, 유닛 헬퍼, exit 2의 세 번째 사유를 넣습니다.
  - §10.2에서 3D-2b를 merged로 표시하고 3D-2c를 적습니다.
- **`CLAUDE.md` "Fix (stage 3D-2)".** 가드, `units`, 라운드트립 표, 기호식 모드를 추가합니다. 이 설계로 틀리게 된
  문장도 모두 바꿉니다.
  - `script`에는 `rollback`이나 `backup`이 필요하다 (이제: `rollback`, `backup`, `units` 중 하나와 `validate`)
  - `validate`는 한 줄, `&&`로 잇는다 (이제: 한 줄이며, `&&`로 이은 조건이나 `*) false` 갈래가 있는 `case` 하나)
  - 서비스 본문 문장 (이제: `units`를 선언하고 `$UNITS`를 돈다)
  - 롤백은 모든 유닛을 unmask한 뒤 모든 유닛을 `enable --now`한다
  - 유닛이 하나인 본문은 `if`를 쓴다
  - `fix-roundtrip` 설명
  - exit 2 사유
  - `make shellcheck` 항목 (이제 `ci/roundtrip/*.sh` 포함)
- **`CONTRIBUTING` 쌍.**
  - 서비스 스크립트는 `units`를 선언하고 `$UNITS`를 돕니다.
  - 위의 validate 규칙
  - 새 scripted control은 `_roundtrip.yaml`에 추가합니다.
- **README 쌍.** 상태 줄과 로드맵 항목입니다.
- **`THREAT_MODEL.md`.** 호스트 가드, `MUSTER_ANY_HOST`, 스크립트에 들어가는 해시, 그리고 §2의 한계 세 가지(해시가 없으면
  열린 채로 실패, 조작된 스냅샷은 잡지 못함, 복제된 id는 구별하지 못함)를 적습니다.
- **`examples/README.md`.** fix 리포트에 이제 가드 줄이 들어 있다고 적습니다.
- **`CHANGELOG`.**
  - Added: 호스트 가드, `units`, 실패·가드 실행
  - Changed: `Escape`, 롤백 분류, 프롤로그 순서, 형식이 틀린 id에서 빈 `machine_id_hash`
  - Controls: 16개의 remediation 블록이며, 판정 변화는 없습니다.

## 7. 미룬 항목

- 16개 밖의 control 스크립트와 그에 필요한 파라미터 치환 규칙(3D-2c).
- `fix --dry-run --result`, `each` control의 대상별 계획, 네 번째 소비자가 생기면 `check.Result`에 둘 구조적 판정
  표지, `explain` — 3D-2 §8 그대로.
- `linked` 유닛의 링크 복원, 그리고 masked로 남은 유닛의 기록된 동작 상태 복원(로그로 남김, §3).
- active 서비스 앞의 masked 소켓(§3 순서).
- machine id를 넘어서 복제된 호스트를 구별하는 일(§2).
- `.service`/`.socket` 단어가 아닌 유닛 이름의 토큰 검사(3D-2 Task 3 N1 중 `units` 밖의 부분).
- 플랜의 사전 점검이 `unproven`이나 `unproven_units`로 표시하는 항목은, 그 사유와 함께, 어떤 이미지가 systemd
  유닛으로 패키지할 때까지.
