# 3D-2b단계 — 검증된 검토용 스크립트: 호스트 가드, 유닛 상태, 라운드트립

영어 원본: `2026-10-13-stage3d2b-remedy-proof-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`
(§4.2 패키지, §6.2 스키마, §7.5 `fix --dry-run`, §10.2 로드맵, D24, D34). 이 사이클이 마무리하는 설계:
`2026-10-07-stage3d2-fix-dry-run-design.ko.md`(X-1..X-10, §8 미룬 항목)와 그 플랜의 미룬 항목 목록. 리뷰
이력: fresh 리뷰 워크플로 한 번(에이전트 145개: 관점 다섯, 발견마다 반박자 셋, critic 하나. 살아남은 발견 29개와
critic 발견 7개)을 이 개정판에 접어 넣었습니다. 이 설계의 판정은 Q 목록입니다.

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
  (`remediation.units`). 템플릿은 본문이 돌기 전에 유닛마다 활성화 상태와 동작 상태를 기록하고, 실패하면 기록한
  영속 상태를 되돌립니다. masked였던 것은 다시 mask하고, enabled였던 것만 enable하고, active였던 것만
  start하며, 되돌릴 수 없는 것은 로그로 남깁니다. 손으로 쓴 서비스 롤백 10개는 지웁니다(§3).
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
  `Escape`가 줄·문단 구분자, 양방향 제어 문자, 폭 없는 서식 문자를 풀어 씁니다. 서비스 본문과 유닛 헬퍼는
  `systemctl`에 `--quiet`를 넘깁니다(§5).
- **Q-6 — 판정은 바뀌지 않는다.** `checks`, `params`, fact는 바뀌지 않습니다. remediation 블록이 바뀌므로
  `controls/VERSION`이 올라가고, 그에 따라 controls digest, 골든, examples도 바뀝니다. plan JSON에는 `fix.host_guard`,
  항목마다의 `units`, 롤백 값 `units`가 추가됩니다(추가만 하므로 plan 스키마는 1을 유지합니다). 이스케이프 변경으로
  check 표가 바뀌는 것은 새로 이스케이프하는 문자를 담은 스냅샷뿐입니다(§5).

## 2. 호스트 가드 (Q-1)

**계획.** `remedy.Build`는 `rep.Run.Host.MachineIDHash`를 읽어, `^[0-9a-f]{64}$`에 맞으면
`FixBlock.MachineIDHash`(`json:"-"`)에 복사하고 맞지 않으면 비워 둡니다. JSON에는 `fix.max_risk` 뒤에
`fix.host_guard: "on" | "off"`가 추가됩니다. 해시는 `fix` 아래에 다시 적지 않습니다. 모든 리포트처럼 plan JSON의
`run.host.machine_id_hash`에 이미 있습니다. 표는 바뀌지 않습니다.

**프롤로그 순서.** 프롤로그는 이 순서가 됩니다: `set -u`, `umask 077`, `log()`, 해시 헬퍼, 루트 확인, 가드,
`MUSTER_BACKUP` 기본값과 case, `mkdir`, 소유자 확인, `backup()`, `restore()`, `save_units()`, `restore_units()`,
`failed=0`. `log()`를 앞으로 옮겨도 동작은 바뀌지 않습니다(출력만 합니다). 가드가 켜져 있으면:

```sh
muster_machine_id_hash() {
  id=$(tr -d '[:space:]' < "$1" 2>/dev/null) || id=
  case "$id" in *[!0-9a-f]*|'') return 0;; esac
  [ "${#id}" -eq 32 ] || return 0
  printf '%s' "$id" | sha256sum | cut -d' ' -f1
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

- **헬퍼가 받아들이는 id.** systemd는 machine id를 소문자 16진수 32자로 씁니다. 헬퍼는 공백 문자를 모두 지우고
  32자 16진수 id만 해시합니다. 그 밖의 경우(파일이 없음, 읽을 수 없음, 빈 파일, `uninitialized`, 중간에 섞인
  잡문자, `sha256sum` 없음)에는 `here`가 비고, 어떤 해시와도 다르므로 거부됩니다. 형식이 맞는 파일에서는 결과가
  collector(`strings.TrimSpace` 뒤 sha256)와 같습니다. 올바른 id에는 중간 공백이 없기 때문입니다. 그 밖의 파일에서는
  스크립트가 안전한 쪽(거부)으로 실패합니다. collector는 심볼릭 링크를 따라가지 않고 읽으므로, `/etc/machine-id`가
  심볼릭 링크이면 스냅샷에 해시가 없고 가드가 꺼져 헬퍼도 내보내지 않습니다.
- **가드의 한계.** 한 이미지에서 id를 다시 만들지 않고 복제한 호스트들은 같은 id를 공유하고, 가드는 그들을
  구별하지 못합니다. `THREAT_MODEL.md`에 그렇게 적습니다. 가드가 잡는 것은 잘못된 스냅샷이지 복제된 id가 아닙니다.
- **D34 수정.** 메인 설계와 §4.2의 `internal/remedy` 행에서 "호스트 값은 명령에 들어가지 않는다"에 예외가 하나
  생깁니다. machine-id 해시이며, 셸 문법을 담을 수 없는 소문자 16진수 64자일 때만 허용합니다.
  `TestScriptEveryLineIsTemplateBodyOrComment`는 정확히 그 형태의 `MUSTER_SNAPSHOT_HOST=` 한 줄을 템플릿 텍스트로
  인정하고, poison 계획은 형식이 틀린 해시를 담아 그 값이 주석이 아닌 어느 줄에도 나오지 않아야 합니다.
- **exit 2의 사유는 이제 세 가지입니다**(루트 아님, 다른 호스트, 쓸 수 없는 백업 디렉터리). 어느 경우에도 아무것도
  실행되지 않았습니다. `MUSTER_ANY_HOST`는 해시가 다를 때만 읽습니다.
- **헬퍼는 공유 문자열이다.** `internal/remedy`는 헬퍼 텍스트를 `MachineIDHashHelper`로 export하고 그 상수에서
  렌더합니다. `internal/collect/collectors`는 `MachineIDHash(data []byte) string`(TrimSpace 뒤 sha256 16진수, 빈
  입력이면 빈 값)을 뽑아내고 `runOS`가 그것을 부릅니다. `TestHostGuardHashMatchesTheCollector`(`internal/remedy`,
  Linux 빌드 태그. `collectors`는 테스트에서만 import하고, purity 테스트는 `.TestImports`가 아니라 `.Imports`를
  읽으므로 허용됩니다)는 헬퍼를 `sh`로 임시 파일에 돌립니다. 끝에 줄바꿈, CRLF, 앞쪽 공백, 앞쪽 줄바꿈이 있는
  id에서는 collector의 값과 같아야 하고, `uninitialized`, 빈 파일, 없는 경로, 31자 id에서는 출력이 비어야 합니다.
- **가드 테스트.** `internal/remedy`의 Linux 테스트로, 렌더한 스크립트에서 `strings.Replace`로 `/etc/machine-id`를
  임시 machine-id 경로로 바꾸고 바뀌었는지 확인한 뒤 실행합니다. 해시가 같으면 통과합니다. 다르면 exit 2로
  거부 문구를 출력하고 `MUSTER_BACKUP`을 만들지 않습니다. 다르고 `MUSTER_ANY_HOST=1`이면 경고를 출력하고
  실행합니다. id 파일이 없으면 exit 2입니다. `runScriptStreams`는 물려받은 환경에서 `MUSTER_ANY_HOST`를 뺍니다.
  `fullPlan`에 형식이 맞는 해시를 넣어 `full.sh` 골든이 가드가 켜진 프롤로그를 렌더하게 하고, `empty.sh`는 가드를
  끈 채로 둡니다. `cmd/muster` e2e는 해시가 있는 스냅샷에서 `host_guard: on`, 없는 스냅샷에서 `off`를 확인합니다.

## 3. 유닛 상태 (Q-2)

**스키마와 lint.** `Remediation`에 `Units []string`(`yaml:"units,omitempty"`)이 추가됩니다. control 단위 lint는
다음과 같습니다.

- 항목마다 `^[A-Za-z0-9][A-Za-z0-9@._:-]*\.(service|socket)$`에 맞아야 하고, 중복은 없어야 합니다.
- `units`에는 `script`가 있어야 합니다.
- `units`도 되돌리는 수단으로 칩니다. `script`에는 `rollback`, `backup`, `units` 중 하나가 있어야 합니다.
- `units`는 `rollback`과도 `backup`과도 함께 쓸 수 없습니다. 유닛 control은 유닛 상태로만 되돌립니다. 그래서
  유닛을 다시 시작한 뒤에 설정 파일 복원이 도는 일이 없습니다.
- `$UNITS`나 `${UNITS`를 담은 `script`나 `rollback`에는 `units`가 있어야 합니다.
- `backup` 경로는 `/muster-units/` 아래에 있으면 안 됩니다(템플릿의 상태 디렉터리, 아래 참조).

세트 단위 lint는 control 단위 검사가 끝난 뒤 세트 전체에 한 번 돕니다. 위반이 있으면 id 순으로 뒤에 오는
control에 Problem 하나를 남기고 앞의 control을 적습니다. 규칙은 `backup_path_shared`(scripted control 두 개가 같은
`backup` 경로를 선언)와 `units_shared`(두 개가 같은 유닛을 선언)입니다. `TestLintSetRules`가 control 두 개짜리
세트로 둘 다 다룹니다.

**계획.** `Item`에 `Units []string`(`json:"units"`, 항상 있고 없으면 `[]`, `Backup`처럼 `Script`가 true일 때만
채움)이 추가됩니다. `Item.Rollback`은 `none | declared | restore_backup | units | both`가 됩니다. `both`는 여전히
`rollback`과 `backup`이 함께 있는 경우입니다(lint가 이제 `units`와 그 둘의 조합을 금지합니다). 표의 롤백 열도 같은
단어를 보여 줍니다.

**템플릿.** 유닛을 선언한 블록은 (없는) `backup` 줄 자리 뒤에
`save_units <u…> || { log "<id>: backup failed, nothing changed"; return 1; }`를 부르고, 실패 경로마다
`restore_units <u…> || log "<id>: ROLLBACK INCOMPLETE, backups in $MUSTER_BACKUP"`를 부릅니다. 유닛 이름은 선언된
리터럴입니다. 프롤로그의 헬퍼는 다음과 같습니다.

```sh
save_units() {
  mkdir -p "$MUSTER_BACKUP/muster-units" || return 1
  for u in "$@"; do
    f="$MUSTER_BACKUP/muster-units/$u"
    if [ -e "$f" ] || [ -L "$f" ]; then log "$u: unit state exists, keeping the first"; continue; fi
    if systemctl cat -- "$u" >/dev/null 2>&1; then
      ue=$(systemctl is-enabled -- "$u" 2>/dev/null) || :
      ua=$(systemctl is-active -- "$u" 2>/dev/null) || :
      printf '%s %s\n' "${ue:-unknown}" "${ua:-unknown}" > "$f" || return 1
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
      masked) systemctl --quiet mask -- "$u" || urc=1;;
      masked-runtime) systemctl --quiet mask --runtime -- "$u" || urc=1;;
      linked|linked-runtime) log "$u: was $ue; the link is not restored"; urc=1;;
    esac
  done
  for u in "$@"; do
    [ -f "$MUSTER_BACKUP/muster-units/$u" ] || continue
    read -r ue ua < "$MUSTER_BACKUP/muster-units/$u"
    case "$ue" in masked|masked-runtime) continue;; esac
    case "$ua" in active|activating|reloading) systemctl --quiet start -- "$u" || urc=1;; esac
  done
  return $urc
}
```

- **1차**는 `absent`를 뺀 모든 기록된 유닛을 unmask합니다. 본문은 `/etc`에 영속 mask를 겁니다. 그래서 이렇게 하지
  않으면 `masked-runtime`으로 기록된 유닛에 그 영속 mask가 남는데, `is-enabled`는 그것을 runtime mask 뒤에 가려
  보여 주지 않습니다.
- **2차**는 기록된 것을 다시 적용합니다. `enabled`/`enabled-runtime`은 다시 enable하고(뒤의 것은 `--runtime`으로),
  `masked`/`masked-runtime`도 같은 방식으로 다시 mask합니다. `linked*`는 되돌리지 못했다고 로그로 남기고 호출이 1을
  돌려주게 합니다(본문의 `disable`이 링크를 지우고 템플릿은 그것을 다시 만들 수 없습니다).
- **3차**는 `active`, `activating`, `reloading`이었던 것을 start합니다. 다시 mask한 유닛은 예외입니다(masked 유닛은
  start할 수 없고, 기록된 동작 상태는 되돌리지 않습니다).
- 세 번에 나눠 도는 것은 3D-2에서 찾은 성질(Z-23)을 지키기 위해서입니다. 필요한 유닛이 아직 masked인 동안에는
  어떤 유닛도 enable하거나 start하지 않습니다.
- unmask 뒤에 본문이 남긴 그대로 두는 상태는 `disabled`, `static`, `indirect`, `generated`, `transient`, `alias`,
  `bad`, `unknown`, `absent`입니다. `inactive`는 멈추지 않습니다(본문이 이미 멈췄습니다). `[Install]` 섹션 없이 손으로
  만든 `.wants` 링크로만 활성화된 유닛은 `enable`로 되살릴 수 없고, 그 실패로 호출이 1을 돌려주며
  `ROLLBACK INCOMPLETE`를 남깁니다. `Also=` 짝은 `enable`을 따라갑니다. matrix 유닛에 그것이 있는지는 플랜의 사전
  점검이 기록합니다.
- 상태 디렉터리 `$MUSTER_BACKUP/muster-units/`는 백업과 겹칠 수 없습니다(lint가 `/muster-units/` 아래의 백업
  경로를 거부합니다). 헬퍼는 자기 변수 이름(`u`, `f`, `ue`, `ua`, `urc`)을 쓰고 블록의 `rc`를 건드리지 않습니다. 같은
  `MUSTER_BACKUP`으로 여러 번 실행해도 첫 파일 복사본처럼 첫 기록을 유지합니다.
- **본문은 선언된 목록을 읽는다.** 유닛을 선언한 블록은 본문 subshell 안의 첫 줄로 `UNITS='<u1> <u2> …'`를
  내보내고, 본문 10개는 모두 `for u in $UNITS; do … done` 루프입니다. 유닛이 하나인 본문도 마찬가지입니다.
  SC2043은 단어 하나짜리 리터럴 목록에서만 경고하므로 `if` 형태는 없앱니다. 소켓이 서비스를 활성화하는 곳에서는
  순서가 중요하므로, lint는 `units`에서 `<name>.socket`이 `<name>.service`보다 앞에 오도록 요구합니다. validate는
  지금처럼 유닛 이름을 명시합니다(한 줄, 루프 없음).
- **collector와 validate에 고정한다.** `TestServiceScriptsNameTheCollectorsUnits`(Linux, 서비스 표 옆)는 서비스
  control마다 `units`를 집합으로서 `services.go`에서 그 control이 대응하는 행들의 `provesInstall` 유닛과
  비교합니다(`tftp_talk_disabled`는 두 행에 대응합니다). control의 `validate`에 있는 유닛 토큰도 그 집합과 같아야
  하고, 유닛을 선언한 control의 `script`는 유닛 이름을 리터럴로 적으면 안 됩니다. 본문의 토큰을 훑던 검사(3D-2
  Task 3 N1)를 대체합니다. 10개 control은 `automount_disabled`, `dos_services_disabled`, `finger_disabled`,
  `nfs_server_disabled`, `nis_disabled`, `rpcbind_disabled`, `rservices_disabled`, `snmp_disabled`, `telnet_disabled`,
  `tftp_talk_disabled`이고, 테스트가 개수를 확인합니다.
- **stub에 대해서만 실행한다.** 유닛을 선언한 렌더 스크립트를 실행하는 Go 테스트는 `PATH` 맨 앞에 stub
  `systemctl`을 둡니다. stub은 임시 디렉터리의 스크립트로, 인자를 로그로 남기고 `cat`, `is-enabled`, `is-active`에
  fixture 파일로 답합니다. 테스트 스위트의 어떤 것도 러너의 systemd에 닿지 않습니다.
  `TestUnitHelpersRestoreRecordedState`(Linux)는 기록될 수 있는 상태마다 실패한 블록을 거치게 합니다. 상태는
  `enabled`, `enabled-runtime`, `disabled` + `active`, `masked`, `masked-runtime`, `masked` + `active`, `linked`,
  `static`, `absent`, `unknown`입니다. 로그된 호출 순서, 세 번의 순서, 두 번째 실행에서 첫 기록 유지, stub 호출이
  실패할 때의 `ROLLBACK INCOMPLETE`를 확인합니다.

## 4. 호스트 증명 (Q-3)

**표.** `controls/testdata/_roundtrip.yaml`(`_mutants.yaml`처럼 fixture 하네스가 무시합니다)에는 스크립트가 있는
control마다 항목이 하나씩, id 순으로 들어갑니다.

```yaml
- id: muster.service.finger_disabled
  unproven: no matrix image ships a systemd unit for a finger server
- id: muster.service.telnet_disabled
  images: [almalinux9-init, rocky9-init]
```

`TestEveryScriptedControlIsInTheRoundtripTable`(`internal/controls`)은 이 표와
`.github/workflows/ci.yml`의 `fix-roundtrip` job을 읽습니다(`yaml.v3`, 이미 모듈 의존성입니다). 그리고 다음을
확인합니다.

- 표가 id 순으로 정렬되어 있습니다.
- 표의 id가 내장 세트에서 스크립트가 있는 id와 정확히 같습니다.
- 항목마다 비어 있지 않고 중복 없는 `images`와 `unproven` 사유 중 정확히 하나가 있습니다.
- `images`가 적은 키가 모두 matrix 행의 `key`입니다.
- matrix 행마다 `key`와 비어 있지 않은 `seeded`가 있습니다.
- 행마다 공백으로 나눈 `seeded`를 집합으로 비교했을 때, `images`에 그 행을 적은 id들과 같습니다.
- `muster.service.*` id는 `init`이 `"false"`인 행을 적지 않습니다.

이미지 배정은 플랜이 정합니다. 플랜의 첫 작업이 일회용 컨테이너에서 이미지마다 사전 점검을 합니다. 유닛마다
패키지가 그 유닛을 담는지, `enable --now`로 `active`가 되는지를 기록하고, `rpcbind.service`와 다른 유닛에 `Also=`가
있는지도 기록합니다. 표에는 사전 점검이 찾은 결과를 적습니다. inetd 서비스로만 패키지된 서버(Debian의 `telnetd`,
`fingerd`, `rsh-server`, `talkd`)는 스크립트가 닿지 않습니다. 스크립트는 systemd 유닛을 끄고 inetd는 그대로 두기
때문입니다. 그런 서버는 그 사유와 함께 `unproven`입니다.

**matrix.** 행에 `key`(`rocky9-init`, `almalinux9-init`, `ubuntu2204`, `debian12-init`)가 생깁니다. `debian12-init`은
job 안에서 빌드합니다. `FROM debian:12`에 `systemd systemd-sysv`를 설치하고 `/sbin/init`을 실행하는 inline
Dockerfile로 `docker build`합니다. EL init 이미지처럼(`--privileged --cgroupns=host`) 띄우고, 같은
`is-system-running --wait` 루프를 돕니다. 시스템이 끝내 `running`이나 `degraded`에 이르지 않으면 job이 실패합니다.
시드 명령은 workflow에서 `ci/roundtrip/<key>.sh`로 옮깁니다. checkout의 `ci/roundtrip/`을 `bin/` 옆에 읽기 전용으로
컨테이너에 마운트하고, 스크립트는 그 안에서 실행합니다. `make shellcheck`와 CI의 shellcheck 단계가
`ci/roundtrip/*.sh`도 검사하고, glob이 비면 실패합니다.

**시드**는 패키지를 설치하고, 사전 점검이 시작할 수 있다고 증명한 유닛을 시작하고(`enable --now`), 파일 권한을
느슨하게 만듭니다. 명령은 `chmod 664 /etc/passwd`, `chmod 666 /etc/services`(파일이 없는 이미지에서는 먼저
`netbase`를 설치), `install -m 644 /dev/null /etc/hosts.lpd`, `chmod 644 /etc/hosts`입니다. collect하기 전에 job은
시드한 유닛이 모두 안정된 상태인지 확인합니다. `active`이거나, 사전 점검이 enable만 하는 유닛으로 표시한 경우
`inactive`여야 합니다. `activating`이나 `failed`에 멈춘 유닛이 있으면 job이 그 유닛을 적고 실패합니다. 호스트 자신의
접근을 빼앗는 시드는 범위 밖입니다. 16개 중 그런 시드가 필요한 것은 없습니다.

**수리 실행**(모든 행)은 3D-2의 job과 같습니다. collect, 계획, 시드한 id가 모두 스크립트가 있는 계획 항목인지
확인, 스크립트 실행(exit 0), 다시 collect, 시드한 id가 모두 `PASS`나 `NOT_APPLICABLE`인지 확인합니다.

**실패 실행**(init 행만)은 첫 컨테이너처럼 띄우고 시드한 두 번째 컨테이너에서 합니다.

1. 이 컨테이너 안에서 collect하고 계획합니다. 수리 실행의 스크립트는 다시 쓰지 않습니다. `fix.host_guard`가
   `on`인지 확인합니다.
2. 계획된 scripted 서비스 항목이 선언한 유닛마다 `systemctl is-enabled`와 `is-active`를 기록합니다. 계획된
   scripted 항목이 선언한 백업 경로마다 `stat -c '%u %g %a'`, `sha256sum`, 그리고 `getfacl`이 있으면
   `getfacl -cp`를 기록합니다. 경로가 없으면 `absent`로 적습니다. sshd 블록은 drop-in을 만들고, 롤백은 그것을 다시
   지워야 합니다.
3. 스크립트를 복사하고, muster의 출력이 아니라 사본만 고칩니다. 계획된 scripted 블록마다 validate subshell을 여는
   `( set -e` 바로 다음 줄을 `false`로 바꿉니다. 기준점은 본문 subshell의 `fi` 다음 줄이므로 본문과 롤백 subshell은
   건드리지 않습니다. 한 단계가 사본이 원본과, validate가 있는 계획된 scripted 블록마다 정확히 한 줄씩만
   다른지 확인합니다.
4. 사본을 `set +e`로 실행합니다. exit 1, 고친 블록마다 `validate failed, rolling back` 한 줄, 그리고
   `ROLLBACK INCOMPLETE`나 `rollback failed` 줄이 없을 것을 요구합니다.
5. 유닛 상태, stat, 체크섬, ACL이 모두 2단계의 기록과 같아야 합니다.

**가드 실행**(init 행)은 첫 컨테이너에서 계획한 수리 실행의 스크립트를 3단계 전에 두 번째 컨테이너에서
실행합니다. exit 2와 거부 문구가 나와야 하고, 그 뒤에도 2단계의 기록이 그대로여야 합니다.

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

`validate`는 control의 validate가 지금 쓰는 것과 같은 `stat -c` 형식(`%u %g %a`, shadow는 `%u %a`)에 대한 한 줄이
됩니다.

```sh
case "$(stat -c '%u %g %a' /etc/hosts)" in '0 0 0'|'0 0 200'|'0 0 400'|'0 0 600') ;; *) false;; esac
```

- 패턴은 control의 기본 `allowed_modes`에 있는 모드입니다. 파라미터가 없는 `passwd`는 그 모드 clause의 리터럴
  목록을 씁니다. 패턴마다 validate의 `stat` 형식이 정하는 소유자 접두어 뒤에 `strconv.FormatInt(mode, 8)`(`%a`가
  출력하듯 앞에 0을 붙이지 않음)로 씁니다. 끝의 `*) false` 갈래는 반드시 있어야 합니다. 아무것에도 맞지 않는
  `case`는 exit 0이기 때문입니다.
- `TestFileValidatesAcceptTheDefaultModes`가 control에서 패턴 목록을 만들어 validate와 비교합니다. 이어 Linux
  테스트가 validate에 임시 사본의 경로를 넣어 돌립니다. 허용된 모드에서는 exit 0, 느슨해진 모드에서는 1이어야
  합니다.
- `text_en`/`text_ko`는 가이드의 목표 모드를 유지하고 "(스크립트는 비트를 지우기만 하므로 더 엄격한 파일은 그대로
  둡니다)"를 덧붙입니다. 소유자와 ACL 줄은 바뀌지 않습니다.

**공유된 백업 경로와 유닛**은 §3의 세트 단위 규칙 두 개입니다.

**Escape.** `escapeRune`이 다음 문자들도 `\u%04x`로 풀어 씁니다. 구분자 U+2028과 U+2029, 양방향 제어 문자
U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, 그리고 폭 없는 서식 문자 U+200B–U+200D, U+2060, U+FEFF입니다.
`Escape`는 fix 표뿐 아니라 check 표에도 쓰이므로, check 표는 그런 문자를 담은 스냅샷에서만 바뀝니다(CHANGELOG
"Changed"). `TestEscapeSpellsOutBidiAndSeparators`가 목록을 고정합니다. poison 골든 둘(remedy의
`poison.sh`/`poison.table`과 report의 poison 표 테스트)에 그 문자들이 추가됩니다.

**`--quiet`.** 서비스 본문은 `systemctl --quiet disable --now`와 `systemctl --quiet mask`를 부르고, 유닛 헬퍼도
상태를 바꾸는 호출마다 `--quiet`를 넘깁니다. 그래서 masked 유닛 위에서 다시 실행해도 아무것도 출력하지 않습니다.

## 6. 테스트, CI, 문서

**테스트.** §2–§5에 적은 새 테스트에 더해 다음이 있습니다.

- `TestLintRules`에 §3의 control 단위 규칙마다 케이스가 추가됩니다.
- `TestPlanRollbackVocabulary`에 `units`가 추가됩니다.
- `TestScriptGolden`은 골든 5개를 다시 만듭니다. `full.sh`에는 켜진 가드가 들어가고, `all-scripted.sh`는 `UNITS=`
  본문 10개를 렌더합니다.
- `TestScriptUnitsBlockOrder`는 `save_units`가 본문 subshell 앞에 있고 `restore_units`가 모든 실패 경로에 있는지
  확인합니다.
- `TestJSONGolden`에 `host_guard`와 `units`가 추가됩니다.
- mutation 테스트는 살아남는 mutant가 0이어야 합니다.

**CI.** §4의 `fix-roundtrip` matrix와 그 수리·실패·가드 실행, 그리고 `ci/roundtrip/*.sh`에 대한 shellcheck
단계입니다. fix 리포트가 바뀌므로 머지 전에 examples 갱신이 반드시 필요합니다.

**문서**(영어와 한국어를 같은 커밋에):

- **메인 설계.** D34를 수정하고, 그에 따라 §4.2의 `internal/remedy` 행도 고칩니다(§2). §6.2에 `units`와 lint
  규칙을 넣습니다. §7.5에 가드, 유닛 헬퍼, exit 2의 세 번째 사유를 넣습니다. §10.2에서 3D-2b를 merged로 표시하고
  3D-2c를 적습니다.
- **`CLAUDE.md` "Fix (stage 3D-2)".** 가드, `units`, 라운드트립 표, 기호식 모드를 추가합니다. 이 설계로 틀리게 된
  두 문장("rollbacks unmask every unit, then `enable --now` every unit", "A one-unit body uses `if`")도 바꿉니다.
- **`CONTRIBUTING` 쌍.** 서비스 스크립트는 `units`를 선언하고 `$UNITS`를 돕니다. 새 scripted control은
  `_roundtrip.yaml`에 추가합니다.
- **README 쌍.** 상태 줄과 로드맵 항목입니다.
- **`THREAT_MODEL.md`.** 호스트 가드, `MUSTER_ANY_HOST`, 스크립트에 들어가는 해시, 복제된 id의 한계를 적습니다.
- **`examples/README.md`.** fix 리포트에 이제 가드 줄이 들어 있다고 적습니다.
- **`CHANGELOG`.** Added: 호스트 가드, `units`, 실패·가드 실행. Changed: `Escape`, 롤백 분류, 프롤로그 순서.
  Controls: 16개의 remediation 블록이며, 판정 변화는 없습니다.

## 7. 미룬 항목

- 16개 밖의 control 스크립트와 그에 필요한 파라미터 치환 규칙(3D-2c).
- `fix --dry-run --result`, `each` control의 대상별 계획, 네 번째 소비자가 생기면 `check.Result`에 둘 구조적 판정
  표지, `explain` — 3D-2 §8 그대로.
- `linked` 유닛의 링크 복원, 그리고 masked로 남은 유닛의 기록된 동작 상태 복원(로그로 남김, §3).
- machine id를 넘어서 복제된 호스트를 구별하는 일(§2).
- 플랜의 사전 점검이 `unproven`으로 표시하는 항목은, 그 사유와 함께, 어떤 이미지가 systemd 유닛으로 패키지할
  때까지.
