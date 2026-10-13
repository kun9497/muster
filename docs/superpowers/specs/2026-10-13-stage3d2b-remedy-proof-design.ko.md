# 3D-2b단계 — 검증된 검토용 스크립트: 호스트 가드, 유닛 상태, 라운드트립

영어 원본: `2026-10-13-stage3d2b-remedy-proof-design.md`. 메인 설계: `2026-09-02-muster-design.ko.md`
(§6.2 스키마, §7.5 `fix --dry-run`, §10.2 로드맵, D24, D34). 이 사이클이 마무리하는 설계:
`2026-10-07-stage3d2-fix-dry-run-design.ko.md`(X-1..X-10, §8 미룬 항목). 이 설계의 판정은 Q 목록입니다.

## 1. 범위와 의도

3D-2는 `fix --dry-run`과 계획, 검토용 스크립트를 내놓았고, `script`를 가진 control 16개를 다시 썼습니다. 그중
4개(`rpcbind_disabled`, `root_remote_login`, `hosts_permissions`, `shadow_permissions`)는 `fix-roundtrip` job이
실제 시스템에서 증명하고, 나머지 12개는 문법으로만 증명되었습니다. 서비스 롤백은 이전 상태와 상관없이 이름을 적은
유닛을 모두 다시 켜고, 한 호스트의 스냅샷으로 만든 스크립트가 다른 호스트에서 실행되는 것을 막는 장치도 없습니다.
3D-2b는 16개에 대해 이 빈틈을 메웁니다. 스크립트가 있는 control을 새로 추가하지는 않습니다. 다른 control의
스크립트와 그에 필요한 파라미터 치환 규칙은 3D-2c입니다.

- **Q-1 — 스크립트는 계획된 호스트에서 실행된다.** 스크립트는 스냅샷의 `host.machine_id_hash`를 담고, 무엇이든
  바꾸기 전에 machine id의 해시가 다른 호스트를 거부합니다(exit 2). `MUSTER_ANY_HOST=1`은 경고를 남기고 이를
  우회합니다. 형식이 맞는 해시가 없는 스냅샷에서는 가드가 꺼지고, 헤더가 그렇게 말합니다(§2).
- **Q-2 — 서비스 롤백은 원래 있던 것을 되돌려 놓는다.** 서비스 control은 유닛을 선언합니다
  (`remediation.units`). 템플릿은 본문이 돌기 전에 유닛마다 활성화 상태와 동작 상태를 기록하고, 실패하면 정확히
  그것을 되돌립니다. masked였던 것은 다시 mask하고, enabled였던 것만 enable하고, active였던 것만 start합니다.
  손으로 쓴 서비스 롤백 9개는 지웁니다(§3).
- **Q-3 — 스크립트가 있는 control은 모두 호스트에서 증명되거나, 증명할 수 없는 이유를 말한다.**
  `controls/testdata/` 아래의 표가 16개마다 라운드트립이 시드하고 고치는 이미지를, 아니면 어느 이미지도 그럴 수
  없는 이유를 적습니다. 테스트가 이 표와 내장 세트, CI matrix가 같은지 지킵니다. matrix에는 job 안에서 공식
  이미지로 빌드하는 Debian 12 init 컨테이너가 추가됩니다. init 이미지마다 실패 경로도 증명합니다. 일부러 실패시킨
  블록이 유닛과 파일을 원래대로 남겨야 합니다(§4).
- **Q-4 — 파일 스크립트는 비트를 빼기만 한다.** 권한 스크립트 5개는 가이드가 금지하는 비트만 지우는 기호식
  `chmod`를 씁니다. 그래서 이미 가이드보다 엄격한 파일을 느슨하게 만드는 일이 없고, validate는 control의 기본
  `allowed_modes`에 있는 모드를 모두 받아들입니다(§5).
- **Q-5 — 작은 미룬 항목들.** lint가 같은 백업 경로를 공유하는 두 scripted control을 거부합니다. `Escape`가 줄·문단
  구분자와 양방향 제어 문자를 풀어 씁니다. 서비스 본문은 `systemctl`에 `--quiet`를 넘깁니다(§5).
- **Q-6 — 판정은 바뀌지 않는다.** `checks`, `params`, fact는 바뀌지 않습니다. remediation 블록이 바뀌므로
  `controls/VERSION`만 올라갑니다. plan JSON에는 `host_guard`와 롤백 값 `units`가 추가됩니다(추가만 하므로 plan
  스키마는 1을 유지합니다).

## 2. 호스트 가드 (Q-1)

`remedy.Build`는 `report.Snapshot.Host.MachineIDHash`가 `^[0-9a-f]{64}$`에 맞을 때 `FixBlock.MachineIDHash`에
복사하고, 맞지 않으면 비워 둡니다. plan JSON에는 `fix.host_guard: "on" | "off"`가 추가됩니다. 해시 자체는 JSON에
넣지 않습니다(계획이 digest로 가리키는 스냅샷에 이미 있습니다). 표는 바뀌지 않습니다.

프롤로그에는 루트 확인 뒤, 백업 디렉터리를 만들기 전에 다음이 들어갑니다.

```sh
MUSTER_SNAPSHOT_HOST=<hash>
here=$(muster_machine_id_hash)
if [ "$here" != "$MUSTER_SNAPSHOT_HOST" ]; then
  if [ "${MUSTER_ANY_HOST:-}" = 1 ]; then
    log "warning: this host's machine id differs from the snapshot's; running because MUSTER_ANY_HOST=1"
  else
    printf 'muster-fix: planned for another host (machine id differs); set MUSTER_ANY_HOST=1 to run it anyway\n' >&2
    exit 2
  fi
fi
```

해시 헬퍼도 프롤로그에 둡니다.

```sh
muster_machine_id_hash() {
  id=$(cat /etc/machine-id 2>/dev/null) || id=
  id=$(printf '%s' "$id" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  [ -n "$id" ] || return 0
  printf '%s' "$id" | sha256sum | cut -d' ' -f1
}
```

- 공백 제거는 collector의 `readTrim`(`strings.TrimSpace`)과 같게 합니다. `$(…)`가 먼저 끝의 줄바꿈을 지웁니다.
  `TestHostGuardHashMatchesTheCollector`(Linux)는 끝에 줄바꿈이 있는 경우, CRLF, 앞쪽 공백, 아무것도 없는 경우의
  machine-id 파일에 헬퍼를 돌려 collector의 Go 계산과 비교합니다.
- `/etc/machine-id`가 없거나 비어 있는 호스트에서는 `here`가 비어 있고, 어떤 해시와도 다르므로 거부됩니다.
- 가드가 꺼지면 블록 대신 주석 한 줄 `# host guard: off (the snapshot has no machine id)`가 들어가고, 헤더의 첫
  주석 줄은 그대로입니다.
- **D34 수정.** "호스트 값은 명령에 들어가지 않는다"에 예외가 하나 생깁니다. machine-id 해시이며, 셸 문법을 담을
  수 없는 소문자 16진수 64자일 때만 허용합니다. `TestScriptEveryLineIsTemplateBodyOrComment`는 정확히 그 한 줄을
  템플릿 텍스트로 인정하고, poison 계획에는 형식이 틀린 해시를 넣어 그 값이 어디에도 들어가지 않음을 증명합니다.
- exit 2의 사유는 이제 세 가지입니다(루트 아님, 쓸 수 없는 백업 디렉터리, 다른 호스트). 어느 경우에도 아무것도
  실행되지 않았습니다. `MUSTER_ANY_HOST`는 해시가 다를 때만 읽습니다.

## 3. 유닛 상태 (Q-2)

**스키마와 lint.** `Remediation`에 `Units []string`(`yaml:"units,omitempty"`)이 추가됩니다. lint 규칙은 다음과
같습니다.

- 항목마다 `^[A-Za-z0-9@._:-]+\.(service|socket)$`에 맞아야 하고, 중복은 없어야 합니다.
- `units`에는 `script`가 있어야 합니다.
- `units`도 되돌리는 수단으로 칩니다. `script`에는 `rollback`, `backup`, `units` 중 하나가 있어야 합니다.
- `units`와 `rollback`은 함께 쓸 수 없습니다(유닛을 되돌리는 방법은 하나여야 합니다).
- 내장 세트에서는 `TestServiceScriptsNameTheCollectorsUnits`(Linux, 서비스 표 옆)가 서비스 control마다 `units`를
  `services.go`에 있는 그 행들의 `provesInstall` 유닛과 순서까지 정확히 비교합니다. 본문의 토큰을 훑던 검사(3D-2
  Task 3 N1)를 대체합니다.

**템플릿.** 프롤로그에 헬퍼 두 개가 추가됩니다. 유닛을 선언한 블록은 `backup` 뒤에 `save_units`를 부르고, 실패
경로에서는 선언된 `rollback`(이 control들에는 없습니다) 뒤, `restore` 앞에 `restore_units`를 부릅니다.

```sh
save_units() {
  mkdir -p "$MUSTER_BACKUP/units" || return 1
  for u in "$@"; do
    f="$MUSTER_BACKUP/units/$u"
    { [ -e "$f" ] || [ -L "$f" ]; } && { log "$u: unit state exists, keeping the first"; continue; }
    if systemctl cat "$u" >/dev/null 2>&1; then
      e=$(systemctl is-enabled "$u" 2>/dev/null) || :
      a=$(systemctl is-active "$u" 2>/dev/null) || :
      printf '%s %s\n' "${e:-unknown}" "${a:-unknown}" > "$f" || return 1
    else
      printf 'absent absent\n' > "$f" || return 1
    fi
  done
}
restore_units() {
  rc=0
  for u in "$@"; do
    read -r e a < "$MUSTER_BACKUP/units/$u" 2>/dev/null || continue
    case "$e" in masked|masked-runtime|absent) ;; *) systemctl --quiet unmask "$u" || rc=1;; esac
  done
  for u in "$@"; do
    read -r e a < "$MUSTER_BACKUP/units/$u" 2>/dev/null || continue
    case "$e" in
      enabled) systemctl --quiet enable "$u" || rc=1;;
      enabled-runtime) systemctl --quiet enable --runtime "$u" || rc=1;;
      masked) systemctl --quiet mask "$u" || rc=1;;
      masked-runtime) systemctl --quiet mask --runtime "$u" || rc=1;;
    esac
  done
  for u in "$@"; do
    read -r e a < "$MUSTER_BACKUP/units/$u" 2>/dev/null || continue
    case "$a" in active|activating|reloading) systemctl --quiet start "$u" || rc=1;; esac
  done
  return $rc
}
```

- 세 번에 나눠 도는 것은 3D-2에서 찾은 성질(Z-23)을 지키기 위해서입니다. 필요한 유닛이 아직 masked인 동안에는
  어떤 유닛도 enable하거나 start하지 않습니다. 다른 상태(`disabled`, `static`, `indirect`, `generated`, `absent` 등)는
  unmask 뒤에 본문이 남긴 그대로 둡니다. `inactive`는 멈추지 않습니다(본문이 이미 멈췄습니다).
- 상태 디렉터리의 유닛 이름은 선언된 이름이고, lint의 문자 집합 덕분에 안전한 경로 구성 요소입니다. 같은
  `MUSTER_BACKUP`으로 여러 번 실행해도 첫 파일 복사본처럼 첫 기록을 유지합니다.
- `save_units`가 실패하면 본문 전에 블록이 멈추고, 복사 실패와 같은 메시지 `backup failed, nothing changed`를
  남깁니다. `restore_units`가 실패하면 `restore`처럼 `ROLLBACK INCOMPLETE`를 남깁니다.
- **본문은 선언된 목록을 읽는다.** 유닛을 선언한 블록은 본문 subshell 안의 첫 줄로 `UNITS='<u1> <u2> …'`를
  내보내고, 본문 9개는 이름을 반복하는 대신 `$UNITS`를 돕니다. 이 값은 lint를 거친 control의 선언이지 호스트 값이
  아닙니다. validate는 지금처럼 유닛 이름을 명시합니다(한 줄, 루프 없음).
- **롤백 분류.** `Item.Rollback`은 `none | declared | restore_backup | units | both`가 됩니다. `both`는 `rollback`,
  `backup`, `units` 중 둘 이상이 선언된 경우입니다. 표의 롤백 열도 같은 단어를 보여 줍니다.

## 4. 호스트 증명 (Q-3)

**표.** `controls/testdata/_roundtrip.yaml`(`_mutants.yaml`처럼 fixture 하네스가 무시합니다)에는 스크립트가 있는
control마다 항목이 하나씩, id 순으로 들어갑니다.

```yaml
- id: muster.service.telnet_disabled
  images: [debian12-init, almalinux9-init]
- id: muster.service.finger_disabled
  unproven: no image of the matrix packages a finger server
```

`TestEveryScriptedControlIsInTheRoundtripTable`(`internal/controls`)은 다음을 확인합니다. 표의 id가 내장 세트에서
스크립트가 있는 id와 정확히 같은지, 항목마다 `images`와 `unproven` 중 정확히 하나가 있는지, 그리고
`.github/workflows/ci.yml`의 `fix-roundtrip` job(`yaml.v3`로 읽습니다)의 matrix 행마다 `seeded` 목록이 `images`에
그 행의 `key`를 적은 id들과 같은지입니다. 이 설계의 이미지 배정은 가설입니다. 플랜의 첫 작업이 일회용 컨테이너에서
이미지마다 패키지가 있는지 확인하고, 표에는 그 결과를 적습니다.

**matrix.** 행에 `key`(`rocky9-init`, `almalinux9-init`, `ubuntu2204`, `debian12-init`)가 생깁니다. `debian12-init`은
job 안에서 빌드합니다. `FROM debian:12`에 `systemd systemd-sysv`를 설치하고 `/sbin/init`을 실행하는 inline
Dockerfile로 `docker build`하고, EL init 이미지처럼(`--privileged --cgroupns=host`) 띄웁니다. 행마다의 시드 명령은
workflow에서 `ci/roundtrip/<key>.sh`로 옮겨 컨테이너 안에서 실행합니다. `make shellcheck`와 CI의 shellcheck 단계가
`ci/roundtrip/*.sh`도 검사합니다. 시드는 패키지를 설치하고, 유닛을 `systemctl enable --now`하고, 파일 권한을
느슨하게 만듭니다(`chmod 664 /etc/passwd`, `chmod 666 /etc/services`, `install -m 644 /dev/null /etc/hosts.lpd`,
`chmod 644 /etc/hosts`). 호스트 자신의 접근을 빼앗는 시드는 범위 밖입니다(16개에는 그런 시드가 없습니다).

**수리 실행**은 3D-2의 job과 같습니다. 행마다 collect, 계획, 시드한 id가 모두 스크립트가 있는 계획 항목인지 확인,
스크립트 실행(exit 0), 다시 collect, 시드한 id가 모두 `PASS`나 `NOT_APPLICABLE`인지 확인합니다.

**실패 실행**(init 행만)은 수리 실행 뒤, 같은 시드를 넣은 새 컨테이너에서 합니다.

1. 시드한 서비스 control이 선언한 유닛마다 `systemctl is-enabled`와 `is-active`를, 선언된 백업 경로마다
   `stat -c '%u %g %a'`를 기록합니다(경로가 없으면 `absent`. sshd 블록은 drop-in을 만들고, 롤백은 그것을 다시
   지워야 합니다).
2. 스크립트를 복사하고, 사본에서만 시드한 블록마다 validate subshell의 첫 명령이 `false`가 되도록 고칩니다. 한
   단계가 시드한 블록마다 정확히 한 줄만 바뀌었는지 확인합니다.
3. 사본을 실행하고 exit 1과, 시드한 블록마다 `validate failed, rolling back` 한 줄을 요구합니다.
4. 유닛 상태와 파일 stat이 1단계의 기록과 같아야 합니다.

이것은 실제 systemd와 실제 파일에 대해 `restore_units`와 `restore`를 증명합니다. 템플릿의 단위 테스트
(`TestScriptBodyFailureReachesTheFailurePath`)는 계속 임시 디렉터리에서 셸의 형태를 증명합니다.

## 5. 파일 스크립트와 작은 항목들 (Q-4, Q-5)

**기호식 모드.** 파일 스크립트 5개는 모드를 지정하는 대신 금지된 비트를 지웁니다.

| control | 이전 | 이후 |
|---|---|---|
| `hosts_permissions`, `hosts_lpd_permissions` | `chmod 600` | `chmod u-xs,g-rwxs,o-rwxt` |
| `passwd_permissions`, `services_permissions` | `chmod 644` | `chmod u-xs,g-wxs,o-wxt` |
| `shadow_permissions` | `chmod 400` | `chmod u-wxs,g-rwxs,o-rwxt` |

`validate`는 `stat -c '%u %g %a'`(shadow는 `%u %a`)에 대한 `case` 한 줄이 되고, 그 패턴은 control의 기본
`allowed_modes`(파라미터가 없는 `passwd`는 모드 clause의 리터럴 목록)에 있는 모드를 8진수로 정확히 담습니다.
`TestFileValidatesAcceptTheDefaultModes`가 control에서 패턴 목록을 만들어 비교합니다. `text_en`/`text_ko`는 계속
가이드의 모드를 목표로 적습니다. ACL과 소유자 줄은 바뀌지 않습니다.

**공유된 백업 경로.** 세트 단위 lint 규칙 `backup_path_shared`가 같은 `backup` 경로를 선언하는 scripted control
두 개를 거부합니다(첫 복사본 규칙 때문에 한 블록의 복원이 다른 블록의 변경을 되돌릴 수 있습니다). 내장 세트에는
그런 경우가 없습니다.

**Escape.** `escapeRune`이 U+2028, U+2029, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069도 `\u%04x`로 풀어 씁니다.
`Escape`와 `EscapeNoCut`은 check도 쓰므로, check 표는 그런 문자를 담은 스냅샷에서만 바뀝니다(CHANGELOG
"Changed"). `TestEscapeSpellsOutBidiAndSeparators`가 목록을 고정하고, poison 골든에 그 문자들이 추가됩니다.

**`--quiet`.** 서비스 본문은 `systemctl --quiet disable --now`와 `systemctl --quiet mask`를 부르고, 템플릿의 유닛
헬퍼도 모두 `--quiet`를 넘깁니다. 그래서 masked 유닛 위에서 다시 실행해도 아무것도 출력하지 않습니다.

## 6. 테스트, CI, 문서

**테스트.** §2–§5에 적은 새 테스트에 더해 다음이 있습니다. §3과 §5의 규칙마다 `TestLintRules` 케이스를 둡니다.
`TestPlanRollbackVocabulary`에 `units`가 추가됩니다. `TestScriptGolden`은 골든 5개를 다시 만듭니다(프롤로그, 가드,
유닛 헬퍼. `all-scripted.sh`는 `UNITS=` 본문 9개를 렌더합니다). `TestScriptUnitsBlockOrder`는 `save_units` 줄이
`backup` 뒤, 본문 앞에 있고 실패 경로에서 `restore_units`가 `restore` 앞에 있는지 봅니다. `TestJSONGolden`에
`host_guard`가 추가됩니다. `cmd/muster` e2e는 해시가 빈 스냅샷에서 `host_guard: off`를 확인합니다. mutation 테스트는
살아남는 mutant가 0이어야 합니다.

**CI.** §4의 `fix-roundtrip` matrix와 그 수리 실행·실패 실행, 그리고 `ci/roundtrip/*.sh`에 대한 shellcheck 단계입니다.
fix 리포트가 바뀌므로 머지 전에 examples 갱신이 반드시 필요합니다.

**문서**(영어와 한국어를 같은 커밋에). 메인 설계: D34 수정(§2), §6.2에 `units`와 lint 규칙, §7.5에 가드와 유닛
헬퍼와 exit 2의 세 번째 사유, §10.2에서 3D-2b를 merged로 표시하고 3D-2c를 적습니다. `CLAUDE.md`의 "Fix (stage
3D-2)"에 가드, `units`, 라운드트립 표, 기호식 모드를 추가합니다. `CONTRIBUTING` 쌍: 서비스 스크립트는 `units`를
선언하고 `$UNITS`를 돌며, scripted control은 `_roundtrip.yaml`에 추가합니다. `CHANGELOG`: Added(호스트 가드,
`units`, 실패 실행), Changed(`Escape`, 롤백 분류), Controls(16개의 remediation 블록, 판정 변화 없음).

## 7. 미룬 항목

- 16개 밖의 control 스크립트와 그에 필요한 파라미터 치환 규칙(3D-2c).
- `fix --dry-run --result`, `each` control의 대상별 계획, `explain` — 3D-2 §8 그대로.
- 플랜의 사전 점검이 `unproven`으로 표시하는 항목은, 그 사유와 함께, 어떤 이미지가 패키지를 담을 때까지.
