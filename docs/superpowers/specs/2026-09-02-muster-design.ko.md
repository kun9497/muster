# muster — 아키텍처와 설계

*[English](2026-09-02-muster-design.md) · 한국어*

**날짜:** 2026-09-02
**상태:** 합의됨. 2026-09-02에 아키텍처, 팩트 스키마, 컨트롤 형식, 오류 처리, 테스트를 절 단위로 승인한 뒤 네 가지 관점의 검토를 거쳐 개정했습니다. 이 문서는 그 합의를 글로 옮긴 것이며, 리포지터리 이전의 인수인계 노트를 대체합니다.

프로젝트 전체의 기준 설계 문서입니다. 개별 슬라이스는 `docs/superpowers/plans/` 아래에 각자의 구현 계획을 갖습니다. 이 문서는 이 시스템이 무엇이고, 왜 이런 모양이며, 첫 릴리스 이후 바뀌면 안 되는 계약이 무엇이고, 어떤 순서로 만들어지는지를 기록합니다. 결정에는 `D01`… 번호를 붙이고 그 결정에 의존하는 절에서 참조합니다. 결정 로그는 13절입니다.

---

## 1. 목표와 정체성

**muster는 하나의 질문에 답합니다. 이 리눅스 서버는 기준을 통과합니까(does this Linux server pass muster)?** root 권한으로 호스트의 팩트를 수집해 스냅샷에 기록하고, 그 스냅샷을 호스트 없이 오프라인으로 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드의 유닉스 서버 항목에 비추어 평가합니다. CIS Benchmark 권고 번호는 상호 참조로 함께 붙습니다.

취약점 스캐너가 아니라 설정 점검 도구입니다. 형제 프로젝트인 [assay](https://github.com/kun9497/assay)는 패키지를 권고와 매칭하지만 muster는 결코 그렇게 하지 않습니다. 둘은 코드가 아니라 결정을 공유합니다(결과에 담기는 근거, 종료 코드 계약, waiver 규칙, 배포판별 로직의 분리) (D01).

비공식 개인 오픈소스 프로젝트입니다. KISA나 Center for Internet Security의 보증을 받지 않았고, CIS Benchmark 본문을 포함하지 않으며, 어떤 수준의 CIS 준수도 주장하지 않고, 공식 평가를 대체하지 않습니다 (D02, D04).

세 가지 속성이 이 도구를 정의하며, 규율이 아니라 구조로 강제됩니다.

- **보지 못한 것은 보지 못한 것입니다.** 읽지 못한 팩트는 조용한 `PASS`가 아니라 `ERROR`입니다. 절반만 수행한 점검도 `PASS`가 아닙니다 (D07).
- **근거는 결과에 함께 실립니다.** 모든 판정은 판단의 근거가 된 값과 그 값을 만든 파일과 줄 번호를 함께 담습니다 (D08).
- **root로 실행해도 안전합니다.** 셸을 쓰지 않고, 명령은 고정된 화이트리스트뿐이며, 심볼릭 링크를 따라가지 않고, 모든 읽기에 크기 상한이 있으며, 스냅샷은 비밀 값 대신 파생 속성을 저장하고, 스냅샷 외에는 아무것도 쓰지 않습니다 (D14).

## 2. 확정된 결정

| 주제 | 결정 | 참조 |
|---|---|---|
| assay와의 관계 | 별도 리포지터리, 별도 바이너리. 결정은 재사용하고 코드는 재사용하지 않음 | D01 |
| 소유 | 개인 오픈소스 프로젝트, Apache-2.0. 회사 코드나 컨트롤 정의 없음. 개인 신원으로 커밋 | D02 |
| 대상 OS | 리눅스 전용, 영구히. 첫 릴리스는 Ubuntu LTS 22.04와 24.04, Rocky / AlmaLinux 9 | D03 |
| 기준 | KISA 가이드 2026년판, 유닉스 서버 항목 U-01–U-67. CIS 번호는 참조로만. 가이드 본문은 복사하거나 동봉하지 않음 | D04 |
| 컨트롤 모델 | 컨트롤은 작은 판단 어휘를 갖는 YAML 데이터. 그 어휘로 표현할 수 없는 것만 이름 붙인 Go 함수로 | D05 |
| collect / check 분리 | `collect`는 호스트에서 root로 실행. `check`는 (스냅샷, 컨트롤, waiver, 파라미터)의 순수 함수이며 호스트가 필요 없음 | D06 |
| CVE 매칭 | 범위 밖. 스냅샷은 설치된 패키지 목록을 담고 있어 SBOM으로 스캐너에 넘길 수 있음 | D24 |
| 네트워크 점검 | 호스트 내부만. 리스닝 소켓, 방화벽 규칙, 네트워크 sysctl, 불필요한 서비스. 포트 스캔은 하지 않음 | D24 |
| 조치 | 적용하지 않음. 검토용 조치 스크립트를 위험도와 롤백과 함께 생성할 수 있음 | D24 |
| 언어 | Go, 최소 의존성, CLI 프레임워크 없음, 정적 바이너리 하나 | D28 |
| 종료 코드 | `2`(실행 불가 또는 신뢰 불가) > `1`(발견 사항) > `0`(깨끗함) | D11 |

## 3. 기준: KISA 판본과 참조

가이드는 두 판본이 함께 쓰이고 있습니다. 2021년판은 유닉스 항목에 U-01–U-72 번호를 매깁니다. 2026년판(KISA가 2025-12-24 공개, PDF 표기일 2025-12-23)은 번호를 전면 재정렬합니다. 항목은 67개이고 그중 코드와 의미가 모두 유지된 것은 U-01, U-03, U-04뿐입니다. 웹 점검은 유닉스 절을 떠나 새 장(WEB-01–WEB-26)으로 옮겨갔습니다. 비밀번호 관련 네 항목이 U-02로 통합됐고, cron과 at이 U-37로 통합됐고, NFS 두 항목이 U-40으로 통합됐습니다. 여덟 항목이 신설됐습니다(U-13 해시 알고리즘, U-51 DNS 동적 업데이트, U-53 FTP 배너, U-59 SNMP 버전, U-61 SNMP 접근 통제, U-63 sudoers 권한, U-65 시각 동기화, U-67 로그 디렉터리 권한). 2021년판 U-43(주기적 로그 검토)은 없어졌습니다. 두 판본 모두 원본 PDF와 대조해 확인했습니다. 항목 목록, 분류, 중요도, 2021→2026 매핑은 `docs/reference/kisa/`에 있습니다 (D04).

**muster는 2026년판을 따릅니다.** 모든 스냅샷과 보고서에 `guide_edition: kisa-unix-2026`이 들어갑니다. 항목 번호는 판본 사이에서 안정적이지 않으므로 무엇의 기본 키도 되지 않습니다. 컨트롤은 muster 고유의 id를 갖고, KISA 번호는 판본별로 `references.kisa` 아래에 담습니다 (D16). 예전 평가서를 읽는 사람이 해당 컨트롤을 찾을 수 있도록 2021년 번호도 기록합니다.

2026년판 유닉스 절을 분류와 중요도별로 보면 다음과 같습니다.

| 분류 | 항목 | 상 | 중 | 하 |
|---|---|---|---|---|
| 계정 관리 | U-01–U-13 (13) | 6 | 3 | 4 |
| 파일 및 디렉토리 관리 | U-14–U-33 (20) | 15 | 3 | 2 |
| 서비스 관리 | U-34–U-63 (30) | 18 | 9 | 3 |
| 패치 관리 | U-64 (1) | 1 | 0 | 0 |
| 로그 관리 | U-65–U-67 (3) | 0 | 3 | 0 |

공개된 자료의 결함 두 가지를 기록해 둡니다. 컨트롤 작성자가 그 결함을 그대로 물려받지 않게 하기 위해서입니다. 첫째, 2026년판 PDF 53쪽은 U-26의 칸에 U-28의 점검 내용을 인쇄했습니다(U-26의 제목, 위협, 판단 기준, 조치 방법은 올바릅니다). 둘째, U-17과 2021년판 U-14의 관계가 불확실합니다(분할인지 신설인지).

**가이드에서 재수록하는 것과 재수록하지 않는 것.** 항목 코드, 항목명, 분류, 중요도, 쪽 번호는 이 리포지터리에 재수록합니다. `docs/reference/kisa/`와 부록 A가 그 자리이며, muster의 결과를 평가와 연결하는 데 필요한 최소한의 사실 상호 참조 색인입니다. 그 밖의 모든 것은 muster 자체의 문구입니다. 컨트롤 제목, 설명, 근거는 독자적으로 작성하며, 가이드의 점검 내용, 목적, 판단 기준, 조치 방법 본문은 참조 디렉터리에서든 다른 어디에서든 결코 재수록하지 않습니다. 가이드 자체는 링크할 뿐 포함하지 않습니다. 가이드의 발행처, 판본, 발행일, 출처 URL, 명시된 저작권 고지는 `ATTRIBUTION.md`에 기록하며, README와 NOTICE 파일과 `ATTRIBUTION.md`는 이 경계를 같은 문구로 밝힙니다 (D04).

**CIS 참조.** 각 컨트롤은 CIS Benchmark 권고를 `{benchmark, version, rec}` 형태로, 즉 벤치마크 이름과 그 버전과 권고 번호로만 나열할 수 있습니다. 권고의 제목, 본문, 감사 절차는 저장하지 않습니다. 컨트롤 스키마에는 그런 필드가 없고 알 수 없는 필드는 거부합니다. `references.kisa`에도 같은 규칙이 적용되며, 여기에는 판본을 키로 하는 항목 id만 담깁니다. muster는 CIS 준수 수준을 보고하지 않습니다. 이유는 서로 다른 두 출처에 있습니다. 하나는 CIS가 비회원용 Benchmark를 CC BY-NC-SA 4.0으로 공개한다는 점으로, NonCommercial과 ShareAlike 조건만으로도 Apache-2.0 리포지터리와 양립하지 않습니다. 다른 하나는 CIS의 이용 약관으로, 비회원용 제품에 직접 기반한 2차적 저작물의 작성과 특정 수준의 준수 표방을 추가로 금지합니다 (D04).

## 4. 아키텍처

### 4.1 하나의 바이너리, 두 개의 핵심 명령

```
sudo muster collect --out host.json      # 호스트에서, root로
muster check --facts host.json           # 어디서나, root 불필요
muster check --facts host.json --format json
```

서브커맨드는 `collect`, `check`, `controls`(`lint`, `list`. 2단계부터 `new`), `snapshot`(`info`, `extract`. 4단계부터 `ls`, `rm`, `prune`), `version`이고, 이후에 `fix --dry-run`과 `explain`이 더해집니다. 인자는 assay와 마찬가지로 직접 디스패치하며, CLI 프레임워크는 쓰지 않습니다 (D28).

### 4.2 패키지

| 패키지 | 책임 | 하지 말아야 할 것 |
|---|---|---|
| `cmd/muster` | 인자 파싱, 디스패치, 종료 코드 | 로직을 담는 것 |
| `internal/facts` | 스냅샷 타입, 팩트 봉투, 키 레지스트리, `schema_version`, 검증, 직렬화 | `collect` import |
| `internal/collect` | 수집기 레지스트리, 단일 읽기 프리미티브, exec 규율, 배포판 어댑터(`distro/ubuntu`, `distro/rhel`), 파일시스템 워크. 리눅스 빌드 태그 | 컨트롤, waiver, 기존 스냅샷 읽기 |
| `internal/controls` | 컨트롤 스키마, 엄격한 YAML 로더, 내장 기본 세트, lint | 평가 |
| `internal/check` | `Evaluate(facts, controls, waivers, params) → results` | `os/exec`, `net`, 그 밖에 호스트에 닿는 무엇이든 import(테스트로 강제) |
| `internal/waiver` | waiver 파일 로딩과 매칭 | 평가 전에 `check`가 참조하는 것 — 억제는 그 뒤의 단계 |
| `internal/report` | 테이블과 JSON 렌더러(4단계에서 SARIF), 결정성, 이스케이프 | 판정 계산 |

### 4.3 데이터 흐름

```
host ──collect (root, 레지스트리가 선언한 것만 읽음)──▶ snapshot.json
        0600, 원자적 쓰기, /var/lib/muster/snapshots/, flock
snapshot.json + controls (내장) + waivers + params
     ──check (root 불필요, 스냅샷을 신뢰할 수 없는 입력으로 취급)──▶ results
results ──renderers──▶ table / JSON ──▶ exit code (2 > 1 > 0)
```

### 4.4 신뢰 경계

root로 도는 프로세스(`collect`)는 코드 수준 레지스트리가 선언한 것만 읽고 화이트리스트에 있는 명령만 실행합니다. 컨트롤 파일, waiver 파일, 이전 스냅샷은 절대 파싱하지 않습니다. 데이터 파일은 `check`만 읽습니다. `check`는 root가 필요 없고 root로 실행되면 경고합니다. 컨트롤은 바이너리에 내장되어 배포됩니다. 외부 컨트롤 디렉터리(`--controls-dir`, 4단계)는 명시적으로 선택해야 하고, 파일별 다이제스트와 함께 기록되며, 내장 id와 충돌하면 거부됩니다. `check`를 root로 실행할 때, root 소유가 아니거나 group/other 쓰기가 가능한 waiver 파일과 컨트롤 파일은 거부됩니다 (D14, D15).

### 4.5 배포판 차이를 흡수하는 곳

오직 `collect` 안입니다. 배포판 어댑터와 논리 서비스 맵(`ssh`→`ssh`/`sshd`, `cron`→`cron`/`crond`, `ntp`→`chrony`/`systemd-timesyncd`/`ntpd`, `syslog`→`rsyslog`/`syslog-ng`/journald)이 그 자리입니다. `services.*` 아래의 키는 언제나 논리 이름이며 유닛 이름이 아닙니다. `check`는 어떤 배포판이 스냅샷을 만들었는지 알지 못합니다. 컨트롤은 오직 `applies_when` 안에서만 배포판을 언급할 수 있습니다. 배포판이 제거한 메커니즘(pam_tally2, `/etc/securetty`, tcp_wrappers)은 컨트롤의 `mechanisms` 목록이 처리하며, 이는 어댑터 코드가 아니라 데이터입니다 (D09).

### 4.6 확장 지점

새 컨트롤은 YAML 파일 하나와 픽스처 둘입니다. 새 팩트는 레지스트리 항목 하나와 수집기 함수 하나입니다. 새 배포판은 어댑터 하나입니다. 그 밖의 것은 설계 변경입니다.

### 4.7 플랫폼

첫 릴리스의 릴리스 아티팩트는 `linux/amd64`와 `linux/arm64`입니다. `collect`는 리눅스 빌드 태그 뒤에 있고, `check`, `controls`, `report`, `facts`는 어떤 GOOS에서도 컴파일되어야 합니다. 그래야 분석가의 워크스테이션용 check 전용 빌드를 구조 변경 없이 나중에 추가할 수 있습니다 (D23).

## 5. 팩트 스냅샷 스키마

### 5.1 형태

JSON 파일 하나, UTF-8, 구조체에서 직렬화하므로 키 순서가 고정입니다. 최상위는 세 부분입니다.

```json
{
  "schema_version": 1,
  "run": {
    "muster_version": "0.1.0", "commit": "abc1234",
    "controls_version": "kisa-unix-2026+2026.09.01", "controls_digest": "sha256:…",
    "guide_edition": "kisa-unix-2026",
    "collected_at": "2026-09-02T06:00:00Z",
    "host": {"hostname": "web-01", "machine_id_hash": "…", "kernel": "5.14.0-…",
             "os_release": {"id": "rocky", "version_id": "9.4"}, "boot_id": "…", "uptime_s": 12345},
    "euid": 0, "capabilities": ["CAP_DAC_READ_SEARCH"],
    "env": {"container": "none", "virt": "kvm", "wsl": false, "chroot": false,
            "has_systemd": true, "sysctl_writable": true, "cloud_init": false},
    "collectors": [{"name": "sshd", "status": "ok", "ms": 41, "cmd": "/usr/sbin/sshd -T"}],
    "redaction": {"profile": "default", "include_secrets": false},
    "deep": false,
    "complete": true, "partial_failures": []
  },
  "facts": {
    "sshd": {
      "collect_method": "T", "version": "8.7", "personas_collected": false,
      "options": {
        "permit_root_login": {
          "runtime":   {"status": "ok", "value": "no", "source": {"kind": "command", "cmd": "/usr/sbin/sshd -T"}},
          "persisted": {"status": "ok", "value": "no",
                        "source": {"kind": "file", "path": "/etc/ssh/sshd_config.d/50-cloud-init.conf", "line": 2,
                                   "raw": "PermitRootLogin no"}},
          "effective": {"status": "ok", "value": "no", "source": {"kind": "command", "cmd": "/usr/sbin/sshd -T"}},
          "winner":    {"kind": "file", "path": "/etc/ssh/sshd_config.d/50-cloud-init.conf", "line": 2}
        }
      }
    }
  }
}
```

`run`은 출처 정보입니다. 어떤 도구와 컨트롤 세트가, 언제, 어느 호스트에서, 어떤 권한으로, 어떤 환경에서 이 파일을 만들었고 무엇이 잘못됐는지를 담습니다. 스냅샷만으로 문제를 재현할 수 있게 하고, 오래된 스냅샷을 현재 것으로 오인하지 않게 하며, 스냅샷 사이의 diff가 "서버가 바뀐 것"과 "규칙이 바뀐 것"을 구분할 수 있게 하려고 존재합니다 (D16, D17). `run`의 `controls_version`과 `controls_digest`는 수집한 바이너리에 내장된 컨트롤 세트를 기록합니다. `check`는 그와 무관하게 자기 컨트롤 세트로 평가하고, 두 쌍을 모두 결과에 기록하며, 둘이 다르면 stderr에 경고합니다. 이것이 오류가 되는 일은 결코 없습니다.

### 5.2 팩트 봉투

`facts` 아래의 모든 잎은 봉투입니다.

```
{status, value, source, truncated}
status ∈ ok | absent | denied | unsupported | timeout | error
source = {kind: file|command|proc|sys|derived, path, line, raw, cmd, exit_code}
```

상태들은 서로 다른 것을 뜻하며 컨트롤도 이를 다르게 다룹니다. `absent` — 수집기가 찾아보았으나 파일, 유닛, 패키지가 존재하지 않습니다. `unsupported` — 이 배포판이나 환경에는 그런 메커니즘이 없습니다(컨테이너 안의 sysctl, RHEL 9의 `/etc/securetty`). `denied` — 권한이 부족하며, 필요한 권한을 함께 적습니다. `timeout`과 `error` — 수집이 실패했습니다. 모든 근거에 담기는 "파일과 줄 번호"는 `source`에서 나옵니다. `raw`는 그 출처 줄 자체이며 길이 상한이 있습니다. `kind: derived`인 경우(병합된 sysctl의 승자, shadow 항목에서 읽은 해시 알고리즘, 여러 PAM 줄에서 조립한 pwquality 값)에는 `path`와 `line`을 생략하고, 봉투가 `inputs: [source, …]`를 담습니다. 값을 계산하는 데 쓴 모든 출처를 평가 순서대로 담은 것입니다. 렌더러는 첫 번째와 나머지의 개수를 보여 줍니다. 값이 여럿인 키(`ciphers`, `listen_address`, `authorized_keys_file` 등)는 처음부터 리스트입니다. 나중에 문자열을 리스트로 바꾸는 것은 호환성을 깨는 변경이기 때문입니다 (D07, D08).

읽는 쪽에만 존재하는 상태가 하나 더 있습니다. `check`가 자기 레지스트리에 있는 키를 찾았는데 스냅샷이 그 키를 아예 담고 있지 않을 때 — 키보다 오래된 스냅샷이거나, 실행되지 않은 수집기 때문입니다 — 읽는 쪽이 상태 `missing`인 봉투를 만들어 냅니다. `collect`는 `missing`을 결코 쓰지 않습니다. `absent_means`로 해결되지도 않습니다. `absent_means`는 수집기가 찾아보았지만 찾지 못한 팩트에만 적용됩니다. `missing` 팩트는 언제나 컨트롤을 `ERROR(missing_fact)`로 만듭니다 (D07, D17).

### 5.3 두 곳에 사는 설정

동작 중인 커널이나 데몬에도 있고 영속화된 파일에도 있는 설정은 단일 봉투가 아니라 `setting`입니다.

```
{runtime: envelope, persisted: envelope, effective: envelope, winner: source}
```

네 면은 오직 컨트롤 절의 `on:`으로만 선택합니다. 어떤 팩트 키에도 면의 이름을 딴 세그먼트는 들어가지 않습니다. sysctl(`/proc/sys` 대 `/etc/sysctl.conf`와 `/etc/sysctl.d`, `/run/sysctl.d`, `/usr/local/lib/sysctl.d`, `/usr/lib/sysctl.d` 아래 모든 `*.conf`의 병합 결과. 앞선 디렉터리의 파일이 뒤 디렉터리의 같은 이름 파일을 가리고, 살아남은 파일들은 사전순으로 적용되며, 이긴 파일과 줄 번호를 `winner`에 기록), 서비스(active 상태 대 유닛 파일 상태), 방화벽(커널 룰셋 대 영속화된 설정), 커널 모듈(로드됨 대 블랙리스트됨), SELinux(`enforce` 대 `/etc/selinux/config`), 마운트(`mountinfo` 대 `fstab`), 비밀번호 정책(`login.defs` 대 `shadow`의 계정별 유효 필드. `PASS_MIN_LEN` 대 pwquality), 그리고 sshd와 PAM(데몬이 보고한 값 대 데몬이 읽는 파일에 대한 muster의 파싱 결과)에 씁니다.

레지스트리는 각 설정의 기본 면을 선언합니다. 파일에도 함께 사는 커널·데몬 상태(sysctl, 서비스, 방화벽, 모듈, SELinux, 마운트, 비밀번호 만료)에서는 `both`입니다. 양쪽 모두 절을 충족해야 하고, 어긋나면 그 자체가 고유한 사유를 가진 별도의 판정이 됩니다. 영속화된 면이 데몬이 읽는 바로 그 파일들에 대한 muster 자신의 파싱 결과인 경우(sshd, PAM)에는 `effective`입니다. 이때 `effective`는 데몬이 보고한 값을 수집했으면 그 값이고, 수집하지 못했으면 저하됨으로 표시된 파싱 결과입니다 (D10).

### 5.4 섹션

`os`, `env`, `packages`, `accounts`(사용자, 그룹, shadow에서 파생한 필드, `login_defs`, NSS 소스), `pam`(관리 계층, 확장된 스택, 소스와 함께 파생한 pwquality/faillock 값), `sshd`(`collect_method`, `version`, `personas_collected`, 설정으로서의 `options.*`, 2단계부터 페르소나별 재정의, include 소스), `sysctl`(트리 전체), `services`(논리 이름, 유닛, load/active/sub 상태, `masked`/`static`/`indirect`를 포함한 유닛 파일 상태, 트리거 소켓, `installed`, `reachable`), `sockets`(inode, pid, 실행 파일을 포함한 리스닝 소켓), `firewall`(탐지 근거를 갖춘 백엔드, 원본 덤프, 정규화된 모델, `normalization_confidence`), `logging`, `files`(열거된 경로의 권한 팩트), `walk`(`--deep`의 결과: SUID/SGID, world-writable, 소유자 없음. `complete`, `skipped`), `cron`(crontab과 systemd 타이머를 하나의 인벤토리로), `mounts`, `mac`(SELinux/AppArmor), `banners`, `patch`(캐시된 업데이트 메타데이터, 재부팅 필요 여부, 자동 업데이트 설정), `time_sync`, `inetd`, `snmp`. 1단계는 다섯 개 컨트롤에 필요한 섹션만 채우고, 나머지는 타입으로만 존재합니다.

`reachable`은 호스트 밖에서 온 연결이 추가 조치 없이 그 서비스에 닿을 때 true입니다. 유닛이 active이거나 그 유닛을 활성화하는 소켓 유닛이 리스닝 중이면서, 루프백이 아닌 주소에서 그럴 때입니다. 서비스가 돌고는 있지만 `127.0.0.1`이나 `::1`에만 바인딩됐거나, 돌고 있지 않고 리스닝 소켓 유닛도 없으면 false입니다.

권한 팩트는 `st_mode`보다 풍부합니다. `{mode, uid, gid, acl_present, acl_entries, default_acl, caps, attrs, selinux_label, has_extra_xattr}`입니다. 모드는 올바르지만 ACL이 group이나 other 접근을 허용하는 파일은 `FAIL`입니다. ACL이 있는데 읽거나 파싱하지 못한 파일은 `PASS`가 될 수 없습니다 (D26).

### 5.5 키 레지스트리

`internal/facts/registry.yaml`은 컨트롤이 참조할 수 있는 모든 키를 `{key, type, description, since, sensitivity, collector, default_on}`으로 나열합니다. `type`은 `string`, `int`, `bool`, `list<string>`, `record`, `list<record>`, `setting<T>` 중 하나입니다. `sensitivity`는 `public`, `internal`, `secret`입니다(5.6절). `default_on`은 설정에 존재합니다(5.3절). 컨트롤은 `sshd.options.permit_root_login` 같은 등록된 키만 참조하며 그 밖의 것은 참조하지 않습니다. 날것의 JSON 경로는 쓰지 않습니다. `muster controls lint`는 등록되지 않은 키에서 실패하고, 어떤 컨트롤도 쓰지 않는 키를 보고합니다. 레지스트리는 `collect`와 `check` 사이의 계약이며, "수집기가 차이를 흡수한다"를 희망이 아니라 강제 가능한 규칙으로 만드는 장치입니다 (D07, D09).

### 5.6 민감한 값

무엇을 저장할지는 레지스트리의 `sensitivity` 라벨이 결정합니다. 기본값은 이렇습니다. `/etc/shadow` → 해시 알고리즘, 라운드 수, 잠금 여부, 빈 비밀번호 플래그, 만료 관련 필드. 해시 자체는 저장하지 않습니다. `authorized_keys` → 키 타입, 비트 수, 지문, 옵션, 주석. 키 자체는 저장하지 않습니다. SNMP 커뮤니티 → 기본값인지 여부, 길이, 출처 제한이 붙어 있는지 여부. 문자열 자체는 저장하지 않습니다. 개인키, 호스트 키, keytab → 존재 여부와 권한만. 프로세스 커맨드라인 → `argv[0]`만. `--include-secrets`는 원본을 저장하고 그 사실을 `run.redaction`에 기록하므로, 파일 자체가 무엇을 담고 있는지 말해 줍니다 (D13).

### 5.7 버저닝

`schema_version`은 정수입니다. 키를 추가하는 것은 버전을 올리지 않습니다(키가 언제 생겼는지는 그 키의 `since`가 기록합니다). 키의 타입이나 의미를 바꾸거나 키를 제거하는 것은 버전을 올립니다. `check`는 더 높은 버전의 스냅샷을 거부하고(`exit 2`, `schema_mismatch`), 더 낮은 버전은 읽습니다. 스냅샷이 담고 있지 않은 등록된 키는 `missing`으로 읽히고(5.2절), 그 키를 참조하는 모든 컨트롤은 `ERROR(missing_fact)`가 됩니다. 결코 `PASS`가 아니며, `absent_means`로 해결되지도 않습니다. 컨트롤은 정수 N에 대해 `requires_facts: ">=N"`을 선언합니다(허용되는 유일한 형태입니다). 스냅샷이 그 요구를 충족하지 못하는 컨트롤은 평가 없이, 버전을 명시한 `ERROR(missing_fact)`가 됩니다. 리플렉션으로 생성한 스키마 골든 파일과 `testdata/snapshots/v<N>/` 아래의 옛 스냅샷 코퍼스가 이 규칙을 지키게 합니다 (D17).

### 5.8 한도

파일 읽기 하나당 1 MiB입니다(`sudoers`와 `authorized_keys`는 더 작습니다). 그 이상은 `truncated: true`입니다. 워크 결과에는 개수 상한과 `truncated_count`가 붙습니다. 잘린 팩트에 의존하는 컨트롤은 `PASS`가 될 수 없습니다.

### 5.9 수명 주기

기본 출력은 `/var/lib/muster/snapshots/<hostname>-<UTC 타임스탬프>-<짧은 다이제스트>.json`이며(디렉터리 0700, 파일 0600), 임시 파일에 쓴 뒤 이름을 바꿉니다. `--out <path>`와 `--out -`로 덮어쓸 수 있습니다. `latest` 심볼릭 링크는 원자적으로 교체합니다. `/var/lib/muster/.lock`의 잠금 덕분에 두 번째 `collect`가 동시에 돌면 실행 중인 PID를 알리며 2로 종료합니다. 쓰기 전에 여유 공간을 확인합니다. `snapshot ls|rm|prune --keep N --keep-days D`와 예시 타이머 유닛은 4단계에 도착합니다 (D13).

## 6. 컨트롤 형식

### 6.1 파일과 식별자

컨트롤 하나가 `controls/<area>/<name>.yaml` 아래의 파일 하나이고, 바이너리에 내장됩니다. 기본 키는 `muster.account.root_remote_login`처럼 안정적이고 의미에 기반한 id이며, KISA 번호는 참조입니다. 세트 전체는 `controls/VERSION`(예: `kisa-unix-2026+2026.09.01`)과 다이제스트를 가지며, 둘 다 모든 결과에 보고됩니다. 바이너리는 semver를 따르고, 컨트롤 세트는 자체 버전을 가집니다. 기존 스냅샷에 대한 판정을 바꾸는 변경은 최소한 마이너 릴리스이며 체인지로그에 `Controls` 절을 둡니다 (D16).

### 6.2 컨트롤 하나

```yaml
id: muster.account.root_remote_login
title_en: Root login over SSH is disabled
title_ko: SSH를 통한 root 직접 로그인 차단
category: account                # account | file | service | patch | log | beyond
importance: 상                    # KISA 중요도, 필수. severity는 여기서 파생(9절)
automation: auto                 # auto | partial | manual | not_applicable
references:
  kisa: { "2026": ["U-01"], "2021": ["U-01"] }
  cis:  [{ benchmark: ubuntu-22.04, version: "2.0.0", rec: "5.1.20" }]   # 번호만
requires_facts: ">=1"
applies_when:
  - { fact: services.ssh.installed, op: eq, expected: true }
absent_means: not_applicable     # ssh 서비스 없음 → 사유를 붙여 NOT_APPLICABLE
params:
  allowed: { type: list<string>, default: ["no", "prohibit-password"],
             description: 비활성으로 간주하는 PermitRootLogin 값 }
mechanisms:                      # `when`이 성립하는 첫 메커니즘이 판정 대상
  - when:
      - { fact: sshd.options.permit_root_login, op: present }
    checks:
      - { fact: sshd.options.permit_root_login, on: effective, persona: root,
          op: in, expected: ${allowed} }
  - when:
      - { fact: files.etc_securetty, op: present }          # 레거시 폴백
    checks:
      - { fact: files.etc_securetty.lines, op: none,
          where: { op: matches, expected: "^pts/" } }
remediation:
  text_en: Set PermitRootLogin no in sshd_config(.d), validate with sshd -t, restart sshd.
  text_ko: sshd_config(.d)에 PermitRootLogin no 를 설정하고 sshd -t 로 검증 후 재시작
  risk: lockout_risk             # none | restart_service | reboot_required | lockout_risk
  idempotent: true
  script: |
    printf 'PermitRootLogin no\n' > /etc/ssh/sshd_config.d/90-muster.conf && sshd -t
  rollback: rm -f /etc/ssh/sshd_config.d/90-muster.conf && sshd -t
decision: D09
```

필드는 다음과 같습니다. `id`, `title_en`, `title_ko`, `description_en`, `description_ko`(자체 문구), `category`, `importance`, `automation`, `manual_reason`(`automation: manual`일 때 필수), `references`(`kisa`는 판본을 키로 하는 항목 id, `cis`는 benchmark/version/`rec`. `isms_p`와 `nist_800_53` 키는 예약되어 있고 비어 있음), `requires_facts`, `applies_when`, `absent_means`(`absent`가 될 수 있는 팩트를 참조하는 모든 컨트롤에 필수), `params`, `checks`·`mechanisms`·`custom` 중 정확히 하나, `remediation`(`automation: auto`이거나 `partial`일 때 필수), `decision`(13절을 가리키는 선택적 포인터).

### 6.3 판단 어휘

**절 문법.** 모든 절은 — `checks`, `when`, `applies_when`, `where`, `require` 아래에서 똑같이 — 키 `{fact, op, expected}`와 선택적 수식어 `on`, `persona`만 씁니다. `where`와 `require` 안에서는 `fact` 대신 `field`가 오며, 검사 대상 원소의 필드 이름을 가리킵니다. 원소가 스칼라이면 생략합니다. 엄격한 디코딩은 그 밖의 키를 모두 거부합니다. `applies_when`과 `when`은 모두 성립해야 하는 절의 리스트입니다. 인라인 절 하나는 원소가 하나인 리스트의 약식 표기입니다. `or`는 없습니다. 대안은 `mechanisms`로 표현합니다.

**연산자.** 스칼라 연산자 열두 개(`eq ne in not_in lt lte gt gte matches contains present absent`)와 컬렉션 연산자 두 개(`each`, `none`)가 있습니다. `present`와 `absent`는 `expected`를 받지 않습니다. `matches`는 Go `regexp`(RE2) 패턴을 받습니다. 앵커 없이 대소문자를 구분해, 스칼라의 값 전체 또는 리스트의 각 원소에 대해 매칭하며, `.`은 개행에 매칭하지 않습니다. lint는 로드 시점에 모든 패턴을 컴파일합니다. 비교는 레지스트리가 타입을 정하므로 `"0"`과 `0`을 혼동할 수 없습니다. `lt`…`gte`는 숫자 타입을 요구합니다.

**파라미터.** `expected`는 리터럴이거나 `${name}`입니다. 치환은 값 전체 단위로만 이루어집니다. `expected` 전체가 정확히 `${name}`이어야 합니다. 파라미터의 값은 선언된 타입을 유지한 채 삽입되므로 리스트 파라미터는 리스트를 내놓습니다. `params` 아래의 각 항목은 `{type, default, description}`을 선언합니다. lint는 선언되지 않은 파라미터에 대한 참조와 타입이 맞지 않는 기본값을 거부합니다.

**설정.** `setting` 팩트에서는 `on`이 `runtime`, `persisted`, `effective`, `both` 중 하나를 고르며, 기본값은 그 키에 대한 레지스트리의 `default_on`입니다(5.3절). `both`에서는 양쪽 모두 절을 충족해야 합니다. 한쪽만 충족하면 `WARN`이며, 사유는 "재부팅하면 되돌아감"(runtime만 충족) 또는 "적용되지 않음"(persisted만 충족)입니다.

**페르소나.** `persona`는 sshd의 Match 페르소나(`root`, `user`, `invalid`)를 고르며, `sshd.options.*`에서만 의미가 있습니다. 스냅샷의 sshd 섹션에 `personas_collected: false`가 있으면 절은 전역 값에 대해 평가되고, 그 컨트롤의 수집은 저하된 것으로 칩니다(6.5절).

**컬렉션.** `each`와 `none`은 `list<record>`나 `list<string>` 팩트에 적용되며 관찰을 만들어 냅니다(6.4절). `each`는 `subject`와, 선택적인 `where`(필터 절. 이를 충족하지 않는 원소는 무시합니다)와, 필수인 `require`(남은 모든 원소가 충족해야 하는 절)를 받습니다. `none`은 선택적인 `subject`와 필수인 `where`를 받으며, 어떤 원소도 이를 충족해서는 안 됩니다. `require`를 충족하지 못하는 원소가 하나라도 있거나 `none`의 `where`를 충족하는 원소가 하나라도 있으면 절은 실패합니다.

**넘치는 것.** 이 어휘로 표현할 수 없는 것은 `custom: <GoFunctionName>`을 씁니다. `check`에 등록된 함수로, 팩트만 읽고 같은 모양의 관찰을 돌려줍니다 (D05).

### 6.4 컬렉션과 관찰

대상이 사물의 집합인 항목은 `each`로 씁니다.

```yaml
id: muster.file.world_writable
automation: partial              # 근거는 자동, 최종 판단은 사람
checks:
  - fact: walk.world_writable
    op: each
    subject: path                # 관찰 키 → file:/var/tmp/x
    where:   { field: sticky, op: eq, expected: false }
    require: { field: package_declared, op: eq, expected: true }   # 패키지가 원래 그렇게 배포한 경우
```

각 관찰은 `{subject, expected, actual, verdict, source}`로 보고됩니다. 대상 키는 `<kind>:<value>` 형태입니다. 컬렉션의 레지스트리 항목이 kind(`file`, `dir`, `user`, `group`, `unit`, `port`, `module`, `mount`, `key`)를 정하고, `subject:` 필드가 `<value>`를 채울 원소 필드의 이름을 가리킵니다. 컨트롤의 상태는 그 관찰들에서 따라 나옵니다. `each`에서는 모든 관찰이 성립해야 하고, `none`에서는 관찰이 하나도 존재해서는 안 됩니다. 실패한 관찰이 하나만 있어도 절이 실패하며, 테이블은 실패한 관찰 중 앞의 N개를 보여 주고 나머지는 `--all`로 봅니다. waiver는 컨트롤 전체를 지정할 수도 있고 관찰 하나를 지정할 수도 있습니다(`muster.file.world_writable#file:/var/tmp/x`) (D08, D20).

### 6.5 상태 도출 (고정)

아래 행들은 순서대로 평가하며, 처음으로 적용되는 행이 결정합니다. 팩트 상태는 각 단계가 참조하는 모든 팩트에 대해 살피며, `applies_when`과 `when`이 쓰는 팩트도 포함합니다.

| 단계 | 상황 | 상태 |
|---|---|---|
| 1 | 스냅샷이 `requires_facts`를 충족하지 못함 | `ERROR(missing_fact)`, 평가하지 않음 |
| 2 | `automation: manual` | 수집한 근거와 함께 `MANUAL` |
| 3 | `applies_when`이 참조한 팩트가 `missing`, `denied`, `timeout`, `error`, `truncated` | 해당 팩트를 명시한 `ERROR` |
| 4 | `applies_when`이 참조한 팩트가 `absent`나 `unsupported`이거나, `applies_when`이 거짓으로 평가됨 | 근거를 붙인 `NOT_APPLICABLE` |
| 5 | `mechanisms`를 쓰는데 후보 팩트가 모두 `absent`나 `unsupported`여서 성립하는 `when`이 없음 | `absent_means`에 따름(`pass`, `fail`, `not_applicable`, `manual`) |
| 6 | 선택된 `checks`가 참조한 팩트가 `missing`, `denied`, `timeout`, `error`, `truncated` | 권한, 한도, 키를 명시한 `ERROR` |
| 7 | 선택된 `checks`가 참조한 팩트가 `unsupported` | 환경을 명시한 `NOT_APPLICABLE` |
| 8 | 선택된 `checks`가 참조한 팩트가 `absent` | `absent_means`에 따름 |
| 9 | 워크 기반 컨트롤인데 워크를 실행하지 않음 | `MANUAL`("collect --deep을 실행하십시오") |
| 10 | 워크 기반 컨트롤인데 `walk.complete`가 false | `ERROR(walk_incomplete)` |
| 11 | 절이 실패하고 `automation: partial` | `WARN`, 수동 검토 항목으로 표시 |
| 12 | 절이 실패 | `FAIL` |
| 13 | 모든 절이 성립하지만 수집이 저하됨(데몬이 보고하는 설정에 대한 파싱 폴백, 페르소나를 요청했으나 수집되지 않음, 방화벽 신뢰도가 full 미만, 계정 팩트의 원격 NSS 소스) | 저하 내용을 명시한 `WARN` |
| 14 | 모든 절이 성립 | `PASS` |

waiver는 표를 거친 뒤에, `FAIL`과 `WARN`에만 적용합니다. 일치하는 유효한 waiver는 결과를 `WAIVED`로 바꾸며, 집계하고 표시합니다. waiver는 `ERROR`, `NOT_APPLICABLE`, `MANUAL`에는 결코 적용되지 않습니다. 그런 컨트롤에 waiver가 일치하면 적용되지 않았다고 사유와 함께 기록하고, 종료 코드는 그대로입니다.

따라서 `WARN`은 세 가지 중 하나를 뜻하고 사유가 어느 쪽인지 말해 줍니다. 수집이 저하됐거나(13단계), 기준은 충족하지만 위험 신호가 남아 있거나(`both` 설정이 한쪽에서만 충족된 경우, 6.3절), 판단이 사람의 몫이거나(11단계)입니다. `MANUAL`은 자동 판정이 불가능하다는 뜻이며 근거가 첨부됩니다. 요청하지 않는 한 둘 다 종료 코드에 영향을 주지 않습니다 (D18).

### 6.6 파라미터와 프로파일

`params`는 타입과 기본값과 함께 임계값을 선언하고, 판정이 이를 참조합니다(6.3절). 1단계에는 기본값만 존재합니다. `--tuning <file>`(조직의 값)과 프로파일(`{extends, include, exclude, params, severity}`, `default`라는 이름의 내장 프로파일 포함)은 3단계에 도착합니다. 실제로 적용된 파라미터 값은 결과에 기록됩니다 (D18).

### 6.7 Waiver

파일 형식은 assay의 D102를 따릅니다.

```yaml
waivers:
  - control: muster.file.world_writable
    subject: "file:/var/tmp/legacy.sock"   # 선택. 없으면 컨트롤 전체
    reason: 레거시 배치 작업이 이 소켓을 만듦. 2026-Q4에 이전 예정   # 필수
    expires: 2026-12-31                    # 선택, 해당일 포함
```

사유가 없거나, 알 수 없는 키가 있거나, 일치 필드가 없는 waiver는 로드 시점에 거부됩니다. 만료된 waiver는 면제를 멈추고 경고합니다. 존재하지 않는 컨트롤 id를 지정한 waiver는 경고합니다. waiver는 `FAIL`과 `WARN`만 억제합니다(6.5절). 상태가 `ERROR`인 컨트롤은 결코 면제되지 않습니다. waiver는 적용되지 않았다고 기록되고 종료 코드는 2로 남으며, 오류를 종료 코드에서 빼는 방법은 `--allow-error`뿐입니다. 면제된 발견 사항은 `WAIVED`로 옮겨집니다. 종료 코드에서는 빠지지만 요약에는 항상 나옵니다("면제 N건, 그중 M건은 30일 안에 만료"). `check`를 root로 실행할 때, root 소유가 아니거나 group/other 쓰기가 가능한 waiver 파일은 거부됩니다 (D12).

### 6.8 Lint

`muster controls lint`는 다음을 거부합니다. 알 수 없는 키(엄격한 디코딩), 중복된 id, 등록되지 않은 팩트 키, 알 수 없는 `custom` 함수 이름, 6.3절 문법을 벗어난 절 키, 컴파일되지 않는 `matches` 패턴, 선언되지 않은 파라미터에 대한 참조나 타입이 맞지 않는 기본값, `manual_reason` 없는 `manual`, `remediation` 없는 `auto`나 `partial`, 빠진 `importance`, `absent` 팩트를 만날 수 있는데 `absent_means`가 없는 컨트롤, `benchmark`·`version`·`rec` 외의 필드를 가진 `references.cis` 항목, 판본을 키로 하는 항목 id 리스트가 아닌 `references.kisa` 값, 픽스처 쌍이 없는 컨트롤입니다. 2단계부터는 `docs/reference/kisa/`의 67개 항목 마스터 목록과 id 집합을 대조해 빠지거나 중복된 KISA 참조도 확인합니다.

## 7. 오류 처리와 종료 코드

규칙은 이렇습니다. 어떤 실패도 조용한 `PASS`가 되지 않으며, 도구 자체는 죽지도 멈추지도 않습니다.

### 7.1 collect

수집기들은 서로 격리됩니다. 실패한 수집기 하나는 자신의 상태, 사유, 소요 시간을 `run.collectors[]`에 기록하고, 자기 팩트를 `error`(또는 `timeout`, `denied`)로 표시하고, `run.complete=false`로 설정하고, `run.partial_failures`에 자기 이름을 적습니다. 나머지는 계속 진행합니다. 스냅샷은 성공한 것들만으로 기록됩니다. 다만 언제나 완성된 임시 파일을 제자리로 이름 바꾸는 방식이므로, 절반만 쓰인 스냅샷은 존재할 수 없습니다.

| 실패 | 결과 |
|---|---|
| 명령 타임아웃(기본 5초, 수집기별 재정의 가능) 또는 전체 데드라인(`--timeout`, 기본 5분) | 프로세스 그룹을 종료. 팩트는 `timeout` |
| 권한 부족 | 필요한 권한을 명시한 `denied` 팩트. euid ≠ 0이면 `--require-root`가 아무것도 쓰기 전에 2로 종료 |
| 심볼릭 링크, FIFO, 디바이스, 크기 초과 또는 바이너리 파일 | 읽기 프리미티브가 거부하거나 자름. `error` / `truncated`. 결코 블록되지 않음 |
| 워크가 예산 초과 | `walk.complete=false`, 멈춘 지점과 `skipped[]`를 기록 |
| 알 수 없는 배포판 | `os.family=unknown`, 경고, 파일 기반 수집기만 동작 |
| 컨테이너, WSL, 가려진 `/proc` | 해당 팩트는 `unsupported` |
| 다른 `collect`가 잠금을 쥐고 있음 | 아무것도 쓰지 않음. PID와 시작 시각을 알리며 2로 종료 |
| 여유 공간 부족, 출력 경로가 심볼릭 링크이거나 world-writable 디렉터리 안에 있음, `--force` 없이 출력 파일이 이미 존재 | 아무것도 쓰지 않음. 2로 종료 |
| 패닉 | 최상위 recover. 2로 종료. 스냅샷 없음 |

`collect`의 종료 코드는 이렇습니다. `0` 완전한 스냅샷, `1` 스냅샷은 썼지만 불완전(부분 실패나 권한 거부), `2` 스냅샷 없음. `--require-complete`는 `1`을 `2`로 바꿉니다 (D11).

### 7.2 check

입력은 신뢰할 수 없습니다. 파싱에 실패하거나, 디코드 크기나 중첩 한도를 넘거나, `schema_version`이 더 높은 스냅샷은 결과를 만들지 않고 2로 종료합니다(`schema_mismatch`). 더 낮은 버전은 빠진 키를 `missing`으로 삼아 읽습니다(5.2절). 로드에 실패한 외부 컨트롤 디렉터리, 그리고 사유가 없거나 알 수 없는 키가 있거나 일치 필드가 없는 waiver 파일은 2로 종료입니다(내장 컨트롤은 CI가 lint하므로 런타임에 실패할 수 없습니다). 알 수 없는 컨트롤 id를 지정한 waiver는 결과에 기록되는 경고입니다.

컨트롤들도 서로 격리됩니다. 어떤 컨트롤의 평가 중 패닉(대개 custom 함수)이 나면 그 컨트롤은 `ERROR(internal_error)`가 되고 나머지는 평가됩니다. 최상위 recover는 마지막 방어선이며 2로 종료합니다.

`ERROR` 사유는 고정된 어휘입니다. `permission_denied`, `timeout`, `truncated`, `unsupported_env`, `parse_error`, `missing_fact`, `schema_mismatch`, `walk_incomplete`, `internal_error`이며, 사람이 읽을 문구와 함께 JSON에 실려 CI가 이 값으로 매칭할 수 있습니다. 요약은 언제나 몇 개의 팩트가 수집에 실패했는지를 밝힙니다.

`check`의 종료 코드는 이렇습니다. `ERROR`가 하나라도 있으면 `2`, 아니면 `FAIL`이 하나라도 있으면 `1`, 그 밖에는 `0`입니다. `--allow-error`는 오류를 보고하되 종료 코드는 실패만으로 계산합니다(비 root 실행처럼 부분적임이 알려진 스냅샷용입니다). `--fail-on`의 기본값은 `fail`입니다. `fail`은 `FAIL`이 하나라도 있으면 1로 종료합니다. `warn`과 `manual`은 여기에 더해 `WARN`이나 `MANUAL`에서도 1로 종료합니다. `none`은 모든 발견 상태에 대해 0으로 종료하며 `ERROR` → 2 규칙만 남깁니다. `2 > 1 > 0` 우선순위는 모든 조합에서 성립하며 골든 테스트로 고정됩니다 (D11).

### 7.3 정직한 하향 판정

완전한 판정이 불가능할 때, 개별 컨트롤이 아니라 엔진이 깨끗한 통과로 오인될 수 없는 상태로 낮춥니다(6.5절 13단계). `sshd -T`를 쓸 수 없으면 → 파일을 파싱해 판정하되 `WARN`. 페르소나를 요청했으나 수집되지 않았으면 → 전역 값에 대해 판정하고 `WARN`. 방화벽 정규화 신뢰도가 `partial`이나 `none`이면 → 원본 룰셋을 붙인 `MANUAL`이며 결코 `FAIL`/`PASS`가 아님. NSS에 원격 계정 소스(sssd, ldap, winbind)가 있으면 → 계정 컨트롤은 `WARN`("로컬 파일만"). ACL이 있는데 읽을 수 없으면 → 모드가 맞더라도 `ERROR`. 패치 메타데이터 캐시가 오래됐으면 → 그 나이와 함께 `WARN`.

### 7.4 채널

결과 JSON은 stdout으로 가고 그 밖의 것은 아무것도 stdout으로 가지 않습니다. 경고, 진행 상황, `-v` 로그는 stderr로 갑니다. 로그 파일은 결코 쓰지 않습니다. stdout이 닫혔거나 실패하면 2로 종료합니다. 테이블 출력은 근거 값에 들어 있는 C0/C1 제어 문자, ANSI 시퀀스, 캐리지 리턴을 이스케이프하고 긴 값을 자릅니다. 침해된 호스트에서 온 스냅샷도 정상적인 입력이기 때문입니다.

## 8. 도구 자체의 보안

muster는 남의 프로덕션 호스트에서 root로 돌고, 그 출력은 공격자가 바랄 수 있는 가장 농축된 호스트 기술서입니다. 아래는 지침이 아니라 테스트로 확인하는 계약입니다 (D14).

- **명령.** 수집기 레지스트리에 등록된 명령만 실행합니다. 절대 경로, 고정된 인자, 명령별 타임아웃, 출력 상한이 붙습니다. 셸은 쓰지 않습니다. 환경은 버리고 다시 구성합니다(`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, `LANG=C`, `TZ=UTC`. `LD_PRELOAD`, `LD_LIBRARY_PATH`, `IFS`는 결코 상속하지 않습니다). 프로세스는 자기 그룹에서 돌기 때문에 타임아웃이 자손까지 종료합니다.
- **읽기.** 모든 파일 읽기는 두 계층을 가진 하나의 프리미티브를 거치며, 어느 계층을 썼는지는 팩트의 `source`에 기록됩니다. 1계층은 `RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`를 준 `openat2`입니다(리눅스 5.6 이상. 첫 릴리스의 모든 대상이 여기 해당합니다). 경로의 어느 구성 요소에 있든 심볼릭 링크를 거부합니다. 2계층은 `openat2`를 거부하는 커널이나 seccomp 프로파일을 위한 것으로, `/`부터 `openat(O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC)`으로 경로를 구성 요소 단위로 걸어가며 같은 보장을 줍니다. 어느 계층도 경로의 어디에서든 심볼릭 링크를 따라가지 않습니다. `os.Root`는 자기 루트 안의 링크를 따라가므로 쓰지 않습니다. 연 다음에는 `fstat`으로 일반 파일임을 확인합니다(FIFO, 디바이스, 소켓은 거부합니다). 크기 상한이 적용됩니다. NUL 바이트가 있으면 그 파일을 바이너리로 표시하고 내용을 저장하지 않습니다. 부모 디렉터리가 world-writable이거나 root 소유가 아니면 `path_untrusted`를 설정합니다.
- **워크.** 기본적으로 꺼져 있습니다(`--deep`). 로컬 파일시스템만 대상으로 하며 `/proc/self/mountinfo`로 판단합니다. `nfs`, `cifs`, `smb3`, `fuse.*`, `sshfs`, `afs`, overlay와 snap 마운트는 제외합니다. autofs 마운트 지점은 `stat`조차 하지 않습니다. `/proc`, `/sys`, `/dev`, `/run`은 건너뜁니다. 심볼릭 링크는 따라가지 않습니다. `(dev, ino)` 집합으로 순환을 끊습니다. 시간과 개수 예산이 다하면 `complete=false`로 워크를 끝냅니다. `nice`와, I/O 스케줄러가 존중하는 경우의 `ionice`가 우선순위를 낮춥니다.
- **쓰기.** 스냅샷은 `collect`가 쓰는 유일한 파일입니다. 어떤 서브커맨드도 서비스를 재시작하지 않고, 설정을 바꾸지 않고, 네트워크 연결을 만들지 않고, 패키지 메타데이터를 갱신하지 않고, 업데이트를 확인하지 않고, 텔레메트리를 보내지 않습니다. CI는 네트워크 없는 컨테이너에서 읽기 전용 바인드 마운트 위에 `collect`를 돌려 이를 증명합니다.
- **데이터 파일.** root는 컨트롤, waiver, 옛 스냅샷을 결코 파싱하지 않습니다. `check`는 root일 때 쓰기 가능한 데이터 파일을 거부하고, 스냅샷을 적대적 입력으로 다룹니다(디코드 한도, 그 안의 무엇도 실행하지 않음, 그 안의 경로를 출력 경로로 재사용하지 않음, 이스케이프한 렌더링).
- **스냅샷 기밀성.** 기본적으로 편집합니다(5.6절). 0700 디렉터리 안의 0600 파일입니다. 기본 위치는 결코 `/tmp`가 아닙니다. 잠금과 보존 정책을 갖춘 수명 주기가 있습니다(5.9절). 공유용 `--anonymize` 모드(호스트명, 주소, 사용자 이름의 안정적 해싱)는 익명화한 스냅샷과 원본 스냅샷이 동일한 판정을 낳는지 확인하는 불변식 테스트와 함께 3단계에 도착합니다.
- **한계는 암시하지 않고 명시합니다.** `THREAT_MODEL.md`가 신뢰 경계를 기록하고, 이미 침해된 호스트(`LD_PRELOAD`, 교체된 바이너리, 되돌려진 설정)는 muster가 `PASS`를 보고하게 만들 수 있음을 분명히 말합니다. muster는 침입 탐지 도구가 아닙니다. `SECURITY.md`는 신고 경로와 지원 버전을 알립니다.
- **릴리스 무결성**(4단계): 재현 가능한 정적 빌드(`CGO_ENABLED=0 -trimpath`, 고정한 Go 버전), `checksums.txt`, GitHub 아티팩트 어테스테이션(SLSA Build L2임을 그대로 명시), 키 없는 cosign 서명, SBOM, CI의 `govulncheck`, deb와 rpm 패키지, 설치 안내보다 앞에 오는 검증 안내, `curl | sh` 없음.

## 9. 출력과 UX 계약

- 사람을 위한 테이블 출력, 나머지 모두를 위한 JSON, 4단계의 SARIF입니다.
- 같은 스냅샷, 같은 컨트롤 세트, 같은 파라미터 → 바이트 단위로 동일한 JSON입니다. 변동하는 값(시각, 호스트, 소요 시간, 버전)은 `run` 아래에만 있습니다. 결과는 심각도 다음 id 순으로 정렬합니다. 로케일과 시간대는 출력에 영향을 주지 않습니다.
- **심각도**는 `high`, `medium`, `low`이며, 3단계에서 프로파일이 덮어쓰기 전까지는 KISA 중요도에서 파생합니다(상 → `high`, 중 → `medium`, 하 → `low`). 정렬 키이자 `--severity` 필터 키(2단계)이자 SARIF level(4단계)입니다.
- **결과의 출처 정보.** 모든 결과는 스냅샷의 `run` 블록을 그대로 담고, 여기에 `check` 블록을 더합니다. 평가한 바이너리의 버전과 커밋, 그 `controls_version`과 `controls_digest`, `snapshot_digest`, `waivers: {path, digest, applied, not_applied}`, 그리고 적용된 파라미터 값입니다.
- **요약.** 테이블 앞에는 언제나 요약 블록이 오며 세 부분으로 나뉩니다. 심각도별 자동 판정(`PASS`, `FAIL`, `WARN`), 수동 검토 대상(`MANUAL`과 partial 컨트롤의 `WARN`), 판정할 수 없는 항목(`ERROR`, `NOT_APPLICABLE`, `WAIVED`)입니다. 그 뒤에 수집에 실패한 팩트의 개수와 30일 안에 만료되는 waiver가 따릅니다. 단일 하드닝 점수는 없습니다. 비율을 보여 준다면 분모를 밝히고 `MANUAL`과 `NOT_APPLICABLE`을 제외합니다 (D18).
- `NO_COLOR`, `TERM=dumb`, 비 TTY는 색과 박스 그리기를 끕니다. `--no-color` / `--color=always`가 이를 덮어씁니다. 한글 항목명은 동아시아 폭 2로 배치합니다.
- `--quiet`는 `FAIL` 이상만 보여 줍니다. `-v`/`-vv`는 수집기별 명령과 소요 시간을 보여 줍니다. 필터 `--only`, `--skip`, `--category`, `--severity`는 2단계에 도착합니다. 설정 파일은 v2로 미룹니다. v1에는 플래그와 환경 변수로 충분합니다.
- `muster collect --list-actions`는 레지스트리를 바탕으로 읽는 모든 경로, 실행하는 모든 명령, 각각에 필요한 권한, 쓰는 단 하나의 경로를 테이블이나 JSON으로 출력합니다. 변경 관리 검토자가 읽는 문서가 바로 이것입니다.
- `muster version`은 바이너리 버전, 커밋, 빌드 일시, 컨트롤 세트 버전, 가이드 판본을 출력합니다.

## 10. 범위와 단계

### 10.1 분류 규칙

항목은 KISA 분류가 아니라 판정에 필요한 팩트의 종류로 분류합니다.

- **auto** — 수집한 팩트에서 판정이 따라 나옵니다.
- **partial** — 근거는 자동으로 수집하지만 최종 판단은 사람의 몫입니다(어떤 계정이 불필요한지, 어떤 SUID 파일이 정당한지). 위반은 관찰 목록과 함께 `WARN`으로 보고하고, 항목은 수동 검토로 집계합니다.
- **manual** — 인터뷰나 외부 사실이 필요합니다. 근거는 첨부합니다.
- **deferred (service)** — 판정에 v1이 제공하지 않는, 특정 데몬 고유 설정의 파서가 필요합니다. 메일(postfix, sendmail), DNS(bind), FTP 데몬 설정(vsftpd, proftpd)이 그렇습니다. 평범한 파일이나 서비스 상태를 읽는 항목(`ftpusers`, telnet, NFS export, `snmpd.conf`의 커뮤니티)은 미루지 않습니다. v1에서 미룬 항목들은 muster가 수집할 수 있는 근거(설치 여부, 구동 여부, 버전 문자열)와 함께 `manual`로 등록하고, `manual_reason`에 미룬 사유를 적습니다.
- **not_applicable** — 지원 플랫폼에 그 메커니즘이 없습니다. 컨트롤이 그 이유를 말합니다.

2026년판 목록에 대입하면 **auto 51, partial 7, deferred 9, manual 전용 0, not-applicable 0**이 됩니다. 67개 중 58개를 어떤 형태로든 자동 판정합니다. 항목별 표는 부록 A입니다. 2단계부터는 컨트롤 세트(id, `automation`)와 `docs/reference/kisa/`의 참조 인벤토리(항목명)를 조인해 재생성하고, 커밋된 표와 일치하는지 CI가 확인합니다.

### 10.2 단계

**1단계 — 뼈대.** `collect`와 `check`. 봉투, 설정, 레지스트리, 출처 정보를 갖춘 팩트 스키마. 읽기 프리미티브, exec 규율, `--list-actions`를 갖춘 수집기 레지스트리. 워크 없는 워크 뼈대(`--deep` 플래그, 경계, 예산, `complete`). 결정성 계약을 갖춘 테이블과 JSON 출력. 종료 코드. waiver. 스냅샷 수명 주기(경로, 이름, 잠금). 편집 정책. 컨트롤 lint. 픽스처 규약과 레지스트리 테스트. 결과 불변식. `testdata/`의 시크릿 스캔. 최상위 recover 가드. `THREAT_MODEL.md`, `SECURITY.md`, `ATTRIBUTION.md`. README 한 쌍. 다섯 개의 컨트롤이 끝에서 끝까지 흐르며, 기계 장치를 두루 시험하도록 골랐습니다. 각각에 대해 1단계가 반드시 내놓아야 하는 최소 수집 능력은 이렇습니다.

- `U-01`(sshd, `mechanisms`, `persona`): `sshd -T`의 전역 값만, `personas_collected: false`, include 추적 없음. 그래서 2단계가 페르소나를 더하기 전까지 이 컨트롤은 평가되어 `WARN`(저하됨)을 보고합니다.
- `U-02`(비밀번호 정책, 두 곳에 사는 설정, `params`): `login.defs`와 계정별 `shadow` 만료 필드. pwquality 절은 2단계에서 PAM 수집기와 함께 합류합니다.
- `U-16`(`/etc/passwd`, 권한 팩트): 모드, 소유자, 그룹, 그리고 ACL xattr에서 얻는 `acl_present`. ACL 항목은 2단계에서 파싱하므로, 1단계에서 ACL이 있는 파일은 `WARN`입니다.
- `U-52`(Telnet, 서비스 정규화, `absent_means: pass`): 매핑된 유닛에 대한 `systemctl show`와 `/proc/net/tcp`의 리스닝 소켓. 소켓 활성화와 `masked`/`static` 처리는 2단계에서 완성됩니다.
- `U-25`(world-writable, 워크, `each`, partial): 1단계에서는 합성 픽스처에 대해서만 판정합니다. `walk.world_writable`을 채우는 워크는 3단계에 오므로, 실제 1단계 스냅샷에서 U-25는 `MANUAL`("collect --deep을 실행하십시오")입니다. 1단계에서의 목적은 `each`와 관찰과 대상 단위 waiver의 계약을 확정하는 것입니다.

**2단계 — 두 배포판, 자동화 가능한 모든 항목.** 수집기를 완성합니다. sshd(`-G` → `-T` → 파싱 폴백. 사용한 방법을 기록. Match 페르소나. include 소스), 서비스(소켓 활성화, masked/static/indirect, 논리 이름), PAM(authselect / pam-auth-update / 수동 설정 탐지, 스택 확장, 소스를 갖춘 파생 pwquality와 faillock), 방화벽(백엔드 탐지, 원본 덤프, 신뢰도를 갖춘 최소한의 정규화 모델), 함수로서의 로깅(journald만 있는 호스트), 네트워크 sysctl(커널이 파라미터마다 `all`과 인터페이스별 값을 합성하는 방식을 반영합니다. `rp_filter`는 최댓값, `send_redirects`는 논리 OR, `accept_redirects`는 해당 인터페이스의 forwarding에 따라 달라집니다. `default`는 앞으로 생길 인터페이스를 위한 템플릿으로 수집하며 유효 값으로 접어 넣지 않고, IPv6 쌍도 함께 다룹니다), `/proc/sys` 트리 전체, MAC 상태(SELinux/AppArmor, 런타임 대 설정), NSS 원격 소스 탐지, inetd/xinetd, 배너, 시각 동기화, `snmpd.conf`(활성화된 버전, 기본값 여부·길이·출처 제한으로 편집한 커뮤니티), 캐시된 메타데이터로 보는 패치 위생, 계정 상태(해시 알고리즘, 빈 비밀번호), `env` 블록, ACL 항목. auto와 partial 58개 항목 전부를 픽스처와 함께 등록하고, deferred 9개 항목을 근거를 갖춘 manual로 등록합니다. CI 매트릭스(`ubuntu:22.04`, `ubuntu:24.04`, `rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`, 카나리아로 `debian:12`), GitHub 러너 VM에서의 `sudo muster collect`, 능력 매트릭스 테스트, 비 root 잡. 커버리지 표를 생성해 커밋합니다. 파서 오라클 테스트. 공개 이미지에서 뜬 예시 스냅샷. `snapshot extract`, `controls new`, `CONTRIBUTING.md`.

**3단계 — 같은 수집기로 얻는, 목록 너머의 고가치 점검.** 워크 자체와, 패키지가 선언한 권한과의 결합(`rpm -V` / `dpkg --verify`. 잡음은 걸러 내고 필터를 기록). 워크에서의 파일 capability와 ACL. 커널 자기 보호 sysctl과 세 소스를 보는 코어 덤프 정책. 부트 체인(grub.cfg 권한, 시큐어 부트 상태). 마운트 옵션, 분리된 파티션, 스왑 암호화, 빌트인 탐지를 포함한 모듈 블랙리스트. 감사 파이프라인 건전성(auditd 규칙 존재와 불변 설정, journald 영속화, 원격 전달, sudo 로깅, 파일 무결성 도구의 설치와 스케줄). 노출 교차 점검(소켓 → 프로세스 → 패키지 대 방화벽. 방화벽 신뢰도가 full일 때만). root와 동등한 경로(컨테이너 런타임 소켓과 그 그룹, `ld.so.preload`, root 유닛의 쓰기 가능한 `ExecStart`, root의 `PATH`). 휴면 계정. U-63의 권한 점검을 넘어서는 `sudoers`의 `NOPASSWD`/`ALL`. 삭제된 실행 파일로 도는 프로세스. `authorized_keys` 인벤토리. 위험도 순서, 백업, 검증 명령, 롤백을 갖춘 `fix --dry-run`. 튜닝과 프로파일. 불변식 테스트를 갖춘 `--anonymize`. `--max-age`. 컨트롤 YAML 뮤테이션 테스트. 파서 퍼징.

**4단계 — 공개 릴리스.** 서버 변화와 규칙 변화를 구분하는 스냅샷 diff. 스키마 검증을 갖춘 SARIF. 드리프트 확인을 갖춘 완전한 이중 언어 문서 한 쌍. 릴리스 무결성(8절). `--controls-dir`. `snapshot ls|rm|prune`과 타이머 유닛. 패키지의 설치/업그레이드/제거 계약(remove는 스냅샷을 남기고 경고하며, purge는 삭제합니다). DCO와, 벤치마크 본문을 복사했는지 묻는 PR 템플릿. README 포지셔닝 표와 데모. 커버리지 공백 탐지기 역할을 하는 Lynis 차분 비교(버전 고정, `lynis-report.dat` 파싱, 매핑 표, 이미지별 기준선).

### 10.3 이후 릴리스로 미룬 것

서비스별 설정 항목(메일, DNS, FTP 데몬 설정 — deferred 9개 항목), 다중 호스트 집계, 에이전트 없는 SSH 모드, 파일 무결성 기준선, 인증서 만료, OS 수명 종료 탐지, 클라우드 VM 항목, ISMS-P와 NIST 매핑(`references` 키는 예약해 두었습니다), 설정 파일, 커널 lockdown과 커맨드라인 점검, Ansible 출력, APT/YUM 저장소, Homebrew, Docker 이미지, macOS와 Windows용 check 전용 빌드.

### 10.4 하지 않을 것

CVE 매칭, 런타임 탐지, 컨테이너와 쿠버네티스 벤치마크, 외부 포트 스캔, 조치 적용, 단일 하드닝 점수, CIS Benchmark 본문 (D24).

## 11. 테스트

assay에서 얻은 두 교훈은 "헬퍼는 커버되는데 아무도 호출하지 않는다"와 "존재하지만 지켜지지 않는 가드"입니다. 아래의 모든 것은 그 교훈을 규율에서 CI로 옮깁니다.

**컨트롤 픽스처(핵심).** 모든 컨트롤은 `controls/testdata/<id>/{pass,fail,na}-*.json`을 갖습니다. 컨트롤이 읽는 키만 담은 부분 스냅샷이며, `muster snapshot extract`로 실제 스냅샷에서 잘라 내고, 각각 출처 헤더(이미지 다이제스트, 수집 날짜)나 `synthetic: true`를 답니다. 레지스트리 테스트가 모든 컨트롤을 훑어, `PASS` 픽스처, `FAIL` 픽스처, 선언된 `NOT_APPLICABLE`/`ERROR` 픽스처, 배포판별 픽스처 중 하나라도 없으면 CI를 실패시킵니다. 커버리지는 전체 컨트롤 대비 픽스처를 가진 컨트롤로 측정하고(기준: 100 %), 수집한 팩트 대비 사용한 팩트로도 측정합니다(보고용). Go 라인 커버리지는 측정하되 `internal/check`에만 기준을 겁니다.

**결과 불변식.** `FAIL`과 `WARN`은 값과 사유를 담습니다. `MANUAL`은 근거를 담습니다. 근거 없는 결과는 존재하지 않습니다. 상태 도출 표(6.5절)와 종료 코드 우선순위는 모든 픽스처에서 성립하며, 각 픽스처의 기대 종료 코드는 그 골든 파일의 일부입니다.

**계약 테스트(1단계).** `internal/check`는 `os/exec`도 `net`도 import하지 않습니다(`go list -deps`). `collect`는 레지스트리 밖의 경로를 읽거나 명령을 실행할 수 없습니다(파일과 exec 접근은 테스트가 대체하는 인터페이스 뒤에 있습니다). 읽기 프리미티브는 아무것도 흘리지 않고 병적인 트리에서도 결코 블록되지 않습니다. 심볼릭 링크 순환, 경로의 모든 위치에 놓인 `/etc/shadow`로 향하는 심볼릭 링크, FIFO, 크기 초과 파일, 개행이 든 이름, 만 개짜리 디렉터리가 대상입니다. 스냅샷 writer는 0600, 원자성, 덮어쓰기 거부를 지킵니다. 리플렉션 스키마 골든과 옛 스냅샷 코퍼스가 5.7절을 강제하며, 스냅샷을 뜬 뒤에 추가된 키가 `missing`으로 읽혀 `PASS`가 아니라 `ERROR`를 낳는다는 것도 여기에 포함됩니다.

**골든 출력과 결정성.** 테이블과 JSON 렌더러는 `-update` 골든 테스트를 갖습니다. 같은 입력에는 바이트 단위로 같은 출력. 변동 필드는 `run` 아래에만. 안정적인 정렬. 로케일과 TZ 독립성. 동아시아 폭, 40칸, `NO_COLOR`, 비 TTY 변형. SARIF는 4단계에서 2.1.0 스키마로 검증합니다.

**CI에서의 lint(1단계).** 6.8절에 더해, 첫 픽스처 커밋부터 `testdata/`에 대해 `gitleaks`를 돌립니다. 규칙은 개인키 블록, `$6$`/`$y$` 비밀번호 해시, `ssh-rsa AAAA` 키, 그리고 개인용이 아닌 이메일 도메인과 내부 호스트명 형태를 대상으로 합니다. 규칙 패턴 자체는 일반적이며, 어떤 조직의 이름이나 도메인도 커밋하지 않습니다.

**파서 오라클(2단계).** 정확성의 오라클은 Lynis가 아니라 데몬입니다. 파서는 컨테이너 CI에서 `sshd -T`/`-G`, `sysctl -a`, `systemctl show -p`, `getent passwd`와 값 하나하나를 대조하며, 시드 코퍼스는 CI 이미지의 실제 파일에서 가져옵니다.

**CI와 능력 매트릭스(2단계).** 이미지는 10.2절과 같습니다. `-race`, `gofmt`, `go vet`, `staticcheck`를 돌립니다. GitHub 러너는 systemd와 비밀번호 없는 sudo를 갖춘 진짜 VM이라, 거기서 `sudo muster collect`를 돌리면 로컬 VM 없이도 sysctl과 서비스 팩트를 얻습니다. 가장 중요한 테스트는 둘입니다. 하나는 환경별로 반드시 `unsupported`나 `denied`여야 하는 팩트를 고정하고, 그 팩트에 의존하는 컨트롤이 통과하면 실패시키는 능력 매트릭스입니다. 다른 하나는 읽을 수 없는 모든 팩트가 반드시 `ERROR`여야 하는 비 root 잡입니다. 컨테이너 잡은 많은 컨트롤이 통과할 때가 아니라, 보지 못한 모든 것이 사유와 함께 `ERROR`나 `NOT_APPLICABLE`일 때 성공합니다.

**3단계.** 컨트롤 YAML의 뮤테이션 테스트(연산자 뒤집기, 기대값 치환, 절 제거, 배포판 조건 제거. 문서화된 제외 목록과 함께 100 % 킬 레이트. gremlins는 custom 함수에만). 커밋된 시드 코퍼스를 갖춘 모든 파서의 네이티브 퍼징. 풀 리퀘스트에서는 파서당 30초, 야간에는 더 길게 돌립니다.

**4단계.** 커버리지 공백 탐지기로서의 Lynis 차분 비교. 버전을 고정하고, `lynis-report.dat`를 파싱하고, 매핑 표와 이미지별 기준선을 두어 새로운 불일치만 신호가 되게 합니다.

**작성 규칙(`CLAUDE.md`에 둡니다).** 헬퍼의 테스트보다 호출자를 구동하는 테스트를 먼저 씁니다. 새 호출 지점을 하나씩 지워 보고 스위트가 빨개지는지 확인합니다. 초록으로 남는다면 기능이 아니라 구현이 테스트된 것입니다. 호출이 사라졌을 때 달라지는 것을 단언합니다. 부분 문자열보다 구조적 단언을 씁니다.

**하지 않는 것.** BDD 프레임워크 없음, 전역 라인 커버리지 기준 없음, 워크 외의 벤치마크 없음.

## 12. 문서, 라이선스, 기여 위생

- **이중 언어, 영어가 정본.** 사용자를 향하는 모든 문서는 `X.md`와 `X.ko.md`로 함께 배포하고 같은 커밋에서 갱신합니다. 둘이 어긋나면 영어가 맞습니다. 구현 계획은 영어 전용이며 해당 슬라이스가 병합되면 삭제합니다. 식별자, 플래그, 경로는 양쪽 모두 영어로 둡니다. 컨트롤 문구는 언어별 필드를 갖습니다(`title_en`/`title_ko`, `description_en`/`description_ko`). KISA 용어는 한국어 형태를 유지하고 영어 설명을 덧붙입니다 (D22).
- **저작 표시 경계.** `ATTRIBUTION.md`는 가이드의 발행처, 판본, 발행일, 출처 URL, 그리고 KISA가 자기 사이트에 밝힌 저작권 고지를 기록하고, 이어서 3절의 경계를 기록합니다. 재수록하는 것은 항목 코드, 항목명, 분류, 중요도, 쪽 번호뿐이며 상호 참조 색인으로서만 그렇습니다. 컨트롤 제목, 설명, 근거는 독자적인 문구입니다. 가이드의 점검, 판단 기준, 조치 방법 본문은 리포지터리 어디에도 나타나지 않습니다. 가이드 자체는 포함하지 않습니다. CIS 참조는 벤치마크 이름, 버전, 권고 번호뿐입니다. muster는 CIS 준수를 판정하지 않습니다. README와 NOTICE 파일과 `ATTRIBUTION.md`는 서로 어긋날 수 없도록 이 경계를 같은 문구로 밝히며, README에는 "비공식이며, 제휴 관계가 없고, 공식 평가를 대체하지 않는다"는 고지를 담습니다 (D04).
- **KISA 항목이 아닌 점검.** 3단계는 CIS 계열 벤치마크도 다루는 점검(마운트 옵션, 모듈 블랙리스트, 커널 자기 보호, 감사 파이프라인 건전성)을 더합니다. 이 점검들은 1차 자료(커널 문서, man 페이지, 배포판 문서)를 근거로 muster 자체의 문구로 작성하고, 매핑을 독자적으로 도출한 경우가 아니면 CIS 권고 번호를 달지 않으며, 벤치마크 본문을 재수록하지 않습니다. 저작 표시 경계가 금지하는 것은 CIS의 본문과 구조를 복사하는 일이지, 커널에 관한 사실을 점검하는 일이 아닙니다.
- **라이선스와 신원.** Apache-2.0이고 `NOTICE`를 둡니다. 커밋은 개인 신원을 씁니다. 리포지터리의 로컬 git 설정이 이를 고정하고 `.mailmap`이 이를 문서화합니다. 픽스처는 공개 이미지에서만 뜹니다. 고용주나 고객 호스트의 스냅샷은 결코 커밋하지 않습니다 (D02).
- **결정 로그.** 이 문서의 13절이 결정 로그입니다. 컨트롤은 `decision: Dnn`으로 결정을 인용할 수 있습니다. 계약(팩트 스키마, 컨트롤 id, 종료 코드, waiver 키)은 결정 항목이 있어야만 바뀝니다.
- **기여.** 2단계부터 `CONTRIBUTING.md`가 컨트롤 추가를 `controls new` → 픽스처 → `controls lint` → `go test`로 설명합니다. 4단계부터 DCO 서명과, "벤치마크 본문을 복사하지 않았음" 체크박스가 있는 풀 리퀘스트 템플릿을 둡니다.
- **인수인계 노트의 정정.** 리포지터리 이전의 노트는 CIS 자료를 "읽는 것은 자유이고 재배포가 제한됨"이라고 적었습니다. 실제 사정은 3절의 두 출처에 관한 것입니다. 또 그 노트는 이 도구를 "KISA 가이드를 구현한다"고 적었습니다. 공개 문구는 muster가 가이드의 *구조와 번호 체계를 따르며* 제휴 관계가 없다고 말합니다. 그 노트는 2021년판을 전제했지만, 대신 2026년판을 따릅니다. 2026년판은 웹 항목을 유닉스 범위에서 들어냈습니다.

## 13. 결정 로그

각 항목은 무엇을 결정했는지, 왜 그랬는지, 되돌리려면 무엇을 치러야 하는지를 담습니다.

- **D01 — assay와 분리한다. 결정은 공유하고 코드는 공유하지 않는다.** assay는 취약점 스캐너로 남습니다. 모듈을 넘어 `internal/` 패키지를 공유하려면 두 프로젝트 모두 아직 원하지 않는 공개 API가 필요합니다. 되돌리기: 나중에 공용 카탈로거를 추출하는 일은 양쪽 도구의 계약을 건드리지 않고도 가능합니다.
- **D02 — 개인, 공개, Apache-2.0, 개인 신원.** 회사 코드도, 컨트롤 정의도, 호스트도 쓰지 않습니다. 고용주 서명이 붙은 커밋은 하나라도 이력에서 지울 수 없기 때문에, 리포지터리의 로컬 git 신원을 저자의 개인 GitHub 주소로 고정합니다.
- **D03 — 리눅스 전용. Ubuntu 22.04/24.04와 Rocky/Alma 9이 먼저.** 처음부터 두 계열을 다루면 어댑터 구조가 존재할 수밖에 없습니다. 되돌리기: 의도한 바 없습니다.
- **D04 — KISA 2026년판. 코드, 이름, 분류, 중요도는 색인으로 재수록. 가이드 본문 없음. CIS는 번호만.** 2026년판은 번호를 전부 바꾸고 웹 항목을 들어냈습니다. 2021년판을 따르면 낡은 번호 체계를 내놓게 됩니다. 비회원용 CIS Benchmark에 붙은 CC BY-NC-SA 라이선스와 CIS의 이용 약관이 함께, Apache-2.0 리포지터리가 그러지 않았다면 했을 일을 금지합니다. KISA 사이트는 모든 권리를 유보한다는 고지를 밝히고 있습니다. 색인은 평가서를 읽는 사람이 결과를 가이드와 연결하는 데 필요한 것만 재수록합니다. 판본 선택을 되돌리기: 쌉니다. id가 muster 고유이기 때문입니다 (D16).
- **D05 — 컨트롤은 데이터다.** 컨트롤은 스칼라 연산자 열두 개와 컬렉션 연산자 두 개를 갖는 YAML입니다. 그 어휘는 모든 것을 표현하기에는 일부러 작게 두었고, 넘치는 부분은 여전히 팩트만 읽는 이름 붙은 Go 함수로 갑니다. 되돌리기: 연산자를 추가하는 것은 호환됩니다. 제거하는 것은 컨트롤 형식의 파괴입니다.
- **D06 — collect/check 분리. check는 순수하다. check에 `command`는 없다.** 오프라인 재평가, 픽스처 테스트, 공급망 경계는 모두 `check`가 호스트에 닿지 않는다는 데 기댑니다. 인수인계 노트의 판정 타입 초안에는 `command`가 있었지만, root 명령을 실행하는 데이터 파일은 이름만 데이터 파일이므로 제거했습니다. 되돌리기: 모든 픽스처와 위협 모델을 깨뜨립니다.
- **D07 — 보지 못한 것은 보지 못한 것이며, 봉투로 강제한다.** 모든 팩트는 상태를 담습니다. `absent`, `denied`, `unsupported`, `timeout`, `error`, `truncated`, 그리고 읽는 쪽의 `missing`은 그것만으로 `PASS`를 만들 수 없습니다. 그러지 않으면 Go의 제로 값이 빠진 키를 통과하는 비교로 바꿔 버립니다. 되돌리기: 스키마 메이저 버전 상승.
- **D08 — 근거는 결과 안에, 소스 경로와 줄 번호를 가진 관찰로 담는다.** 로그 줄에 맡긴 것은 사실상 존재하지 않는 것입니다. 되돌리기: 출력 계약의 파괴.
- **D09 — 배포판 차이는 수집기에 산다. 제거된 메커니즘은 컨트롤 데이터다.** `check`는 배포판을 보지 못합니다. `mechanisms`가 컨트롤별로 대안의 순서를 정합니다. 되돌리기: 의도한 바 없습니다.
- **D10 — 런타임과 영속화된 값을 둘 다 수집한다.** 지금은 안전하지만 디스크에는 없는 설정, 또는 디스크에는 있지만 적용되지 않은 설정은 그 자체가 하나의 발견 사항입니다. 되돌리기: 스키마 메이저 버전 상승.
- **D11 — 종료 코드.** `check`: `ERROR`가 하나라도 있으면 2(`--allow-error`로 제외 가능), `FAIL`이 하나라도 있으면 1, 그 밖에는 0. `--fail-on`이 `WARN`/`MANUAL`을 올립니다. `collect`: 0 완전, 1 부분, 2 없음(`--require-complete`). 되돌리기: 남의 CI를 깨뜨립니다. 지금 고정합니다.
- **D12 — waiver는 집계되고 사유를 가지며 결코 조용하지 않다. 대상 수준의 키를 갖는다. `ERROR`에는 결코 적용하지 않는다.** 사유는 필수, 만료는 선택이며 해당일을 포함합니다. 키는 엄격하고, 요약에는 항상 나옵니다. 컨트롤 단위 또는 관찰 대상 단위로 키를 잡습니다. waiver가 읽지 못한 팩트를 깨끗한 실행으로 바꿀 수는 없습니다. 되돌리기: 의도한 바 없습니다.
- **D13 — 스냅샷의 기밀성과 수명 주기.** 비밀 값 대신 파생 속성, 0700 안의 0600, 표준 디렉터리, 원자적 쓰기, 잠금, 4단계의 보존 명령. 되돌리기: 새어 나간 스냅샷은 되돌릴 수 없으므로, 스냅샷이 하나라도 생기기 전에 고정합니다.
- **D14 — root로 안전하며, 테스트로 확인한다.** 명령 화이트리스트, 환경 초기화, 타임아웃, 심볼릭 링크를 결코 따라가지 않는 두 계층 읽기 프리미티브, 워크 경계, 스냅샷만 쓰기, 어떤 서브커맨드에도 네트워크 없음, 텔레메트리 없음, 업데이트 확인 없음. 되돌리기: 의도한 바 없습니다.
- **D15 — 컨트롤은 내장한다. 외부 컨트롤은 다이제스트와 함께 선택적으로.** 런타임의 신뢰 경계는 바이너리입니다. 기여는 풀 리퀘스트로 들어옵니다. `--controls-dir`은 4단계에 추가되며 어떤 계약도 바꾸지 않습니다.
- **D16 — muster 고유의 컨트롤 id. 컨트롤 세트는 바이너리와 별도로 버저닝한다.** KISA 번호는 판본별 참조입니다. 되돌리기: id 변경은 모든 waiver 파일을 깨뜨립니다. id는 릴리스되면 영구합니다.
- **D17 — 정수 `schema_version`. 높으면 거부하고, 낮으면 `missing`으로 읽는다.** 스냅샷이 담고 있지 않은 키는 그 키가 필요한 컨트롤에게 오류이며, 결코 조용한 부재가 아닙니다. 되돌리기: 스키마 메이저 버전 상승.
- **D18 — 상태의 의미, 필수 중요도, 파생 심각도, 단일 점수 없음.** `WARN`, `MANUAL`, `WAIVED`, `NOT_APPLICABLE`은 고정된 의미와 고정된 평가 순서를 갖습니다. KISA 중요도는 컨트롤의 필수 필드이며 심각도가 여기서 파생됩니다. 요약은 세 부분입니다. 되돌리기: 출력 계약의 파괴.
- **D19 — 적용 여부는 컨트롤이 선언한다.** `applies_when`, `absent_means`, 환경 팩트를 씁니다. 알 수 없는 배포판은 가정하지 않고 `unknown`입니다. 되돌리기: 호환되는 추가만 가능합니다.
- **D20 — 결정적 출력.** 같은 입력에는 바이트 단위로 같은 JSON. 변동 값은 `run` 아래에만. 되돌리기: 스냅샷 diff를 깨뜨립니다.
- **D21 — 테스트의 모양.** 컨트롤별 픽스처는 필수입니다. 불변식과 계약 테스트는 1단계부터 CI에 있습니다. 파서 오라클은 데몬입니다. Lynis는 커버리지 공백 탐지기입니다. 되돌리기: 의도한 바 없습니다.
- **D22 — 이중 언어 문서, 영어가 정본.** 같은 커밋 규칙. 계획은 영어 전용이며 병합 후 삭제. 컨트롤 문구는 언어별로.
- **D23 — v1 아티팩트는 리눅스. check 쪽은 어디서나 컴파일된다.** 빌드 태그가 `collect`를 리눅스 전용으로 묶어 두므로, 워크스테이션용 빌드는 리팩터링이 아니라 패키징 결정입니다.
- **D24 — 범위의 경계.** 팩트의 종류에 따른 분류, 미룬 목록, 하지 않을 목록. 2026년판에서 웹 항목은 더 이상 유닉스의 관심사가 아닙니다.
- **D25 — 비 root는 일급 경로다.** `denied` 팩트, 권한을 명시한 `ERROR`, CI를 위한 `--require-root`. `check`는 root가 결코 필요 없습니다.
- **D26 — 권한 팩트는 ACL, capability, 속성을 포함한다.** `st_mode`만으로는 조용히 틀린 답이 나옵니다.
- **D27 — 패치 위생은 캐시된 패키지 메타데이터만 쓴다.** `collect`는 패키지 메타데이터를 갱신하지 않고 패키지 매니저 잠금을 쥐지도 않습니다. 오래된 캐시는 그 나이와 함께 `WARN`입니다.
- **D28 — Go, 최소 의존성, CLI 프레임워크 없음, 정적 바이너리 하나.** assay와 같은 선택이고 이유도 같습니다. 망 분리된 호스트에 복사할 파일 하나, 런타임 없음, 그리고 감사할 수 있을 만큼 짧은 의존성 목록입니다. 되돌리기: 의도한 바 없습니다.

## 14. 열린 쟁점

- U-17의 매핑(2021년판 U-14에서의 분할인지 신설인지)은 `docs/reference/kisa/kisa_mapping.json`에 불확실하다고 기록했습니다. 컨트롤 자체에는 영향이 없고 2021년 참조에만 영향을 줍니다.
- README용 예시 스냅샷을 GitHub 러너 VM에서 뜰지 CI 컨테이너에서 뜰지는 2단계의 선택입니다. 어느 쪽이든 출처 정보를 담습니다.
- 첫 실행에서 `--deep` 없이 활성화할 수집기 집합은 CI 이미지에서 측정한 실행 시간에 맞춰 2단계에서 조정합니다. 7.1절의 예산 기본값은 출발점입니다.

## 부록 A — KISA 2026 유닉스 항목과 v1 분류

범례: auto — 팩트로 판정. partial — 근거는 자동이고 판단은 사람(위반 시 `WARN`). deferred — 데몬 설정 파서가 v1에 없어 근거와 함께 `manual`로 등록. 항목 코드와 항목명은 상호 참조 색인으로서 가이드에서 재수록한 것이며(3절), muster 자체의 제목과 설명은 컨트롤 안에 있습니다.

| ID | 항목명 (KISA) | 중요도 | v1 |
|---|---|---|---|
| U-01 | root 계정 원격 접속 제한 | 상 | auto |
| U-02 | 비밀번호 관리정책 설정 | 상 | auto |
| U-03 | 계정 잠금 임계값 설정 | 상 | auto |
| U-04 | 비밀번호 파일 보호 | 상 | auto |
| U-05 | root 이외의 UID가 '0' 금지 | 상 | auto |
| U-06 | 사용자 계정 su 기능 제한 | 상 | auto |
| U-07 | 불필요한 계정 제거 | 하 | partial |
| U-08 | 관리자 그룹에 최소한의 계정 포함 | 중 | partial |
| U-09 | 계정이 존재하지 않는 GID 금지 | 하 | auto |
| U-10 | 동일한 UID 금지 | 중 | auto |
| U-11 | 사용자 Shell 점검 | 하 | auto |
| U-12 | 세션 종료 시간 설정 | 하 | auto |
| U-13 | 안전한 비밀번호 암호화 알고리즘 사용 | 중 | auto |
| U-14 | root 홈, 패스 디렉터리 권한 및 패스 설정 | 상 | auto |
| U-15 | 파일 및 디렉터리 소유자 설정 | 상 | auto (walk) |
| U-16 | /etc/passwd 파일 소유자 및 권한 설정 | 상 | auto |
| U-17 | 시스템 시작 스크립트 권한 설정 | 상 | auto |
| U-18 | /etc/shadow 파일 소유자 및 권한 설정 | 상 | auto |
| U-19 | /etc/hosts 파일 소유자 및 권한 설정 | 상 | auto |
| U-20 | /etc/(x)inetd.conf 파일 소유자 및 권한 설정 | 상 | auto |
| U-21 | /etc/(r)syslog.conf 파일 소유자 및 권한 설정 | 상 | auto |
| U-22 | /etc/services 파일 소유자 및 권한 설정 | 상 | auto |
| U-23 | SUID, SGID, Sticky bit 설정 파일 점검 | 상 | partial (walk) |
| U-24 | 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 | 상 | auto |
| U-25 | world writable 파일 점검 | 상 | partial (walk) |
| U-26 | /dev에 존재하지 않는 device 파일 점검 | 상 | auto |
| U-27 | $HOME/.rhosts, hosts.equiv 사용 금지 | 상 | auto |
| U-28 | 접속 IP 및 포트 제한 | 상 | auto (mechanisms. 방화벽 신뢰도가 partial이면 `MANUAL`) |
| U-29 | hosts.lpd 파일 소유자 및 권한 설정 | 하 | auto |
| U-30 | UMASK 설정 관리 | 중 | auto |
| U-31 | 홈 디렉토리 소유자 및 권한 설정 | 중 | auto |
| U-32 | 홈 디렉토리로 지정한 디렉토리의 존재 관리 | 중 | auto |
| U-33 | 숨겨진 파일 및 디렉토리 검색 및 제거 | 하 | partial (walk) |
| U-34 | Finger 서비스 비활성화 | 상 | auto |
| U-35 | 공유 서비스에 대한 익명 접근 제한 설정 | 상 | deferred |
| U-36 | r 계열 서비스 비활성화 | 상 | auto |
| U-37 | crontab 설정파일 권한 설정 미흡 | 상 | auto |
| U-38 | DoS 공격에 취약한 서비스 비활성화 | 상 | auto |
| U-39 | 불필요한 NFS 서비스 비활성화 | 상 | auto |
| U-40 | NFS 접근 통제 | 상 | auto |
| U-41 | 불필요한 automountd 제거 | 상 | auto |
| U-42 | 불필요한 RPC 서비스 비활성화 | 상 | auto |
| U-43 | NIS, NIS+ 점검 | 상 | auto |
| U-44 | tftp, talk 서비스 비활성화 | 상 | auto |
| U-45 | 메일 서비스 버전 점검 | 상 | deferred |
| U-46 | 일반 사용자의 메일 서비스 실행 방지 | 상 | deferred |
| U-47 | 스팸 메일 릴레이 제한 | 상 | deferred |
| U-48 | expn, vrfy 명령어 제한 | 중 | deferred |
| U-49 | DNS 보안 버전 패치 | 상 | deferred |
| U-50 | DNS Zone Transfer 설정 | 상 | deferred |
| U-51 | DNS 서비스의 취약한 동적 업데이트 설정 금지 | 중 | deferred |
| U-52 | Telnet 서비스 비활성화 | 중 | auto |
| U-53 | FTP 서비스 정보 노출 제한 | 하 | deferred |
| U-54 | 암호화되지 않는 FTP 서비스 비활성화 | 중 | auto |
| U-55 | FTP 계정 Shell 제한 | 중 | auto |
| U-56 | FTP 서비스 접근 제어 설정 | 하 | auto |
| U-57 | Ftpusers 파일 설정 | 중 | auto |
| U-58 | 불필요한 SNMP 서비스 구동 점검 | 중 | auto |
| U-59 | 안전한 SNMP 버전 사용 | 상 | auto |
| U-60 | SNMP Community String 복잡성 설정 | 중 | auto |
| U-61 | SNMP Access Control 설정 | 상 | auto |
| U-62 | 로그인 시 경고 메시지 설정 | 하 | partial |
| U-63 | sudo 명령어 접근 관리 | 중 | auto |
| U-64 | 주기적 보안 패치 및 벤더 권고사항 적용 | 상 | partial |
| U-65 | NTP 및 시각 동기화 설정 | 중 | auto |
| U-66 | 정책에 따른 시스템 로깅 설정 | 중 | auto |
| U-67 | 로그 디렉터리 소유자 및 권한 설정 | 중 | auto |

합계: auto 51, partial 7, deferred 9.
