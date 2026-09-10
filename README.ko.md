# muster

*[English](README.md) · 한국어*

**이 리눅스 서버는 점호를 통과하는가?** `muster`는 호스트의 사실(facts)을 root로
수집한 뒤, 그 스냅샷만으로 — 호스트 없이, 오프라인으로 — KISA 주요정보통신기반시설
기술적 취약점 분석·평가 방법 상세가이드의 유닉스 서버 항목(U-xx)에 대고 평가합니다.
매핑이 있는 항목에는 CIS 벤치마크·DISA STIG·NIST SP 800-53 번호를 참조로 답니다.

국내 보안 실무에서 이런 점검을 CCE 점검(CVE와 대비되는 설정 취약점 점검)이라고
부릅니다. muster는 리눅스 서버 자산군을 위한 CCE 점검 도구입니다. KISA 가이드가
1차 기준이고, 글로벌 벤치마크(CIS Benchmarks, DISA STIG, NIST SP 800-53)는
참조로 붙이며 이후에는 선택 가능한 프로파일로 제공합니다.

> **상태: 2단계 완료 (2026년 9월).** 1단계 — 뼈대: `collect`, `check`,
> waiver, 종료 코드, 끝까지 흐르는 컨트롤 여덟 개 — 와 2단계 — 자동 판정 가능한
> KISA 항목 전체 — 가 병합되었습니다: DISA STIG·NIST SP 800-53 참조를 갖춘 기반
> 작업, 계정, PAM 스택, 완성된 sshd 수집기와 로그인 배너, 홈 디렉터리와 셸 환경,
> 시스템 파일·시작 스크립트·cron 권한, 서비스와 슈퍼 서버, 방화벽, 로깅과 시간
> 동기화, NFS·SNMP·패치 위생, FTP·메일·DNS, 그리고 마무리 커버리지·참조 게이트.
> 67개 중 64개 항목이 등재되어 있고, 심층 파일시스템 워크가 필요한 3개(U-15,
> U-23, U-33)는 3단계로 유예되었으며, U-25(world-writable 파일)는 등재되어 있으나
> 같은 워크가 들어오기 전까지 `MANUAL`로 읽힙니다. 어떤 항목을 어떤 컨트롤이 어떤
> 자동화 등급으로 판정하는지, 컨트롤이 읽는 팩트 키가 무엇인지는
> [커버리지 표](docs/reference/coverage.md)로 생성되어 CI가 검사합니다. CI는 또한
> 수집기를 VM에서 root로, 일반 사용자로, Ubuntu 22.04/24.04·Rocky/Alma 9 컨테이너
> 안에서(Debian 12는 실패해도 CI를 막지 않는 카나리로 함께), 네트워크 없는 읽기 전용
> 컨테이너에서 돌리고, root 없이는 `denied`·systemd 없이는 `unsupported`여야 하는
> 팩트의 [capability matrix](docs/reference/capability-matrix.json)에 대조합니다.
> 아키텍처, 계약, 릴리스 범위는
> [설계 스펙](docs/superpowers/specs/2026-09-02-muster-design.ko.md)에 정리되어
> 있고, 판정을 바꾸는 변경은 [CHANGELOG.md](CHANGELOG.md)에 기록합니다. 아래의
> 3·4단계 항목은 계획이지 약속이 아닙니다.

> **공식 도구가 아닙니다.** muster는 비공식 개인 프로젝트입니다. KISA나 Center for
> Internet Security의 승인·인증과 무관하며, CIS 벤치마크 본문을 포함하지 않고(권고
> 번호만 참조), CIS 준수 여부를 판정하지 않으며, 공식 취약점 분석·평가를 대체하지
> 않습니다.

## 하는 일

```
sudo muster collect --out host.json      # 호스트에서 root로: 사실 스냅샷
muster check --facts host.json           # 어디서든, root 없이: 표 + 종료 코드
muster check --facts host.json --format json
muster controls lint --references docs/reference   # 컨트롤 세트 자체의 게이트
```

- **`collect`**는 호스트에서 실행되어 JSON 스냅샷 하나를 씁니다. OS 릴리스와 환경,
  패키지 목록, `sshd` 유효 설정(`Match` 페르소나 포함), PAM 스택과 거기서 파생한
  정책, 서비스·소켓·슈퍼 서버 상태, 리스닝 소켓, 방화벽 백엔드와 규칙, 계정과
  패스워드 정책, 홈 디렉터리와 셸 환경, 로그인 배너,
  시스템 파일·시작 스크립트·cron 항목·`sudoers`의
  권한, 로깅과 시간 동기화, NFS export, SNMP(커뮤니티는 문자열이 아니라 형태만),
  패치 상태, FTP·메일·DNS 설정. 그 외에는 아무것도 쓰지 않고, 어떤 서비스도
  재시작하지 않으며, 네트워크로 나가지 않습니다.
- **`check`**는 스냅샷과 컨트롤 세트를 읽어 항목마다 `PASS`, `FAIL`, `WARN`,
  `MANUAL`, `NOT_APPLICABLE`, `ERROR`, `WAIVED` 중 하나를 내고, 항상 판정 근거(값,
  그 값이 나온 파일과 줄, 이유)를 함께 싣습니다. 호스트가 필요 없습니다.
- **컨트롤은 데이터입니다.** KISA 항목 하나가 YAML 컨트롤 하나이고 판정 어휘는
  작습니다. 그 어휘로 표현할 수 없는 항목은 이름 붙인 Go 함수를 부를 수 있지만,
  현재 그런 항목은 없습니다. 배포판 편차는 수집기가 흡수하므로 컨트롤은 정규화된
  사실 위에 한 번만 씁니다.
- **waiver**는 사유 필수, 만료 선택인 파일로 관리합니다. waive된 결과는 세어지고
  표시되며 조용히 사라지지 않고, waiver는 `ERROR`를 덮지 못합니다.
- **종료 코드**는 계약입니다. `2`(실행 불가 또는 신뢰 불가) > `1`(findings 있음)
  > `0`(clean). `MANUAL` 항목은 따로 요청하지 않는 한 실행을 실패시키지 않습니다.

## 원칙

- **못 본 것은 못 봤다고 말합니다.** 읽지 못한 사실은 `ERROR`이지 조용한 `PASS`가
  아닙니다. 절반의 확인도 `PASS`가 아닙니다. 인터뷰가 필요한 항목은 수집된 근거를
  붙여 `MANUAL`로 냅니다. muster가 읽지 않기로 한 호스트 구성(통상적인 루트 밖의 홈
  디렉터리, 파서 모델 밖의 설정 구문)도 추측하지 않고, 사유에 그 이름을 남겨
  `MANUAL`로 냅니다.
- **근거는 결과 안에 있습니다.** 판정 이유가 로그 줄에만 있다면 그것은 사실상 없는
  것입니다.
- **런타임과 영속 설정을 둘 다 봅니다.** 커널 룰셋은 살아 있지만 디스크 설정으로는
  다시 살아나지 않을 방화벽, `login.defs`와 실제 PAM 스택이 어긋난 패스워드 정책,
  `enabled`이지만 실제로는 소켓 활성화로 뜨는 서비스는 있는 그대로 보고하고 하나의
  boolean으로 접지 않습니다.
- **root로 돌려도 안전하게.** 셸을 거치지 않고, 절대 경로와 타임아웃이 고정된 명령
  화이트리스트만 실행하며, 심볼릭 링크를 따라가지 않고, 모든 파일 읽기에 크기 상한을
  두고, 스냅샷에는 비밀 대신 파생 속성(해시 알고리즘, machine-id 해시, SNMP 커뮤니티의
  길이와 기본값 여부)만 저장합니다.
  `muster collect --list-actions`가 수집기가 읽고 실행하는 것을 정확히 출력합니다.

## 일부러 하지 않는 일

- **CVE 매칭.** 스냅샷에 설치 패키지 목록을 실어 [assay](https://github.com/kun9497/assay)
  같은 취약점 스캐너에 SBOM으로 넘길 수 있게 하되, muster 자신은 권고 데이터를
  매칭하지 않습니다.
- **런타임 탐지**(eBPF, 프로세스 감시) — Tetragon 같은 도구가 있습니다.
- **컨테이너·Kubernetes 벤치마크** — kube-bench가 있습니다.
- **외부 포트 스캔.** 네트워크 점검은 호스트 내부 관점만입니다: 리스닝 소켓, 방화벽
  규칙, 불필요한 서비스.
- **조치 실행.** 판정하는 모든 컨트롤이 조치 문구·위험 등급·롤백을 담고 있어 이후
  검토용 스크립트를 생성할 수 있지만, muster가 실행하지는 않습니다.
- **다른 자산군.** Windows, DBMS, 웹/WAS, 네트워크·보안 장비는 KISA 가이드에서
  별도 절입니다. muster의 컨트롤·리포트 계약을 공유하는 형제 도구로 만들지, 이
  코드베이스에는 넣지 않습니다.

## 대상

영구적으로 Linux만. 첫 릴리스는 **Ubuntu LTS(22.04, 24.04)**와 **Rocky /
AlmaLinux 9**를 대상으로 합니다. 처음부터 둘 다 지원해야 배포판 편차 처리 구조가
나중에 덧붙는 것이 아니라 처음부터 존재하게 됩니다.

## 기준

컨트롤 세트는 KISA 상세가이드(주요정보통신기반시설 기술적 취약점 분석·평가 방법
상세가이드) **2026년판**(2025-12-24 게시) 유닉스 서버 절의 구조와 번호 체계를
따릅니다: 67개 항목, U-01~U-67. 모든 컨트롤은 판본별 KISA 항목 번호를 가지며,
2021년판에 해당 항목이 있던 경우 그 번호도 함께 담으므로 예전 판본 기준의 평가
결과와도 대응시킬 수 있습니다.

이 저장소가 가이드에서 옮겨 오는 것은 항목 코드, 항목명, 분류, 중요도, 쪽 번호뿐이며
(`docs/reference/kisa/`), 결과와 가이드를 대응시키기 위한 참조 색인으로만 씁니다.
컨트롤의 제목·설명·근거는 muster가 자체 작성한 문장이고, 가이드의 점검 내용·판단
기준·조치 방법 문구는 포함하지 않으며, 가이드 문서 자체도 포함하지 않습니다. CIS
벤치마크 참조는 벤치마크 이름·버전·권고 번호뿐이고 muster는 CIS 준수 여부를
판정하지 않습니다. [ATTRIBUTION.md](ATTRIBUTION.md)를 보세요.

글로벌 벤치마크는 두 번째 규칙집이 아니라 교차 참조입니다. 64개 컨트롤 중 25개가
DISA STIG 규칙 id, 20개가 NIST SP 800-53 통제 id, 13개가 CIS 벤치마크 권고 번호를
답니다. 매핑은 아직 채워 가는 중이며, 벤치마크가 같은 기준을 판정하는 곳에만 붙입니다.
`muster controls lint`는 커밋된 색인에 없는 STIG·NIST id를 거부하고, 모든 KISA
항목 번호를 67개 항목 인벤토리와 교차 검사하므로 항목이 빠지거나 두 번 등재될 수
없습니다. 3단계부터는 같은 수집기 위에서 `cis-<배포판>-l1` 프로파일이 컨트롤과
파라미터를 고를 수 있습니다. muster는 번호만 기록하고 벤치마크 본문은 담지 않으며,
CIS나 STIG 준수 여부를 인증하지 않습니다. 컨트롤이 인용할 수 있는 STIG·NIST
식별자는 DISA의 공개 파일로부터 `tools/refindex`가 `docs/reference/stig/`에
생성합니다. 이 저장소가 옮겨 오는 것은 STIG와 CCI 식별자, 심각도, 제목뿐이며,
점검 내용·판단 기준·조치 방법 문구는 담지 않습니다.
[ATTRIBUTION.md](ATTRIBUTION.md)를 보세요.

## 로드맵

1. **뼈대.** `collect`와 `check`, facts 스키마, 표·JSON 출력, 종료 코드, waiver,
   그리고 끝까지 흐르는 컨트롤 여덟 개.
2. **두 배포판, 자동 판정 가능한 KISA 항목 전체.** Ubuntu와 Rocky 수집기. 67개 중 64개를
   자동 판정하거나 자동 근거를 붙임(auto 55, partial 5, manual 4 — manual은 근거를 함께
   제시). 나머지 3개 — 파일·디렉터리 소유자(U-15), SUID/SGID/sticky 파일(U-23), 숨겨진
   파일(U-33) — 는 stage 3의 심층 파일시스템 워크가 필요하며 `docs/reference/coverage.md`에
   유예 항목으로 표시. 매핑이 있는 모든 컨트롤에 DISA STIG와 NIST SP 800-53 참조 번호를
   추가하고, `controls lint`가 모든 KISA 참조를 67개 항목 인벤토리와 교차 검사.
3. **심층 파일시스템 워크, 목록 밖의 고가치 점검, 프로파일**, 같은 수집기에서:
   유예된 3개 항목(파일 소유자, SUID/SGID/sticky 파일, 숨겨진 파일)을 등재하는 워크,
   패키지 무결성, world-writable 파일, 파일 capability와 ACL, cron·타이머 인벤토리,
   `authorized_keys` 인벤토리, 삭제된 바이너리로 도는 프로세스, 커널 자기보호 sysctl,
   마운트 옵션, 감사 파이프라인 상태, 패치 위생, 리스닝 소켓과 방화벽 규칙의 노출면
   교차 판정. 프로파일이 컨트롤과 파라미터를 고릅니다. `kisa-unix-2026`이 기본이고,
   `cis-<배포판>-l1` 프로파일이 대상 배포판의 CIS Level 1 서버 권고를
   `references.cis`를 1차 참조로 삼아 다룹니다.
4. **공개 릴리스.** 스냅샷 diff, SARIF, 한/영 문서, SBOM이 붙은 서명·재현 빌드,
   deb/rpm 패키지, Lynis와의 차분 비교.

이후 릴리스로 미룬 것: 다중 호스트 집계, 에이전트리스 SSH 모드, ISMS-P 매핑, 파일
무결성 베이스라인, 인증서 만료, OS EOL 감지, 클라우드 VM 항목.

## 문서와 기여

- [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md) — 컨트롤 추가(`muster controls new`가
  뼈대를 만들고 `muster snapshot extract`가 스냅샷에서 픽스처를 잘라 냄), 팩트 추가,
  수집기 규약, 테스트 원칙, 절대 커밋하지 말아야 할 것.
- [CHANGELOG.md](CHANGELOG.md) — 컨트롤 세트의 버전과 판정을 바꾸는 모든 변경.
- [docs/reference/coverage.md](docs/reference/coverage.md) — 어떤 KISA 항목을 어떤
  컨트롤이 판정하는지, 컨트롤이 읽는 팩트 키는 무엇인지. 생성 문서이며 CI가 검사.
- [docs/reference/kisa/](docs/reference/kisa/) — 항목 인벤토리와 유예 항목,
  [docs/reference/stig/](docs/reference/stig/) — 컨트롤이 인용할 수 있는 STIG·NIST
  식별자.
- [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md),
  [ATTRIBUTION.md](ATTRIBUTION.md).

## assay와의 관계

[assay](https://github.com/kun9497/assay)는 취약점 스캐너이고 muster는 설정
점검기입니다. 둘은 결정(결과 안의 근거, 종료 코드 계약, waiver 규칙, 배포판별 로직
분리)을 공유하지 코드를 공유하지 않습니다.

## 라이선스

Apache License 2.0. [LICENSE](LICENSE)와 [NOTICE](NOTICE)를 보세요.
