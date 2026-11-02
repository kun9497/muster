# 4단계 — 공개 릴리스

영문 원본: `2026-11-02-stage4-public-release-design.md`. 기준 설계: `2026-09-02-muster-design.md` (§5.9 스냅샷
생애주기, §7 종료 코드, §8 `:428` 릴리스 무결성, §9 출력, §10.2 4단계 문단, §10.3 유보 목록, D13, D16, D28). 이
설계의 판정은 RL 목록이다(한 글자 접두어는 이전 단계와 충돌한다). 이 문서를 낳은 브레인스토밍은 §1.1에 요약했고,
브레인스토밍이 저자에게 맡긴 선택은 나오는 자리마다 "저자의 선택"으로 표시하고 §10에 모았다.

**날짜** 2026-11-02 · **상태** 2026-11-02 사용자 승인; 4A 실행됨(그 판정 RA-1..RA-44는 플랜의 Execution notes에 있고, 문장을 고치는 것은 여기에 반영됨).

## 1. 범위와 의도

4단계는 muster를 "빌드하는 저장소"에서 "설치하는 릴리스"로 바꾼다. 이 단계가 섬기는 사람은 회사 보안팀의 리눅스
운영자다. 그 사람은 GitHub Releases 페이지를 열어 자기 배포판의 패키지를 받고, 검증하고, 설치하고, `sudo muster
collect` 한 번과 `muster check` 한 번을 돌린 뒤, 한 달 뒤에 그 서버에서 무엇이 바뀌었는지 알고 싶어 한다. 이 단계의
어느 것도 다른 사람을 위한 것이 아니다. 출력을 소비하는 중앙 도구는 없고, 외부 기여자를 아직 모으지 않는다.

4단계는 세 조각이고, 조각마다 플랜 하나, 순서는 다음과 같다.

- **4A — 릴리스 파이프라인과 패키지** (§4): 태그 푸시 한 번이 리눅스 바이너리, `.deb`·`.rpm` 패키지, checksums,
  SBOM을 빌드·스캔·서명·증명·게시한다. 패키지는 바이너리와 문서를 설치하고 아무것도 시작하지 않는다. `snapshot
  ls|rm|prune`이 D13이 약속한 생애주기를 닫는다.
- **4B — `snapshot diff`** (§5): 그 호스트의 가장 새 스냅샷 두 개 또는 지정한 두 파일을 설치된 컨트롤 세트로 평가해서
  바뀐 판정을 보여 주고, 요청하면 사실 변화도 보여 준다.
- **4C — 운영자 문서와 릴리스 게이트** (§6): 운영자용으로 다시 쓴 README 쌍(설치보다 검증이 먼저), 위협 모델의
  공급망 절, 영문·한글 쌍의 문서 drift 검사, 재현성 검사, `RELEASING.md`.

첫 공개 릴리스는 `v0.1.0`이다. 릴리스가 모으려는 운영자 피드백을 읽기 전까지 바이너리는 `0.x`에 머문다(RL-1). 컨트롤
세트는 자기 버전(`controls/VERSION`, D16)을 따로 유지한다.

### 1.1 브레인스토밍에서 정한 것

사용자의 결정이며, 사용자가 말한 대로 옮긴 곳은 그대로다.

- 운영자는 GitHub Releases에서 받아 패키지를 설치한다, "assay처럼". 다만 요구 사항은 설계 자체의 릴리스 무결성
  목록(§8 `:428`)이고, assay의 파이프라인은 그 목록을 충족하는 곳에서 출발점이다(§4.1).
- `.deb`와 `.rpm`은 tar.gz와 함께 첫 릴리스에 들어간다.
- 서명은 keyless(Sigstore / OIDC)다. assay처럼 프로젝트 키를 쓰지 않는다.
- `apt install` 뒤에는 "바이너리만 설치되고 아무것도 자동으로 돌지 않아야" 한다.
- 한 달 뒤 운영자는 "지난 결과와 비교해서 뭐가 바뀌었는지"를 원한다. 기본은 바뀐 판정, 사실 변화는 옵션. 직전 스냅샷은
  알아서 집고, 파일 지정도 된다.
- 결과는 서버에 남는 걸로 끝이고 중앙 도구는 없다. SARIF는 미룬다(§9).
- `--controls-dir`은 저자의 권고로 미룬다(§9).
- 릴리스는 운영자가 받아 쓰게 하는 것이 목적이다. 기여자용 항목(DCO, PR 템플릿, Lynis 차분)은 미룬다.
- 첫 버전은 `v0.x`다.

## 2. 목표, 비목표, 반목표

**목표.** 운영자는 (1) 받은 파일을 root로 실행하기 전에 저장소와 태그에 대해 검증할 수 있다. 서로 독립인 두 방법이
있고 명령은 README에서 그대로 복사한다. (2) Ubuntu 22.04/24.04, Debian 12, RHEL 9 계열에는 패키지로, 그 밖에는
tar.gz로 설치할 수 있고, 호스트에서 아무것도 시작되거나 바뀌지 않는다. (3) 태그에서 바이너리를 다시 빌드하면 같은
바이트가 나온다. (4) 같은 호스트의 스냅샷 두 개 사이에서 어떤 판정이 바뀌었는지, 그 뒤의 사실과 함께 볼 수 있다.
(5) muster가 보관하는 스냅샷을 나열하고 정리할 수 있다. (6) 운영자 문서 — README와 `RELEASING.md` 쌍 — 를 영문이나
한글로 읽어도 같은 사실을 얻는다(RL-38: `THREAT_MODEL.md`, `SECURITY.md`, `ATTRIBUTION.md`, `CHANGELOG.md`는 오늘
CONTRIBUTING이 말하듯 영문 전용으로 남는다; `README.ko.md`가 검증이 증명하는 것과 증명하지 않는 것을 한글로 요약한다).

**비목표.** 설치 스크립트 없음, `curl | sh` 없음, 자동 업데이트 없음, 업데이트 확인 없음, 텔레메트리 없음. macOS나
Windows 빌드 없음(check 전용 빌드는 기준 설계 §10.3에 남는다). 결과를 어디로도 올리지 않는다. `collect`, `check`,
`fix`의 판정·사실·종료 코드·출력은 하나도 바뀌지 않는다. 예제 보고서를 움직이는 4A/4B/4C 변경은 결함이다(예제
게이트가 지킨다).

**반목표** — 모든 잡이 녹색이어도 다음이면 릴리스는 실패다.

1. **설치나 실행이 서버를 바꾼다.** 유닛을 켜거나, 사용자를 만들거나, 설정 파일을 쓰거나, 프로세스를 시작하는 패키지
   스크립트. 설정을 바꾸는 하위 명령. muster의 첫 약속(§8)은 `collect`가 파일 하나를 쓰고 그 밖에는 아무것도 쓰지
   않는다는 것이며, 패키지도 같은 약속을 지킨다.
2. **받은 파일을 검증할 수 없다**, 또는 README의 검증 명령이 게시된 릴리스에서 실패한다.
3. **같은 소스에서 다른 바이트가 나온다.** `scripts/reproduce.sh --ref v0.1.0 --version 0.1.0 <archive>`가 게시된 바이너리를 재현하지 못하면
   "재현 가능한 빌드"는 거짓 주장이고, 참이 될 때까지 README에서 뺀다.
4. **`snapshot diff`가 muster 업그레이드를 서버 변화로 보고한다.** 규칙이 움직였다는 이유로 운영자를 호스트 고치러
   보내서는 안 된다(§5.4).
5. **게시한 스냅샷이나 보고서에 비밀이 들어 있다.** redaction 정책(기준 설계 §5.6)과 익명화기(3D-3)를 태그 전에 릴리스
   아티팩트에서 다시 증명한다(§6.5).
6. **영문 문서와 한글 문서가 다른 말을 한다.** drift 검사(§6.3)가 릴리스 게이트다.

## 3. 제약

- CLAUDE.md "Rules that are contracts"의 전부: 종료 코드, 결정성, stdout에는 JSON만, 엄격한 YAML, KISA·CIS 본문
  금지, 공개 이미지에서 온 픽스처. 영문이 정본이고 `.ko.md` 쌍은 같은 커밋에 들어간다. 기준 설계 쌍은 줄 정렬을 유지한다.
- `internal/report`, `internal/check`, 새 `internal/diff`는 순수하다(`os`, `os/exec`, `net`, `syscall`, `time` 없음).
  `internal/profile`과 `internal/anonymize`처럼 테스트가 강제한다.
- 바이너리에는 표준 라이브러리와 기존 모듈 둘(`yaml.v3`, `x/sys`)만 들어간다(D28). 릴리스 도구(GoReleaser, cosign,
  syft, govulncheck, GoReleaser를 통한 nfpm)는 CI에서만 돌고 버전으로, GitHub Actions는 커밋 SHA로 고정한다.
- 커밋되는 파일에는 점으로 쓴 RFC1918이나 공인 IPv4 리터럴, `.corp/.internal/.intra/.lan/.local/.priv`로 끝나는 호스트
  이름을 절대 넣지 않는다(gitleaks가 PR 범위를 스캔한다).
- 이력 재작성 없음. 태그는 절대 옮기지 않는다(RL-6).
- 이 단계에서 랩 호스트는 읽기 전용이다. 패키지 설치는 CI 컨테이너와 러너 VM에서 증명하고 랩에서는 절대 하지 않는다.

## 4. 4A — 릴리스 파이프라인과 패키지

### 4.1 assay에서 오는 것과 오지 않는 것

assay의 `release.yml`과 `.goreleaser.yaml`(2026-11-02에 assay 030da65에서 읽음)이 출발점이다. 그대로 가져오는 것:
`v*` 태그 트리거; 커밋으로 고정한 GoReleaser v2; `CGO_ENABLED=0`, `-trimpath`, `-s -w`와 세 개의 `-X
main.version/commit/date` 변수(muster의 Makefile이 이미 같은 셋을 넣는다); 릴리스 때 `go mod tidy` 없음(릴리스는 CI가
테스트한 `go.sum`을 빌드한다); `go.mod`가 이름 붙인 Go 버전보다 낮은 빌드를 거부하는 툴체인 검사(assay v0.12.0은
`go-version: "1.26"`이 러너의 오래된 패치를 집어서 GO-2026-6809를 안고 나갔다); 바이너리마다 돌리는 고정 버전의
`govulncheck -mode=binary` post-build 훅 — 무엇이 게시되기 전에 릴리스를 멈춘다; `checksums.txt`; 게시 파일에 대한
`actions/attest-build-provenance`; 릴리스 잡이 실패하거나 회복하면 고정 이슈 하나를 열거나 닫는 잡.

바꾸는 것: 서명은 keyless(§4.5)다. assay는 같은 키가 데이터베이스 아티팩트에도 서명하기 때문에 투명성 로그 밖에서
프로젝트 키로 서명한다. 대상은 `linux/amd64`와 `linux/arm64`만(RL-2: `collect`는 리눅스 전용이고 다른 시스템의 check
전용 빌드는 유보). README의 설치 한 줄, `install.sh`, `install.ps1`, README 핀을 `main`에 커밋하는 단계는 가져오지
않는다 — 기준 설계가 `curl | sh`를 금지하고, 릴리스 잡은 `main`에 절대 푸시하지 않는다(RL-3).

더하는 것, assay에 둘 다 없기 때문에: SBOM(§4.4), `.deb`·`.rpm` 패키지(§4.6), 재현성 검사(§4.3), `CHANGELOG.md`에서
오는 릴리스 노트(§4.8), 생애주기 명령(§4.9).

### 4.2 빌드

- **RL-4 — 툴체인은 하나, `go.mod`에 이름이 있다.** `go.mod`는 `go 1.25`를 언어 버전으로 유지하고, 지원되는 Go 라인의 최신 패치를 이름 붙인 `toolchain goX.Y.Z` 줄이 생긴다(4A에서 go1.26.10; RA-17 — 1.25는 더 이상 수정을 받지 않으므로 "권고에 줄을 올린다"에는 아직 움직이는 라인이 필요하다; CI가 오늘 고정하는
  버전은 4A 전에 1.25.5였다). `release.yml`과 `ci.yml`은 `go-version-file: go.mod`로
  Go를 설치하고 `scripts/check-go-toolchain.sh`를 돌린다. CI에서는 이 줄이 하한이고(더 새 패치는 통과), 릴리스 잡에서는
  같아야 한다(`--exact`). 패치가 다르면 바이트가 달라져 §4.3이 실패하기 때문이다. 줄을 올리는 것은 보통 커밋이다.
  수정이 있는 stdlib 권고는 다음 태그 전에 줄을 올린다.
- **RL-5 — 빌드는 구성상 재현 가능하다.** GoReleaser의 빌드는 `mod_timestamp: '{{ .CommitTimestamp }}'`, `-X
  main.date={{ .CommitDate }}`(빌드 날짜가 아닌 커밋 날짜 — 따라서 `muster version`은 소스가 커밋된 때를 찍고,
  Makefile의 `DATE`는 `TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ`로 바뀐다 — `{{ .CommitDate }}`와 같은 유일한 표기이며, `%cI`는 커미터의 오프셋을 찍고 보통 `format:`은 그것을 가짜 `Z`와 함께 그린다(RA-1) — 그래서 `make build`와 일치한다), `-X main.version={{ .Version }}`(`v`
  없는 태그), `-X main.commit={{ .FullCommit }}`(Makefile의 짧은 해시가 전체 해시가 된다; `muster version`은 전처럼
  두 형태를 찍는다)를 설정한다. `-buildvcs=false`를 두어 바이너리가 이 변수들 외의 VCS 스탬프를 들지 않게 한다.
  아카이브와 패키지는 커밋 타임스탬프에서 `SOURCE_DATE_EPOCH`를 설정한다.
- 빌드: `id: muster`, `main: ./cmd/muster`, `goos: [linux]`, `goarch: [amd64, arm64]`. post 훅은
  `scripts/release-vulncheck.sh "{{ .Path }}"`를 돌린다(버전 고정 govulncheck; 툴체인이 아직 고칠 수 없는 권고는
  관리자가 툴체인을 올리거나 스크립트에 검토된 예외를 기록할 때까지 릴리스를 막는다 — 고정을 푸는 것으로는 절대 안 된다).
- `ci.yml`에는 모든 PR에서 소스 모드로 `govulncheck ./...`가 생긴다(같은 고정 버전). PR의 소스 모드와 릴리스의 바이너리
  모드가 두 겹이다. 어느 쪽도 다른 쪽을 대신하지 않는다.

### 4.3 재현성

`scripts/reproduce.sh --ref <tag> --version <X.Y.Z> [--arch amd64|arm64] <artefact>`(RA-22, RA-25: 아티팩트는 tar.gz, `.deb`, `.rpm` 또는 맨 바이너리; `--version`은 릴리스 문자열 그대로)는 임시 분리 워크트리에 ref를 체크아웃하고, `go.mod`가 이름 붙인 툴체인을 `GOTOOLCHAIN`으로 고르고, 그것이 `go.mod` 줄과 같은지 확인하고,
호스트 아키텍처(또는 주어진 `GOARCH`)로 §4.2의 정확한 플래그로 빌드하고, 바이너리의 sha256을 받은 아카이브나 패키지
안의 것과 나란히 찍고, 일치할 때만 0으로 끝난다. 같은 스크립트가 CI의 `release-dry-run` 잡(§4.7)에서 GoReleaser 자신의
스냅샷 빌드에 대해 돌아서, 재현성을 깨는 변경은 태그가 아니라 PR을 실패시킨다. README의 "Reproduce the build" 절은 이
스크립트의 사용법이고 그 이상이 아니다(RL-7: README의 주장은 스크립트가 증명하는 것과 정확히 같다).

### 4.4 릴리스의 아티팩트

태그 `vX.Y.Z`에 대해 GitHub Release는 다음을 들고, 그 밖에는 아무것도 들지 않는다.

| 파일 | 내용 |
|---|---|
| `muster_X.Y.Z_linux_<arch>.tar.gz` | `muster`, `LICENSE`, `NOTICE`, `ATTRIBUTION.md`, `README.md`, `README.ko.md`, `THREAT_MODEL.md`, `SECURITY.md`, `CHANGELOG.md`, `examples/systemd/` (§4.6) |
| `muster_X.Y.Z-1_<amd64|arm64>.deb`, `muster-X.Y.Z-1.<x86_64|aarch64>.rpm` (nfpm의 관례 이름, RA-19) | §4.6 |
| `muster_X.Y.Z_checksums.txt` | 위 모든 파일의 sha256 |
| `muster_X.Y.Z_checksums.txt.sigstore.json` | checksums 파일에 대한 keyless 서명 번들 (§4.5) |
| `muster_X.Y.Z_linux_<arch>.tar.gz.spdx.json`, `.deb`/`.rpm`마다 하나 | SBOM, SPDX JSON, 고정 버전 syft (RL-8) |
| 릴리스 노트 | 이 버전의 `CHANGELOG.md` 절 (§4.8) |

빌드 출처 증명(`actions/attest-build-provenance`)은 모든 아카이브와 패키지에 붙고 저장소의 attestation 저장소에
살며, 릴리스 파일로는 없다. `NOTICE`와 `ATTRIBUTION.md`는 모든 아카이브와 패키지에 들어간다. ComplianceAsCode에서
파생한 CIS 인덱스가 BSD-3-Clause이고 CIS 면책 문구가 사용자에게 닿아야 하기 때문이다(CB-13).

### 4.5 서명과 증명

- **RL-9 — keyless, Sigstore 번들.** 잡의 OIDC 토큰(`id-token: write`) 아래에서 `cosign sign-blob --new-bundle-format --bundle
  <checksums>.sigstore.json <checksums>`. cosign은 assay가 고정하는 대로 v2.4 라인으로 고정한다. 서명 신원은 태그
  시점의 워크플로다: `https://github.com/kun9497/muster/.github/workflows/release.yml@refs/tags/vX.Y.Z`, 발급자
  `https://token.actions.githubusercontent.com`. 항목은 공개 투명성 로그에 들어간다. 저장소가 공개라 로그는 Releases
  페이지가 말하지 않는 것을 말하지 않는다.
- **RL-10 — 증명은 SLSA Build L2이고, 그렇게 말한다.** `gh attestation verify <file> -R kun9497/muster`는
  GitHub 호스트 Actions가 이 저장소의 이 태그에서 파일을 빌드했음을 증명한다. README는 L2라고 말하고, 증명하지 않는
  것도 말한다: 태그의 소스가 안전하다는 것, 리뷰어가 그것을 읽었다는 것.
- 어느 한 방법만으로 충분하며 README가 그렇게 말한다. 둘 다 주는 것은 하나는 `gh`가, 다른 하나는 `cosign`이 필요하고
  망분리 호스트에는 둘 다 없을 수 있기 때문이다 — 그 호스트에는 README가 sha256 경로를 주고 가장 약하다고 이름
  붙인다(받은 것이 checksums 파일과 일치함만 증명하고, 그 파일의 신뢰는 서명이다).

### 4.6 패키지

- **RL-11 — 패키지는 바이너리와 문서를 설치하고 아무것도 시작하지 않는다.** GoReleaser를 통한 nfpm, 패키지 `muster`,
  amd64/arm64용 `.deb`와 x86_64/aarch64용 `.rpm`, 라이선스 Apache-2.0, 의존성 없음(정적 바이너리), `Section: admin` /
  `Group: Applications/System`. 내용: `/usr/bin/muster`(0755); §4.4의 문서가 든 `/usr/share/doc/muster/`;
  `/usr/share/doc/muster/examples/systemd/muster-collect.service`와 `muster-collect.timer`(RL-12); 배포판의 관례
  자리에 라이선스(Debian은 `/usr/share/doc/muster/copyright`). `/etc`, `/var`, `/usr/lib/systemd` 아래에는 아무것도 없다.
- **RL-12 — 예시 유닛은 유닛 검색 경로가 아닌 문서 디렉터리에 산다.** 사용자의 말은 "바이너리만, 아무것도 돌지 않음"
  이었다. `/usr/lib/systemd/system/` 아래 유닛 파일은 RHEL 계열에서, 그리고 관리자 스크립트가 없는 Debian에서 비활성
  이지만, 미래의 preset이나 패키징 변경이 켤 수 있다. `examples/` 아래 파일은 실수로 켜질 수 없다. README는 설치하고
  켜는 두 명령을 보여 준다(`install -m 0644 … /etc/systemd/system/`, `systemctl enable --now
  muster-collect.timer`). 서비스는 `--out`을 기본값으로 두고 `/usr/bin/muster collect`를 주마다 돌린다. 주마다
  (`OnCalendar=weekly`, `Persistent=true`)는 저자의 선택이다. 운영자가 말한 지평이 한 달이고 한 주면 그 안에 네 점이
  생기기 때문이다. 유닛은 README의 첫 실행과 같은 명령인 `--deep` 없는 `collect`를 돌려서 주간 스냅샷들이 통째로
  비교된다(§5.4). walk를 원하는 운영자는 유닛을 고치고, 그러면 모든 스냅샷이 deep이 된다.
- **RL-13 — 관리자 스크립트.** `preinst`, `postinst`, `prerm` 없음. Debian의 `postrm`(RA-27, RA-40): `purge`에서만 — 심볼릭 링크인 `/var/lib/muster`는 링크만 사라지고, 마운트 지점인 `/var/lib/muster`(`/var/lib`와 장치가 다름; 같은 파일시스템의 바인드 마운트는 감지되지 않음)는 stderr 메모와 함께 운영자에게 남기고, 그 밖에는 `rm -rf --one-file-system`이 지운다 — 그리고 purge는 이 스크립트 때문에 절대 실패하지 않는다. 그 밖에는
  `/var/lib/muster`(스냅샷, 락, `latest`)를 지우고 그 밖에는 아무것도 지우지 않는다. `remove`에서는 남긴다. rpm에는
  purge가 없다: `%postun`은 아무것도 하지 않고, erase는 `/var/lib/muster`를 남기며, README가 손으로 지우는 법을 말한다.
  패키지 스크립트는 `systemctl`을 절대 부르지 않고, 사용자나 디렉터리를 절대 만들지 않는다(`collect`가
  `/var/lib/muster`를 스스로 0700으로 만든다, D13). 업그레이드는 설치 위의 설치다: 스크립트 없음, 스냅샷은 남고, 새
  `controls_version`은 다음 check와 diff에 나타난다.
- 패키지 메타데이터: `Maintainer`/`Packager`는 `.mailmap`과 `NOTICE`가 쓰는 커밋 신원 `seonggyun.seo
  <40746364+kun9497@users.noreply.github.com>`(RL-39; 권장 형태를 사용자가 택함), `Homepage`는 저장소,
  `Description`/`Summary`는 README의 첫 두 문장(RA-41). `.deb`는 `Priority: optional`, `.rpm`은 `Release: 1`. 설치 계약(§4.7)이 이
  필드들을 단언한다.

### 4.7 CI가 모든 PR에서 패키지를 증명한다

`ci.yml`의 새 `release-dry-run` 잡: `goreleaser release --snapshot --clean --skip=publish,sign`이 §4.4의 모든
아티팩트를 빌드하고(증명과 서명 단계는 태그가 필요해서 건너뛴다), 그 다음:

- amd64 스냅샷 바이너리에 대한 `scripts/reproduce.sh`(§4.3);
- post 훅으로 돌아간 `scripts/release-vulncheck.sh`(dry run은 릴리스처럼 발견에서 실패한다);
- `ubuntu:22.04`, `ubuntu:24.04`, `debian:12`(`.deb`), `rockylinux/rockylinux:9`, `almalinux:9`(`.rpm`)에 대한 **설치 계약**
  매트릭스: 패키지를 설치하고, 설치된 파일 목록이 §4.6과 정확히 같은지(`dpkg -L` / `rpm -ql`을 커밋된 목록
  커밋된 목록 `ci/release/contract-files.deb.txt`와 `.rpm.txt`와 비교 — 둘인 이유는 dpkg와 rpm이 다른 행을 찍기 때문이다: dpkg는 `/.`가 없고 rpm은 디렉터리 행이 전혀 없다(RA-34); EL 이미지에 `diff`가 없어 문자열 동등으로 비교), 유닛이 하나도 켜지지 않았는지(`systemctl list-unit-files 'muster*'`가
  비었거나 컨테이너에 systemd가 없음), muster 프로세스가 돌지 않았고 `/var/lib/muster`가 없는지 단언하고, `muster
  version`을 돌려 다섯 줄을 비교하고(1행은 `muster <version>` 그대로; 패키지 자체의 `Version` 필드는 nfpm의 `X.Y.Z-1` 형태로, 스냅샷 버전의 `-`는 `~`가 된다) 메타데이터 필드(`Maintainer`/`Packager`, `Homepage`/`URL`, 섹션/그룹, 우선순위/릴리스, RA-23)를 비교하고, `muster check --facts <예제 스냅샷>`을 돌려 종료 코드를 예제의 것과
  비교하고, 자기 위에 업그레이드하고, remove 뒤 심어 둔 `/var/lib/muster`가 남는지, purge(Debian) 뒤 사라지는지 단언한다;
- tar.gz: 풀고 같은 `muster version`과 `check` 단언;
- **README의 설치 블록이 돈다**(RL-28): README Install 절의 펜스 블록은 실행 가능한 템플릿이고 — `vX.Y.Z`, 아키텍처,
  서명 신원만이 자리 표시자다 — dry run은 자리 표시자를 치환해 스냅샷 빌드에 대해 그것들을 실행한다: sha256 경로와
  패키지 설치는 모든 PR에서; `gh attestation verify`와 `cosign verify-blob` 명령은 `main`으로의 `push`에서만, 거기서는
  잡이 OIDC 토큰을 갖고 `ci.yml`의 신원으로 스냅샷 빌드를 증명하고 서명한다(포크의 PR에는 토큰이 없다). 돌 수 없는
  README 명령은 붉은 릴리스가 아니라 붉은 PR이다.

잡은 `pull_request`와 `main`으로의 `push`에서 돌고 필수 체크다. 태그 전에 릴리스 파이프라인이 연습되는 유일한 곳이라
플랜은 이것을 `.goreleaser.yaml`과 같은 태스크에서 쓴다.

### 4.8 릴리스 노트, 체인지로그, 버전

- **RL-14 — 릴리스 노트는 `CHANGELOG.md`의 절이다.** `scripts/release-notes.sh vX.Y.Z`가 `## [X.Y.Z] - YYYY-MM-DD`
  절(Keep a Changelog)을 파일로 뽑아 GoReleaser가 노트로 게시한다(`release.header`/`--release-notes`). GoReleaser
  자신의 커밋 기반 체인지로그는 꺼 둔다. 절이 없거나 아직 `[Unreleased]`로 읽히면 잡이 실패하므로, 릴리스를 끊는 일은
  체인지로그 커밋으로 시작한다. D16이 요구하는 `Controls` 문단은 그 자리에 그대로다. `[0.1.0]` 절은 새로 쓴 운영자용
  한 쪽이다 — 릴리스가 하는 일, 검증과 설치 방법, 한계, 그 다음 `Controls` 문단 — 그리고 오늘 `[Unreleased]`인 누적된
  단계 이력은 통째로 파일에 남는 `## History before 0.1.0` 제목 아래로 옮긴다(RL-29). 이후의 절은 Keep a Changelog대로
  릴리스마다 쓴다.
- 릴리스는 Latest로 표시되는 보통의 GitHub 릴리스다. 버전의 `0.x`가 유일한 프리릴리스 신호다(RL-30: 프리릴리스
  플래그는 Releases 페이지에 Latest를 없애고 모든 설치 명령이 태그를 손으로 이름 붙이게 만든다).
- `muster version`은 `muster X.Y.Z`, `commit <전체 sha>`, `built <커밋 날짜>`를 찍고 두 줄을 더 얻는다: `controls
  <controls/VERSION>`과 `schema <facts schema_version>`(RL-15: diff를 읽는 운영자는 리뷰어에게 셋을 모두 말해야 하고,
  `version`은 입력을 읽지 않는 유일한 명령이라 그것들이 있을 자리다). e2e 테스트가 다섯 줄을 고정한다.
- SECURITY.md의 "Supported versions"는 이미 "1.0까지는 최신 태그 릴리스만 수정을 받는다"로 읽히고 그대로다. README의
  상태 블록은 `v0.1.0`이 생기면 최신 머지 단계 대신 최신 릴리스를 이름 붙인다(§6.1).

### 4.9 스냅샷 생애주기: `snapshot ls|rm|prune` (D13)

- `muster snapshot ls [--dir <d>] [--format table|json]`은 디렉터리(기본 `/var/lib/muster/snapshots`)의 스냅샷을
  나열한다: 파일 이름, `collected_at`, 호스트 이름, `muster_version`, `controls_version`, 크기, `latest`가 가리키는
  것. `collected_at` 내림차순, 이름 자체의 UTC 타임스탬프가 동점을 가른다. 작성기의 패턴(`<hostname>-<UTC
  timestamp>-<short digest>.json`)과 맞는 이름의 일반 파일만 나열한다. 디렉터리 안의 그 밖의 것은 헤더 줄에서(RA-9) 수를
  세고 절대 열지 않는다. **RL-16 — 행은 세 종류다.** 스냅샷으로 디코드되는 파일은 `ok`; `schema_version`이
  바이너리보다 새 파일은 `newer`(헤더 필드 `collected_at`과 버전들은 헤더만 느슨하게 디코드해 읽어서, 운영자가 어느
  바이너리가 썼는지 본다); 어느 쪽으로도 디코드되지 않는 파일은 `unreadable`이고 이름의 UTC 타임스탬프로 정렬한다. 두
  표시 모두 나열하고 절대 건너뛰지 않는다. 운영자는 무엇이 공간을 차지하는지 봐야 한다. "가장 새 스냅샷" — 아래 RL-17과
  `diff`의 선택(RL-19)에서 — 은 가장 새 `ok` 행을 뜻한다. 그보다 새 `newer`나 `unreadable` 행은 `prune`과 `rm`의 재지정이
  stderr 경고로 이름을 대고 `ls`는 대지 않는다(RA-4): `<name> (<class>) is newer than the newest readable snapshot <newest>`(RA-37).
- `muster snapshot rm <name|path>…`는 이름 붙인 파일을 지운다: 디렉터리 안의 어떤 일반 파일이든 이름으로(패턴에
  맞든 아니든, `ok`든 `newer`든 `unreadable`이든 — `rm`은 `prune`이 건드리지 않는 것을 위한 명시적 길이다), 또는 어디의
  파일이든 전체 경로로(`rm`은 디렉터리를 절대 추측하지 않는다). `rm latest`는 거부한다("latest는 링크다; 가리키는
  스냅샷을 이름 붙이라"). `latest`가 가리키는 파일을 지우면 `latest`를 남은 가장 새 `ok` 스냅샷으로 다시 가리키거나,
  남은 것이 없으면 링크를 지운다. `--dry-run`은 무엇이 사라질지 찍는다.
- `muster snapshot prune [--keep N] [--keep-days D] [--dir <d>] [--dry-run]`은 둘 다 주면 가장 새 `N`개 밖에 있고
  `D`일보다 오래된 `ok` 스냅샷을, 하나만 주면 `N`개 밖이거나 `D`일보다 오래된 것을 지운다. 둘 다 없으면 사용법
  오류(종료 2)다. `newer`와 `unreadable` 행은 `prune`이 절대 지우지 않고 `N`에 절대 세지 않는다(오래된 바이너리가 새
  바이너리가 쓴 것을 지워서는 안 된다; 쓰레기는 `rm`이 이름으로 지운다). **RL-17 — prune은 가장 새 `ok` 스냅샷을 절대
  지우지 않는다**, 경계가 무엇이든(§5의 diff가 그것을 필요로 하고, `--keep-days 0`을 친 운영자의 뜻은 "오래된
  것들"이다). `latest`가 지워진 파일을 가리켰다면 `prune`은 `rm`처럼 다시 가리킨다. 시계는 `--max-age`가 읽듯 명령당
  한 번 읽는다.
- **RL-18 — muster가 삭제하는 디렉터리의 신뢰 규칙.** 수집기 작성기가 자기가 쓰는 디렉터리에 적용하는 것과 같은
  규칙(`trustedDir`: 디렉터리 자체를 `lstat`해서 심볼릭 링크가 아니고 타인 쓰기 불가), 더하여 호출자 소유이고 그룹 쓰기
  불가. 위의 구성 요소들은 걷지 않는다. 그래서 작성기와 삭제기가 일치하고, `collect`할 수 있는 디렉터리는 prune할 수
  있다. 잠금은 같은 경로에 대한 `collect`의 도우미다(기본 디렉터리에서는 공유 잠금 파일, 그 밖에서는 디렉터리 자체의
  flock — 경로로 한 번 더 여는 것이며, Task 4 판정에서 받아들였다). 나열과 삭제를 위해 디렉터리는 `O_NOFOLLOW|O_DIRECTORY`로
  한 번 열고, 모든 나열과 삭제는 그 fd를 통한다(`unlinkat`). 나열과 삭제
  사이에 다시 가리켜질 수 있는 경로로는 절대 지우지 않는다. 디렉터리 안의 심볼릭 링크는 절대 따르지 않고 `prune`이 절대
  지우지 않는다(`ls`는 헤더의 수에 넣어 나열한다). 디렉터리 밖의 전체 경로를 `rm`에 주면 그 부모에 같은 규칙을 적용한다.
  세 명령은 디렉터리의 소유자로 돈다 — 기본 배치에서는 root — 소유하지 않는 디렉터리는 거부하고(종료 2) 다른 사용자의
  파일에 `sudo`로 행동하지 않는다. `collect`는 바뀌지 않는다.
- 기준 설계 §8의 "스냅샷은 `collect`가 쓰는 유일한 파일이다" 문장은 `snapshot rm`과 `prune`을 파일을 지우는 유일한
  하위 명령으로, 그것도 그 디렉터리 안에서만, 더한다. THREAT_MODEL도 같게 말한다.
- `ls`/`rm`/`prune`은 `info`/`extract`/`anonymize` 옆 `cmd/muster/snapshot.go`에 산다. 순수한 나열·선택 논리(이름과
  시각이 주어졌을 때 prune이 무엇을 지울지)는 `os` 없는 패키지(`internal/snapshots`)이고 픽스처로 테스트한다. 파일
  연산은 얇은 Linux 태그 층이고 CI에서 root로 임시 디렉터리 테스트와 비root 거부 테스트를 한다. 종료 코드: 0, 거부나
  I/O 오류에 2. stdout에는 목록이나 dry-run 계획 외에 아무것도 없다.

### 4.10 릴리스 잡과 알림

모든 워크플로의 액션 — `release.yml`과 기존의 `ci.yml`, `examples.yml`, `fuzz.yml` — 은 4A의 한 커밋에서 커밋 SHA로
고정하고, `.github/dependabot.yml`(생태계 `github-actions`, 월간)이 이동을 제안한다. 다른 PR처럼 관리자가 머지하는
PR로서다(RL-31: 갱신기 없는 SHA 고정은 썩는다).

`release.yml`: `on: push: tags: ["v*"]`; 권한 `contents: write`, `id-token: write`, `attestations: write`; 단계:
checkout(GoReleaser를 위한 전체 깊이), `go.mod`에서 setup-go, `check-go-toolchain.sh --exact`, 고정 cosign 설치기,
고정 syft 설치기, `release-notes.sh`, GoReleaser(`release --clean --release-notes <file>`), `dist/*.tar.gz
dist/*.deb dist/*.rpm`에 대한 `attest-build-provenance`. 그 다음 assay의 것과 같은 `alert` 잡(고정 이슈 하나, 다음
성공에 닫힘). `main` 이력 위에 없는 태그는 첫 단계에서 실패한다(RL-6: 태그는 `main`에서 끊고 절대 옮기지 않는다;
스크립트가 `git merge-base --is-ancestor`를 확인한다).

## 5. 4B — `snapshot diff`

### 5.1 명령

`muster snapshot diff [<old> [<new>]] [--dir <d>] [--facts] [--any-host] [--format table|json] [--profile <p>]
[--tuning <t>] [--waivers <w>] [--fail-on <status>]`

- **선택(RL-19).** 인자 없음: §4.9 `ls`의 규칙으로 `--dir`에서 가장 새 `ok` 스냅샷 둘(가장 새 것이 `new`, 그
  다음이 `old`; 어느 쪽보다 새 `newer`나 `unreadable` 행은 stderr 경고에 이름이 나고 건너뛴다). 둘 미만이면 디렉터리를
  이름 붙여 거부한다. 인자 하나: 그 파일이 `old`, 디렉터리의 가장 새 것이 `new` — 단
  그 인자가 자신이 가장 새 것이면 거부한다("다른 스냅샷을 이름 붙이라"). 인자 둘: `old`, `new`, 그 순서. `new.collected_at`이
  `old.collected_at`보다 앞이면 stderr에 한 번 경고하고 이름 붙인 대로 비교한다(운영자는 "무엇을 잃었나"를 묻고 있을 수
  있다). `-`는 둘 중 하나에만(stdin) 허용되고 둘 다에는 안 된다. 파일은 `check`의 신뢰 검사가 있는 `openFacts`로 연다.
- **같은 호스트(RL-20).** 두 스냅샷은 같은 `run.host.machine_id_hash`를 들어야 한다. 아니면 종료 2("스냅샷이 다른
  호스트의 것이다; `--any-host`가 어쨌든 비교한다"). 한 키로 익명화한 두 스냅샷은 이 검사를 통과한다(해시가 같은 식으로
  매핑된다). 하나는 익명화되고 하나는 아니면 통과하지 못하고, `--any-host`가 의도된 길이다. 머신 id가 없는
  스냅샷(읽을 수 없는 `/etc/machine-id`, 또는 컨테이너)은 호스트 이름으로 비교하고 헤더가 어느 신원을 썼는지 말한다.
- **한 번의 평가, 양쪽.** 두 스냅샷은 이 바이너리의 컨트롤 세트로, 같은 `resolveSelection` 결과(프로파일과 튜닝), 같은
  면제, 한 번의 시계 읽기 아래 평가된다. 따라서 규칙은 양쪽에서 절대 다르지 않다(§5.4).

### 5.2 바뀐 판정(기본)

양쪽에서 상태가 다른 컨트롤마다 한 행: id, 유효한 심각도, `old → new` 상태, 그리고 그 뒤의 사실: 컨트롤의 절이 읽는
모든 리프(2M 단계의 facts-used 기계) 중 두 스냅샷 사이에 값이나 상태가 다른 것을 `key: old → new`로, `check` 표가
이스케이프하는 방식으로 값을 이스케이프하고, 리스트는 요약하며(`+3 −1 elements`, 처음 몇 이름), 행당 최대 여덟
리프(`… and N more`, `--format json`은 모두 든다). 행은 나빠진 것 먼저, 그 다음 좋아진 것, 그 다음 나머지. 그룹 안에서는
심각도 다음 id 순(RL-21). "나빠짐"은 사다리 `PASS = NOT_APPLICABLE < MANUAL < WARN < FAIL < ERROR`를 올라가는
이동이다. `WAIVED`는 사다리에서는 바탕 상태와 같이 앉고 `WAIVED(FAIL)`로 보인다.

양쪽 상태가 같지만 이유 코드가 다른 컨트롤(다른 `FAIL`)은 둘째 그룹 "같은 판정, 다른 이유"의 행이다. `--quiet`이면 빠진다.

### 5.3 사실 변화(`--facts`)

`--facts`가 있으면 판정 행 뒤에: 상태나 값이 다른 모든 사실 리프를 수집기(키의 첫 구성 요소)별로 묶어 `key: old →
new`, 같은 이스케이프와 리스트 요약, 표에서는 200행에서 자르고(`… and N more; --format json carries all`) JSON에서는
자르지 않는다. `run.` 아래 키는 절대 비교하지 않는다(설계상 휘발성, 기준 설계 §9). `collected_at`, 두 버전, 호스트
블록은 헤더에 한 번 나온다.

### 5.4 규칙 변화 — 반목표 4의 장치

양쪽이 같은 컨트롤 세트로 평가되므로 바뀐 규칙은 바뀐 판정으로 절대 나타날 수 없다. 나타날 수 있는 것은 무엇이
*수집*되었는지의 차이다: 그 스냅샷을 쓴 바이너리에 수집기가 없어서 오래된 스냅샷이 들지 않은 리프(그 쪽에서 컨트롤은
`ERROR(missing_fact)`를 읽는다), 한쪽에서는 돌고 다른 쪽에서는 거부·건너뜀·시간 초과된 수집기(비root 실행; 컨테이너),
또는 한쪽에만 있는 `--deep`(walk와 verify 컨트롤은 얕은 쪽에서 deep 게이트 뒤의 `MANUAL`을 읽는다). **RL-22 — 입력이
양쪽에서 같게 수집되지 않은 컨트롤은 변화가 아니라 "비교 불가"다.** 신호는 레지스트리의 `since`가 아니라 스냅샷
자체다(모든 키가 `since: 1`이고 기준 설계 §5.7은 추가가 스키마를 절대 올리지 않는다고 말하므로 `since`는 결정할 수
없다). 컨트롤은 절이 읽는 어느 리프가 정확히 한쪽에서 `missing`(들지 않음)일 때, 읽는 수집기의 `run.collectors`
상태가 양쪽에서 다를 때, 또는 deep 게이트(`deepFamilies`) 뒤에 있고 `run.deep`이 다를 때 비교 불가다. 그런 행은 셋째
그룹 "비교 불가"로 가며 각각 원인을 단다(`older snapshot lacks <key>`, `<collector> denied on the old side`,
`--deep on the new side only`). 화살표도 종료 코드 효과도 없다. 헤더는 두 `muster_version`과 `controls_version` 쌍을
찍고, 다르면 한 줄을 찍는다: "이 스냅샷들 사이에 컨트롤 세트가 바뀌었다: CHANGELOG.md의 Controls 항목을 <old>에서
<new>까지 보라". `run.deep`이나 수집기 상태가 다르면 그렇다고 한 줄 찍는다. 그 줄들이 규칙 변화 보고의 전부다.
브레인스토밍에서 그린 "오래된 스냅샷을 오래된 규칙으로 다시 평가"는 가능하지 않고(오래된 규칙은 오래된 바이너리 안에만
있다) 필요하지도 않아서(양쪽에 같은 규칙), 저자는 RL-22를 택하고 그것을 거두었다.

### 5.5 출력과 종료 코드

- 표: 헤더(두 파일 이름, 두 `collected_at`, 쓴 신원, 두 버전 쌍, `check`가 찍는 대로의 프로파일 줄), 그 다음 §5.2의
  그룹들과, `--facts`가 있으면 §5.3. 빈 그룹은 생략한다. "바뀐 판정 없음"은 한 줄이다. JSON: `{schema_version, run:
  {…check처럼…, old: {path, collected_at, host, muster_version, controls_version, schema_version}, new: {…},
  identity: machine_id|hostname|any}, changed: [{id, severity, severity_source, old: {status, reason_code}, new:
  {…}, facts: [{key, old: {status, value}, new: {…}}]}], same_verdict_different_reason: […], not_comparable: […],
  facts?: […]}`. 배열은 표가 정렬하는 대로. 렌더러에 map은 닿지 않는다. 같은 입력에 바이트가 같다.
- **RL-23 — 종료 코드.** 거부(선택, 신뢰, 다른 호스트, 읽을 수 없는 입력, 바이너리보다 새 스키마)에 2. 그 밖에는
  `check`의 임계값을 나빠진 행의 *새* 상태에 적용한다: 플래그 없이, 또는 `--fail-on fail`이면 어느 행이 `FAIL`이나
  `ERROR`로 나빠졌을 때 종료 1; `--fail-on warn`은 `WARN`을, `--fail-on manual`은 `MANUAL`을 더하고, `--fail-on
  none`은 2가 아니면 항상 0 — `check`와 같은 단어, 같은 기본값이라 `check`를 읽는 CI는 `diff`도 같은 식으로 읽는다.
  `WARN`으로 나빠진 행은 나열되고 기본으로는 0으로 끝난다. 비교 가능한 행의 new 쪽 `ERROR`는 나빠짐(종료 1)이고 종료
  2가 아니다. diff는 비교를 멈추는 것만 거부한다.
- `diff`에는 `--max-age`가 없다(오래된 쪽의 나이가 요점이다). 사용법에 적는다.

### 5.6 어디에 살고 어떻게 테스트하나

`internal/diff`(순수: `[]check.Result` 둘, 사실 맵 둘, 레지스트리, 선택을 받아 그룹들을 돌려준다)에 결정성 테스트,
사다리 테스트, `since` 테스트. `cmd/muster/snapshot.go`가 `runCheck`의 도우미 위에 하위 명령을 더한다(`openFacts` →
`resolveSelection` → `loadWaivers` → 두 번 평가 → `diff.Build` → 렌더). 픽스처: 컨트롤 픽스처로 만든
`cmd/muster/testdata/diff/` 아래의 쌍(한 컨트롤의 `pass-*`/`fail-*` 쌍은 나빠짐; `_hosts` 스냅샷과 그 편집본은 사실
변화), 두 예제 스냅샷(다른 호스트 → 거부와 `--any-host`), RL-22를 위해 한 수집기의 키를 지운 픽스처("오래된 바이너리"
경우), `run.collectors`에서 한 수집기를 `denied`로 표시한 것, deep/얕음 쌍, 3D-3 픽스처에서 온 익명화 쌍. 표와 JSON의 golden은 `-update`로. e2e 테스트는 임시 디렉터리 위에서 세 선택 형태와 종료 코드를 다룬다. 예제
게이트는 건드리지 않는다(diff는 예제 파일을 더하지 않는다; RL-24: 예제 워크플로는 이미지마다 한 번 수집하므로 게시할
둘째 스냅샷이 없다).

## 6. 4C — 운영자 문서와 릴리스 게이트

### 6.1 README 쌍

운영자용으로 다시 쓰고, 순서는: muster가 무엇인가(지금의 첫 두 문단, 유지); **Install** — "먼저 검증"(§4.5의 두 명령,
그 다음 sha256 경로, 각각이 무엇을 증명하는지), 그 다음 배포판별 패키지 명령과 tar.gz, 그 다음 "Reproduce the
build"(§4.3); **First run** — `sudo muster collect`, `muster check`, 한 달 뒤 `muster snapshot diff`, 각각 짧은 출력 발췌
하나; **Keep it running** — 예시 유닛과 `snapshot prune`; **Positioning** — Lynis, OpenSCAP/`oscap`, CIS-CAT에 대한
짧은 표. 축은 스냅샷에서 오프라인, 아무것도 바꾸지 않음, KISA 항목, CIS/STIG/NIST 참조, 리뷰 스크립트로서의 조치(사실만,
벤치마크 본문 없음, 다른 도구의 품질에 대한 주장 없음); 그 다음 지금의 절들(하는 일, 원칙, 하지 않는 일, 대상, 표준,
로드맵, 문서, assay와의 관계, 라이선스). 상태 블록은 최신 릴리스를 이름 붙이고 Releases 페이지를 링크한다. `coverage
-check`가 확인하는 로드맵 문장은 글자 그대로 남는다. `README.ko.md`는 같은 문서의 한글이고 §6.3이 지킨다.

- **RL-32 — 발췌는 커밋된 파일에 고정된다.** `collect`와 `check` 발췌는 `examples/ubuntu-24.04-vm-report.txt`의
  연속된 줄이고 `diff` 발췌는 `internal/diff`의 표 golden(픽스처 쌍; RL-24는 그대로다 — 예제 워크플로는 한 번
  수집한다)이다. `cmd/muster`의 테스트가 README의 각 펜스 발췌를 그 출처와 같게 지켜서, 예제 갱신이나 렌더러 변경은 같은
  커밋에서 README를 고치거나 CI를 실패시킨다. 같은 바이트가 `README.ko.md`에 앉는다(§6.3).
- **RL-33 — Install 절은 태그가 생기기 전에 `v0.1.0`용으로 쓴다**, 글자 그대로의 파일 이름과 서명 신원으로, 그리고 그
  블록들이 `release-dry-run`이 실행하는 것이다(RL-28). 게시된 릴리스가 필요한 명령은 운영자 리허설(§6.5)에서 돈다. 거기서
  하나가 실패하면 `v0.1.1`이 고친 README를 들고 나가고 `v0.1.0` 릴리스 노트는 그것을 가리키게 고친다(RL-6: 태그는 남는다).
- 포지셔닝의 각 칸은 출처가 있다: 비교 대상마다 버전과 읽은 공개 문서를 이름 붙인 각주, 저자가 출처를 댈 수 없는 칸은
  주장이 아니라 `—`다(RL-34). 각주 표시는 §6.3이 양쪽에서 지키는 식별자다.
- 대상: README는 참인 것을 말한다 — 패키지는 Debian 12에 설치되고 거기서 테스트되며, 수집기는 거기서 CI의 비차단
  카나리로 돈다; Ubuntu 22.04/24.04와 RHEL 9 계열이 지원 대상으로 남는다(RL-35). SECURITY.md의 범위도 같게 말한다.

### 6.2 THREAT_MODEL과 SECURITY

THREAT_MODEL에 "Supply chain"이 생긴다: 증명과 서명이 증명하는 것(GitHub Actions가 이 저장소의 이 태그에서 빌드했다;
checksums 파일은 잡이 만든 그것이다)과 증명하지 않는 것(소스가 무해하다는 것; 관리자 계정이 오용되지 않았다는 것 —
리뷰어가 태그의 diff를 읽는다), 툴체인과 의존성 고정, govulncheck의 두 겹과 fail-closed 규칙, 어느 릴리스 아티팩트도
키를 들지 않는다는 진술. "Reads"와 "Writes" 문단은 `snapshot rm`/`prune`을 삭제 경로로 이름 붙인다(§4.9).
SECURITY.md는 손상된 릴리스를 어떻게 보고하는지(같은 경로)와, 회수된 릴리스는 Releases 페이지와 CHANGELOG에 표시하고
절대 지우지 않는다는 것을 더한다(RL-25: 지우면 검증자가 필요로 하는 증거가 숨는다). 둘은 영문 전용으로 남는다(RL-38).
README 쌍의 Install 절이 두 검증이 증명하는 것과 증명하지 않는 것을 두 언어로 말해서, 한국어 운영자는 그것을 위해
THREAT_MODEL이 필요하지 않다.

### 6.3 문서 drift 검사

`tools/docdrift`(`make docdrift`; CI는 `go run ./tools/docdrift -check`)는 커밋된 표 `tools/docdrift/pairs.txt`를
읽는다: 쌍마다 한 줄, `<path> <rule set>`. 저장소 루트나 `docs/` 아래 어디든 표에 없는 `X.ko.md`는 거부하고(새 쌍은 규칙
세트를 골라야 한다), 영문 쪽이 없는 표 항목도 거부한다. 규칙 세트는 둘이다(RL-36).

- **`operator`** — 운영자가 읽는 문서: `README`, `CONTRIBUTING`, `RELEASING`, 그리고 달리 적지 않은 모든 미래의
  쌍(RL-38의 영문 전용 문서는 쌍이 아니고 적히지 않는다). 두 파일이 모두 있다; 제목 개요가 맞는다(수준별 제목 수가 같고
  수준의 순서가 같다); 펜스 코드 블록이 순서대로 바이트 단위로 같다(명령과 출력은 번역하지 않는다 — 명령 블록 안의
  주석은 양쪽에서 영문이다); 코드 블록 밖의 백틱 식별자 집합이 두 정규화 뒤에 같다: `<…>` 자리 표시자 묶음은 `<>`가
  되고(자리 표시자는 식별자 안에서 번역되는 유일한 것이다: `` `--walk-budget <기간>` ``) 링크 대상의 `.ko.md`는
  `.md`가 된다.
- **`design`** — 기준 설계 쌍: 두 파일이 모두 있고, 제목 개요가 맞고, 줄 수가 같다(쌍은 줄마다 맞춰 고친다). 코드
  블록과 식별자는 비교하지 않는다. YAML 예시의 한글 주석이 한국어 독자를 섬기기 때문이다.

머지된 열다섯 단계 스펙은 규칙 세트 `history`로 적는다 — 존재와 제목 개요만: 그것들은 결정이 내려진 대로의 기록이고,
식별자 집합을 맞추려면 어느 독자도 위하지 않는 한글 ~8,000줄을 다시 쓰게 된다. 오늘 측정하면 모든 쌍이 어딘가에서
`operator` 규칙에 실패한다(README의 하나뿐인 코드 블록에 번역된 주석이 있다; CONTRIBUTING의 한글 쪽은 영문 쪽에 없는
명령을 이름 붙인다). 4C는 잡이 필수가 되기 전에 `operator` 쌍들과 기준 설계 쌍을 맞춘다. 검사는 필수 CI 잡이고
`release-dry-run`에서도 돌아서, drift된 쌍 위에서는 태그를 끊을 수 없다(RL-26). 모양을 검사하고 뜻은 검사하지 않는다.
리뷰어는 여전히 둘을 읽는다.

### 6.4 `RELEASING.md`

영문과 한글. 순서: CHANGELOG 커밋(절, 날짜, 판정이 움직였으면 Controls 문단); C 툴체인이 있으면 로컬에서 `make docdrift
coverage-check release-dry-run`, 없으면 커밋의 CI를 믿는다; `main`의 CI를 기다린다; `git tag vX.Y.Z && git push
origin vX.Y.Z`(`main`의 깨끗한 체크아웃에서, 관리자가, 손으로 — RL-27: 에이전트 세션은 태그를 푸시하지 않는다;
CLAUDE.md의 푸시 규칙이 태그에도 미친다); 릴리스 잡을 지켜본다; 그 다음 **운영자 리허설**(§6.5). 실패한 릴리스:
`main`에서 고치고 다음 패치 태그를 끊는다. 실패한 태그는 CHANGELOG 메모와 함께 남는다(RL-6).

### 6.5 운영자 리허설 — 발표 전의 게이트

잡이 게시한 뒤, 빌드 러너가 아닌 기계에서(랩 호스트는 제외; 새 컨테이너나 VM): README의 Install 절을 글자 그대로
따른다 — 두 명령으로 검증, 패키지 설치, `collect`, `check`, `anonymize`, `diff` 실행; `go run ./tools/anonverify
<original> --key <key> <anonymised> <check json> <check table> <fix script>` 실행(RL-37: `tools/coverage` 옆의
관리자 도구 — 원본에 같은 키로 익명화기를 라이브러리로 다시 돌려, 장부가 매핑한 모든 평문 값을 오라클로 삼고 — 호스트
레이블, 계정·그룹 이름, 주소, 지문, 머신 id, 경로 구성 요소 — 만들어진 파일들에서 그것들을 온전한 토큰으로 찾는다;
바이너리와 순수한 `internal/anonymize`는 건드리지 않고, 도구는 예제 스냅샷에 대한 테스트를 갖는다), 그리고 보고서와 fix
스크립트가 redaction 정책이 금하는 것을 들지 않는지 확인; `reproduce.sh` 실행; `remove`와 `purge`. 체크리스트는
RELEASING.md에 단계마다 채울 줄과 함께 있고, 모든 줄이 채워졌을 때만 릴리스를 발표한다(`main`의 README 상태 블록 갱신).
첫 리허설은 `v0.1.0`의 것이고 채운 체크리스트는 `docs/releases/v0.1.0.md`에 커밋한다.

## 7. 테스트와 CI(요약)

| 게이트 | 어디서 | 지키는 것 |
|---|---|---|
| `release-dry-run` | ci.yml, PR + main | §4.7: 게시 없는 전체 파이프라인; reproduce; 설치 계약 매트릭스; vulncheck |
| `govulncheck` 소스 | ci.yml `test` 잡 | §4.2 |
| `check-go-toolchain.sh` | ci.yml 하한, release.yml 정확히 | RL-4 |
| `docdrift -check` | ci.yml + release-dry-run | §6.3 |
| 예제 게이트 | 기존 | `check`/`fix` 출력의 어느 바이트도 움직이지 않음 |
| `internal/snapshots`, `internal/diff` 순수성·결정성 테스트 | go test | §4.9, §5.6 |
| e2e: `version` 다섯 줄, `ls/rm/prune`, `diff` 선택과 종료 코드 | cmd/muster | §4.8, §4.9, §5.5 |
| golden: diff 표/JSON | internal/diff | §5.5 |
| root 테스트: 임시 디렉터리의 `prune`, 디렉터리 fd를 통한 `rm`; 비root 거부 | CI sudo 단계 | RL-18 |
| shellcheck | 기존 타깃 | 새 `scripts/*.sh`와 `ci/release/*.sh`가 목록에 들어감 |

## 8. 문서

기준 설계: §5.9(세 명령이 도착), §7(diff의 종료 코드), §9(`version`의 다섯 줄이 "빌드 날짜 … 가이드 판"을 대신한다 —
가이드 판은 `controls` 값 안에 탄다), §8 `:428`(목록을 만든 것으로 바꾼다: keyless,
SBOM, 패키지, 설치 스크립트 없음, reproduce 스크립트), §9(SARIF는 "유보"로 이동), §10.2(4단계 문단을 4A/4B/4C로 다시
적고 도착하는 대로 "merged" 표시), §10.3(SARIF, `--controls-dir`, 기여자 항목, Lynis 추가), D13 닫힘, 새 **D37 — 릴리스
무결성과 설치 계약**(keyless 서명, 그렇게 말한 L2 증명, 정확한 툴체인과 커밋 날짜에 의한 재현 빌드, 아무것도 시작하지
않는 패키지, purge 의미), **D38 — `snapshot diff`는 한 컨트롤 세트 아래 비교한다**(RL-20, RL-22, RL-23). 쌍은 줄
정렬을 유지한다. CLAUDE.md에 "Release (stage 4)" 절이 생긴다(파이프라인, 계약 목록, reproduce 규칙, drift 검사,
"에이전트 세션에서 태그를 절대 푸시하지 않는다"). CHANGELOG는 조각마다 Unreleased 아래. README 쌍은 §6.1,
THREAT_MODEL과 SECURITY는 §6.2, RELEASING.md는 §6.4, CONTRIBUTING.md는 `docdrift`에 대한 한 문단.

## 9. 유보(4단계에 없음)

- **SARIF** — 운영자의 그림에 소비자가 없다. 생기면 돌아온다(렌더러와 스키마 검증은 기준 설계 §9에 설계된 채로 남는다).
- **`--controls-dir`** — 저자의 권고, 수락됨: 운영자는 컨트롤을 소비하고, 프로파일과 튜닝이 이미 선택과 값을 다루며,
  사이트 컨트롤은 수집기만 더할 수 있는 사실이 필요하다. §4의 충돌과 digest 규칙은 올 때를 위해 남는다.
- **기여자 항목** — DCO 사인오프, PR 템플릿, Lynis 차분과 이미지별 베이스라인.
- **다른 플랫폼** — macOS와 Windows용 check 전용 빌드(기준 설계 §10.3).
- **설치 스크립트나 한 줄** — 절대 없음(기준 설계 §8).
- **중앙 업로드나 에이전트** — 범위 밖(§10.3).

## 10. 저자의 선택

브레인스토밍이 열어 두었고 이 문서가 정한 선택. 사용자는 플랜 전에 어느 것이든 뒤집을 수 있다.

1. 예시 타이머의 `OnCalendar`는 weekly(§4.6, RL-12).
2. 예시 유닛은 유닛 경로가 아닌 `/usr/share/doc/muster/examples/systemd/` 아래(RL-12).
3. rpm erase는 `/var/lib/muster`를 남긴다. Debian의 purge만 지운다(RL-13).
4. `muster version`에 `controls`와 `schema` 줄이 생긴다(RL-15).
5. `prune`은 경계가 무엇이든 가장 새 스냅샷을 남긴다(RL-17).
6. 규칙 변화 보고는 CHANGELOG를 가리키는 헤더 한 줄과 "비교 불가" 그룹이다. 브레인스토밍의 "옛 규칙으로 재평가" 안은
   거둔다(RL-22, §5.4).
7. diff의 종료 코드: 비교 가능한 행의 새 `ERROR`를 포함해 어떤 나빠짐에도 1(RL-23).
8. `diff`에 인자 하나는 "이 오래된 것을 가장 새 것과"(RL-19).
9. 재현성 주장은 `scripts/reproduce.sh`가 증명하는 것과 정확히 같고, `muster version`에서 커밋 날짜가 빌드 날짜를
   대신한다(RL-5, RL-7).
10. 포지셔닝 표의 비교 대상 셋과 축 다섯(§6.1).
11. drift 검사는 개요, 코드 블록, 식별자 집합, 적힌 줄 수를 비교하고 산문은 비교하지 않는다(§6.3).
12. 회수된 릴리스는 표시하고 절대 지우지 않는다(RL-25). 태그는 절대 옮기지 않는다(RL-6).

빌더 검토 뒤에 정한 것(리뷰어의 질문에 저자가 답한 것):

13. "비교 불가"는 스냅샷이 결정한다 — 한쪽에서 `missing`인 리프, 다른 수집기 상태, 한쪽만의 `--deep` — 레지스트리의
    `since`가 아니다(RL-22, §5.4). 예시 타이머는 `--deep` 없이 돌아서 주간 스냅샷이 통째로 비교된다(§4.6).
14. `ls`는 세 행 종류(`ok`, `newer`, `unreadable`)를 갖는다. `prune`은 `ok` 행만 건드리고 가장 새 것을 남긴다. `rm`은
    무엇이든 이름으로 지운다(RL-16, RL-17, §4.9).
15. 디렉터리 신뢰 규칙은 수집기 작성기의 규칙에 소유권을 더한 것, 디렉터리 fd 하나를 통해, 구성 요소 걷기 없음.
    `collect`는 바뀌지 않는다(RL-18).
16. diff의 종료 임계값은 `check`의 것이다: 기본은 `FAIL`/`ERROR`, `--fail-on`은 같은 단어(RL-23).
17. README의 설치 블록은 `release-dry-run`이 돌리는 실행 가능한 템플릿이다. Install 절은 태그 전에 `v0.1.0`용으로
    쓴다(RL-28, RL-33). 발췌는 커밋된 파일에 고정된다(RL-32).
18. Latest로 표시되는 보통 릴리스, 프리릴리스 플래그 없음(RL-30). `[0.1.0]`은 새 운영자용 쪽이고 단계 이력은 자기
    제목 아래로 옮긴다(RL-29).
19. 모든 워크플로의 액션을 4A에서 SHA로 고정하고 액션용 `dependabot.yml`을 둔다(RL-31).
20. drift 검사는 커밋된 쌍 표에 세 규칙 세트 — `operator`, `design`, `history` — 를 갖는다. 머지된 단계 스펙은
    `history`다(RL-36).
21. 리허설의 카나리 검사는 장부의 평문 값에 대한 관리자 도구 `tools/anonverify`다(RL-37).
22. 포지셔닝 칸은 출처가 있거나 `—`다(RL-34). Debian 12는 "설치되고 테스트된다; 수집기는 카나리"(RL-35).

빌더 검토 뒤에 사용자가 정한 것: 한글 쌍은 README와 RELEASING만, `README.ko.md`에 한글 공급망 요약(RL-38); 패키지
관리자 문자열은 커밋 신원(RL-39).

## 11. 빌더에게 맡기는 것

GoReleaser와 nfpm의 필드 이름과 정확한 고정 버전; `scripts/`와 `ci/release/`의 배치; §5의 규칙 안에서 `diff` 그룹의
표 너비와 문구; 픽스처 쌍의 컨트롤 선택; `docdrift` 식별자 토크나이저의 경계 사례(코드 스팬 안의 백틱, 코드 블록 안의
제목); 세 플랜의 태스크 순서; 어느 `releases/`와 `ci/` 경로가 shellcheck 타깃에 들어가는지.

## 12. 판정

- **RL-1** `v0.1.0`이 처음. 운영자 피드백을 읽기 전까지 `0.x`.
- **RL-2** 대상은 `linux/amd64`, `linux/arm64`만.
- **RL-3** 설치 스크립트 없음. 릴리스 잡은 `main`에 절대 푸시하지 않는다.
- **RL-4** `go.mod`에 이름 붙인 툴체인 하나(지원되는 라인의 최신 패치; `go 1.25`는 그대로). CI는 하한, 릴리스는 정확히.
- **RL-5** 구성상 재현 가능: 커밋 타임스탬프와 날짜(`TZ=UTC` 아래 `format-local:`), `-trimpath`, `-buildvcs=false`, 정확한 툴체인.
- **RL-6** 태그는 `main`에서 끊고 절대 옮기거나 지우지 않는다. 실패한 태그는 남고 메모된다.
- **RL-7** README는 `reproduce.sh`가 증명하는 것만 주장한다.
- **RL-8** SBOM은 고정 syft의 SPDX JSON, 아카이브와 패키지마다 하나. 아카이브의 SBOM은 바이너리의 모듈을 나열하고, 패키지의 SBOM은 패키지 자체를 기술한다(syft는 `.deb`/`.rpm`의 헤더를 읽고 페이로드는 읽지 않는다).
- **RL-9** checksums 파일에 대한 keyless 서명, Sigstore 번들(`--new-bundle-format`), 신원 = 태그 시점의 릴리스 워크플로.
- **RL-10** 증명은 SLSA Build L2로 말하고, 증명하지 않는 것도 말한다.
- **RL-11** 패키지는 바이너리와 문서를 설치하고 아무것도 시작하지 않는다. `/etc`, `/var`, `/usr/lib/systemd` 아래에는 아무것도 없다.
- **RL-12** 예시 유닛은 문서 디렉터리에. weekly.
- **RL-13** pre/post-install 스크립트 없음. Debian purge는 마운트 지점(메모와 함께 남김)이나 심볼릭 링크(링크만 사라짐)가 아닌 한 `/var/lib/muster`를 지우고 절대 실패하지 않는다. rpm erase는 남긴다.
- **RL-14** 릴리스 노트는 CHANGELOG 절. 절이 없으면 릴리스가 실패한다.
- **RL-15** `muster version`은 다섯 줄을 찍는다(version, commit, built, controls, schema).
- **RL-16** `ls`의 행은 `ok`, `newer`, `unreadable`이고 절대 건너뛰지 않는다. 스냅샷이 아닌 이름은 세기만 하고 절대 열지 않는다.
- **RL-17** `prune`은 `ok` 행만 지우고 가장 새 `ok` 스냅샷은 절대 지우지 않는다. `newer`/`unreadable`은 `rm`으로만 지운다.
- **RL-18** 호출자가 소유한 디렉터리에서만, 작성기의 `trustedDir` 규칙 아래, 디렉터리 fd 하나를 통해, 심볼릭 링크를 절대 따르지 않고 지운다. `collect`는 그대로.
- **RL-19** `ok` 행 위의 선택: 없음 → 가장 새 둘; 하나 → 그것을 가장 새 것과; 둘 → 준 대로, 뒤집혔으면 경고.
- **RL-20** 같은 `machine_id_hash` 또는 `--any-host`. id가 없으면 호스트 이름, 헤더에 말한다.
- **RL-21** 행 순서: 나빠짐, 좋아짐, 나머지. 안에서는 심각도 다음 id.
- **RL-22** 입력이 같게 수집되지 않은 컨트롤(한쪽에서 `missing`인 리프, 다른 수집기 상태, 한쪽만의 `--deep`)은 "비교 불가"다.
- **RL-23** 거부에만 종료 2. 그 밖에는 나빠진 행의 새 상태에 `check`의 임계값(기본 `FAIL`/`ERROR`, `--fail-on`은 `check`의 단어).
- **RL-24** 예제 diff 파일 없음. 예제 워크플로는 이미지마다 스냅샷 하나.
- **RL-25** 회수된 릴리스는 표시하고 절대 지우지 않는다.
- **RL-26** `docdrift -check`는 필수 CI 잡이고 `release-dry-run`에서도 돈다.
- **RL-27** 에이전트 세션은 태그를 푸시하지 않는다.
- **RL-28** README의 설치 블록은 `release-dry-run`이 돌리는 실행 가능한 템플릿이다(검증은 `main` 푸시에서).
- **RL-29** `[0.1.0]`은 새로 쓴 운영자용 절이다. 단계 이력은 `## History before 0.1.0` 아래로 옮긴다.
- **RL-30** Latest로 표시되는 보통 릴리스. 프리릴리스 플래그 없음.
- **RL-31** 모든 워크플로의 액션을 커밋 SHA로 고정한다. 액션용 `dependabot.yml`이 이동을 제안한다.
- **RL-32** README 발췌는 테스트가 커밋된 파일(예제 보고서, diff golden)과 같게 지킨다.
- **RL-33** Install 절은 태그 전에 `v0.1.0`용으로 쓴다. 리허설의 실패는 `v0.1.1`이 고친다.
- **RL-34** 포지셔닝 칸은 출처(각주의 버전과 문서)가 있거나 `—`다.
- **RL-35** Debian 12: 패키지는 설치되고 테스트된다. 수집기는 CI의 카나리. 지원 대상은 아니다.
- **RL-36** `docdrift`는 규칙 세트 `operator`, `design`, `history`가 있는 쌍 표를 읽는다. 표에 없는 `.ko.md`는 거부한다.
- **RL-37** `tools/anonverify`가 리허설의 카나리 검사이고, 장부의 평문 값이 오라클이다.
- **RL-38** 한글 쌍: README와 RELEASING. THREAT_MODEL, SECURITY, ATTRIBUTION, CHANGELOG는 영문 전용. `README.ko.md`가 검증을 요약한다.
- **RL-39** 패키지 `Maintainer`/`Packager`는 커밋 신원 `seonggyun.seo <40746364+kun9497@users.noreply.github.com>`.
