# Stage 3B — 커널·부트·마운트: 가이드 밖의 첫 점검

*[English](2026-09-18-stage3b-kernel-boot-mount-design.md) · 한국어*

이 문서는 muster 계획 3B의 설계입니다: KISA 항목이 아닌 첫 컨트롤들로, 메인 설계
(`2026-09-02-muster-design.md`, §10.2 "Stage 3", §11 "Checks that are not KISA items")가
2026-09-15에 합의한 하위 프로젝트 "3B kernel/boot/mount"에 남겨 둔 영역 — 커널 자기보호
sysctl과 세 출처의 코어덤프 정책, 부트 체인, 마운트 옵션과 별도 파티션, 스왑 암호화,
내장(built-in) 탐지를 포함한 모듈 블랙리스트 — 를 다룹니다. 세 번째 stage-3 하위
프로젝트입니다(3A walk와 3F 테스트 강화는 병합됨). 결정은 B-1 … B-12로 번호를 매기며
계획을 구속합니다. 2026-09-18의 프레시 리뷰(blocking 5, medium 10, low 6)를 반영했으며,
이 판이 초안과 다른 곳은 리뷰의 몫입니다. 여기의 모든 점검은 1차 출처 — 커널 문서, man
페이지, 배포판 자체 문서 — 에서 muster의 표현으로 쓰이고, CIS 권고 번호를 달지 않으며,
벤치마크 문장을 옮기지 않습니다(메인 설계 §11, D04).

설계 전 브레인스토밍에서 정한 세 가지가 아래 전체를 좌우하므로 여기 적습니다: 새
컨트롤은 기본으로 돌고 리포트 요약은 "가이드"와 "가이드 밖"으로 나뉜다(B-9); 컨트롤은
설정 하나당 하나도, 영역당 하나도 아닌 위험 단위로 묶는다(B-5); 네 영역을 한 계획에
담는다.

## 1. 목표

`category: beyond` 컨트롤 19개 — 커널 7, 부트 체인 3, 마운트·스왑 6, 커널 모듈 3 — 를
새 수집기 6개로 먹이고, 판정 중 얼마가 KISA 가이드에서 오고 얼마가 그 밖에서 오는지
리포트가 말하게 합니다. 3B 이후 컨트롤 세트는 87개(67항목에 대한 68개는 그대로 + beyond
19)이고, 기본 `check`는 둘 다 보고하며, 종료 코드는 원래대로입니다.

계획이 표류하지 않도록 3B 밖을 이름 짓습니다: 네트워크 sysctl(`ip_forward`,
`rp_filter`, redirects, syncookies — 노출 교차검사 3C의 몫); `/var`, `/var/log`,
`/var/log/audit`의 마운트 옵션(별도 파티션 컨트롤이 존재 여부는 다루고, 옵션은 여기의
옵션 컨트롤 넷이 모양을 증명한 뒤); squashfs(snap 때문에 모든 Ubuntu 커널에 내장이라
"끄라"는 컨트롤은 얻는 것 없이 모든 Ubuntu 호스트를 실패시킴); 커널 명령행(`lockdown=`,
`init_on_alloc=`); 감사 파이프라인 상태(3C); 어느 범위를 돌릴지 고르는 프로필(3D).

## 2. 팩트와 수집기 (B-1 … B-4)

**B-1 — 고정 어휘는 leaf로, 발견되는 집합은 list로.** `where`가 아무 행도 고르지 못한
`each` 절은 관찰만 남기고 통과합니다(M-6). 따라서 *부재* 자체가 결함인 설정 — 이 커널에
없는 sysctl, 거기 없는 부트로더 파일 — 은 자기 봉투를 가진 leaf여야 `absent`가
`absent_means`에 닿습니다. 호스트가 정하는 집합 — 어떤 마운트가 있는지, 어떤 스왑
장치인지, 모듈이 로드됐는지 — 은 `list<record>`이고, 판정할 행이 고정 후보 목록(마운트
지점, 모듈 이름)이면 수집기가 **후보마다 행을 항상** 내어(있든 없든) `where`가 결코 비지
않고 면제가 행을 부를 수 있게 합니다(`mount:/tmp`, `module:usb-storage`).

**B-2 — 수집기 여섯, 모두 `Needs: none`, 읽기만, 명령 없음.** 각각 경로를 선언하며
아무것도 프로그램을 실행하지 않습니다. 키 40개, 전부 `since: 1`, `sensitivity: public`
(sysctl 12 + coredump 6 + boot 13 + mounts 5 + modules 1 + swap 3):

| 수집기 | 키 | 타입 | 출처 |
|---|---|---|---|
| `sysctl` | `kernel.sysctl.kptr_restrict`, `dmesg_restrict`, `yama_ptrace_scope`, `randomize_va_space`, `unprivileged_bpf_disabled`, `bpf_jit_harden`, `perf_event_paranoid`, `sysrq`, `protected_symlinks`, `protected_hardlinks`, `protected_fifos`, `protected_regular` | `setting<int>`, `default_on: effective` | runtime는 `/proc/sys/<path>`; persisted는 `/etc/sysctl.d/*.conf`, `/run/sysctl.d/*.conf`, `/usr/local/lib/sysctl.d/*.conf`, `/usr/lib/sysctl.d/*.conf`, `/etc/sysctl.conf`를 systemd-sysctl과 같은 방식으로 합친 것(디렉터리를 가로질러 파일 이름순으로 정렬하되 앞선 디렉터리의 같은 이름이 뒤를 가림; 그 순서 안에서 마지막 대입이 이김; `-` 접두와 `kernel/yama/ptrace_scope` 슬래시 형태는 sysctl.d(5)대로); 스톡 `/etc/sysctl.d/99-sysctl.conf`는 `../sysctl.conf`로의 심링크이며 모델링합니다 — 그 위치에서 `/etc/sysctl.conf`를 읽고 winner는 실제 파일을 인용 — 오류로 보고하지 않음(C4, crypto-policies 선례); effective = runtime이고 봉투에 persisted 값과 그 파일을 실음 |
| `coredump` | `coredump.core_pattern` | `string` | `/proc/sys/kernel/core_pattern` |
| | `coredump.suid_dumpable` | `setting<int>` | `fs.suid_dumpable`, 위와 같은 두 집 |
| | `coredump.systemd.storage`, `coredump.systemd.process_size_max` | `string`, `int` | 본 파일 `/etc/systemd/coredump.conf`(systemd ≥ 254가 거기 두는 곳에서는 `/usr/lib/systemd/coredump.conf`)와 `/etc/systemd/coredump.conf.d`, `/run/systemd/coredump.conf.d`, `/usr/local/lib/systemd/coredump.conf.d`, `/usr/lib/systemd/coredump.conf.d`의 drop-in을 디렉터리를 가로질러 이름순으로, `/etc`가 이름으로 가림; 마지막 대입이 이김; 파일이 전혀 없으면 `absent` — 데몬 기본 `external`은 데몬의 것이지 muster의 것이 아님 |
| | `coredump.limits.hard_core`, `coredump.limits.sources` | `int`, `list<string>` | `/etc/security/limits.conf` + `/etc/security/limits.d/*.conf`의 `* hard core` 또는 `* - core`(`-` 타입은 두 한도를 모두 정함, limits.conf(5)), 마지막이 이김, `unlimited` → -1; 줄이 없으면 `absent` |
| `boot` | `boot.firmware` | `string` | `/sys/firmware/efi`가 있으면 `uefi`, 아니면 `bios` |
| | `boot.secure_boot` | `bool` | `/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c`의 오프셋 4 바이트(4바이트 속성 워드 다음); BIOS, 그리고 efivarfs나 변수가 없는 UEFI에서는 `absent`(SetupMode의 펌웨어도 강제하지 않음; 설명이 그렇게 말함) |
| | `boot.grub_cfg.path` + `boot.grub_cfg.` 아래 `writePermFacts` leaf 9개 | `string` + 권한 leaf | `/boot/grub/grub.cfg`, `/boot/grub2/grub.cfg`, `/boot/efi/EFI/<vendor>/grub.cfg` 중 존재하는 첫 것(심링크를 따라가지 않는 stat, C4); EACCES로 거부된 stat(EL의 `/boot/grub2`는 0700)은 모든 leaf에 `denied`이며 결코 "다음 후보"가 아님; 없으면 `absent`; 수집기는 그룹 이름을 위해 `/etc/group`을 선언 |
| | `boot.grub_password_set` | `bool` | grub.cfg, `/boot/grub2/user.cfg`(EL에서 0600), 정규 파일인 `/etc/grub.d/*`의 주석 아닌 줄에 리터럴 `grub.pbkdf2.` 해시가 있을 때만 true — `password_pbkdf2 <user> grub.pbkdf2.…` 또는 EL의 `GRUB2_PASSWORD=grub.pbkdf2.…`; `set superusers`만으로는 아무것도 증명하지 못하고(EL의 `01_users` 템플릿이 모든 grub.cfg에 그것을 내보냄) `${GRUB2_PASSWORD}`는 참조이지 해시가 아님; 그중 읽을 수 없는 파일은 읽기의 상태(C3) |
| `mounts` | `mounts.points`(`subject_kind: mount`) | `list<record>` | `/proc/self/mountinfo`(3A의 `parseMountinfo`를 필드 6의 마운트별 옵션과 source를 남기도록 확장)로 후보 `/`, `/boot`, `/home`, `/tmp`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit`, `/dev/shm`마다 한 행: `target`, `separate`(정확히 그 target에 마운트가 있음), `mounted_by`(그것을 담는 마운트 — `separate`면 target 자신), `source`, `fstype`, `options`(`list<string>`); 별도가 아닌 행의 `source`·`fstype`·`options`는 `mounted_by`의 것이라 행이 오늘 그 경로를 지배하는 것을 말함. 영속 마운트(`/etc/fstab`, `.mount` 유닛)는 3B에서 읽지 않음: 판정하는 컨트롤이 없음 |
| | `mounts.tmp.separate`, `mounts.var_tmp.separate`, `mounts.dev_shm.separate`, `mounts.home.separate` | `bool` | 행의 `separate`와 같은 사실을 leaf로, 메커니즘이 문지기로 쓸 수 있게(B-1) |
| `modules` | `kernel.modules`(`subject_kind: module`) | `list<record>` | 후보 `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `usb-storage`, `dccp`, `sctp`, `rds`, `tipc`마다 한 행: `name`, `loaded`(`/proc/modules`), `builtin`(`/usr/lib/modules/<release>/modules.builtin`; `/lib/modules`는 `/lib`가 실제 디렉터리일 때만 — merged-`/usr` 호스트에서는 심링크이고, `/usr/lib/modules`가 없는 컨테이너 이미지는 링크에 걸려 넘어지는 대신 트리를 `unsupported`로 보고), `available`(`modules.dep`), `blacklisted`(`blacklist <name>` 줄), `install_disabled`(`install <name> /bin/false` 또는 `/bin/true`), `disabled`(파생: `!loaded && !builtin && (install_disabled || !available)`), `sources`(`list<string>`: 그 모듈을 언급하는 modprobe.d 파일들, `builtin`이면 감시자 값 `built into the kernel` 하나 추가); `modules.dep`의 이름은 `.ko`, `.ko.zst`, `.ko.xz`, `.ko.gz` 접미를 떼고 비교; modprobe.d는 `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, `/lib/modprobe.d` 이 우선순위(kmod의 순서)로, `.conf` 파일만, modprobe.d(5)대로 이름으로 가림; 모듈 이름은 `-`와 `_`를 접어서 비교 |
| `swap` | `swap.present` | `bool` | `/proc/swaps`에 행이 있음 |
| | `swap.devices` | `list<record>` | `path`, `type`(`file` \| `partition`), `encrypted`, `backing`(판정의 근거가 된 블록 장치) |
| | `swap.encrypted` | `bool` | 모든 장치가 dm-crypt 위일 때 true: 장치(스왑 파일이면 그것을 담는 마운트의 소스 장치)의 `/sys/block/<dev>` 링크를 읽고 — 거기의 항목은 전부 심링크 — 대상이 `devices/virtual/block` 아래이면 `slaves/`를 따라 내려가 `dm/uuid`가 `CRYPT-`로 시작하는 장치(암호화)나 링크가 물리 장치를 가리키는 장치(비암호화)에 닿을 때까지; 담는 마운트의 소스가 블록 장치 노드가 아닌 스왑 파일(컨테이너의 `overlay`, 클라우드 이미지의 `/dev/root`)은 소스를 이름 짓는 `unsupported`이지 결코 오류가 아님 — 스톡 "암호화 LVM" 배치는 스왑이 `LVM-` 볼륨 위에 있고 그 slave가 `CRYPT-` 장치; `backing`은 판정이 내려진 장치; `/sys/block/zramN/backing_dev`가 `none`인 zram은 메모리라 `backing: zram`으로 암호화로 침; 스왑이 없으면 `absent` |

**B-3 — `/proc/sys`를 직접 읽고, 판정은 runtime 쪽을 읽는다.** `sysctl` 바이너리도,
선언의 명령도 없습니다. `default_on: effective`(= runtime)는 sysctl에 `both`를 이름 짓는
메인 설계 §5.3에서 벗어납니다: 커널이 컴파일해 넣는 값 — Ubuntu의 `dmesg_restrict`,
어디서나 `protected_symlinks` — 은 persisted 줄이 아예 없어서, `both`라면 되돌아가지도
않는 설정에 대해 모든 호스트에서 "재부팅 시 되돌아감" WARN을 낼 것입니다. persisted
쪽은 봉투 안의 증거이며, D29가 이 이탈을 기록합니다. 존재하지 않는
`/proc/sys/kernel/yama/ptrace_scope`(Yama 미빌드)는 경로와 함께 `absent`이고, 4.19 이전
커널의 `fs/protected_fifos`도 그렇습니다. 정수로 파싱되지 않는 값은 경로와 바이트를 이름
짓는 `error`입니다. 파일 열둘 중 다섯(`net/core/bpf_jit_harden`과 `fs/protected_*` 넷)은
lab의 커널에서 0600이라 root 없이는 runtime 쪽이 `denied`입니다; capability matrix의
`nonroot` 행이 그 다섯을 적고 컨트롤 3과 4는 비root 실행에서 ERROR입니다. persisted
쪽은 leaf의 effective 값을 결코 정하지 않습니다 — runtime 값이 `sysctl.d`에서 어긋난
호스트가 바로 두 집이 보이게 하는 것입니다.

**B-4 — 모듈은 `modprobe`가 아니라 파일로 정한다.** `modules.builtin`은 모듈을
블랙리스트할 수 없음을, `modules.dep`은 로드될 수 있는지를, `/proc/modules`는 로드됐는지를,
modprobe.d는 관리자가 무엇을 했는지를 말합니다. 트리가 모르는 모듈(`available` false,
`builtin` false)은 부재로 비활성이며 통과합니다. 내장 모듈은 modprobe.d가 무엇을 말하든
`disabled` false입니다 — 공식의 `!builtin` 항이 그것인데, 내장은 `/proc/modules`에 결코
없어서 `install … /bin/false` 줄만 있으면 통과해 버릴 것이기 때문입니다 — 그리고
`sources` 항목이 `built into the kernel`을 말합니다; 컨트롤은 그 행을 실패시키고 조치
문구는 재빌드나 면제만이 길이라고 말합니다. 모듈 트리(`/usr/lib/modules/<release>`)가 없으면(컨테이너,
모듈을 지운 커널) `kernel.modules` 봉투 전체가 경로와 함께 `unsupported`입니다 — 절반만
아는 행의 목록은 결코 아닙니다.

## 3. 컨트롤 (B-5 … B-8)

**B-5 — 위험 단위로 묶은 컨트롤 19개, 모두 `category: beyond`, id `muster.beyond.<name>`,
파일은 `controls/beyond/` 아래.** `importance`는 1차 출처와 규칙이 있는 곳의 STIG
심각도(CAT I ≈ 상, II ≈ 중, III ≈ 하)로 muster가 매기고, 모든 설명이 그 이유를 한 문장으로
말합니다. `references.stig`는 규칙이 맞는 곳에서 인덱스(`docs/reference/stig`)를 인용하고,
`references.cis`는 비워 둡니다 — 벤치마크 자신의 매핑에서 옮긴 번호는 독립 유도가 아닙니다 —
`references.nist_800_53`은 STIG 인덱스를 따릅니다. `references.kisa`는 없으며 커버리지
lint는 이를 허용하고(인용된 항목만 셈), 새 lint 규칙이 두 범위를 배타적으로 만듭니다:
`category: beyond`인 것과 `references.kisa`가 없는 것은 동치. `coverage.md`에 "Beyond the
guide" 표가 생깁니다. STIG 인덱스는 제목만 담으므로 `references.stig` 항목은 제목으로
맞추며, grub.cfg에는 소유자·그룹 규칙만 있고 모드 규칙은 없습니다 — 컨트롤 8의 0600은
grub-mkconfig 자신의 umask 077에 근거하며 설명에 인용합니다.

19개 전부 `applies_when: [{fact: env.container, op: eq, expected: none}]`을 갖습니다:
컨테이너 안에서 이 팩트들은 호스트를 묘사하며, 컨테이너는 그것을 바꿀 수도 책임질 수도
없습니다(§5).

| # | 컨트롤 | 중요도 | 판정 |
|---|---|---|---|
| 1 | `kernel_pointer_exposure` | 중 | `kptr_restrict in [1, 2]`; `dmesg_restrict eq 1`; `absent_means: fail` |
| 2 | `ptrace_restriction` | 중 | `yama_ptrace_scope in [1, 2, 3]`; `perf_event_paranoid gte 2`; `absent_means: fail`(Yama 없는 커널에는 ptrace 범위 자체가 없음; §6.5의 선별이 첫 absent 팩트에서 컨트롤 전체를 해소하므로 그때 나머지 절은 증거일 뿐) |
| 3 | `unprivileged_bpf_restricted` | 하 | `unprivileged_bpf_disabled in [1, 2]`; `bpf_jit_harden in [1, 2]`; `absent_means: not_applicable`(BPF 시스템콜이나 JIT 없이 빌드된 커널에는 제한할 것이 없음). `bpf_jit_harden`은 기본 0이고 스톡 Ubuntu·EL9의 어떤 sysctl.d도 정하지 않아 모든 스톡 호스트가 이것에 실패합니다 — 실제 KSPP 약점이며, 컨트롤 2를 물들이지 않도록 따로, 낮게 둠 |
| 4 | `aslr_and_link_protection` | 상 | `randomize_va_space eq 2`; `protected_symlinks eq 1`; `protected_hardlinks eq 1`; `protected_fifos in [1, 2]`; `protected_regular in [1, 2]`; `absent_means: fail` |
| 5 | `sysrq_restricted` | 중 | `sysrq in ${allowed_sysrq}`, 기본 `[0]`; `absent_means: fail`; 설명이 배포판 기본(Ubuntu 176, Debian 438, EL 16)과 그중 하나를 허용하는 파라미터를 이름 지음 |
| 6 | `core_dump_policy` | 중, `partial` | `coredump.core_pattern`에 대한 메커니즘 넷, 첫 일치가 이김: (a) `matches ^\|.*systemd-coredump` → `coredump.systemd.storage eq none` 그리고 `coredump.systemd.process_size_max eq 0`; (b) `matches ^\|/bin/(false\|true)( \|$)` — 비활성 패턴에 대한 STIG 자신의 조치 — → 구성상 성립하는 검사(`core_pattern matches ^\|/bin/`), PASS; (c) `not_matches ^\|` → `coredump.limits.hard_core eq 0`; (d) 그 밖의 파이프(apport 등) → 구성상 실패하는 검사 하나 `core_pattern not_matches ^\|`, 그래서 `partial` 컨트롤이 패턴을 증거로 WARN을 읽음 — 검사 없는 메커니즘은 PASS가 될 것. `absent_means: manual`: systemd coredump 파일이 아무것도 정하지 않고 limits 줄도 없는 호스트는 코어덤프에 대해 아무것도 결정하지 않은 것 — systemd 자신의 기본값이 덤프를 저장함 — 이며 `partial` 아래서 그것은 검토 항목이지 muster가 데몬의 기본값으로 지어내는 판정이 아님 |
| 7 | `suid_dumpable_disabled` | 중 | `coredump.suid_dumpable eq 0`; `absent_means: fail` |
| 8 | `bootloader_config_permissions` | 상 | `boot.grub_cfg.mode in` 0600의 부분집합(`params.allowed_modes`), `uid eq 0`, `gid eq 0`; `absent_means: not_applicable`(grub.cfg 없음: 다른 부트로더거나 없음); `denied` stat(root 없는 EL)은 ERROR, 결코 NOT_APPLICABLE이 아님 |
| 9 | `bootloader_password` | 중 | `boot.grub_password_set eq true`(리터럴 `grub.pbkdf2.` 해시이지 템플릿의 `set superusers`가 아님); `absent_means: not_applicable`; `denied` 읽기(root 없이 EL의 0600 grub.cfg)는 모든 denied 팩트처럼 ERROR |
| 10 | `secure_boot_enabled` | 중 | `applies_when`에 `boot.firmware eq uefi`도; `boot.secure_boot eq true`; `absent_means: manual`(efivarfs나 변수가 없는 UEFI는 여기서 읽을 수 없음) |
| 11 | `separate_partitions` | 중, `partial` | `mounts.points` `each`, `subject: target`, `where target in ${required_separate}`(기본 `[/tmp, /var, /var/tmp, /var/log, /var/log/audit, /home]`), `require separate eq true`; `absent_means: not_applicable`; 파티션은 설치 시점의 결정이라 WARN |
| 12 | `tmp_mount_options` | 중 | 메커니즘 하나 `when mounts.tmp.separate eq true`: `mounts.points each where target eq /tmp require options contains nodev`, `nosuid`, `noexec`도 같게; 메커니즘 없음 → 평가기의 사유("no mechanism applies to this host")로 NOT_APPLICABLE; 설명이 그런 호스트의 결함은 컨트롤 11이라고 말함 |
| 13 | `var_tmp_mount_options` | 중 | `/var/tmp`에 대해 12와 같음 |
| 14 | `dev_shm_mount_options` | 중 | `/dev/shm`에 대해 12와 같음; 모든 systemd 호스트가 이를 `nosuid,nodev`만 있고 `noexec` 없는 별도 tmpfs로 마운트하므로 스톡 호스트는 이것에 실패 |
| 15 | `home_mount_options` | 하 | `/home`에 대해 12와 같되 `nodev`, `nosuid`만; EL9 기본 배치는 `/home`에 둘 다 없는 자체 볼륨을 주므로 스톡 EL은 실패 |
| 16 | `swap_encrypted` | 중 | `swap.encrypted eq true`; `absent_means: not_applicable`(스왑 없음) |
| 17 | `uncommon_filesystems_disabled` | 하 | `kernel.modules each`, `subject: name`, `where name in [cramfs, freevxfs, jffs2, hfs, hfsplus, udf]`, `require disabled eq true`; `absent_means: fail`(17–19) |
| 18 | `usb_storage_disabled` | 중 | `usb-storage`에 대해 17과 같음 |
| 19 | `uncommon_network_protocols_disabled` | 중 | `dccp`, `sctp`, `rds`, `tipc`에 대해 17과 같음 |

**B-6 — 마운트 옵션 컨트롤은 행이 아니라 leaf로 문을 연다.** `applies_when`은 행을 읽지
못하고, `/tmp` 행을 못 찾은 `each`는 통과합니다. 그래서 수집기가
`mounts.<point>.separate`를 leaf로도 쓰고, 메커니즘의 `when`이 그것을 읽으며, 별도
`/tmp`가 없는 호스트는 NOT_APPLICABLE이 됩니다; 설명이 컨트롤 11을 가리키며 그 호스트의
결함은 거기에 있습니다.

**B-7 — 모듈이 "비활성"이라는 뜻.** 모듈을 비활성화하는 것은 `install <name> /bin/false`
(또는 `/bin/true`)입니다; `blacklist <name>`은 별칭에 의한 자동 로드만 막으므로 기록만
하고 인정하지 않습니다. 로드된 모듈은 결코 비활성이 아닙니다. 트리가 배포하지 않는
모듈은 부재로 비활성입니다. 내장 모듈은 비활성화할 수 없고, 실패하며, 그렇게 말합니다.

**B-8 — 파라미터.** `allowed_sysrq`(list<int>, `[0]`), 컨트롤 8의 `allowed_modes`
(`[0600, 0400, 0200, 0000]` — 기존 권한 컨트롤이 "≤ 0600"을 적는 방식), `required_separate`
(list<string>). 그 밖에는 조정할 수 없습니다; 조정해야 할 값은 프로필의 일(3D)입니다.

## 4. 리포트: 두 범위 (B-9)

**B-9 — beyond는 기본으로 돌고, 요약이 어느 쪽인지 말하며, 종료 코드는 바뀌지 않는다.**
메인 설계의 결정 D29.

- `summary`는 기존 필드를 기존 의미 — 모든 컨트롤에 대한 합계 — 그대로 유지하므로 오늘
  이를 파싱하는 소비자는 같은 숫자를 읽습니다. `scopes: {guide: {...}, beyond: {...}}`가
  더해지고, 각각 `controls`(개수), 심각도별 `automatic`, `manual_review`, `undecidable` —
  최상위와 같은 세 부분 — 을 갖습니다. `beyond`는 `category: beyond`인 모든 컨트롤,
  `guide`는 그 밖의 모든 컨트롤 — 술어 하나이므로 둘 다에 들거나 어디에도 안 드는 것이
  없고, B-5의 lint 규칙이 카테고리와 KISA 참조를 나란히 유지합니다; 둘의 합은 최상위와
  같고 테스트가 그렇게 말합니다. `scopes`는 필드 순서가 고정된 구조체이지 결코 맵이
  아닙니다(D20).
- 행은 (scope, severity, id)로 정렬합니다: 가이드가 먼저, beyond가 뒤 — 따라서 높은 beyond
  행이 낮은 가이드 행 뒤에 찍히며, 그것이 분리의 요점입니다. 기존 출력에는 beyond 행이
  없으므로 바이트가 움직이지 않고 순서 때문에 재생성되는 골든은 없습니다. 결과 행에 새
  필드는 없습니다 — `category`가 이미 `beyond`를 말합니다.
- 테이블 요약 블록에 두 줄이 더해집니다: `KISA 2026 (68 controls): pass … fail … warn …
  manual … n/a … error …`와 `beyond the guide (19 controls): …`(개수는 리포트 결과 기준),
  그리고 표시되는 첫 beyond 행 앞에 구분선 한 줄 `— beyond the guide —`. 테이블 골든은
  정확히 그 줄들만큼 바뀌고, 재생성하는 커밋이 그렇게 말합니다.
- 종료 코드는 원래의 계약입니다: ERROR 하나라도 → 2, FAIL 하나라도 → 1. 가이드 밖의
  FAIL도 FAIL입니다. README와 CHANGELOG가 각각 한 문장으로 이를 말하며, KISA만 쓰는
  사용자에게 선택을 주는 것은 여기 더하는 플래그가 아니라 프로필(3D)입니다.

## 5. 환경 (B-10)

**B-10 — beyond 컨트롤은 호스트 컨트롤이다.** 컨테이너 안에서는 19개 전부
`env.container`에 대한 `applies_when`으로 NOT_APPLICABLE입니다: 커널 sysctl은 호스트의
것이고, `/boot`는 컨테이너의 것이 아니며, 마운트와 스왑은 호스트의 배치이고,
`/lib/modules` 없는 모듈 목록은 목록이 아닙니다. 수집기는 그래도 거기서 돌며 증거를
씁니다: `kernel.modules`는 빠진 모듈 트리를 이름 짓는 `unsupported`, `swap.encrypted`는
overlay 소스를 이름 짓는 `unsupported`(capability matrix의 `container` 행에 둘 다 추가되고
CI 컨테이너 매트릭스가 검사), `boot.firmware`는
`/sys/firmware/efi`가 말하는 대로(UEFI 호스트의 컨테이너는 그것을 봄), `boot.grub_cfg.*`는
`absent`, `mounts.points`는 컨테이너 자신의 mountinfo로.

root 없이도 여기의 읽기는 대부분 됩니다 — efivars, `/proc/swaps`, `modprobe.d`, 모듈
트리, 그리고 `/proc/sys` 파일 열둘 중 일곱은 누구나 읽습니다 — 예외가 둘입니다. B-3의
0600 sysctl 파일 다섯은 `denied`이므로 컨트롤 3과 4는 root 없이 ERROR이고 capability
matrix의 `nonroot` 행이 그 다섯 키를 적습니다. EL에서는 `/boot/grub2`가 0700이라
grub.cfg의 stat조차 거부됩니다: 모든 `boot.grub_cfg.*` leaf와 `boot.grub_password_set`
(0600인 `user.cfg`도 읽음)이 `denied`이고 컨트롤 8과 9는 ERROR입니다 — 다음 후보로
넘어갔더라면 나왔을 NOT_APPLICABLE은 결코 아닙니다. Ubuntu는 `/boot/grub`와 grub.cfg를
읽을 수 있게 배포하므로 러너의 비root 잡이 읽습니다; capability matrix는 배포판별
`denied`를 표현할 수 없으므로 두 컨트롤의 설명이 그 문장을 담습니다. CI 컨테이너 스텝이
Rocky·Alma init 이미지 안에서 비root `collect`를 한 번 돌려 그 `denied` 상태를 단언하며,
그것이 EL 경로를 증명합니다 — 이미지가 싣지 않는 모양(`/boot/grub2` 0700과 그 안의 0600
grub.cfg)을 먼저 놓고 나서, root 잡이 sshd drop-in을 쓰는 방식 그대로.

systemd 없이는 아무것도 바뀌지 않습니다: `coredump.systemd.*`가 `absent`이고 그런
호스트의 `core_pattern`은 systemd 파이프가 아니므로 컨트롤 6은 메커니즘 (c)나 (d)로 갑니다.

BIOS 기계에서는 `boot.firmware`가 `bios`, `boot.secure_boot`가 `absent`, 컨트롤 10이
NOT_APPLICABLE입니다; UEFI인데 Secure Boot가 꺼져 있으면 실패하며 그것이 사실입니다.
`--deep`은 여기 어디에도 필요 없습니다: `mounts`는 mountinfo만 읽습니다.

스톡 lab 호스트(VMware 위 Ubuntu 22.04, BIOS, 평문 스왑 파일, 별도 `/tmp`·`/var` 없음,
sysrq 176, `suid_dumpable` 2, apport의 core pattern, 배포판 블랙리스트만)의 예상 판정:
1 PASS, 2 PASS, 3 FAIL(`bpf_jit_harden` 0), 4 PASS, 5 FAIL(176), 6 WARN(apport 파이프),
7 FAIL(2), 8 FAIL(0644), 9 FAIL, 10 NOT_APPLICABLE, 11 WARN, 12–13 NOT_APPLICABLE,
14 FAIL(`/dev/shm`에 `noexec` 없음), 15 NOT_APPLICABLE, 16 FAIL, 17–19 FAIL. 이 표가 실제
호스트에서 수집기에 대한 계획의 수용 테스트입니다.

## 6. 테스트·CI·문서 (B-11, B-12)

**B-11 — 3F의 문지기가 문지기다.** 모든 컨트롤에 `pass-`, `fail-`, `na-` 픽스처(컨테이너,
BIOS, 스왑 없음, 별도 마운트 아님)가 있고 `partial` 둘에는 WARN 픽스처가 있습니다; 변이
테스트는 생존 0을 유지해야 하며 동치 변이체는 이유와 함께 `_mutants.yaml`에 갑니다. §5의
스톡 호스트를 담은 합성 스냅샷 하나를 끝까지 검사해 19개 판정을 한 번에 고정합니다.
새 파서 — sysctl.d, modprobe.d, limits, coredump.conf, modules.builtin과 modules.dep,
`/proc/swaps`, grub.cfg 스캔 — 는 모두 시드 있는 `Fuzz<Name>` 타깃을 얻고 인벤토리
테스트가 이를 강제합니다. 새 오라클 한 쌍: 12개 키에 대한 `sysctl -n <key>` 대 runtime
leaf, 기존 오라클 스텝의 `MUSTER_ORACLE=1` 아래. 수집기는 `memAccess`로 존재/부재/거부/
잘림 경로를 단위 테스트하고, lab 호스트에서 §5의 표와 대조하고, 공개 Rocky 9 init
컨테이너에서 NOT_APPLICABLE 경로를 증명하며, 러너의 root 잡이 실물을 판정합니다.
리포트의 불변식(scopes의 합 = 전체)과 (scope, severity, id) 순서에 테스트가 있고, JSON과
테이블 골든은 요약 줄 때문에 한 번 재생성합니다.

**B-12 — 문서와 3A 인계 둘.** 메인 설계에 D29와 §9(`scopes`)·§10.2(3B 병합)의 문장;
README(두 언어)의 카운트 문장 — "67항목에 대한 68개 컨트롤, 그리고 가이드 밖 19개" — 과
로드맵 줄; CHANGELOG의 Controls(19개, `controls/VERSION` → `kisa-unix-2026+2026.09.18`,
종료 코드 문장), Collectors(6개), Tooling(`scopes`, coverage 표); CONTRIBUTING(두 언어)에
짧은 "가이드 밖 컨트롤" 규칙 — 1차 출처, CIS 번호 없음, 중요도 문장, 컨테이너 문지기;
CLAUDE.md 한 줄; `coverage.md` 재생성. 커밋된 예시는 풀 리퀘스트에서 `examples.yml`을
수동 실행해 갱신합니다(컨트롤 세트가 바뀌므로 아니면 digest 게이트가 바이트 비교를
건너뜀). 3A에서: `subject_kind` 없는 record-list 팩트 넷 중 셋(`files.user_rhosts`,
`files.env_files`, `files.dev_nondevice`)에 `file`을 부여 — 관찰의 subject가 `item:`에서
`file:`로 바뀌고, 그 subject를 부르는 waiver 키도 함께 바뀌므로 계약 변경입니다: D29가
이를 실으며 CHANGELOG는 `muster.x#item:/path`로 쓴 waiver가 `#file:/path`가 되어야 한다고
말하고, 팩트 골든을 재생성합니다. `env.shell.root_path_entries`는 `item:`을 유지합니다 —
그 subject는 위치이고 `dir:2`는 오해를 부릅니다; U-23의 설명에 `/etc/passwd` 밖 계정의
rootless 컨테이너 저장소에 대한 문장.

## 7. 보류

- 네트워크 sysctl, `/var*` 마운트 옵션, squashfs, 커널 명령행: §1.
- 가이드만, 또는 beyond만 돌리는 프로필: 3D. 그때까지 두 범위는 보이고 종료 코드는 둘 다
  셉니다.
- 영속 마운트(`/etc/fstab`, `.mount` 유닛)를 증거로, 그리고 "재부팅을 견딤" 규칙;
  `kernel.kexec_load_disabled`와 `systemd-coredump.socket` 마스킹(둘 다 STIG 인덱스에 있음)
  — 커널·코어덤프 컨트롤의 자연스러운 다음 행.
- beyond 컨트롤의 `references.cis`: 벤치마크 자체 문장과 독립적으로 1차 출처에서 유도한
  매핑일 때만; 여기서는 아무것도 주장하지 않습니다.
