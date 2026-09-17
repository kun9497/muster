# Stage 3A — 심층 파일시스템 워크

*[English](2026-09-16-stage3a-walk-design.md) · 한국어*

이 문서는 muster 계획 3A의 설계입니다. 본 설계(`2026-09-02-muster-design.ko.md`, §5 "워크", §5.8,
§6.5의 9–10a행, §10.2 "3단계")가 자리만 잡아 둔 `--deep` 파일시스템 워크와, 그 워크에 기대는
KISA 항목 넷을 다룹니다. 2026-09-15에 합의한 3단계 하위 프로젝트 — 3A 워크, 3B 커널·부트·
마운트, 3C 감사·노출·root 등가 경로(그리고 패키지 검증, W-8), 3D 프로파일과 튜닝, 3E `fix
--dry-run`, 3F 뮤테이션 테스트와 퍼징(3F는 3A와 병행 가능) — 중 첫 번째입니다. 결정은 W-1 …
W-12로 번호를 붙이며 계획을 구속합니다. 2026-09-16의 신선한 검토 두 번(36건, 18건)을 접어
넣었고, 초안과 다른 곳은 그 검토의 결과입니다.

## 1. 목표

파일시스템 순회가 필요한 KISA 2026 Unix 항목 셋 — U-15(유효한 소유자가 없는 파일·디렉터리),
U-23(SUID/SGID/sticky bit), U-33(숨겨진 파일·디렉터리) — 을 등재하고, 1단계부터 등재되어 있으나
워크가 없어 `MANUAL`로만 읽히던 U-25(world-writable 파일)가 실제 호스트를 판정하게 합니다. 3A
이후에는 67개 항목 전부에 컨트롤이 있습니다(새 컨트롤 넷, 64 → 68). 커버리지는 "67 of 67 items
enrolled"가 되고, `kisa_deferred.json`은 비며, README 로드맵 문장도 그에 맞게 바뀝니다.

3A 범위 밖: 패키지 검증(`rpm -V` / `dpkg --verify`, `--verify-packages` 플래그, `walk.package_verify`
키). 실행마다 달라지는 패키지명 꼬리를 화이트리스트할 수 있는 가드(`CommandTemplate`)가 필요하고
3A에는 그 출력을 판정하는 컨트롤이 없으므로 전부 3C 몫입니다(W-8). 워크 안의 파일 capability·ACL
(3C, 컨트롤이 필요로 할 때), 프로파일(3D), KISA 밖 점검의 워크 활용(3B/3C가 `walk.*`를 근거로 씀).

## 2. 순회, 경계, 예산 (W-1, W-2, W-3)

**W-1 — 워크는 수집기이며 기본은 꺼짐.** `walk`가 `internal/collect/collectors/walk.go`의 1단계
자리표시자를 대체합니다. `collect --deep`일 때만 돌고, 플래그가 없으면 지금처럼 아무 키도 쓰지
않아 U-25와 새 컨트롤 넷은 `MANUAL`("run collect --deep", 본 설계 §6.5 9행)로 읽힙니다. `--deep`을
주면 워크가 이후 거부되거나 실패했더라도 `run.deep`은 `true`이므로, 읽는 쪽이 "요청하지 않음"과
"요청했으나 못 함"을 구별할 수 있습니다. root가 필요하며(`Needs: "root"`), 비root에서는 수집기가
키 하나 `walk.complete`만 `denied("the walk needs root")`로 쓰고 `nil`을 돌려줍니다. 수집기 상태는
팩트에서 유도되어(`denied`) 실행은 partial, `collect`는 exit 1 — root가 필요한 다른 모든 수집기와
같습니다(R56/R71). `ErrSkipped`도 `callRun` 변경도 없습니다. 그러면 이 스펙과 함께 추가한 본 설계
§6.5 10a행이 워크 기반 컨트롤을 모두 거부를 명시한 `ERROR`로 만들며, 운영자가 이미 따른 "run
collect --deep" MANUAL은 나오지 않습니다.

**W-2 — 경계.** 첫 디렉터리를 열기 전에 `/proc/self/mountinfo`(선언됨)를 읽어 들어갈 마운트
집합을 **로컬 유형의 긍정 목록**으로 만듭니다: `ext2`, `ext3`, `ext4`, `xfs`, `btrfs`, `f2fs`, `jfs`,
`reiserfs`, `zfs`, `tmpfs`, `ramfs`, `vfat`, `exfat`, `ntfs`, `ntfs3`, `iso9660`, `udf`, `erofs`. 그
밖의 유형 — `nfs`, `nfs4`, `cifs`, `smb3`, `fuse`, `fuseblk`, `fuse.*`, `sshfs`, `afs`, `9p`, `ceph`,
`glusterfs`, `lustre`, `gfs2`, `ocfs2`, `nfsd`, `overlay`, `squashfs`, `autofs`, `devtmpfs`, `proc`,
`sysfs`, `cgroup*`, `bpf`, `tracefs`, `debugfs`, `securityfs`, `pstore`, `configfs`, 그리고 목록에 없는
모든 유형 — 은 들어가지 않습니다(모르는 유형은 건드리지 않는 쪽으로 틀립니다). `tmpfs`는
일부러 목록에 있습니다. `/tmp`와 `/var/tmp`가 U-25와 U-23의 sticky 절반이 사는 곳입니다. 유형과
무관하게 경로로 제외: `/proc`, `/sys`, `/dev`, `/run`. **bind 별칭**은 여기서, mountinfo만으로
정합니다. 두 마운트가 `major:minor`를 공유하고 한쪽의 `root`가 다른 쪽의 `root`와 같거나 그 아래면
별칭이며, 진입하는 별칭은 `root`가 `/`인 것, 다음은 마운트 지점이 가장 짧은 것, 다음은 사전순으로
앞선 것(두 별칭 모두 `root`가 `/`일 때의 결정적 tie-break)이고, 나머지 별칭은
첫 디렉터리를 열기 전에 `walk.skipped[]`에 `bind_duplicate`로 쓰이고 그 마운트 id는 진입 집합에서
빠집니다. 컨테이너·VM·chroot 저장소로서 제외: overlay 아래 계층이 루트 파일시스템에 있고 외부
uid와 자체 setuid 파일을 담기 때문입니다. 고정 집합 `/var/lib/docker`, `/var/lib/containerd`,
`/var/lib/containers`, `/var/lib/lxd`, `/var/lib/lxc`, `/var/snap`, `/var/lib/libvirt/images`,
`/var/lib/machines`, `/var/lib/mock`, `/var/cache/pbuilder`, `/var/lib/schroot`, `/var/lib/kubelet`,
`/var/lib/rancher`, `/var/lib/k0s`, `/var/lib/cni`. 고정 집합의 경로가 그 자체로 심링크이면
(`/var/lib/docker -> /data/docker`는 `data-root`만큼 흔함) `readlink`(선언됨; 워크는 여전히 따라가지
않음)가 대상을 알려 주고, 대상이 링크 경로를 사유에 담은 `container_storage`로 집합에 들어갑니다.
여기에 호스트에 설정된 루트 — 워크가 `/etc/docker/daemon.json`(`data-root`),
`/etc/containers/storage.conf`(`graphroot`, `rootless_storage_path`), `/etc/containerd/config.toml`
(`root`)을 선언하고 읽음 — 와, W-4에서 홈으로 치는 모든 홈 디렉터리의
`<pw_dir>/.local/share/containers`, `<pw_dir>/.local/share/docker`가 더해집니다. 존재하지만 읽을 수
없는 설정 파일은 루트가 아닙니다. `walk.stats.config_unreadable`(`[{path, status}]`, 고정 순서)에
기록하고, 고정 집합은 그대로 적용하며, U-15/U-23 설명이 워크가 알아내지 못한 설정 루트는 발견으로
떠오를 수 있다고 말합니다. 플래그 둘이 목록을 조정합니다. `--walk-exclude <경로>`(반복 가능)는
루트를 더하고, `--walk-include <경로>`(반복 가능)는 고정 컨테이너 저장소 집합의 항목만 되살립니다.
그 밖의 값(`/proc`, 원격 마운트, 임의 경로)은 플래그를 명시해 거부하므로 일반 override가 될 수
없습니다.

워크가 들어가지 않은 모든 루트는 `walk.skipped[]`의 한 행 `{path, reason}`이며, `reason`의 닫힌
어휘는 하나뿐이고 §2·§7·테스트가 같은 것을 씁니다: `excluded_type`(긍정 목록에 없는 유형의
마운트; 유형은 사유에), `pseudo_path`(경로 넷), `container_storage`(고정 집합, 심링크 대상, 설정된
루트, 홈별 루트), `excluded_by_flag`, `bind_duplicate`(mountinfo 별칭, 또는 이미 방문한 `(dev, ino)` —
마지막 방어선), `denied`(디렉터리를 여는 EACCES/EPERM), `vanished`(나열과 열기 사이의
ENOENT/ENOTDIR/ELOOP, 또는 열고 난 뒤 정체 불일치), `unlisted_mount`(mountinfo에 없던 마운트 id를
순회 중에 만남 — automount가 발화함). `walk.skipped`는 10,000행에서 상한을 두고 그 너머는
`truncated: true`이므로, 막힌 트리가 스냅샷 크기 상한에 다가갈 수 없습니다.

**W-3 — 순회 프리미티브와 가드.** `filepath.WalkDir`는 no-follow·마운트 경계·순환 규칙을 지킬 수
없으므로 새 읽기 프리미티브를 씁니다. `hostAccess.ReadDir(path) ([]DirEntry, error)`는 기존
`openNoFollow`로 디렉터리를 `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`로 열고, fd를 `fstat`해
부모가 나열한 항목의 `(dev, ino)`와 비교하며(불일치는 `vanished`이고 내려가지 않음 — 나열과 열기
사이의 rename이 다른 트리를 바꿔 넣을 수 없음), 항목을 나열하고, 각 항목을
`statx(dirfd, name, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_BASIC_STATS|STATX_MNT_ID)`로 보아
`{name, kind, mode, uid, gid, dev, ino, mnt_id, size}`를 돌려줍니다. `kind`는 기존 `kindOf` 어휘
(`regular, dir, symlink, socket, fifo, chardev, blockdev`)입니다. 심링크는 `symlink` 종류의 항목일
뿐 절대 따라가지 않습니다. autofs 마운트 지점은 부모가 나열만 하고 절대 열지 않으며,
`AT_NO_AUTOMOUNT`(4.11부터 `fstatat`의 커널 기본)가 나열이 마운트를 일으키지 않게 합니다. 마운트
경계는 `mnt_id`를 mountinfo의 첫 필드와 대조해 정합니다. btrfs 하위 볼륨과 순회 중 automount에서
`st_dev`는 틀리지만 이 방법은 정확합니다. 현재 마운트와 `mnt_id`가 다른 항목은 그 id가 W-2 진입
집합(별칭은 W-2에서 이미 빠짐)에 있을 때만 진입하고, mountinfo에 없는 id는 `unlisted_mount`입니다.
`STATX_MNT_ID`가 없는 커널(대상에는 없음 — Linux 5.8+)에서는 `st_dev`로 후퇴하고 `walk.stats`에
`mnt_id_fallback: true`를 기록합니다. 방문한 디렉터리의 `(dev, ino)` 집합은 여전히 순환을 끊으며,
걸리면 `bind_duplicate`입니다. `Access`에 `ReadDir`가 늘고, 모든 테스트 더블은 내장 가능한 기반
타입에서 그것을 얻어 `collectors_test.go`와 `cmd/muster`의 더블이 각각 메서드를 늘리지 않습니다.
가드에는 선언 종류가 하나 늘어납니다. `Declaration.Walk: true`는 그 수집기에 한해 어떤 경로에서든
`ReadDir`를 허용하고, 워크가 그 밖에 만지는 것에는 `Reads`·`Commands`의 정확 일치 의미가 그대로
적용됩니다. `Action.Kind`에 `walk`가 늘고 `ListActions`는 한 줄을 그립니다: `walk  every local
filesystem, no symlink followed, boundaries and exclusions as declared`. root인데 디렉터리에서
EACCES가 나는 일은 LSM으로 제한된 트리나 줄어든 capability bounding set에서만 실재하며, `denied`로
기록하고 워크는 멈추지 않습니다.

**예산과 데드라인.** 한도는 둘이며 둘 다 플래그입니다. `--walk-budget 10m`(벽시계 시간)과
`--walk-max-entries 2000000`. `--deep`은 `--timeout`을 따로 주지 않은 경우 기본 전역 `--timeout`
(오늘 5분)을 `--walk-budget + 5m`으로 올립니다. 유효 `--timeout`보다 큰 `--walk-budget`은 둘을
명시한 오류입니다. 워크는 디렉터리마다 `ctx.Done()`을 확인합니다. 한도를 넘으면 그 자리에서
순회를 멈춥니다. `walk.complete = false`, `walk.stats.stop_reason`은 `time_budget`, `entry_budget`,
`deadline` 중 하나, `walk.stats.last_path`는 읽고 있던 디렉터리. `deadline`이면 수집기는
`ctx.Err()`도 돌려주어 다른 수집기처럼 `timeout`으로 기록됩니다. 그러면 본 설계 §6.5 10행에 따라
워크 기반 컨트롤은 모두 `ERROR(walk_incomplete)`입니다. 절반만 본 파일시스템으로는 PASS도 FAIL도
내지 않습니다. **가득 찬 발견 리스트는 워크를 멈추지 않습니다**(본 설계 §5.8). 리스트마다 2,000건
상한이 있되 `walk.hidden`은 예외로, 허용 목록 밖 행 10,000건과 별도로 허용된 행을 최대 2,000건
담습니다(그 이상의 허용된 항목은 `walk.stats.allowlisted_hidden`으로 세기만 하고 `truncated`를
세우지 않음). 개발용 호스트의 Node 트리가 허용된 행만으로 리스트를 상한까지 밀어 올릴 수 없게
하기 위해서입니다. 판정 대상 행이 상한에 닿은 리스트는 `truncated: true`로 쓰며 순회는 세면서
계속됩니다. `walk.stats.truncated_counts`는 W-4 순서로 리스트당
정수 필드 하나씩을 가진 **레코드**(`suid_sgid, suid_sgid_unverified, world_writable, sticky_missing,
unowned, hidden, skipped`)이지 map이 아닙니다. 그러면 본 설계 §6.5 6행이 그 리스트를 읽는
컨트롤에만 `ERROR(truncated)`를 줍니다. `walk.complete`는 순회만 반영합니다. 워크 고루틴은
`runtime.LockOSThread()`를 부른 뒤 무조건, 최선 노력으로 `setpriority(PRIO_PROCESS, 0, 10)`과
`ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE)`을 호출합니다. 결과는 `walk.stats`의 불리언
둘(`nice_applied`, `ioprio_applied`)이고, `/sys`는 읽지 않으며, 어느 실패도 워크를 중단시키지
않습니다. 본 설계 §8의 "I/O 스케줄러가 존중하는 곳에서"는 "최선 노력"으로 고칩니다.

## 3. 후보와 팩트 (W-4, W-5)

**W-4 — 조건 넷, `statx`만으로 판단.** 워크는 파일 내용을 열지 않습니다. `walk.unowned`는 심링크를
포함한 모든 항목을 보고(심링크에도 소유자가 있고 `find -nouser`가 보고함), 모드 기반 리스트 넷은
심링크가 아닌 모든 항목을 봅니다.

| 리스트 | 조건 | 레코드 필드 |
|---|---|---|
| `walk.suid_sgid` | setuid 또는 setgid가 있는 일반 파일, 검증 가능하게 판정됨(§4) | `path, mode, uid, gid, setuid, setgid, package, package_declared, declared_mode, declared_path, reference` |
| `walk.suid_sgid_unverified` | 위와 같으나 결합이 모드를 확인하지 못한 것(§4) | 같은 필드 |
| `walk.world_writable` (기존 키) | other-write가 있는 심링크 아닌 모든 항목 | `path, kind, sticky, uid, gid, package, package_declared, reference` (기존 필드 유지, `kind`·`package`·`reference` 추가) |
| `walk.sticky_missing` | other-write인데 sticky bit이 없는 디렉터리 | `path, mode, uid, gid` |
| `walk.unowned` | uid 또는 gid가 알려지지 않음(W-5); 모든 종류 | `path, kind, uid, gid, uid_known, gid_known, uid_class, gid_class` |
| `walk.hidden` | 이름이 `.`로 시작하고 홈의 dotfile로 면제되지 않음(아래) | `path, kind, uid, package, package_declared, reference, allowlisted` |

`walk.world_writable`은 모든 종류(`dir`, `socket`, `fifo`, 장치)를 담습니다. sticky bit은
디렉터리에서 의미가 있고, 기존 U-25 컨트롤과 그 픽스처(`/tmp`, `/var/tmp/legacy.sock`)와 본 설계
§6.4가 이미 그렇게 가정합니다. `walk.sticky_missing`은 U-23이 판정하는 디렉터리 부분집합이며 결합
필드를 갖지 않습니다(읽는 것이 없음).

**숨김 규칙의 홈.** 숨김 항목은 이름이 `.`로 시작하고 홈의 dotfile로 면제되지 않는 모든 순회
항목입니다. 홈은 두 종류입니다. **사용자 홈** — `/root`와 `/home` 아래의 모든 디렉터리 — 은 어느
깊이에서든 면제됩니다. 거기의 dotfile 트리(`~/.config/x/.y`)는 정상 상태입니다. **서비스 홈** —
`/etc/passwd`의 그 밖의 모든 `pw_dir`이되 `/`이거나 `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`,
`/libx32`, `/usr`, `/etc`, `/dev`, `/boot`, `/proc`, `/sys`, `/run`, `/tmp`, `/var/tmp`와 같거나 그
아래인 것은 제외 — 은 **직접 자식**인 숨김 항목만 면제합니다(`/var/lib/postgresql/.psql_history`는
정상). 서비스 홈 안 더 깊은 곳의 숨김 항목(`/var/www/html/.cache`, `/var/ftp/pub/.x`)은 기록합니다.
`www-data:/var/www`와 `ftp:/var/ftp`는 stock 계정이고 그 트리는 서비스되는 곳이지 사는 곳이
아니기 때문입니다. stock `/etc/passwd`는 RHEL 계열에 `nobody:/`, Debian 계열에 `daemon:/usr/sbin`을
담고 있어, 이것을 홈으로 치면 파일시스템 전체나 `/usr/sbin`이 보이지 않게 되므로 제외 목록이
있습니다. 워크가 쓴 홈 집합은 `walk.stats.home_roots`(`[{path, user, kind: user|service}]`, `path`
다음 `user` 순; 여러 계정이 공유하는 `pw_dir` — Debian 계열은 `_apt`, `messagebus`, `tcpdump`가
모두 `/nonexistent` — 은 계정마다 한 행, 존재하지 않는 `pw_dir`도 한 행, 접두 루트 `/root`와
`/home`은 각각 `user: ""`, `kind: user`로 한 번씩)에 기록되어, 읽는 쪽이 어떤 항목이 왜
기록되었거나 되지 않았는지 볼 수 있습니다. 워크는 숨김
디렉터리 안으로 여전히 내려가되 그 항목만 기록하고 자식은 기록하지 않습니다. 내장 허용 목록은
두 부분이며 줄마다 왜 정상인지 문서화합니다. 정확한 경로(`/.dockerenv`, `/etc/.pwd.lock`,
`/etc/.updated`, `/var/.updated`, `/etc/.resolv.conf.systemd-resolved.bak`, `/var/lib/rpm/.rpm.lock`
(비소속, RHEL 계열 모든 호스트에서 rpm이 만듦), systemd `tmpfiles.d/x11.conf`의 디렉터리 다섯 `/tmp/.X11-unix`, `/tmp/.ICE-unix`, `/tmp/.XIM-unix`,
`/tmp/.font-unix`, `/tmp/.Test-unix`, …)와 이름만(`.well-known`, `.git`, `.gitignore`, `.gitkeep`,
`.keep`, `.placeholder`, `.htaccess`, `.bin`, `.github`, `.npmignore`, `.eslintrc*`, …). 허용된 항목도
(자체 상한까지) `allowlisted: true`로 기록합니다. 목록은 보여 주지 숨기지 않습니다. `mode`는
`st_mode & 07777`의 정수 원값이며 `writePermFacts` 컨벤션과 같습니다.

**W-5 — 알려진 id.** `uid_known`은 "`/etc/passwd`에 있거나, `/etc/subuid`가 passwd 사용자에게
부여한 범위 안에 있거나, systemd 동적 사용자 범위 61184–65519 안에 있음"이고, `gid_known`은
`/etc/group`과 `/etc/subgid`에 대해 같습니다. 네 파일은 선언된 읽기입니다. `uid_class`/`gid_class`가
어느 쪽인지 말합니다: `passwd`, `subid`, `dynamic`, `unknown`. 수집기끼리 서로의 팩트를 읽을 수
없어 `accounts` 수집기의 passwd 파싱을 중복하지만 작은 파일 넷을 읽는 비용뿐입니다. 계정이 원격
NSS(sssd, ldap, winbind)에서도 오는 호스트에서는 원격에만 있고 로컬에는 없는 uid의 파일이 생깁니다.
평가기의 저하는 성립하는 판정만 부드럽게 할 뿐 FAIL을 WARN으로 바꾸지 않으므로, U-15는 저하되지
않고 물러섭니다. 판정은 `accounts.nss.remote eq false`와 `accounts.nss.passwd_sources not_contains
compat`(compat의 NIS `+` 항목은 `accounts.nss.remote`가 감지하지 못한다고 문서화한 유일한 원격
배치)로 게이트된 mechanism 안에 있고, 그런 호스트에서는 적용되는 mechanism이 없어 `absent_means:
manual`이 그 팩트들을 근거로 MANUAL을 냅니다(§5). 컨트롤 설명은 남는 사각지대를 드러내 말합니다.
`conf.d`로만 설정된 sssd는 `accounts.nss.remote`가 감지하지 못해 FAIL로 읽히며, 운영자의 대처는
waiver나 감지 수정입니다.

그 밖의 키: `walk.complete`(기존; W-1과 §7의 비root·mountinfo 실패도 실음), `walk.skipped[]`
(`{path, reason}`), `walk.stats`(레코드: `entries, dirs, files, symlinks, stop_reason, last_path,
truncated_counts, allowlisted_hidden, config_unreadable, home_roots, mnt_id_fallback, nice_applied,
ioprio_applied`). `walk.*` 아래에 소요 시간은 없습니다. `run.collectors[walk].ms`가 이미 기록하고, 본
설계 §9는 가변값을 `run` 아래에만 둡니다. 새 키 7개(`walk.suid_sgid`, `walk.suid_sgid_unverified`,
`walk.sticky_missing`, `walk.unowned`, `walk.hidden`, `walk.skipped`, `walk.stats`), 리스트 전부와
`walk.stats`는 `sensitivity: internal`(경로, uid, 그리고 `home_roots`의 사용자명 — `accounts.users`가
이미 가진 것과 같은 민감도), 리스트는 모두 `subject_kind: file`, 지금까지의 모든 키처럼 `since: 1`, `schema_version` 불변. `walk.world_writable`은 레코드 필드 셋이 늘며 본 설계 §5.7은
이를 추가로 칩니다. `walk.skipped`와 `walk.stats`는 팩트 사용 리포트에 어느 컨트롤도 읽지 않는 키로
나타납니다. 출처 정보이며 리포트가 그렇게 말합니다. 모든 리스트는 `path`순 정렬, 레코드 필드는
고정 순서.

## 4. 패키지 결합과 기준 목록 (W-6, W-7, W-8)

**W-6 — 순회 후 후보에 대해서만 한 번 결합.** 기본 결합은 소유권과, 출처가 갖고 있는 경우
선언된 모드입니다. 어떤 패키지도 검증하지 않습니다(W-8). 계열은 `patch.go`와 같은 방식으로
정합니다. `/var/lib/dpkg/status`가 있으면 dpkg, `/var/lib/rpm`이 있으면 rpm — 둘 다 이미 선언된
형태입니다. 어느 쪽도 없는 호스트는 패키지 DB가 없어 결합된 리스트 전부가 `absent`("no package
database")이고, `absent_means: manual`이 MANUAL로 바꿉니다. 워크는 `/etc/os-release`(RHEL 계열에서
심링크)를 읽지 않습니다. 기준 목록(W-7)은 `walk`보다 먼저 도는 `os` 수집기가 채우는
`run.host.os_release.{id, version_id}`로 고릅니다.

*리스트별 `package_declared`의 뜻.* `walk.suid_sgid`와 `walk.world_writable`에서는 "어떤 출처가 이
경로를 후보와 같은 특수 비트(각각 setuid/setgid, other-write)와 함께 선언함"이고, `walk.hidden`에서는
"경로가 패키지 소속임"뿐입니다. 숨김 항목에는 비교할 비트가 없습니다. `reference`는 결정한 출처
— `rpmdb`, `dpkgdb`(소유권만), `statoverride`, `list`, `unpackaged`(어느 출처도 경로를 소유하지
않음) — 또는 어느 출처도 결정하지 못한 이유 — `unlisted`, `version_mismatch`, `postinst`(패키지가
설치 시 모드를 세움, W-7), `none` — 를 말합니다.

*rpm 호스트:* 화이트리스트 명령 하나
`rpm -qa --qf '[%{=NAME}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILENAMES}\n]'`
(타임아웃 120초, 출력 상한 256 MiB — 패키지 파일 한 줄이 약 80바이트이고 큰 호스트는 백만 개에
가까움. `=` 접두사가 파일마다 패키지명을 반복하고, 경로가 마지막이라 한 줄을 처음 탭 넷으로
나누면 경로의 공백이 무해하며, 다이제스트는 출력하지 않음). 스트림을 한 줄씩 파싱해 후보 집합에
있는 경로의 줄만 남깁니다. 결합의 메모리는 호스트 파일 수가 아니라 후보 수에 묶이고,
`RunCommand`의 버퍼가 유일한 사본입니다. `package`는 소유 패키지, `package_declared`는 위 정의대로
선언된 모드에서, `declared_mode`는 표의 모드, `declared_owner`/`declared_group`은 rpm이 기록한
이름(`uid`/`gid`라고 부르지 않음), `reference`는 `rpmdb`. 표에 없는 경로는 `package: ""`,
`package_declared: false`. 실패·타임아웃·잘린 명령은 결합된 모든 리스트에 명령의 상태 —
`error`/`timeout`, 또는 출력 상한이면 `ok`에 `truncated: true` — 를 명령을 사유에 담아 줍니다(C3).
`absent`가 아닙니다. 본 설계 §6.5 6행이 그 컨트롤들을 ERROR로 만들며, 끝나지 않은 결합에 대한
진실이 그것입니다.

*dpkg 호스트:* 경로→패키지 표를 `/var/lib/dpkg/info/*.list`(선언된 glob, 파일당 16 MiB — TeX
Live의 목록은 1 MiB를 넘음; 잘린 `.list`는 잘린 `rpm`과 똑같이 결합을 자릅니다),
`/var/lib/dpkg/diversions`(먼저 적용: 우회된 경로는 우회 대상 이름으로 찾음),
`/var/lib/dpkg/statoverride`에서 만들고, 설치 버전은 `/var/lib/dpkg/status`(`patch.go`의 읽기 형태,
`Package:`/`Version:`만)에서 얻습니다. **merged-usr 별칭:** 목록은 `/bin/su`, `/sbin/…`, `/lib/…`로
적지만 no-follow 워크는 `/usr/bin/su`만 봅니다. 워크는 `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`,
`/libx32` 중 어느 것이 `/usr`로 가는 심링크인지 기록하고(`/`는 어차피 나열함) `.list`, `diversions`,
`statoverride`, 기준 목록의 모든 경로를 그 표로 정규화한 뒤 찾으며, 일치한 병합 전 형태가 다르면
`declared_path`에 남깁니다. DB에 모드가 없으므로 비트로 판정하는 두 리스트의 `package_declared`는
다음 순서로 정합니다. 경로에 대한 `statoverride` 항목(모드를 선언; `reference: statoverride` —
패키지 비소속 경로의 override도 `package: ""`로 선언된 것으로 침, dpkg가 업그레이드마다
강제하므로); 아니면 릴리스의 기준 목록(W-7)과 그 버전 규칙 — 목록이 비트**와 함께** 담고 있는
경로는 설치 버전과 무관하게 선언 참(패치된 호스트를 모두 unverified로 치면 `apt upgrade` 다음
날부터 목록이 쓸모없어짐; 목록은 본 것만 보증할 수 있으므로 이후 업데이트가 뺀 비트 —
util-linux는 CVE-2024-28085로 `/usr/bin/wall`과 `/usr/bin/write`의 setgid를 뺐고 iputils는 `ping`을
setuid에서 파일 capability로 옮김 — 는 목록을 다시 생성할 때까지 `reference: list`로 통과하며,
정상 상태 절과 컨트롤 설명이 이를 말함),
목록이 비트 없이 담거나 담지 않는 경로는 설치 버전이 고정 버전과 같을 때만 선언 거짓, 다르면
`reference: version_mismatch`(새 버전이 정당하게 helper를 더했을 수 있음); 아니면 `unlisted`(패키지
소속이나 목록이 그 패키지를 다루지 않음) 또는 `none`(이 릴리스에 목록 없음). `walk.hidden`은 `.list` 일치로
충분합니다(`dpkgdb`). dpkg의 `walk.world_writable`에서 다루지 않는 패키지는 `unlisted` → 선언 거짓
→ WARN(컨트롤이 `partial`)이며, 이것이 정직한 읽기입니다. 완전히 읽은 표에 대한 조회만 결정하며,
`.list` 파일은 rpm처럼 스트리밍하고 후보 경로만 남깁니다.

**W-7 — 기준 목록이 결정하고, `walk.suid_sgid_unverified`는 결정 못 한 것을 담습니다.** 문법은 "이
요소는 FAIL, 저 요소는 WARN"을 말할 수 없으므로 수집기가 검증 가능성으로 나눕니다. 패키지
소속이지만 결합이 모드를 결정하지 **못한**(`reference`가 `unlisted`, `version_mismatch`, `postinst`,
`none`)
SUID/SGID 후보는 `walk.suid_sgid_unverified`로, 결정된 모든 것 — 비소속(`package_declared: false`),
또는 statoverride·rpm DB·기준 목록이 어느 쪽으로든 다룬 것 — 은 `walk.suid_sgid`로 갑니다. 목록이
**어느 쪽으로든** 결정하려면 setuid 파일만이 아니라 **다루는 모든 패키지의 모든 파일을 모드와
함께** 담아야 합니다. `docs/reference/suid/<id>-<version_id>.json`은 `{distro, release, image_digest,
generated, packages: [{name, version}], entries: [{path, mode, owner, group, package}]}`이며 경로순,
경로는 워크가 볼 형태(같은 merged-usr 표로 정규화)입니다. dpkg의 결합 규칙, 경우마다 한 행:

| 후보의 패키지 | 설치 버전 | 목록의 경로 | 결과 |
|---|---|---|---|
| `packages`에 없음 | — | — | `unlisted` → unverified(WARN) |
| `packages`에 있음 | 무관 | 비트와 함께 있음 | `list`, 선언 참 → 검증됨, 통과 |
| `packages`에 있음 | = 고정 버전 | 비트 없이 있거나 없음 | `list`, 선언 **거짓** → `walk.suid_sgid`, FAIL(`chmod u+s /usr/bin/python3`이 잡힘) |
| `packages`에 있음 | ≠ 고정 버전 | 비트 없이 있거나 없음 | `version_mismatch` → unverified(두 버전을 명시한 WARN) |
| 비소속 | — | — | `unpackaged`, `package_declared: false` → `walk.suid_sgid`, FAIL |

아카이브에 비트를 실어 배포하지 않고 설치 시 maintainer 스크립트로 비트를 세우는 패키지(Debian
정책은 결합이 읽는 `dpkg-statoverride`를 선호하지만 `postinst`의 맨 `chmod`도 존재함)는 큐레이션할
때 그 패키지의 maintainer 스크립트를 읽어 찾아 `sources.json`에 `postinst_sets_mode: true`로
기록하고, 그 파일들을 목록에 표시해 거짓 FAIL이 아니라 `reference: postinst`의 unverified로 가게
합니다. 따라서 업데이트를 적용한 호스트의 정상 상태는: 목록이 비트와 함께 아는 파일은 통과 —
보안 업데이트가 그 뒤 뺀 비트를 관리자가 되살린 경우도 포함하며, 목록은 천장이 아니라 바닥이고
`suid_sgid` 컨트롤 설명이 이 잔여를 명시함 — 새로 생기거나 옮겨진 helper는 유지보수자가 그
릴리스의 목록을 다시 생성할 때까지(point release마다) WARN입니다.

목록은 유지보수자용 도구 `tools/suidindex`가 `docs/reference/suid/sources.json`에서 만듭니다.
릴리스마다 공개 컨테이너 이미지(이름과 다이제스트)와 정식 패키지의 **큐레이션된** 목록 —
이미지 자체의 `find / -perm /6000` 소유자로 씨를 뿌리고, setuid/setgid 파일을 배포하는 것으로
알려진 서버 패키지(`at`, `screen`, `postfix`, `exim4-base`, `mtr-tiny`, `fuse3`, `polkitd`, `dbus`, …)를
이름으로 더하며, 각각 한 줄 사유를 둠. 이미지에 설치된 패키지는 이미지 자체의 파일시스템에서
읽고(`dpkg -L` / `rpm -ql`과 `stat`, 다운로드 없음), 확장 목록의 패키지는 항목마다 스냅샷 서비스
URL(`snapshot.debian.org`, `snapshot.ubuntu.com`)과 SHA-256에 고정해 — `tools/refindex/sources.json`이
URL과 다이제스트를 고정하는 방식 — `-check`가 살아 있는 아카이브를 따라 흘러가지 않게 합니다. 같은
컨테이너 안에서 도구는 그 `.deb`를 받아 `dpkg-deb --fsys-tarfile <deb> | tar -tv`로 헤더를 읽습니다
(설치 없음, 새 Go 의존성 없음; D28 유지). rpm 릴리스는 이미지에서 `rpm -qa --qf`로 같은 방식이며
그 목록은 교차 확인 근거일 뿐 rpm 결합은 그것에 기대지 않습니다. Debian `Contents-amd64` 색인은
모드가 없으므로, 쓴다면 알려진 경로의 소유 패키지를 찾는 데만 씁니다. `refindex`처럼 CI는 생성기를
돌리지 않고, `tools/suidindex -check`는 유지보수자가 원할 때 재생성해 대조하며, 단위 테스트가
커밋된 모든 목록의 형태·정렬·정규 경로와 `sources.json`의 각 릴리스에 목록이 있는지 검사합니다.
첫 `sources.json`은 ubuntu 22.04, ubuntu 24.04, debian 12, rocky 9, almalinux 9 — CI 이미지 — 를
담습니다.

*출하된 형태(플랜 3A 실행 판정 A-36~A-39. 플랜은 병합 시 삭제되므로 여기에 기록).* 다루는
집합은 이름으로 적은 패키지와 이미지의 setuid/setgid 파일 소유자의 **합집합**이며, `sources.json`의
최상위 `note`가 이를 말하고 발견된 패키지는 사유와 함께 다시 적었습니다. `postinst_sets_mode`는 손으로
큐레이션하지 않습니다. 도구가 확장 패키지의 maintainer 스크립트를 읽어 `postinst`가 그 패키지가
배포하는 파일에 모드를 세우는(`chmod`의 리터럴·계산 모드, `dpkg-statoverride --add`) 패키지를 표시하고
일치한 줄을 근거로 출력합니다. 디렉터리나 배포하지 않는 경로를 가리키는 리터럴 대상은 표시하지
않습니다. 아카이브의 고정은 SHA-256입니다. URL은 이미지 안에서 `apt-get download --print-uris`가
보고한 것이고(뒤에 스냅샷 서비스 URL로 바꿀 수 있음), 도구는 호스트에서 `net/http`로 받아 열기 전에
다이제스트를 검증하고 `--network none`으로 돌리는 컨테이너에 읽기 전용으로 바인드 마운트합니다.
네트워크는 `-resolve` 모드에만 있습니다. 목록은 `arch`(`amd64`, 고정한 `--platform`)와
`packages[].postinst_sets_mode`를 담고 이미지 자체의 `VERSION_ID`로 이름 짓습니다(`rocky-9.8.json`).
`suid.Load(id, version_id)`는 정확한 파일, 다음 `<id>-<major>.json`, 다음 커밋된 가장 높은
`<id>-<major>.<minor>.json` 순으로 찾으므로 Rocky 9.5 호스트는 9.8 목록을 얻습니다. 이는 W-7의 바닥
안에서 더 관대할 뿐(목록에 있는 비트는 통과, 그 밖은 `version_mismatch` → WARN) 거짓 FAIL은 결코
아닙니다. `-check`는 `generated` 날짜만 빼고 모든 바이트를 대조하며 날짜는 보고합니다.

**W-8 — 패키지 검증은 계획 3C의 몫.** `rpm -V <pkg…>`와 `dpkg --verify <pkg…>`는 실행 시점에
계산된 패키지 목록을 받습니다. 가드의 화이트리스트는 인수 정확 일치(본 설계 §8 "고정 인수")이고,
두 명령은 어느 파일이든 다르면 exit 1이라 오늘의 명령 컨벤션은 실패한 명령으로 기록합니다. 3C가
`Tail`이 어휘(`package-name`: `^[A-Za-z0-9][A-Za-z0-9.+_-]*$`, 앞에 `-` 금지, 개수 상한)를 지정하는
`CommandTemplate{Path, Args, Tail}` 선언, 그 가드 규칙과 `--list-actions` 표현(`rpm -V <package…>`),
"exit 1 = 차이"를 결과를 판정하는 패키지 무결성 점검과 함께 설계합니다. 3A는 검증 플래그·키·
명령을 내지 않습니다.

## 5. 컨트롤 (W-9, W-10, W-11)

| 컨트롤 | 항목 | 자동화 | 판정 |
|---|---|---|---|
| `muster.file.unowned_files` | U-15 | `auto` | `absent_means: manual`; mechanism 하나 `when: [{accounts.nss.remote eq false}, {accounts.nss.passwd_sources not_contains compat}]`에 checks `walk.unowned none subject path where uid_known eq false`와 `walk.unowned none subject path where gid_known eq false`; 원격 NSS나 NIS compat 호스트는 그 팩트들을 근거로 MANUAL |
| `muster.file.suid_sgid` | U-23 | `auto` | `walk.suid_sgid each subject path require package_declared eq true`; `walk.suid_sgid none subject path where path in "${forbidden_suid}"`(`params.forbidden_suid`, `list<string>`, 기본 `[]`); `walk.sticky_missing none subject path where path present` |
| `muster.file.suid_sgid_unverified` | U-23 | `partial` | `walk.suid_sgid_unverified none subject path where path present` → 경로·패키지·`reference`를 명시한 WARN |
| `muster.file.hidden_entries` | U-33 | `partial` | `walk.hidden each subject path where allowlisted eq false require package_declared eq true` → WARN |
| `muster.file.world_writable` (기존) | U-25 | `partial` | 변경 없음; `walk.world_writable`이 이제 채워짐; 설명에 `kind`·`reference` 필드 추가 |

모든 `none` 절은 `subject: path`를 가져 관측이 `file:<경로>`로 키가 잡히고(본 설계 §6.4) waiver가
subject를 지정할 수 있습니다. 계획은 "`list<record>`의 `none`은 `subject`가 필요하다"는 lint 규칙을
더해 이를 다시 잊을 수 없게 합니다. 새 컨트롤 넷은 모두 `absent_means: manual`을 가집니다(§7이
패키지 DB 없음 케이스에서 이에 의존). `accounts.nss.passwd_sources`는 `list<string>`이고, 문법에
`contains`는 있으나 `not_contains`는 없으므로, 계획이 리스트 비교(`compareList`), 스칼라 비교의
문자열 분기(부분 문자열 — lint와 평가기가 모든 팩트 유형에서 일치하도록), lint의 `scalarOps`에
`contains` 옆에 `not_contains`를 `in` 옆의 `not_in`과 같은 모양으로 추가합니다.

**W-9 — "제거할 SUID 바이너리" 가이드 목록은 어디에도 없음.** `forbidden_suid`의 기본값은 빈
목록입니다. KISA 가이드와 CIS 모두 setuid를 관례적으로 제거하는 바이너리 목록을 갖지만, 어느
쪽을 옮겨도 원문 전재이고 목록은 배포판마다 다릅니다. 그런 정책이 있는 운영자가 파라미터를
설정하며, 컨트롤 설명이 그렇게 말합니다. 같은 경계가 `tools/suidindex/sources.json`도 구속합니다.
그 패키지 목록은 이미지와 패키지의 사실에서 나오지, 가이드나 벤치마크의 바이너리 목록에서 씨를
뿌리지 않습니다.

**W-10 — 항목 하나, 컨트롤 둘, 그리고 U-23은 `auto`.** U-23은 컨트롤 둘이 등재합니다. 2M의
`kisa_coverage` lint 규칙("항목당 정확히 하나")을 "하나 이상"으로 완화하고, 중복 검사는 한 컨트롤
안에 같은 id가 두 번 적힌 경우로 좁히며, README의 "항목이 빠지거나 두 번 등재될 수 없다" 문장
(두 언어)은 "빠지거나 잘못 등재될 수 없다"로, "64개 컨트롤 중"은 68로 바뀝니다. 본 설계 부록 A는
U-23을 `partial (walk)`로 적고 §10.1은 "어떤 SUID 파일이 정당한지"를 사람 판단의 예로 드는데, 둘
다 이 스펙과 같은 커밋에서 다음 결정으로 고칩니다. 패키지 비소속 setuid 파일이나 패키지가 그 비트
없이 선언한 파일은 자동 판정 대상이고, 결합이 검증할 수 없는 패키지 선언만 사람의 판단입니다.
등재 수는 항목 기준(67 of 67)이고, 자동화 3종 수는 컨트롤 기준(68개 중 auto 57, partial 7, manual
4)입니다.

**W-11 — 상태.** 워크 기반 컨트롤 다섯(새 넷과 U-25) 모두 본 설계 §6.5 9–10a행을 거칩니다. `--deep`
없이는 `MANUAL`, 워크가 일찍 멈추면 `ERROR(walk_incomplete)`, 비root라 돌지 못했으면 거부를 명시한
`ERROR`(10a행). 명령이나 읽기의 실패를 실은 결합 리스트는 6행에 따라 ERROR, 상한에 닿은 리스트는
그 컨트롤만 `ERROR(truncated)`, 패키지 DB가 없는 호스트는 `absent_means: manual`로 MANUAL, 루트
마운트를 걸을 수 없는 호스트는 NOT_APPLICABLE(§7). 결합에 기대는 리스트: `suid_sgid`,
`suid_sgid_unverified`, `world_writable`, `hidden`. `unowned`, `sticky_missing`, `skipped`, `stats`,
`complete`는 결코 기대지 않습니다. rpm 실패가 소유자 없는 파일이나 sticky 없는 디렉터리를 숨길 수
없습니다.

컨트롤마다 해당하는 픽스처: `pass-*`/`fail-*`(partial 컨트롤의 `fail-`은 WARN 기대),
`manual-no-walk`(`walk.*` 키 없음), `error-walk-incomplete`(`walk.complete false`,
`_expect.reason_code: walk_incomplete`), `error-walk-denied`(`walk.complete`가 denied,
`_expect.reason_code: permission_denied`), 다섯 모두에 `na-overlay-root`(모든 워크 리스트
`unsupported`, `walk.complete true`), 결합 형태(`pass-rpm-declared`, `pass-dpkg-usrmerge` —
`/usr/bin/su` 후보에 `/bin/su`를 적은 `.list`, `fail-dpkg-unpackaged`, `fail-dpkg-covered-no-bit`,
`pass-dpkg-version-differs-bit-listed`, unverified 컨트롤은 `fail-dpkg-unlisted`와
`fail-dpkg-version-mismatch`), `suid_sgid`에 `fail-sticky-missing`(`forbidden_suid` 파라미터는 픽스처
하네스가 `_expect.reason_code`/`exit_code`만 읽으므로 params를 준 평가기 단위 테스트로 검증),
`hidden_entries`에 `fail-hidden-in-usr-sbin`과 `fail-hidden-in-var-www`, `manual-no-package-db`,
`error-rpm-truncated`, U-15는 `manual-remote-nss`, `manual-nis-compat`, `pass-subuid-owned`. U-15의
`error-*`와 `na-*` 픽스처는 워크 게이트보다 먼저 mechanism이 선택되도록 NSS 게이트 팩트 둘을 `ok`로
싣습니다. 모두 synthetic이며 경로는 실제 배포판 경로입니다.

## 6. 명령줄 (W-12)

`collect`에 추가: `--deep`(이미 파싱됨; "3단계에 온다"는 경고가 사라지고 `run.deep`이 참이 됨),
`--walk-budget <기간>`(기본 `10m`), `--walk-max-entries <n>`(기본 `2000000`), `--walk-exclude <경로>`
(반복 가능), `--walk-include <경로>`(반복 가능, 고정 집합 항목만). `--deep` 없이 워크 플래그를 쓰면
오류(`exit 2`, 플래그 명시)이고, 유효 `--timeout`보다 큰 `--walk-budget`도 그렇습니다. `--deep`은
`--timeout`을 따로 주지 않은 경우 기본 `--timeout`을 `--walk-budget + 5m`으로 올립니다. `collect
--list-actions`에 워크 행과 `rpm -qa --qf …` 명령이 나옵니다. 실행 헤더에는 `run.deep`과 수집기의
`status`/`reason`/`ms` 외에 워크에 관한 것을 쓰지 않으며, 유효 제외 목록은 `walk.skipped[]`에서
읽을 수 있습니다.

## 7. 오류와 저하

- 워크가 `/proc/self/mountinfo`를 읽지 못함 → `walk.complete`가 그 읽기의 봉투를 실음(경로 접두,
  C3), 다른 키는 쓰지 않음, 수집기 상태는 그것을 따름, 본 설계 §6.5 10a행이 읽기를 명시한 ERROR를 냄.
- 비root → `walk.complete`가 denied("the walk needs root"), 수집기는 팩트에서 `denied`, 실행은
  partial(exit 1), 컨트롤은 10a행으로 ERROR(W-1).
- 루트 마운트 `/`가 W-2 집합에 없음(overlay, squashfs, 모르는 유형) → 모든 워크 리스트가 `root
  filesystem is <type>; the walk answers for a host, not for a container layer` 사유로
  `unsupported`, `walk.complete`는 `true`, `walk.skipped`는 `/`를 `excluded_type`으로 기록. 본 설계
  §6.5 7행이 NOT_APPLICABLE(unsupported_env)을 냄 — 빈 리스트로 PASS는 결코 없음.
- 열 수 없거나 발밑에서 바뀐 디렉터리 → `walk.skipped[]`에 `denied` 또는 `vanished`; 워크는 계속;
  `walk.complete`는 참 유지.
- 예산이나 데드라인 → `walk.complete false`, 중단 사유, 마지막 경로(§2). 상한에 닿은 리스트 → 그
  리스트만 `truncated: true`, 워크는 계속.
- `/etc/passwd`, `/etc/group`, `/etc/subuid`, `/etc/subgid`를 읽지 못함 → `walk.unowned`는 그 읽기의
  상태(C3), 다른 리스트는 영향 없음. 존재하지만 읽을 수 없는 컨테이너 저장소 설정 파일 →
  `walk.stats.config_unreadable`(W-2); 고정 집합은 그대로 적용.
- `rpm -qa --qf` 실패·타임아웃·잘림 → 결합된 모든 리스트가 명령을 사유에 담은 명령의 상태
  (`error`, `timeout`, 또는 `ok` + `truncated`)를 실음; dpkg 호스트에서는 읽지 못했거나 잘린
  `.list`/`diversions`/`statoverride`/`status` 파일이 같은 방식으로 결합을 오염시킴(첫 읽기 오류가
  파일을 명시). `walk.unowned`, `walk.sticky_missing`, `walk.skipped`, `walk.stats`, `walk.complete`는
  영향 없음.
- 호스트에 패키지 DB가 없음 → 결합된 모든 리스트가 `absent`("no package database") →
  `absent_means: manual`로 MANUAL.
- 릴리스에 기준 목록이 없거나, 패키지 버전이 고정 버전과 다르**면서 목록이 그 경로를 비트와
  함께 담고 있지 않거나**, 패키지가 `postinst`에서 모드를 세움 → 패키지 소속 SUID/SGID 후보는
  `walk.suid_sgid_unverified`(WARN, `reference: none`, `version_mismatch` 또는 `postinst`)로,
  비소속은 여전히 `walk.suid_sgid`에서 FAIL.
- 워크는 들어가지 않기로 한 배치나 읽지 않기로 한 파일에 대해 결코 리프 `error`를 내지 않음.
  규약 C4가 적용되어 그런 결정은 모두 `walk.skipped` 행이거나 `walk.stats` 메모이거나
  `allowlisted`/`unlisted` 표시이지 오류 봉투가 아님.

## 8. 테스트

- **단위, 크로스플랫폼:** 순회는 `ReadDir`가 각본대로 짜인 트리(디렉터리별 종류·모드·uid·마운트
  id·`(dev, ino)`·오류)와 각본 mountinfo를 내주는 인메모리 `Access` 더블 위에서 돕니다. §2의 규칙마다
  케이스가 있습니다. 심링크 미추적, 다른 마운트 id 미진입, bind 별칭이 워크 전에 진입 집합에서 빠져
  한 번 기록됨, `(dev, ino)` 적중이 `bind_duplicate`로 기록됨, 목록에 없는 마운트 기록, autofs 루트
  나열만 하고 미개방, 컨테이너 루트 제외와 플래그로 재포함, 설정된 `data-root`/`graphroot`/containerd
  `root` 제외, 심링크인 고정 집합 루트의 대상 제외, 홈별 rootless 루트 제외, 읽을 수 없는 설정
  파일이 `walk.stats`에 기록됨, `denied`와 `vanished` 기록 후 계속, 열고 난 뒤 정체 불일치, 각 예산과
  데드라인이 올바른 사유로 멈추고 `complete false`, 상한에 닿은 리스트가 `truncated`로 계속, 허용된
  행의 별도 상한. 홈 규칙은 RHEL의 `nobody:/`와 Debian의 `daemon:/usr/sbin` 항목 그대로와
  `/var/lib/postgresql` 서비스 홈을 케이스로 둡니다. 결합은 픽스처 `rpm -qa --qf` 출력과 픽스처
  `.list`/`diversions`/`statoverride`/`status` 파일, 픽스처 기준 목록 위에서 돌며 merged-usr 별칭
  케이스, 버전 케이스(비트가 목록에 있고 버전이 다름 → 통과; 없고 버전이 다름 →
  `version_mismatch`), `postinst_sets_mode` 패키지를 포함하고, W-7 표의 모든 행과 `reference`의 모든
  값이 테스트로 만들어집니다. 후보 규칙은 리스트마다 케이스를 두며 두 부분 허용 목록, 사용자
  홈과 서비스 홈의 깊이 규칙(`www-data:/var/www`의 깊은 숨김 디렉터리는 기록, `postgres`의 직접
  자식 `.psql_history`는 면제), `walk.unowned`의 심링크, 모든 `uid_class`를 포함합니다.
- **결정성:** 각본 트리를 두 번 걸으면 바이트 동일한 리스트가 나오고, 디렉터리 순서를 바꿔
  제시해도 같은 출력이 나옵니다.
- **Linux, 랩 호스트:** root의 `collect --deep`이 기본 예산 안에 stock Ubuntu 22.04 노드에서
  완료됩니다. `walk.stats`와 리스트 크기를 계획의 Execution notes에 기록하고, stock 호스트에서 컨트롤
  다섯의 상태를 기록하며, 비root 실행은 `walk.complete`가 denied이고 `collect`가 exit 1임을 보입니다.
  `denied` 건너뜀은 uid 0으로 `CAP_DAC_READ_SEARCH`와 `CAP_DAC_OVERRIDE`를 떨어뜨리고(`setpriv
  --inh-caps=… --bounding-set=…`) `mktemp -d` 트리의 `chmod 000` 디렉터리에 대해 워크를 돌려
  증명합니다. `chmod 000`만으로는 root를 막지 못하고 `chattr +i`는 쓰기만 막습니다.
- **CI:** `collect-root`(러너 VM, ext4)가 `collect --deep`을 돌려 `walk.complete == true`와 모든 워크
  리스트의 `status == "ok"`, 그리고 ERROR 없는 `check`를 단언합니다(러너 이미지 자체의 dotfile
  트리가 언젠가 `walk.hidden`을 상한까지 밀면 처방은 허용 목록이나 상한이지 약한 단언이 아님).
  컨테이너 매트릭스와 읽기 전용
  계약 잡도 `--deep`을 돌려 모든 워크 리스트가 `unsupported`(루트가 overlay)이면서 `run.complete`는
  여전히 참임을 단언하며, 이는 `docs/reference/capability-matrix.json`의 새 `container` 클래스
  (`unsupported: [walk.suid_sgid, walk.suid_sgid_unverified, walk.world_writable, walk.sticky_missing,
  walk.unowned, walk.hidden]`)가 `no-systemd` 클래스가 자기 단계를 이끄는 방식으로 이끕니다. 비root
  잡은 `--deep`을 돌리고 매트릭스는 `nonroot.denied` 아래에 `walk.complete`를 얻습니다.
- **기준 목록:** `tools/suidindex -check`는 유지보수자 타깃. 단위 테스트가 커밋된 모든 목록을 읽어
  형태·정렬·정규(`/usr` 형태) 경로, 모든 항목의 패키지가 버전과 함께 `packages`에 있는지,
  `sources.json`의 각 릴리스에 목록이 있는지 검사합니다.
- **픽스처와 커버리지:** §5의 픽스처 집합, 완화된 `kisa_coverage`와 새 "`none`에는 `subject`" 규칙의
  `controls lint`, 67/67 줄과 README 문구가 같은 태스크에서 갱신된 `coverage -check`.

## 9. 다른 곳의 변경

- `internal/collect`: `Access.ReadDir`(+ 내장 가능한 더블 기반), `DirEntry`, `Declaration.Walk`,
  `Action.Kind: walk`, 가드의 워크 허가, 화이트리스트 명령 하나(`rpm -qa --qf …`). `callRun` 변경 없음.
- `internal/facts/registry.yaml`: 키 7개, `walk.world_writable`의 레코드 필드 3개.
- `internal/controls/lint.go`: `kisa_coverage` 완화(W-10); `list<record>`의 `none`에는 `subject`;
  `not_contains`(§5).
- `cmd/muster/collect.go`: 플래그 5개, 데드라인 연동, 경고 제거, `run.deep`.
- `tools/suidindex`, `docs/reference/suid/`(목록 5개 + `sources.json`); 새 Go 의존성 없음.
- `controls/file/`: 새 컨트롤 넷, `world_writable`의 설명; `docs/reference/kisa/kisa_deferred.json`
  비움; `docs/reference/coverage.md` 재생성; `docs/reference/capability-matrix.json`(`nonroot.denied`
  아래 `walk.complete` 추가, `container` 클래스 추가); README 쌍(로드맵 문장, lint 문장, "64개 컨트롤
  중" → 68); `CHANGELOG.md`(Controls 아래 판정에 영향을 주는 컨트롤 넷; `controls/VERSION` 범프).
- 본 설계, 영/한, 이 스펙과 같은 커밋에서 수정: 부록 A의 U-23 행과 §10.1 예시(W-10); §8의 ionice
  문구와 autofs 문구(§2, W-3); §5.8의 `truncated_count` → 리스트별 `truncated: true` +
  `walk.stats.truncated_counts`; §6.5의 10a행.
- `CLAUDE.md`: `Declaration.Walk`/`ReadDir`에 관한 한 줄과 랩 스크립트에서의 `--deep`에 관한 한 줄
  (레시피는 저장소가 아니라 세션 노트에 있음).
