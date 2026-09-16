# Stage 3A — the deep filesystem walk

*English · [한국어](2026-09-16-stage3a-walk-design.ko.md)*

This document is the design for plan 3A of muster: the `--deep` filesystem walk the main
design (`2026-09-02-muster-design.md`, §5 "Walk", §5.8, §6.5 rows 9–10a, §10.2 "Stage 3")
reserved, and the four KISA items that depend on it. It is the first of the stage-3
sub-projects agreed on 2026-09-15: 3A walk, 3B kernel/boot/mount, 3C audit/exposure/root-
equivalent paths (and package verification, W-8), 3D profiles and tuning, 3E `fix --dry-run`,
3F mutation testing and fuzzing (3F may run in parallel with 3A). Decisions are numbered
W-1 … W-12 and bind the plan. Two fresh reviews on 2026-09-16 (36 and 18 findings) are
folded in; where this version differs from the first draft, the difference is theirs.

## 1. Goal

Enrol the three KISA 2026 Unix items that need a filesystem traversal — U-15 (files and
directories without a valid owner), U-23 (SUID/SGID/sticky bits), U-33 (hidden files and
directories) — and let U-25 (world-writable files), enrolled since stage 1 but reading
`MANUAL` until the walk exists, judge a real host. After 3A every one of the 67 items has a
control (four new controls, 64 → 68): coverage reads "67 of 67 items enrolled",
`kisa_deferred.json` is empty, and the README's roadmap sentence changes accordingly.

Out of scope for 3A: package verification (`rpm -V` / `dpkg --verify`, a `--verify-packages`
flag, a `walk.package_verify` key) — it needs a guard that can whitelist a command with a
variable package-name tail (`CommandTemplate`), and nothing in 3A judges its output, so the
whole of it is plan 3C's (W-8); file capabilities and ACLs in the walk (3C, once a control
needs them); profiles (3D); the walk's use by non-KISA checks (3B/3C consume `walk.*` as
evidence where useful).

## 2. Traversal, boundaries, budget (W-1, W-2, W-3)

**W-1 — the walk is a collector, off by default.** `walk` replaces the stage-1 placeholder in
`internal/collect/collectors/walk.go`. It runs only under `collect --deep`; without the flag it
writes no key, exactly as today, so U-25 and the four new controls read `MANUAL` ("run collect
--deep", main §6.5 row 9). `run.deep` is `true` whenever `--deep` was given, even when the walk
was then denied or failed, so a reader can tell "not requested" from "requested and could
not". It needs root (`Needs: "root"`); as non-root the collector writes exactly one key,
`walk.complete` as `denied("the walk needs root")`, and returns `nil` — the collector's status
then derives from its facts (`denied`), the run is partial and `collect` exits 1, exactly as
for every other root-needing collector (R56/R71); no `ErrSkipped`, no `callRun` change. Main
§6.5 row 10a (added with this spec) then makes every walk-based control `ERROR` naming the
denial, never a "run collect --deep" MANUAL the operator already obeyed.

**W-2 — boundaries.** Before the first directory is opened the collector reads
`/proc/self/mountinfo` (declared) and builds the set of mounts it will enter as a **positive
list of local types**: `ext2`, `ext3`, `ext4`, `xfs`, `btrfs`, `f2fs`, `jfs`, `reiserfs`,
`zfs`, `tmpfs`, `ramfs`, `vfat`, `exfat`, `ntfs`, `ntfs3`, `iso9660`, `udf`, `erofs`. Any other
type — including `nfs`, `nfs4`, `cifs`, `smb3`, `fuse`, `fuseblk`, `fuse.*`, `sshfs`, `afs`,
`9p`, `ceph`, `glusterfs`, `lustre`, `gfs2`, `ocfs2`, `nfsd`, `overlay`, `squashfs`, `autofs`,
`devtmpfs`, `proc`, `sysfs`, `cgroup*`, `bpf`, `tracefs`, `debugfs`, `securityfs`, `pstore`,
`configfs` and every type not on the list — is not entered (an unknown type errs on the side
of not touching it). `tmpfs` is on the list on purpose: `/tmp` and `/var/tmp` are where U-25
and the sticky half of U-23 live. Excluded by path regardless of type: `/proc`, `/sys`, `/dev`,
`/run`. **Bind aliases** are decided here, from mountinfo alone: two mounts are aliases when
they share `major:minor` and one's `root` equals or lies under the other's; the alias entered
is the one whose `root` is `/`, then the shortest mount point, then the lexicographically
first (a deterministic tie-break when two aliases both have `root` `/`); every other alias
is written to `walk.skipped[]` as `bind_duplicate` before the first directory is opened and
its mount id leaves the enter set. Excluded as container, VM and chroot storage, because the
layers beneath an overlay live on the root filesystem and carry foreign uids and their own
setuid files: the fixed set `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/containers`,
`/var/lib/lxd`, `/var/lib/lxc`, `/var/snap`, `/var/lib/libvirt/images`, `/var/lib/machines`,
`/var/lib/mock`, `/var/cache/pbuilder`, `/var/lib/schroot`, `/var/lib/kubelet`,
`/var/lib/rancher`, `/var/lib/k0s`, `/var/lib/cni`; when a fixed-set path is itself a symlink
(`/var/lib/docker -> /data/docker` is as common as `data-root`), `readlink` (declared; the walk
still never follows it) names the target, which joins the set as `container_storage` with the
link path in the reason; plus the roots configured on the host — the walk declares and reads
`/etc/docker/daemon.json` (`data-root`), `/etc/containers/storage.conf` (`graphroot`,
`rootless_storage_path`) and `/etc/containerd/config.toml` (`root`); and, for every home
directory that counts as one under W-4, `<pw_dir>/.local/share/containers` and
`<pw_dir>/.local/share/docker`. A configuration file that exists but cannot be read is not a
root: it is recorded in `walk.stats.config_unreadable` (`[{path, status}]`, fixed order), the
fixed set still applies, and the U-15/U-23 descriptions say that a configured root the walk
could not learn may surface as findings. Two flags adjust the list: `--walk-exclude <path>`
(repeatable) adds a root; `--walk-include <path>` (repeatable) removes an entry of the fixed
container-storage set only — any other value (`/proc`, a remote mount, an arbitrary path) is
rejected naming the flag, so it cannot become a general override.

Every root the walk did not enter is one row of `walk.skipped[]` — `{path, reason}` — and
this is the one closed vocabulary for `reason`, used by §2, §7 and the tests alike:
`excluded_type` (a mount whose type is not on the positive list; the type is in the reason),
`pseudo_path` (the four paths), `container_storage` (fixed set, symlink targets, configured
roots and per-home roots), `excluded_by_flag`, `bind_duplicate` (a mountinfo alias, or a
`(dev, ino)` already visited — the last line of defence), `denied` (EACCES/EPERM opening a
directory), `vanished` (ENOENT/ENOTDIR/ELOOP between listing and opening, or a post-open
identity mismatch), `unlisted_mount` (a mount id seen mid-walk that mountinfo did not carry —
an automount that fired). `walk.skipped` is capped at 10,000 rows with `truncated: true`
beyond, so a stuck tree cannot approach the snapshot size cap.

**W-3 — the traversal primitive and its guard.** `filepath.WalkDir` cannot honour the
no-follow, mount-boundary and cycle rules, so the walk uses a new read primitive.
`hostAccess.ReadDir(path) ([]DirEntry, error)` opens the directory through the existing
`openNoFollow` with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, `fstat`s the fd and compares
`(dev, ino)` with the entry the parent listed (a mismatch is `vanished` and the directory is
not descended — a rename between listing and opening cannot swap in another tree), lists it,
and `statx(dirfd, name, AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT, STATX_BASIC_STATS|STATX_MNT_ID)`
every entry, returning `{name, kind, mode, uid, gid, dev, ino, mnt_id, size}`. `kind` is the
existing `kindOf` vocabulary (`regular, dir, symlink, socket, fifo, chardev, blockdev`). A
symlink is an entry of kind `symlink` and is never followed. An autofs mount point is listed
by its parent and never opened; `AT_NO_AUTOMOUNT` (the kernel's default for `fstatat` since
4.11) keeps the listing from triggering it. Mount boundaries are decided by `mnt_id` against
mountinfo's first field — exact for btrfs subvolumes and mid-walk automounts, where `st_dev`
is not: an entry whose `mnt_id` differs from the current mount is entered only if that id is
in the W-2 enter set (aliases were removed from it in W-2); an id mountinfo does not carry is
`unlisted_mount`. On a kernel without `STATX_MNT_ID` (none of the targets — it is Linux 5.8+)
the walk falls back to `st_dev` and records `mnt_id_fallback: true` in `walk.stats`. A
`(dev, ino)` set of visited directories still breaks cycles; a hit is `bind_duplicate`.
`Access` gains `ReadDir`; every test double gets it from an embeddable base type so the
doubles in `collectors_test.go` and `cmd/muster` do not each grow a method. The guard gains a
declaration kind: `Declaration.Walk: true` licenses `ReadDir` on any path for that collector
alone; `Reads` and `Commands` keep their exact-match semantics for everything else the walk
touches. `Action.Kind` gains `walk` and `ListActions` renders one row: `walk  every local
filesystem, no symlink followed, boundaries and exclusions as declared`. EACCES on a directory
as root is real only under an LSM-confined tree or a reduced capability bounding set; it is
recorded as `denied` and does not stop the walk.

**Budget and deadline.** Two limits, both flags: `--walk-budget 10m` (wall time) and
`--walk-max-entries 2000000`. `--deep` raises the default global `--timeout` (5 min today) to
`--walk-budget + 5m` unless `--timeout` was given; a `--walk-budget` greater than the effective
`--timeout` is an error naming both. The walk checks `ctx.Done()` before every directory.
Exceeding a limit stops the traversal at that point: `walk.complete = false`,
`walk.stats.stop_reason` is `time_budget`, `entry_budget` or `deadline`, `walk.stats.last_path`
is the directory being read; on `deadline` the collector also returns `ctx.Err()` so it is
filed `timeout` as every collector is. Main §6.5 row 10 then makes every walk-based control
`ERROR(walk_incomplete)`: a half-seen filesystem yields neither PASS nor FAIL. **A full finding
list does not stop the walk** (main §5.8): each list has a cap of 2,000 records except
`walk.hidden`, which keeps 10,000 non-allowlisted rows and, separately, up to 2,000
allowlisted ones (further allowlisted entries are only counted in
`walk.stats.allowlisted_hidden` and never set `truncated`), so a developer host's Node trees
cannot push the list to its cap on allowlisted rows alone. A list whose judged rows reach its
cap is written with `truncated: true` and the traversal continues, counting; `walk.stats.truncated_counts` is a **record**
with one integer field per list in W-4's order (`suid_sgid, suid_sgid_unverified,
world_writable, sticky_missing, unowned, hidden, skipped`) — never a map. Main §6.5 row 6 then
gives `ERROR(truncated)` to the control(s) that read that list and nothing else.
`walk.complete` reflects the traversal only. The walk goroutine calls `runtime.LockOSThread()`
and then, best effort and unconditionally, `setpriority(PRIO_PROCESS, 0, 10)` and
`ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_CLASS_IDLE)`; the outcome is two booleans in
`walk.stats` (`nice_applied`, `ioprio_applied`), no `/sys` is read, and neither failure aborts
the walk. Main §8's "where the I/O scheduler honours it" is amended to "best effort".

## 3. Candidates and facts (W-4, W-5)

**W-4 — four conditions, evaluated from `statx` alone.** The walk never opens a file's
contents. `walk.unowned` sees every entry, symlinks included (a symlink has an owner, and
`find -nouser` reports it); the four mode-based lists see every entry that is not a symlink:

| List | Condition | Record fields |
|---|---|---|
| `walk.suid_sgid` | regular file with setuid or setgid, verifiably judged (§4) | `path, mode, uid, gid, setuid, setgid, package, package_declared, declared_mode, declared_path, reference` |
| `walk.suid_sgid_unverified` | as above, but the join could not verify the mode (§4) | same fields |
| `walk.world_writable` (existing key) | any non-symlink entry with other-write | `path, kind, sticky, uid, gid, package, package_declared, reference` (existing fields kept; `kind`, `package`, `reference` added) |
| `walk.sticky_missing` | directory with other-write and no sticky bit | `path, mode, uid, gid` |
| `walk.unowned` | uid or gid not known (W-5); every kind | `path, kind, uid, gid, uid_known, gid_known, uid_class, gid_class` |
| `walk.hidden` | name begins with `.` and not exempt as a home dotfile (below) | `path, kind, uid, package, package_declared, reference, allowlisted` |

`walk.world_writable` carries every kind (`dir`, `socket`, `fifo`, devices) — the sticky bit
is meaningful on a directory, and the existing U-25 control, its fixtures (`/tmp`,
`/var/tmp/legacy.sock`) and main §6.4 already assume it. `walk.sticky_missing` is the
directory subset U-23 judges; it carries no join fields (nothing reads them).

**Homes, for the hidden rule.** A hidden entry is any walked entry whose name begins with `.`
and that is not exempt as a home dotfile. Two kinds of home exist. **User homes** — `/root`
and every directory under `/home` — are exempt at any depth: a dotfile tree there
(`~/.config/x/.y`) is the normal state. **Service homes** — every other `pw_dir` of
`/etc/passwd` except one that is `/` or equal to or under `/bin`, `/sbin`, `/lib`, `/lib32`,
`/lib64`, `/libx32`, `/usr`, `/etc`, `/dev`, `/boot`, `/proc`, `/sys`, `/run`, `/tmp`,
`/var/tmp` — exempt only their **direct** hidden children (`/var/lib/postgresql/.psql_history`
is normal); a hidden entry deeper inside a service home (`/var/www/html/.cache`,
`/var/ftp/pub/.x`) is recorded, because `www-data:/var/www` and `ftp:/var/ftp` are stock
accounts whose trees are served, not lived in. Stock `/etc/passwd` carries `nobody:/` on the
RHEL family and `daemon:/usr/sbin` on the Debian family; treating those as homes would blind
the whole filesystem or `/usr/sbin`, hence the exclusion list. The home set the walk used is
recorded in `walk.stats.home_roots` (`[{path, user, kind: user|service}]`, sorted by `path`
then `user`; a `pw_dir` shared by several accounts — `_apt`, `messagebus` and `tcpdump` all
sit on `/nonexistent` on the Debian family — yields one row per account, a `pw_dir` that does
not exist is still a row, and the two prefix roots `/root` and `/home` appear once each with
`user: ""` and `kind: user`) so a reader can see why an entry was or was not recorded. The walk still descends into a hidden
directory but records only the entry, never its children. The embedded allowlist has two
parts, each line documented with why it is normal: exact paths (`/.dockerenv`,
`/etc/.pwd.lock`, `/etc/.updated`, `/var/.updated`, `/etc/.resolv.conf.systemd-resolved.bak`,
`/var/lib/rpm/.rpm.lock` (unpackaged, created by rpm on every RHEL-family host), the five systemd `tmpfiles.d/x11.conf` directories `/tmp/.X11-unix`, `/tmp/.ICE-unix`,
`/tmp/.XIM-unix`, `/tmp/.font-unix`, `/tmp/.Test-unix`, …) and bare names
(`.well-known`, `.git`, `.gitignore`, `.gitkeep`, `.keep`, `.placeholder`, `.htaccess`,
`.bin`, `.github`, `.npmignore`, `.eslintrc*`, …). An allowlisted entry is still recorded (up to
its own cap) with `allowlisted: true` — the list shows, it never hides. `mode` is the raw
`st_mode & 07777` as an integer, the `writePermFacts` convention.

**W-5 — known ids.** `uid_known` is "in `/etc/passwd`, or inside a range `/etc/subuid` grants
to a passwd user, or inside the systemd dynamic-user range 61184–65519"; `gid_known` the same
over `/etc/group` and `/etc/subgid`; the four files are declared reads. `uid_class`/`gid_class`
say which: `passwd`, `subid`, `dynamic`, `unknown`. Collectors cannot read each other's
facts, so this duplicates the `accounts` collector's passwd parse at the cost of four small
reads. A host whose accounts also come from a remote NSS source (sssd, ldap, winbind) has
files whose uids exist remotely and not locally; the evaluator's degradation only softens a
holding verdict, it never turns a FAIL into WARN — so U-15 does not degrade, it steps aside:
its judgment sits in a mechanism gated on `accounts.nss.remote eq false` and
`accounts.nss.passwd_sources not_contains compat` (compat's NIS `+` entries are the one
remote layout `accounts.nss.remote` documents it cannot detect), and on such a host no
mechanism applies and `absent_means: manual` reads MANUAL with those facts as evidence (§5).
The control's description says the remaining blind spot out loud: an sssd configured only
through `conf.d`, which `accounts.nss.remote` does not detect, reads FAIL, and the operator's
remedy is a waiver or fixing the detection.

Other keys: `walk.complete` (existing; also the carrier of the non-root and mountinfo
failures, W-1 and §7), `walk.skipped[]` (`{path, reason}`), `walk.stats` (record: `entries,
dirs, files, symlinks, stop_reason, last_path, truncated_counts, allowlisted_hidden,
config_unreadable, home_roots, mnt_id_fallback, nice_applied, ioprio_applied`). No duration lives under
`walk.*` — `run.collectors[walk].ms` already records it, and main §9 keeps volatile values
under `run`. Seven new keys (`walk.suid_sgid`, `walk.suid_sgid_unverified`,
`walk.sticky_missing`, `walk.unowned`, `walk.hidden`, `walk.skipped`, `walk.stats`), every
list and `walk.stats` `sensitivity: internal` (paths, uids and, in `home_roots`, user names —
the same sensitivity `accounts.users` already carries), every list `subject_kind: file`, all
`since: 1` like every key so far, `schema_version` unchanged;
`walk.world_writable` gains three record fields, which main §5.7 counts as additions.
`walk.skipped` and `walk.stats` will appear in the fact-usage report as read by no control —
they are provenance, and the report says so. Every list is sorted by `path`; record fields
are emitted in a fixed order.

## 4. The package join and the reference list (W-6, W-7, W-8)

**W-6 — one join, after the traversal, over the candidates only.** The default join is
ownership and, where a source has it, the declared mode; no package is verified (W-8). The
family is decided the way `patch.go` does — `/var/lib/dpkg/status` present → dpkg,
`/var/lib/rpm` present → rpm — both already-declared shapes; a host with neither has no
package database and every joined list is `absent` ("no package database"), which
`absent_means: manual` turns into MANUAL. The walk never reads `/etc/os-release` (a symlink on
the RHEL family); the reference list (W-7) is chosen from `run.host.os_release.{id,
version_id}`, which the `os` collector fills before `walk` runs.

*What `package_declared` means, per list.* For `walk.suid_sgid` and `walk.world_writable` it is
"a source declares this path with the same special bit the candidate carries" (setuid/setgid,
resp. other-write); for `walk.hidden` it is only "the path is owned by a package" — a hidden
entry carries no bit to compare. `reference` names the source that decided: `rpmdb`, `dpkgdb`
(ownership only), `statoverride`, `list`, `unpackaged` (no source owns the path), or the reason
no source could decide — `unlisted`, `version_mismatch`, `postinst` (the package sets the mode
at install time, W-7), `none`.

*rpm hosts:* one whitelisted command,
`rpm -qa --qf '[%{=NAME}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILENAMES}\n]'`
(timeout 120 s, output cap 256 MiB — a line per packaged file is ~80 bytes and a large host
has close to a million; the `=` prefix repeats the package name per file, the path is last so
a line splits on the first four tabs and whitespace in a path is harmless, and no digest is
printed). The stream is parsed line by line and only lines whose path is in the candidate set
are kept — the join's memory is bounded by the candidates, not by the host's file count, and
`RunCommand`'s buffer is the only copy. `package` is the owning package, `package_declared`
as defined above from the declared mode, `declared_mode` the table's mode, `declared_owner`/
`declared_group` the names rpm records (never called `uid`/`gid`), `reference` `rpmdb`. A path
not in the table: `package: ""`, `package_declared: false`. A failed, timed-out or capped
command gives every joined list the command's status — `error`/`timeout`, or `ok` with
`truncated: true` on the output cap — with the command in the reason (C3), never `absent`:
main §6.5 row 6 makes those controls ERROR, which is the truth about a join that did not
finish.

*dpkg hosts:* the path → package table is read from `/var/lib/dpkg/info/*.list` (declared
glob, 16 MiB per file — TeX Live's lists exceed 1 MiB; a truncated `.list` truncates the join
exactly like a capped `rpm`), `/var/lib/dpkg/diversions` (applied first: a diverted path is
looked up under its diverted-to name) and `/var/lib/dpkg/statoverride` on top; installed
versions come from `/var/lib/dpkg/status` (the `patch.go` read shape, `Package:`/`Version:`
only). **Merged-usr aliasing:** the lists record `/bin/su`, `/sbin/…`, `/lib/…` while the
no-follow walk sees only `/usr/bin/su`; the walk records which of `/bin`, `/sbin`, `/lib`,
`/lib32`, `/lib64`, `/libx32` are symlinks into `/usr` (it lists `/` anyway) and canonicalises
every `.list`, `diversions`, `statoverride` and reference-list path through that table before
lookup, keeping the pre-merge form it matched in `declared_path` when it differs. The
database holds no modes, so for the two bit-judged lists `package_declared` is decided by, in
order: a `statoverride` entry for the path (declares the mode; `reference: statoverride` — an
override on an unpackaged path counts as declared with `package: ""`, because dpkg enforces it
on every upgrade); else the release's reference list (W-7) with its version rule: a path the
list holds **with** the bit is declared true whatever the installed version (treating every
patched host as unverified would make the list useless on the day after `apt upgrade`; the
list can only vouch for what it saw, so a bit a later update removed — util-linux dropped
setgid from `/usr/bin/wall` and `/usr/bin/write` for CVE-2024-28085, iputils moved `ping` from
setuid to file capabilities — still passes with `reference: list` until the list is
regenerated; the steady-state note and the control description say so); a path the list holds
without the bit, or does not hold, is declared false only when the installed version equals
the pinned one — otherwise `reference: version_mismatch` (the newer version may legitimately
have added the helper); else `unlisted` (packaged, package not covered by the list) or `none`
(no list for this release). For `walk.hidden` a `.list` hit is enough (`dpkgdb`). For
`walk.world_writable` on dpkg an uncovered package yields `unlisted` → declared false → WARN
(the control is `partial`), which is the honest reading. Only candidates that are lookups
against a fully read table are decided; the `.list` files are streamed and only candidate
paths are kept, as for rpm.

**W-7 — the reference list decides, `walk.suid_sgid_unverified` holds what it cannot.** The
grammar cannot say "this element is FAIL, that one WARN", so the collector splits by
verifiability: a SUID/SGID candidate that is packaged and whose mode the join could NOT decide
(`reference` `unlisted`, `version_mismatch`, `postinst` or `none`) goes to
`walk.suid_sgid_unverified`;
everything decided — unpackaged (`package_declared: false`), or covered by statoverride, the
rpm database or the reference list either way — goes to `walk.suid_sgid`. For the list to
decide **either way** it must hold **every file of every covered package with its mode**, not
only the setuid ones: `docs/reference/suid/<id>-<version_id>.json` is `{distro, release,
image_digest, generated, packages: [{name, version}], entries: [{path, mode, owner, group,
package}]}`, sorted by path, paths in the form the walk will see them (canonicalised through
the same merged-usr table). Join rule on dpkg, one row per case:

| Candidate's package | Installed version | Path in the list | Result |
|---|---|---|---|
| not in `packages` | — | — | `unlisted` → unverified (WARN) |
| in `packages` | any | present with the bit | `list`, declared true → verified, passes |
| in `packages` | = pinned | present without the bit, or absent | `list`, declared **false** → `walk.suid_sgid`, FAIL (`chmod u+s /usr/bin/python3` is caught) |
| in `packages` | ≠ pinned | present without the bit, or absent | `version_mismatch` → unverified (WARN naming both versions) |
| unpackaged | — | — | `unpackaged`, `package_declared: false` → `walk.suid_sgid`, FAIL |

A package whose maintainer script sets the bit at install time instead of shipping it in the
archive (Debian policy prefers `dpkg-statoverride`, which the join reads, but a plain `chmod`
in `postinst` exists) is recorded in `sources.json` with `postinst_sets_mode: true` — found by
reading the package's maintainer scripts when it is curated — and its files are marked in the
list so they route to unverified with `reference: postinst` rather than to a false FAIL. On a
host that has applied updates, the steady state is therefore: files the list knows with the bit
pass, including a bit a security update has since removed and an administrator restored — the
list is a floor, not a ceiling, and the `suid_sgid` control description names this residue;
new or moved helpers read WARN until the list is regenerated for that release, which the
maintainer does per point release.

The list is generated by a maintainer-run tool, `tools/suidindex`, from
`docs/reference/suid/sources.json`: per release, a public container image (name and digest)
and a **curated** list of official packages — seeded from the image's own `find / -perm /6000`
owners and extended with named server packages known to ship setuid/setgid files (`at`,
`screen`, `postfix`, `exim4-base`, `mtr-tiny`, `fuse3`, `polkitd`, `dbus`, …), each with a
one-line reason. Packages installed in the image are read from the image's own filesystem
(`dpkg -L` / `rpm -ql` plus `stat`, no download); packages of the extended list are pinned per
entry to a snapshot-service URL (`snapshot.debian.org`, `snapshot.ubuntu.com`) and a SHA-256,
the way `tools/refindex/sources.json` pins URL and digest, so `-check` cannot drift with the
live archive; inside the same container the tool fetches that `.deb` and reads its headers
with `dpkg-deb --fsys-tarfile <deb> | tar -tv` (no install, no new Go dependency; D28 stands).
rpm releases use `rpm -qa --qf` in the image the same way and their list is cross-check
evidence only — the rpm join never depends on it. The Debian `Contents-amd64` index carries no
modes and is used, if at all, only to map a known path to its owning package. Like `refindex`,
CI never runs the generator; `tools/suidindex -check` regenerates and compares when the
maintainer wants to, and a unit test loads every committed list for shape, sort order,
canonical paths and that each release in `sources.json` has one. The first `sources.json`
covers ubuntu 22.04, ubuntu 24.04, debian 12, rocky 9, almalinux 9 — the CI images.

**W-8 — package verification is plan 3C's.** `rpm -V <pkg…>` and `dpkg --verify <pkg…>` take a
package list computed at run time; the guard's whitelist is an exact argument match (main §8
"fixed arguments"), and both commands exit 1 when any file differs, which today's command
convention would file as a failed command. 3C designs a `CommandTemplate{Path, Args, Tail}`
declaration whose `Tail` names a vocabulary (`package-name`: `^[A-Za-z0-9][A-Za-z0-9.+_-]*$`,
never a leading `-`, count capped), the guard rule and `--list-actions` rendering for it
(`rpm -V <package…>`), and "exit 1 = differences", together with the package-integrity check
that judges the result. 3A ships no verify flag, no verify key and no verify command.

## 5. Controls (W-9, W-10, W-11)

| Control | Item | Automation | Judgment |
|---|---|---|---|
| `muster.file.unowned_files` | U-15 | `auto` | `absent_means: manual`; one mechanism `when: [{accounts.nss.remote eq false}, {accounts.nss.passwd_sources not_contains compat}]` with checks `walk.unowned none subject path where uid_known eq false` and `walk.unowned none subject path where gid_known eq false`; a remote-NSS or NIS-compat host reads MANUAL with those facts as evidence |
| `muster.file.suid_sgid` | U-23 | `auto` | `walk.suid_sgid each subject path require package_declared eq true`; `walk.suid_sgid none subject path where path in "${forbidden_suid}"` (`params.forbidden_suid`, `list<string>`, default `[]`); `walk.sticky_missing none subject path where path present` |
| `muster.file.suid_sgid_unverified` | U-23 | `partial` | `walk.suid_sgid_unverified none subject path where path present` → WARN naming each path, its package and its `reference` |
| `muster.file.hidden_entries` | U-33 | `partial` | `walk.hidden each subject path where allowlisted eq false require package_declared eq true` → WARN |
| `muster.file.world_writable` (existing) | U-25 | `partial` | unchanged; `walk.world_writable` is now populated; its description gains the `kind` and `reference` fields |

Every `none` clause carries `subject: path` so observations are keyed `file:<path>` (main §6.4)
and waivers can name a subject; the plan adds a lint rule "`none` on a `list<record>` needs
`subject`" so this cannot be forgotten again. All four new controls carry `absent_means:
manual` (§7 relies on it for the no-package-database case). `accounts.nss.passwd_sources` is
`list<string>`; the grammar has `contains` but no `not_contains`, so the plan adds
`not_contains` beside `contains` in the list comparison (`compareList`), in the string branch
of the scalar comparison (substring, so lint and the evaluator agree on every fact type) and
in lint's `scalarOps`, the same shape as `not_in` beside `in`.

**W-9 — no guide list of "SUID binaries to remove", anywhere.** The default `forbidden_suid` is
empty. The KISA guide and CIS both carry lists of binaries whose setuid bit is conventionally
removed; copying either would reproduce their text and the lists differ by distribution. An
operator who has such a policy sets the parameter; the control's description says so. The
same boundary binds `tools/suidindex/sources.json`: its package list is derived from image
and package facts, never seeded from a guide's or benchmark's list of binaries.

**W-10 — one item, two controls, and U-23 is `auto`.** U-23 is claimed by two controls. 2M's
`kisa_coverage` lint rule ("exactly one control per item") is relaxed to "at least one"; the
duplicate detection is narrowed to an id listed twice inside one control; the README sentence
"an item can be neither forgotten nor claimed twice" (both languages) becomes "neither
forgotten nor mis-claimed", and its "Of the 64 controls" becomes 68. Main Appendix A lists U-23
as `partial (walk)` and §10.1 uses "which SUID files are legitimate" as its example of a human
judgment; both are amended in the same commit as this spec with the decision: an unpackaged
setuid file, or a packaged one whose package declares the file without the bit, is an
automatic finding; only a package declaration the join cannot verify is a human judgment. The
enrolled count stays per item (67 of 67); the automation triple counts controls (auto 57,
partial 7, manual 4, of 68).

**W-11 — statuses.** All five walk-based controls (the four new ones and U-25) pass through
main §6.5 rows 9–10a: `MANUAL` without `--deep`, `ERROR(walk_incomplete)` when the walk
stopped early, `ERROR` naming the denial when it could not run as non-root (row 10a). A joined
list that carries a command's or read's failure is ERROR by row 6; a list at its cap is
`ERROR(truncated)` for that control only; a host with no package database is MANUAL through
`absent_means: manual`; a host whose root mount is not walkable reads NOT_APPLICABLE (§7).
Which lists depend on the join: `suid_sgid`, `suid_sgid_unverified`, `world_writable`,
`hidden`; `unowned`, `sticky_missing`, `skipped`, `stats`, `complete` never do — an rpm failure
cannot hide an unowned file or a sticky-less directory.

Fixtures, per control as they apply: `pass-*`/`fail-*` (`fail-` on a partial control expects
WARN), `manual-no-walk` (no `walk.*` keys), `error-walk-incomplete` (`walk.complete false`,
`_expect.reason_code: walk_incomplete`), `error-walk-denied` (`walk.complete` denied,
`_expect.reason_code: permission_denied`), `na-overlay-root` (every walk list `unsupported`,
`walk.complete true`) for all five, the join shapes (`pass-rpm-declared`, `pass-dpkg-usrmerge`
— a `.list` naming `/bin/su` for a candidate `/usr/bin/su`, `fail-dpkg-unpackaged`,
`fail-dpkg-covered-no-bit`, `pass-dpkg-version-differs-bit-listed`, and for the unverified
control `fail-dpkg-unlisted` and `fail-dpkg-version-mismatch`), `fail-sticky-missing` for
`suid_sgid` (the `forbidden_suid` parameter is exercised by an evaluator unit test with
params, since the fixture harness reads only `_expect.reason_code`/`exit_code`),
`fail-hidden-in-usr-sbin` and `fail-hidden-in-var-www` for `hidden_entries`,
`manual-no-package-db`, `error-rpm-truncated`, and for U-15 `manual-remote-nss`,
`manual-nis-compat` and `pass-subuid-owned`. U-15's `error-*` and `na-*` fixtures carry the two
NSS gate facts as `ok` so the mechanism is chosen before the walk gate runs. All synthetic;
paths are real distribution paths.

## 6. Command line (W-12)

`collect` gains: `--deep` (already parsed; the "arrives in stage 3" warning goes away and
`run.deep` becomes true), `--walk-budget <duration>` (default `10m`), `--walk-max-entries <n>`
(default `2000000`), `--walk-exclude <path>` (repeatable), `--walk-include <path>` (repeatable,
fixed-set entries only). Every walk flag without `--deep` is an error (`exit 2`, the flag
named); so is a `--walk-budget` above the effective `--timeout`. `--deep` raises the default
`--timeout` to `--walk-budget + 5m` unless `--timeout` was given. `collect --list-actions`
gains the walk row and the `rpm -qa --qf …` command. Nothing about the walk is written to the
run header beyond `run.deep` and the collector's `status`/`reason`/`ms`; the effective
exclusions are readable from `walk.skipped[]`.

## 7. Errors and degradation

- The walk cannot read `/proc/self/mountinfo` → `walk.complete` carries that read's envelope
  (path-prefixed, C3); no other key is written; the collector's status follows it; main §6.5
  row 10a makes the controls ERROR naming the read.
- Non-root → `walk.complete` denied ("the walk needs root"), the collector `denied` from its
  facts, the run partial (exit 1), the controls ERROR by row 10a (W-1).
- The root mount `/` is not in the W-2 set (overlay, squashfs, an unknown type): every walk
  list is `unsupported` with the reason `root filesystem is <type>; the walk answers for a
  host, not for a container layer`, `walk.complete` is `true`, `walk.skipped` records `/` as
  `excluded_type`. Main §6.5 row 7 gives NOT_APPLICABLE(unsupported_env) — never a PASS on
  empty lists.
- A directory the walk cannot open or that changed under it → `walk.skipped[]` with `denied`
  or `vanished`; the walk continues; `walk.complete` stays true.
- Budget or deadline → `walk.complete false`, stop reason, last path (§2). A list at its cap →
  that list `truncated: true`, the walk continues.
- `/etc/passwd`, `/etc/group`, `/etc/subuid` or `/etc/subgid` unreadable → `walk.unowned` is
  that read's status (C3); the other lists are unaffected. A container-storage configuration
  file that exists but cannot be read → `walk.stats.config_unreadable` (W-2); the fixed set
  still applies.
- `rpm -qa --qf` fails, times out or is capped → every joined list carries the command's
  status with the command in the reason (`error`, `timeout`, or `ok` + `truncated`); on dpkg
  hosts an unreadable or truncated `.list`/`diversions`/`statoverride`/`status` file poisons
  the join the same way (the first read error names the file). `walk.unowned`,
  `walk.sticky_missing`, `walk.skipped`, `walk.stats`, `walk.complete` are unaffected.
- No package database on the host → every joined list `absent` ("no package database") →
  MANUAL through `absent_means: manual`.
- No reference list for the release, or the package's version differs from the pin **and the
  list does not hold the path with the bit**, or the package sets the mode in `postinst` → the
  packaged SUID/SGID candidate goes to `walk.suid_sgid_unverified` (WARN, `reference: none`,
  `version_mismatch` or `postinst`); the unpackaged ones still FAIL in `walk.suid_sgid`.
- Nothing in the walk ever produces `error` on a leaf for a layout it declined to enter or a
  file it declined to read: convention C4 applies — every such decision is a `walk.skipped`
  row, a `walk.stats` note or an `allowlisted`/`unlisted` mark, never an error envelope.

## 8. Testing

- **Unit, cross-platform:** the traversal runs against an in-memory `Access` double whose
  `ReadDir` serves a scripted tree (kinds, modes, uids, mount ids, `(dev, ino)`, errors per
  directory) and a scripted mountinfo; every rule of §2 has a case: symlink not followed, a
  foreign mount id not entered, a bind alias removed from the enter set before the walk and
  recorded once, a `(dev, ino)` hit recorded as `bind_duplicate`, an unlisted mount recorded, an
  autofs root listed and never opened, a container root excluded and re-included by flag, a
  configured `data-root`/`graphroot`/containerd `root` excluded, a symlinked fixed-set root's
  target excluded, a per-home rootless root excluded, an unreadable configuration file noted
  in `walk.stats`, `denied` and `vanished` recorded and continued, the post-open identity
  mismatch, each budget and the deadline stopping with the right reason and `complete false`, a
  list at its cap continuing with `truncated`, the allowlisted-rows sub-cap. The home rule has
  the literal RHEL `nobody:/` and Debian `daemon:/usr/sbin` entries and a `/var/lib/postgresql`
  service home. The join runs against fixture `rpm -qa --qf` output and fixture
  `.list`/`diversions`/`statoverride`/`status` files plus a fixture reference list, including
  the merged-usr alias case, the version cases (bit listed + version differs → passes; absent
  + version differs → `version_mismatch`) and a `postinst_sets_mode` package; every row of
  W-7's table and every `reference` value is produced by a test. The candidate rules have a
  case per list, including the two-part allowlist, the user-home vs service-home depth rule
  (`www-data:/var/www` with a deep hidden directory recorded, `postgres` with a direct
  `.psql_history` exempt), a symlink in `walk.unowned`, and every `uid_class`.
- **Determinism:** the walk over a scripted tree twice yields byte-identical lists; a tree
  presented in a different directory order yields the same output.
- **Linux, on the lab host:** `collect --deep` as root completes on the stock Ubuntu 22.04
  node within the default budget; `walk.stats` and the list sizes are recorded in the plan's
  Execution notes; the five controls' statuses on the stock host are recorded; a non-root run
  shows `walk.complete` denied and `collect` exit 1. The `denied` skip is proven by running the
  walk as uid 0 with `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE` dropped (`setpriv
  --inh-caps=… --bounding-set=…`) against a `chmod 000` directory in a `mktemp -d` tree —
  `chmod 000` alone does not stop root, and `chattr +i` forbids writes only.
- **CI:** `collect-root` (the runner VM, ext4) runs `collect --deep` and asserts
  `walk.complete == true` and `status == "ok"` on every walk list, plus `check` with no ERROR
  (if the runner image's own dotfile trees ever push `walk.hidden` to its cap, the remedy is
  the allowlist or the cap, never a weaker assertion); the container matrix and the read-only contract job run `--deep` too and assert every walk
  list `unsupported` (their root is overlay) with `run.complete` still true, driven by a new
  `container` class in `docs/reference/capability-matrix.json` (`unsupported: [walk.suid_sgid,
  walk.suid_sgid_unverified, walk.world_writable, walk.sticky_missing, walk.unowned,
  walk.hidden]`) the way the `no-systemd` class drives its step; the non-root job runs `--deep`
  and the matrix gains `walk.complete` under `nonroot.denied`.
- **Reference list:** `tools/suidindex -check` is a maintainer target; a unit test loads every
  committed list and checks the shape, sorting, canonical (`/usr`-form) paths, that every
  entry's package is in `packages` with a version, and that each release named in
  `sources.json` has a list.
- **Fixtures and coverage:** the fixture set of §5; `controls lint` with the relaxed
  `kisa_coverage` and the new `none`-needs-`subject` rule; `coverage -check` with the 67/67
  line and the README fragments updated in the same task.

## 9. What changes elsewhere

- `internal/collect`: `Access.ReadDir` (+ the embeddable double base), `DirEntry`,
  `Declaration.Walk`, `Action.Kind: walk`, the guard's walk licence, one whitelisted command
  (`rpm -qa --qf …`). No change to `callRun`.
- `internal/facts/registry.yaml`: seven keys, three record fields on `walk.world_writable`.
- `internal/controls/lint.go`: `kisa_coverage` relaxed (W-10); `none` on a `list<record>`
  needs `subject`; `not_contains` (§5).
- `cmd/muster/collect.go`: five flags, the deadline coupling, the warning removed, `run.deep`.
- `tools/suidindex`, `docs/reference/suid/` (five lists + `sources.json`); no new Go dependency.
- `controls/file/`: four new controls, `world_writable`'s description; `docs/reference/kisa/
  kisa_deferred.json` emptied; `docs/reference/coverage.md` regenerated; `docs/reference/
  capability-matrix.json` (+ `walk.complete` under `nonroot.denied`, + the `container` class);
  README pair (the roadmap sentence, the lint sentence, "Of the 64 controls" → 68);
  `CHANGELOG.md` (four verdict-affecting controls under Controls; `controls/VERSION` bumps).
- Main design, EN and KO, amended in the same commit as this spec: Appendix A row U-23 and
  the §10.1 example (W-10); §8's ionice wording and autofs wording (§2, W-3); §5.8's
  `truncated_count` → per-list `truncated: true` + `walk.stats.truncated_counts`; §6.5 row 10a.
- `CLAUDE.md`: a line on `Declaration.Walk`/`ReadDir` and one on `--deep` with the lab scripts
  (the recipe lives in the session notes, not in the repository).
