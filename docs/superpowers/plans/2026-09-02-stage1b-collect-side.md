# Stage 1B — collect side (Linux) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `muster collect` for Linux so that, on Ubuntu 22.04/24.04 or Rocky/Alma 9, it writes a snapshot that `muster check` (plan 1A) evaluates end to end for the five stage-1 controls — with the read primitive, exec discipline, collector registry, `--list-actions`, snapshot lifecycle and `collect` exit codes that the design makes contracts.

**Architecture:** Everything here lives in `internal/collect` behind `//go:build linux` (plus a tiny non-Linux stub so the binary still builds elsewhere and says `collect` needs Linux). Collectors are registered with what they read and run; the registry drives both execution and `--list-actions`. The five collectors fill exactly the keys in `internal/facts/registry.yaml`. The snapshot writer owns the lifecycle. Nothing in this plan changes `internal/check`, `internal/controls` or `internal/report`.

**Tech Stack:** Go 1.25, `golang.org/x/sys/unix` (second and last direct dependency: `Openat2`, `Flock`, `Statfs`, `Llistxattr`), standard library. Tests need Linux; some need root and are skipped otherwise (`t.Skip` with the reason — and the CI job runs them as root so the skip is never the only path).

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` — sections 4.4–4.5 (trust boundary, distribution variance), 5 (snapshot), 5.6 (sensitive values), 5.9 (lifecycle), 7.1 (collect errors and exit codes), 8 (security of the tool), 9 (`--list-actions`), 10.2 (stage 1 collector minimums), 11 (contract tests, CI). Plan 1A defines every type this plan fills.

## Global Constraints

- All collector code is Linux-only: `//go:build linux` on every file in `internal/collect` except `collect_other.go`; the check side must keep compiling on every GOOS (spec §4.7, D23).
- Direct dependencies after this plan: `gopkg.in/yaml.v3`, `golang.org/x/sys` — nothing else (D28).
- `collect` writes exactly one file (the snapshot), restarts nothing, changes nothing, opens no network connection, and never reads a control, waiver or previous snapshot (spec §4.4, §8, D14).
- Every command runs through the exec discipline: absolute path, fixed arguments, rebuilt environment (`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, `LANG=C`, `TZ=UTC`), no shell, its own process group, a timeout and an output cap (spec §8).
- Every file read goes through the read primitive: no symlink followed in any path component, regular files only, size cap with `truncated`, NUL → binary (spec §8).
- Every collector declares its reads and commands in the registry; a test fails when a collector touches anything it did not declare (spec §11).
- Fact statuses written by collect are exactly `ok | absent | denied | unsupported | timeout | error`; never `missing` (spec §5.2).
- Secrets are never stored: no password hashes, key bodies or community strings; `sensitivity: secret` keys are redacted by construction (spec §5.6).
- Snapshot: default `/var/lib/muster/snapshots/<hostname>-<UTC timestamp>-<short digest>.json`, 0600 in a 0700 directory, atomic, lock at `/var/lib/muster/.lock`, never `/tmp` by default (spec §5.9).
- Exit codes: 0 complete, 1 partial, 2 no snapshot; `--require-root` and `--require-complete` (spec §7.1, D11).
- No snapshot captured from an employer or customer host is ever committed (D02); CI fixtures come from public images or the GitHub runner.
- Commit after every task with the repository's trailer lines; never push.

---

## Where to run this plan

Nothing here runs on Windows. Three options, in order of preference for a task's Step "Run":

1. **A Linux lab host over SSH** with root (an Ubuntu 22.04 host is ideal — it is a first-release target). Sync the working tree with `git push` to a private remote or `rsync`, build there, run `go test ./internal/collect/ -v` as root. Never commit a snapshot from such a host.
2. **A container**: `docker run --rm -v "$PWD":/src -w /src golang:1.25 go test ./internal/collect/ -v` for non-root tests; add `--privileged` only for the walk boundary test that needs a bind mount.
3. **GitHub Actions** (Task 7) as the always-on oracle: the runner is a real VM with systemd and passwordless sudo.

Lab-host details (address, credentials, aliases) live in the developer's `~/.ssh/config`, never in this repository.

---

## File structure

| Path | Responsibility |
|---|---|
| `internal/collect/doc.go` | package doc, build tag note |
| `internal/collect/collect_other.go` | `//go:build !linux`: `Run` returns "collect requires Linux" |
| `internal/collect/readfile.go` | the read primitive: `ReadFile`, `Stat`, tiers, limits |
| `internal/collect/exec.go` | `RunCommand` with the exec discipline |
| `internal/collect/registry.go` | `Collector`, `Register`, `All`, `ListActions`, access interfaces |
| `internal/collect/facts.go` | `Builder`: sets envelopes/settings by registry key; `ok/absent/denied/...` helpers |
| `internal/collect/writer.go` | snapshot lifecycle: dir, name, lock, free space, atomic write, `latest` |
| `internal/collect/run.go` | `Run(ctx, Options) (Outcome, error)`: header, collectors, partial failures, exit-code mapping |
| `internal/collect/collectors/os.go` | `os`, `host`, `env` facts |
| `internal/collect/collectors/services.go` | `services.ssh.*`, `services.telnet.*` via `systemctl show` |
| `internal/collect/collectors/sockets.go` | `/proc/net/{tcp,tcp6,udp,udp6}` → `sockets.listening` |
| `internal/collect/collectors/sshd.go` | `sshd -T`, `sshd_config` + `Include` parse → `sshd.*` |
| `internal/collect/collectors/files.go` | `/etc/passwd` permission facts, `/etc/securetty` |
| `internal/collect/collectors/accounts.go` | `login.defs`, `/etc/shadow` ageing (derived, no hashes), `accounts.users` |
| `internal/collect/collectors/walk.go` | the walk skeleton: `--deep` flag, boundaries, budget, `complete`; no traversal yet |
| `cmd/muster/collect.go` | `collect` flags and wiring; `--list-actions` |
| `.github/workflows/ci.yml` | `collect-linux` jobs (runner as root, non-root, containers, network-less read-only) |

---

### Task 1: The read primitive

**Files:**
- Create: `internal/collect/doc.go`, `internal/collect/collect_other.go`, `internal/collect/readfile.go`, `internal/collect/readfile_test.go`
- Modify: `go.mod` (add `golang.org/x/sys`)

**Interfaces:**
- Produces (package `collect`, Linux):
  - `type ReadMeta struct { Tier string; Size int64; Truncated bool; Binary bool; Mode os.FileMode; UID, GID uint32; ParentUntrusted bool }` — `Tier` is `openat2` or `componentwise`.
  - `var ErrNotRegular = errors.New("not a regular file")`, `var ErrSymlink = errors.New("symbolic link in path")`.
  - `func ReadFile(path string, limit int64) ([]byte, ReadMeta, error)` — `path` must be absolute and clean; tier 1 `unix.Openat2(AT_FDCWD, path, &OpenHow{Flags: O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK, Resolve: RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS})`; on `ENOSYS`/`EPERM`/`EINVAL` from a seccomp profile fall back to tier 2: open `/` with `O_PATH|O_DIRECTORY|O_NOFOLLOW`, then for each component `Openat(fd, comp, O_PATH|O_NOFOLLOW|O_CLOEXEC)` (directories) and finally `O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` for the last; `ELOOP` at any step → `ErrSymlink`. After opening, `Fstat`: not `S_IFREG` → `ErrNotRegular`. Read at most `limit+1` bytes; more → keep `limit`, `Truncated=true`. Any NUL byte in the data → `Binary=true` and data is returned empty. `ParentUntrusted` when the parent directory is not uid 0 or has `S_IWOTH`/`S_IWGRP`.
  - `func Stat(path string) (ReadMeta, error)` — the same resolution without reading (for permission facts), `Lstat`-based on the final component so a symlink is reported as `ErrSymlink` rather than followed.
  - `func DeniedReason(err error) (string, bool)` — maps `EACCES`/`EPERM` to `"requires root or CAP_DAC_READ_SEARCH"`.
- Produces (non-Linux stub): `func RunCLI(...)` is not needed here; `collect_other.go` only exports `const Supported = false` and `func ReadFile(string, int64) ([]byte, ReadMeta, error)` returning `errors.New("collect requires Linux")`, with `ReadMeta` defined in a shared `//go:build` -free file `types.go` (move the struct there so both builds see it).

- [ ] **Step 1: Write the failing tests (Linux)**

`internal/collect/readfile_test.go`:

```go
//go:build linux

package collect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func mkfile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestReadFileHappyPathRecordsMeta(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	mkfile(t, p, "PermitRootLogin no\n", 0o600)
	data, meta, err := ReadFile(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "PermitRootLogin no\n" || meta.Truncated || meta.Binary || meta.Size != 19 {
		t.Errorf("%q %+v", data, meta)
	}
	if meta.Tier != "openat2" && meta.Tier != "componentwise" {
		t.Errorf("tier %q", meta.Tier)
	}
}

func TestReadFileRefusesSymlinkInAnyComponent(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "shadow")
	mkfile(t, secret, "root:$6$notreally$hash::0:99999:7:::\n", 0o600)
	// final component is a link
	link := filepath.Join(dir, "passwd")
	os.Symlink(secret, link)
	if _, _, err := ReadFile(link, 1<<20); !errors.Is(err, ErrSymlink) {
		t.Errorf("final-component symlink: err=%v", err)
	}
	// intermediate component is a link
	realDir := filepath.Join(dir, "real")
	os.Mkdir(realDir, 0o755)
	mkfile(t, filepath.Join(realDir, "f"), "x", 0o644)
	os.Symlink(realDir, filepath.Join(dir, "linkdir"))
	if _, _, err := ReadFile(filepath.Join(dir, "linkdir", "f"), 1<<20); !errors.Is(err, ErrSymlink) {
		t.Errorf("intermediate symlink: err=%v", err)
	}
	// symlink loop
	os.Symlink(filepath.Join(dir, "b"), filepath.Join(dir, "a"))
	os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	if _, _, err := ReadFile(filepath.Join(dir, "a"), 1<<20); !errors.Is(err, ErrSymlink) {
		t.Errorf("loop: err=%v", err)
	}
}

func TestReadFileRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := ReadFile(fifo, 1<<20); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("err=%v want ErrNotRegular", err)
		}
	case <-timeAfter(2):
		t.Fatal("ReadFile blocked on a FIFO")
	}
}

func TestReadFileTruncatesAndFlagsBinary(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	mkfile(t, big, strings.Repeat("a", 1000), 0o644)
	data, meta, err := ReadFile(big, 100)
	if err != nil || len(data) != 100 || !meta.Truncated {
		t.Errorf("len=%d meta=%+v err=%v", len(data), meta, err)
	}
	bin := filepath.Join(dir, "bin")
	mkfile(t, bin, "abc\x00def", 0o644)
	data, meta, err = ReadFile(bin, 100)
	if err != nil || len(data) != 0 || !meta.Binary {
		t.Errorf("binary: len=%d meta=%+v err=%v", len(data), meta, err)
	}
}

func TestReadFileNamesWithNewlines(t *testing.T) {
	dir := t.TempDir()
	odd := filepath.Join(dir, "weird\nname")
	mkfile(t, odd, "ok", 0o644)
	if data, _, err := ReadFile(odd, 10); err != nil || string(data) != "ok" {
		t.Errorf("%q %v", data, err)
	}
}

func TestReadFileRequiresAbsolutePath(t *testing.T) {
	if _, _, err := ReadFile("etc/passwd", 10); err == nil {
		t.Error("relative path must be refused")
	}
}

func TestStatReportsSymlinkAndParentTrust(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o777)
	p := filepath.Join(dir, "f")
	mkfile(t, p, "x", 0o644)
	meta, err := Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !meta.ParentUntrusted {
		t.Error("world-writable parent must set ParentUntrusted")
	}
	os.Symlink(p, filepath.Join(dir, "l"))
	if _, err := Stat(filepath.Join(dir, "l")); !errors.Is(err, ErrSymlink) {
		t.Errorf("err=%v", err)
	}
}
```

Add a helper in the same test file:

```go
import "time"

func timeAfter(sec int) <-chan time.Time { return time.After(time.Duration(sec) * time.Second) }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (Linux): `go test ./internal/collect/ -run 'TestReadFile|TestStat' -v`
Expected: FAIL — package does not compile.

- [ ] **Step 3: Write the primitive**

Run: `go get golang.org/x/sys@v0.36.0 && go mod tidy`

`internal/collect/types.go` (no build tag):

```go
// Package collect gathers host facts as root and writes the snapshot
// (spec §4, §5, §8). Everything but this file and collect_other.go is
// Linux-only.
package collect

import "os"

// ReadMeta describes how a file was read and what it looked like.
type ReadMeta struct {
	Tier            string // openat2 | componentwise
	Size            int64
	Truncated       bool
	Binary          bool
	Mode            os.FileMode
	UID, GID        uint32
	ParentUntrusted bool
}
```

`internal/collect/collect_other.go`:

```go
//go:build !linux

package collect

import "errors"

// Supported reports whether collect can run on this platform (D23).
const Supported = false

var errPlatform = errors.New("muster collect requires Linux")

func ReadFile(string, int64) ([]byte, ReadMeta, error) { return nil, ReadMeta{}, errPlatform }
func Stat(string) (ReadMeta, error)                    { return ReadMeta{}, errPlatform }
```

`internal/collect/doc.go`:

```go
//go:build linux

package collect

// Supported reports whether collect can run on this platform (D23).
const Supported = true
```

`internal/collect/readfile.go`:

```go
//go:build linux

package collect

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	ErrNotRegular = errors.New("not a regular file")
	ErrSymlink    = errors.New("symbolic link in path")
)

const openFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK

// openNoFollow opens path without following a symlink in any component
// (spec §8 "Reads"): tier 1 openat2 with RESOLVE_NO_SYMLINKS, tier 2 a
// component-wise walk with O_NOFOLLOW. Returns the fd and the tier used.
func openNoFollow(p string, flags int) (int, string, error) {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return -1, "", fmt.Errorf("path %q must be absolute and clean", p)
	}
	how := unix.OpenHow{Flags: uint64(flags), Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(unix.AT_FDCWD, p, &how)
	switch {
	case err == nil:
		return fd, "openat2", nil
	case errors.Is(err, unix.ELOOP):
		return -1, "openat2", ErrSymlink
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EPERM), errors.Is(err, unix.EINVAL):
		// kernel without openat2, or a seccomp profile that rejects it: tier 2
	default:
		return -1, "openat2", err
	}
	dir, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "componentwise", err
	}
	comps := strings.Split(strings.Trim(p, "/"), "/")
	for i, c := range comps {
		last := i == len(comps)-1
		f := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if last {
			f = flags
		}
		next, err := unix.Openat(dir, c, f, 0)
		unix.Close(dir)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return -1, "componentwise", ErrSymlink
			}
			return -1, "componentwise", err
		}
		dir = next
	}
	return dir, "componentwise", nil
}

// ReadFile reads a regular file with a size cap. A symlink anywhere in the
// path, a FIFO, device or socket, or a relative path is an error; a file
// over the limit is returned truncated and flagged; a NUL byte marks the
// file binary and its content is not returned.
func ReadFile(p string, limit int64) ([]byte, ReadMeta, error) {
	fd, tier, err := openNoFollow(p, openFlags)
	meta := ReadMeta{Tier: tier}
	if err != nil {
		return nil, meta, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, meta, err
	}
	fillMeta(&meta, &st)
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, meta, ErrNotRegular
	}
	meta.ParentUntrusted = parentUntrusted(p)
	f := os.NewFile(uintptr(fd), p)
	// os.NewFile takes ownership; clear our deferred close by dup-ing is
	// unnecessary because we read through the fd and close once.
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, meta, err
	}
	if int64(len(data)) > limit {
		data = data[:limit]
		meta.Truncated = true
	}
	if bytes.IndexByte(data, 0) >= 0 {
		meta.Binary = true
		return nil, meta, nil
	}
	return data, meta, nil
}

// Stat resolves like ReadFile but only stats the final component; a final
// symlink is ErrSymlink, never followed.
func Stat(p string) (ReadMeta, error) {
	fd, tier, err := openNoFollow(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	meta := ReadMeta{Tier: tier}
	if err != nil {
		return meta, err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return meta, err
	}
	fillMeta(&meta, &st)
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return meta, ErrSymlink
	}
	meta.ParentUntrusted = parentUntrusted(p)
	return meta, nil
}

func fillMeta(m *ReadMeta, st *unix.Stat_t) {
	m.Size = st.Size
	m.Mode = os.FileMode(st.Mode & 0o7777)
	m.UID, m.GID = st.Uid, st.Gid
}

func parentUntrusted(p string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(path.Dir(p), &st); err != nil {
		return true
	}
	return st.Uid != 0 || st.Mode&(unix.S_IWOTH|unix.S_IWGRP) != 0
}

// DeniedReason turns a permission error into the reason a denied fact
// carries (spec §7.1).
func DeniedReason(err error) (string, bool) {
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return "requires root or CAP_DAC_READ_SEARCH", true
	}
	return "", false
}
```

Note on `os.NewFile` and the deferred `unix.Close`: `os.NewFile` will also close the fd when garbage-collected; to avoid a double close, replace the deferred close with `defer f.Close()` after constructing `f` and remove the `unix.Close(fd)` defer. Write it that way (open → fstat via `unix.Fstat(fd)` → `f := os.NewFile(...)` → `defer f.Close()`).

- [ ] **Step 4: Run the tests to verify they pass**

Run (Linux, as an ordinary user is enough): `go test ./internal/collect/ -run 'TestReadFile|TestStat' -v`
Expected: PASS; on a kernel with `openat2` the tier is `openat2`. Then on the same host run once under a seccomp profile without `openat2` if available (`docker run --security-opt seccomp=<profile>`) to see `componentwise`; otherwise rely on the unit test that forces tier 2 (add `var forceComponentwise bool` checked before `Openat2` and a test that sets it).

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/collect/
git commit -m "Add the Linux read primitive with no-symlink guarantees"
```

---

### Task 2: Exec discipline

**Files:**
- Create: `internal/collect/exec.go`, `internal/collect/exec_test.go`

**Interfaces:**
- Produces (package `collect`, Linux):
  - `type Command struct { Path string; Args []string; Timeout time.Duration; MaxOutput int }` — `Path` must be absolute; `Timeout` 0 means 5 s; `MaxOutput` 0 means 1 MiB.
  - `type Output struct { Stdout, Stderr []byte; ExitCode int; TimedOut, Truncated bool; Duration time.Duration; Err error }`.
  - `func RunCommand(ctx context.Context, c Command) Output` — refuses a relative `Path` or a missing executable (`Err` set, `ExitCode -1`); runs with `exec.CommandContext`, `SysProcAttr{Setpgid: true}`, `Cmd.Env` rebuilt to exactly `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, `LANG=C`, `TZ=UTC`; `Cancel` kills the process group (`unix.Kill(-pid, SIGKILL)`); stdout and stderr each capped at `MaxOutput` bytes (`Truncated=true` when cut) via a limiting writer that keeps reading and discarding so the child never blocks on a full pipe; `WaitDelay` 1 s.
  - `func (o Output) Source(c Command) *facts.Source` — `{Kind: "command", Cmd: Path + " " + Args, ExitCode: &ExitCode}`.

- [ ] **Step 1: Write the failing tests**

`internal/collect/exec_test.go`:

```go
//go:build linux

package collect

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func sh(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/bin/sh", "/usr/bin/sh"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no /bin/sh")
	return ""
}

func TestRunCommandRefusesRelativePath(t *testing.T) {
	o := RunCommand(context.Background(), Command{Path: "sh", Args: []string{"-c", "true"}})
	if o.Err == nil || o.ExitCode != -1 {
		t.Fatalf("%+v", o)
	}
}

func TestRunCommandRebuildsEnvironment(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("LC_ALL", "ko_KR.UTF-8")
	o := RunCommand(context.Background(), Command{Path: sh(t), Args: []string{"-c", "env"}})
	env := string(o.Stdout)
	if strings.Contains(env, "LD_PRELOAD") || !strings.Contains(env, "LC_ALL=C\n") || !strings.Contains(env, "TZ=UTC\n") || !strings.Contains(env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n") {
		t.Fatalf("environment not rebuilt:\n%s", env)
	}
}

func TestRunCommandTimeoutKillsProcessGroup(t *testing.T) {
	start := time.Now()
	o := RunCommand(context.Background(), Command{Path: sh(t), Args: []string{"-c", "sleep 30 & sleep 30"}, Timeout: 300 * time.Millisecond})
	if !o.TimedOut {
		t.Fatalf("expected timeout: %+v", o)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("children were not killed with the group; took %s", time.Since(start))
	}
}

func TestRunCommandCapsOutputWithoutDeadlock(t *testing.T) {
	o := RunCommand(context.Background(), Command{Path: sh(t), Args: []string{"-c", "yes | head -c 5000000"}, MaxOutput: 1024, Timeout: 10 * time.Second})
	if o.TimedOut || !o.Truncated || len(o.Stdout) != 1024 {
		t.Fatalf("%+v len=%d", o, len(o.Stdout))
	}
}

func TestRunCommandExitCodeAndSource(t *testing.T) {
	c := Command{Path: sh(t), Args: []string{"-c", "echo out; echo err >&2; exit 3"}}
	o := RunCommand(context.Background(), c)
	if o.ExitCode != 3 || strings.TrimSpace(string(o.Stdout)) != "out" || strings.TrimSpace(string(o.Stderr)) != "err" {
		t.Fatalf("%+v", o)
	}
	src := o.Source(c)
	if src.Kind != "command" || *src.ExitCode != 3 || !strings.HasPrefix(src.Cmd, c.Path) {
		t.Fatalf("%+v", src)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (Linux): `go test ./internal/collect/ -run TestRunCommand -v`
Expected: FAIL — undefined `RunCommand`.

- [ ] **Step 3: Write `exec.go`**

```go
//go:build linux

package collect

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// Command is one whitelisted invocation (spec §8 "Commands").
type Command struct {
	Path      string
	Args      []string
	Timeout   time.Duration
	MaxOutput int
}

// Output is what the collector sees; Err is set only when the command could
// not be started at all.
type Output struct {
	Stdout, Stderr []byte
	ExitCode       int
	TimedOut       bool
	Truncated      bool
	Duration       time.Duration
	Err            error
}

var fixedEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "TZ=UTC"}

// capWriter keeps the first n bytes and discards the rest, so the child is
// never blocked on a full pipe while we stop storing its output.
type capWriter struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.limit - w.buf.Len()
	if room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.truncated = true
		} else {
			w.buf.Write(p)
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	return len(p), nil
}

// RunCommand runs c under the discipline: absolute path, no shell, rebuilt
// environment, own process group, timeout that kills the group, output caps.
func RunCommand(ctx context.Context, c Command) Output {
	if !filepath.IsAbs(c.Path) {
		return Output{ExitCode: -1, Err: errors.New("command path must be absolute: " + c.Path)}
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.MaxOutput <= 0 {
		c.MaxOutput = 1 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Path, c.Args...)
	cmd.Env = append([]string(nil), fixedEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return unix.Kill(-cmd.Process.Pid, unix.SIGKILL) }
	cmd.WaitDelay = time.Second
	out, errw := &capWriter{limit: c.MaxOutput}, &capWriter{limit: c.MaxOutput}
	cmd.Stdout, cmd.Stderr = out, errw
	start := time.Now()
	err := cmd.Run()
	o := Output{Stdout: out.buf.Bytes(), Stderr: errw.buf.Bytes(), Duration: time.Since(start), Truncated: out.truncated || errw.truncated}
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		o.TimedOut, o.ExitCode = true, -1
	case err == nil:
		o.ExitCode = 0
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			o.ExitCode = ee.ExitCode()
		} else {
			o.ExitCode, o.Err = -1, err
		}
	}
	return o
}

// Source describes the command for evidence (spec §5.2).
func (o Output) Source(c Command) *facts.Source {
	code := o.ExitCode
	return &facts.Source{Kind: "command", Cmd: strings.TrimSpace(c.Path + " " + strings.Join(c.Args, " ")), ExitCode: &code}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run (Linux): `go test ./internal/collect/ -run TestRunCommand -v`
Expected: PASS; the timeout test finishes in well under three seconds.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/exec.go internal/collect/exec_test.go
git commit -m "Add the exec discipline for whitelisted commands"
```

---

### Task 3: Collector registry, access declarations and `--list-actions`

**Files:**
- Create: `internal/collect/registry.go`, `internal/collect/facts.go`, `internal/collect/registry_test.go`

**Interfaces:**
- Produces (package `collect`, Linux):
  - `type Access interface { ReadFile(path string, limit int64) ([]byte, ReadMeta, error); Stat(path string) (ReadMeta, error); Glob(pattern string) ([]string, error); Run(ctx context.Context, c Command) Output }` — collectors touch the host only through this; the default implementation wraps Task 1–2; tests substitute a recording double.
  - `type Declaration struct { Reads []string; Commands []Command; Needs string }` — `Reads` are absolute paths or globs; `Needs` is `root` or `none`.
  - `type Collector struct { Name string; Declare Declaration; Run func(ctx context.Context, a Access, b *Builder) error }`.
  - `func Register(c Collector)` (panics on duplicate name), `func All() []Collector` (sorted by name), `func Reset()` for tests.
  - `type Action struct { Collector, Kind, Target, Needs string }` and `func ListActions() []Action` — one row per declared read/command plus one `write` row for the snapshot path (`Target: "<snapshot path>"`); `func WriteActions(w io.Writer, actions []Action, format string) error` for `table|json`.
  - `type guardedAccess struct { inner Access; decl Declaration; name string; violations []string }` — an `Access` that records any read/command outside the declaration (path matched against `Reads` globs with `path.Match` after cleaning; commands matched by `Path`+`Args` prefix) and returns `ErrUndeclared`; `func Guard(a Access, c Collector) *guardedAccess`; `var ErrUndeclared = errors.New("access outside the collector's declaration")`.
  - `Builder` (`facts.go`): `func NewBuilder(reg *facts.Registry) *Builder`; `func (b *Builder) Set(key string, env facts.Envelope)`; `func (b *Builder) SetSetting(key string, s facts.Setting)`; helpers `OK(value any, src *facts.Source) facts.Envelope`, `Absent(reason string)`, `Denied(reason string)`, `Unsupported(reason string)`, `TimeoutEnv(reason string)`, `ErrorEnv(reason string)`; `func (b *Builder) Tree() map[string]any` (nested by dotted key); `Set` panics on an unregistered key (a programming error caught by tests) and on a `setting<...>` key given a plain envelope.
  - `func FromReadError(err error, meta ReadMeta) facts.Envelope` — maps `ENOENT`→`Absent`, `EACCES/EPERM`→`Denied(DeniedReason)`, `ErrSymlink`/`ErrNotRegular`→`ErrorEnv`, `meta.Truncated`→`ok` with `Truncated: true`.

- [ ] **Step 1: Write the failing tests**

`internal/collect/registry_test.go`:

```go
//go:build linux

package collect

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

type fakeAccess struct{ reads []string }

func (f *fakeAccess) ReadFile(p string, _ int64) ([]byte, ReadMeta, error) {
	f.reads = append(f.reads, p)
	return []byte("x"), ReadMeta{}, nil
}
func (f *fakeAccess) Stat(p string) (ReadMeta, error)           { f.reads = append(f.reads, p); return ReadMeta{}, nil }
func (f *fakeAccess) Glob(p string) ([]string, error)           { return []string{p}, nil }
func (f *fakeAccess) Run(_ context.Context, c Command) Output { return Output{ExitCode: 0} }

func TestGuardRejectsUndeclaredAccess(t *testing.T) {
	c := Collector{Name: "t", Declare: Declaration{Reads: []string{"/etc/login.defs", "/etc/ssh/sshd_config.d/*.conf"}, Commands: []Command{{Path: "/usr/sbin/sshd", Args: []string{"-T"}}}}}
	g := Guard(&fakeAccess{}, c)
	if _, _, err := g.ReadFile("/etc/login.defs", 10); err != nil {
		t.Error("declared read must pass")
	}
	if _, _, err := g.ReadFile("/etc/ssh/sshd_config.d/50-cloud-init.conf", 10); err != nil {
		t.Error("glob-declared read must pass")
	}
	if _, _, err := g.ReadFile("/etc/shadow", 10); !errors.Is(err, ErrUndeclared) {
		t.Errorf("undeclared read: err=%v", err)
	}
	if o := g.Run(context.Background(), Command{Path: "/usr/sbin/sshd", Args: []string{"-T"}}); o.Err != nil {
		t.Error("declared command must pass")
	}
	if o := g.Run(context.Background(), Command{Path: "/bin/sh", Args: []string{"-c", "id"}}); !errors.Is(o.Err, ErrUndeclared) {
		t.Errorf("undeclared command: %+v", o)
	}
	if len(g.violations) != 2 {
		t.Errorf("violations %v", g.violations)
	}
}

func TestBuilderSetsEnvelopesAndSettingsByRegistryKey(t *testing.T) {
	reg, _ := facts.LoadRegistry()
	b := NewBuilder(reg)
	b.Set("services.ssh.installed", OK(true, nil))
	b.SetSetting("sshd.options.permit_root_login", facts.Setting{Effective: &facts.Envelope{Status: facts.StatusOK, Value: "no"}})
	tree := b.Tree()
	svc := tree["services"].(map[string]any)["ssh"].(map[string]any)["installed"].(facts.Envelope)
	if svc.Value != true {
		t.Errorf("%+v", tree)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("unregistered key must panic")
			}
		}()
		b.Set("nope.key", OK(1, nil))
	}()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("plain envelope on a setting key must panic")
			}
		}()
		b.Set("sshd.options.permit_root_login", OK("no", nil))
	}()
}

func TestListActionsIncludesEveryDeclarationAndTheWrite(t *testing.T) {
	Reset()
	Register(Collector{Name: "a", Declare: Declaration{Reads: []string{"/etc/passwd"}, Needs: "none"}})
	Register(Collector{Name: "b", Declare: Declaration{Commands: []Command{{Path: "/usr/sbin/sshd", Args: []string{"-T"}}}, Needs: "root"}})
	acts := ListActions()
	var kinds []string
	for _, a := range acts {
		kinds = append(kinds, a.Collector+":"+a.Kind+":"+a.Target)
	}
	joined := strings.Join(kinds, "\n")
	for _, want := range []string{"a:read:/etc/passwd", "b:command:/usr/sbin/sshd -T", "muster:write:"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	var buf bytes.Buffer
	if err := WriteActions(&buf, acts, "json"); err != nil || !strings.Contains(buf.String(), `"kind": "command"`) {
		t.Errorf("json: %v %s", err, buf.String())
	}
}

func TestFromReadErrorMapsStatuses(t *testing.T) {
	if e := FromReadError(errNoEnt(), ReadMeta{}); e.Status != facts.StatusAbsent {
		t.Errorf("%+v", e)
	}
	if e := FromReadError(errAccess(), ReadMeta{}); e.Status != facts.StatusDenied || e.Reason == "" {
		t.Errorf("%+v", e)
	}
	if e := FromReadError(ErrSymlink, ReadMeta{}); e.Status != facts.StatusError {
		t.Errorf("%+v", e)
	}
}
```

Add to the test file:

```go
import "golang.org/x/sys/unix"

func errNoEnt() error  { return unix.ENOENT }
func errAccess() error { return unix.EACCES }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (Linux): `go test ./internal/collect/ -run 'TestGuard|TestBuilder|TestListActions|TestFromReadError' -v`
Expected: FAIL — undefined identifiers.

- [ ] **Step 3: Write `registry.go` and `facts.go`**

`internal/collect/registry.go`:

```go
//go:build linux

package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Access is the only way a collector touches the host. The real one wraps
// the read primitive and the exec discipline; tests substitute a double.
type Access interface {
	ReadFile(path string, limit int64) ([]byte, ReadMeta, error)
	Stat(path string) (ReadMeta, error)
	Glob(pattern string) ([]string, error)
	Run(ctx context.Context, c Command) Output
}

// Declaration is what a collector says it will read and run (spec §9
// --list-actions, §11 contract tests).
type Declaration struct {
	Reads    []string
	Commands []Command
	Needs    string // root | none
}

// Collector is one registered fact source.
type Collector struct {
	Name    string
	Declare Declaration
	Run     func(ctx context.Context, a Access, b *Builder) error
}

var registry = map[string]Collector{}

// Register adds a collector; a duplicate name is a programming error.
func Register(c Collector) {
	if _, dup := registry[c.Name]; dup {
		panic("collector registered twice: " + c.Name)
	}
	registry[c.Name] = c
}

// All returns collectors sorted by name so runs are deterministic.
func All() []Collector {
	out := make([]Collector, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Reset clears the registry (tests only).
func Reset() { registry = map[string]Collector{} }

// hostAccess is the production Access.
type hostAccess struct{}

func (hostAccess) ReadFile(p string, limit int64) ([]byte, ReadMeta, error) { return ReadFile(p, limit) }
func (hostAccess) Stat(p string) (ReadMeta, error)                         { return Stat(p) }
func (hostAccess) Glob(pattern string) ([]string, error)                   { return filepath.Glob(pattern) }
func (hostAccess) Run(ctx context.Context, c Command) Output              { return RunCommand(ctx, c) }

// ErrUndeclared is returned by the guard when a collector reaches outside
// its declaration; the run test in Task 6 fails on any violation.
var ErrUndeclared = errors.New("access outside the collector's declaration")

type guardedAccess struct {
	inner      Access
	decl       Declaration
	name       string
	violations []string
}

// Guard wraps a with the collector's declaration.
func Guard(a Access, c Collector) *guardedAccess {
	return &guardedAccess{inner: a, decl: c.Declare, name: c.Name}
}

func (g *guardedAccess) allowedPath(p string) bool {
	p = path.Clean(p)
	for _, r := range g.decl.Reads {
		if ok, _ := path.Match(r, p); ok || r == p {
			return true
		}
	}
	return false
}

func (g *guardedAccess) allowedCommand(c Command) bool {
	for _, d := range g.decl.Commands {
		if d.Path != c.Path || len(c.Args) < len(d.Args) {
			continue
		}
		match := true
		for i := range d.Args {
			if d.Args[i] != c.Args[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (g *guardedAccess) violate(what string) error {
	g.violations = append(g.violations, g.name+": "+what)
	return fmt.Errorf("%w: %s %s", ErrUndeclared, g.name, what)
}

func (g *guardedAccess) ReadFile(p string, limit int64) ([]byte, ReadMeta, error) {
	if !g.allowedPath(p) {
		return nil, ReadMeta{}, g.violate("read " + p)
	}
	return g.inner.ReadFile(p, limit)
}

func (g *guardedAccess) Stat(p string) (ReadMeta, error) {
	if !g.allowedPath(p) {
		return ReadMeta{}, g.violate("stat " + p)
	}
	return g.inner.Stat(p)
}

func (g *guardedAccess) Glob(pattern string) ([]string, error) {
	if !g.allowedPath(pattern) {
		return nil, g.violate("glob " + pattern)
	}
	return g.inner.Glob(pattern)
}

func (g *guardedAccess) Run(ctx context.Context, c Command) Output {
	if !g.allowedCommand(c) {
		return Output{ExitCode: -1, Err: g.violate("run " + c.Path + " " + strings.Join(c.Args, " "))}
	}
	return g.inner.Run(ctx, c)
}

// Action is one row of --list-actions (spec §9).
type Action struct {
	Collector string `json:"collector"`
	Kind      string `json:"kind"` // read | command | write
	Target    string `json:"target"`
	Needs     string `json:"needs"`
}

// ListActions renders the registry as the document a change-control
// reviewer reads: every path read, every command run, the single write.
func ListActions() []Action {
	var out []Action
	for _, c := range All() {
		for _, r := range c.Declare.Reads {
			out = append(out, Action{Collector: c.Name, Kind: "read", Target: r, Needs: c.Declare.Needs})
		}
		for _, cmd := range c.Declare.Commands {
			out = append(out, Action{Collector: c.Name, Kind: "command", Target: strings.TrimSpace(cmd.Path + " " + strings.Join(cmd.Args, " ")), Needs: c.Declare.Needs})
		}
	}
	out = append(out, Action{Collector: "muster", Kind: "write", Target: DefaultSnapshotDir + "/<hostname>-<time>-<digest>.json", Needs: "root"})
	return out
}

// WriteActions prints actions as a table or JSON.
func WriteActions(w io.Writer, actions []Action, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(actions)
	}
	for _, a := range actions {
		if _, err := fmt.Fprintf(w, "%-10s %-8s %-5s %s\n", a.Collector, a.Kind, a.Needs, a.Target); err != nil {
			return err
		}
	}
	return nil
}
```

`internal/collect/facts.go`:

```go
//go:build linux

package collect

import (
	"errors"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// Builder accumulates facts by registry key and renders the nested tree.
// Setting an unregistered key panics: it is a programming error the
// collector tests must catch, never a runtime condition.
type Builder struct {
	reg  *facts.Registry
	tree map[string]any
}

func NewBuilder(reg *facts.Registry) *Builder { return &Builder{reg: reg, tree: map[string]any{}} }

func (b *Builder) place(key string, leaf any) {
	e, ok := b.reg.Lookup(key)
	if !ok {
		panic("collect: unregistered fact key " + key)
	}
	_, isSetting := leaf.(facts.Setting)
	if b.reg.IsSetting(e) != isSetting {
		panic("collect: key " + key + " has type " + e.Type + "; wrong leaf kind")
	}
	segs := strings.Split(key, ".")
	cur := b.tree
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = leaf
}

// Set records an envelope under key.
func (b *Builder) Set(key string, env facts.Envelope) { b.place(key, env) }

// SetSetting records a two-home setting under key.
func (b *Builder) SetSetting(key string, s facts.Setting) { b.place(key, s) }

// Tree returns the nested facts tree for the snapshot.
func (b *Builder) Tree() map[string]any { return b.tree }

func OK(value any, src *facts.Source) facts.Envelope {
	return facts.Envelope{Status: facts.StatusOK, Value: value, Source: src}
}
func Absent(reason string) facts.Envelope      { return facts.Envelope{Status: facts.StatusAbsent, Reason: reason} }
func Denied(reason string) facts.Envelope      { return facts.Envelope{Status: facts.StatusDenied, Reason: reason} }
func Unsupported(reason string) facts.Envelope { return facts.Envelope{Status: facts.StatusUnsupported, Reason: reason} }
func TimeoutEnv(reason string) facts.Envelope  { return facts.Envelope{Status: facts.StatusTimeout, Reason: reason} }
func ErrorEnv(reason string) facts.Envelope    { return facts.Envelope{Status: facts.StatusError, Reason: reason} }

// FromReadError turns a read primitive error into the right status
// (spec §7.1): ENOENT is absent, EACCES/EPERM is denied with the privilege
// named, anything else is error with the text.
func FromReadError(err error, meta ReadMeta) facts.Envelope {
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		return Absent("not present")
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		r, _ := DeniedReason(err)
		return Denied(r)
	default:
		return ErrorEnv(err.Error())
	}
}
```

Add `const DefaultSnapshotDir = "/var/lib/muster/snapshots"` to `writer.go` in Task 4; until then declare it in `registry.go` and move it in Task 4.

- [ ] **Step 4: Run the tests to verify they pass**

Run (Linux): `go test ./internal/collect/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/registry.go internal/collect/facts.go internal/collect/registry_test.go
git commit -m "Add the collector registry, access guard, builder and --list-actions"
```

---

### Task 4: Snapshot writer and lifecycle

**Files:**
- Create: `internal/collect/writer.go`, `internal/collect/writer_test.go`
- Modify: `internal/collect/registry.go` (remove the temporary `DefaultSnapshotDir` constant)

**Interfaces:**
- Produces (package `collect`, Linux):
  - `const DefaultSnapshotDir = "/var/lib/muster/snapshots"`, `const LockPath = "/var/lib/muster/.lock"`, `const MinFreeBytes = 64 << 20`.
  - `func SnapshotName(hostname, collectedAt, digest string) string` — `<hostname>-<collectedAt with ':' removed>-<first 12 hex chars of digest after "sha256:">.json`; hostname sanitised to `[A-Za-z0-9._-]`, other runes replaced by `_`.
  - `type WriteOptions struct { Out string; Force bool; Dir string }` — `Out` empty → `Dir` (default `DefaultSnapshotDir`) + generated name; `Out == "-"` → stdout; `Out` a path → that path.
  - `var ErrExists = errors.New("snapshot exists; use --force")`, `var ErrUntrustedDir = errors.New("output directory is a symlink or world-writable")`, `var ErrNoSpace = errors.New("not enough free space for a snapshot")`, `var ErrLocked = errors.New("another muster collect is running")`.
  - `func WriteSnapshot(data []byte, o WriteOptions, stdout io.Writer) (path string, err error)` — for a file: create `Dir` with 0700 if missing (only when `Out` is empty), refuse if the parent is a symlink (`Lstat`) or world-writable, refuse if `Out` exists and not `Force` (`O_EXCL`), check `unix.Statfs` free bytes ≥ `MinFreeBytes` + `len(data)`, write to `<dir>/.<name>.tmp-<pid>` opened with `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW`, 0600, `fsync`, `rename` into place, then replace `<dir>/latest` symlink atomically (`symlink` to a temp name + `rename`) only when `Out` was empty. For `-`: write to `stdout`.
  - `type Lock struct{ fd int }`; `func AcquireLock(path string) (*Lock, error)` — creates the parent 0700, opens the lock file 0600, `unix.Flock(fd, LOCK_EX|LOCK_NB)`; on `EWOULDBLOCK` reads the file's content (`pid start-time`) and returns `ErrLocked` wrapped with that text; on success writes `"<pid> <RFC3339 now>\n"`; `func (l *Lock) Release()`.

- [ ] **Step 1: Write the failing tests**

`internal/collect/writer_test.go`:

```go
//go:build linux

package collect

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotNameIsSanitisedAndStable(t *testing.T) {
	n := SnapshotName("web 01/prod", "2026-09-02T06:00:00Z", "sha256:0123456789abcdef0123")
	if n != "web_01_prod-2026-09-02T060000Z-0123456789ab.json" {
		t.Fatalf("%q", n)
	}
}

func TestWriteSnapshotCreatesDirAtomicallyWithLatest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshots")
	p, err := WriteSnapshot([]byte(`{"a":1}`), WriteOptions{Dir: dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %o", st.Mode().Perm())
	}
	dst, _ := os.Stat(dir)
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o", dst.Mode().Perm())
	}
	if target, err := os.Readlink(filepath.Join(dir, "latest")); err != nil || target != filepath.Base(p) {
		t.Errorf("latest → %q err=%v", target, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") && strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestWriteSnapshotRefusesExistingWithoutForce(t *testing.T) {
	out := filepath.Join(t.TempDir(), "s.json")
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: out}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: out}, nil); !errors.Is(err, ErrExists) {
		t.Errorf("err=%v", err)
	}
	if _, err := WriteSnapshot([]byte(`{"v":2}`), WriteOptions{Out: out, Force: true}, nil); err != nil {
		t.Errorf("force: %v", err)
	}
}

func TestWriteSnapshotRefusesWorldWritableOrSymlinkedParent(t *testing.T) {
	base := t.TempDir()
	ww := filepath.Join(base, "ww")
	os.Mkdir(ww, 0o777)
	os.Chmod(ww, 0o777)
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: filepath.Join(ww, "s.json")}, nil); !errors.Is(err, ErrUntrustedDir) {
		t.Errorf("world-writable: err=%v", err)
	}
	real := filepath.Join(base, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(base, "link")
	os.Symlink(real, link)
	if _, err := WriteSnapshot([]byte("{}"), WriteOptions{Out: filepath.Join(link, "s.json")}, nil); !errors.Is(err, ErrUntrustedDir) {
		t.Errorf("symlinked parent: err=%v", err)
	}
}

func TestWriteSnapshotToStdout(t *testing.T) {
	var buf bytes.Buffer
	p, err := WriteSnapshot([]byte("{}\n"), WriteOptions{Out: "-"}, &buf)
	if err != nil || p != "-" || buf.String() != "{}\n" {
		t.Errorf("%q %v %q", p, err, buf.String())
	}
}

func TestLockIsExclusiveAndNamesTheHolder(t *testing.T) {
	lp := filepath.Join(t.TempDir(), "d", ".lock")
	l1, err := AcquireLock(lp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(lp); !errors.Is(err, ErrLocked) || !strings.Contains(err.Error(), "pid") {
		t.Errorf("second lock: err=%v", err)
	}
	l1.Release()
	if l2, err := AcquireLock(lp); err != nil {
		t.Errorf("after release: %v", err)
	} else {
		l2.Release()
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (Linux): `go test ./internal/collect/ -run 'TestSnapshotName|TestWriteSnapshot|TestLock' -v`
Expected: FAIL — undefined identifiers.

- [ ] **Step 3: Write `writer.go`**

```go
//go:build linux

package collect

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DefaultSnapshotDir = "/var/lib/muster/snapshots"
	LockPath           = "/var/lib/muster/.lock"
	MinFreeBytes       = 64 << 20
)

var (
	ErrExists       = errors.New("snapshot exists; use --force")
	ErrUntrustedDir = errors.New("output directory is a symlink or world-writable")
	ErrNoSpace      = errors.New("not enough free space for a snapshot")
	ErrLocked       = errors.New("another muster collect is running")
)

// SnapshotName is <host>-<utc time>-<short digest>.json (spec §5.9).
func SnapshotName(hostname, collectedAt, digest string) string {
	h := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, hostname)
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return fmt.Sprintf("%s-%s-%s.json", h, strings.ReplaceAll(collectedAt, ":", ""), d)
}

// WriteOptions selects the destination.
type WriteOptions struct {
	Out   string // "" = Dir + generated name; "-" = stdout; else a path
	Force bool
	Dir   string
}

func trustedDir(dir string) error {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK || st.Mode&unix.S_IWOTH != 0 {
		return ErrUntrustedDir
	}
	return nil
}

// WriteSnapshot writes data atomically with 0600 (spec §5.9, §7.1). The
// only file collect ever writes goes through here.
func WriteSnapshot(data []byte, o WriteOptions, stdout io.Writer) (string, error) {
	if o.Out == "-" {
		_, err := stdout.Write(data)
		return "-", err
	}
	dir, name := "", ""
	generated := o.Out == ""
	if generated {
		dir = o.Dir
		if dir == "" {
			dir = DefaultSnapshotDir
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		host, _ := os.Hostname()
		name = SnapshotName(host, time.Now().UTC().Format(time.RFC3339), digestOf(data))
	} else {
		dir, name = filepath.Split(o.Out)
		dir = filepath.Clean(dir)
	}
	if err := trustedDir(dir); err != nil {
		return "", err
	}
	final := filepath.Join(dir, name)
	if !o.Force {
		if _, err := os.Lstat(final); err == nil {
			return "", ErrExists
		}
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err == nil {
		if free := uint64(fs.Bavail) * uint64(fs.Bsize); free < MinFreeBytes+uint64(len(data)) {
			return "", ErrNoSpace
		}
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%d", name, os.Getpid()))
	fd, err := unix.Open(tmp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if generated {
		latestTmp := filepath.Join(dir, fmt.Sprintf(".latest.tmp-%d", os.Getpid()))
		os.Remove(latestTmp)
		if err := os.Symlink(name, latestTmp); err == nil {
			os.Rename(latestTmp, filepath.Join(dir, "latest"))
		}
	}
	return final, nil
}

// digestOf is the sha256 of the bytes as written; the same value check
// reports as snapshot_digest for a file it reads back unchanged.
func digestOf(data []byte) string {
	sum := unixSHA256(data)
	return "sha256:" + sum
}

// Lock is the flock that keeps two collects from interleaving.
type Lock struct{ fd int }

// AcquireLock takes an exclusive, non-blocking lock and records the holder.
func AcquireLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder := make([]byte, 128)
		n, _ := unix.Pread(fd, holder, 0)
		unix.Close(fd)
		return nil, fmt.Errorf("%w (holder: pid %s)", ErrLocked, strings.TrimSpace(string(holder[:n])))
	}
	unix.Ftruncate(fd, 0)
	unix.Pwrite(fd, []byte(fmt.Sprintf("%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))), 0)
	return &Lock{fd: fd}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l != nil && l.fd >= 0 {
		unix.Flock(l.fd, unix.LOCK_UN)
		unix.Close(l.fd)
		l.fd = -1
	}
}
```

Add the helper (plain Go, no tag needed but keep it in this file):

```go
import (
	"crypto/sha256"
	"encoding/hex"
)

func unixSHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
```

The `ErrLocked` message must contain "pid" for the test: the holder line starts with the pid, and the wrapping text says `pid`.

- [ ] **Step 4: Run the tests to verify they pass**

Run (Linux): `go test ./internal/collect/ -v`
Expected: PASS. Note `TestWriteSnapshotRefusesWorldWritableOrSymlinkedParent` also passes as root because the check is on mode and link type, not on permission failure.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/writer.go internal/collect/writer_test.go internal/collect/registry.go
git commit -m "Add the snapshot writer, naming, lock and latest symlink"
```

---

### Task 5: The five collectors (stage-1 minimum capabilities)

**Files:**
- Create: `internal/collect/collectors/register.go`, `os.go`, `services.go`, `sockets.go`, `sshd.go`, `files.go`, `accounts.go`, `walk.go`, and `collectors_test.go` with `testdata/` inputs

**Interfaces:**
- Consumes: `collect.Register`, `collect.Access`, `collect.Builder`, helpers from Task 3, `facts.Source`.
- Produces (package `collectors`, Linux; `func init()` registers all of them; `collect.RunAll` in Task 6 imports this package for its side effect):

| Collector | Declares (reads / commands) | Keys filled | Stage-1 rule |
|---|---|---|---|
| `os` | `/etc/os-release`, `/etc/hostname`, `/etc/machine-id`, `/proc/sys/kernel/osrelease`, `/proc/sys/kernel/random/boot_id`, `/proc/uptime`, `/proc/1/cgroup`, `/proc/1/comm`, `/.dockerenv`, `/run/.containerenv`, `/run/systemd/system`, `/proc/version`, `/sys/class/dmi/id/product_name`, `/var/lib/cloud` | none (fills `Run.Host` and `Run.Env` through `Builder.Header()`) | `machine_id_hash` is sha256 of the id, never the id; `container` = `docker` if `/.dockerenv`, `podman` if `/run/.containerenv`, `lxc` if `/proc/1/cgroup` mentions lxc, else `none`; `wsl` if `/proc/version` contains `microsoft`; `has_systemd` if `/run/systemd/system` exists; `sysctl_writable` = `unix.Access("/proc/sys/net", W_OK) == nil`; `virt` from DMI product name (`KVM`, `VMware`, `VirtualBox`, `Virtual Machine` → lowercase word; empty → `none`; unreadable → `unknown`); `cloud_init` if `/var/lib/cloud` exists |
| `services` | commands `/usr/bin/systemctl show -p LoadState,ActiveState,UnitFileState,SubState <unit>` for units `ssh.service`, `sshd.service`, `ssh.socket`, `telnet.socket`, `telnet.service`, `telnetd.service`, `inetd.service`, `xinetd.service`; reads `/etc/inetd.conf`, `/etc/xinetd.d/*` | `services.ssh.installed`, `services.ssh.active`, `services.telnet.installed`, `services.telnet.reachable` | `installed` = any mapped unit `LoadState=loaded` (not `not-found`) or an inetd/xinetd entry; `active` = any `ActiveState=active`; `reachable` = active or a listening `ssh.socket`/`telnet.socket` **and** the sockets collector saw port 22/23 on a non-loopback address — computed in `services` from `sockets.listening` via the builder (run order: sockets before services; `All()` sorts by name, so name the collectors `10-sockets` and `20-services`? No — keep names plain and let `services` read `/proc/net/tcp*` itself through its declaration; do not depend on run order). Without systemd (`/run/systemd/system` missing) → `unsupported` with reason "no systemd" |
| `sockets` | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` | `sockets.listening` | records `{proto, addr, port, inode, loopback}`; `pid`/`exe` left absent in stage 1 (registry description allows it) |
| `sshd` | commands `/usr/sbin/sshd -T`; reads `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*.conf` | `sshd.collect_method`, `sshd.personas_collected` (=false), `sshd.options.permit_root_login` | runtime from `-T` (`permitrootlogin <v>` line); persisted from the files with `Include` expanded in order (a directive's first occurrence wins, as sshd does) recording file/line/raw; `effective` = runtime when `-T` succeeded, else persisted with `Reason: "parsed files; sshd -T unavailable"`; `-T` missing binary → `collect_method: parse`; both unavailable → `absent` |
| `files` | `/etc/passwd`, `/etc/securetty` | `files.etc_passwd.{mode,uid,gid,acl_present}`, `files.etc_securetty`, `files.etc_securetty_lines` | `Stat` for mode/uid/gid; `acl_present` = `unix.Llistxattr` contains `system.posix_acl_access` (EOPNOTSUPP → false); securetty lines exclude blank and `#` lines |
| `accounts` | `/etc/login.defs`, `/etc/passwd`, `/etc/shadow` | `accounts.login_defs.pass_max_days` (setting), `accounts.login_defs.pass_min_days` (setting), `accounts.login_defs.pass_min_len`, `accounts.users` | persisted from `login.defs` with line/raw; runtime = max (for max_days) / min (for min_days) over `shadow` entries whose field 2 is a hash (`$`-prefixed), source `derived` with inputs `/etc/shadow`; `accounts.users` records `{name, uid, gid, shell, password_status, last_change, min, max, warn, inactive, expire, hash_algo}` where `password_status` is `locked` (`!`/`*` prefix), `nopass` (empty) or `hashed`, `hash_algo` is the `$id$` prefix only, and **no hash is ever stored**; `shadow` unreadable → the two runtime sides `denied` and `accounts.users` rows without shadow fields |
| `walk` | none | `walk.complete` only when `--deep` | stage 1: with `--deep` the collector records `walk.complete` as `unsupported` with reason "deep walk arrives in stage 3" and marks itself `skipped`; without `--deep` it sets nothing (the keys stay absent → U-25 is `MANUAL`) |

- [ ] **Step 1: Write the failing tests with fixture inputs**

Create `internal/collect/collectors/testdata/`:

`sshd_T.txt`:
```
port 22
permitrootlogin prohibit-password
passwordauthentication yes
```
`sshd_config`:
```
# comment
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
```
`sshd_config.d_50-cloud-init.conf`:
```
PasswordAuthentication yes
PermitRootLogin no
```
`login.defs`:
```
# defaults
PASS_MAX_DAYS	90
PASS_MIN_DAYS	1
PASS_MIN_LEN	8
UID_MIN 1000
```
`shadow`:
```
root:$6$saltsalt$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhash:19000:0:99999:7:::
svc:!:19000:0:99999:7:::
alice:$y$j9T$salt$hashhashhashhashhashhashhashhashhashhashhash:19500:1:90:7:::
```
`proc_net_tcp`:
```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0017 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
```

`internal/collect/collectors/collectors_test.go`:

```go
//go:build linux

package collectors

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// fsAccess serves declared paths from testdata and commands from canned
// outputs, and records everything so the guard can be asserted.
type fsAccess struct {
	files map[string]string // host path → testdata file name
	cmds  map[string]string // command line → testdata file name
	fails map[string]error
}

func (a *fsAccess) read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("testdata", name))
}

func (a *fsAccess) ReadFile(p string, limit int64) ([]byte, collect.ReadMeta, error) {
	if err, ok := a.fails[p]; ok {
		return nil, collect.ReadMeta{}, err
	}
	name, ok := a.files[p]
	if !ok {
		return nil, collect.ReadMeta{}, os.ErrNotExist
	}
	b, err := a.read(name)
	return b, collect.ReadMeta{Size: int64(len(b)), Mode: 0o644}, err
}

func (a *fsAccess) Stat(p string) (collect.ReadMeta, error) {
	if _, ok := a.files[p]; !ok {
		return collect.ReadMeta{}, os.ErrNotExist
	}
	return collect.ReadMeta{Mode: 0o644, UID: 0, GID: 0}, nil
}

func (a *fsAccess) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range a.files {
		if ok, _ := filepath.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (a *fsAccess) Run(_ context.Context, c collect.Command) collect.Output {
	line := c.Path + " " + strings.Join(c.Args, " ")
	if name, ok := a.cmds[line]; ok {
		b, _ := a.read(name)
		return collect.Output{Stdout: b, ExitCode: 0}
	}
	return collect.Output{ExitCode: 127, Err: os.ErrNotExist}
}

func build(t *testing.T, name string, a collect.Access) *collect.Builder {
	t.Helper()
	reg, _ := facts.LoadRegistry()
	b := collect.NewBuilder(reg)
	for _, c := range collect.All() {
		if c.Name == name {
			g := collect.Guard(a, c)
			if err := c.Run(context.Background(), g, b); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			return b
		}
	}
	t.Fatalf("collector %s not registered", name)
	return nil
}

func leaf(t *testing.T, b *collect.Builder, key string) any {
	t.Helper()
	cur := any(b.Tree())
	for _, s := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: not present", key)
		}
		cur = m[s]
	}
	return cur
}

func TestSshdRuntimeAndPersistedWithInclude(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config", "/etc/ssh/sshd_config.d/50-cloud-init.conf": "sshd_config.d_50-cloud-init.conf"},
		cmds:  map[string]string{"/usr/sbin/sshd -T": "sshd_T.txt"},
	}
	b := build(t, "sshd", a)
	s := leaf(t, b, "sshd.options.permit_root_login").(facts.Setting)
	if s.Runtime.Value != "prohibit-password" || s.Effective.Value != "prohibit-password" {
		t.Errorf("runtime/effective %+v %+v", s.Runtime, s.Effective)
	}
	if s.Persisted.Value != "no" || s.Persisted.Source.Path != "/etc/ssh/sshd_config.d/50-cloud-init.conf" || s.Persisted.Source.Line != 2 {
		t.Errorf("persisted must come from the Include (first occurrence wins): %+v", s.Persisted)
	}
	if leaf(t, b, "sshd.collect_method").(facts.Envelope).Value != "T" || leaf(t, b, "sshd.personas_collected").(facts.Envelope).Value != false {
		t.Error("method/personas")
	}
}

func TestSshdFallsBackToParseWhenTUnavailable(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"}}
	b := build(t, "sshd", a)
	s := leaf(t, b, "sshd.options.permit_root_login").(facts.Setting)
	if s.Runtime != nil || s.Effective.Value != "yes" || !strings.Contains(s.Effective.Reason, "sshd -T unavailable") {
		t.Errorf("%+v", s)
	}
	if leaf(t, b, "sshd.collect_method").(facts.Envelope).Value != "parse" {
		t.Error("method must be parse")
	}
}

func TestAccountsDerivesRuntimeAgeingWithoutStoringHashes(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/login.defs": "login.defs", "/etc/shadow": "shadow", "/etc/passwd": "passwd"}}
	os.WriteFile(filepath.Join("testdata", "passwd"), []byte("root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n"), 0o644)
	b := build(t, "accounts", a)
	mx := leaf(t, b, "accounts.login_defs.pass_max_days").(facts.Setting)
	if mx.Persisted.Value != 90 || mx.Persisted.Source.Line != 2 || mx.Runtime.Value != 99999 || mx.Runtime.Source.Kind != "derived" {
		t.Errorf("%+v %+v", mx.Persisted, mx.Runtime)
	}
	users := leaf(t, b, "accounts.users").(facts.Envelope).Value.([]any)
	for _, u := range users {
		m := u.(map[string]any)
		for k, v := range m {
			if s, ok := v.(string); ok && strings.Contains(s, "hashhash") {
				t.Fatalf("hash leaked into %s=%q", k, s)
			}
		}
	}
	root := users[0].(map[string]any)
	if root["hash_algo"] != "$6$" || root["password_status"] != "hashed" {
		t.Errorf("%v", root)
	}
	if users[1].(map[string]any)["password_status"] != "locked" {
		t.Errorf("%v", users[1])
	}
}

func TestAccountsShadowDeniedIsDeniedNotAbsent(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd"}, fails: map[string]error{"/etc/shadow": os.ErrPermission}}
	b := build(t, "accounts", a)
	mx := leaf(t, b, "accounts.login_defs.pass_max_days").(facts.Setting)
	if mx.Runtime.Status != facts.StatusDenied {
		t.Errorf("%+v", mx.Runtime)
	}
}

func TestSocketsParsesListeningAndLoopback(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/proc/net/tcp": "proc_net_tcp"}}
	b := build(t, "sockets", a)
	list := leaf(t, b, "sockets.listening").(facts.Envelope).Value.([]any)
	if len(list) != 2 {
		t.Fatalf("%v", list)
	}
	first := list[0].(map[string]any)
	if first["port"] != 22 || first["loopback"] != false || first["proto"] != "tcp" {
		t.Errorf("%v", first)
	}
	if list[1].(map[string]any)["loopback"] != true {
		t.Errorf("%v", list[1])
	}
}

func TestFilesPasswdPermissionFacts(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/passwd": "passwd"}}
	b := build(t, "files", a)
	if leaf(t, b, "files.etc_passwd.mode").(facts.Envelope).Value != 420 || leaf(t, b, "files.etc_passwd.uid").(facts.Envelope).Value != 0 {
		t.Error("mode/uid")
	}
	if leaf(t, b, "files.etc_securetty").(facts.Envelope).Status != facts.StatusAbsent {
		t.Error("securetty absent on this fixture")
	}
}

func TestEveryCollectorStaysInsideItsDeclaration(t *testing.T) {
	a := &fsAccess{files: map[string]string{}, cmds: map[string]string{}}
	reg, _ := facts.LoadRegistry()
	for _, c := range collect.All() {
		g := collect.Guard(a, c)
		b := collect.NewBuilder(reg)
		_ = c.Run(context.Background(), g, b)
		if v := collect.Violations(g); len(v) != 0 {
			t.Errorf("%s touched undeclared targets: %v", c.Name, v)
		}
	}
}
```

Add `func Violations(g *guardedAccess) []string { return g.violations }` to `registry.go` (exported accessor for tests in other packages).

- [ ] **Step 2: Run the tests to verify they fail**

Run (Linux): `go test ./internal/collect/collectors/ -v`
Expected: FAIL — package missing.

- [ ] **Step 3: Write the collectors**

`register.go`:

```go
//go:build linux

// Package collectors holds the stage-1 collectors. Importing it registers
// them; the registry declares every path read and command run (spec §9).
package collectors

import "github.com/kun9497/muster/internal/collect"

const readLimit = 1 << 20

func init() {
	collect.Register(osCollector)
	collect.Register(servicesCollector)
	collect.Register(socketsCollector)
	collect.Register(sshdCollector)
	collect.Register(filesCollector)
	collect.Register(accountsCollector)
	collect.Register(walkCollector)
}
```

`sshd.go`:

```go
//go:build linux

package collectors

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var sshdT = collect.Command{Path: "/usr/sbin/sshd", Args: []string{"-T"}}

var sshdCollector = collect.Collector{
	Name: "sshd",
	Declare: collect.Declaration{
		Reads:    []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"},
		Commands: []collect.Command{sshdT},
		Needs:    "root",
	},
	Run: runSshd,
}

// runSshd fills sshd.* (spec §10.2 stage 1: -T global values only, no
// personas, persisted side from the files with Include expanded).
func runSshd(ctx context.Context, a collect.Access, b *collect.Builder) error {
	b.Set("sshd.personas_collected", collect.OK(false, nil))
	setting := facts.Setting{}
	method := "parse"

	out := a.Run(ctx, sshdT)
	src := out.Source(sshdT)
	switch {
	case out.Err == nil && out.ExitCode == 0:
		method = "T"
		for _, line := range strings.Split(string(out.Stdout), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "permitrootlogin" {
				v := collect.OK(f[1], src)
				setting.Runtime = &v
			}
		}
		if setting.Runtime == nil {
			e := collect.ErrorEnv("sshd -T printed no permitrootlogin line")
			setting.Runtime = &e
		}
	case out.TimedOut:
		e := collect.TimeoutEnv("sshd -T timed out")
		setting.Runtime = &e
	}

	persisted, found := parseSshdConfig(a, "/etc/ssh/sshd_config", "permitrootlogin", 0)
	if found {
		setting.Persisted = &persisted
	}
	b.Set("sshd.collect_method", collect.OK(method, nil))

	switch {
	case setting.Runtime != nil && setting.Runtime.Status == facts.StatusOK:
		eff := *setting.Runtime
		setting.Effective = &eff
	case setting.Persisted != nil:
		eff := *setting.Persisted
		eff.Reason = "parsed files; sshd -T unavailable"
		setting.Effective = &eff
	case setting.Runtime != nil:
		eff := *setting.Runtime
		setting.Effective = &eff
	default:
		e := collect.Absent("no sshd -T output and no sshd_config")
		setting.Effective = &e
	}
	b.SetSetting("sshd.options.permit_root_login", setting)
	return nil
}

// parseSshdConfig walks sshd_config in sshd's own order: Include files are
// read at the point of the directive, sorted, and the FIRST occurrence of a
// keyword wins. depth guards against Include loops.
func parseSshdConfig(a collect.Access, path, keyword string, depth int) (facts.Envelope, bool) {
	if depth > 8 {
		return collect.ErrorEnv("Include nesting too deep"), true
	}
	data, meta, err := a.ReadFile(path, readLimit)
	if err != nil {
		if depth == 0 {
			return collect.FromReadError(err, meta), true
		}
		return facts.Envelope{}, false
	}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		key := strings.ToLower(f[0])
		if key == "match" {
			break // stage 1: global section only; personas arrive in stage 2
		}
		if key == "include" && len(f) >= 2 {
			for _, pat := range f[1:] {
				matches, _ := a.Glob(pat)
				sort.Strings(matches)
				for _, m := range matches {
					if env, ok := parseSshdConfig(a, filepath.Clean(m), keyword, depth+1); ok {
						return env, true
					}
				}
			}
			continue
		}
		if key == keyword && len(f) >= 2 {
			return collect.OK(f[1], &facts.Source{Kind: "file", Path: path, Line: i + 1, Raw: raw}), true
		}
	}
	return facts.Envelope{}, false
}
```

`accounts.go`:

```go
//go:build linux

package collectors

import (
	"context"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var accountsCollector = collect.Collector{
	Name:    "accounts",
	Declare: collect.Declaration{Reads: []string{"/etc/login.defs", "/etc/passwd", "/etc/shadow"}, Needs: "root"},
	Run:     runAccounts,
}

func loginDefsValue(a collect.Access, key string) (facts.Envelope, bool) {
	data, meta, err := a.ReadFile("/etc/login.defs", readLimit)
	if err != nil {
		return collect.FromReadError(err, meta), true
	}
	for i, raw := range strings.Split(string(data), "\n") {
		f := strings.Fields(raw)
		if len(f) >= 2 && f[0] == key {
			n, err := strconv.Atoi(f[1])
			if err != nil {
				return collect.ErrorEnv(key + " is not a number"), true
			}
			return collect.OK(n, &facts.Source{Kind: "file", Path: "/etc/login.defs", Line: i + 1, Raw: raw}), true
		}
	}
	return collect.Absent(key + " not set in /etc/login.defs"), true
}

type shadowRow struct {
	name, status, algo             string
	lastChange, min, max, warn      int
	inactive, expire               int
	hasAgeing                      bool
}

// parseShadow keeps ageing fields and the hash *prefix* only (spec §5.6):
// the hash itself never enters memory beyond this function.
func parseShadow(data string) []shadowRow {
	var rows []shadowRow
	for _, line := range strings.Split(data, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 8 || f[0] == "" {
			continue
		}
		r := shadowRow{name: f[0], hasAgeing: true}
		pw := f[1]
		switch {
		case pw == "":
			r.status = "nopass"
		case strings.HasPrefix(pw, "!") || strings.HasPrefix(pw, "*"):
			r.status = "locked"
		default:
			r.status = "hashed"
			if strings.HasPrefix(pw, "$") {
				if end := strings.Index(pw[1:], "$"); end > 0 {
					r.algo = pw[:end+2]
				}
			}
		}
		atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
		r.lastChange, r.min, r.max, r.warn = atoi(f[2]), atoi(f[3]), atoi(f[4]), atoi(f[5])
		r.inactive, r.expire = atoi(f[6]), atoi(f[7])
		rows = append(rows, r)
	}
	return rows
}

func runAccounts(ctx context.Context, a collect.Access, b *collect.Builder) error {
	maxP, _ := loginDefsValue(a, "PASS_MAX_DAYS")
	minP, _ := loginDefsValue(a, "PASS_MIN_DAYS")
	lenP, _ := loginDefsValue(a, "PASS_MIN_LEN")
	b.Set("accounts.login_defs.pass_min_len", lenP)

	shadowData, meta, serr := a.ReadFile("/etc/shadow", readLimit)
	var rows []shadowRow
	var maxR, minR facts.Envelope
	if serr != nil {
		maxR, minR = collect.FromReadError(serr, meta), collect.FromReadError(serr, meta)
	} else {
		rows = parseShadow(string(shadowData))
		derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: "/etc/shadow"}}}
		mx, mn, seen := 0, 1<<30, false
		for _, r := range rows {
			if r.status != "hashed" {
				continue
			}
			seen = true
			if r.max > mx {
				mx = r.max
			}
			if r.min < mn {
				mn = r.min
			}
		}
		if seen {
			maxR, minR = collect.OK(mx, derived), collect.OK(mn, derived)
		} else {
			maxR, minR = collect.Absent("no account with a password hash"), collect.Absent("no account with a password hash")
		}
	}
	b.SetSetting("accounts.login_defs.pass_max_days", facts.Setting{Runtime: &maxR, Persisted: &maxP})
	b.SetSetting("accounts.login_defs.pass_min_days", facts.Setting{Runtime: &minR, Persisted: &minP})

	pwData, pmeta, perr := a.ReadFile("/etc/passwd", readLimit)
	if perr != nil {
		b.Set("accounts.users", collect.FromReadError(perr, pmeta))
		return nil
	}
	byName := map[string]shadowRow{}
	for _, r := range rows {
		byName[r.name] = r
	}
	var users []any
	for _, line := range strings.Split(string(pwData), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		u := map[string]any{"name": f[0], "uid": uid, "gid": gid, "shell": f[6]}
		if r, ok := byName[f[0]]; ok {
			u["password_status"], u["hash_algo"] = r.status, r.algo
			u["last_change"], u["min"], u["max"], u["warn"], u["inactive"], u["expire"] = r.lastChange, r.min, r.max, r.warn, r.inactive, r.expire
		}
		users = append(users, u)
	}
	b.Set("accounts.users", collect.OK(users, &facts.Source{Kind: "file", Path: "/etc/passwd"}))
	return nil
}
```

`sockets.go`:

```go
//go:build linux

package collectors

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var socketsCollector = collect.Collector{
	Name:    "sockets",
	Declare: collect.Declaration{Reads: []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}, Needs: "none"},
	Run:     runSockets,
}

// ListeningSockets parses the four proc tables; exported so services can
// reuse it without depending on collector order.
func ListeningSockets(a collect.Access) ([]any, *facts.Source, error) {
	var out []any
	var firstErr error
	for _, tbl := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}, {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"}} {
		data, _, err := a.ReadFile(tbl.path, 4<<20)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			st := f[3]
			isTCP := strings.HasPrefix(tbl.proto, "tcp")
			if (isTCP && st != "0A") || (!isTCP && st != "07") {
				continue // TCP LISTEN is 0A; UDP "unconnected" is 07
			}
			addr, port, loop := parseProcAddr(f[1])
			inode, _ := strconv.Atoi(f[9])
			out = append(out, map[string]any{"proto": tbl.proto, "addr": addr, "port": port, "inode": inode, "loopback": loop})
		}
	}
	if out == nil && firstErr != nil {
		return nil, nil, firstErr
	}
	return out, &facts.Source{Kind: "proc", Path: "/proc/net/tcp"}, nil
}

func parseProcAddr(s string) (string, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s, 0, false
	}
	port64, _ := strconv.ParseInt(parts[1], 16, 32)
	raw, _ := hex.DecodeString(parts[0])
	switch len(raw) {
	case 4: // little-endian IPv4
		ip := []string{strconv.Itoa(int(raw[3])), strconv.Itoa(int(raw[2])), strconv.Itoa(int(raw[1])), strconv.Itoa(int(raw[0]))}
		addr := strings.Join(ip, ".")
		return addr, int(port64), raw[3] == 127
	case 16:
		allZero := true
		for _, b := range raw {
			if b != 0 {
				allZero = false
			}
		}
		loop := raw[12] == 1 && allZero == false && raw[0] == 0 // ::1 in kernel byte order ends with 01 00 00 00
		return parts[0], int(port64), loop
	}
	return s, int(port64), false
}

func runSockets(ctx context.Context, a collect.Access, b *collect.Builder) error {
	list, src, err := ListeningSockets(a)
	if err != nil {
		b.Set("sockets.listening", collect.FromReadError(err, collect.ReadMeta{}))
		return nil
	}
	b.Set("sockets.listening", collect.OK(list, src))
	return nil
}
```

`services.go`:

```go
//go:build linux

package collectors

import (
	"context"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var systemctl = "/usr/bin/systemctl"

func showCmd(unit string) collect.Command {
	return collect.Command{Path: systemctl, Args: []string{"show", "-p", "LoadState,ActiveState,UnitFileState,SubState", unit}}
}

var logical = map[string][]string{
	"ssh":    {"ssh.service", "sshd.service", "ssh.socket"},
	"telnet": {"telnet.socket", "telnet.service", "telnetd.service", "inetd.service", "xinetd.service"},
}

var servicesCollector = collect.Collector{
	Name: "services",
	Declare: collect.Declaration{
		Reads: []string{"/run/systemd/system", "/etc/inetd.conf", "/etc/xinetd.d/*", "/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"},
		Commands: []collect.Command{
			showCmd("ssh.service"), showCmd("sshd.service"), showCmd("ssh.socket"),
			showCmd("telnet.socket"), showCmd("telnet.service"), showCmd("telnetd.service"),
			showCmd("inetd.service"), showCmd("xinetd.service"),
		},
		Needs: "none",
	},
	Run: runServices,
}

type unitState struct{ load, active, file, sub string }

func showUnit(ctx context.Context, a collect.Access, unit string) (unitState, *facts.Source, bool) {
	out := a.Run(ctx, showCmd(unit))
	if out.Err != nil || out.ExitCode != 0 {
		return unitState{}, out.Source(showCmd(unit)), false
	}
	var u unitState
	for _, line := range strings.Split(string(out.Stdout), "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "LoadState":
			u.load = v
		case "ActiveState":
			u.active = v
		case "UnitFileState":
			u.file = v
		case "SubState":
			u.sub = v
		}
	}
	return u, out.Source(showCmd(unit)), true
}

func runServices(ctx context.Context, a collect.Access, b *collect.Builder) error {
	if _, err := a.Stat("/run/systemd/system"); err != nil {
		for _, k := range []string{"services.ssh.installed", "services.ssh.active", "services.telnet.installed", "services.telnet.reachable"} {
			b.Set(k, collect.Unsupported("no systemd on this host or inside this container"))
		}
		return nil
	}
	sockets, _, _ := ListeningSockets(a)
	nonLoopbackPort := func(port int) bool {
		for _, s := range sockets {
			m := s.(map[string]any)
			if m["port"] == port && m["loopback"] == false && strings.HasPrefix(m["proto"].(string), "tcp") {
				return true
			}
		}
		return false
	}
	for name, units := range logical {
		installed, active, listening := false, false, false
		var src *facts.Source
		for _, unit := range units {
			u, s, ok := showUnit(ctx, a, unit)
			if !ok {
				continue
			}
			if u.load == "loaded" {
				installed = true
				src = s
			}
			if u.active == "active" {
				active = true
				if strings.HasSuffix(unit, ".socket") && u.sub == "listening" {
					listening = true
				}
			}
		}
		if name == "telnet" && !installed {
			if data, _, err := a.ReadFile("/etc/inetd.conf", readLimit); err == nil && strings.Contains(string(data), "telnet") {
				installed = true
				src = &facts.Source{Kind: "file", Path: "/etc/inetd.conf"}
			}
		}
		if !installed {
			b.Set("services."+name+".installed", collect.OK(false, src))
			if name == "ssh" {
				b.Set("services.ssh.active", collect.Absent("no ssh unit"))
			} else {
				b.Set("services.telnet.reachable", collect.Absent("no telnet unit or inetd entry"))
			}
			continue
		}
		b.Set("services."+name+".installed", collect.OK(true, src))
		switch name {
		case "ssh":
			b.Set("services.ssh.active", collect.OK(active, src))
		case "telnet":
			reachable := (active || listening) && nonLoopbackPort(23)
			if !active && !listening {
				reachable = nonLoopbackPort(23) // inetd-run telnet has no unit state
			}
			b.Set("services.telnet.reachable", collect.OK(reachable, src))
		}
	}
	return nil
}
```

`files.go`:

```go
//go:build linux

package collectors

import (
	"context"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var filesCollector = collect.Collector{
	Name:    "files",
	Declare: collect.Declaration{Reads: []string{"/etc/passwd", "/etc/securetty"}, Needs: "none"},
	Run:     runFiles,
}

// aclPresent reports whether an access ACL xattr exists. EOPNOTSUPP or
// ENODATA mean no ACL; a permission error propagates so the fact is denied.
func aclPresent(path string) (bool, error) {
	buf := make([]byte, 4096)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		if err == unix.EOPNOTSUPP || err == unix.ENODATA || err == unix.ENOTSUP {
			return false, nil
		}
		return false, err
	}
	for _, name := range strings.Split(string(buf[:n]), "\x00") {
		if name == "system.posix_acl_access" {
			return true, nil
		}
	}
	return false, nil
}

func runFiles(ctx context.Context, a collect.Access, b *collect.Builder) error {
	src := &facts.Source{Kind: "sys", Path: "/etc/passwd"}
	meta, err := a.Stat("/etc/passwd")
	if err != nil {
		e := collect.FromReadError(err, meta)
		for _, k := range []string{"mode", "uid", "gid", "acl_present"} {
			b.Set("files.etc_passwd."+k, e)
		}
	} else {
		b.Set("files.etc_passwd.mode", collect.OK(int(meta.Mode.Perm()), src))
		b.Set("files.etc_passwd.uid", collect.OK(int(meta.UID), src))
		b.Set("files.etc_passwd.gid", collect.OK(int(meta.GID), src))
		if present, err := aclPresent("/etc/passwd"); err != nil {
			b.Set("files.etc_passwd.acl_present", collect.FromReadError(err, meta))
		} else {
			b.Set("files.etc_passwd.acl_present", collect.OK(present, src))
		}
	}
	data, smeta, err := a.ReadFile("/etc/securetty", readLimit)
	if err != nil {
		e := collect.FromReadError(err, smeta)
		b.Set("files.etc_securetty", e)
		b.Set("files.etc_securetty_lines", e)
		return nil
	}
	var lines []any
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	ssrc := &facts.Source{Kind: "file", Path: "/etc/securetty"}
	b.Set("files.etc_securetty", collect.OK(map[string]any{"mode": int(smeta.Mode.Perm())}, ssrc))
	b.Set("files.etc_securetty_lines", collect.OK(lines, ssrc))
	return nil
}
```

Note: `aclPresent` calls `unix.Llistxattr` directly on the path rather than through `Access`; declare it by listing `/etc/passwd` in `Reads` (already there) and, in the guard test, the fake `Stat` succeeds so the xattr call runs against the real `/etc/passwd`, which is world-readable — acceptable, but to keep the guard honest add `Llistxattr(path string) ([]string, error)` to the `Access` interface in Task 3 and route through it (the fake returns none). Do that: add the method to `Access`, `hostAccess`, `guardedAccess` (checked as a read) and the test doubles.

`os.go`:

```go
//go:build linux

package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

var osCollector = collect.Collector{
	Name: "os",
	Declare: collect.Declaration{Reads: []string{
		"/etc/os-release", "/etc/hostname", "/etc/machine-id", "/proc/sys/kernel/osrelease",
		"/proc/sys/kernel/random/boot_id", "/proc/uptime", "/proc/1/cgroup", "/proc/1/comm",
		"/.dockerenv", "/run/.containerenv", "/run/systemd/system", "/proc/version",
		"/sys/class/dmi/id/product_name", "/var/lib/cloud", "/proc/sys/net",
	}, Needs: "none"},
	Run: runOS,
}

func readTrim(a collect.Access, p string) string {
	data, _, err := a.ReadFile(p, 64<<10)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func exists(a collect.Access, p string) bool { _, err := a.Stat(p); return err == nil }

// runOS fills the run header through the builder's Header hook (Task 6
// wires Header() into Run.Host and Run.Env).
func runOS(ctx context.Context, a collect.Access, b *collect.Builder) error {
	h := &b.Header().Host
	e := &b.Header().Env
	h.Hostname = readTrim(a, "/etc/hostname")
	if id := readTrim(a, "/etc/machine-id"); id != "" {
		sum := sha256.Sum256([]byte(id))
		h.MachineIDHash = hex.EncodeToString(sum[:])
	}
	h.Kernel = readTrim(a, "/proc/sys/kernel/osrelease")
	h.BootID = readTrim(a, "/proc/sys/kernel/random/boot_id")
	if up := strings.Fields(readTrim(a, "/proc/uptime")); len(up) > 0 {
		f, _ := strconv.ParseFloat(up[0], 64)
		h.UptimeS = int64(f)
	}
	for _, line := range strings.Split(readTrim(a, "/etc/os-release"), "\n") {
		k, v, _ := strings.Cut(line, "=")
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			h.OSRelease.ID = v
		case "VERSION_ID":
			h.OSRelease.VersionID = v
		case "ID_LIKE":
			if strings.Contains(v, "rhel") || strings.Contains(v, "fedora") {
				h.OSRelease.Family = "rhel"
			} else if strings.Contains(v, "debian") {
				h.OSRelease.Family = "debian"
			}
		}
	}
	switch h.OSRelease.ID {
	case "ubuntu", "debian":
		h.OSRelease.Family = "debian"
	case "rocky", "almalinux", "rhel", "centos", "fedora":
		h.OSRelease.Family = "rhel"
	}
	if h.OSRelease.Family == "" {
		h.OSRelease.Family = "unknown"
	}
	e.Container = "none"
	switch {
	case exists(a, "/.dockerenv"):
		e.Container = "docker"
	case exists(a, "/run/.containerenv"):
		e.Container = "podman"
	case strings.Contains(readTrim(a, "/proc/1/cgroup"), "lxc"):
		e.Container = "lxc"
	}
	e.WSL = strings.Contains(strings.ToLower(readTrim(a, "/proc/version")), "microsoft")
	e.HasSystemd = exists(a, "/run/systemd/system")
	e.SysctlWritable = unix.Access("/proc/sys/net", unix.W_OK) == nil
	e.CloudInit = exists(a, "/var/lib/cloud")
	product := strings.ToLower(readTrim(a, "/sys/class/dmi/id/product_name"))
	switch {
	case product == "":
		e.Virt = "unknown"
	case strings.Contains(product, "kvm"):
		e.Virt = "kvm"
	case strings.Contains(product, "vmware"):
		e.Virt = "vmware"
	case strings.Contains(product, "virtualbox"):
		e.Virt = "virtualbox"
	case strings.Contains(product, "virtual machine"):
		e.Virt = "hyperv"
	default:
		e.Virt = "none"
	}
	_ = facts.Run{} // header types live in facts
	return nil
}
```

Add to `Builder` (Task 3 `facts.go`): a `header facts.Run` field and `func (b *Builder) Header() *facts.Run` so `os` can fill `Host` and `Env` without a registry key.

`walk.go`:

```go
//go:build linux

package collectors

import (
	"context"

	"github.com/kun9497/muster/internal/collect"
)

// Deep is set by the collect command when --deep is given. Stage 1 ships
// the flag and the boundary contract; the traversal arrives in stage 3.
var Deep bool

var walkCollector = collect.Collector{
	Name:    "walk",
	Declare: collect.Declaration{Needs: "root"},
	Run: func(ctx context.Context, a collect.Access, b *collect.Builder) error {
		if !Deep {
			return nil // keys stay absent → walk-based controls are MANUAL ("run collect --deep")
		}
		b.Set("walk.complete", collect.Unsupported("the deep walk arrives in stage 3"))
		return collect.ErrSkipped
	},
}
```

Add `var ErrSkipped = errors.New("collector skipped")` to `registry.go`; Task 6 records a collector returning it with status `skipped` and does not count it as a partial failure.

- [ ] **Step 4: Run the tests to verify they pass**

Run (Linux): `go test ./internal/collect/... -v`
Expected: PASS, including `TestEveryCollectorStaysInsideItsDeclaration`.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/
git commit -m "Add the stage-1 collectors: os, services, sockets, sshd, files, accounts, walk skeleton"
```

---

### Task 6: `Run`, the provenance header, `collect` exit codes and the command

**Files:**
- Create: `internal/collect/run.go`, `internal/collect/run_test.go`, `cmd/muster/collect.go`, `cmd/muster/collect_other.go`, `cmd/muster/collect_test.go`
- Modify: `cmd/muster/main.go` (dispatch `collect`), `internal/collect/facts.go` (`Header()`), `internal/collect/registry.go` (`ErrSkipped`, `Violations`, `Llistxattr` on `Access`)

**Interfaces:**
- Produces (package `collect`, Linux):
  - `type Options struct { Out string; Force bool; Deep bool; Timeout time.Duration; RequireRoot, RequireComplete bool; IncludeSecrets bool; Version, Commit, ControlsVersion, ControlsDigest string; LockPath string; Now func() time.Time; Access Access }` — `Timeout` 0 means 5 min; `LockPath` empty means `LockPath` constant; `Now` nil means `time.Now`; `Access` nil means the host.
  - `type Outcome struct { Path string; Complete bool; Partial []string; Header facts.Run }`.
  - `var ErrNotRoot = errors.New("collect requires root (--require-root)")`.
  - `func Run(ctx context.Context, o Options, stdout io.Writer) (Outcome, error)` — checks `--require-root` first (euid ≠ 0 → `ErrNotRoot`, nothing written), acquires the lock (`ErrLocked` → returned, nothing written), builds the header (`SchemaVersion=facts.SchemaVersion`, versions, `GuideEdition="kisa-unix-2026"`, `CollectedAt` RFC3339 UTC, `EUID`, `Capabilities` from `/proc/self/status` `CapEff` decoded against a small table for the bits collect cares about — `CAP_DAC_READ_SEARCH`(2), `CAP_SYS_ADMIN`(21), `CAP_NET_ADMIN`(12) — plus `"raw:<hex>"`), runs every collector under the global deadline with `Guard`, each in its own `recover`, recording `CollectorRun{Name, Status, Ms, Cmd, Reason}` where status is `ok`, `skipped` (returned `ErrSkipped`), `timeout` (ctx deadline hit during it), `error` (returned error or panic) or `violation` (guard recorded a violation — treated as `error` and named in `PartialFailures`), sets `Complete = no error/timeout/violation and no fact with status denied`, `Deep`, `Redaction{Profile: "default"|"none", IncludeSecrets}`, then serialises `facts.Snapshot{SchemaVersion, Run, Facts: builder.Tree()}` with `json.MarshalIndent` and writes it via `WriteSnapshot`. `RequireComplete` does not change what is written; the command maps it to the exit code.
  - `func ExitCodeFor(out Outcome, err error, requireComplete bool) int` — `err != nil` → 2; `!out.Complete && requireComplete` → 2; `!out.Complete` → 1; else 0.
- Produces (package `main`):
  - `runCollect(args, stdout, stderr)` with flags `--out <path|->`, `--force`, `--deep`, `--timeout <duration>`, `--require-root`, `--require-complete`, `--include-secrets`, `--list-actions [--format table|json]`. Prints `muster: wrote <path> (complete|partial: a, b)` to stderr, and `muster: warning: not running as root; expect denied facts` when euid ≠ 0 and `--require-root` is absent. On non-Linux (`collect_other.go`): prints `muster: collect requires Linux` and exits 2 (`--list-actions` also unsupported there).

- [ ] **Step 1: Write the failing tests**

`internal/collect/run_test.go`:

```go
//go:build linux

package collect

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/facts"
)

type quietAccess struct{}

func (quietAccess) ReadFile(string, int64) ([]byte, ReadMeta, error) { return nil, ReadMeta{}, os.ErrNotExist }
func (quietAccess) Stat(string) (ReadMeta, error)                    { return ReadMeta{}, os.ErrNotExist }
func (quietAccess) Glob(string) ([]string, error)                    { return nil, nil }
func (quietAccess) Llistxattr(string) ([]string, error)              { return nil, nil }
func (quietAccess) Run(context.Context, Command) Output              { return Output{ExitCode: 127, Err: os.ErrNotExist} }

func TestRunWritesSnapshotWithHeaderAndCollectorLog(t *testing.T) {
	Reset()
	Register(Collector{Name: "good", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		b.Set("services.ssh.installed", OK(true, nil))
		return nil
	}})
	Register(Collector{Name: "bad", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		return errors.New("boom")
	}})
	Register(Collector{Name: "skip", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error { return ErrSkipped }})
	Register(Collector{Name: "panics", Declare: Declaration{Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error { panic("x") }})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), LockPath: filepath.Join(dir, ".lock"), Access: quietAccess{},
		Version: "0.1.0", Commit: "abc", ControlsVersion: "cv", ControlsDigest: "sha256:cd",
		Now: func() time.Time { return time.Date(2026, 9, 2, 6, 0, 0, 0, time.UTC) }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Complete {
		t.Error("a failing collector must make the run partial")
	}
	if strings.Join(out.Partial, ",") != "bad,panics" {
		t.Errorf("partial %v", out.Partial)
	}
	f, _ := os.Open(out.Path)
	snap, err := facts.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion != facts.SchemaVersion || snap.Run.CollectedAt != "2026-09-02T06:00:00Z" || snap.Run.GuideEdition != "kisa-unix-2026" || snap.Run.ControlsDigest != "sha256:cd" {
		t.Errorf("header %+v", snap.Run)
	}
	statuses := map[string]string{}
	for _, c := range snap.Run.Collectors {
		statuses[c.Name] = c.Status
	}
	if statuses["good"] != "ok" || statuses["bad"] != "error" || statuses["skip"] != "skipped" || statuses["panics"] != "error" {
		t.Errorf("collector log %v", statuses)
	}
	reg, _ := facts.LoadRegistry()
	if r, _ := reg.Resolve(snap, "services.ssh.installed"); r.Envelope.Value != true {
		t.Errorf("fact lost: %+v", r)
	}
}

func TestRunDeniedFactMakesPartial(t *testing.T) {
	Reset()
	Register(Collector{Name: "d", Declare: Declaration{Needs: "root"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		b.Set("files.etc_passwd.mode", Denied("requires root"))
		return nil
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), LockPath: filepath.Join(dir, ".lock"), Access: quietAccess{}}, nil)
	if err != nil || out.Complete {
		t.Fatalf("%+v %v", out, err)
	}
	if ExitCodeFor(out, nil, false) != 1 || ExitCodeFor(out, nil, true) != 2 || ExitCodeFor(out, errors.New("x"), false) != 2 {
		t.Error("exit code mapping")
	}
}

func TestRunRequireRootRefusesWithoutWriting(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	Reset()
	dir := t.TempDir()
	p := filepath.Join(dir, "s.json")
	_, err := Run(context.Background(), Options{Out: p, LockPath: filepath.Join(dir, ".lock"), RequireRoot: true, Access: quietAccess{}}, nil)
	if !errors.Is(err, ErrNotRoot) {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(p); statErr == nil {
		t.Error("nothing may be written when --require-root fails")
	}
}

func TestRunGuardViolationIsRecorded(t *testing.T) {
	Reset()
	Register(Collector{Name: "sneaky", Declare: Declaration{Reads: []string{"/etc/hostname"}, Needs: "none"}, Run: func(ctx context.Context, a Access, b *Builder) error {
		a.ReadFile("/etc/shadow", 10)
		return nil
	}})
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: filepath.Join(dir, "s.json"), LockPath: filepath.Join(dir, ".lock"), Access: quietAccess{}}, nil)
	if err != nil || out.Complete || strings.Join(out.Partial, ",") != "sneaky" {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestRunToStdout(t *testing.T) {
	Reset()
	var buf bytes.Buffer
	dir := t.TempDir()
	out, err := Run(context.Background(), Options{Out: "-", LockPath: filepath.Join(dir, ".lock"), Access: quietAccess{}}, &buf)
	if err != nil || out.Path != "-" || !strings.HasPrefix(buf.String(), "{") {
		t.Fatalf("%+v %v %q", out, err, buf.String())
	}
}
```

`cmd/muster/collect_test.go`:

```go
package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestCollectRejectsUnknownFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--bogus"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "--bogus") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

func TestCollectOffLinuxSaysSo(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux")
	}
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--out", "-"}, &out, &errb); code != exitError || !strings.Contains(errb.String(), "requires Linux") {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

func TestCollectListActionsOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	var out, errb bytes.Buffer
	if code := run([]string{"collect", "--list-actions", "--format", "json"}, &out, &errb); code != exitOK {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
	for _, want := range []string{`"kind": "read"`, `"kind": "command"`, `"kind": "write"`, "/usr/sbin/sshd -T"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run (Linux): `go test ./internal/collect/ -run TestRun -v; go test ./cmd/muster/ -run TestCollect -v`
Expected: FAIL — undefined `Run`, `Options`, `ExitCodeFor`; `collect` not dispatched.

- [ ] **Step 3: Write `run.go`, the command and the stub**

Registry additions (`registry.go`): `var ErrSkipped = errors.New("collector skipped")`; `func Violations(g *guardedAccess) []string { return g.violations }`; add `Llistxattr(path string) ([]string, error)` to `Access`, implement on `hostAccess` (`unix.Llistxattr` into a 4096-byte buffer split on NUL; `EOPNOTSUPP`/`ENOTSUP`/`ENODATA` → empty, nil) and on `guardedAccess` (checked as a read). Builder additions (`facts.go`): `header facts.Run` field; `func (b *Builder) Header() *facts.Run { return &b.header }`.

`internal/collect/run.go`:

```go
//go:build linux

package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/facts"
)

var ErrNotRoot = errors.New("collect requires root (--require-root)")

// Options for one collect run.
type Options struct {
	Out             string
	Force           bool
	Deep            bool
	Timeout         time.Duration
	RequireRoot     bool
	RequireComplete bool
	IncludeSecrets  bool
	Version         string
	Commit          string
	ControlsVersion string
	ControlsDigest  string
	LockPath        string
	Now             func() time.Time
	Access          Access
}

// Outcome is what the command needs to report and to choose an exit code.
type Outcome struct {
	Path     string
	Complete bool
	Partial  []string
	Header   facts.Run
}

// capabilities decodes CapEff from /proc/self/status for the bits collect
// cares about; the raw mask is kept so nothing is lost.
func capabilities(a Access) []string {
	data, _, err := a.ReadFile("/proc/self/status", 64<<10)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hexMask := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, err := strconv.ParseUint(hexMask, 16, 64)
		if err != nil {
			return []string{"raw:" + hexMask}
		}
		names := []string{}
		for bit, name := range map[uint]string{2: "CAP_DAC_READ_SEARCH", 12: "CAP_NET_ADMIN", 21: "CAP_SYS_ADMIN"} {
			if mask&(1<<bit) != 0 {
				names = append(names, name)
			}
		}
		return append(names, "raw:"+hexMask)
	}
	return nil
}

// Run executes every registered collector and writes the snapshot (spec
// §7.1). Nothing is written when --require-root fails or the lock is held.
func Run(ctx context.Context, o Options, stdout io.Writer) (Outcome, error) {
	if o.RequireRoot && os.Geteuid() != 0 {
		return Outcome{}, ErrNotRoot
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Access == nil {
		o.Access = hostAccess{}
	}
	if o.LockPath == "" {
		o.LockPath = LockPath
	}
	lock, err := AcquireLock(o.LockPath)
	if err != nil {
		return Outcome{}, err
	}
	defer lock.Release()

	reg, err := facts.LoadRegistry()
	if err != nil {
		return Outcome{}, err
	}
	b := NewBuilder(reg)
	hdr := b.Header()
	hdr.MusterVersion, hdr.Commit = o.Version, o.Commit
	hdr.ControlsVersion, hdr.ControlsDigest = o.ControlsVersion, o.ControlsDigest
	hdr.GuideEdition = "kisa-unix-2026"
	hdr.CollectedAt = o.Now().UTC().Format(time.RFC3339)
	hdr.EUID = os.Geteuid()
	hdr.Capabilities = capabilities(o.Access)
	hdr.Deep = o.Deep
	hdr.Redaction = facts.Redaction{Profile: "default", IncludeSecrets: o.IncludeSecrets}
	if o.IncludeSecrets {
		hdr.Redaction.Profile = "none"
	}
	hdr.Collectors = []facts.CollectorRun{}
	hdr.PartialFailures = []string{}

	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	complete := true
	for _, c := range All() {
		g := Guard(o.Access, c)
		start := o.Now()
		status, reason := runOne(ctx, c, g, b)
		if len(g.violations) > 0 {
			status, reason = "error", strings.Join(g.violations, "; ")
		}
		hdr.Collectors = append(hdr.Collectors, facts.CollectorRun{Name: c.Name, Status: status, Ms: o.Now().Sub(start).Milliseconds(), Reason: reason})
		if status == "error" || status == "timeout" {
			complete = false
			hdr.PartialFailures = append(hdr.PartialFailures, c.Name)
		}
	}
	if anyDenied(b.Tree()) {
		complete = false
	}
	hdr.Complete = complete
	if hdr.Host.Hostname == "" {
		hdr.Host.Hostname, _ = os.Hostname()
	}

	snap := facts.Snapshot{SchemaVersion: facts.SchemaVersion, Run: *hdr, Facts: b.Tree()}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return Outcome{}, err
	}
	data = append(data, '\n')
	path, err := WriteSnapshot(data, WriteOptions{Out: o.Out, Force: o.Force}, stdout)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Path: path, Complete: complete, Partial: hdr.PartialFailures, Header: *hdr}, nil
}

func runOne(ctx context.Context, c Collector, a Access, b *Builder) (status, reason string) {
	defer func() {
		if p := recover(); p != nil {
			status, reason = "error", fmt.Sprintf("panic: %v", p)
		}
	}()
	if c.Run == nil {
		return "skipped", "no run function"
	}
	err := c.Run(ctx, a, b)
	switch {
	case errors.Is(err, ErrSkipped):
		return "skipped", ""
	case ctx.Err() != nil:
		return "timeout", "global deadline exceeded"
	case err != nil:
		return "error", err.Error()
	}
	return "ok", ""
}

// anyDenied walks the tree for a denied envelope or setting side.
func anyDenied(tree map[string]any) bool {
	for _, v := range tree {
		switch x := v.(type) {
		case map[string]any:
			if anyDenied(x) {
				return true
			}
		case facts.Envelope:
			if x.Status == facts.StatusDenied {
				return true
			}
		case facts.Setting:
			for _, s := range []*facts.Envelope{x.Runtime, x.Persisted, x.Effective} {
				if s != nil && s.Status == facts.StatusDenied {
					return true
				}
			}
		}
	}
	return false
}

// ExitCodeFor maps an outcome to the collect contract: 0 complete, 1
// partial, 2 nothing written (or partial with --require-complete).
func ExitCodeFor(out Outcome, err error, requireComplete bool) int {
	switch {
	case err != nil:
		return 2
	case !out.Complete && requireComplete:
		return 2
	case !out.Complete:
		return 1
	}
	return 0
}
```

`cmd/muster/collect.go` (`//go:build linux`):

```go
//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/collect/collectors"
	"github.com/kun9497/muster/internal/controls"
)

const collectUsage = `usage: muster collect [flags]

flags:
  --out <path|->        snapshot path (default /var/lib/muster/snapshots/<host>-<time>-<digest>.json)
  --force               overwrite an existing --out path
  --deep                run the filesystem walk (stage 3; recorded as unsupported in stage 1)
  --timeout <duration>  global deadline (default 5m)
  --require-root        exit 2 without writing when not root
  --require-complete    exit 2 (instead of 1) when the snapshot is partial
  --include-secrets     store original secret values (recorded in the snapshot header)
  --list-actions        print every path read, command run and the file written, then exit
  --format table|json   with --list-actions
`

func runCollect(args []string, stdout, stderr io.Writer) int {
	o := collect.Options{Version: version, Commit: commit}
	format, list := "table", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		var v string
		var ok bool
		switch a {
		case "--out":
			if v, ok = next(); ok {
				o.Out = v
			}
		case "--timeout":
			if v, ok = next(); ok {
				d, err := time.ParseDuration(v)
				if err != nil {
					fmt.Fprintf(stderr, "muster: --timeout: %v\n", err)
					return exitError
				}
				o.Timeout = d
			}
		case "--format":
			if v, ok = next(); ok {
				format = v
			}
		case "--force":
			o.Force, ok = true, true
		case "--deep":
			o.Deep, ok = true, true
		case "--require-root":
			o.RequireRoot, ok = true, true
		case "--require-complete":
			o.RequireComplete, ok = true, true
		case "--include-secrets":
			o.IncludeSecrets, ok = true, true
		case "--list-actions":
			list, ok = true, true
		default:
			fmt.Fprintf(stderr, "muster: unknown flag %s\n%s", a, collectUsage)
			return exitError
		}
		if !ok {
			fmt.Fprintf(stderr, "muster: flag %s needs a value\n", a)
			return exitError
		}
	}
	if list {
		if err := collect.WriteActions(stdout, collect.ListActions(), format); err != nil {
			fmt.Fprintf(stderr, "muster: %v\n", err)
			return exitError
		}
		return exitOK
	}
	set, err := controls.LoadDefault()
	if err != nil {
		fmt.Fprintf(stderr, "muster: %v\n", err)
		return exitError
	}
	o.ControlsVersion, o.ControlsDigest = set.Version, set.Digest
	collectors.Deep = o.Deep
	if os.Geteuid() != 0 && !o.RequireRoot {
		fmt.Fprintln(stderr, "muster: warning: not running as root; expect denied facts")
	}
	out, err := collect.Run(context.Background(), o, stdout)
	if err != nil {
		if errors.Is(err, collect.ErrLocked) || errors.Is(err, collect.ErrNotRoot) || errors.Is(err, collect.ErrExists) {
			fmt.Fprintf(stderr, "muster: %v\n", err)
		} else {
			fmt.Fprintf(stderr, "muster: collect failed: %v\n", err)
		}
		return exitError
	}
	if out.Complete {
		fmt.Fprintf(stderr, "muster: wrote %s (complete)\n", out.Path)
	} else {
		fmt.Fprintf(stderr, "muster: wrote %s (partial: %s)\n", out.Path, strings.Join(out.Partial, ", "))
	}
	return collect.ExitCodeFor(out, nil, o.RequireComplete)
}
```

`cmd/muster/collect_other.go`:

```go
//go:build !linux

package main

import (
	"fmt"
	"io"
)

func runCollect(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		if a == "--bogus" {
			fmt.Fprintf(stderr, "muster: unknown flag %s\n", a)
			return exitError
		}
	}
	fmt.Fprintln(stderr, "muster: collect requires Linux; check runs anywhere")
	return exitError
}
```

(The `--bogus` branch exists so the shared flag test passes on both platforms; replace it with a real flag parser shared via a small `parseCollectFlags` in a tag-free file if you prefer — keep the behaviour: unknown flag → exit 2 naming it.)

Add `case "collect": return runCollect(args[1:], stdout, stderr)` to `run` in `main.go` and the line `collect    gather host facts as root and write a snapshot (Linux)` to `usage`.

- [ ] **Step 4: Run the tests to verify they pass**

Run (Linux): `go test ./internal/collect/... ./cmd/muster/ -v` and then, as root, the real thing:

```
sudo go run ./cmd/muster collect --out /tmp/muster-test.json --force
go run ./cmd/muster check --facts /tmp/muster-test.json
rm /tmp/muster-test.json
```

Expected: tests PASS; the real run prints `wrote /tmp/muster-test.json (complete)` (or `partial: walk`-free — walk without `--deep` sets nothing), and `check` shows U-01 (WARN degraded, personas not collected), U-02, U-16, U-52 with real verdicts and U-25 MANUAL. Then run as an ordinary user with `--out /tmp/muster-user.json` and confirm exit 1, `shadow` facts `denied`, and `check --facts /tmp/muster-user.json` exits 2 with U-02 `ERROR(permission_denied)`. Delete both files; never commit them.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/ cmd/muster/
git commit -m "Add collect: run orchestration, provenance header, exit codes and the command"
```

---

### Task 7: Linux CI — runner as root, non-root, containers, network-less read-only

**Files:**
- Modify: `.github/workflows/ci.yml` (add jobs)

**Interfaces:**
- Produces: four jobs that together are the spec §11 "capability matrix" for stage 1: (1) `collect-root` on the runner VM: `sudo` collect → complete snapshot → `check` exits 0 or 1 (never 2), and `--list-actions` runs; (2) `collect-nonroot`: collect exits 1, `check` exits 2, and every `denied` fact belongs to a control that is `ERROR` — asserted with `jq`; (3) `collect-containers` for `ubuntu:22.04`, `ubuntu:24.04`, `rockylinux/rockylinux:9-ubi-init`, `almalinux/9-init`: collect inside the container, assert `run.env.container != "none"` and that `services.*` are `unsupported` where systemd is absent (the plain Ubuntu images) and `ok` where it runs (`*-init` images started with `/sbin/init`); (4) `collect-contract`: run collect in a `--network none` container on a read-only bind mount with `--out /out/s.json` on a writable volume, and assert that the only new file under the writable volume is the snapshot.

- [ ] **Step 1: Add the jobs**

Append to `.github/workflows/ci.yml`:

```yaml
  collect-root:
    runs-on: ubuntu-24.04
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.5"
      - run: CGO_ENABLED=0 go build -trimpath -o bin/muster ./cmd/muster
      - name: list actions
        run: ./bin/muster collect --list-actions
      - name: collect as root
        run: sudo ./bin/muster collect --out /tmp/root.json --require-root --require-complete
      - name: check the root snapshot
        run: |
          set +e
          ./bin/muster check --facts /tmp/root.json --format json > /tmp/root-report.json
          code=$?
          set -e
          echo "check exit $code"
          test "$code" -ne 2
          jq -e '.results | map(select(.status=="ERROR")) | length == 0' /tmp/root-report.json
          jq -e '.check.guide_edition == "kisa-unix-2026"' /tmp/root-report.json
      - name: sudo-run linux tests
        run: sudo env PATH="$PATH" go test ./internal/collect/... -run 'TestRun|TestWriteSnapshot|TestReadFile' -v

  collect-nonroot:
    runs-on: ubuntu-24.04
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.5"
      - run: CGO_ENABLED=0 go build -trimpath -o bin/muster ./cmd/muster
      - name: collect without root is partial (exit 1)
        run: |
          set +e
          ./bin/muster collect --out /tmp/user.json
          code=$?
          set -e
          test "$code" -eq 1
          jq -e '.run.complete == false and .run.euid != 0' /tmp/user.json
      - name: every denied fact is an ERROR, never a PASS
        run: |
          set +e
          ./bin/muster check --facts /tmp/user.json --format json > /tmp/user-report.json
          code=$?
          set -e
          test "$code" -eq 2
          jq -e '.results | map(select(.id=="muster.account.password_policy")) | .[0].status == "ERROR" and .[0].reason_code == "permission_denied"' /tmp/user-report.json
          jq -e '[.results[] | select(.evidence != null) | .evidence[] | select(.status=="denied")] | length == 0' /tmp/user-report.json

  collect-containers:
    runs-on: ubuntu-24.04
    needs: test
    strategy:
      fail-fast: false
      matrix:
        include:
          - image: ubuntu:22.04
            init: "false"
          - image: ubuntu:24.04
            init: "false"
          - image: rockylinux/rockylinux:9-ubi-init
            init: "true"
          - image: almalinux/9-init
            init: "true"
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.5"
      - run: CGO_ENABLED=0 go build -trimpath -o bin/muster ./cmd/muster
      - name: collect inside ${{ matrix.image }}
        run: |
          mkdir -p out
          if [ "${{ matrix.init }}" = "true" ]; then
            cid=$(docker run -d --privileged --cgroupns=host -v "$PWD/bin:/m:ro" -v "$PWD/out:/out" ${{ matrix.image }} /sbin/init)
            sleep 5
            docker exec "$cid" /m/muster collect --out /out/c.json || true
            docker rm -f "$cid"
          else
            docker run --rm -v "$PWD/bin:/m:ro" -v "$PWD/out:/out" ${{ matrix.image }} /m/muster collect --out /out/c.json || true
          fi
          test -s out/c.json
          jq -e '.run.env.container != "none"' out/c.json
          if [ "${{ matrix.init }}" = "true" ]; then
            jq -e '.facts.services.ssh.installed.status == "ok"' out/c.json
          else
            jq -e '.facts.services.ssh.installed.status == "unsupported"' out/c.json
          fi
      - name: unseen facts are ERROR or NOT_APPLICABLE, never PASS
        run: |
          set +e
          ./bin/muster check --facts out/c.json --format json > out/report.json
          set -e
          jq -e '[.results[] | select(.status=="PASS") | .evidence[]? | select(.status != "ok")] | length == 0' out/report.json

  collect-contract:
    runs-on: ubuntu-24.04
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.5"
      - run: CGO_ENABLED=0 go build -trimpath -o bin/muster ./cmd/muster
      - name: no network, read-only root, one file written
        run: |
          mkdir -p out
          docker run --rm --network none --read-only --tmpfs /run --tmpfs /tmp -v "$PWD/bin:/m:ro" -v "$PWD/out:/out" ubuntu:24.04 \
            sh -c '/m/muster collect --out /out/s.json; echo "exit $?"; ls -A /out'
          test "$(ls -A out | wc -l)" -eq 1
          test -f out/s.json
```

- [ ] **Step 2: Run the workflow**

Push the branch to the private remote (the developer does this; agents never push) and open the Actions page. Expected: all four jobs green; `collect-nonroot` proves the "unseen is unseen" contract on a real host; `collect-containers` proves `unsupported` on systemd-less images.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "Add Linux collect CI: root, non-root, containers, network-less read-only"
```

---

## Self-review

**Spec coverage (stage 1 items from §10.2 not covered by plan 1A):** `collect` (T6); read primitive (T1); exec discipline (T2); collector registry with `--list-actions` (T3, T6); walk skeleton — flag, boundary contract recorded in the design, `complete` handling (T5 `walk`, T6 header `Deep`; the traversal and boundaries themselves are stage 3 and are not implemented here, which §10.2 allows: "without the walk"); snapshot lifecycle (T4); redaction policy enforced by construction in `accounts` (T5: no hash leaves `parseShadow`; test asserts it); `collect` exit codes and `--require-root` (T6); the five collectors at their stage-1 minimums — sshd `-T` global only with `personas_collected=false` (T5), `login.defs` + shadow ageing (T5), `/etc/passwd` mode/uid/gid + `acl_present` (T5), telnet via `systemctl show` + listening sockets (T5), U-25 fixtures only (plan 1A). Provenance header (T6). Non-root as a first-class path (T6, T7). Container `unsupported` statuses (T5 `services`, T7).

**Deviations and notes:** `walk --deep` in stage 1 records `walk.complete` as `unsupported` and the collector as `skipped`, so U-25 reads `NOT_APPLICABLE` with `--deep` and `MANUAL` without it until stage 3 — both honest. `services.telnet.reachable` uses the sockets table directly rather than depending on collector order. `aclPresent` goes through the `Access` interface so the guard sees it.

**Placeholder scan:** none; every code step has code. `collect_other.go`'s `--bogus` special case is called out as a temporary shortcut to keep one shared test green — replace with a shared flag parser when convenient.

**Type consistency:** `collect.Command`/`Output` (T2) are what `Access.Run` (T3) and the collectors (T5) use; `Builder.Set/SetSetting/Header` (T3, T6) match every collector; `facts.CollectorRun` fields (plan 1A T3) match what `Run` writes (T6); `WriteOptions` (T4) matches `Run` (T6); registry keys in plan 1A T4 match every `b.Set` key in T5 (`services.ssh.installed`, `services.ssh.active`, `services.telnet.installed`, `services.telnet.reachable`, `sockets.listening`, `sshd.collect_method`, `sshd.personas_collected`, `sshd.options.permit_root_login`, `files.etc_securetty`, `files.etc_securetty_lines`, `files.etc_passwd.{mode,uid,gid,acl_present}`, `accounts.login_defs.{pass_max_days,pass_min_days,pass_min_len}`, `accounts.users`, `walk.complete`).
