# Stage 4A — Release Pipeline and Packages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `v*` tag push builds, scans, signs, attests and publishes Linux binaries, `.deb`/`.rpm` packages, checksums and SBOMs that install the binary and the documents and start nothing; `snapshot ls|rm|prune` close the lifecycle; a CI dry run proves the whole pipeline, reproducibility and the install contract on every PR.

**Architecture:** GoReleaser v2 (assay's configuration as the starting point) drives one `CGO_ENABLED=0 -trimpath` build per architecture into archives and nfpm packages; `release.yml` signs the checksums keyless with cosign and attests provenance; a `release-dry-run` CI job runs the same configuration with `--snapshot`, rebuilds the binary with `scripts/reproduce.sh` and installs the packages in five containers against a committed file list. The lifecycle commands split into a pure selection package (`internal/snapshots`) and a Linux-tagged directory-fd layer in `cmd/muster`, with a lenient header decoder added to `internal/facts`.

**Tech Stack:** Go (`go 1.25` language version; `toolchain` line names the newest patch of a supported line, go1.26.x — RA-17), GoReleaser v2.18.0 exact + nfpm, cosign v2.4.3 (keyless, `--new-bundle-format`), syft via `anchore/sbom-action/download-syft`, govulncheck v1.9.0, GitHub Actions (SHA-pinned), POSIX sh scripts, `golang.org/x/sys/unix`.

**Spec:** `docs/superpowers/specs/2026-11-02-stage4-public-release-design.md` §4 (4A), §7, §8 and the rulings RL-1..RL-18, RL-28..RL-31, RL-39 (Korean pair `…-design.ko.md`). Section numbers below (§4.x) are the spec's.

## Global Constraints

- Nothing in this plan changes a byte of `collect`, `check` or `fix` output or any verdict; the examples gate (`TestExamplesLoadAndCheck`) stays green without an examples refresh. The one accepted change: `run.commit` and `check.commit` carry the full 40-hex commit instead of the short one (both are masked by the examples test).
- Binary dependencies stay `gopkg.in/yaml.v3` and `golang.org/x/sys` (D28). Release tooling runs in CI only, pinned by version; every GitHub Action is pinned by commit SHA with the tag in a trailing comment (RL-31).
- `internal/snapshots` imports none of `os`, `os/exec`, `net`, `syscall` (it may import `time`); `internal/facts` keeps its purity (no `os`). A test enforces each.
- Targets `linux/amd64` and `linux/arm64` only (RL-2). No install script, no `curl | sh`; the release job never pushes to `main` (RL-3).
- The packages install `/usr/bin/muster` and files under `/usr/share/doc/muster/` (and the distribution's licence location) and nothing else; no `preinst`/`postinst`/`prerm`; Debian `postrm` acts on `purge` only; rpm has no scripts (RL-11, RL-13). Package `Maintainer`/`Packager` is exactly `seonggyun.seo <40746364+kun9497@users.noreply.github.com>` (RL-39).
- Exit codes: `ls`/`rm`/`prune` exit 0 or 2 (`exitError`), never `exitRefused`; stdout carries only the listing or the dry-run plan; warnings go to stderr.
- Never a dotted RFC1918/public IPv4 literal or a `.corp/.internal/.intra/.lan/.local/.priv` hostname in a committed file (gitleaks scans the PR range); the sigstore identity URL and `token.actions.githubusercontent.com` match no rule.
- Commits: personal identity, trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, no push from an agent session, no stash/amend/rebase/force. English docs with the `.ko.md` pair in the same commit (plans are English-only); the main design pair stays line-aligned.
- Shell scripts: `#!/bin/sh`, `set -eu`, POSIX, a header comment naming the spec section, shellcheck-clean at the default severity; `make shellcheck` and ci.yml's duplicate loop both enumerate them.
- Out of this plan, by the spec's split: the README Install section and its executable blocks in `release-dry-run` (RL-28, RL-32, RL-33), `tools/docdrift`, `RELEASING.md`, `tools/anonverify` and the rehearsal are 4C; `snapshot diff` is 4B. `release-dry-run` is written here so 4C only adds steps to it.

## Review Focus

Inputs the spec implies but no step below would otherwise exercise; each gets its test in the owning task:

1. **A hostile file name in the snapshot directory** (a newline, `..`, 200 bytes, a name that is only `-2026-…-abcdef012345.json`): `ls` lists or counts it without opening anything but pattern-matching regular files, and the table escapes it (`report.Escape`); `rm` refuses a name containing `/`, a control character or equal to `.`/`..` — Task 4.
2. **`latest` that dangles or points outside the directory** (`latest -> ../../etc/passwd`, `latest -> gone.json`): `ls` shows the target text with `(dangling)`/`(outside)` and never follows it; `rm`/`prune` re-point only by name — Task 4.
3. **`--keep-days` at the boundary**: a snapshot whose `collected_at` is exactly `D*24h` before the clock is not older and is kept; one second more is removed — Task 2.
4. **A file at or over the size cap, or a pattern-matching empty file**: `LoadHeader` applies `MaxSnapshotBytes` and both are `unreadable`, never a crash, never opened twice — Task 2 and Task 3.
5. **A symlinked `/var/lib/muster` at purge**: Debian's `postrm purge` removes the link, not what it points at; an upgrade over a populated `/var/lib/muster` leaves every file — Task 7.

---

### Task 1: `muster version` prints five lines; the Makefile stamps the commit date and the full hash

**Files:**
- Modify: `cmd/muster/main.go:36-46` (usage), `:66-68` (version case)
- Modify: `cmd/muster/main_test.go:9-20`
- Modify: `Makefile:3-7`, `:17`
- Test: `cmd/muster/main_test.go`

**Interfaces:**
- Consumes: `controls.LoadDefault() (*controls.Set, error)` with `Set.Version string` (`internal/controls/load.go`); `facts.SchemaVersion` (`internal/facts/snapshot.go:15`).
- Produces: `version` output contract, five lines in this order: `muster <version>`, `commit <commit>`, `built <date>`, `controls <controls/VERSION>`, `schema <N>`. Task 7's install contract and Task 6's reproduce script read line 1 and line 3.

- [ ] **Step 1: Replace `TestRunVersionPrintsThreeFields` with `TestRunVersionPrintsFiveLines`**

```go
func TestRunVersionPrintsFiveLines(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	set, err := controls.LoadDefault()
	if err != nil { t.Fatal(err) }
	want := []string{
		"muster " + version, "commit " + commit, "built " + date,
		"controls " + set.Version, "schema " + strconv.Itoa(facts.SchemaVersion),
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if !slices.Equal(got, want) { t.Fatalf("got %q\nwant %q", got, want) }
	if errb.Len() != 0 { t.Fatalf("stderr %q", errb.String()) }
}
```

- [ ] **Step 2: Run it and see it fail** — `go test ./cmd/muster -run TestRunVersionPrintsFiveLines` → FAIL (three lines).

- [ ] **Step 3: Implement.** In `main.go`'s `case "version"`: load the set; on error `fmt.Fprintf(stderr, "muster: %v\n", err); return exitError`; print the five lines with one `fmt.Fprintf`. Change the usage line to `  version    print version, commit, commit date, control set and schema versions`.

- [ ] **Step 4: Makefile.** Lines 4–5 become `COMMIT  := $(shell git rev-parse HEAD 2>/dev/null || echo none)` and `DATE    := $(shell TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)` (RA-1: `format-local:` under `TZ=UTC` renders the commit's instant in UTC; plain `format:` renders the committer's own offset with a fake `Z`, and `%cI` prints `+09:00` — neither equals GoReleaser's `{{ .CommitDate }}`, which is `time.Unix(%ct).UTC()` in RFC3339). Line 17 adds `-buildvcs=false` after `-trimpath`. Add a comment above `DATE` saying why the build date is the commit date and why `format-local:`.

- [ ] **Step 5: Run** `go test ./cmd/muster -run 'TestRunVersion|TestFixUsageListed'` → PASS; `make build && ./bin/muster version` (on the lab via `lab-run.sh`, or skip on Windows and rely on Task 6's dry run) prints five lines with a 40-hex commit and a `…Z` date.

- [ ] **Step 6: Commit** — `git commit -m "version: print controls and schema versions; stamp the commit date and full hash (RL-5, RL-15)"`.

---

### Task 2: `facts.LoadHeader` and the pure `internal/snapshots` package

**Files:**
- Create: `internal/snapshots/snapshots.go`, `internal/snapshots/snapshots_test.go`, `internal/snapshots/imports_test.go`
- Modify: `internal/facts/snapshot.go` (add `LoadHeader`), create `internal/facts/header_test.go`, `internal/facts/imports_test.go`
- Modify: `cmd/muster/maxage.go:76-82` (`parseCollectedAt` delegates)

**Interfaces:**
- Produces (package `facts`): `func LoadHeader(r io.Reader) (Header, error)` with `type Header struct { SchemaVersion int; Run Run }` — same size and depth limits as `Load`, decodes only `schema_version` and `run`, does NOT compare the schema version (that is the caller's classification), returns `ErrSchemaMismatch` only for `schema_version < 1`, `ErrTrailingData` as `Load` does.
- Produces (package `snapshots`):
  - `const DefaultDir = "/var/lib/muster/snapshots"`
  - `type Class string` with `ClassOK Class = "ok"`, `ClassNewer Class = "newer"`, `ClassUnreadable Class = "unreadable"`
  - `type Entry struct { Name string; Class Class; Size int64; SchemaVersion int; CollectedAt string; Hostname, MusterVersion, ControlsVersion string; Latest bool }`
  - `func ParseName(name string) (host, stamp string, ok bool)` — `<host>-<YYYY-MM-DDTHHMMSSZ>-<12 lowercase hex>.json`, parsed from the right (the host may contain `-` and `.`), host 0..64 bytes of `[A-Za-z0-9._-]`.
  - `func ParseCollectedAt(s string) (time.Time, error)` — the strict `YYYY-MM-DDTHH:MM:SSZ` round trip moved from `cmd/muster/maxage.go`.
  - `func Classify(name string, size int64, h facts.Header, err error) Entry` — `err != nil` or `h.SchemaVersion < 1` → unreadable; `h.SchemaVersion > facts.SchemaVersion` → newer (header fields kept as written); an ok-range schema whose `CollectedAt` fails `ParseCollectedAt` → unreadable; else ok.
  - `func Sort(entries []Entry)` — newest first: the key is the parsed `CollectedAt` when `ParseCollectedAt` accepts it (every ok row; a newer row whose spelling still parses) and otherwise the name's stamp (unreadable rows; a newer row with an unparseable date — RA-10); ties by the name's stamp, then by name, so the order is total and deterministic.
  - `func Newest(entries []Entry) (Entry, bool)` — the first ok row after `Sort`.
  - `type Bounds struct { Keep, KeepDays int; HasKeep, HasKeepDays bool }`
  - `func Prune(entries []Entry, b Bounds, now time.Time) ([]Entry, error)` — `ErrNoBounds` when neither is set; candidates are ok rows only, excluding `Newest`; with both set, remove rows that are both beyond the newest `Keep` ok rows and older than `now - KeepDays*24h` (strictly older: `collected_at < cutoff`); with one set, that criterion alone; returned in `Sort` order.
  - `func Repoint(remaining []Entry) (target string, ok bool)` — the newest ok row's name, or `false` when none.
- Consumes: `facts.SchemaVersion`, `facts.Run`.

- [ ] **Step 1: `internal/facts/header_test.go`** — `TestLoadHeaderReadsRunAndSchemaWithoutComparing`: a document with `"schema_version": 7` and a `run` block → `Header{SchemaVersion: 7}` with `Run.CollectedAt`, `Run.Host.Hostname`, `Run.MusterVersion` filled and no error; `"schema_version": 0` → `errors.Is(err, ErrSchemaMismatch)`; a body of `MaxSnapshotBytes+1` bytes → `ErrTooLarge`; trailing `x` → `ErrTrailingData`; `{}` → `ErrSchemaMismatch`. `internal/facts/imports_test.go`: `TestFactsPackageHasNoHostImports` copied from `internal/remedy/imports_test.go` (forbid `os`, `os/exec`, `net`, `syscall`).
- [ ] **Step 2: Run** `go test ./internal/facts -run 'TestLoadHeader|TestFactsPackageHasNoHostImports'` → FAIL (undefined `LoadHeader`).
- [ ] **Step 3: Implement `LoadHeader`** next to `Load`, reusing `checkDepth` and `AtEnd`; decode into `struct{ SchemaVersion int \`json:"schema_version"\`; Run Run \`json:"run"\` }`.
- [ ] **Step 4: Run** the two tests → PASS. Run `go test ./internal/facts` whole → PASS (the schema golden is untouched: no field changed).
- [ ] **Step 5: `internal/snapshots/snapshots_test.go`** — table tests:
  - `TestParseName`: `web_01_prod-2026-09-02T060000Z-0123456789ab.json` → (`web_01_prod`, `2026-09-02T060000Z`, true); `-2026-09-02T060000Z-0123456789ab.json` → (``, stamp, true); `a-b-c-2026-09-02T060000Z-0123456789ab.json` → host `a-b-c`; `x-2026-09-02T060000Z-0123456789AB.json` (uppercase hex) → false; `x-2026-09-02T060000Z-0123456789ab.json.bak` → false; `latest`, `.x.tmp-12`, a 300-byte host → false.
  - `TestParseCollectedAt`: `2026-09-02T06:00:00Z` ok; `2026-09-02T06:00:00+00:00`, `2026-09-02T06:00:00.5Z`, `` → error.
  - `TestClassify`: ok header → `ClassOK` with fields; `SchemaVersion: facts.SchemaVersion+1` → `ClassNewer` with `CollectedAt` kept; `err != nil` → `ClassUnreadable` with only `Name`/`Size`; a bad `collected_at` → unreadable.
  - `TestSortIsNewestFirstAndTotal`: three ok rows, one newer, one newer with `collected_at: "2026-09-02T06:00:00+00:00"` (sorted by its name stamp, RA-10), two unreadable (one with a later name stamp than every ok row); assert the exact order and that `Sort` of a shuffled copy gives the same slice; `Newest` returns the newest **ok** row even though the unreadable row's stamp is later.
  - `TestPruneBounds` (Review Focus 3): rows at `now-1d`, `now-3d`, `now-7d` exactly, `now-7d-1s`, `now-30d`; `Bounds{KeepDays: 7, HasKeepDays: true}` removes `now-7d-1s` and `now-30d` only; `Bounds{Keep: 2, HasKeep: true}` removes the three oldest; both set → the intersection; neither → `ErrNoBounds`; a `newer` row and an `unreadable` row older than everything are never in the result; with one ok row and `Keep: 0`, nothing is removed (RL-17).
  - `TestRepoint`: remaining `[newer, ok(old), ok(new), unreadable]` → the newest ok name; `[newer, unreadable]` → `false`.
  - `imports_test.go`: `TestSnapshotsPackageHasNoHostImports` forbidding `os`, `os/exec`, `net`, `syscall`.
- [ ] **Step 6: Run** `go test ./internal/snapshots` → FAIL (package missing).
- [ ] **Step 7: Implement `internal/snapshots/snapshots.go`** with the interfaces above. `ParseName` parses fixed widths from the right (RA-5): strip `.json`; the last 13 bytes are `-` + 12 lowercase hex; the 19 bytes before them are `-DDDD-DD-DDTDDDDDDZ` (digits checked, the `T` and `Z` literal); what remains is the host, 0..64 bytes of `[A-Za-z0-9._-]` (the stamp itself carries two `-`, so a split on `-` cannot work). `Sort` with `slices.SortStableFunc`.
- [ ] **Step 8: `cmd/muster/maxage.go`**: `parseCollectedAt` becomes a one-line call to `snapshots.ParseCollectedAt` (keep the name; `maxage_test.go` unchanged).
- [ ] **Step 9: Run** `go test ./internal/snapshots ./internal/facts ./cmd/muster` → PASS; `gofmt -l .` empty; `go vet ./...` clean.
- [ ] **Step 10: Commit** — `git commit -m "snapshots: pure listing and prune selection; facts.LoadHeader (RL-16, RL-17)"`.

---

### Task 3: `snapshot ls`

**Files:**
- Create: `cmd/muster/snapshotdir_linux.go`, `cmd/muster/snapshotdir_other.go`, `cmd/muster/snapshotls.go`, `cmd/muster/snapshotls_test.go` (untagged: parsing and usage), `cmd/muster/snapshotls_linux_test.go`, `cmd/muster/snapshotls_other_test.go` (`//go:build !linux`; proven on the Windows host only — say so in the report), `cmd/muster/snapshotdir_linux_test.go` (RA-30: build tags are per file)
- Modify: `cmd/muster/snapshot.go:17-62` (usage), `:125-139` (dispatch); `cmd/muster/main.go:42` (usage line); `internal/report/table.go` + `width.go` (export `DisplayWidth` and `PadRight`, RA-29)

**Interfaces:**
- Produces (Linux layer, `snapshotdir_linux.go`, build tag `linux`):
  - `type snapshotDir struct { fd int; path string }`
  - `func openSnapshotDir(path string) (*snapshotDir, error)` — `unix.Open(path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`, then `unix.Fstat(fd)` and RL-18: refuse (`errUntrustedSnapshotDir`, message `<path> is not owned by uid N, or is group- or world-writable`) when `st.Uid != uint32(os.Geteuid())` or `st.Mode&(S_IWGRP|S_IWOTH) != 0`. A symlink at `path` fails the open with `ELOOP`/`ENOTDIR` and is reported as `<path> is a symlink`.
  - `func (d *snapshotDir) list() (entries []snapshots.Entry, other int, latest latestLink, err error)` — `unix.Getdents` names (reuse the shape of `internal/collect/readdir.go:272 readNames`; it is unexported and Linux-only, so copy the loop, do not import), for each name: `unix.Fstatat(d.fd, name, &st, AT_SYMLINK_NOFOLLOW)`; a regular file whose name `snapshots.ParseName` accepts is opened with `unix.Openat(d.fd, name, O_RDONLY|O_NOFOLLOW|O_CLOEXEC)`, identity-checked (`Fstat` dev/ino equal to the `Fstatat` result, else counted as other), read through `io.LimitReader(f, facts.MaxSnapshotBytes+1)` into `facts.LoadHeader`, and classified. One counting rule (RA-6): a symlink named `latest` is reported through `latestLink` and not counted; every other non-entry name — `.*.tmp-*`, directories, other symlinks, a non-symlink `latest` — increments `other` and is never opened.
  - `type latestLink struct { present bool; target string; state string }` — `state` is `ok` (target names an entry in the listing), `dangling` (no such entry), `outside` (target contains `/`); read with `unix.Readlinkat(d.fd, "latest", buf)`; a non-symlink `latest` is `present: false`.
  - `type dirKind int` with `kindAbsent`, `kindRegular`, `kindDir`, `kindSymlink`, `kindOther`; `func (d *snapshotDir) stat(name string) (dirKind, error)` — one `Fstatat … AT_SYMLINK_NOFOLLOW` (Task 4's pre-pass, RA-3).
  - `func (d *snapshotDir) close()`
  - `type dirLock interface{ Release() }` in the untagged `snapshotls.go` (RA-2: `collect.Lock` is Linux-only, so no untagged file may name it).
- Produces (`snapshotls.go`, untagged): `type lsFlags struct { dir, format string }`, `func parseLsArgs(args []string) (lsFlags, error)` (hand-rolled as `parseExtractArgs`; `--dir` default `snapshots.DefaultDir`; `--format` `table|json`, default `table`; an empty value → `flag %s needs a non-empty value`), `func runSnapshotLs(args []string, stdout, stderr io.Writer) int`, `func renderLsTable(w io.Writer, dir string, entries []snapshots.Entry, other int, latest latestLink)`, `func renderLsJSON(w io.Writer, …) error`.
- Produces (`snapshotdir_other.go`, `!linux`): the same `snapshotDir` and `latestLink` types with `openSnapshotDir` returning `errors.New("snapshot ls, rm and prune require Linux")` and `list`/`stat`/`close` stubs, so the untagged `runSnapshotLs` compiles everywhere and prints `muster: <that error>` exit 2 after parsing flags (the `collect_other.go` precedent). Task 4 adds `remove`, `repointLatest` and `lock` stubs here too. The Linux-only symbols of `internal/collect` (`Lock`, `AcquireLock`, `AcquireDirLock`, `ErrLocked`, `LockPath`) are named only in `snapshotdir_linux.go` (`collect_flags.go` already imports the package for its untagged `walkroots.go` symbols, so the import itself is not the constraint).
- Table (byte-exact, `report.Escape` on every file name and target, columns separated by two spaces, no trailing spaces):
  ```
  <dir>  (<N> snapshots, <M> other files; latest -> <target>[ (dangling|outside)]|no latest link)
  NAME  COLLECTED  HOST  MUSTER  CONTROLS  SIZE  CLASS
  <name>  <collected_at>  <hostname>  <muster_version>  <controls_version>  <size>  ok|newer|unreadable[  *]
  ```
  `*` marks the row `latest` points at; unreadable rows print `-` in the four header columns; column widths are the maximum of each column's display widths, measured and padded by the check table's own rule — `report.DisplayWidth` and `report.PadRight`, exported from `internal/report/width.go`/`table.go` in this task (RA-29: East Asian width counts 2; a Hangul hostname is seeded in the determinism test to pin it). The "other files" count sits in the header line (RA-9: the spec's "trailing line" wording is amended in Task 9).
- JSON: `{"dir": "<dir>", "other_files": M, "latest": {"present": bool, "target": "…", "state": "ok|dangling|outside"} | null, "entries": [{"name","class","size","schema_version","collected_at","hostname","muster_version","controls_version","latest"}]}`, keys in that order, entries in `Sort` order, one trailing newline.
- Exit: 0 on a listing (an empty directory is a listing); 2 on a refused or unopenable directory with `muster: <reason>` on stderr and empty stdout.

- [ ] **Step 1: Usage pins** in `snapshotls_test.go`: `TestSnapshotLsUsageListed` asserts `snapshotUsage` contains `muster snapshot ls [--dir <d>] [--format table|json]` and the top-level `usage` contains `list, remove or prune the snapshots muster keeps`; run → FAIL.
- [ ] **Step 2: Update usage texts**: `snapshotUsage` first line `usage: muster snapshot <extract|anonymize|ls|rm|prune> [flags]`, the `anonymizeSynopsis` constant kept on its own synopsis line (`TestSnapshotUsageNamesAnonymize` pins it, RA-13), synopsis lines for the three (rm and prune now, implemented in Task 4), a paragraph per command and their exit codes; `main.go` snapshot line → `  snapshot   cut a fixture, anonymise a snapshot, or list, remove or prune the snapshots muster keeps`. Add the `ls` case to `runSnapshot`. Run `go test ./cmd/muster -run 'TestSnapshotUsage|TestSnapshotLsUsage|TestFixUsageListed'` → PASS.
- [ ] **Step 3: Linux-layer tests** (`snapshotdir_linux_test.go`, build tag `linux`, not root-only — `t.TempDir()` is owned by the test user): `TestOpenSnapshotDirRefusesSymlinkAndWritable` (a symlink to a dir → error mentions `symlink`; `chmod 0770` → error mentions `group- or world-writable`; a plain `0700` dir → ok); `TestListClassifiesAndCountsOthers`: seed with `writeSnapshot(t, …)`-style bodies named by `collect.SnapshotName`'s format — two ok (different `collected_at`), one `schema_version: 99` (newer), one pattern-matching file holding `{` (unreadable), one empty pattern-matching file (unreadable, Review Focus 4), one `.x.tmp-1`, one `notes.txt`, a subdirectory, a `latest` symlink to the newest ok name → entries 5 in `Sort` order, `other == 3`, `latest.state == "ok"`; `TestListLatestDanglingAndOutside` (Review Focus 2): `latest -> gone.json` → `dangling`; `latest -> ../x/y.json` → `outside`; neither is opened (assert no error, the target text is reported verbatim). Run → FAIL (undefined).
- [ ] **Step 4: Implement `snapshotdir_linux.go` and `snapshotdir_other.go`.** The identity check and the LimitReader are in the Interfaces block; nothing else is open.
- [ ] **Step 5: Run** Step 3 tests → PASS (on the lab: `bash C:/Users/ssk/muster-lab/lab-sync.sh <worktree>` then `bash C:/Users/ssk/muster-lab/lab-run.sh 'go test ./cmd/muster -run "TestOpenSnapshotDir|TestList"'`; they also run in CI's `test` job).
- [ ] **Step 6: Command tests** (`snapshotls_linux_test.go` for everything that needs a directory; `snapshotls_test.go` for flag refusals; `snapshotls_other_test.go` for the `!linux` refusal): `TestSnapshotLsTableIsDeterministic` — seed as in Step 3 plus one ok row whose `run.host.hostname` is Hangul (`웹서버01`, RA-29), run `run([]string{"snapshot","ls","--dir",dir})` twice, `bytes.Equal`, and compare the whole output against the literal expected table (write the expected string in the test with the seeded values). Review Focus 1 in the same test: a seeded regular file whose name carries a newline does not match `ParseName`, so it is counted in `other` and never opened (assert `other` in the header line), and a seeded `latest -> "a\nb"` target prints as `a\u000ab` in the header line (`report.Escape`). `TestSnapshotLsJSONShape` decodes with `readJSON` and asserts the key order via a `json.Decoder` token walk and the `entries` length; `TestSnapshotLsRefusals`: a missing directory → exit 2, empty stdout, stderr names it; `--format xml` → exit 2 with usage; `--dir ""` → `flag --dir needs a non-empty value`. Non-Linux: `TestSnapshotLsRequiresLinux` (tag `!linux`) → exit 2, `requires Linux`.
- [ ] **Step 7: Implement `snapshotls.go`** (parse → `openSnapshotDir` → `list` → `snapshots.Sort` → mark `Latest` on the entry whose name equals the link target → render).
- [ ] **Step 8: Run** `go test ./cmd/muster` on Windows (non-Linux tests) and on the lab (`-run 'TestSnapshotLs|TestOpenSnapshotDir|TestList'`) → PASS; `gofmt`, `vet`, `staticcheck` (the scratchpad binary, `GOOS=linux`) clean.
- [ ] **Step 9: Commit** — `git commit -m "snapshot ls: list the snapshot directory through one fd, three row classes (RL-16, RL-18)"`.

---

### Task 4: `snapshot rm` and `snapshot prune`

**Files:**
- Create: `cmd/muster/snapshotrm.go`, `cmd/muster/snapshotrm_test.go` (untagged: parsing), `cmd/muster/snapshotrm_linux_test.go`, `cmd/muster/snapshotrm_other_test.go` (RA-30)
- Modify: `cmd/muster/snapshotdir_linux.go` and `snapshotdir_other.go` (add `remove`, `repointLatest`, `lock`), `cmd/muster/snapshotdir_linux_test.go`, `cmd/muster/snapshot.go` (dispatch `rm`, `prune`)

**Interfaces:**
- Consumes: Task 3's `snapshotDir`, Task 2's `snapshots.Prune`, `snapshots.Repoint`, `snapshots.Newest`; `commandClock()` (`maxage.go`); `collect.AcquireLock(collect.LockPath)` / `collect.AcquireDirLock(dir)` (`internal/collect/writer.go`, Linux-only, imported only from `snapshotdir_linux.go`).
- Produces (Linux layer):
  - `func (d *snapshotDir) remove(name string) error` — `unix.Fstatat(d.fd, name, &st, AT_SYMLINK_NOFOLLOW)`; refuse (`errNotRegular`) unless `S_IFREG`; `unix.Unlinkat(d.fd, name, 0)`.
  - `func (d *snapshotDir) repointLatest(target string) error` — `target == ""`: if `latest` is a symlink (`Fstatat … S_IFLNK`) `Unlinkat(d.fd, "latest", 0)`, else no-op; otherwise `unix.Symlinkat(target, d.fd, ".latest.tmp-<pid>")` (remove a stale tmp first, best effort) then `unix.Renameat(d.fd, tmp, d.fd, "latest")` — the relative bare name, as `collect` writes it.
  - `func (d *snapshotDir) lock() (dirLock, error)` — `collect.AcquireLock(collect.LockPath)` when `d.path` cleaned equals `snapshots.DefaultDir`, else `collect.AcquireDirLock(d.path)`; the Linux file maps `collect.ErrLocked` to the local `errLockHeld` whose text is `another muster holds the lock: <detail>` (RA-2; mirrors `internal/collect/run.go:356-372`); the `!linux` stub returns the requires-Linux error.
  - `func validRmName(name string) bool` — not `.`/`..`/empty, no `/`, no byte < 0x20 or 0x7f (Review Focus 1). `latest` is checked before this, by name, so the spec's message wins (RA-8).
- Produces (`snapshotrm.go`, untagged): `type rmFlags struct { dir string; dryRun bool; names []string }`, `func parseRmArgs(args []string) (rmFlags, error)` (positional names after flags; at least one; a name containing `/` is a full path and must be absolute — `rm` never guesses a directory: it is split into `filepath.Dir` (opened as the snapshot directory under RL-18) and `filepath.Base`; RA-11: every full path must share one directory, and a full path beside a bare name or beside an explicit `--dir` is refused with `rm takes bare names under --dir or full paths of one directory, not both`); `type pruneFlags struct { dir string; dryRun bool; b snapshots.Bounds }`, `func parsePruneArgs(args []string) (pruneFlags, error)` (`--keep N`/`--keep-days D` non-negative integers, `strconv.Atoi`, each at most once; neither given → `prune needs --keep or --keep-days`); `func runSnapshotRm(args []string, stdout, stderr io.Writer) int`; `func runSnapshotPrune(args []string, stdout, stderr io.Writer) int`; `func warnAboveNewest(stderr io.Writer, entries []snapshots.Entry)` — after `Sort`, one line `muster: warning: <name> is <class> and newer than the newest readable snapshot <newest>` per `newer`/`unreadable` row that sorts above `Newest` (names through `report.Escape`; RA-4, spec RL-16's warning — called by `prune` and by `rm`'s re-point, not by `ls`).
- Behaviour: `rm` — open the directory, lock, `list` once, then a pre-pass (RA-3): `latest` → exit 2 `latest is a link; name the snapshot it points at`; a name `validRmName` refuses → exit 2; `stat(name)` over every name — anything but `kindRegular` → exit 2 naming the name and its kind, before anything is removed; `--dry-run` prints `would remove <name>` per name to stdout and exits 0; else `remove` each, then if `latest` pointed at a removed name, `warnAboveNewest`, `repointLatest(snapshots.Repoint(remaining))` and print `muster: latest -> <target>` or `muster: latest link removed` on stderr. `prune` — open, lock, `list`, `nowT := commandClock()` read after the listing, `warnAboveNewest`, `snapshots.Prune(entries, b, nowT)`; `--dry-run` prints `would remove <name>` lines (in `Sort` order); else remove each and re-point as `rm` does. Both print nothing on stdout on success without `--dry-run`. Exit 2 on `ErrNoBounds`, a refused directory, a lock held, or any I/O error (naming the file; files already removed stay removed and the message says `stopped after <k> of <n>`).
- The removable set for `rm`: any `kindRegular` name — a pattern-matching `newer`/`unreadable` row and a non-pattern regular file (`notes.txt`) alike (RL-16's "junk is removed by `rm`"); directories, symlinks and absent names are refused in the pre-pass.

- [ ] **Step 1: Linux-layer tests** (`snapshotdir_linux_test.go`): `TestRemoveUnlinksOnlyRegularFiles` (a file is gone after `remove`; a subdirectory and a symlink → `errNotRegular`, both still present); `TestRepointLatestWritesARelativeLinkAtomically` (`repointLatest("b.json")` → `os.Readlink(dir/latest) == "b.json"`, no `.latest.tmp-*` left; `repointLatest("")` removes a link and leaves a regular file named `latest` alone); `TestLockRefusesASecondHolder` (take `lock()` on a temp dir, a second `lock()` → `errors.Is(err, collect.ErrLocked)`). Run → FAIL.
- [ ] **Step 2: Implement** the three methods and `validRmName`. Run Step 1 → PASS (lab).
- [ ] **Step 3: Command tests** (`snapshotrm_linux_test.go`): seed a directory with ok rows `a`(oldest) `b` `c`(newest), a `newer` row `n` whose `collected_at` is later than `c`'s, an `unreadable` row `u`, `notes.txt`, a subdir `d`, `latest -> c`.
  - `TestRmRemovesByNameAndRepointsLatest`: `rm --dir D c` → exit 0, empty stdout, `c` gone, `latest -> b`, stderr has the RA-4 warning naming `n` and then `muster: latest -> b…`; `rm --dir D n u notes.txt` → all three gone; `rm --dir D d` → exit 2, nothing removed; `rm --dir D c d` → exit 2 and `c` still present (RA-3 pre-pass); `rm --dir D latest` and, after `rm`-ing the link and creating a regular file named `latest`, `rm --dir D latest` → exit 2 `latest is a link; name the snapshot it points at` both times (RA-8); `rm --dir D ../x` and `rm --dir D "a\nb"` → exit 2 (Review Focus 1); `rm /abs/path/to/b.json` (full path) → exit 0; `rm --dir D /abs/path/to/a.json` and `rm /abs/D/a.json /abs/E/b.json` → exit 2 `not both` (RA-11).
  - `TestRmDryRunRemovesNothing`: `--dry-run` prints exactly `would remove <name>\n` per name and the directory listing is unchanged (compare `os.ReadDir` before/after).
  - `TestPruneKeepsTheNewestAndSkipsNewerAndUnreadable`: `pinNow` at `c.collected_at + 1h`; `a` is 40 days old, `b` 10 days, `c` 1 day. `prune --keep-days 7` removes `a` and `b` and keeps `c` (the newest, RL-17), `n`, `u`, `notes.txt`; `latest` still `c`; stderr carries exactly one RA-4 line, naming `n` (`newer`) and `c`. Re-seed: `prune --keep 1` → the same result. Re-seed: `prune --keep 2 --keep-days 7` → removes only `a`. `prune` with neither bound → exit 2 `needs --keep or --keep-days`, nothing removed. With `c` the only ok row, `prune --keep-days 0` → nothing removed, exit 0.
  - `TestPruneRepointsLatestWhenItsTargetGoes`: `latest -> a`, `prune --keep 1` → `latest -> c`.
  - `TestPruneReadsTheClockOnceAfterTheListing` (RA-7, the shape of `TestClockIsReadAfterTheSnapshot` in `maxage_test.go`): the pinned `now` closure counts its calls and, on its first call, writes one more pattern-matching ok snapshot `z` into the directory, 40 days older than the fixed time it returns; `prune --dir D --keep-days 7 --dry-run` → `z` is absent from the `would remove` lines (it did not exist when the listing ran) and `now` was called exactly once. A `prune` that reads the clock before `list` lists `z` and fails the test.
  - `TestRmAndPruneRefuseALockedDirectory`: hold `collect.AcquireDirLock(dir)` in the test, run `prune --dir dir --keep 1` → exit 2 `another muster holds the lock`.
  - Root-only (`os.Geteuid() != 0 → t.Skip`): `TestPruneRefusesADirectoryRootDoesNotOwn` — `os.Chown(dir, 65534, 65534)` then `prune --dir dir --keep 1` → exit 2 `not owned by uid 0`. Non-root inverse: `TestPruneRefusesAGroupWritableDirectory` (`chmod 0770`) → exit 2.
- [ ] **Step 4: Implement `snapshotrm.go`**; add `rm` and `prune` cases in `runSnapshot`.
- [ ] **Step 5: Run** `go test ./cmd/muster` on the lab as the user and as root (`lab-run.sh` runs as root: the root-only test runs; run the non-root half locally on Windows where it is tagged out, so rely on CI's `test` job for it and say so in the report) → PASS; `gofmt`/`vet`/`staticcheck` clean.
- [ ] **Step 6: Delete-the-call check**: comment out the `repointLatest` call in `prune`; `TestPruneRepointsLatestWhenItsTargetGoes` must fail; restore.
- [ ] **Step 7: Commit** — `git commit -m "snapshot rm, prune: remove through the directory fd, keep the newest, re-point latest (RL-17, RL-18)"`.

---

### Task 5: The toolchain line, `check-go-toolchain.sh`, govulncheck in CI

**Files:**
- Modify: `go.mod` (add `toolchain go1.25.N`)
- Create: `scripts/check-go-toolchain.sh`, `scripts/README.md` (one paragraph: what each script is for, all referenced from the spec §4)
- Modify: `.github/workflows/ci.yml` (test job: setup-go `go-version-file`, toolchain step, govulncheck step, shellcheck loop), `.github/workflows/examples.yml`, `.github/workflows/fuzz.yml` (setup-go `go-version-file: go.mod`), `Makefile` (shellcheck target: `scripts/*.sh`)

**Interfaces:**
- Produces: `scripts/check-go-toolchain.sh [--exact] [path/to/go.mod]` — exit 0 when `go env GOVERSION` (suffix after `go`, GOEXPERIMENT suffix stripped) is ≥ (or, with `--exact`, equal to) `go.mod`'s `toolchain goX.Y.Z`; exit 1 with `error: Go <have> is older than go<want>, the toolchain go.mod requires` / `error: Go <have> is not go<want> (--exact)`; exit 1 when `go.mod` names no toolchain line. Task 6 and Task 8 call it.
- `GOVULNCHECK_VERSION=v1.9.0` lives in `scripts/release-vulncheck.sh` (Task 6); this task's CI step uses the same pinned version literal with a comment pointing there.

- [ ] **Step 1: Pick the toolchain** (RA-17). The `go 1.25` directive stays (the language version staticcheck 2025.1.1 checks). The `toolchain` line names the newest **go1.26.x** patch listed at `https://go.dev/dl/?mode=json&include=all` (fetched with `curl -fsSL` into an empty scratchpad directory and read with `python -I`): Go 1.27 is released, so 1.25 receives no more security fixes and RL-4's "raise the line on an advisory" would have nowhere to go; the spec's "go1.25.x" wording is corrected in Task 9. Record the chosen patch in the commit message. Then run `go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...` under that toolchain (`GOTOOLCHAIN=go1.26.N`); if it fails with an export-data error, raise the staticcheck pin in `ci.yml:26` to the newest release that supports Go 1.26 and record that too. Note for the report: the lab's `lab-run.sh` exports `GOTOOLCHAIN=go1.25.5` and is never edited, so lab runs keep building with 1.25.5 (`go 1.25` admits it); the toolchain checks run in CI only.
- [ ] **Step 2: Script test** (a Go test drives the script): `cmd/muster/scripts_test.go` `TestCheckGoToolchainScript` (Linux-tagged; skips when `sh` is absent): writes temp `go.mod` files with `toolchain go1.0.1` (passes, floor), `toolchain go99.0.0` (fails, floor), the running toolchain's exact version (passes with `--exact`), `toolchain go1.0.1` with `--exact` (fails), no toolchain line (fails); runs `sh ../../scripts/check-go-toolchain.sh … <absolute temp go.mod path>` with `exec.Command` and `cmd.Dir` left at the package directory (RA-26: `go env GOVERSION` must run inside the real module — in a temp module naming `go99.0.0`, `go env` itself fails and the case would pass for the wrong reason); the "running toolchain" value comes from `go env GOVERSION` run the same way with any ` X:…` suffix stripped, not from `runtime.Version()`; assert exit codes, the `error:` prefix, and that stdout names the go.mod path read. Run → FAIL (no script).
- [ ] **Step 3: Write the script** (assay's `scripts/check-go-toolchain.sh` as the model: `sort -V` comparison; add `--exact`). Header comment cites spec §4.2 RL-4 and the assay incident (GO-2026-6809) and says: reads the go.mod given by path; runs `go env GOVERSION` where it is invoked.
- [ ] **Step 4: Run** Step 2 → PASS (lab). `shellcheck -s sh scripts/check-go-toolchain.sh` clean.
- [ ] **Step 5: CI.** In `ci.yml` every `actions/setup-go` step: replace `go-version: "1.25.5"` with `go-version-file: go.mod` (keep `check-latest: false`); same in `examples.yml` and `fuzz.yml`. RA-17: `setup-go@v5` ignores the `toolchain` directive (it parses only `^go `), so Task 8's pin for `actions/setup-go` is the newest **v6 or v7** release SHA, where the `toolchain` line is honoured — until Task 8 lands, the `go 1.25` floor plus `GOTOOLCHAIN=auto` still download the named toolchain, so this step is correct either way. In the `test` job after setup-go: `- name: toolchain meets go.mod` / `run: sh scripts/check-go-toolchain.sh`; after `vet`: `- name: govulncheck (source)` / `run: go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`. Extend the shellcheck step (ci.yml:29-50) and `Makefile`'s `shellcheck` target with a fourth loop over `scripts/*.sh` (`[ "$n" -ge 1 ]`).
- [ ] **Step 6: Local gates**: `go build ./...` with the new toolchain (Go downloads it once under `GOTOOLCHAIN=auto`; note in the report if the local Go refuses), `go test ./...`, `make shellcheck` on the lab.
- [ ] **Step 7: Commit** — `git commit -m "ci: name the toolchain in go.mod, hold builds to it, scan sources with govulncheck (RL-4)"`.

---

### Task 6: GoReleaser, packages, reproduce script, the `release-dry-run` job

**Files:**
- Create: `.goreleaser.yaml`, `scripts/release-vulncheck.sh`, `scripts/reproduce.sh`, `ci/release/postrm.sh`, `examples/systemd/muster-collect.service`, `examples/systemd/muster-collect.timer`, `examples/systemd/README.md`
- Modify: `.github/workflows/ci.yml` (new job `release-dry-run`), `Makefile` (`release-dry-run` target; shellcheck loop over `ci/release/*.sh`), `.gitignore` (already ignores `/dist/`; verify)

**Interfaces:**
- Produces: `dist/` layout from `goreleaser release --snapshot --clean --skip=publish,sign`: `dist/metadata.json` (`.version` — `0.0.1-next` while the repository has no tag), `dist/artifacts.json` (rows with `type` ∈ `Binary`, `Archive`, `Linux Package`, `Checksum`, `Metadata`, `SBOM`, plus `name`, `path`, `goarch`; every consumer selects by `type`/`goarch`/`name` and never hard-codes a path), the binaries under GoReleaser's build dirs, `dist/muster_<v>_linux_<arch>.tar.gz`, the packages under their conventional names `muster_<v>-1_<amd64|arm64>.deb` and `muster-<v>-1.<x86_64|aarch64>.rpm` (RA-19: `file_name_template: '{{ .ConventionalFileName }}'`; the spec's §4.4 table is corrected in Task 9), `dist/muster_<v>_checksums.txt`, `dist/*.spdx.json`.
- `scripts/reproduce.sh --ref <git ref> --version <string> [--arch amd64|arm64] <artefact>` — `--version` is the exact `{{ .Version }}` GoReleaser used (`metadata.json` `.version`; a tag release passes `X.Y.Z`), validated only as non-empty without whitespace or quotes (RA-25); `<artefact>` is a `.tar.gz`, `.deb`, `.rpm` or a bare binary. The script: `git worktree add --detach <tmp> <ref>` with `trap 'git worktree remove --force <tmp>' EXIT` (RA-22), `export GOTOOLCHAIN=$(sed -n 's/^toolchain //p' <tmp>/go.mod)` so the named toolchain is selected (downloaded when absent) before `sh scripts/check-go-toolchain.sh --exact <tmp>/go.mod` proves it, then `CGO_ENABLED=0 GOOS=linux GOARCH=<arch> GOFLAGS=-mod=readonly go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=<version> -X main.commit=<full sha of ref> -X main.date=<TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ <ref>>" -o <tmp>/out/muster ./cmd/muster` (RA-1); extracts the artefact's binary (`tar -xzf` → `muster`; `dpkg-deb -x` or `ar x` + `tar` → `usr/bin/muster`; `rpm2cpio | cpio -id` → `usr/bin/muster`; a bare path as is), prints `built   <sha256>` / `artefact <sha256>` and exits 0 only when equal (else 1 with `error: the build does not reproduce the artefact`); exit 2 on usage or a missing tool, naming it.
- `scripts/release-vulncheck.sh <binary>` — assay's, `GOVULNCHECK_VERSION=v1.9.0`, `go run golang.org/x/vuln/cmd/govulncheck@$V -mode=binary "$1"`; header says an unfixable advisory blocks the release until the toolchain moves or a reviewed exception is written here.
- `ci/release/postrm.sh` — Debian `postrm`: `case "$1" in purge) if [ -L /var/lib/muster ]; then rm -f /var/lib/muster; elif [ -d /var/lib/muster ]; then rm -rf --one-file-system /var/lib/muster; fi ;; esac` (Review Focus 5; RA-27: a filesystem mounted at `/var/lib/muster` keeps its content and the mount point stays — RL-13's text gains that sentence in Task 9), nothing else; shellcheck-clean.
- Units: `muster-collect.service` (`[Unit] Description=muster: collect a facts snapshot` / `[Service] Type=oneshot` / `ExecStart=/usr/bin/muster collect` / `Nice=10` / `IOSchedulingClass=idle`), `muster-collect.timer` (`OnCalendar=weekly`, `Persistent=true`, `RandomizedDelaySec=1h`, `[Install] WantedBy=timers.target`); `examples/systemd/README.md` gives the two install commands from RL-12 and says the package does not install them.

`.goreleaser.yaml` (the fields the spec pins; everything else is the builder's):
- `version: 2`, `project_name: muster`, no `before` hooks.
- `metadata: {mod_timestamp: '{{ .CommitTimestamp }}'}` (RA-24).
- `builds[0]`: `id: muster`, `main: ./cmd/muster`, `binary: muster`, `env: [CGO_ENABLED=0]`, `goos: [linux]`, `goarch: [amd64, arm64]`, `mod_timestamp: '{{ .CommitTimestamp }}'`, `flags: [-trimpath, -buildvcs=false]`, `ldflags: ['-s -w -X main.version={{ .Version }} -X main.commit={{ .FullCommit }} -X main.date={{ .CommitDate }}']`, `hooks.post: [{cmd: 'sh scripts/release-vulncheck.sh "{{ .Path }}"', output: true}]`.
- `archives[0]`: `formats: [tar.gz]`, `name_template: '{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}'`, `builds_info: {mtime: '{{ .CommitDate }}'}`, `files: [LICENSE, NOTICE, ATTRIBUTION.md, README.md, README.ko.md, THREAT_MODEL.md, SECURITY.md, CHANGELOG.md, {src: examples/systemd/*, dst: examples/systemd}]` each with `info: {mtime: '{{ .CommitDate }}'}` (RA-24: the archive and package bytes then follow the commit too; the proof the plan commits to remains the binary's bytes — the dry run compares those).
- `nfpms[0]`: `package_name: muster`, `file_name_template: '{{ .ConventionalFileName }}'` (RA-19), `vendor: kun9497`, `homepage: https://github.com/kun9497/muster`, `maintainer: 'seonggyun.seo <40746364+kun9497@users.noreply.github.com>'`, `description: <README's first sentence>`, `license: Apache-2.0`, `formats: [deb, rpm]`, `section: admin`, `priority: optional`, `bindir: /usr/bin`, `release: "1"`, `mtime: '{{ .CommitDate }}'`, `contents:` the document files to `/usr/share/doc/muster/<name>` (type `doc`), the two units + their README to `/usr/share/doc/muster/examples/systemd/`, `LICENSE` additionally to `/usr/share/doc/muster/copyright` for deb (`packager: deb`) and to `/usr/share/licenses/muster/LICENSE` for rpm (`packager: rpm`, type `license`), `overrides.deb.scripts.postremove: ci/release/postrm.sh`, `overrides.rpm.scripts: {}`; `rpm.group: Applications/System`; `rpm.summary` the first sentence.
- `checksum: {name_template: '{{ .ProjectName }}_{{ .Version }}_checksums.txt', algorithm: sha256}`.
- `sboms: [{id: archives, artifacts: archive, documents: ['{{ .ArtifactName }}.spdx.json'], cmd: syft, args: ['$artifact', '--output', 'spdx-json=$document']}, {id: packages, artifacts: package, …the same}]` (RA-14: two entries need distinct `id`s or `goreleaser check` refuses the file).
- `signs[0]: {id: checksums, cmd: cosign, artifacts: checksum, signature: '${artifact}.sigstore.json', args: [sign-blob, --new-bundle-format, --bundle, '${signature}', --yes, '${artifact}']}` (keyless: no `--key`; the job's OIDC token signs; RA-18: cosign v2.4.3's `--bundle` alone writes its legacy JSON — `--new-bundle-format` writes the Sigstore bundle that `.sigstore.json` names and that cosign v3, `gh` and sigstore-go read; RL-9's text gains the format in Task 9).
- `snapshot.version_template: '{{ incpatch .Version }}-next'`, `changelog.disable: true`, `release: {github: {owner: kun9497, name: muster}, draft: false, prerelease: false, mode: replace}` (RL-30).

- [ ] **Step 1: Write the units, their README, `postrm.sh`, `release-vulncheck.sh`** (shellcheck both). Commit separately: `git commit -m "release: example timer units, Debian postrm, release vulncheck script (RL-12, RL-13)"`.
- [ ] **Step 2: `reproduce.sh` tests** — `cmd/muster/scripts_test.go`, Linux (RA-22): `TestReproduceScriptMatchesItsOwnBuild` skips with a reason when `git rev-parse --git-dir` fails (the lab copy has no `.git`) or `git status --porcelain` is non-empty (a dirty tree during TDD would differ from committed HEAD); otherwise it builds its reference binary from its own `git worktree add --detach` of `HEAD` (removed in `t.Cleanup` with `git worktree remove --force`, so the root run of CI's sudo step leaves nothing root-owned under `.git`) with the exact ldflags, the date derived in Go as `time.Unix(ct, 0).UTC().Format("2006-01-02T15:04:05Z")` from `git log -1 --format=%ct` (RA-1: a wrong shell date formula fails here), then runs `sh ../../scripts/reproduce.sh --ref HEAD --version 0.0.0 <that binary>` → exit 0 and stdout has two equal sha256 lines; corrupt one byte of a copy → exit 1 with `does not reproduce`. `TestReproduceScriptDateIsUTC`: a temp repository with one commit made under `GIT_COMMITTER_DATE='2026-01-01T12:00:00+09:00'`; the script's `-X main.date` value (exposed by a `--print-date` flag, or by running the built binary's `version`) is `2026-01-01T03:00:00Z`. Run → FAIL.
- [ ] **Step 3: Write `scripts/reproduce.sh`**; run Step 2 locally where `git` and the toolchain exist; the proof is CI's `test` job (the lab cannot run it: no `.git`, and `lab-run.sh` pins `GOTOOLCHAIN=go1.25.5`).
- [ ] **Step 4: Write `.goreleaser.yaml`.** Run `goreleaser check` where the binary is available; the configuration is otherwise proven by CI's dry run (Step 6) on the branch's first run.
- [ ] **Step 5: `Makefile`**: `release-dry-run:` → `goreleaser release --snapshot --clean --skip=publish,sign` then `sh scripts/reproduce.sh --ref HEAD --version "$$(jq -r .version dist/metadata.json)" "$$(jq -r '.[] | select(.type=="Binary" and .goarch=="amd64") | .path' dist/artifacts.json)"`; add the `ci/release/*.sh` loop to `shellcheck` (and to ci.yml's copy).
- [ ] **Step 6: `release-dry-run` job** in `ci.yml` (`needs: test`, `runs-on: ubuntu-24.04`, `timeout-minutes: 30`): checkout `fetch-depth: 0`; setup-go from `go.mod`; `sh scripts/check-go-toolchain.sh --exact` and `test "$(go env GOVERSION)" = "go$(sed -n 's/^toolchain go//p' go.mod)"` (RA-17: proves the action honoured the line); install syft with `anchore/sbom-action/download-syft` pinned by SHA and an explicit `syft-version:` (RA-21; the action's default is a constant baked per release, so the SHA pins it too — the explicit input makes it visible); `goreleaser/goreleaser-action` pinned by SHA with `version: v2.18.0` exactly (RA-21: the spec pins tooling by version; `~> v2` floats the binary and nfpm's directory rows), then a step `goreleaser --version` for the log; `args: release --snapshot --clean --skip=publish,sign`; the reproduce call of Step 5; `test -e "dist/$(jq -r '.[] | select(.type=="Linux Package" and .goarch=="amd64" and (.name|endswith(".deb"))) | .name' dist/artifacts.json)"` (pins the RA-19 names); for each `dist/*.tar.gz.spdx.json`: `jq -e '(.packages|length) >= 3 and any(.packages[]; .name=="gopkg.in/yaml.v3") and any(.packages[]; .name=="golang.org/x/sys")'` (RA-20); `actions/upload-artifact` (SHA) with a multi-line `path:` — `dist/*.tar.gz`, `dist/*.deb`, `dist/*.rpm`, `dist/*checksums.txt`, `dist/*.spdx.json`, `dist/artifacts.json`, `dist/metadata.json` — `if-no-files-found: error`, named `release-dry-run-${{ github.run_id }}` (RA-15: `@actions/glob` has no brace expansion, and Task 7's separate job reads `artifacts.json`). The job is `pull_request` + `push` like the others.
- [ ] **Step 7: Push nothing; verify locally what can be**: `go test ./cmd/muster -run TestReproduce` (lab), `make shellcheck` (lab), `gofmt`/`vet`. The GoReleaser run is proven on the branch's first CI run after the user pushes — record this in the task report as the one unverified step.
- [ ] **Step 8: Commit** — `git commit -m "release: GoReleaser configuration, packages, reproduce script, release-dry-run job (RL-5, RL-8, RL-11, RL-30)"`.

---

### Task 7: The install contract

**Files:**
- Create: `ci/release/contract.sh`, `ci/release/contract-files.deb.txt`, `ci/release/contract-files.rpm.txt`, `ci/release/expected-exit.sh`
- Modify: `.github/workflows/ci.yml` (`release-dry-run` gains the matrix step or a dependent job `install-contract`)

**Interfaces:**
- `ci/release/expected-exit.sh <report.json>` — prints `2` if any `.results[].status == "ERROR"`, else `1` if any `"FAIL"`, else `0` (`jq`), mirroring `internal/report/exitcode.go` for a report produced with no `--fail-on`/`--allow-error`.
- `ci/release/contract.sh <deb|rpm|tar> <artefact path inside the container> <example snapshot path> <expected exit> <version>` — runs **inside** the container with no package installation and no network (`set -eu`): install (`dpkg -i`, `rpm -U` — RA-28: `rpm -i` refuses an already-installed NEVRA, so `-U` serves both the install and the upgrade step — or `tar -xzf` into `/opt/muster-tar`); assert the installed file list (`dpkg -L muster | sort` / `rpm -ql muster | sort`) equals the committed list exactly (`diff`); the package metadata (RA-23): deb `dpkg-deb -f "$pkg" Maintainer Homepage Section Priority` and rpm `rpm -qp --qf '%{PACKAGER}\n%{URL}\n%{GROUP}\n%{RELEASE}\n' "$pkg"` against literals (the RL-39 string, the repository URL, `admin`/`Applications/System`, `optional`/`1`), and the package version `dpkg-deb -f "$pkg" Version` / `%{VERSION}-%{RELEASE}` equal to `<version>` with `-` rewritten to `~` plus `-1` (nfpm's conventional spelling, e.g. `0.0.1~next-1`) — separately from the binary's own `muster version` line 1, which is `muster <version>` verbatim; that no `muster*` exists under `/etc/systemd/system` or `/usr/lib/systemd/system`; that no process is named muster — `for c in /proc/[0-9]*/comm; do [ "$(cat "$c" 2>/dev/null)" != muster ] || exit 1; done` (RA-32: the bare images lack `procps`; `/proc` is the only route); that `/var/lib/muster` does not exist; that `muster version` has five lines; that `muster check --facts <snapshot> --format json >/dev/null; echo $?` equals the expected exit; upgrade: install the same package again → same assertions; `mkdir -p /var/lib/muster/snapshots && touch /var/lib/muster/snapshots/keep.json`; remove (`dpkg -r` / `rpm -e`) → `/var/lib/muster/snapshots/keep.json` still exists and `/usr/bin/muster` is gone; deb only, purge twice: (a) reinstall, `dpkg -P` with a real `/var/lib/muster` → gone; (b) reinstall, make `/var/lib/muster` a symlink to a seeded directory elsewhere, `dpkg -P` → the link is gone and the target directory and its file survive (Review Focus 5).
- Matrix rows (`strategy.matrix.include`): `{image: ubuntu:22.04, kind: deb}`, `{image: ubuntu:24.04, kind: deb}`, `{image: debian:12, kind: deb}`, `{image: rockylinux/rockylinux:9, kind: rpm}`, `{image: almalinux:9, kind: rpm}`, `{image: ubuntu:24.04, kind: tar}`; each row: `docker run --rm -v "$PWD/dist:/dist:ro" -v "$PWD/ci/release:/ci:ro" -v "$PWD/examples:/ex:ro" <image> sh /ci/contract.sh <kind> /dist/<artefact for amd64> /ex/ubuntu-24.04-vm.json <expected> <version>`, where the artefact name comes from `dist/artifacts.json` (`jq -r '.[] | select(.type=="Linux Package" and .goarch=="amd64" and (.name|endswith(".deb"))) | .name'`, and the `.rpm`/`Archive` forms), the version from `dist/metadata.json`, and the expected exit from `expected-exit.sh examples/ubuntu-24.04-vm-report.json` on the runner.
- The committed file lists are the exact `dpkg -L`/`rpm -ql` output of §4.6's contents (directories included, as the tools print them), so a packaging change must touch the list in the same commit. Two lists, not the spec's one `contract-files.txt` (RA-34: dpkg and rpm print different directory rows and the rpm adds the licence path; the spec's sentence is amended in Task 9).

- [ ] **Step 1: Write the two scripts and the two lists** (derive the lists by reading the §4.6 contents and nfpm's directory conventions; the first CI run corrects them — say so in the report if a line had to move). `shellcheck` both.
- [ ] **Step 2: Local proof**: `sh -n` and shellcheck on both scripts; `sh ci/release/expected-exit.sh examples/ubuntu-24.04-vm-report.json` prints `1` (the committed report has FAIL rows and no ERROR); the container rows are proven by CI on the branch's first run (no hand-built package stands in for GoReleaser's).
- [ ] **Step 3: CI**: add the matrix as a second job `install-contract` (`needs: release-dry-run`, `strategy.fail-fast: false`; `actions/download-artifact` pinned by SHA with `name: release-dry-run-${{ github.run_id }}`, `path: dist` — v4 restores the files directly under `dist/`; then `test -s dist/artifacts.json` before the matrix step) — a separate job so one failing distribution does not hide the others (RA-15).
- [ ] **Step 4: Commit** — `git commit -m "ci: install contract over five images and the tar.gz (RL-11, RL-13)"`.

---

### Task 8: `release.yml`, release notes, the alert, SHA pins and dependabot

**Files:**
- Create: `.github/workflows/release.yml`, `scripts/release-notes.sh`, `ci/release/ops-alert.sh`, `.github/dependabot.yml`, `ci/release/testdata/CHANGELOG.sample.md`
- Modify: `.github/workflows/ci.yml`, `examples.yml`, `fuzz.yml` (SHA pins), `ci.yml` (`release-dry-run`: run `release-notes.sh` against the sample, and assert that `v0.0.0` — a version that will never exist — fails on the real CHANGELOG)

**Interfaces:**
- `scripts/release-notes.sh vX.Y.Z [CHANGELOG.md]` — prints the body of the `## [X.Y.Z] - YYYY-MM-DD` section (from the line after the heading to the line before the next `## `) to stdout; exit 1 with `error: CHANGELOG.md has no section for X.Y.Z` when absent; exit 2 on usage. Also checks the heading's date is `YYYY-MM-DD` shaped.
- `ci/release/ops-alert.sh <workflow> <result> <run url>` — assay's `scripts/ops-alert.sh` pattern: on `failure`, find an open issue titled `release failed` (label `ops`) and update its body with the run URL or create it and pin it; on `success`, close it; `cancelled`/`skipped` → no-op; uses `gh issue` with `GH_TOKEN`.
- `release.yml`: `on: push: tags: ['v*']`; `permissions: {contents: write, id-token: write, attestations: write}`; job `goreleaser`: checkout (`fetch-depth: 0`), `git fetch origin main && git merge-base --is-ancestor "$GITHUB_SHA" origin/main || { echo "tag is not on main"; exit 1; }` (RL-6), setup-go from `go.mod` (v6+ SHA, RA-17), `sh scripts/check-go-toolchain.sh --exact`, cosign installer (`sigstore/cosign-installer` pinned by SHA, `cosign-release: v2.4.3`), syft install (as in Task 6, explicit `syft-version:`), `sh scripts/release-notes.sh "$GITHUB_REF_NAME" > "${{ runner.temp }}/notes.md"`, `goreleaser/goreleaser-action` (SHA) with `version: v2.18.0` and `args: release --clean --release-notes ${{ runner.temp }}/notes.md` (RA-16: the action passes `args` to the binary without a shell, so `$RUNNER_TEMP` would reach GoReleaser literally; only `${{ }}` expressions expand) with `GITHUB_TOKEN`, `actions/attest-build-provenance` (SHA) over `dist/*.tar.gz`, `dist/*.deb`, `dist/*.rpm` (one `subject-path` per line); job `alert` (`needs: [goreleaser]`, `if: always()`, `permissions: {contents: read, issues: write}`) runs `ops-alert.sh release "${{ needs.goreleaser.result }}" "<run url>"`.
- `.github/dependabot.yml`: `version: 2`, one update for `package-ecosystem: github-actions`, `directory: /`, `schedule.interval: monthly`.

- [ ] **Step 1: `release-notes.sh` tests** in `cmd/muster/scripts_test.go` `TestReleaseNotesScript` (Linux): against `ci/release/testdata/CHANGELOG.sample.md` (two sections `[0.2.0] - 2026-12-01`, `[0.1.0] - 2026-11-20`, an `Unreleased` above) `v0.1.0` prints exactly the 0.1.0 body; `v0.3.0` → exit 1 `no section`; `vUnreleased` → exit 1 (RL-14: the `[Unreleased]` heading is never a release); against the real `CHANGELOG.md`, `v0.0.0` → exit 1 (RA-31: `v0.1.0` would turn red the day 4C writes the section). Run → FAIL.
- [ ] **Step 2: Write the script**; Step 1 → PASS; shellcheck clean.
- [ ] **Step 3: Write `ops-alert.sh`** (shellcheck); no test beyond `sh -n` — it needs GitHub.
- [ ] **Step 4: Write `release.yml` and `dependabot.yml`.**
- [ ] **Step 5: SHA pins.** For each action in all four workflows, resolve the newest release tag (`gh api repos/<owner>/<repo>/releases/latest --jq .tag_name`, then `gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha`; a tag object needs one more hop to the commit) and write `uses: owner/repo@<sha> # <tag>`. `actions/setup-go` moves to its newest major (v6 or v7: the `toolchain` directive is honoured there and ignored by v5 — RA-17); the others keep the major in use when the latest release is in it, else move to the latest. Actions: `actions/checkout`, `actions/setup-go`, `actions/upload-artifact`, `actions/download-artifact`, `gitleaks/gitleaks-action`, `goreleaser/goreleaser-action`, `sigstore/cosign-installer`, `anchore/sbom-action` (`download-syft`), `actions/attest-build-provenance`. `goreleaser-action`'s `version:` input is the one tooling version dependabot does not track; its comment says so.
- [ ] **Step 6: Dry-run hook**: in `release-dry-run` add `sh scripts/release-notes.sh v0.1.0 ci/release/testdata/CHANGELOG.sample.md >/dev/null` and `! sh scripts/release-notes.sh v0.0.0 CHANGELOG.md` (proves the failure path on the real file).
- [ ] **Step 7: Validate YAML** (`python -I -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' <file>` for each workflow; gitleaks on the worktree dir with `--no-git`).
- [ ] **Step 8: Commit** — `git commit -m "release: tag-driven release workflow, notes from CHANGELOG, failure alert; pin every action by SHA (RL-3, RL-6, RL-9, RL-10, RL-14, RL-31)"`.

---

### Task 9: Documents (controller)

**Files:**
- Modify: `docs/superpowers/specs/2026-09-02-muster-design.md` + `.ko.md` (line-aligned): §5.9 (the three commands as built), a new `### 7.6 snapshot ls, rm, prune` (exit codes 0/2 and what stdout carries — RA-33: §7.5 is `fix --dry-run`'s and §7's diff line is 4B's), §8 `:424` (`collect` writes one file; `snapshot rm`/`prune` remove files only in the snapshot directory, and the three default-directory commands record their pid in the shared lock file as `collect` does — RA-12), §8 `:428` (replace the stage-4 list with what 4A built: keyless, L2 attestation stated, SBOM, packages that start nothing, reproduce script, no install script), §9 (`version`'s five lines), §10.2 (4A "merged" wording prepared as "(this cycle)" until the merge), §13: D13 closed, new D37 text per the stage-4 spec §8.
- Modify: `docs/superpowers/specs/2026-11-02-stage4-public-release-design.md` + `.ko.md` — the pre-flight corrections, each cited to its RA ruling: RL-5's `%cI` → the `format-local:` expression (RA-1); RL-4 "go1.25.x" → "the newest patch of a supported line" (RA-17); §4.4's package names → the conventional names (RA-19); RL-9 gains "Sigstore bundle (`--new-bundle-format` on cosign v2.4)" (RA-18); RL-13 gains the mounted-filesystem sentence (RA-27); §4.7's one `contract-files.txt` → two lists and "three lines" → five (RA-34); §4.9's "trailing line" for the other-files count → "in the header line" twice (RA-9); RL-16's warning named as `prune`'s and the re-point's (RA-4).
- Modify: `CLAUDE.md` — a "Release (stage 4A)" section: the pipeline in one paragraph, the install contract lists, `reproduce.sh`, the toolchain rule, `snapshot ls|rm|prune` rules (three classes, newest kept, fd + `trustedDir` + ownership, the lock), "never push a tag from an agent session".
- Modify: `THREAT_MODEL.md` (Trust boundary first bullet: `collect` writes one file; `snapshot rm` and `prune` remove snapshots only in a directory the caller owns, through its fd, and share `collect`'s lock file; `## What the snapshot contains…` the directory sentence), `CONTRIBUTING.md` + `.ko.md` (a paragraph on `scripts/`, `ci/release/`, the shellcheck lists and the SHA-pin rule), `CHANGELOG.md` (Unreleased: Added `snapshot ls|rm|prune`, `version` lines; Tooling: the pipeline; RA-33: lines 11–943 — the Unreleased body — and the `## Stage 1 (2026-09-03)` section both move under a new `## History before 0.1.0` heading per RL-29; the `[Unreleased]` heading stays at the top holding only the new entries), `README.md` + `.ko.md` only where a sentence is now false (the status block's stage list is 4C's job; leave it).
- Modify: this plan — Execution notes (rulings `RA-1..`) at the end.

- [ ] **Step 1: Apply the edits**; keep the main design pair line counts equal (`wc -l` both).
- [ ] **Step 2: Gates**: `go run ./tools/coverage -check` (README roadmap sentence untouched), `go test ./...`, `gofmt`, `vet`, `staticcheck`, `make shellcheck` (lab), gitleaks over `main..HEAD`.
- [ ] **Step 3: Commit** — `git commit -m "docs: stage 4A — lifecycle commands, release pipeline, D37; CHANGELOG history heading (RL-29)"`.

---

### Task 10: Whole-branch review and the first CI run

- [ ] **Step 1:** Whole-branch review as an ultracode workflow (fresh finders by area: lifecycle commands and RL-18; GoReleaser/packages/scripts; CI workflows and pins; docs — each with refuters), fix wave, re-review, as in 3D-3.
- [ ] **Step 2:** On the user's word: push, open the PR (body per the 3D-1b/3D-3 shape, ending with the Claude Code line). The first CI run proves GoReleaser, the install contract lists and the SHA pins; fix what it finds in follow-up commits (never a force push). Run `examples.yml` on the branch; no example should change (the `commit` field is masked).
- [ ] **Step 3:** On the user's word: merge; delete the plan; record lessons.

## Execution notes

Pre-flight (2026-11-02, a workflow of three fresh finders by lens and one refuter each; 48 findings, 47 survived, 4 Blocking) folded as rulings:

- **RA-1** The commit-date stamp is `TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ` in the Makefile and `reproduce.sh`; `format:` renders the committer's offset with a false `Z` and `%cI` prints `+09:00`; only `format-local:` under `TZ=UTC` equals GoReleaser's `{{ .CommitDate }}` (verified: identical binary hashes). The reproduce test derives its reference date in Go from `%ct`. Spec RL-5 is corrected in Task 9.
- **RA-2** `lock()` returns a local `dirLock interface{ Release() }`; `collect.Lock`/`ErrLocked` are Linux-only and named only in `snapshotdir_linux.go`.
- **RA-3** `rm` runs a `stat` pre-pass over every name before the first `remove`, so a refusal removes nothing.
- **RA-4** The spec's RL-16 warning (a `newer`/`unreadable` row above the newest ok snapshot) is printed by `prune` and by `rm`'s re-point, not by `ls`.
- **RA-5** `ParseName` parses fixed widths from the right (the stamp carries two `-`).
- **RA-6** A `latest` symlink is reported through `latestLink` and not counted in `other`; every other non-entry name is.
- **RA-7** The clock-order test makes `now` create a file the listing must not have seen.
- **RA-8** `latest` is refused by name before `validRmName`, so the spec's message is the one printed.
- **RA-9** The other-files count sits in `ls`'s header line; the spec's "trailing line" wording is amended.
- **RA-10** A `newer` row whose `collected_at` does not parse sorts by its name stamp.
- **RA-11** `rm` refuses mixing bare names, full paths of different directories, or `--dir` with a full path.
- **RA-12** The docs say the default-directory commands record their pid in the shared lock file, as `collect` does.
- **RA-13** The usage rewrite keeps `anonymizeSynopsis` on its own line.
- **RA-14** Two `sboms` entries carry distinct `id`s (`goreleaser check` refuses duplicates).
- **RA-15** `install-contract` is a separate job; the dry run uploads a multi-line `path:` list including `artifacts.json` and `metadata.json` (no brace globs in `@actions/glob`).
- **RA-16** `goreleaser-action`'s `args` take `${{ runner.temp }}`, never `$RUNNER_TEMP`.
- **RA-17** The `toolchain` line names the newest patch of a supported line (go1.26.x), the `go 1.25` directive stays; `actions/setup-go` moves to v6+ (v5 ignores `toolchain`); the dry run asserts `go env GOVERSION` equals the line; staticcheck's pin is raised only if 2025.1.1 fails under the toolchain. Spec RL-4's "1.25.x" is corrected.
- **RA-18** cosign v2.4.3 with `--new-bundle-format`: the `.sigstore.json` is a Sigstore bundle; RL-9's text names the format.
- **RA-19** `nfpms.file_name_template: '{{ .ConventionalFileName }}'`; packages are `muster_X.Y.Z-1_<amd64|arm64>.deb` and `muster-X.Y.Z-1.<x86_64|aarch64>.rpm`; spec §4.4 corrected; every consumer reads `artifacts.json`.
- **RA-20** The dry run asserts each archive SBOM lists ≥ 3 packages including the two modules.
- **RA-21** GoReleaser is pinned `version: v2.18.0` (exact) in both workflows; syft's version is explicit.
- **RA-22** `reproduce.sh` uses `git worktree add --detach` with an `EXIT` trap and exports `GOTOOLCHAIN` from the ref's `go.mod`; its test skips on no `.git` or a dirty tree, builds its reference from a worktree too, and cleans up; the proof is CI's `test` job, not the lab.
- **RA-23** The install contract asserts the package metadata fields and the package version (`~` form) separately from the binary's.
- **RA-24** `mod_timestamp`, archive `builds_info.mtime`, file `info.mtime` and nfpm `mtime` follow the commit; the committed proof stays the binary's bytes.
- **RA-25** `reproduce.sh --version` is the verbatim `{{ .Version }}` string.
- **RA-26** The toolchain-script test keeps `cmd.Dir` in the real module and passes the temp `go.mod` by absolute path.
- **RA-27** Debian `postrm purge` uses `rm -rf --one-file-system`; RL-13 says a mounted `/var/lib/muster` is left to the operator.
- **RA-28** `rpm -U` for install and upgrade.
- **RA-29** `report.DisplayWidth`/`report.PadRight` are exported and used by the `ls` table; a Hangul hostname pins the rule.
- **RA-30** Test files are split per build tag (`_test.go`, `_linux_test.go`, `_other_test.go`); the `!linux` files are proven on the Windows host only.
- **RA-31** The release-notes test uses `v0.0.0` against the real CHANGELOG and guards `vUnreleased`.
- **RA-32** The contract's process check reads `/proc/[0-9]*/comm`; the containers install nothing.
- **RA-33** The lifecycle exit codes get `### 7.6` in the main design; the Stage 1 section joins the history heading.
- **RA-34** Two contract file lists; spec §4.7's sentence and "three lines" → five are corrected.

(rulings RA-35.. are appended here during execution)
