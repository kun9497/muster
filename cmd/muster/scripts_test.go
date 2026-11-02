//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const toolchainScript = "../../scripts/check-go-toolchain.sh"

// runningGoVersion is what the script compares against: `go env GOVERSION`
// run in this package's directory (inside the real module, RA-26), the "go"
// prefix and any " X:…" GOEXPERIMENT suffix removed. runtime.Version() names
// the toolchain that built the test binary, which need not be the one the
// script finds on PATH.
func runningGoVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		t.Fatalf("go env GOVERSION: %v", err)
	}
	v := strings.TrimSpace(string(out))
	if i := strings.IndexAny(v, " -"); i >= 0 {
		v = v[:i]
	}
	if !strings.HasPrefix(v, "go") || len(v) == 2 {
		t.Fatalf("go env GOVERSION = %q, want go<version>", out)
	}
	return strings.TrimPrefix(v, "go")
}

// TestCheckGoToolchainScript drives scripts/check-go-toolchain.sh (RL-4)
// with temp go.mod files named by absolute path, from the package directory
// so `go env GOVERSION` runs inside the real module (RA-26).
func TestCheckGoToolchainScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	have := runningGoVersion(t)
	cases := []struct {
		name      string
		toolchain string // "" writes no toolchain line
		exact     bool
		wantExit  int
		wantErr   string // a substring of stderr after "error: "
		errPath   bool   // stderr also names the go.mod read
	}{
		{name: "floor below", toolchain: "go1.0.1", wantExit: 0},
		{name: "floor above", toolchain: "go99.0.0", wantExit: 1, wantErr: "Go " + have + " is older than go99.0.0, the toolchain ", errPath: true},
		{name: "exact running", toolchain: "go" + have, exact: true, wantExit: 0},
		{name: "exact other", toolchain: "go1.0.1", exact: true, wantExit: 1, wantErr: "Go " + have + " is not go1.0.1 (--exact)"},
		{name: "no toolchain line", toolchain: "", wantExit: 1, wantErr: " names no toolchain line", errPath: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := "module example.com/m\n\ngo 1.21\n"
			if c.toolchain != "" {
				body += "\ntoolchain " + c.toolchain + "\n"
			}
			mod := filepath.Join(t.TempDir(), "go.mod")
			if err := os.WriteFile(mod, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			args := []string{toolchainScript}
			if c.exact {
				args = append(args, "--exact")
			}
			args = append(args, mod)
			cmd := exec.Command("sh", args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("run: %v", err)
			}
			if code != c.wantExit {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.wantExit, stdout.String(), stderr.String())
			}
			if c.wantExit == 0 {
				if stderr.Len() != 0 {
					t.Errorf("stderr on success: %q", stderr.String())
				}
				if !strings.Contains(stdout.String(), mod) {
					t.Errorf("stdout %q does not name the go.mod read (%s)", stdout.String(), mod)
				}
				return
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout on failure: %q", stdout.String())
			}
			msg := stderr.String()
			if !strings.HasPrefix(msg, "error: ") {
				t.Fatalf("stderr %q lacks the error: prefix", msg)
			}
			if !strings.Contains(msg, c.wantErr) {
				t.Errorf("stderr %q does not contain %q", msg, c.wantErr)
			}
			if c.errPath && !strings.Contains(msg, mod) {
				t.Errorf("stderr %q does not name the go.mod read (%s)", msg, mod)
			}
		})
	}
}

const reproduceScript = "../../scripts/reproduce.sh"

// runScript runs sh with args in dir (the package directory when dir is
// "") under env appended to the process environment, and returns the exit
// code with both streams. Any failure to start the shell fails the test.
func runScript(t *testing.T, dir string, env []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("sh", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return ee.ExitCode(), stdout.String(), stderr.String()
	case err != nil:
		t.Fatalf("run sh %v: %v", args, err)
	}
	return 0, stdout.String(), stderr.String()
}

// gitOut runs git in dir and returns its trimmed stdout, failing the test on
// an error.
func gitOut(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("git %v: %v\n%s", args, err, ee.Stderr)
		}
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// requireCleanCheckout skips the test unless the package directory is inside
// a git checkout whose tree matches HEAD: the lab's copy has no .git, and a
// dirty tree during development would not be the commit the script builds.
func requireCleanCheckout(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"sh", "git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	if err := exec.Command("git", "rev-parse", "--git-dir").Run(); err != nil {
		t.Skipf("not a git checkout (git rev-parse --git-dir: %v); reproduce.sh builds a git ref", err)
	}
	out, err := exec.Command("git", "--no-optional-locks", "status", "--porcelain").Output()
	if err != nil {
		t.Skipf("git status --porcelain: %v", err)
	}
	if len(bytes.TrimSpace(out)) != 0 {
		t.Skip("the working tree differs from HEAD; reproduce.sh builds the committed HEAD")
	}
}

// TestReproduceScriptMatchesItsOwnBuild builds a reference binary of HEAD the
// way GoReleaser does (RA-1: the ldflags of .goreleaser.yaml, the commit date
// in UTC computed here in Go, not by the script's shell formula) and requires
// scripts/reproduce.sh to rebuild the same bytes; a copy with one byte changed
// must not reproduce (RA-22).
func TestReproduceScriptMatchesItsOwnBuild(t *testing.T) {
	requireCleanCheckout(t)
	sha := gitOut(t, "", nil, "rev-parse", "HEAD")
	ct, err := strconv.ParseInt(gitOut(t, "", nil, "log", "-1", "--format=%ct", sha), 10, 64)
	if err != nil {
		t.Fatalf("commit time: %v", err)
	}
	date := time.Unix(ct, 0).UTC().Format("2006-01-02T15:04:05Z")

	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	gitOut(t, "", nil, "worktree", "add", "--detach", src, sha)
	t.Cleanup(func() {
		// Removed with git so a root run (CI's sudo step) leaves nothing
		// root-owned under .git/worktrees.
		if out, err := exec.Command("git", "worktree", "remove", "--force", src).CombinedOutput(); err != nil {
			t.Errorf("git worktree remove: %v\n%s", err, out)
		}
	})
	mod, err := os.ReadFile(filepath.Join(src, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var toolchain string
	for _, line := range strings.Split(string(mod), "\n") {
		if v, ok := strings.CutPrefix(line, "toolchain "); ok {
			toolchain = strings.TrimSpace(v)
			break
		}
	}
	if toolchain == "" {
		t.Fatal("go.mod names no toolchain line")
	}
	ref := filepath.Join(tmp, "muster")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X main.version=0.0.0 -X main.commit="+sha+" -X main.date="+date,
		"-o", ref, "./cmd/muster")
	build.Dir = src
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1",
		"GOFLAGS=-mod=readonly", "GOTOOLCHAIN="+toolchain)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("reference build: %v\n%s", err, out)
	}

	code, stdout, stderr := runScript(t, "", nil, reproduceScript, "--ref", "HEAD", "--version", "0.0.0", ref)
	if code != 0 {
		t.Fatalf("reproduce.sh exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdout has %d lines, want 2: %q", len(lines), stdout)
	}
	built, okB := strings.CutPrefix(lines[0], "built   ")
	art, okA := strings.CutPrefix(lines[1], "artefact ")
	if !okB || !okA || len(built) != 64 || built != art {
		t.Fatalf("stdout %q is not two equal sha256 lines", stdout)
	}

	data, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xff
	bad := filepath.Join(tmp, "muster-corrupt")
	if err := os.WriteFile(bad, data, 0o755); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runScript(t, "", nil, reproduceScript, "--ref", "HEAD", "--version", "0.0.0", bad)
	if code != 1 {
		t.Fatalf("reproduce.sh on a corrupt copy: exit %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "error: the build does not reproduce the artefact") {
		t.Errorf("stderr %q does not say the build does not reproduce", stderr)
	}
}

// TestReproduceScriptDateIsUTC pins the -X main.date formula (RA-1): a
// commit made at 12:00 +09:00 reads 03:00 UTC whatever the caller's TZ; plain
// `--date=format:` would print the committer's 12:00 behind a false Z.
func TestReproduceScriptDateIsUTC(t *testing.T) {
	for _, tool := range []string{"sh", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	script, err := filepath.Abs(reproduceScript)
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	env := []string{
		"GIT_AUTHOR_NAME=muster test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=muster test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_AUTHOR_DATE=2026-01-01T12:00:00+09:00", "GIT_COMMITTER_DATE=2026-01-01T12:00:00+09:00",
	}
	gitOut(t, repo, env, "init", "-q")
	gitOut(t, repo, env, "commit", "-q", "--allow-empty", "-m", "one")
	code, stdout, stderr := runScript(t, repo, []string{"TZ=KST-9"}, script, "--print-date", "--ref", "HEAD")
	if code != 0 {
		t.Fatalf("reproduce.sh --print-date: exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if got, want := strings.TrimSpace(stdout), "2026-01-01T03:00:00Z"; got != want {
		t.Errorf("date = %q, want %q", got, want)
	}
}

// TestReproduceScriptUsage: a malformed call exits 2 with its message on
// stderr and builds nothing (RA-25: --version is only non-empty, without
// whitespace or quotes).
func TestReproduceScriptUsage(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"no artefact", []string{"--ref", "HEAD", "--version", "1.0.0"}},
		{"no ref", []string{"--version", "1.0.0", "muster"}},
		{"no version", []string{"--ref", "HEAD", "muster"}},
		{"empty version", []string{"--ref", "HEAD", "--version", "", "muster"}},
		{"version with a space", []string{"--ref", "HEAD", "--version", "1.0 0", "muster"}},
		{"version with a quote", []string{"--ref", "HEAD", "--version", "1.0'0", "muster"}},
		{"unknown arch", []string{"--ref", "HEAD", "--version", "1.0.0", "--arch", "386", "muster"}},
		{"unknown option", []string{"--ref", "HEAD", "--version", "1.0.0", "--bogus", "muster"}},
		{"two artefacts", []string{"--ref", "HEAD", "--version", "1.0.0", "a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runScript(t, "", nil, append([]string{reproduceScript}, c.args...)...)
			if code != 2 {
				t.Fatalf("exit %d, want 2\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout %q on a usage error", stdout)
			}
			if !strings.HasPrefix(stderr, "usage: ") && !strings.HasPrefix(stderr, "error: ") {
				t.Errorf("stderr %q is not the script's usage: or error: line", stderr)
			}
		})
	}
}

const releaseNotesScript = "../../scripts/release-notes.sh"

// sampleNotes010 is the body of the sample's [0.1.0] section: every line from
// the one after its heading to the one before the next "## " heading.
const sampleNotes010 = `
The first release.

### Added
- ` + "`muster check` and `muster collect`" + `.

### Controls
- 117 controls.

`

// TestReleaseNotesScript drives scripts/release-notes.sh (RL-14): a
// version's section is printed byte for byte, a missing one, the
// [Unreleased] heading and a malformed date fail the release, and the real
// CHANGELOG.md fails for a version that will never exist (RA-31).
func TestReleaseNotesScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	const sample = "../../ci/release/testdata/CHANGELOG.sample.md"
	badDate := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(badDate, []byte("# Changelog\n\n## [0.1.0] - 2026-11\n\nText.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		args     []string
		wantExit int
		wantOut  string // exact stdout when wantExit is 0
		wantErr  string // a substring of stderr otherwise
	}{
		{name: "section", args: []string{"v0.1.0", sample}, wantOut: sampleNotes010},
		{name: "no section", args: []string{"v0.3.0", sample}, wantExit: 1, wantErr: "has no section for 0.3.0"},
		{name: "unreleased is never a release", args: []string{"vUnreleased", sample}, wantExit: 1, wantErr: "error: "},
		{name: "date not YYYY-MM-DD", args: []string{"v0.1.0", badDate}, wantExit: 1, wantErr: "YYYY-MM-DD"},
		{name: "real changelog, never a version", args: []string{"v0.0.0", "../../CHANGELOG.md"}, wantExit: 1, wantErr: "has no section for 0.0.0"},
		{name: "no arguments", args: nil, wantExit: 2, wantErr: "usage: "},
		{name: "no v prefix", args: []string{"0.1.0", sample}, wantExit: 2, wantErr: "usage: "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runScript(t, "", nil, append([]string{releaseNotesScript}, c.args...)...)
			if code != c.wantExit {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, c.wantExit, stdout, stderr)
			}
			if c.wantExit == 0 {
				if stdout != c.wantOut {
					t.Errorf("stdout = %q, want %q", stdout, c.wantOut)
				}
				if stderr != "" {
					t.Errorf("stderr on success: %q", stderr)
				}
				return
			}
			if stdout != "" {
				t.Errorf("stdout on failure: %q", stdout)
			}
			if !strings.Contains(stderr, c.wantErr) {
				t.Errorf("stderr %q does not contain %q", stderr, c.wantErr)
			}
		})
	}
}
