//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
