//go:build linux

package collect

import (
	"context"
	"os"
	"path/filepath"
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
	// R61: no shared paths in tests — LD_PRELOAD points under t.TempDir(),
	// never /tmp/evil.so. The assertion is unchanged: the child's
	// environment contains no LD_PRELOAD and exactly the fixed variables.
	t.Setenv("LD_PRELOAD", filepath.Join(t.TempDir(), "evil.so"))
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
