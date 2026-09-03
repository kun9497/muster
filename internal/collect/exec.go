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
		if cmd.Process == nil {
			// The deadline (or an already-cancelled parent context) had
			// already expired before the process could be started, so
			// nothing ever ran: report it as the start failure it is,
			// per the Output doc ("Err is set only when the command could
			// not be started at all"). A real mid-run timeout still
			// leaves Err nil here — the process did start.
			o.Err = err
		}
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
