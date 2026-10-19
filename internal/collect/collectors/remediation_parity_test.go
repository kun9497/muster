//go:build linux

package collectors

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
)

// The reader parity test (3D-2d §3.10, O-10, O-21, O-28): a review-script body
// that gates on a value read from a file defines its reader as a one-line
// shell function rd_<what>() { LC_ALL=C <command>; }, and the reader must
// agree with the collector's parser over the same bytes, or the body would
// leave a line the check still judges (a block "done" that check still
// FAILs) or rewrite one it does not. The tests here extract the reader from
// the shipped body, run it with sh over each row's file and compare with the
// Go parser the collector calls.

// shippedBody returns the shipped remediation of the control id, failing the
// test when the control or its script is missing.
func shippedBody(t *testing.T, id string) *controls.Remediation {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := set.ByID(id)
	if !ok || c.Remediation == nil || strings.TrimSpace(c.Remediation.Script) == "" {
		t.Fatalf("no shipped script for %s", id)
	}
	return c.Remediation
}

var firstSingleQuoted = regexp.MustCompile(`'[^']*'`)

// readerLine returns the one line of r.Script that defines the reader
// function name (O-21: `^\s*<name>\(\) \{.*\}$`), failing the test when there
// is none or more than one, or when the function's command does not start
// with LC_ALL=C (O-47: the locale is the reader's own, not the caller's).
// With inValidate, the function's first single-quoted string (its awk
// program or grep/sed pattern) must appear verbatim in r.Validate, and the
// validate must set LC_ALL=C too: the validate runs in its own subshell and
// cannot call the body's function, so it repeats the program.
func readerLine(t *testing.T, r *controls.Remediation, name string, inValidate bool) string {
	t.Helper()
	def := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(name) + `\(\) \{(.*)\}$`)
	var found []string
	var command string
	for _, l := range strings.Split(r.Script, "\n") {
		if m := def.FindStringSubmatch(l); m != nil {
			found = append(found, strings.TrimSpace(l))
			command = strings.TrimSpace(m[1])
		}
	}
	if len(found) != 1 {
		t.Fatalf("the script defines %s() on %d lines, want one:\n%s", name, len(found), r.Script)
	}
	if !strings.HasPrefix(command, "LC_ALL=C ") {
		t.Fatalf("%s's command %q does not start with LC_ALL=C", name, command)
	}
	if inValidate {
		prog := firstSingleQuoted.FindString(command)
		if prog == "" {
			t.Fatalf("%s's command %q carries no single-quoted program", name, command)
		}
		if !strings.Contains(r.Validate, prog) {
			t.Fatalf("the validate does not repeat %s's program %s verbatim:\n%s", name, prog, r.Validate)
		}
		if !strings.Contains(r.Validate, "LC_ALL=C ") {
			t.Fatalf("the validate repeats %s's program without LC_ALL=C:\n%s", name, r.Validate)
		}
	}
	return found[0]
}

// runReader writes each of files (keyed by absolute host path) under a fresh
// temporary root, substitutes {root} in call and in every file's content,
// and runs fn and then call with `sh -c` (no -e, no locale forced: the
// reader carries its own LC_ALL=C). It returns stdout without its trailing
// newlines and the exit code; a non-zero exit is data (a reader that
// compares by exit code), never a test failure.
func runReader(t *testing.T, fn, call string, files map[string][]byte) (stdout string, code int) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root := t.TempDir()
	for p, data := range files {
		if !filepath.IsAbs(p) {
			t.Fatalf("runReader: %q is not an absolute host path", p)
		}
		f := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(strings.ReplaceAll(string(data), "{root}", root)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", fn+"\n"+strings.ReplaceAll(call, "{root}", root))
	cmd.Dir = root
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("sh: %v", err)
	}
	if errb.Len() > 0 {
		t.Logf("%s: stderr %q", call, errb.String())
	}
	return strings.TrimRight(out.String(), "\n"), code
}

// TestRhostsReaderMatchesTheCollector (§4.5): rd_plus counts the lines of
// /etc/hosts.equiv the body comments out, and that count is the number of
// hostsEquivLines entries the control's clause (`matches "^\+"`) judges, so
// the body leaves no "+" line check still sees and the validate agrees with
// check after it ran.
func TestRhostsReaderMatchesTheCollector(t *testing.T) {
	r := shippedBody(t, "muster.file.rhosts_forbidden")
	fn := readerLine(t, r, "rd_plus", true)
	plus := regexp.MustCompile(`^\+`)
	for _, row := range []struct{ name, file string }{
		{"bare", "+\n"},
		{"indented netgroup", "  +@ops\n"},
		{"comment", "#+x\n"},
		{"indented comment", "  # +x\n"},
		{"host", "host\n"},
		{"tab", "\t+h\n"},
		{"minus", "-host\n+-@ops\n"},
		{"crlf", "+\r\nhost\r\n"},
		{"no final newline", "host\n+host-b"},
		{"empty", ""},
		{"mixed", "+\n  +@ops\nhost-a\n# c\n+host-b\n"},
		{"after the body", "# muster: +\n# muster:   +@ops\nhost-a\n# c\n# muster: +host-b\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			want := 0
			for _, l := range hostsEquivLines([]byte(row.file)) {
				if plus.MatchString(l.(string)) {
					want++
				}
			}
			got, code := runReader(t, fn, "rd_plus {root}/etc/hosts.equiv", map[string][]byte{"/etc/hosts.equiv": []byte(row.file)})
			if code != 0 || got != strconv.Itoa(want) {
				t.Errorf("rd_plus over %q printed %q (exit %d), the collector judges %d \"+\" lines", row.file, got, code, want)
			}
		})
	}
}
