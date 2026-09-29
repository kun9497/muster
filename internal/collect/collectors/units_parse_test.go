package collectors

import (
	"os"
	"reflect"
	"testing"
)

// P-4: the unit-file grammar. Pure Go, run on every platform; the
// collector's leaves are tested in units_test.go.

// V-4: every prefix of systemd.service(5) is stripped, quotes are removed,
// and only an absolute path without a specifier is resolved.
func TestExecFirstToken(t *testing.T) {
	for _, c := range []struct {
		line     string
		path     string
		resolved bool
	}{
		{"@/usr/bin/x argv0", "/usr/bin/x", true},
		{"-/bin/true", "/bin/true", true},
		{"+:/bin/sh -c x", "/bin/sh", true},
		{"!:/bin/sh", "/bin/sh", true},
		{"!!/bin/a", "/bin/a", true},
		{"|/bin/b", "/bin/b", true},
		{"-@|/bin/c x", "/bin/c", true},
		{`"/opt/my app/run" arg`, "/opt/my app/run", true},
		{`'/opt/q/run'`, "/opt/q/run", true},
		{`/opt/sp\sace/run`, "/opt/sp ace/run", true},
		{"/usr/sbin/sshd -D $SSHD_OPTS", "/usr/sbin/sshd", true},
		{"sshd -D", "sshd", false},
		{"/usr/lib/getty/%I-prepare", "/usr/lib/getty/%I-prepare", false},
		{"$BIN arg", "$BIN", false},
		{"/usr/bin/../bin/x", "/usr/bin/../bin/x", false},
		{`"/opt/unterminated`, "/opt/unterminated", false},
		{`"/opt/a"b`, "/opt/a", false},
		{"", "", false},
		{"-", "", false},
	} {
		p, ok := execFirstToken(c.line)
		if p != c.path || ok != c.resolved {
			t.Errorf("execFirstToken(%q) = %q, %v; want %q, %v", c.line, p, ok, c.path, c.resolved)
		}
	}
}

// Only [Service] is read, continuation lines join, comments inside a
// continuation are skipped, and an empty assignment leaves the reset marker.
func TestParseUnitFile(t *testing.T) {
	data, err := os.ReadFile("testdata/units/ssh.service")
	if err != nil {
		t.Fatal(err)
	}
	u := parseUnitFile(data)
	want := map[string][]string{
		"ExecStartPre": {"/usr/sbin/sshd -t"},
		"ExecStart":    {"/usr/sbin/sshd -D $SSHD_OPTS"},
		"ExecReload":   {"/usr/sbin/sshd -t", "/bin/kill -HUP $MAINPID"},
	}
	if !reflect.DeepEqual(u.Exec, want) || u.User != nil {
		t.Errorf("ssh.service: exec %v user %v", u.Exec, u.User)
	}

	u = parseUnitFile([]byte("[Unit]\nExecStart=/not/service\n[Service]\nExecStart=/a \\\n# note\n  -x\n ExecStop = /b\nUser = svc\n"))
	if got := u.Exec["ExecStart"]; !reflect.DeepEqual(got, []string{"/a  -x"}) {
		t.Errorf("continuation: %q", got)
	}
	if got := u.Exec["ExecStop"]; !reflect.DeepEqual(got, []string{"/b"}) {
		t.Errorf("spaces around =: %q", got)
	}
	if u.User == nil || *u.User != "svc" {
		t.Errorf("user %v", u.User)
	}

	data, err = os.ReadFile("testdata/units/dropin-reset.conf")
	if err != nil {
		t.Fatal(err)
	}
	if got := parseUnitFile(data).Exec["ExecStart"]; !reflect.DeepEqual(got, []string{"", "/opt/app/bin/run"}) {
		t.Errorf("reset: %q", got)
	}
}

// A later User= wins, a reset discards what came before, other lines append.
func TestMergeUnitFiles(t *testing.T) {
	root, svc := "root", "svc"
	m := mergeUnitFiles([]unitFile{
		{User: &svc, Exec: map[string][]string{"ExecStart": {"/a"}, "ExecStartPre": {"/p"}}},
		{Exec: map[string][]string{"ExecStart": {"", "/b"}, "ExecStartPre": {"/q"}}},
		{User: &root, Exec: map[string][]string{"ExecStop": {""}}},
	})
	want := map[string][]string{"ExecStart": {"/b"}, "ExecStartPre": {"/p", "/q"}}
	if !reflect.DeepEqual(m.Exec, want) || m.User == nil || *m.User != "root" {
		t.Errorf("merge: exec %v user %v", m.Exec, m.User)
	}
}

func TestTemplateOf(t *testing.T) {
	for unit, want := range map[string]struct {
		tpl  string
		inst bool
	}{
		"getty@tty1.service": {"getty@.service", true},
		"getty@.service":     {"getty@.service", false},
		"ssh.service":        {"ssh.service", false},
		"a@b@c.service":      {"a@.service", true},
	} {
		if tpl, inst := templateOf(unit); tpl != want.tpl || inst != want.inst {
			t.Errorf("templateOf(%q) = %q, %v", unit, tpl, inst)
		}
	}
}

func TestParseListUnits(t *testing.T) {
	data, err := os.ReadFile("testdata/list_units.active")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cron.service", "getty@tty1.service", "ssh.service", "systemd-journald.service", "unattended-upgrades.service"}
	if got := parseListUnits(data); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q", got)
	}
	if got := parseListUnits([]byte("● failed.service loaded failed failed X\n\n")); !reflect.DeepEqual(got, []string{"failed.service"}) {
		t.Errorf("bullet: %q", got)
	}
}
