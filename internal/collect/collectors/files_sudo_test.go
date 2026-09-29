//go:build linux

package collectors

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// sudoAccess is the files collector's double for the sudo.log.* leaves:
// /etc/sudoers as main, and the drop-ins as literal content.
func sudoAccess(main string, dropins map[string]string) *fsAccess {
	a := &fsAccess{
		files:    map[string]string{"/etc/group": "group"},
		contents: map[string][]byte{},
		fails:    map[string]error{},
		stats:    map[string]statResult{sudoersDDir: {mode: 0o750, kind: "dir"}},
	}
	if main != "" {
		a.contents[sudoersPath] = []byte(main)
	}
	for p, c := range dropins {
		a.contents[p] = []byte(c)
	}
	return a
}

// sudoLog returns the three leaves.
func sudoLog(t *testing.T, a *fsAccess) (facts.Envelope, facts.Envelope, facts.Envelope) {
	t.Helper()
	b := build(t, "files", a)
	return env(t, b, "sudo.log.syslog"), env(t, b, "sudo.log.logfile"), env(t, b, "sudo.defaults.scoped_count")
}

func TestSudoLogDefaults(t *testing.T) {
	// The stock Ubuntu 22.04 file: tab-separated Defaults, seven commented
	// "#Defaults:%sudo env_keep += …" lines that are comments, not scoped
	// defaults.
	a := sudoAccess("", nil)
	a.files[sudoersPath] = "sudoers.ubuntu"
	sl, lf, sc := sudoLog(t, a)
	okValue(t, sl, true, "stock syslog")
	okValue(t, lf, "", "stock logfile")
	okValue(t, sc, 0, "stock scoped_count")
	if sl.Source == nil || sl.Source.Kind != "derived" || len(sl.Source.Inputs) != 1 || sl.Source.Inputs[0].Path != sudoersPath {
		t.Errorf("syslog source %+v, want derived from /etc/sudoers", sl.Source)
	}

	for _, c := range []struct {
		name, main string
		dropins    map[string]string
		syslog     bool
		logfile    string
		scoped     int
	}{
		{"negated", "Defaults !syslog\n", nil, false, "", 0},
		{"tab negated", "Defaults\t!syslog\n", nil, false, "", 0},
		{"option list", `Defaults env_reset, !syslog, logfile="/var/log/sudo.log"` + "\n", nil, false, "/var/log/sudo.log", 0},
		{"scoped user", "Defaults:root !syslog\n", nil, true, "", 1},
		{"scoped command", "Defaults!/usr/bin/x !syslog\nDefaults@host logfile=/h\nDefaults>op !syslog\n", nil, true, "", 3},
		{"env_keep += with spaces", `Defaults env_keep += "LANG LC_ALL, X", !syslog` + "\n", nil, false, "", 0},
		{"continuation", "Defaults env_reset, \\\n  logfile=/x\n", nil, true, "/x", 0},
		{"syslog facility keeps it on", "Defaults !syslog\nDefaults syslog=authpriv\n", nil, true, "", 0},
		{"logfile negated", "Defaults logfile=/a\nDefaults !logfile\n", nil, true, "", 0},
		{"comment after options", "Defaults !syslog # quiet\n", nil, false, "", 0},
		{"drop-in wins", "Defaults !syslog\n@includedir /etc/sudoers.d\n",
			map[string]string{
				"/etc/sudoers.d/10-log":   "Defaults syslog=authpriv\n",
				"/etc/sudoers.d/20-x.bak": "Defaults logfile=/dotted\n",
				"/etc/sudoers.d/30-y~":    "Defaults logfile=/tilde\n",
			}, true, "", 0},
		{"drop-ins in lexical order", "#includedir /etc/sudoers.d\n",
			map[string]string{"/etc/sudoers.d/b": "Defaults logfile=/b\n", "/etc/sudoers.d/a": "Defaults logfile=/a\n"}, true, "/b", 0},
		{"line after the includedir wins", "@includedir /etc/sudoers.d\nDefaults !syslog\n",
			map[string]string{"/etc/sudoers.d/10-log": "Defaults syslog=auth\n"}, false, "", 0},
		{"no includedir, no drop-ins", "Defaults env_reset\n",
			map[string]string{"/etc/sudoers.d/10-log": "Defaults !syslog\n"}, true, "", 0},
		{"scoped drop-in", "@includedir /etc/sudoers.d\n",
			map[string]string{"/etc/sudoers.d/10": "Defaults:%admin !syslog\n"}, true, "", 1},
		{"not a Defaults word", "DefaultsX !syslog\n", nil, true, "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			sl, lf, sc := sudoLog(t, sudoAccess(c.main, c.dropins))
			okValue(t, sl, c.syslog, "syslog")
			okValue(t, lf, c.logfile, "logfile")
			okValue(t, sc, c.scoped, "scoped_count")
		})
	}

	// No /etc/sudoers: sudo's defaults, derived.
	sl, lf, sc = sudoLog(t, sudoAccess("", nil))
	okValue(t, sl, true, "absent syslog")
	okValue(t, lf, "", "absent logfile")
	okValue(t, sc, 0, "absent scoped_count")
	if sl.Source == nil || sl.Source.Kind != "derived" {
		t.Errorf("absent source %+v", sl.Source)
	}
}

// C3: a drop-in the directory lists but this run may not read is the answer
// for every value it could set.
func TestSudoLogDeniedDropIn(t *testing.T) {
	a := sudoAccess("Defaults env_reset\n@includedir /etc/sudoers.d\n", map[string]string{"/etc/sudoers.d/90-x": "Defaults !syslog\n"})
	a.fails["/etc/sudoers.d/90-x"] = unix.EACCES
	sl, lf, sc := sudoLog(t, a)
	for name, e := range map[string]facts.Envelope{"syslog": sl, "logfile": lf, "scoped_count": sc} {
		if e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/sudoers.d/90-x: ") {
			t.Errorf("%s = %+v, want denied naming the drop-in", name, e)
		}
	}

	// A directory this run may not search is the same answer (EL's 0750).
	a = sudoAccess("@includedir /etc/sudoers.d\n", nil)
	a.deniedDirs = map[string]bool{sudoersDDir: true}
	sl, _, _ = sudoLog(t, a)
	if sl.Status != facts.StatusDenied || !strings.Contains(sl.Reason, sudoersDDir) {
		t.Errorf("denied directory syslog = %+v", sl)
	}

	// The main file denied (a non-root run): the read's status.
	a = sudoAccess("", nil)
	a.fails[sudoersPath] = unix.EACCES
	a.stats[sudoersPath] = statResult{mode: 0o440, kind: "regular"}
	sl, _, sc = sudoLog(t, a)
	if sl.Status != facts.StatusDenied || sc.Status != facts.StatusDenied || !strings.HasPrefix(sl.Reason, sudoersPath+": ") {
		t.Errorf("denied main = %+v / %+v", sl, sc)
	}
}

// Every registered sudo.* key the files collector owns is written on every
// sudoers shape.
func TestFilesPublishesEverySudoKey(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, k := range reg.Keys {
		if k.Collector == "files" && strings.HasPrefix(k.Key, "sudo.") {
			keys = append(keys, k.Key)
		}
	}
	if len(keys) != 10 {
		t.Fatalf("the registry declares %d sudo.* keys, want 10", len(keys))
	}
	deniedMain := sudoAccess("", nil)
	deniedMain.fails[sudoersPath] = unix.EACCES
	deniedDrop := sudoAccess("@includedir /etc/sudoers.d\n", map[string]string{"/etc/sudoers.d/x": "Defaults !syslog\n"})
	deniedDrop.fails["/etc/sudoers.d/x"] = unix.EACCES
	for name, a := range map[string]*fsAccess{
		"absent":      sudoAccess("", nil),
		"stock":       sudoAccess("Defaults env_reset\n@includedir /etc/sudoers.d\n", nil),
		"denied main": deniedMain,
		"denied drop": deniedDrop,
	} {
		t.Run(name, func(t *testing.T) {
			b := buildBegun(t, "files", a)
			got := b.Keys("files")
			for _, k := range keys {
				if !slices.Contains(got, k) {
					t.Errorf("%s was not written", k)
				}
			}
		})
	}
}

// Review fix 5 / W-7: muster never follows a link, so a symlinked drop-in is
// skipped — never read, never an error. sudo does follow it, so what it sets
// is unknown: the three leaves are absent naming the link.
func TestSudoLogSkipsASymlinkedDropIn(t *testing.T) {
	a := sudoAccess("@includedir /etc/sudoers.d\n", map[string]string{"/etc/sudoers.d/10-log": "Defaults !syslog\n"})
	a.links = map[string]string{"/etc/sudoers.d/10-log": "/srv/sudo-log"}
	sl, lf, sc := sudoLog(t, a)
	for name, e := range map[string]facts.Envelope{"syslog": sl, "logfile": lf, "scoped_count": sc} {
		if e.Status != facts.StatusAbsent || e.Reason != "a symlinked drop-in was not read: /etc/sudoers.d/10-log" {
			t.Errorf("%s = %+v, want absent naming the skipped link", name, e)
		}
	}
}

// R-4 / K-21: a drop-in linked to /dev/null is a mask. It holds no line, so
// the real drop-in beside it still answers and the three leaves stay ok; a
// link anywhere else is still skipped and named (W-7).
func TestSudoLogDevNullDropInIsAMask(t *testing.T) {
	// The links carry content only so the double's Glob lists them; a read
	// of either would set a logfile and fail the ok assertions.
	dropins := map[string]string{
		"/etc/sudoers.d/10-masked":    "Defaults logfile=/var/log/sudo.log\n",
		"/etc/sudoers.d/20-log":       "Defaults !syslog\n",
		"/etc/sudoers.d/30-elsewhere": "Defaults logfile=/var/log/sudo.log\n",
	}
	a := sudoAccess("@includedir /etc/sudoers.d\n", dropins)
	delete(a.contents, "/etc/sudoers.d/30-elsewhere")
	a.links = map[string]string{"/etc/sudoers.d/10-masked": "/dev/null"}
	sl, lf, sc := sudoLog(t, a)
	okValue(t, sl, false, "syslog beside a mask")
	okValue(t, lf, "", "logfile beside a mask")
	okValue(t, sc, 0, "scoped_count beside a mask")

	a = sudoAccess("@includedir /etc/sudoers.d\n", dropins)
	a.links = map[string]string{"/etc/sudoers.d/10-masked": "/dev/null", "/etc/sudoers.d/30-elsewhere": "/srv/sudo-log"}
	sl, lf, sc = sudoLog(t, a)
	for name, e := range map[string]facts.Envelope{"syslog": sl, "logfile": lf, "scoped_count": sc} {
		if e.Status != facts.StatusAbsent || e.Reason != "a symlinked drop-in was not read: /etc/sudoers.d/30-elsewhere" {
			t.Errorf("%s = %+v, want absent naming only the non-mask link", name, e)
		}
	}
}

// X-1 / C4: an @include or @includedir outside the paths the collector
// declares is a file muster did not look at, so the three leaves are absent
// naming it — never sudo's default.
func TestSudoLogIncludeOutsideTheDeclaration(t *testing.T) {
	for _, c := range []struct{ main, reason string }{
		{"Defaults env_reset\n@include /etc/sudoers.local\n", "include /etc/sudoers.local is outside the collector's declaration"},
		{"@includedir /etc/sudoers.extra\n", "includedir /etc/sudoers.extra is outside the collector's declaration"},
	} {
		sl, lf, sc := sudoLog(t, sudoAccess(c.main, nil))
		for name, e := range map[string]facts.Envelope{"syslog": sl, "logfile": lf, "scoped_count": sc} {
			if e.Status != facts.StatusAbsent || e.Reason != c.reason {
				t.Errorf("%q: %s = %+v, want absent %q", c.main, name, e, c.reason)
			}
		}
	}
}

// wantSudoRuleKeys are the four leaves of P-2.
var wantSudoRuleKeys = []string{"sudo.rules", "sudo.nopasswd_all", "sudo.authenticate_disabled", "sudo.rules_unresolved"}

func sudoRuleEnvs(t *testing.T, a *fsAccess) map[string]facts.Envelope {
	t.Helper()
	b := build(t, "files", a)
	out := map[string]facts.Envelope{}
	for _, k := range wantSudoRuleKeys {
		out[k] = env(t, b, k)
	}
	return out
}

// P-2: the rules follow the chain the logging leaves read, and degrade
// with them.
func TestSudoRuleFacts(t *testing.T) {
	// The stock Ubuntu file and cloud-init's drop-in: every rule, sorted by
	// file and line, and the one passwordless ALL.
	a := sudoAccess("", nil)
	a.files[sudoersPath] = "sudoers.ubuntu"
	a.files["/etc/sudoers.d/90-cloud-init-users"] = "sudoers_d.90-cloud-init-users"
	e := sudoRuleEnvs(t, a)
	rules := e["sudo.rules"]
	rows, _ := rules.Value.([]any)
	if rules.Status != facts.StatusOK || len(rows) != 4 {
		t.Fatalf("sudo.rules = %+v", rules)
	}
	var got []string
	for _, r := range rows {
		m := r.(map[string]any)
		got = append(got, fmt.Sprintf("%s:%d %s %s %v %v", m["file"], m["line"], m["principal"], m["kind"], m["nopasswd"], m["commands"]))
		for _, f := range []string{"file", "line", "principal", "kind", "negated", "runas", "nopasswd", "commands", "resolved"} {
			if _, ok := m[f]; !ok {
				t.Errorf("row %v lacks %s", m, f)
			}
		}
		if len(m) != 9 {
			t.Errorf("row %v carries %d fields, want 9", m, len(m))
		}
	}
	want := []string{
		"/etc/sudoers:44 root user false [ALL]",
		"/etc/sudoers:47 %admin group false [ALL]",
		"/etc/sudoers:50 %sudo group false [ALL]",
		"/etc/sudoers.d/90-cloud-init-users:4 ubuntu user true [ALL]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rows\n got %q\nwant %q", got, want)
	}
	if rules.Source == nil || rules.Source.Kind != "derived" || len(rules.Source.Inputs) != 2 {
		t.Errorf("rules source %+v", rules.Source)
	}
	np := e["sudo.nopasswd_all"]
	if l, _ := np.Value.([]any); np.Status != facts.StatusOK || !slices.Equal(l, []any{"ubuntu"}) {
		t.Errorf("nopasswd_all = %+v", np)
	}
	okValue(t, e["sudo.authenticate_disabled"], false, "authenticate_disabled")
	okValue(t, e["sudo.rules_unresolved"], 0, "rules_unresolved")

	// An unresolved rule: the rules and the count stand, the two answers are
	// absent naming what could not be resolved.
	e = sudoRuleEnvs(t, sudoAccess("+admins ALL = NOPASSWD: ALL\nroot ALL = ALL\nUser_Alias OPS = GHOST\nOPS ALL = ALL\n", nil))
	if rows, _ := e["sudo.rules"].Value.([]any); e["sudo.rules"].Status != facts.StatusOK || len(rows) != 3 {
		t.Errorf("rules = %+v", e["sudo.rules"])
	}
	okValue(t, e["sudo.rules_unresolved"], 2, "rules_unresolved")
	for _, k := range []string{"sudo.nopasswd_all", "sudo.authenticate_disabled"} {
		if e[k].Status != facts.StatusAbsent || e[k].Reason != "2 rules could not be resolved: +admins, GHOST — the answer needs them" {
			t.Errorf("%s = %+v", k, e[k])
		}
	}
	e = sudoRuleEnvs(t, sudoAccess("+admins ALL = ALL\n", nil))
	if r := e["sudo.nopasswd_all"].Reason; r != "1 rule could not be resolved: +admins — the answer needs them" {
		t.Errorf("one unresolved: %q", r)
	}

	// Defaults !authenticate in a drop-in, and the main file's later line
	// after the includedir winning over it (sudo's order).
	e = sudoRuleEnvs(t, sudoAccess("@includedir /etc/sudoers.d\n", map[string]string{"/etc/sudoers.d/10": "Defaults !authenticate\n"}))
	okValue(t, e["sudo.authenticate_disabled"], true, "drop-in !authenticate")
	e = sudoRuleEnvs(t, sudoAccess("@includedir /etc/sudoers.d\nDefaults authenticate\n", map[string]string{"/etc/sudoers.d/10": "Defaults !authenticate\n"}))
	okValue(t, e["sudo.authenticate_disabled"], false, "main line after the includedir")
	e = sudoRuleEnvs(t, sudoAccess("Defaults authenticate\n@includedir /etc/sudoers.d\n", map[string]string{"/etc/sudoers.d/10": "Defaults !authenticate\n"}))
	okValue(t, e["sudo.authenticate_disabled"], true, "main line before the includedir")
	// Between two includes: the line is applied after the first file and
	// before the second.
	e = sudoRuleEnvs(t, sudoAccess("@include /etc/sudoers.d/a\nDefaults !authenticate\n@include /etc/sudoers.d/b\n",
		map[string]string{"/etc/sudoers.d/a": "Defaults env_reset\n", "/etc/sudoers.d/b": "Defaults authenticate\n"}))
	okValue(t, e["sudo.authenticate_disabled"], false, "the second include after the main line")
	e = sudoRuleEnvs(t, sudoAccess("@include /etc/sudoers.d/a\nDefaults authenticate\n@include /etc/sudoers.d/b\n",
		map[string]string{"/etc/sudoers.d/a": "Defaults !authenticate\n", "/etc/sudoers.d/b": "Defaults env_reset\n"}))
	okValue(t, e["sudo.authenticate_disabled"], false, "the main line after the first include")

	// A host-scoped !authenticate is counted, not applied (§1 parks it).
	b := build(t, "files", sudoAccess("Defaults@web !authenticate\n", nil))
	okValue(t, env(t, b, "sudo.authenticate_disabled"), false, "Defaults@web")
	okValue(t, env(t, b, "sudo.defaults.scoped_count"), 1, "Defaults@web scoped_count")

	// An include outside the declaration and a symlinked drop-in: all four
	// absent, with the logging leaves.
	e = sudoRuleEnvs(t, sudoAccess("root ALL = ALL\n@include /etc/sudoers.local\n", nil))
	for _, k := range wantSudoRuleKeys {
		if e[k].Status != facts.StatusAbsent || e[k].Reason != "include /etc/sudoers.local is outside the collector's declaration" {
			t.Errorf("include outside: %s = %+v", k, e[k])
		}
	}
	a = sudoAccess("@includedir /etc/sudoers.d\n", map[string]string{"/etc/sudoers.d/10": "alice ALL = NOPASSWD: ALL\n"})
	a.links = map[string]string{"/etc/sudoers.d/10": "/srv/sudo"}
	e = sudoRuleEnvs(t, a)
	for _, k := range wantSudoRuleKeys {
		if e[k].Status != facts.StatusAbsent || e[k].Reason != "a symlinked drop-in was not read: /etc/sudoers.d/10" {
			t.Errorf("symlinked drop-in: %s = %+v", k, e[k])
		}
	}
	// A denied drop-in: the read's status on all four (C3).
	a = sudoAccess("@includedir /etc/sudoers.d\n", map[string]string{"/etc/sudoers.d/90-x": "alice ALL = NOPASSWD: ALL\n"})
	a.fails["/etc/sudoers.d/90-x"] = unix.EACCES
	e = sudoRuleEnvs(t, a)
	for _, k := range wantSudoRuleKeys {
		if e[k].Status != facts.StatusDenied || !strings.HasPrefix(e[k].Reason, "/etc/sudoers.d/90-x: ") {
			t.Errorf("denied drop-in: %s = %+v", k, e[k])
		}
	}
	// The main file denied.
	a = sudoAccess("", nil)
	a.fails[sudoersPath] = unix.EACCES
	a.stats[sudoersPath] = statResult{mode: 0o440, kind: "regular"}
	e = sudoRuleEnvs(t, a)
	for _, k := range wantSudoRuleKeys {
		if e[k].Status != facts.StatusDenied || !strings.HasPrefix(e[k].Reason, sudoersPath+": ") {
			t.Errorf("denied main: %s = %+v", k, e[k])
		}
	}

	// sudo not installed: facts, derived.
	e = sudoRuleEnvs(t, sudoAccess("", nil))
	for k, v := range map[string]any{"sudo.authenticate_disabled": false, "sudo.rules_unresolved": 0} {
		okValue(t, e[k], v, k)
	}
	for _, k := range []string{"sudo.rules", "sudo.nopasswd_all"} {
		if l, ok := e[k].Value.([]any); e[k].Status != facts.StatusOK || !ok || len(l) != 0 {
			t.Errorf("no sudo: %s = %+v", k, e[k])
		}
	}
	for _, k := range wantSudoRuleKeys {
		if s := e[k].Source; s == nil || s.Kind != "derived" {
			t.Errorf("no sudo: %s source %+v", k, s)
		}
	}

	// 2001 rules: the first 2000, truncated; the answers still read every rule.
	var big strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&big, "u%d ALL = ALL\n", i)
	}
	big.WriteString("last ALL = NOPASSWD: ALL\n")
	e = sudoRuleEnvs(t, sudoAccess(big.String(), nil))
	if rows, _ := e["sudo.rules"].Value.([]any); e["sudo.rules"].Status != facts.StatusOK || len(rows) != 2000 || !e["sudo.rules"].Truncated {
		t.Errorf("2001 rules: %d rows truncated=%t", len(rows), e["sudo.rules"].Truncated)
	}
	if l, _ := e["sudo.nopasswd_all"].Value.([]any); !slices.Equal(l, []any{"last"}) {
		t.Errorf("nopasswd_all past the cap = %+v", e["sudo.nopasswd_all"])
	}
}
