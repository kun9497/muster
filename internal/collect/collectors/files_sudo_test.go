//go:build linux

package collectors

import (
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
	if len(keys) != 6 {
		t.Fatalf("the registry declares %d sudo.* keys, want 6", len(keys))
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
