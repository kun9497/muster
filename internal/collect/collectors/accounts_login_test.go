//go:build linux

package collectors

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	loginPasswd = "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n" +
		"ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n" +
		"alice:x:1001:1001::/home/alice:/bin/zsh\n" +
		"bob:x:1002:1002::/home/bob:/bin/sh\n"
	loginShadow = "root:$6$salt$hash:19000:0:99999:7:::\n" +
		"daemon:*:19000:0:99999:7:::\n" +
		"sshd:*:19000:0:99999:7:::\n" +
		"ubuntu:!:19000:0:99999:7:::\n" +
		"alice:$6$salt$hash:19000:0:99999:7:35:20000:\n" +
		"bob:$6$salt$hash:19000:0:99999:7:0::\n"
	// The EL shape: /etc/shells lists nologin, so membership alone is not
	// the test of an interactive shell.
	loginShellsFile = "/bin/sh\n/bin/bash\n/bin/zsh\n/usr/sbin/nologin\n"
)

func loginShellSet() map[string]bool {
	set := map[string]bool{}
	for _, s := range strings.Fields(loginShellsFile) {
		set[s] = true
	}
	return set
}

func shadowByName(data string) map[string]shadowRow {
	m := map[string]shadowRow{}
	for _, r := range parseShadow([]byte(data)) {
		m[r.name] = r
	}
	return m
}

type capable struct {
	name                  string
	uid, inactive, expire int
	inactiveUnset, locked bool
}

func checkCapable(t *testing.T, got []any, want []capable) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d rows, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		m := got[i].(map[string]any)
		exp := map[string]any{
			"name": w.name, "uid": w.uid, "inactive": w.inactive, "expire": w.expire,
			"inactive_unset": w.inactiveUnset, "locked": w.locked,
		}
		if len(m) != len(exp) {
			t.Errorf("row %d carries %v, want exactly the fields of %v (V-9)", i, m, exp)
		}
		for k, v := range exp {
			if m[k] != v {
				t.Errorf("row %d (%v) %s = %#v, want %#v", i, m["name"], k, m[k], v)
			}
		}
	}
}

// P-1: the accounts the inactivity policy must cover are the interactive,
// non-system ones — root included, password-locked accounts included, the
// nologin service accounts out even where /etc/shells lists nologin.
func TestLoginCapableIsInteractiveNonSystemWithRoot(t *testing.T) {
	prows, _ := parsePasswd([]byte(loginPasswd))
	got := loginCapable(prows, shadowByName(loginShadow), true, 1000, loginShellSet())
	checkCapable(t, got, []capable{
		{"alice", 1001, 35, 20000, false, false},
		{"bob", 1002, 0, -1, false, false},
		{"root", 0, -1, -1, true, false},
		{"ubuntu", 1000, -1, -1, true, true},
	})
}

// R138, V-30: with no /etc/shadow the field cannot exist, so every row is
// unset (and nothing is locked by a file that is not there).
func TestLoginCapableWithoutShadowIsUnset(t *testing.T) {
	prows, _ := parsePasswd([]byte(loginPasswd))
	got := loginCapable(prows, map[string]shadowRow{}, true, 1000, loginShellSet())
	checkCapable(t, got, []capable{
		{"alice", 1001, -1, -1, true, false},
		{"bob", 1002, -1, -1, true, false},
		{"root", 0, -1, -1, true, false},
		{"ubuntu", 1000, -1, -1, true, false},
	})

	// Through the collector: shadow ENOENT is the same reading.
	a := inactivityAccess()
	delete(a.contents, "/etc/shadow")
	b := build(t, "accounts", a)
	checkCapable(t, okList(t, b, "accounts.login_capable"), []capable{
		{"alice", 1001, -1, -1, true, false},
		{"bob", 1002, -1, -1, true, false},
		{"root", 0, -1, -1, true, false},
		{"ubuntu", 1000, -1, -1, true, false},
	})
}

func inactivityAccess() *fsAccess {
	return &fsAccess{
		files: map[string]string{
			"/etc/login.defs":      "login.defs_2b",
			"/etc/default/useradd": "useradd.default.el9",
		},
		contents: map[string][]byte{
			"/etc/passwd":      []byte(loginPasswd),
			"/etc/shadow":      []byte(loginShadow),
			"/etc/shells":      []byte(loginShellsFile),
			"/var/log/lastlog": lastlogBytes(lastlogRecordSize(), 1003, map[int]lastlogRecord{0: {1700000000, "pts/0", "203.0.113.5"}}),
		},
	}
}

// hasLeaf reports whether key is written, as an envelope or a setting.
func hasLeaf(b *collect.Builder, key string) bool {
	cur := any(b.Tree())
	for _, s := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		if cur, ok = m[s]; !ok {
			return false
		}
	}
	switch cur.(type) {
	case facts.Envelope, facts.Setting:
		return true
	}
	return false
}

// P-1, V-1, V-7: the three leaves on every shape the collector can meet.
func TestAccountsInactivityFacts(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, k := range reg.Keys {
		if k.Collector == "accounts" {
			keys = append(keys, k.Key)
		}
	}
	size := lastlogRecordSize()

	t.Run("stock", func(t *testing.T) {
		b := build(t, "accounts", inactivityAccess())
		lc := env(t, b, "accounts.login_capable")
		if lc.Status != facts.StatusOK || lc.Source == nil || lc.Source.Kind != "derived" || len(lc.Source.Inputs) != 3 {
			t.Errorf("login_capable %+v, want ok derived from passwd, shadow and shells", lc)
		}
		checkCapable(t, okList(t, b, "accounts.login_capable"), []capable{
			{"alice", 1001, 35, 20000, false, false},
			{"bob", 1002, 0, -1, false, false},
			{"root", 0, -1, -1, true, false},
			{"ubuntu", 1000, -1, -1, true, true},
		})
		ui := env(t, b, "accounts.useradd.inactive")
		if ui.Status != facts.StatusOK || ui.Value != -1 || !strings.Contains(ui.Reason, "INACTIVE=-1") {
			t.Errorf("useradd.inactive %+v, want ok -1 naming INACTIVE=-1", ui)
		}
		ll := env(t, b, "accounts.lastlog")
		if ll.Status != facts.StatusOK || ll.Truncated || ll.Reason != fmt.Sprintf("record size %d", size) {
			t.Errorf("lastlog %+v", ll)
		}
		rows := lastlogRowsByName(t, okList(t, b, "accounts.lastlog"))
		if len(rows) != 6 {
			t.Errorf("%d lastlog rows, want one per account: %v", len(rows), rows)
		}
		if rows["root"]["last_login"] != "2023-11-14T22:13:20Z" || rows["alice"]["last_login"] != "" {
			t.Errorf("lastlog rows %v", rows)
		}
	})

	t.Run("useradd 35 and stock Ubuntu", func(t *testing.T) {
		a := inactivityAccess()
		a.files["/etc/default/useradd"] = "useradd.default.35"
		if e := env(t, build(t, "accounts", a), "accounts.useradd.inactive"); e.Status != facts.StatusOK || e.Value != 35 || e.Reason != "" {
			t.Errorf("useradd.inactive %+v, want ok 35", e)
		}
		a.files["/etc/default/useradd"] = "useradd.default.ubuntu"
		if e := env(t, build(t, "accounts", a), "accounts.useradd.inactive"); e.Status != facts.StatusOK || e.Value != -1 || !strings.Contains(e.Reason, "commented") {
			t.Errorf("useradd.inactive %+v, want ok -1 commented", e)
		}
	})

	shapes := map[string]func() *fsAccess{
		"stock": inactivityAccess,
		"empty": func() *fsAccess { return &fsAccess{} },
		"shadow denied": func() *fsAccess {
			a := inactivityAccess()
			a.fails = map[string]error{"/etc/shadow": os.ErrPermission}
			return a
		},
		"shadow missing": func() *fsAccess {
			a := inactivityAccess()
			delete(a.contents, "/etc/shadow")
			return a
		},
		"passwd denied": func() *fsAccess {
			a := inactivityAccess()
			a.fails = map[string]error{"/etc/passwd": os.ErrPermission}
			return a
		},
		"useradd denied, lastlog denied": func() *fsAccess {
			a := inactivityAccess()
			a.fails = map[string]error{"/etc/default/useradd": os.ErrPermission, "/var/log/lastlog": os.ErrPermission}
			return a
		},
		"useradd missing, lastlog missing": func() *fsAccess {
			a := inactivityAccess()
			delete(a.files, "/etc/default/useradd")
			delete(a.contents, "/var/log/lastlog")
			return a
		},
		"lastlog 40 MiB": func() *fsAccess {
			a := inactivityAccess()
			a.contents["/etc/passwd"] = []byte(loginPasswd + "far:x:200000:200000::/home/far:/bin/bash\n")
			a.contents["/var/log/lastlog"] = lastlogBytes(size, (40<<20)/size, map[int]lastlogRecord{0: {1700000000, "pts/0", "203.0.113.5"}})
			return a
		},
	}
	results := map[string]*collect.Builder{}
	for name, mk := range shapes {
		b := build(t, "accounts", mk())
		results[name] = b
		for _, k := range keys {
			if !hasLeaf(b, k) {
				t.Errorf("%s: %s is not written", name, k)
			}
		}
	}

	if e := env(t, results["shadow denied"], "accounts.login_capable"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/shadow: ") {
		t.Errorf("shadow denied: login_capable %+v, want denied naming /etc/shadow (C3)", e)
	}
	if e := env(t, results["shadow denied"], "accounts.useradd.inactive"); e.Status != facts.StatusOK || e.Value != -1 {
		t.Errorf("shadow denied: useradd.inactive %+v must not depend on shadow", e)
	}
	if e := env(t, results["shadow denied"], "accounts.lastlog"); e.Status != facts.StatusOK {
		t.Errorf("shadow denied: lastlog %+v must not depend on shadow", e)
	}
	// The passwd-failure branch: without the accounts there is nothing to
	// select, join or index, so all three carry the passwd read's status.
	for _, k := range []string{"accounts.login_capable", "accounts.useradd.inactive", "accounts.lastlog"} {
		if e := env(t, results["passwd denied"], k); e.Status != facts.StatusDenied {
			t.Errorf("passwd denied: %s %+v, want the passwd read's status", k, e)
		}
	}
	if e := env(t, results["useradd denied, lastlog denied"], "accounts.useradd.inactive"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/default/useradd: ") {
		t.Errorf("useradd denied: %+v, want denied naming the file (C3), never the default", e)
	}
	if e := env(t, results["useradd denied, lastlog denied"], "accounts.lastlog"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/var/log/lastlog: ") {
		t.Errorf("lastlog denied: %+v", e)
	}
	if e := env(t, results["useradd missing, lastlog missing"], "accounts.useradd.inactive"); e.Status != facts.StatusOK || e.Value != -1 || e.Reason != "file does not exist" || e.Source == nil || e.Source.Kind != "derived" {
		t.Errorf("useradd missing: %+v, want ok -1 derived, file does not exist", e)
	}
	if e := env(t, results["useradd missing, lastlog missing"], "accounts.lastlog"); e.Status != facts.StatusAbsent || !strings.Contains(e.Reason, "lastlog2") {
		t.Errorf("lastlog missing: %+v, want absent naming lastlog2", e)
	}
	big := env(t, results["lastlog 40 MiB"], "accounts.lastlog")
	if big.Status != facts.StatusOK || !big.Truncated {
		t.Errorf("lastlog 40 MiB: %+v, want ok and truncated", big)
	}
	rows := lastlogRowsByName(t, okList(t, results["lastlog 40 MiB"], "accounts.lastlog"))
	if _, ok := rows["far"]; ok {
		t.Errorf("uid 200000's record lies past the 32 MiB limit and must not be decoded: %v", rows["far"])
	}
	if rows["root"]["last_login"] != "2023-11-14T22:13:20Z" || len(rows) != 6 {
		t.Errorf("lastlog 40 MiB: the records inside the limit must decode: %v", rows)
	}
}
