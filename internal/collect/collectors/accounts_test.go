//go:build linux

package collectors

import (
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// Task 1: login.defs values that are not numbers are kept verbatim, the
// boundaries are integers, and a key must match whole (UMASKX is not UMASK).
func TestLoginDefsStringsAndBoundaries(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs_2b",
		"/etc/shadow":     "shadow_2b",
		"/etc/passwd":     "passwd",
	}}
	b := build(t, "accounts", a)
	for key, want := range map[string]any{
		"accounts.login_defs.umask":                "022",
		"accounts.login_defs.home_mode":            "0750",
		"accounts.login_defs.encrypt_method":       "SHA512",
		"accounts.login_defs.env_supath":           "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"accounts.login_defs.env_path":             "PATH=/usr/local/bin:/usr/bin:/bin",
		"accounts.login_defs.uid_min":              1000,
		"accounts.login_defs.sys_uid_max":          999,
		"accounts.login_defs.sha_crypt_min_rounds": 5000,
	} {
		if e := env(t, b, key); e.Status != facts.StatusOK || e.Value != want {
			t.Errorf("%s = %+v, want %v", key, e, want)
		}
	}
	if e := env(t, b, "accounts.login_defs.umask"); e.Source == nil || e.Source.Line != 10 {
		t.Errorf("umask must cite line 10 (the UMASK line, not the UMASKX decoy): %+v", e.Source)
	}
	w := setting(t, b, "accounts.login_defs.pass_warn_age")
	if w.Persisted == nil || w.Persisted.Value != 7 || w.Runtime == nil || w.Runtime.Value != 3 || w.Runtime.Source.Kind != "derived" {
		t.Errorf("pass_warn_age persisted %+v runtime %+v (runtime is the minimum warn over hashed rows: carol's 3)", w.Persisted, w.Runtime)
	}
}

func TestLoginDefsUnsetStringIsAbsent(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd", "/etc/shadow": "shadow"}}
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.login_defs.umask"); e.Status != facts.StatusAbsent {
		t.Errorf("UMASK is not in the stage-1 fixture: %+v", e)
	}
	if e := env(t, b, "accounts.login_defs.uid_min"); e.Status != facts.StatusOK || e.Value != 1000 {
		t.Errorf("UID_MIN 1000 is in the stage-1 fixture: %+v", e)
	}
}

func TestLoginDefsIntOrFallsBack(t *testing.T) {
	d := loginDefs{lines: []string{"UID_MIN abc", "SYS_UID_MAX 999"}}
	if got := d.intOr("UID_MIN", 1000); got != 1000 {
		t.Errorf("unparsable UID_MIN must fall back, got %d", got)
	}
	if got := d.intOr("SYS_UID_MAX", 999); got != 999 {
		t.Errorf("got %d", got)
	}
	if got := d.intOr("UID_MAX", 60000); got != 60000 {
		t.Errorf("unset UID_MAX must fall back, got %d", got)
	}
}

// --- Task 2: the user record's joins ------------------------------------

func accounts2B() *fsAccess {
	return &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs_2b",
		"/etc/passwd":     "passwd_2b",
		"/etc/shadow":     "shadow_2b",
		"/etc/shells":     "shells_2b",
	}}
}

func userNamed(t *testing.T, users []any, name string, nth int) map[string]any {
	t.Helper()
	seen := 0
	for _, u := range users {
		m := u.(map[string]any)
		if m["name"] == name {
			if seen == nth {
				return m
			}
			seen++
		}
	}
	t.Fatalf("no user %q (occurrence %d)", name, nth)
	return nil
}

// Task 2: the joins inside /etc/passwd are fields of every user record,
// a mangled file is counted, and the shell's validity comes from /etc/shells.
func TestAccountsUsersCarryTheInFileJoins(t *testing.T) {
	b := build(t, "accounts", accounts2B())
	users := okList(t, b, "accounts.users")
	if len(users) != 13 {
		t.Fatalf("%d users, want 13 (12 well-formed rows plus badu with uid -1)", len(users))
	}
	if e := env(t, b, "accounts.parse_failures"); e.Value != 2 {
		t.Errorf("parse_failures = %+v, want 2 (the mangled line and badu's uid)", e)
	}
	root := userNamed(t, users, "root", 0)
	if root["home"] != "/root" || root["system"] != false || root["shadowed"] != true || root["uid_duplicate"] != true || root["name_duplicate"] != false || root["shell_valid"] != true {
		t.Errorf("root %v", root)
	}
	if toor := userNamed(t, users, "toor", 0); toor["uid_duplicate"] != true || toor["system"] != false {
		t.Errorf("toor %v (uid 0 is neither system nor unique)", toor)
	}
	if d := userNamed(t, users, "daemon", 0); d["system"] != true || d["shell_valid"] != false {
		t.Errorf("daemon %v", d)
	}
	if s := userNamed(t, users, "sync", 0); s["shell_valid"] != false {
		t.Errorf("sync %v (/bin/sync is not in /etc/shells)", s)
	}
	if f := userNamed(t, users, "ftp", 0); f["shell_valid"] != true || f["system"] != true {
		t.Errorf("ftp %v", f)
	}
	a1, a2 := userNamed(t, users, "alice", 0), userNamed(t, users, "alice", 1)
	if a1["uid_duplicate"] != true || a1["name_duplicate"] != true || a2["name_duplicate"] != true || a2["uid_duplicate"] != false {
		t.Errorf("alice rows %v %v", a1, a2)
	}
	if bob := userNamed(t, users, "bob", 0); bob["uid_duplicate"] != true || bob["password_status"] != "nopass" {
		t.Errorf("bob %v", bob)
	}
	if dave := userNamed(t, users, "dave", 0); dave["shadowed"] != false || dave["hash_algo"] != "$5$" {
		t.Errorf("dave %v (passwd field is not x; shadow row still joins)", dave)
	}
	if badu := userNamed(t, users, "badu", 0); badu["uid"] != -1 || badu["system"] != false {
		t.Errorf("badu %v (an unparsable uid is -1 and never system)", badu)
	}
	if e := env(t, b, "accounts.shells"); e.Status != facts.StatusOK {
		t.Errorf("shells %+v", e)
	} else if l := e.Value.([]any); len(l) != 4 || l[0] != "/bin/sh" || l[3] != "/bin/dash" {
		t.Errorf("shells %v (comments and blank lines dropped, order kept)", l)
	}
	for _, u := range users {
		for k, v := range u.(map[string]any) {
			if s, ok := v.(string); ok && strings.Contains(s, "hashhash") {
				t.Fatalf("hash material leaked into %s=%q", k, s)
			}
		}
	}
}

// R (analysis #15): a locked account that still holds a hash reports the
// hash's algorithm — the lock is its own flag. A hash without a "$id$"
// prefix is "legacy"; a bare lock marker has no algorithm at all.
func TestAccountsLockedAccountsKeepTheirHashAlgorithm(t *testing.T) {
	b := build(t, "accounts", accounts2B())
	users := okList(t, b, "accounts.users")
	if toor := userNamed(t, users, "toor", 0); toor["password_status"] != "locked" || toor["locked"] != true || toor["hash_algo"] != "$1$" {
		t.Errorf("toor %v", toor)
	}
	if svc := userNamed(t, users, "svc", 0); svc["locked"] != true || svc["hash_algo"] != "" {
		t.Errorf("svc %v (\"!\" alone is a lock without a hash)", svc)
	}
	if ftp := userNamed(t, users, "ftp", 0); ftp["locked"] != true || ftp["hash_algo"] != "" {
		t.Errorf("ftp %v (\"!!\" is a lock without a hash)", ftp)
	}
	if carol := userNamed(t, users, "carol", 0); carol["hash_algo"] != "legacy" || carol["password_status"] != "hashed" || carol["locked"] != false {
		t.Errorf("carol %v", carol)
	}
	if root := userNamed(t, users, "root", 0); root["locked"] != false || root["hash_algo"] != "$6$" {
		t.Errorf("root %v", root)
	}
}

func TestHashAlgoStripsLockMarkersAndNamesLegacy(t *testing.T) {
	for in, want := range map[string]string{
		"$6$salt$digest": "$6$", "!$6$salt$digest": "$6$", "!!$y$j9T$x$y": "$y$", "*$1$a$b": "$1$",
		"!": "", "!!": "", "*": "", "": "", "hashhashhashh": "legacy", "!hashhashhashh": "legacy",
		"$$": "", "$toolongidentifier$x": "",
	} {
		if got := hashAlgo(in); got != want {
			t.Errorf("hashAlgo(%q) = %q, want %q", in, got, want)
		}
	}
}

// R126. /etc/shells missing is legitimate — getusershell(3) then answers
// /bin/sh and /bin/csh — so the fact carries that libc list with a reason
// saying where it came from rather than going absent. An unreadable file
// carries the read's status instead, and either way the same fallback set
// keeps shell_valid on every row: a control never meets a record without
// the field.
func TestAccountsShellsFallBackToTheLibcDefault(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		a := accounts2B()
		delete(a.files, "/etc/shells")
		b := build(t, "accounts", a)
		e := env(t, b, "accounts.shells")
		if e.Status != facts.StatusOK || e.Source == nil || e.Source.Kind != "derived" {
			t.Fatalf("shells %+v (source %+v)", e, e.Source)
		}
		if l, ok := e.Value.([]any); !ok || len(l) != 2 || l[0] != "/bin/sh" || l[1] != "/bin/csh" {
			t.Errorf("shells %#v, want the libc default", e.Value)
		}
		assertLibcShellJoin(t, okList(t, b, "accounts.users"))
	})
	t.Run("unreadable", func(t *testing.T) {
		a := accounts2B()
		a.fails = map[string]error{"/etc/shells": os.ErrPermission}
		b := build(t, "accounts", a)
		if e := env(t, b, "accounts.shells"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/shells: ") {
			t.Errorf("shells %+v, want denied naming the file", e)
		}
		assertLibcShellJoin(t, okList(t, b, "accounts.users"))
	})
}

func assertLibcShellJoin(t *testing.T, users []any) {
	t.Helper()
	if r := userNamed(t, users, "root", 0); r["shell_valid"] != false {
		t.Errorf("root %v (/bin/bash is not in the libc fallback set)", r)
	}
	if a2 := userNamed(t, users, "alice", 1); a2["shell_valid"] != true {
		t.Errorf("alice2 %v (/bin/sh is)", a2)
	}
}

// R132. Once /etc/shadow was read, a passwd row with no shadow row is a
// finding of its own — "noshadow" — not a record missing the fields every
// other record has. A control that screens on password_status must be able
// to meet this row without hitting an absent field.
func TestAccountsPasswdRowWithoutShadowRowIsNoshadow(t *testing.T) {
	a := accounts2B()
	a.files["/etc/passwd"] = "passwd_2b_ghost"
	b := build(t, "accounts", a)
	ghost := userNamed(t, okList(t, b, "accounts.users"), "ghost", 0)
	if ghost["password_status"] != "noshadow" || ghost["locked"] != false || ghost["hash_algo"] != "" {
		t.Errorf("ghost %v", ghost)
	}
	for _, f := range [...]string{"last_change", "min", "max", "warn", "inactive", "expire"} {
		if ghost[f] != -1 {
			t.Errorf("ghost %s = %v, want -1 (no shadow row sets no policy)", f, ghost[f])
		}
	}
}

// R131. Truncation crosses the join: a shadow read that hit the cap makes
// accounts.users partial too, because the record carries shadow-derived
// fields. A fact built from a file that was read whole stays whole.
func TestAccountsUsersCarryShadowTruncation(t *testing.T) {
	a := accounts2B()
	a.truncated = map[string]bool{"/etc/shadow": true}
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.users"); !e.Truncated {
		t.Errorf("accounts.users %+v must be truncated when /etc/shadow was", e)
	}
	if e := env(t, b, "accounts.shells"); e.Truncated {
		t.Errorf("accounts.shells %+v was read whole", e)
	}
}
