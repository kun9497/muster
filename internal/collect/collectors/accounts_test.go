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
	unreadable := loginDefs{err: os.ErrPermission}
	if got := unreadable.intOr("UID_MIN", 1000); got != 1000 {
		t.Errorf("unreadable login.defs must fall back, got %d", got)
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
		if e.Reason != "libc default; /etc/shells does not exist" {
			t.Errorf("shells reason %q must say where the list came from", e.Reason)
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

// R138. A missing /etc/shadow (ENOENT) is a known state, not an unread one:
// every row must still carry password_status "noshadow" the same way a
// passwd row with no matching shadow row does (R132), rather than no shadow
// fields at all, and accounts.shadow_in_use stays ok/false (never denied).
func TestAccountsMissingShadowMarksEveryRowNoshadow(t *testing.T) {
	a := accounts2B()
	delete(a.files, "/etc/shadow")
	b := build(t, "accounts", a)
	users := okList(t, b, "accounts.users")
	if len(users) == 0 {
		t.Fatal("no users")
	}
	for _, u := range users {
		m := u.(map[string]any)
		if m["password_status"] != "noshadow" || m["locked"] != false || m["hash_algo"] != "" {
			t.Errorf("%v", m)
		}
		for _, f := range [...]string{"last_change", "min", "max", "warn", "inactive", "expire"} {
			if m[f] != -1 {
				t.Errorf("%s %s = %v, want -1 (no shadow at all sets no policy)", m["name"], f, m[f])
			}
		}
	}
	if e := env(t, b, "accounts.shadow_in_use"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("accounts.shadow_in_use %+v, want ok/false", e)
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
	if e := env(t, b, "accounts.shadow_in_use"); !e.Truncated {
		t.Errorf("accounts.shadow_in_use %+v must be truncated when /etc/shadow was", e)
	}
	if e := env(t, b, "accounts.shells"); e.Truncated {
		t.Errorf("accounts.shells %+v was read whole", e)
	}
}

// --- Task 3: /etc/group, its joins with /etc/passwd and shadow-in-use ---

func accounts2BWithGroup() *fsAccess {
	a := accounts2B()
	a.files["/etc/group"] = "group_2b"
	return a
}

func record(t *testing.T, list []any, i int) map[string]any {
	t.Helper()
	if i >= len(list) {
		t.Fatalf("element %d of %d", i, len(list))
	}
	return list[i].(map[string]any)
}

// Task 3: groups keep file order and count their listed members; the
// primary-group join and the administrative membership are their own keys.
func TestAccountsGroupsOrphansAndAdminMembers(t *testing.T) {
	b := build(t, "accounts", accounts2BWithGroup())
	groups := okList(t, b, "accounts.groups")
	if len(groups) != 12 {
		t.Fatalf("%d groups, want 12", len(groups))
	}
	sudo := record(t, groups, 4)
	if sudo["name"] != "sudo" || sudo["gid"] != 27 || sudo["member_count"] != 2 || sudo["gid_duplicate"] != false {
		t.Errorf("sudo %v (a member listed twice counts once)", sudo)
	}
	if m := sudo["members"].([]any); len(m) != 2 || m[0] != "alice" || m[1] != "bob" {
		t.Errorf("sudo members %v", m)
	}
	if g := record(t, groups, 7); g["name"] != "alice" || g["gid_duplicate"] != true {
		t.Errorf("alice group %v", g)
	}
	if g := record(t, groups, 9); g["name"] != "dupgid" || g["gid_duplicate"] != true {
		t.Errorf("dupgid %v", g)
	}
	if g := record(t, groups, 0); g["member_count"] != 0 || g["gid_duplicate"] != false {
		t.Errorf("root group %v", g)
	}
	// R136: badg's gid "notanumber" is unparsable, so it is kept with
	// gid -1, counted as a parse failure, and excluded from gid_duplicate
	// (only gid >= 0 entries are compared) and from admin_group_members
	// (badg is not an administrative group).
	if badg := record(t, groups, 11); badg["name"] != "badg" || badg["gid"] != -1 || badg["gid_duplicate"] != false {
		t.Errorf("badg %v", badg)
	}
	orphans := okList(t, b, "accounts.orphan_gids")
	if len(orphans) != 1 || record(t, orphans, 0)["name"] != "carol" || record(t, orphans, 0)["gid"] != 4242 {
		t.Errorf("orphan_gids %v", orphans)
	}
	admins := okList(t, b, "accounts.admin_group_members")
	want := []map[string]any{
		{"name": "toor", "group": "root", "via": "primary"},
		{"name": "carol", "group": "wheel", "via": "secondary"},
		{"name": "alice", "group": "sudo", "via": "secondary"},
		{"name": "bob", "group": "sudo", "via": "secondary"},
	}
	if len(admins) != len(want) {
		t.Fatalf("admin_group_members %v", admins)
	}
	for i, w := range want {
		got := record(t, admins, i)
		for k, v := range w {
			if got[k] != v {
				t.Errorf("admin[%d] %v, want %v", i, got, w)
			}
		}
	}
	if e := env(t, b, "accounts.parse_failures"); e.Value != 4 {
		t.Errorf("parse_failures %+v, want 4 (two passwd, two group)", e)
	}
	if e := env(t, b, "accounts.parse_failures"); len(e.Source.Inputs) != 2 {
		t.Errorf("parse_failures source inputs %+v, want 2 (passwd and group both readable)", e.Source.Inputs)
	}
}

func TestAccountsShadowInUse(t *testing.T) {
	b := build(t, "accounts", accounts2BWithGroup())
	if e := env(t, b, "accounts.shadow_in_use"); e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "dave") {
		t.Errorf("%+v (dave keeps hash material in /etc/passwd)", e)
	}
	a := &fsAccess{files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd", "/etc/shadow": "shadow"}}
	if e := env(t, build(t, "accounts", a), "accounts.shadow_in_use"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("stage-1 fixtures: %+v", e)
	}
	delete(a.files, "/etc/shadow")
	if e := env(t, build(t, "accounts", a), "accounts.shadow_in_use"); e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "/etc/shadow") {
		t.Errorf("no shadow file: %+v", e)
	}
	a.fails = map[string]error{"/etc/shadow": os.ErrPermission}
	if e := env(t, build(t, "accounts", a), "accounts.shadow_in_use"); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/shadow: ") {
		t.Errorf("denied shadow: %+v", e)
	}
}

// A denied /etc/group costs the three group-derived keys and nothing else:
// users and the passwd-only joins still come out, and parse_failures counts
// what was parsed.
func TestAccountsGroupDeniedReachesOnlyTheGroupJoins(t *testing.T) {
	a := accounts2B()
	a.fails = map[string]error{"/etc/group": os.ErrPermission}
	b := build(t, "accounts", a)
	for _, k := range []string{"accounts.groups", "accounts.orphan_gids", "accounts.admin_group_members"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/group: ") {
			t.Errorf("%s = %+v", k, e)
		}
	}
	if users := okList(t, b, "accounts.users"); len(users) != 13 {
		t.Errorf("%d users", len(users))
	}
	if e := env(t, b, "accounts.parse_failures"); e.Value != 2 {
		t.Errorf("parse_failures %+v", e)
	}
	if e := env(t, b, "accounts.parse_failures"); len(e.Source.Inputs) != 1 {
		t.Errorf("parse_failures source inputs %+v, want 1 (passwd alone; /etc/group is denied)", e.Source.Inputs)
	}
}

// R135(a). The mirror of the group case: an unreadable /etc/passwd reaches
// every key the passwd read feeds — the user list, both joins, shadow-in-use
// and the failure count — and stops at accounts.groups, which /etc/passwd
// has no part in.
func TestAccountsPasswdDeniedReachesEveryPasswdJoin(t *testing.T) {
	a := accounts2BWithGroup()
	a.fails = map[string]error{"/etc/passwd": os.ErrPermission}
	b := build(t, "accounts", a)
	for _, k := range []string{
		"accounts.users", "accounts.orphan_gids", "accounts.admin_group_members",
		"accounts.shadow_in_use", "accounts.parse_failures",
	} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s = %+v, want denied", k, e)
		}
	}
	if groups := okList(t, b, "accounts.groups"); len(groups) != 12 {
		t.Errorf("%d groups, want 12 (/etc/group was readable)", len(groups))
	}
}

// R131. Truncation crosses every join this collector makes: a count taken
// from two files is partial when either was cut short, and a key built from
// one of them stays whole when the other was truncated.
func TestAccountsParseFailuresCarryTruncation(t *testing.T) {
	a := accounts2BWithGroup()
	a.truncated = map[string]bool{"/etc/passwd": true}
	b := build(t, "accounts", a)
	for _, k := range []string{
		"accounts.users", "accounts.orphan_gids", "accounts.admin_group_members",
		"accounts.shadow_in_use", "accounts.parse_failures",
	} {
		if e := env(t, b, k); !e.Truncated {
			t.Errorf("%s %+v must be truncated when /etc/passwd was", k, e)
		}
	}
	if e := env(t, b, "accounts.groups"); e.Truncated {
		t.Errorf("accounts.groups %+v is built from /etc/group alone", e)
	}
	a = accounts2BWithGroup()
	a.truncated = map[string]bool{"/etc/group": true}
	b = build(t, "accounts", a)
	for _, k := range []string{
		"accounts.groups", "accounts.orphan_gids", "accounts.admin_group_members", "accounts.parse_failures",
	} {
		if e := env(t, b, k); !e.Truncated {
			t.Errorf("%s %+v must be truncated when /etc/group was", k, e)
		}
	}
	for _, k := range []string{"accounts.users", "accounts.shadow_in_use"} {
		if e := env(t, b, k); e.Truncated {
			t.Errorf("%s %+v is built from /etc/passwd and /etc/shadow alone", k, e)
		}
	}
}

// --- Task 4: NSS sources and the remote-source degradation --------------

// Task 4: the NSS sources of the two account databases, bracketed actions
// removed, and the derived "any remote source" flag.
func TestAccountsNSSSourcesAndRemote(t *testing.T) {
	a := accounts2BWithGroup()
	a.files["/etc/nsswitch.conf"] = "nsswitch.conf"
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.nss.passwd_sources"); e.Status != facts.StatusOK || e.Source == nil || e.Source.Line != 2 {
		t.Errorf("%+v", e)
	} else if l := e.Value.([]any); len(l) != 2 || l[0] != "files" || l[1] != "systemd" {
		t.Errorf("%v", l)
	}
	if e := env(t, b, "accounts.nss.remote"); e.Status != facts.StatusOK || e.Value != false || e.Source.Kind != "derived" {
		t.Errorf("%+v", e)
	}

	a.files["/etc/nsswitch.conf"] = "nsswitch_sss.conf"
	b = build(t, "accounts", a)
	if l := okList(t, b, "accounts.nss.passwd_sources"); len(l) != 3 || l[1] != "sss" || l[2] != "ldap" {
		t.Errorf("%v (the [NOTFOUND=return] action is not a source)", l)
	}
	// Fix round 1: ldap alone already makes remote true, so the sss caveat
	// (which would wrongly imply sss was the reason) must not be attached.
	if e := env(t, b, "accounts.nss.remote"); e.Value != true || e.Reason != "" {
		t.Errorf("%+v (ldap makes remote true on its own; no sss caveat needed)", e)
	}
}

func TestAccountsNSSFileMissingMeansLocal(t *testing.T) {
	b := build(t, "accounts", accounts2BWithGroup())
	if e := env(t, b, "accounts.nss.passwd_sources"); e.Status != facts.StatusAbsent {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "accounts.nss.remote"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("%+v (glibc resolves from files when nsswitch.conf is missing)", e)
	}
	a := accounts2BWithGroup()
	a.fails = map[string]error{"/etc/nsswitch.conf": os.ErrPermission}
	b = build(t, "accounts", a)
	for _, k := range []string{"accounts.nss.passwd_sources", "accounts.nss.group_sources", "accounts.nss.remote"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s = %+v (unknown is not local)", k, e)
		}
	}
}

func TestNSSSourcesParsing(t *testing.T) {
	data := []byte("passwd: files sss [NOTFOUND=return] ldap\n# group: comment\ngroup:files\n")
	if s, line, ok := nssSources(data, "passwd"); !ok || line != 1 || strings.Join(s, ",") != "files,sss,ldap" {
		t.Errorf("%v %d %v", s, line, ok)
	}
	if s, line, ok := nssSources(data, "group"); !ok || line != 3 || strings.Join(s, ",") != "files" {
		t.Errorf("%v %d %v", s, line, ok)
	}
	if _, _, ok := nssSources(data, "shadow"); ok {
		t.Error("shadow is not listed")
	}
	if nssRemote([][]string{{"files", "systemd"}, {"compat"}}, false) {
		t.Error("files/systemd/compat are local")
	}
	if !nssRemote([][]string{{"files"}, {"files", "winbind"}}, false) {
		t.Error("winbind is remote")
	}
	// Fix round 1: glibc truncates a line at the first '#' wherever it
	// appears, not only at the start of the line.
	if s, _, ok := nssSources([]byte("passwd: files systemd # local only\n"), "passwd"); !ok || strings.Join(s, ",") != "files,systemd" {
		t.Errorf("%v %v (trailing comment must be dropped)", s, ok)
	}
	// Fix round 1: a multi-word bracketed action is skipped by bracket
	// depth, not just a leading "[" or trailing "]" token.
	if s, _, ok := nssSources([]byte("passwd: compat [SUCCESS=return NOTFOUND=continue UNAVAIL=continue] ldap\n"), "passwd"); !ok || strings.Join(s, ",") != "compat,ldap" {
		t.Errorf("%v %v (multi-word action must be skipped entirely)", s, ok)
	}
}

// R127: authselect lists "sss" in nsswitch.conf on every RHEL-family host
// whether or not sssd has a domain configured, so "sss" alone must not read
// as a remote source — only /etc/sssd/sssd.conf existing makes it one.
func TestAccountsNSSSssCountsOnlyWhenConfigured(t *testing.T) {
	if !nssRemote([][]string{{"files", "sss"}}, true) {
		t.Error("sss counts as remote once sssd is configured")
	}
	a := accounts2BWithGroup()
	a.files["/etc/nsswitch.conf"] = "nsswitch_rhel.conf"
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.nss.remote"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("%+v (sss alone, sssd not configured, must not count as remote)", e)
	} else if want := "sss listed but /etc/sssd/sssd.conf absent: not counted"; e.Reason != want {
		t.Errorf("reason %q, want %q", e.Reason, want)
	} else if e.Source == nil || len(e.Source.Inputs) != 2 {
		// Fix round 1: the derived source names both files this path
		// actually consulted (nsswitch.conf and the sssd.conf Stat).
		t.Errorf("source inputs %+v, want 2", e.Source)
	}
	if l := okList(t, b, "accounts.nss.passwd_sources"); len(l) != 3 || l[0] != "sss" || l[1] != "files" || l[2] != "systemd" {
		t.Errorf("%v", l)
	}

	a.files["/etc/sssd/sssd.conf"] = "nsswitch.conf" // any existing fixture; only Stat presence matters
	b = build(t, "accounts", a)
	if e := env(t, b, "accounts.nss.remote"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("%+v (sssd.conf present: sss now counts)", e)
	}
}
