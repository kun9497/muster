//go:build linux

package collectors

import (
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// H-11 (f9): a text file holding a NUL byte is the read's error, never an
// empty ok read. These drive the callers through the double, whose NUL rule
// is the host primitive's: before the fix the primitive returned no bytes and
// no error, so /etc/passwd with one NUL parsed as no users and
// root_only_uid_zero passed over a hidden second uid-0 account.

const nulPasswd = "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n\x00"

func binaryReason(t *testing.T, key string, e facts.Envelope, path string) {
	t.Helper()
	if e.Status != facts.StatusError || !strings.HasPrefix(e.Reason, path+": ") || !strings.Contains(e.Reason, "binary") {
		t.Errorf("%s = %+v, want error naming %s as binary", key, e, path)
	}
	// D16: the path is written once, though the primitive's error carries it.
	if strings.Count(e.Reason, path+": ") != 1 {
		t.Errorf("%s reason %q names %s more than once", key, e.Reason, path)
	}
}

func TestAccountsBinaryPasswdIsAnErrorOnEveryPasswdKey(t *testing.T) {
	a := accounts2BWithGroup()
	a.contents = map[string][]byte{"/etc/passwd": []byte(nulPasswd)}
	b := build(t, "accounts", a)
	for _, k := range []string{
		"accounts.users", "accounts.parse_failures", "accounts.login_capable",
		"accounts.orphan_gids", "accounts.admin_group_members", "accounts.shadow_in_use",
		"accounts.lastlog",
	} {
		binaryReason(t, k, env(t, b, k), "/etc/passwd")
	}
	if groups := okList(t, b, "accounts.groups"); len(groups) == 0 {
		t.Error("accounts.groups must stay ok: /etc/group was readable")
	}

	// The normal condition: the same file without the NUL is two users.
	a = accounts2BWithGroup()
	a.contents = map[string][]byte{"/etc/passwd": []byte(strings.TrimSuffix(nulPasswd, "\x00"))}
	b = build(t, "accounts", a)
	if users := okList(t, b, "accounts.users"); len(users) != 2 {
		t.Errorf("%d users, want 2 (root and toor)", len(users))
	}
}

func TestAccountsBinaryShadowIsAnErrorOnTheRuntimeAgeing(t *testing.T) {
	a := accounts2BWithGroup()
	a.contents = map[string][]byte{"/etc/shadow": []byte("root:*:19000:0:99999:7:::\n\x00")}
	b := build(t, "accounts", a)
	for _, k := range []string{"accounts.login_defs.pass_max_days", "accounts.login_defs.pass_min_days", "accounts.login_defs.pass_warn_age"} {
		s := setting(t, b, k)
		if s.Runtime == nil {
			t.Fatalf("%s has no runtime side", k)
		}
		binaryReason(t, k+" runtime", *s.Runtime, "/etc/shadow")
	}
	binaryReason(t, "accounts.shadow_in_use", env(t, b, "accounts.shadow_in_use"), "/etc/shadow")
}

func TestAccountsBinaryGroupReachesOnlyTheGroupJoins(t *testing.T) {
	a := accounts2BWithGroup()
	a.contents = map[string][]byte{"/etc/group": []byte("root:x:0:\n\x00")}
	b := build(t, "accounts", a)
	for _, k := range []string{"accounts.groups", "accounts.orphan_gids", "accounts.admin_group_members"} {
		binaryReason(t, k, env(t, b, k), "/etc/group")
	}
	if users := okList(t, b, "accounts.users"); len(users) != 13 {
		t.Errorf("%d users, want 13: /etc/passwd was readable", len(users))
	}
}

func TestSudoBinarySudoersIsAnErrorNotNoRules(t *testing.T) {
	e := sudoRuleEnvs(t, sudoAccess("root ALL = ALL\nalice ALL = NOPASSWD: ALL\n\x00", nil))
	for _, k := range []string{"sudo.nopasswd_all", "sudo.authenticate_disabled"} {
		binaryReason(t, k, e[k], sudoersPath)
	}
	// Normal condition: without the NUL, alice is the NOPASSWD rule.
	e = sudoRuleEnvs(t, sudoAccess("root ALL = ALL\nalice ALL = NOPASSWD: ALL\n", nil))
	if l, _ := e["sudo.nopasswd_all"].Value.([]any); e["sudo.nopasswd_all"].Status != facts.StatusOK || len(l) != 1 {
		t.Errorf("nopasswd_all = %+v, want ok [alice]", e["sudo.nopasswd_all"])
	}
}

func TestPrivilegeBinaryPreloadIsAnErrorNotNoPreload(t *testing.T) {
	a := privilegeAccess(stockGroup, stockPasswd)
	a.contents[ldSoPreloadPath] = []byte("/usr/lib/evil.so\n\x00")
	b := build(t, "privilege", a)
	binaryReason(t, "privilege.ld_so_preload", env(t, b, "privilege.ld_so_preload"), ldSoPreloadPath)
}

func TestSysctlBinaryDropInIsAChainFailure(t *testing.T) {
	const drop = "/etc/sysctl.d/10-base.conf"
	a := &fsAccess{files: map[string]string{}, contents: map[string][]byte{drop: []byte("kernel.sysrq = 16\n\x00")}}
	for k, v := range procSysSeeds() {
		a.files[k] = v
	}
	b := build(t, "sysctl", a)
	s := setting(t, b, "kernel.sysctl.sysrq")
	if s.Persisted == nil {
		t.Fatal("kernel.sysctl.sysrq has no persisted side")
	}
	if s.Persisted.Status != facts.StatusError || !strings.Contains(s.Persisted.Reason, drop) || !strings.Contains(s.Persisted.Reason, "binary") {
		t.Errorf("persisted %+v, want error naming %s as binary", *s.Persisted, drop)
	}
}

func TestFtpBinaryBannerFileIsAnErrorBanner(t *testing.T) {
	a := ftpAccess(map[string]string{"/etc/vsftpd.conf": "vsftpd.conf.banner-file"})
	a.contents = map[string][]byte{"/etc/issue.net": []byte("Welcome\n\x00")}
	b := buildBegun(t, "ftp", a)
	for _, k := range []string{"ftp.banner_text", "ftp.banner_discloses_version"} {
		binaryReason(t, k, env(t, b, k), "/etc/issue.net")
	}
}
