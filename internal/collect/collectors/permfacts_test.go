//go:build linux

package collectors

import (
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

func TestGroupNamesReadsEtcGroup(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}}
	got, _, err := groupNames(a)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "root" || got[42] != "shadow" || got[4] != "adm" || len(got) != 3 {
		t.Errorf("groups = %v", got)
	}
}

func TestWritePermFactsLeavesForAFixedPath(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		stats: map[string]statResult{"/etc/hosts": {mode: 0o644, uid: 0, gid: 42, kind: "regular"}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_hosts.mode"); v.Status != facts.StatusOK || v.Value != 0o644 {
		t.Errorf("mode %+v", v)
	}
	if v := env(t, b, "files.etc_hosts.group"); v.Value != "shadow" {
		t.Errorf("group %+v", v)
	}
	for k, want := range map[string]bool{"group_readable": true, "group_writable": false, "other_readable": true, "other_writable": false, "acl_present": false} {
		if v := env(t, b, "files.etc_hosts."+k); v.Value != want {
			t.Errorf("%s = %+v, want %v", k, v, want)
		}
	}
}

func TestWritePermFactsAbsentAndDeniedReachEveryLeaf(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}, fails: map[string]error{"/etc/hosts.lpd": os.ErrNotExist, "/etc/services": os.ErrPermission}}
	b := build(t, "files", a)
	for _, k := range permLeaves {
		if v := env(t, b, "files.etc_hosts_lpd."+k); v.Status != facts.StatusAbsent {
			t.Errorf("hosts.lpd %s = %v, want absent", k, v.Status)
		}
		if v := env(t, b, "files.etc_services."+k); v.Status != facts.StatusDenied {
			t.Errorf("services %s = %v, want denied", k, v.Status)
		}
	}
}

func TestPasswdACLEntriesAreListed(t *testing.T) {
	a := &fsAccess{
		files:       map[string]string{"/etc/group": "group"},
		stats:       map[string]statResult{"/etc/passwd": {mode: 0o644, uid: 0, gid: 0, kind: "regular"}},
		xattrValues: map[string]map[string][]byte{"/etc/passwd": {"system.posix_acl_access": fiveEntryACL()}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_passwd.acl_present"); v.Value != true {
		t.Errorf("acl_present %+v", v)
	}
	entries := env(t, b, "files.etc_passwd.acl_entries").Value.([]any)
	if len(entries) != 5 || entries[1] != "user:1000:rw-" {
		t.Errorf("acl_entries = %v", entries)
	}
	if v := env(t, b, "files.etc_hosts.acl_present"); v.Status != facts.StatusAbsent {
		t.Errorf("a path without a stat entry must be absent, got %v", v.Status)
	}
}

func TestGroupFailureDoesNotHideThePermissionFacts(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/etc/group": os.ErrPermission},
		stats: map[string]statResult{"/etc/hosts": {mode: 0o600, uid: 0, gid: 0, kind: "regular"}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_hosts.mode"); v.Status != facts.StatusOK {
		t.Errorf("mode must not depend on /etc/group: %+v", v)
	}
	v := env(t, b, "files.etc_hosts.group")
	if v.Status != facts.StatusDenied {
		t.Errorf("group name must carry the /etc/group failure, got %+v", v)
	}
	// R109: the failing input is named in the reason, so a reader of the
	// snapshot sees which file could not be read, not just "denied".
	if !strings.HasPrefix(v.Reason, "/etc/group: ") {
		t.Errorf("group reason = %q, want it to name /etc/group", v.Reason)
	}
}
