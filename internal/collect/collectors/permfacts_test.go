//go:build linux

package collectors

import (
	"os"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// aclLeaves are the leaves a withACL path carries: permLeaves plus
// acl_entries. A fresh copy each call, so a caller's append can never
// reach permLeaves' backing array.
func aclLeaves() []string {
	return append(append([]string{}, permLeaves...), "acl_entries")
}

func TestGroupNamesReadsEtcGroup(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/group": "group"}}
	got, _, err := groupNames(a)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "root" || got[42] != "shadow" || got[4] != "adm" || len(got) != 3 {
		t.Errorf("groups = %v", got)
	}
	// The fixture repeats gid 42 as dupshadow after shadow, and carries a
	// line with no fields at all: the first name for a gid wins and the
	// malformed line is skipped, so the map is the same on every run.
	if got[42] != "shadow" {
		t.Errorf("gid 42 = %q, want the first name in the file", got[42])
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

// A gid with no /etc/group entry is not a failure: the numeric gid leaf
// still carries the judgment, so the name is an ok empty string rather
// than a missing, errored or absent leaf.
func TestWritePermFactsUnnamedGidIsAnEmptyName(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		stats: map[string]statResult{"/etc/services": {mode: 0o644, uid: 0, gid: 999, kind: "regular"}},
	}
	b := build(t, "files", a)
	if v := env(t, b, "files.etc_services.gid"); v.Status != facts.StatusOK || v.Value != 999 {
		t.Errorf("gid %+v", v)
	}
	if v := env(t, b, "files.etc_services.group"); v.Status != facts.StatusOK || v.Value != "" {
		t.Errorf("group %+v, want ok with an empty name", v)
	}
}

// R70/R109: a truncated /etc/group read may have cut off the very entry
// the name would have come from, so the flag has to reach the group-name
// leaf. The status stays ok — the value is still the best answer the read
// supports — and the flag is what tells a reader not to treat an empty
// name as proof the gid has none.
func TestTruncatedGroupFileMarksTheGroupNameLeaf(t *testing.T) {
	a := &fsAccess{
		files:     map[string]string{"/etc/group": "group"},
		truncated: map[string]bool{"/etc/group": true},
		stats:     map[string]statResult{"/etc/hosts": {mode: 0o644, uid: 0, gid: 42, kind: "regular"}},
	}
	b := build(t, "files", a)
	v := env(t, b, "files.etc_hosts.group")
	if v.Status != facts.StatusOK || v.Value != "shadow" {
		t.Fatalf("group %+v, want ok with the name the read did reach", v)
	}
	if !v.Truncated {
		t.Error("a truncated /etc/group read must mark the group-name leaf")
	}
	// The truncation belongs to /etc/group alone: every other leaf comes
	// from Stat, which read nothing that could be cut short.
	if env(t, b, "files.etc_hosts.mode").Truncated {
		t.Error("mode comes from Stat and must not carry the /etc/group truncation")
	}
}

func TestWritePermFactsAbsentAndDeniedReachEveryLeaf(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/group": "group"},
		fails: map[string]error{"/etc/hosts.lpd": os.ErrNotExist, "/etc/services": os.ErrPermission, "/etc/passwd": os.ErrNotExist},
	}
	b := build(t, "files", a)
	for _, k := range permLeaves {
		if v := env(t, b, "files.etc_hosts_lpd."+k); v.Status != facts.StatusAbsent {
			t.Errorf("hosts.lpd %s = %v, want absent", k, v.Status)
		}
		if v := env(t, b, "files.etc_services."+k); v.Status != facts.StatusDenied {
			t.Errorf("services %s = %v, want denied", k, v.Status)
		}
	}
	// The withACL path has one leaf more, and it must not be the one the
	// Stat-failure branch quietly drops: an omitted acl_entries next to an
	// absent acl_present is exactly the partial set a clause could misread
	// as "this file has no ACL".
	for _, k := range aclLeaves() {
		if v := env(t, b, "files.etc_passwd."+k); v.Status != facts.StatusAbsent {
			t.Errorf("passwd %s = %v, want absent", k, v.Status)
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
