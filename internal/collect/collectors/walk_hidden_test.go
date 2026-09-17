//go:build linux

package collectors

import (
	"path"
	"strings"
	"testing"
)

// wantExactPaths and wantBareNames are the two tables of A-17 written out
// again, so a row removed from the allowlist — which silences a real
// finding for every host — fails here rather than passing quietly.
var wantExactPaths = []string{
	"/.dockerenv",
	"/etc/.pwd.lock",
	"/etc/.updated",
	"/var/.updated",
	"/etc/.resolv.conf.systemd-resolved.bak",
	"/var/lib/rpm/.rpm.lock",
	"/tmp/.X11-unix",
	"/tmp/.ICE-unix",
	"/tmp/.XIM-unix",
	"/tmp/.font-unix",
	"/tmp/.Test-unix",
}

var wantBareNames = []string{
	".well-known", ".git", ".gitignore", ".gitattributes", ".gitkeep", ".keep",
	".placeholder", ".htaccess", ".bin", ".github", ".npmignore", ".eslintrc",
	".eslintrc.js", ".eslintrc.json", ".prettierrc", ".editorconfig",
	".travis.yml", ".package-lock.json", ".yarn-integrity", ".dockerignore",
}

// allowValues is the value column of one table, for the "is this row still
// here" checks. contains lives in timesync_test.go.
func allowValues(rows []allowRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.value)
	}
	return out
}

// Every row carries a reason. An allowlist entry is a decision not to
// report something, and a decision with no stated reason cannot be reviewed.
func TestHiddenAllowlistRowsAreJustified(t *testing.T) {
	for _, table := range []struct {
		name string
		rows []allowRow
	}{{"hiddenExactPaths", hiddenExactPaths}, {"hiddenBareNames", hiddenBareNames}} {
		seen := map[string]bool{}
		for i, r := range table.rows {
			if strings.TrimSpace(r.value) == "" {
				t.Errorf("%s[%d]: empty value", table.name, i)
			}
			if strings.TrimSpace(r.why) == "" {
				t.Errorf("%s[%d] (%s): empty why", table.name, i, r.value)
			}
			if seen[r.value] {
				t.Errorf("%s: %s is listed twice", table.name, r.value)
			}
			seen[r.value] = true
		}
	}
	for _, r := range hiddenExactPaths {
		if !strings.HasPrefix(r.value, "/") {
			t.Errorf("hiddenExactPaths: %q is not an absolute path", r.value)
		}
		if !strings.HasPrefix(path.Base(r.value), ".") {
			t.Errorf("hiddenExactPaths: %q does not name a hidden entry", r.value)
		}
	}
	for _, r := range hiddenBareNames {
		if strings.Contains(r.value, "/") {
			t.Errorf("hiddenBareNames: %q is a path, not a bare name", r.value)
		}
		if !strings.HasPrefix(r.value, ".") {
			t.Errorf("hiddenBareNames: %q does not name a hidden entry", r.value)
		}
	}
}

func TestHiddenAllowlistCoversA17(t *testing.T) {
	exact := allowValues(hiddenExactPaths)
	for _, want := range wantExactPaths {
		if !contains(exact, want) {
			t.Errorf("hiddenExactPaths is missing %s", want)
		}
	}
	if len(exact) != len(wantExactPaths) {
		t.Errorf("hiddenExactPaths has %d rows, A-17 lists %d: %v", len(exact), len(wantExactPaths), exact)
	}
	bare := allowValues(hiddenBareNames)
	for _, want := range wantBareNames {
		if !contains(bare, want) {
			t.Errorf("hiddenBareNames is missing %s", want)
		}
	}
	if len(bare) != len(wantBareNames) {
		t.Errorf("hiddenBareNames has %d rows, A-17 lists %d: %v", len(bare), len(wantBareNames), bare)
	}
}

func TestHiddenAllowlisted(t *testing.T) {
	cases := []struct {
		path, name string
		want       bool
		why        string
	}{
		{"/etc/.pwd.lock", ".pwd.lock", true, "an exact row matches its own path"},
		{"/etc/.pwd.lock2", ".pwd.lock2", false, "an exact row is not a prefix"},
		{"/etc/.pwd.loc", ".pwd.loc", false, "an exact row is not a prefix of the path either"},
		{"/srv/.pwd.lock", ".pwd.lock", false, "an exact row does not travel to another directory"},
		{"/etc/.pwd.lock/x", "x", false, "an exact row does not cover what is under it"},
		{"/.dockerenv", ".dockerenv", true, "a row at the filesystem root"},
		{"/tmp/.X11-unix", ".X11-unix", true, "a socket directory X11 creates"},
		{"/var/tmp/.X11-unix", ".X11-unix", false, "the same name outside /tmp is still a finding"},
		{"/srv/www/.well-known", ".well-known", true, "a bare name matches at any depth"},
		{"/.well-known", ".well-known", true, "a bare name matches at the root too"},
		{"/srv/a/b/c/d/.git", ".git", true, "a bare name matches however deep it sits"},
		{"/srv/www/.well-known2", ".well-known2", false, "a bare name is not a prefix"},
		{"/srv/www/.wellknown", ".wellknown", false, "a bare name is matched exactly"},
		{"/srv/www/.ssh", ".ssh", false, "a name on neither table is a candidate"},
		{"/var/lib/rpm/.rpm.lock", ".rpm.lock", true, "rpm's lock file"},
	}
	for _, c := range cases {
		if got := hiddenAllowlisted(c.path, c.name); got != c.want {
			t.Errorf("hiddenAllowlisted(%q, %q) = %v, want %v: %s", c.path, c.name, got, c.want, c.why)
		}
	}
}

// The caps bound what one run may record. They are not assertions about the
// exact numbers — those are a budget decision — but about the shape: seven
// lists, every cap positive, and the two informational lists (hidden and
// skipped) allowed to grow past the finding lists.
func TestHiddenAllowlistListCaps(t *testing.T) {
	if len(listCaps) != capCount {
		t.Fatalf("listCaps has %d entries, want one per walk list (%d)", len(listCaps), capCount)
	}
	for i, c := range listCaps {
		if c <= 0 {
			t.Errorf("listCaps[%d] = %d, want a positive cap", i, c)
		}
	}
	for _, i := range []int{capSUIDSGID, capSUIDUnverified, capWorldWritable, capStickyMissing, capUnowned} {
		if listCaps[capHidden] < listCaps[i] || listCaps[capSkipped] < listCaps[i] {
			t.Errorf("listCaps[%d] = %d exceeds the hidden (%d) or skipped (%d) cap",
				i, listCaps[i], listCaps[capHidden], listCaps[capSkipped])
		}
	}
	if allowlistedHiddenCap <= 0 {
		t.Errorf("allowlistedHiddenCap = %d, want a positive cap", allowlistedHiddenCap)
	}
}
