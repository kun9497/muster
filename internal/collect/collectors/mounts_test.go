//go:build linux

package collectors

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// mountsDouble serves one mountinfo fixture as the only file this collector
// reads.
func mountsDouble(fixture string) *fsAccess {
	return &fsAccess{files: map[string]string{mountinfoPath: fixture}}
}

// pointRow returns the mounts.points record for one target, failing when the
// list has none — which is itself the K-5 failure the caller wants reported.
func pointRow(t *testing.T, list []any, target string) map[string]any {
	t.Helper()
	for _, v := range list {
		r, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("mounts.points carries %#v, not a record", v)
		}
		if r["target"] == target {
			return r
		}
	}
	t.Fatalf("mounts.points has no row for %s", target)
	return nil
}

func rowStrings(t *testing.T, r map[string]any, field string) []string {
	t.Helper()
	list, ok := r[field].([]any)
	if !ok {
		t.Fatalf("row %v: %s is %#v, not a list", r["target"], field, r[field])
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("row %v: %s carries %#v, not a string", r["target"], field, v)
		}
		out = append(out, s)
	}
	return out
}

// K-5: the nine candidates are rows on every host, in the spec's order,
// whatever the host has actually mounted. A candidate with no mount of its
// own is not missing from the list — it carries what governs the path today,
// which is what makes the option controls readable at all.
func TestMountRowsAlwaysNineInOrder(t *testing.T) {
	b := build(t, "mounts", mountsDouble("mountinfo.ubuntu-stock"))
	list := okList(t, b, "mounts.points")

	var targets []string
	for _, v := range list {
		targets = append(targets, v.(map[string]any)["target"].(string))
	}
	want := []string{"/", "/boot", "/home", "/tmp", "/var", "/var/tmp", "/var/log", "/var/log/audit", "/dev/shm"}
	if !slices.Equal(targets, want) {
		t.Fatalf("mounts.points targets =\n%v\nwant\n%v", targets, want)
	}

	// /tmp is part of the root filesystem on this host, so its row says what
	// governs it: the root mount, with the root mount's source, type and
	// options. A row that left them empty would read as "no options", which
	// is not what the kernel is enforcing on /tmp.
	tmp := pointRow(t, list, "/tmp")
	if tmp["separate"] != false || tmp["mounted_by"] != "/" {
		t.Errorf("/tmp row = %v, want separate false mounted_by /", tmp)
	}
	if tmp["fstype"] != "ext4" || tmp["source"] != "/dev/mapper/vg-root" {
		t.Errorf("/tmp row = %v, want the root mount's ext4 /dev/mapper/vg-root", tmp)
	}
	root := pointRow(t, list, "/")
	if !slices.Equal(rowStrings(t, tmp, "options"), rowStrings(t, root, "options")) {
		t.Errorf("/tmp options %v, want the root mount's %v", tmp["options"], root["options"])
	}
	if root["separate"] != true || root["mounted_by"] != "/" {
		t.Errorf("/ row = %v, want separate true mounted_by /", root)
	}

	// /dev/shm is its own tmpfs on every systemd host, mounted nosuid and
	// nodev and NOT noexec — the row is where control 14 reads that from.
	shm := pointRow(t, list, "/dev/shm")
	if shm["separate"] != true || shm["mounted_by"] != "/dev/shm" || shm["fstype"] != "tmpfs" {
		t.Errorf("/dev/shm row = %v, want separate true, mounted by itself, tmpfs", shm)
	}
	opts := rowStrings(t, shm, "options")
	for _, o := range []string{"nosuid", "nodev"} {
		if !slices.Contains(opts, o) {
			t.Errorf("/dev/shm options %v lack %s", opts, o)
		}
	}
	if slices.Contains(opts, "noexec") {
		t.Errorf("/dev/shm options %v claim noexec, which the fixture does not set", opts)
	}

	// A candidate nested under another candidate that is not mounted either
	// falls all the way back to the root mount.
	if audit := pointRow(t, list, "/var/log/audit"); audit["mounted_by"] != "/" || audit["separate"] != false {
		t.Errorf("/var/log/audit row = %v, want separate false mounted_by /", audit)
	}

	// B-6: the four leaves say exactly what their rows say, so a mechanism
	// can gate on a fact an `each` clause cannot reach.
	for _, l := range separateLeaves {
		e := env(t, b, l.key)
		row := pointRow(t, list, l.target)
		if e.Status != facts.StatusOK || e.Value != row["separate"] {
			t.Errorf("%s = %+v, want ok %v like the %s row", l.key, e, row["separate"], l.target)
		}
	}
}

// The mount that governs a path is the DEEPEST one whose mount point is a
// prefix of it, not the root and not the first that matches: on a host with
// /var and /var/log mounted and no /var/log/audit, the audit directory is
// governed by /var/log, and that is the source, type and options it answers
// with.
func TestMountGoverningMountIsTheDeepest(t *testing.T) {
	b := build(t, "mounts", mountsDouble("mountinfo.varlog"))
	list := okList(t, b, "mounts.points")

	audit := pointRow(t, list, "/var/log/audit")
	if audit["separate"] != false || audit["mounted_by"] != "/var/log" {
		t.Errorf("/var/log/audit row = %v, want separate false mounted_by /var/log", audit)
	}
	if audit["source"] != "/dev/mapper/vg-varlog" || audit["fstype"] != "xfs" {
		t.Errorf("/var/log/audit row = %v, want the /var/log mount's xfs /dev/mapper/vg-varlog", audit)
	}
	if opts := rowStrings(t, audit, "options"); !slices.Contains(opts, "nodev") {
		t.Errorf("/var/log/audit options %v, want the /var/log mount's, which include nodev", opts)
	}
	// /var/tmp stops one level higher, at /var, rather than falling to /.
	if vartmp := pointRow(t, list, "/var/tmp"); vartmp["mounted_by"] != "/var" || vartmp["source"] != "/dev/mapper/vg-var" {
		t.Errorf("/var/tmp row = %v, want mounted_by /var with the /var mount's source", vartmp)
	}
	// /home has no mount of its own anywhere in this table.
	if e := env(t, b, "mounts.home.separate"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("mounts.home.separate = %+v, want ok false", e)
	}
}

// C3: the one file that could answer every key here is the answer for every
// key here when it cannot be read. A partial answer would publish "nothing is
// separate" for a host nobody could look at.
func TestMountsReadErrorReachesEveryKey(t *testing.T) {
	keys := append([]string{"mounts.points"}, separateKeys()...)

	denied := &fsAccess{fails: map[string]error{mountinfoPath: os.ErrPermission}}
	b := build(t, "mounts", denied)
	for _, k := range keys {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s = %+v, want denied", k, e)
		}
		if e.Value != nil {
			t.Errorf("%s carries a value %#v on a denied read", k, e.Value)
		}
		if !strings.Contains(e.Reason, mountinfoPath) {
			t.Errorf("%s reason %q does not name %s", k, e.Reason, mountinfoPath)
		}
	}

	// A mount table with rows but none at "/" describes no tree at all: an
	// error naming the file, never nine rows governed by nothing.
	b = build(t, "mounts", mountsDouble("mountinfo.no-root"))
	for _, k := range keys {
		if e := env(t, b, k); e.Status != facts.StatusError || !strings.Contains(e.Reason, mountinfoPath) {
			t.Errorf("%s on a mountinfo with no root = %+v, want an error naming %s", k, e, mountinfoPath)
		}
	}
}

func separateKeys() []string {
	out := make([]string, 0, len(separateLeaves))
	for _, l := range separateLeaves {
		out = append(out, l.key)
	}
	return out
}

// K-4: the collector declares the one file it reads, runs nothing, and writes
// exactly the five keys of B-2.
func TestMountsDeclarationCoversItsReads(t *testing.T) {
	c := collectorNamed(t, "mounts")
	if c.Declare.Needs != "none" {
		t.Errorf("Needs %q, want none", c.Declare.Needs)
	}
	if len(c.Declare.Commands) != 0 {
		t.Errorf("declares %d commands, want none", len(c.Declare.Commands))
	}
	if c.Declare.Walk {
		t.Error("declares the walk licence, which this collector has no use for")
	}
	if want := []string{mountinfoPath}; !slices.Equal(c.Declare.Reads, want) {
		t.Errorf("Reads = %v, want %v", c.Declare.Reads, want)
	}

	b := buildBegun(t, "mounts", mountsDouble("mountinfo.ubuntu-stock"))
	want := append([]string{"mounts.points"}, separateKeys()...)
	slices.Sort(want)
	if got := b.Keys("mounts"); !slices.Equal(got, want) {
		t.Errorf("wrote %v, want the five keys of B-2 %v", got, want)
	}
}
