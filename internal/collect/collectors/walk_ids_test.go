//go:build linux

package collectors

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// idDouble serves the four files the id tables are built from. passwd has
// root(0), svc(998) and alice(1000); group has root(0), adm(4), shadow(42)
// and syslog(104); the two sub-id fixtures are synthetic.
func idDouble() *fsAccess {
	return &fsAccess{files: map[string]string{
		"/etc/passwd": "passwd",
		"/etc/group":  "group",
		"/etc/subuid": "subuid.sample",
		"/etc/subgid": "subgid.sample",
	}}
}

// idCase is one id and the answer the tables must give for it.
type idCase struct {
	id    uint32
	known bool
	class string
	why   string
}

func checkIDs(t *testing.T, name string, fn func(uint32) (bool, string), cases []idCase) {
	t.Helper()
	for _, c := range cases {
		known, class := fn(c.id)
		if known != c.known || class != c.class {
			t.Errorf("%s(%d) = (%v, %q), want (%v, %q): %s", name, c.id, known, class, c.known, c.class, c.why)
		}
	}
}

func TestIDTables(t *testing.T) {
	tables, failures := loadIDTables(idDouble())
	if len(failures) != 0 {
		t.Fatalf("every file is readable, yet loadIDTables reported %v", failures)
	}

	checkIDs(t, "uidKnown", tables.uidKnown, []idCase{
		{0, true, "passwd", "root is a passwd account"},
		{1000, true, "passwd", "alice is a passwd account"},
		{998, true, "passwd", "svc is a passwd account"},
		{1001, false, "unknown", "no account and no range claims it"},
		{100000, true, "subid", "the first id of alice's subordinate range"},
		{100005, true, "subid", "inside alice's subordinate range"},
		{165535, true, "subid", "the last id of alice's subordinate range"},
		{165536, false, "unknown", "one past alice's range: count is exclusive"},
		{400000, false, "unknown", "a subuid line naming a user /etc/passwd has no row for is ignored"},
		{200000, true, "subid", "a numeric first field is that uid's own range"},
		{265535, true, "subid", "the last id of the numeric row's range"},
		{265536, false, "unknown", "one past the numeric row's range"},
		{4294966999, false, "unknown", "one below the range that runs off the end of the id space"},
		{4294967295, true, "subid", "the clamped end of a range whose count runs past the id space"},
		{5, false, "unknown", "a count larger than the whole id space delegates nothing at all"},
		{61183, false, "unknown", "one below the DynamicUser range"},
		{61184, true, "dynamic", "the first id of the DynamicUser range"},
		{65519, true, "dynamic", "the last id of the DynamicUser range"},
		{65520, false, "unknown", "one above the DynamicUser range"},
	})

	checkIDs(t, "gidKnown", tables.gidKnown, []idCase{
		{0, true, "passwd", "root is a group in /etc/group"},
		{4, true, "passwd", "adm is a group in /etc/group"},
		{42, true, "passwd", "shadow is a group in /etc/group"},
		{998, false, "unknown", "svc's primary gid, which no group in /etc/group claims"},
		{100005, true, "subid", "inside alice's subordinate gid range, named through /etc/passwd"},
		{300050, true, "subid", "inside adm's subordinate gid range, named through /etc/group"},
		{400000, false, "unknown", "a subgid line naming neither a user nor a group is ignored"},
		{600025, true, "subid", "dupshadow shares gid 42 with shadow; the SECOND name of a gid still names its range"},
		{500000, false, "unknown", "a zero count is an empty range"},
		{61184, true, "dynamic", "the DynamicUser range covers gids too"},
		{65519, true, "dynamic", "the last id of the DynamicUser range"},
		{65520, false, "unknown", "one above the DynamicUser range"},
	})
}

// A file that cannot be read contributes no ids and is reported under its
// own path: the other three files still answer, so one denied /etc/subuid
// never turns a known passwd account into an unknown owner.
func TestIDTablesFileFailuresAreIsolated(t *testing.T) {
	a := idDouble()
	a.fails = map[string]error{"/etc/subuid": unix.EACCES}
	delete(a.files, "/etc/subgid")

	tables, failures := loadIDTables(a)

	checkIDs(t, "uidKnown", tables.uidKnown, []idCase{
		{1000, true, "passwd", "a denied /etc/subuid leaves the passwd answers intact"},
		{61184, true, "dynamic", "the dynamic range needs no file at all"},
		{100005, false, "unknown", "the denied file contributed no ranges"},
	})
	checkIDs(t, "gidKnown", tables.gidKnown, []idCase{
		{4, true, "passwd", "/etc/group was read"},
		{100005, false, "unknown", "the absent /etc/subgid contributed no ranges"},
	})

	paths := make([]string, 0, len(failures))
	for p := range failures {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	if want := []string{"/etc/subgid", "/etc/subuid"}; !slices.Equal(paths, want) {
		t.Fatalf("failures cover %v, want %v", paths, want)
	}
	if e := failures["/etc/subuid"]; e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/subuid: ") {
		t.Errorf("/etc/subuid: %+v, want a denied envelope whose reason names the path", e)
	}
	// A file that is not there is reported as absent, not as denied or as an
	// error: the caller tells "this host has no sub-id delegation" from "this
	// host would not let me look" by the envelope's status.
	if e := failures["/etc/subgid"]; e.Status != facts.StatusAbsent || !strings.HasPrefix(e.Reason, "/etc/subgid: ") {
		t.Errorf("/etc/subgid: %+v, want an absent envelope whose reason names the path", e)
	}
}

// A read that hit the size cap contributes what it did read and says so
// under that path: the accounts before the cap are real accounts, and the
// entry is what stops the caller reading "unknown" as "nothing on this host
// claims this file" when the truth is that the file was never fully read.
func TestIDTablesTruncatedFileIsReported(t *testing.T) {
	a := idDouble()
	a.truncated = map[string]bool{"/etc/passwd": true}

	tables, failures := loadIDTables(a)

	checkIDs(t, "uidKnown", tables.uidKnown, []idCase{
		{1000, true, "passwd", "what was read before the cap is still an account"},
	})
	e, ok := failures["/etc/passwd"]
	if !ok {
		t.Fatalf("a truncated /etc/passwd went unreported: %v", failures)
	}
	// R70: a short read is not a failed one. The entry is an ok envelope
	// carrying Truncated, which the caller forwards rather than degrading on.
	if e.Status != facts.StatusOK || !e.Truncated || !strings.HasPrefix(e.Reason, "/etc/passwd: ") {
		t.Errorf("/etc/passwd: %+v, want an ok+truncated envelope whose reason names the path", e)
	}
}

// An unreadable /etc/passwd leaves the numeric sub-id rows and the dynamic
// range answering: the tables degrade one file at a time.
func TestIDTablesWithoutPasswd(t *testing.T) {
	a := idDouble()
	a.fails = map[string]error{"/etc/passwd": unix.EACCES}

	tables, failures := loadIDTables(a)

	checkIDs(t, "uidKnown", tables.uidKnown, []idCase{
		{1000, false, "unknown", "no passwd row was read"},
		{100005, false, "unknown", "alice's row cannot be resolved without /etc/passwd"},
		{200000, true, "subid", "a numeric first field needs no name lookup"},
		{61184, true, "dynamic", "the dynamic range is a constant"},
	})
	if e, ok := failures["/etc/passwd"]; !ok || e.Status != facts.StatusDenied {
		t.Errorf("/etc/passwd: %+v (present %v), want a denied envelope", e, ok)
	}
}

// dynamicUIDMin/Max are systemd's DynamicUser range and both ends are
// inclusive; the two tables read the same pair.
func TestIDTablesDynamicRangeBounds(t *testing.T) {
	if dynamicUIDMin >= dynamicUIDMax {
		t.Fatalf("dynamic range is empty: [%d, %d]", dynamicUIDMin, dynamicUIDMax)
	}
	tables, _ := loadIDTables(&fsAccess{})
	for _, id := range []uint32{dynamicUIDMin, dynamicUIDMax} {
		if known, class := tables.uidKnown(id); !known || class != "dynamic" {
			t.Errorf("uidKnown(%d) = (%v, %q) on a host with no id files at all", id, known, class)
		}
		if known, class := tables.gidKnown(id); !known || class != "dynamic" {
			t.Errorf("gidKnown(%d) = (%v, %q) on a host with no id files at all", id, known, class)
		}
	}
}
