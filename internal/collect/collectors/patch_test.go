//go:build linux

package collectors

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The host paths the patch collector works from, spelled here as literals so
// a test asserts against the real path rather than against whatever the
// collector happens to have named its constant. Ruling J-20: the reboot flag
// lives under /run — /var/run is a SYMLINK to it on every supported family,
// the read primitive refuses a symlinked component outright (ErrSymlink →
// error), and one error envelope flips run.complete.
const (
	testDpkgStatus   = "/var/lib/dpkg/status"
	testDpkgLog      = "/var/log/dpkg.log"
	testAptListsMain = "/var/lib/apt/lists/archive.example.org_ubuntu_dists_jammy_main_binary-amd64_Packages"
	testAptListsSec  = "/var/lib/apt/lists/archive.example.org_ubuntu_dists_jammy-security_main_binary-amd64_Packages"
	// The compressed spellings an Acquire::GzipIndexes host keeps INSTEAD of
	// the bare ones — what the official debian and ubuntu images ship
	// (Ruling J-45). Such a host has no periodic stamp either, since
	// apt-daily never runs in a container.
	testAptListsMainGz  = "/var/lib/apt/lists/archive.example.org_ubuntu_dists_jammy_main_binary-amd64_Packages.gz"
	testAptListsSecGz   = "/var/lib/apt/lists/archive.example.org_ubuntu_dists_jammy-security_main_binary-amd64_Packages.gz"
	testAptInRelease    = "/var/lib/apt/lists/archive.example.org_ubuntu_dists_jammy_InRelease"
	testAptSecInRelease = "/var/lib/apt/lists/archive.example.org_ubuntu_dists_jammy-security_InRelease"
	testAptAutoUpgrades = "/etc/apt/apt.conf.d/20auto-upgrades"
	testRunReboot       = "/run/reboot-required"
	testRunRebootPkgs   = "/run/reboot-required.pkgs"
	testVarRunReboot    = "/var/run/reboot-required"
	testVarRunPkgs      = "/var/run/reboot-required.pkgs"
	testDnfCacheDir     = "/var/cache/dnf"
	testDnfRepomd       = "/var/cache/dnf/baseos-9f2c1a4b7d3e/repodata/repomd.xml"
	testDnfAutomatic    = "/etc/dnf/automatic.conf"
)

// testPatchCollectedAt is the run header's single clock reading (R54). Every
// age this collector derives is CollectedAt − mtime (Ruling J-21), so the
// expected values below are exact rather than approximate — an
// implementation that reached for time.Now() would produce an age of years,
// not the seeded hour.
const testPatchCollectedAt = "2026-09-08T06:00:00Z"

func testPatchNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, testPatchCollectedAt)
	if err != nil {
		t.Fatalf("parse %s: %v", testPatchCollectedAt, err)
	}
	return now.UTC()
}

// cmdKey renders a declared command the way fsAccess keys its canned
// outcomes — the same join collect.commandString uses for --list-actions and
// for the run header. Ruling J-23: every test key below is built by passing
// the collector's OWN command value through here, so the declaration, the
// run and the fixture key cannot drift apart (a hand-typed key would hide a
// changed argument instead of failing).
func cmdKey(c collect.Command) string {
	return strings.TrimSpace(c.Path + " " + strings.Join(c.Args, " "))
}

// recordingAccess wraps the shared double with a log of every command that
// actually reached Run. Ruling J-31 needs to assert a command was NOT run,
// which no assertion on the resulting facts can prove on its own: a
// container's `needs-restarting -r` could answer "no reboot needed" for the
// wrong reason and look identical to a skipped probe.
type recordingAccess struct {
	*fsAccess
	ran []string
}

func (r *recordingAccess) Run(ctx context.Context, c collect.Command) collect.Output {
	r.ran = append(r.ran, cmdKey(c))
	return r.fsAccess.Run(ctx, c)
}

func (r *recordingAccess) didRun(c collect.Command) bool {
	return slices.Contains(r.ran, cmdKey(c))
}

// patchAccess seeds every map fsAccess exposes, so a test may assign into
// any of them after construction without tripping a nil-map panic (the
// R226/I-20 lesson).
func patchAccess(files map[string]string, cmds map[string]cmdResult) *recordingAccess {
	if files == nil {
		files = map[string]string{}
	}
	if cmds == nil {
		cmds = map[string]cmdResult{}
	}
	return &recordingAccess{fsAccess: &fsAccess{
		files:     files,
		cmds:      cmds,
		fails:     map[string]error{},
		dirs:      map[string]bool{},
		stats:     map[string]statResult{},
		truncated: map[string]bool{},
		modes:     map[string]uint32{},
		writable:  map[string]bool{},
	}}
}

// patchAptAccess is an apt host: the dpkg database exists (so the manager is
// apt) and the metadata cache holds a main Packages list, optionally
// alongside the -security one that decides security_metadata_available
// (Ruling J-26 — a FILE-based definition). A cache entry is seeded in both
// dirs (so Glob names it) and stats (so Stat answers with the modification
// time the age is derived from); its content is never read.
func patchAptAccess(cacheMtime time.Time, withSecurityList bool, cmds map[string]cmdResult) *recordingAccess {
	lists := []string{testAptListsMain}
	if withSecurityList {
		lists = append(lists, testAptListsSec)
	}
	return patchAptAccessLists(cacheMtime, lists, cmds)
}

// patchAptAccessLists is patchAptAccess over an explicit set of list-file
// names, so a test can describe a cache the way a real host holds it — bare
// indexes, compressed ones, or an InRelease with no Packages file at all.
func patchAptAccessLists(cacheMtime time.Time, lists []string, cmds map[string]cmdResult) *recordingAccess {
	a := patchAccess(map[string]string{
		testDpkgStatus:      "dpkg.status.sample",
		testDpkgLog:         "dpkg.log.sample",
		testAptAutoUpgrades: "apt.20auto-upgrades",
	}, cmds)
	for _, p := range lists {
		a.dirs[p] = true
		a.stats[p] = statResult{mode: 0o644, kind: "regular", mtime: cacheMtime}
	}
	return a
}

// patchDnfAccess is a dnf host: no dpkg database, a /var/cache/dnf directory
// and one cached repomd.xml whose content decides whether an updateinfo
// (security) channel exists at all.
func patchDnfAccess(cacheMtime time.Time, repomd string, cmds map[string]cmdResult) *recordingAccess {
	a := patchAccess(map[string]string{
		testDnfRepomd:    repomd,
		testDnfAutomatic: "dnf.automatic.conf",
	}, cmds)
	a.dirs[testDnfCacheDir] = true
	a.stats[testDnfCacheDir] = statResult{mode: 0o755, kind: "dir"}
	a.stats[testDnfRepomd] = statResult{mode: 0o644, kind: "regular", mtime: cacheMtime}
	return a
}

// buildPatch runs the patch collector under the guard with the run header
// already carrying the two things this collector reads from it: the single
// clock reading every age is derived from (R54/J-21) and the container kind
// the os collector fills in (J-31; All() is name-sorted, so os runs first).
func buildPatch(t *testing.T, a collect.Access, collectedAt, container string) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	b.Header().CollectedAt = collectedAt
	b.Header().Env.Container = container
	c := collectorNamed(t, "patch")
	b.Begin("patch")
	g := collect.Guard(a, c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("patch: %v", err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("patch touched undeclared targets: %v", v)
	}
	return b
}

// findRecord returns the first record in a list whose field equals want.
func findRecord(t *testing.T, list []any, field, want string) map[string]any {
	t.Helper()
	for _, v := range list {
		rec, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("list entry %#v is not a record", v)
		}
		if rec[field] == want {
			return rec
		}
	}
	t.Fatalf("no record with %s = %q in %#v", field, want, list)
	return nil
}

// assertCacheLeavesAgree pins the one pair of answers that can never both be
// true: a snapshot must not say "there is no package metadata cache at all"
// and "this host has a security channel" at the same time. The two are
// derived from the same listing, so a presence test narrower than the
// channel test makes the snapshot contradict itself (review LOW 1).
func assertCacheLeavesAgree(t *testing.T, b *collect.Builder) {
	t.Helper()
	age := env(t, b, "patch.metadata_age_s")
	sec := env(t, b, "patch.security_metadata_available")
	if age.Status == facts.StatusAbsent && sec.Status == facts.StatusOK && sec.Value == true {
		t.Errorf("contradiction: metadata_age_s says there is no cache (%+v) while security_metadata_available found a channel in it (%+v)", age, sec)
	}
}

// apt: the newest Packages list stamps metadata_age_s; `apt-get -s upgrade`
// lists two pending upgrades, exactly one of which comes from a -security
// origin, so pending_security_count is 1 — the count is derived from the
// ORIGIN of each simulated upgrade, never from the number of lines.
func TestPatchAptSecurityCountFromSimulation(t *testing.T) {
	now := testPatchNow(t)
	a := patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.security"},
		cmdKey(aptMarkHoldCmd): {file: "apt-mark.showhold"},
	})
	b := buildPatch(t, a, testPatchCollectedAt, "none")

	if e := env(t, b, "patch.manager"); e.Status != facts.StatusOK || e.Value != "apt" {
		t.Fatalf("manager %+v, want ok apt", e)
	}
	sec := env(t, b, "patch.security_metadata_available")
	if sec.Status != facts.StatusOK || sec.Value != true {
		t.Errorf("security_metadata_available %+v, want ok true", sec)
	}
	if sec.Source == nil || sec.Source.Path != testAptListsSec {
		t.Errorf("security_metadata_available must cite the -security list that proved it, not %+v", sec.Source)
	}
	if e := env(t, b, "patch.pending_security_count"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Errorf("pending_security_count %+v, want ok 1", e)
	}

	ups := okList(t, b, "patch.pending_updates")
	if len(ups) != 2 {
		t.Fatalf("pending_updates has %d records, want 2: %#v", len(ups), ups)
	}
	ssl := findRecord(t, ups, "name", "libssl3")
	if ssl["current"] != "3.0.2-0ubuntu1.15" || ssl["candidate"] != "3.0.2-0ubuntu1.18" {
		t.Errorf("libssl3 versions %+v", ssl)
	}
	if o, _ := ssl["origin"].(string); !strings.Contains(o, "jammy-security") {
		t.Errorf("libssl3 origin %+v, want the -security suite", ssl)
	}
	if len(ssl) != 4 {
		t.Errorf("record %+v has %d fields, want exactly {name, current, candidate, origin}", ssl, len(ssl))
	}
	// The architecture apt appends in brackets is not part of the origin.
	if tz := findRecord(t, ups, "name", "tzdata"); tz["origin"] != "Ubuntu:22.04/jammy-updates" {
		t.Errorf("tzdata origin %+v, want the bare suite", tz)
	}
	// The `Conf` lines of the same simulation must never be counted as
	// upgrades: a parser that took every line mentioning a version would
	// report four records and two security updates.
	if held := okList(t, b, "patch.held_packages"); len(held) != 2 || held[0] != "libssl3" || held[1] != "tzdata" {
		t.Errorf("held_packages %#v, want the two showhold names sorted", held)
	}
	s := setting(t, b, "patch.auto_update.enabled")
	if s.Persisted == nil || s.Persisted.Status != facts.StatusOK || s.Persisted.Value != true {
		t.Errorf("auto_update persisted %+v, want ok true from 20auto-upgrades", s.Persisted)
	}
	if s.Runtime == nil || s.Runtime.Status != facts.StatusUnsupported {
		t.Errorf("auto_update runtime %+v: both sides are always set and the runtime side is not probed", s.Runtime)
	}
	if w := b.Worst("patch"); w != facts.StatusOK {
		t.Errorf("Worst = %s, want ok", w)
	}
}

// Ruling J-21: the age is CollectedAt − ReadMeta.ModTime, taken from the run
// header's clock and never from time.Now(); the same seeds render the same
// bytes twice. An unseeded modification time yields no age at all rather
// than a fabricated one.
func TestPatchMetadataAgeUsesCollectedAtAndModTime(t *testing.T) {
	now := testPatchNow(t)
	cmds := map[string]cmdResult{cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"}}

	b := buildPatch(t, patchAptAccess(now.Add(-3600*time.Second), true, cmds), testPatchCollectedAt, "none")
	if e := env(t, b, "patch.metadata_age_s"); e.Status != facts.StatusOK || e.Value != 3600 {
		t.Fatalf("metadata_age_s %+v, want ok 3600 (CollectedAt − mtime)", e)
	}
	// The header clock, not the wall clock: a run whose CollectedAt is one
	// day later sees the same file as a day older.
	later := now.Add(24 * time.Hour).Format(time.RFC3339)
	b2 := buildPatch(t, patchAptAccess(now.Add(-3600*time.Second), true, cmds), later, "none")
	if e := env(t, b2, "patch.metadata_age_s"); e.Value != 3600+86400 {
		t.Errorf("metadata_age_s with a later CollectedAt = %+v, want 90000", e)
	}

	// Same input, same bytes.
	first := encodeNoEscape(t, b.Tree())
	again := encodeNoEscape(t, buildPatch(t, patchAptAccess(now.Add(-3600*time.Second), true, cmds), testPatchCollectedAt, "none").Tree())
	if !bytes.Equal(first, again) {
		t.Errorf("two runs over the same seeds differ:\n%s\n%s", first, again)
	}

	// An unseeded mtime is "not known" — never an invented age, and never a
	// silently absent leaf either.
	b3 := buildPatch(t, patchAptAccess(time.Time{}, true, cmds), testPatchCollectedAt, "none")
	if e := env(t, b3, "patch.metadata_age_s"); e.Status == facts.StatusOK {
		t.Errorf("metadata_age_s %+v: an unknown modification time must not produce an age", e)
	}
}

// dnf: `dnf --cacheonly check-update` exits 100 when updates are pending —
// success, never an error. Exit 0 means nothing is pending.
func TestPatchDnfExit100IsUpdatesNotError(t *testing.T) {
	now := testPatchNow(t)
	a := patchDnfAccess(now.Add(-2*time.Hour), "repomd.updateinfo.xml", map[string]cmdResult{
		cmdKey(dnfCheckUpdateCmd):  {file: "dnf.check-update.100", exitCode: 100},
		cmdKey(dnfUpdateinfoCmd):   {file: "dnf.updateinfo.list"},
		cmdKey(rpmQaCmd):           {file: "rpm.qa.sample"},
		cmdKey(needsRestartingCmd): {exitCode: 0},
	})
	b := buildPatch(t, a, testPatchCollectedAt, "none")

	if e := env(t, b, "patch.manager"); e.Value != "dnf" {
		t.Fatalf("manager %+v, want dnf", e)
	}
	ups := okList(t, b, "patch.pending_updates")
	if len(ups) != 2 {
		t.Fatalf("exit 100 must parse the rows, not fail: %d records %#v", len(ups), ups)
	}
	ssl := findRecord(t, ups, "name", "openssl")
	if ssl["candidate"] != "1:3.0.7-27.el9" || ssl["origin"] != "baseos" {
		t.Errorf("openssl row %+v", ssl)
	}
	if e := env(t, b, "patch.pending_security_count"); e.Status != facts.StatusOK || e.Value != 2 {
		t.Errorf("pending_security_count %+v, want ok 2 from updateinfo", e)
	}
	if e := env(t, b, "patch.metadata_age_s"); e.Status != facts.StatusOK || e.Value != 7200 {
		t.Errorf("metadata_age_s %+v, want ok 7200 from the repomd mtime", e)
	}
	if w := b.Worst("patch"); w != facts.StatusOK {
		t.Errorf("Worst = %s, want ok", w)
	}

	// Exit 0: nothing pending. Still ok, still an empty list, never an error.
	a0 := patchDnfAccess(now.Add(-2*time.Hour), "repomd.updateinfo.xml", map[string]cmdResult{
		cmdKey(dnfCheckUpdateCmd): {exitCode: 0},
		cmdKey(dnfUpdateinfoCmd):  {exitCode: 0},
		cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
	})
	b0 := buildPatch(t, a0, testPatchCollectedAt, "none")
	if ups := okList(t, b0, "patch.pending_updates"); len(ups) != 0 {
		t.Errorf("exit 0 means nothing pending: %#v", ups)
	}
	if e := env(t, b0, "patch.pending_security_count"); e.Status != facts.StatusOK || e.Value != 0 {
		t.Errorf("pending_security_count %+v, want ok 0 — updateinfo metadata exists and reported nothing", e)
	}
}

// Ruling J-26: a cache that EXISTS but carries no security channel makes
// pending_security_count UNSUPPORTED, never 0 — `dnf updateinfo list
// security` exits 0 with empty stdout both when there is no updateinfo
// metadata and when nothing is pending, so exit 0 alone is never evidence of
// "no security updates". The same file-based rule decides the apt side.
func TestPatchNoSecurityMetadataIsUnsupportedNotZero(t *testing.T) {
	now := testPatchNow(t)

	t.Run("dnf", func(t *testing.T) {
		a := patchDnfAccess(now.Add(-time.Hour), "repomd.nosecurity.xml", map[string]cmdResult{
			cmdKey(dnfCheckUpdateCmd): {file: "dnf.check-update.100", exitCode: 100},
			cmdKey(dnfUpdateinfoCmd):  {exitCode: 0}, // exits clean with nothing to say
			cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
		})
		b := buildPatch(t, a, testPatchCollectedAt, "none")
		if e := env(t, b, "patch.security_metadata_available"); e.Status != facts.StatusOK || e.Value != false {
			t.Errorf("security_metadata_available %+v, want ok false", e)
		}
		e := env(t, b, "patch.pending_security_count")
		if e.Status != facts.StatusUnsupported {
			t.Fatalf("pending_security_count %+v, want unsupported (never 0)", e)
		}
		if e.Value != nil {
			t.Errorf("an unsupported count carries no value: %+v", e)
		}
		// The cache itself exists, so the age is still an answer.
		if age := env(t, b, "patch.metadata_age_s"); age.Status != facts.StatusOK {
			t.Errorf("metadata_age_s %+v: the cache exists, only its security channel is missing", age)
		}
	})

	t.Run("apt", func(t *testing.T) {
		a := patchAptAccess(now.Add(-time.Hour), false, map[string]cmdResult{
			cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.security"},
		})
		b := buildPatch(t, a, testPatchCollectedAt, "none")
		if e := env(t, b, "patch.security_metadata_available"); e.Status != facts.StatusOK || e.Value != false {
			t.Errorf("security_metadata_available %+v, want ok false without a -security list", e)
		}
		if e := env(t, b, "patch.pending_security_count"); e.Status != facts.StatusUnsupported {
			t.Errorf("pending_security_count %+v, want unsupported — the simulation's origins cannot be trusted without the channel", e)
		}
		if age := env(t, b, "patch.metadata_age_s"); age.Status != facts.StatusOK {
			t.Errorf("metadata_age_s %+v: the main list is still a cache", age)
		}
	})
}

// Ruling J-25: NO metadata cache at all (a host that was never updated, a
// --read-only container) makes metadata_age_s AND pending_security_count
// both ABSENT, so U-64 reads MANUAL. The count must not be `unsupported`
// here: mergeSoft lets a single unsupported beat an absent, and the control
// would silently read NOT_APPLICABLE instead.
func TestPatchNoCacheIsAbsentOnBothLeaves(t *testing.T) {
	// The dnf half (review LOW 4): /var/cache/dnf exists, so the manager is
	// dnf, but it holds no repomd.xml — the same "never updated" shape the
	// apt half describes, reached through a different family.
	dnfEmpty := patchAccess(nil, map[string]cmdResult{
		cmdKey(dnfCheckUpdateCmd): {exitCode: 0},
		cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
	})
	dnfEmpty.dirs[testDnfCacheDir] = true
	dnfEmpty.stats[testDnfCacheDir] = statResult{mode: 0o755, kind: "dir"}

	shapes := []struct {
		name    string
		access  collect.Access
		manager string
	}{
		{"apt", patchAccess(map[string]string{testDpkgStatus: "dpkg.status.sample"}, map[string]cmdResult{
			cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
		}), "apt"},
		{"dnf", dnfEmpty, "dnf"},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			b := buildPatch(t, s.access, testPatchCollectedAt, "none")

			if e := env(t, b, "patch.manager"); e.Value != s.manager {
				t.Fatalf("manager %+v, want %s", e, s.manager)
			}
			age := env(t, b, "patch.metadata_age_s")
			if age.Status != facts.StatusAbsent {
				t.Errorf("metadata_age_s %+v, want absent", age)
			}
			count := env(t, b, "patch.pending_security_count")
			if count.Status != facts.StatusAbsent {
				t.Fatalf("pending_security_count %+v, want absent — unsupported would read NOT_APPLICABLE, not MANUAL", count)
			}
			if age.Reason == "" || count.Reason == "" {
				t.Errorf("both leaves must say why: %+v / %+v", age, count)
			}
			assertCacheLeavesAgree(t, b)
			if w := b.Worst("patch"); w != facts.StatusOK {
				t.Errorf("Worst = %s, want ok — a host that was never updated is not a collection failure", w)
			}
		})
	}
}

// Ruling J-45: a host with Acquire::GzipIndexes "true" — what the official
// debian and ubuntu images ship in /etc/apt/apt.conf.d/docker-gzip-indexes —
// keeps only the COMPRESSED indexes and has no periodic stamp, because
// apt-daily never runs there. Seconds after a successful `apt-get update`
// that host must not be told it "may never have been updated": every index
// spelling is cache evidence, and the newest of them is the age anchor.
func TestPatchCompressedIndexesCountAsCache(t *testing.T) {
	now := testPatchNow(t)
	a := patchAptAccessLists(now.Add(-1800*time.Second), []string{
		testAptInRelease, testAptListsMainGz, testAptSecInRelease, testAptListsSecGz,
	}, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.security"},
	})
	b := buildPatch(t, a, testPatchCollectedAt, "none")

	age := env(t, b, "patch.metadata_age_s")
	if age.Status != facts.StatusOK || age.Value != 1800 {
		t.Fatalf("metadata_age_s %+v, want ok 1800 — a compressed index is a cache", age)
	}
	sec := env(t, b, "patch.security_metadata_available")
	if sec.Status != facts.StatusOK || sec.Value != true {
		t.Errorf("security_metadata_available %+v, want ok true from the -security files", sec)
	}
	if e := env(t, b, "patch.pending_security_count"); e.Status != facts.StatusOK || e.Value != 1 {
		t.Errorf("pending_security_count %+v, want ok 1 from the simulation", e)
	}
	assertCacheLeavesAgree(t, b)
	if w := b.Worst("patch"); w != facts.StatusOK {
		t.Errorf("Worst = %s, want ok", w)
	}

	// An InRelease with no index beside it is still evidence that this host
	// talked to a repository, so it anchors the age rather than reading as
	// "never updated".
	only := patchAptAccessLists(now.Add(-600*time.Second), []string{testAptInRelease}, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
	})
	b2 := buildPatch(t, only, testPatchCollectedAt, "none")
	if e := env(t, b2, "patch.metadata_age_s"); e.Status != facts.StatusOK || e.Value != 600 {
		t.Errorf("metadata_age_s %+v, want ok 600", e)
	}
	assertCacheLeavesAgree(t, b2)
}

// Ruling J-44: a capture that hit the 8 MiB output cap yields a count derived
// from a PARTIAL stream, and pending_security_count is a judged leaf — an
// undercount published as a complete `ok` reads as PASS. The truncation flag
// R70 exists for must reach the count, exactly as it reaches its dnf twin and
// the pending_updates list beside it.
func TestPatchTruncatedSimulationMarksTheCount(t *testing.T) {
	now := testPatchNow(t)
	a := patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.security", truncated: true},
	})
	b := buildPatch(t, a, testPatchCollectedAt, "none")

	count := env(t, b, "patch.pending_security_count")
	if count.Status != facts.StatusOK {
		t.Fatalf("pending_security_count %+v, want ok", count)
	}
	if !count.Truncated {
		t.Errorf("pending_security_count %+v: a count taken from a capped capture must be marked truncated", count)
	}
	if ups := env(t, b, "patch.pending_updates"); !ups.Truncated {
		t.Errorf("pending_updates %+v must be marked truncated too", ups)
	}

	// The dnf twin already carries the flag; assert it so the two families
	// cannot drift apart again.
	d := patchDnfAccess(now.Add(-time.Hour), "repomd.updateinfo.xml", map[string]cmdResult{
		cmdKey(dnfCheckUpdateCmd): {file: "dnf.check-update.100", exitCode: 100},
		cmdKey(dnfUpdateinfoCmd):  {file: "dnf.updateinfo.list", truncated: true},
		cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
	})
	if e := env(t, buildPatch(t, d, testPatchCollectedAt, "none"), "patch.pending_security_count"); !e.Truncated {
		t.Errorf("dnf pending_security_count %+v must be marked truncated", e)
	}
}

// R220 again: this collector needs no privilege and files every limitation as
// `unsupported`. A listing that cannot be produced is one more limitation —
// an error envelope there would rank worst and flip run.complete, breaking
// the collect-contract leg over a condition the collector already knows how
// to describe (review LOW 2).
func TestPatchGlobFailureIsUnsupportedNotError(t *testing.T) {
	for _, s := range []struct {
		name   string
		access *recordingAccess
	}{
		{"apt", patchAptAccess(testPatchNow(t).Add(-time.Hour), true, map[string]cmdResult{
			cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
		})},
		{"dnf", patchDnfAccess(testPatchNow(t).Add(-time.Hour), "repomd.updateinfo.xml", map[string]cmdResult{
			cmdKey(dnfCheckUpdateCmd): {exitCode: 0},
			cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
		})},
	} {
		t.Run(s.name, func(t *testing.T) {
			s.access.globErr = errors.New("syntax error in pattern")
			b := buildPatch(t, s.access, testPatchCollectedAt, "none")
			for _, k := range []string{"patch.metadata_age_s", "patch.security_metadata_available", "patch.pending_security_count"} {
				if e := env(t, b, k); e.Status != facts.StatusUnsupported {
					t.Errorf("%s %+v, want unsupported", k, e)
				}
			}
			if w := b.Worst("patch"); w != facts.StatusOK {
				t.Fatalf("Worst = %s, want ok — an unlistable cache must not flip run.complete", w)
			}
		})
	}
}

// Ruling J-20: reboot detection consults /run/reboot-required and
// /run/reboot-required.pkgs. /var/run is a symlink to /run, the read
// primitive refuses a symlinked component (ErrSymlink → error) and one error
// envelope flips run.complete — so the /var/run spellings must appear
// nowhere, and a host that has only those must NOT report a reboot.
func TestPatchRebootRequiredUsesRunNotVarRun(t *testing.T) {
	reads := collectorNamed(t, "patch").Declare.Reads
	for _, want := range []string{testRunReboot, testRunRebootPkgs} {
		if !slices.Contains(reads, want) {
			t.Errorf("%s is not declared: %v", want, reads)
		}
	}
	for _, r := range reads {
		if strings.HasPrefix(r, "/var/run/") {
			t.Errorf("%s is under /var/run, a symlink the read primitive refuses", r)
		}
	}

	// A double seeded with the /var/run spellings ONLY: the collector must
	// never reach them, so the fact stays false.
	a := patchAptAccess(testPatchNow(t).Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
	})
	a.stats[testVarRunReboot] = statResult{mode: 0o644, kind: "regular"}
	a.stats[testVarRunPkgs] = statResult{mode: 0o644, kind: "regular"}
	b := buildPatch(t, a, testPatchCollectedAt, "none")
	if e := env(t, b, "patch.reboot_required"); e.Status != facts.StatusOK || e.Value != false {
		t.Fatalf("reboot_required %+v, want ok false — only the /var/run spellings exist", e)
	}

	// The /run spelling is the one that answers.
	a2 := patchAptAccess(testPatchNow(t).Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
	})
	a2.stats[testRunReboot] = statResult{mode: 0o644, kind: "regular"}
	b2 := buildPatch(t, a2, testPatchCollectedAt, "none")
	e := env(t, b2, "patch.reboot_required")
	if e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("reboot_required %+v, want ok true from %s", e, testRunReboot)
	}
	if e.Source == nil || e.Source.Path != testRunReboot {
		t.Errorf("reboot_required must cite the file it found: %+v", e.Source)
	}
}

// needs-restarting is not installed by default on the rhel family, so its
// absence is an environment limitation (unsupported), never a finding: exit
// 1 means "reboot needed", exit 0 means "no reboot needed", and a binary
// that never ran means neither.
func TestPatchRebootRequiredShapes(t *testing.T) {
	now := testPatchNow(t)
	base := map[string]cmdResult{
		cmdKey(dnfCheckUpdateCmd): {exitCode: 0},
		cmdKey(dnfUpdateinfoCmd):  {exitCode: 0},
		cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
	}
	shapes := []struct {
		name    string
		outcome *cmdResult
		status  facts.Status
		value   any
	}{
		{"absent", nil, facts.StatusUnsupported, nil},
		{"exit1", &cmdResult{exitCode: 1}, facts.StatusOK, true},
		{"exit0", &cmdResult{exitCode: 0}, facts.StatusOK, false},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			cmds := map[string]cmdResult{}
			for k, v := range base {
				cmds[k] = v
			}
			if s.outcome != nil {
				cmds[cmdKey(needsRestartingCmd)] = *s.outcome
			}
			a := patchDnfAccess(now.Add(-time.Hour), "repomd.updateinfo.xml", cmds)
			b := buildPatch(t, a, testPatchCollectedAt, "none")
			e := env(t, b, "patch.reboot_required")
			if e.Status != s.status || e.Value != s.value {
				t.Fatalf("reboot_required %+v, want %s %v", e, s.status, s.value)
			}
			if w := b.Worst("patch"); w != facts.StatusOK {
				t.Errorf("Worst = %s, want ok", w)
			}
		})
	}
}

// Ruling J-31: inside a container the host kernel's reboot state is not this
// namespace's business — reboot_required is unsupported and needs-restarting
// is never run at all. Asserting only on the fact would pass for the wrong
// reason (a container where the command happens to exit 0), so the call log
// is the assertion.
func TestPatchRebootRequiredInContainerSkipsCommand(t *testing.T) {
	now := testPatchNow(t)
	a := patchDnfAccess(now.Add(-time.Hour), "repomd.updateinfo.xml", map[string]cmdResult{
		cmdKey(dnfCheckUpdateCmd):  {exitCode: 0},
		cmdKey(dnfUpdateinfoCmd):   {exitCode: 0},
		cmdKey(rpmQaCmd):           {file: "rpm.qa.sample"},
		cmdKey(needsRestartingCmd): {exitCode: 1}, // would say "reboot needed"
	})
	b := buildPatch(t, a, testPatchCollectedAt, "docker")

	e := env(t, b, "patch.reboot_required")
	if e.Status != facts.StatusUnsupported {
		t.Fatalf("reboot_required %+v, want unsupported in a container", e)
	}
	if !strings.Contains(e.Reason, "container") {
		t.Errorf("reason %q must name the container", e.Reason)
	}
	if a.didRun(needsRestartingCmd) {
		t.Errorf("needs-restarting must never run in a container: %v", a.ran)
	}

	// An apt container does not consult the /run flag either — the same
	// namespace argument applies to the file.
	a2 := patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
	})
	a2.stats[testRunReboot] = statResult{mode: 0o644, kind: "regular"}
	b2 := buildPatch(t, a2, testPatchCollectedAt, "podman")
	if e := env(t, b2, "patch.reboot_required"); e.Status != facts.StatusUnsupported {
		t.Errorf("reboot_required %+v, want unsupported in a podman container", e)
	}
}

// packages.installed comes from the package database — the dpkg status file
// or `rpm -qa` — and never from a daemon (D14). Records are sorted by (name,
// arch) so the same host renders the same bytes; a package that is merely
// configured-but-removed is not installed.
func TestPatchPackagesInstalled(t *testing.T) {
	now := testPatchNow(t)

	t.Run("dpkg", func(t *testing.T) {
		a := patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
			cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
		})
		b := buildPatch(t, a, testPatchCollectedAt, "none")
		got := okList(t, b, "packages.installed")
		want := [][3]string{
			{"base-files", "12ubuntu4.6", "amd64"},
			{"libssl3", "3.0.2-0ubuntu1.18", "amd64"},
			{"libssl3", "3.0.2-0ubuntu1.18", "i386"},
		}
		assertPackages(t, got, want)
	})

	t.Run("rpm", func(t *testing.T) {
		a := patchDnfAccess(now.Add(-time.Hour), "repomd.updateinfo.xml", map[string]cmdResult{
			cmdKey(dnfCheckUpdateCmd): {exitCode: 0},
			cmdKey(dnfUpdateinfoCmd):  {exitCode: 0},
			cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
		})
		b := buildPatch(t, a, testPatchCollectedAt, "none")
		assertPackages(t, okList(t, b, "packages.installed"), [][3]string{
			{"basesystem", "11-13.el9", "noarch"},
			{"openssl", "1:3.0.7-27.el9", "i686"},
			{"openssl", "1:3.0.7-27.el9", "x86_64"},
		})
	})

	// Ruling J-23: the format the declaration carries must hold the LITERAL
	// backslash escapes rpm expands itself. A real tab or newline would split
	// the --list-actions row and put a newline in every evidence Source.Cmd.
	t.Run("format", func(t *testing.T) {
		var declared *collect.Command
		for _, c := range collectorNamed(t, "patch").Declare.Commands {
			if c.Path == rpmQaCmd.Path && slices.Equal(c.Args, rpmQaCmd.Args) {
				declared = &c
			}
		}
		if declared == nil {
			t.Fatalf("rpm -qa is not declared: %+v", collectorNamed(t, "patch").Declare.Commands)
		}
		if strings.ContainsAny(rpmQaFormat, "\t\n\r") {
			t.Errorf("rpmQaFormat %q holds a real control byte; rpm expands the escapes itself", rpmQaFormat)
		}
		if !strings.Contains(rpmQaFormat, `\t`) || !strings.Contains(rpmQaFormat, `\n`) {
			t.Errorf("rpmQaFormat %q must carry the literal backslash escapes", rpmQaFormat)
		}
		if strings.ContainsAny(cmdKey(rpmQaCmd), "\t\n\r") {
			t.Errorf("the rendered command %q spans more than one line", cmdKey(rpmQaCmd))
		}
	})
}

func assertPackages(t *testing.T, got []any, want [][3]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("packages.installed has %d records, want %d: %#v", len(got), len(want), got)
	}
	for i, w := range want {
		rec, ok := got[i].(map[string]any)
		if !ok {
			t.Fatalf("record %d is %#v, not a record", i, got[i])
		}
		if rec["name"] != w[0] || rec["version"] != w[1] || rec["arch"] != w[2] {
			t.Errorf("record %d = %+v, want %v", i, rec, w)
		}
		if len(rec) != 3 {
			t.Errorf("record %d has %d fields, want exactly {name, version, arch}: %+v", i, len(rec), rec)
		}
	}
}

// Ruling J-24: a command that hits its Timeout is `unsupported` like any
// other environment limitation, but its reason NAMES the timeout — a slow
// host must never be mistaken for a host with nothing to report.
func TestPatchCommandTimeoutIsUnsupportedWithReason(t *testing.T) {
	a := patchAptAccess(testPatchNow(t).Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {timedOut: true, exitCode: -1},
	})
	b := buildPatch(t, a, testPatchCollectedAt, "none")

	e := env(t, b, "patch.pending_updates")
	if e.Status != facts.StatusUnsupported {
		t.Fatalf("pending_updates %+v, want unsupported after a timeout", e)
	}
	if !strings.Contains(e.Reason, aptSimulateCmd.Timeout.String()) {
		t.Errorf("reason %q must name the %s timeout", e.Reason, aptSimulateCmd.Timeout)
	}
	if c := env(t, b, "patch.pending_security_count"); c.Status != facts.StatusUnsupported {
		t.Errorf("pending_security_count %+v: a timed-out simulation counts nothing", c)
	}
	if w := b.Worst("patch"); w != facts.StatusOK {
		t.Errorf("Worst = %s, want ok — a slow host is not a collection failure", w)
	}

	// A command that simply is not installed carries its stderr instead.
	a2 := patchAptAccess(testPatchNow(t).Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {exitCode: 100, stderr: "E: Unable to correct problems\nsecond line\n"},
	})
	b2 := buildPatch(t, a2, testPatchCollectedAt, "none")
	e2 := env(t, b2, "patch.pending_updates")
	if e2.Status != facts.StatusUnsupported || e2.Reason != "E: Unable to correct problems" {
		t.Errorf("pending_updates %+v, want unsupported with the first stderr line", e2)
	}
}

// R220: every degraded shape leaves the collector "ok" and every registered
// key set — a key the snapshot lacks is `missing` → ERROR(missing_fact), and
// the collect-contract leg's `.run.complete == true` depends on it.
func TestPatchSetsEveryKeyOnEveryShape(t *testing.T) {
	now := testPatchNow(t)
	shapes := []struct {
		name      string
		access    collect.Access
		container string
	}{
		{"unknown-manager", patchAccess(nil, nil), "none"},
		{"apt-no-cache-no-commands", patchAccess(map[string]string{testDpkgStatus: "dpkg.status.sample"}, nil), "none"},
		{"apt-full", patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
			cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.security"},
			cmdKey(aptMarkHoldCmd): {file: "apt-mark.showhold"},
		}), "none"},
		{"dnf-no-commands", patchDnfAccess(now.Add(-time.Hour), "repomd.updateinfo.xml", nil), "none"},
		{"container", patchDnfAccess(now.Add(-time.Hour), "repomd.updateinfo.xml", nil), "lxc"},
	}
	registered := patchRegisteredKeys(t)
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			b := buildPatch(t, s.access, testPatchCollectedAt, s.container)
			if w := b.Worst("patch"); w != facts.StatusOK {
				t.Errorf("Worst = %s, want ok", w)
			}
			set := b.Keys("patch")
			for _, k := range registered {
				if !slices.Contains(set, k) {
					t.Errorf("%s was not set; a registered key the snapshot lacks is ERROR(missing_fact)", k)
				}
			}
		})
	}
	if len(registered) < 10 {
		t.Fatalf("the registry lists only %d patch keys: %v", len(registered), registered)
	}
}

// patchRegisteredKeys is every key the registry says this collector owns —
// asked of the registry rather than listed here, so a key added later is
// covered by the shape table above without editing it.
func patchRegisteredKeys(t *testing.T) []string {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	var out []string
	for _, e := range reg.Keys {
		if e.Collector == "patch" {
			out = append(out, e.Key)
		}
	}
	return out
}

// The unknown-manager shape is honest about what it could not determine and
// still publishes an inventory, empty rather than missing.
func TestPatchUnknownManagerIsUnsupportedNotEmpty(t *testing.T) {
	b := buildPatch(t, patchAccess(nil, nil), testPatchCollectedAt, "none")
	if e := env(t, b, "patch.manager"); e.Status != facts.StatusOK || e.Value != "unknown" {
		t.Fatalf("manager %+v, want ok unknown", e)
	}
	for _, k := range []string{"patch.metadata_age_s", "patch.pending_security_count", "patch.reboot_required", "patch.held_packages"} {
		if e := env(t, b, k); e.Status != facts.StatusUnsupported {
			t.Errorf("%s %+v, want unsupported", k, e)
		}
	}
	if pk := okList(t, b, "packages.installed"); len(pk) != 0 {
		t.Errorf("packages.installed %#v, want an empty list", pk)
	}
}

// days_since_last_install reads the dpkg log under the same header clock
// (Ruling J-21): the newest "status installed" line, never the file's own
// modification time and never time.Now().
func TestPatchDaysSinceLastInstall(t *testing.T) {
	now := testPatchNow(t)
	a := patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
	})
	b := buildPatch(t, a, testPatchCollectedAt, "none")
	// The newest install line is 2026-09-05 04:10:11; CollectedAt is
	// 2026-09-08T06:00:00Z — two whole days and change.
	if e := env(t, b, "patch.days_since_last_install"); e.Status != facts.StatusOK || e.Value != 3 {
		t.Fatalf("days_since_last_install %+v, want ok 3", e)
	}

	a2 := patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
	})
	a2.files[testDpkgLog] = "dpkg.log.no-install"
	b2 := buildPatch(t, a2, testPatchCollectedAt, "none")
	if e := env(t, b2, "patch.days_since_last_install"); e.Status != facts.StatusAbsent {
		t.Errorf("days_since_last_install %+v, want absent when the log records no install", e)
	}

	a3 := patchAptAccess(now.Add(-time.Hour), true, map[string]cmdResult{
		cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"},
	})
	delete(a3.files, testDpkgLog)
	b3 := buildPatch(t, a3, testPatchCollectedAt, "none")
	if e := env(t, b3, "patch.days_since_last_install"); e.Status != facts.StatusAbsent {
		t.Errorf("days_since_last_install %+v, want absent without a dpkg log", e)
	}
}

// C3: a configuration file that EXISTS but cannot be read is the answer for
// every value it could set — never the module's default. auto_update's
// persisted side carries the read's status, path-prefixed.
func TestPatchAutoUpdateShapes(t *testing.T) {
	now := testPatchNow(t)
	cmds := map[string]cmdResult{cmdKey(aptSimulateCmd): {file: "apt-get.s-upgrade.none"}}

	off := patchAptAccess(now.Add(-time.Hour), true, cmds)
	off.files[testAptAutoUpgrades] = "apt.20auto-upgrades.off"
	if s := setting(t, buildPatch(t, off, testPatchCollectedAt, "none"), "patch.auto_update.enabled"); s.Persisted.Value != false {
		t.Errorf(`persisted %+v, want false from Unattended-Upgrade "0"`, s.Persisted)
	}

	none := patchAptAccess(now.Add(-time.Hour), true, cmds)
	delete(none.files, testAptAutoUpgrades)
	if s := setting(t, buildPatch(t, none, testPatchCollectedAt, "none"), "patch.auto_update.enabled"); s.Persisted.Status != facts.StatusOK || s.Persisted.Value != false {
		t.Errorf("persisted %+v, want ok false when apt's periodic configuration says nothing", s.Persisted)
	}

	denied := patchAptAccess(now.Add(-time.Hour), true, cmds)
	denied.fails[testAptAutoUpgrades] = os.ErrPermission
	s := setting(t, buildPatch(t, denied, testPatchCollectedAt, "none"), "patch.auto_update.enabled")
	if s.Persisted.Status != facts.StatusDenied {
		t.Fatalf("persisted %+v, want denied — an unreadable file is never the default", s.Persisted)
	}
	if !strings.Contains(s.Persisted.Reason, testAptAutoUpgrades) {
		t.Errorf("reason %q must name the file", s.Persisted.Reason)
	}

	dnf := patchDnfAccess(now.Add(-time.Hour), "repomd.updateinfo.xml", map[string]cmdResult{
		cmdKey(dnfCheckUpdateCmd): {exitCode: 0},
		cmdKey(dnfUpdateinfoCmd):  {exitCode: 0},
		cmdKey(rpmQaCmd):          {file: "rpm.qa.sample"},
	})
	if s := setting(t, buildPatch(t, dnf, testPatchCollectedAt, "none"), "patch.auto_update.enabled"); s.Persisted.Value != true {
		t.Errorf("persisted %+v, want true from dnf-automatic's apply_updates = yes", s.Persisted)
	}
}
