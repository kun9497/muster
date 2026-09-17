//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The parser oracles (F-8 … F-10).
//
// Each of the four tests below reads the host the way the collector does —
// through collect.Host() under the collector's own guard — and asks the
// daemon that owns those bytes what IT thinks they say. A fixture can only
// prove that a parser still answers what it answered yesterday; only the
// daemon can prove the answer is right.
//
// Three rules hold for every pair:
//
//   - The oracle's own output is parsed HERE, by code this file owns, never
//     by the function under test. An oracle that shares a parser with the
//     parser it judges cannot disagree with it.
//   - Nothing is written, started, stopped or installed. Every command is a
//     query (`sshd -T`, `getent`, `findmnt`, `systemctl show`), run through
//     the same exec discipline the collectors use.
//   - A pair whose oracle binary is not on this machine skips, naming the
//     binary; that is the only skip an enabled run may produce, and the CI
//     job on the runner VM — which has all four — asserts there are none.
//     A binary that IS there and refuses to answer fails the pair: a daemon
//     that will not print its own configuration is a finding, not a gap.

// oracleEnabled gates every pair. The oracles talk to the host's real
// daemons, so they are opt-in: `go test ./...` on a developer's machine or
// in the ordinary CI job skips them, and the jobs that mean to run them set
// MUSTER_ORACLE=1.
func oracleEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("MUSTER_ORACLE") != "1" {
		t.Skip("the oracles compare muster with this host's own daemons; set MUSTER_ORACLE=1 to run them")
	}
}

// The oracle binaries, by absolute path — the same discipline the collectors
// follow (spec §8): no PATH lookup decides which program answers.
const (
	getentPath  = "/usr/bin/getent"
	findmntPath = "/usr/bin/findmnt"
)

// oracleBinary skips the pair when its oracle is not installed, naming the
// binary. That is the container case F-9 allows: a minimal init image ships
// no sshd, so the sshd pair has no oracle there and reports so rather than
// failing or, worse, passing on a comparison it never made.
func oracleBinary(t *testing.T, path string) string {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("oracle binary %s is not on this machine", path)
	}
	return path
}

// oracleOutput runs one oracle query and returns its stdout. The command goes
// through collect.RunCommand for the exec discipline only — absolute path, no
// shell, rebuilt environment, timeout, output cap — never through a guarded
// Access: the oracle commands are deliberately outside every collector's
// declaration, and asking a guard for them would be the violation it is meant
// to catch.
func oracleOutput(t *testing.T, path string, args ...string) []byte {
	t.Helper()
	line := strings.TrimSpace(path + " " + strings.Join(args, " "))
	out := collect.RunCommand(context.Background(), collect.Command{
		Path: path, Args: args, Timeout: 30 * time.Second, MaxOutput: 8 << 20,
	})
	switch {
	case out.Err != nil:
		t.Fatalf("%s could not be run: %v", line, out.Err)
	case out.TimedOut:
		t.Fatalf("%s timed out", line)
	case out.ExitCode != 0:
		t.Fatalf("%s exited %d: %s", line, out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	case out.Truncated:
		t.Fatalf("%s produced more output than the oracle reads", line)
	}
	return out.Stdout
}

// oracleLines splits a command's output into lines the way a reader would,
// without the production splitter: see the first rule above.
func oracleLines(b []byte) []string {
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

// --- sshd ---------------------------------------------------------------

// sshdOracleAliases folds the spellings OpenSSH itself treats as one value
// onto a single token, so the comparison is about the VALUE and not about
// which synonym each side happens to print. The map belongs to the test: it
// is what the oracle knows about the daemon's vocabulary, never a rule the
// parser has to follow.
//
// PermitRootLogin has two spellings of one setting, and the fold has to run
// on BOTH sides rather than one way from the file's word to the daemon's.
// `sshd -T` does not print the modern word: it prints whichever spelling its
// multistate table lists first, which on OpenSSH 9.6p1 (Ubuntu 24.04) is the
// deprecated "without-password" — measured, for every value:
//
//	file: without-password     -> sshd -T: without-password
//	file: prohibit-password    -> sshd -T: without-password
//	file: yes / no / forced-commands-only -> the same word back
//
// So a one-way map onto "prohibit-password" would report a mismatch on a host
// configured with either spelling, including the modern one the guides
// recommend. muster stores what the FILE says, which is right; the synonym is
// the daemon's presentation, and knowing that is the oracle's job. Every
// other value still has to match exactly.
var sshdOracleAliases = map[string]string{
	"without-password":  "prohibit-password",
	"prohibit-password": "prohibit-password",
}

// sshdOracleValue is one value in the vocabulary both sides are compared in.
// An unset Banner is the daemon's "none" — sshd prints the default, the file
// says nothing — so an empty value is compared as "none" rather than as a
// difference the administrator never made.
func sshdOracleValue(keyword, v string) string {
	if a, ok := sshdOracleAliases[strings.ToLower(v)]; ok {
		return a
	}
	if keyword == "banner" && strings.TrimSpace(v) == "" {
		return "none"
	}
	return v
}

// oracleSshdDump reads the "keyword value" lines `sshd -T` prints into a map,
// first line per keyword winning — the daemon's own dump order. It is a
// deliberate second implementation of what parseDaemonDump does.
func oracleSshdDump(stdout []byte) map[string]string {
	out := map[string]string{}
	for _, line := range oracleLines(stdout) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		k := strings.ToLower(f[0])
		if _, seen := out[k]; !seen {
			out[k] = f[1]
		}
	}
	return out
}

// TestOracleSshdConfig: what muster parsed out of sshd_config is what the
// daemon says it will use. Only keywords the FILE set are compared — a
// keyword the file leaves alone is the daemon's default, which muster does
// not claim to know — and the parse path is called directly, so the daemon's
// answer is the oracle rather than the other half of the method ladder.
func TestOracleSshdConfig(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, sshdT.Path)
	c := collectorNamed(t, "sshd")
	g := collect.Guard(collect.Host(), c)
	dump := oracleSshdDump(oracleOutput(t, bin, "-T"))
	compared := 0
	for _, o := range sshdOptions {
		e, found := parseSshdConfig(g, sshdConfigPath, o.keyword, 0)
		if !found || e.Status != facts.StatusOK {
			continue // the file did not set it, or the read failed: no claim to check
		}
		v, ok := e.Value.(string)
		if !ok {
			t.Errorf("sshd: %s: parser produced %#v, which is not a parsed value", o.keyword, e.Value)
			continue
		}
		want, listed := dump[o.keyword]
		if !listed {
			t.Errorf("sshd: %s: parser %q, sshd -T did not list the keyword", o.keyword, v)
			continue
		}
		compared++
		// Both sides go through the fold, and the message reports the RAW
		// words each side used — the folded token is the test's arithmetic,
		// not evidence anyone can act on.
		if !strings.EqualFold(sshdOracleValue(o.keyword, v), sshdOracleValue(o.keyword, want)) {
			t.Errorf("sshd: %s: parser %q, sshd -T %q", o.keyword, v, want)
		}
	}
	if v := g.Violations(); len(v) != 0 {
		t.Errorf("sshd oracle reached outside the collector's declaration: %v", v)
	}
	t.Logf("oracle sshd: compared %d", compared)
}

// --- accounts -----------------------------------------------------------

// oracleAccount is one account as both sides describe it: the five fields
// that are the account, without the password field (muster keeps only
// whether it defers to shadow, and getent never prints hash material).
type oracleAccount struct {
	name, home, shell string
	uid, gid          int
}

// oracleGroup is one group; members is the joined member list, so the whole
// row is a comparable map key.
type oracleGroup struct {
	name    string
	gid     int
	members string
}

// oracleGetentAccounts parses `getent passwd`. A row whose uid or gid is not
// a number is impossible from the name service, so it is kept with -1 and
// will simply not match any parser row.
func oracleGetentAccounts(stdout []byte) []oracleAccount {
	var out []oracleAccount
	for _, line := range oracleLines(stdout) {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		out = append(out, oracleAccount{
			name: f[0], uid: oracleInt(f[2]), gid: oracleInt(f[3]), home: f[5], shell: f[6],
		})
	}
	return out
}

// oracleGetentGroups parses `getent group`, applying the same trim and
// de-duplication of the member list the parser applies, so the comparison is
// about the fields and not about a trailing comma.
func oracleGetentGroups(stdout []byte) []oracleGroup {
	var out []oracleGroup
	for _, line := range oracleLines(stdout) {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		out = append(out, oracleGroup{name: f[0], gid: oracleInt(f[2]), members: oracleMembers(f[3])})
	}
	return out
}

// oracleMembers trims and de-duplicates a comma-separated member list,
// keeping list order, and joins it back into one comparable string.
func oracleMembers(field string) string {
	var kept []string
	seen := map[string]bool{}
	for _, m := range strings.Split(field, ",") {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		kept = append(kept, m)
	}
	return strings.Join(kept, ",")
}

func oracleInt(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return -1
	}
	return n
}

// oracleDynamic reports whether an id the name service has and the file does
// not is one systemd allocated for a DynamicUser= unit. Ubuntu 24.04 and the
// EL9 family ship `passwd: files systemd`, so getent legitimately lists
// accounts /etc/passwd never mentions — but only inside that range. Anything
// else getent knows and the file does not is a parser that dropped a row.
func oracleDynamic(id int) bool { return id >= dynamicUIDMin && id <= dynamicUIDMax }

// TestOracleAccounts: every row parsePasswd and parseGroup produced is a row
// the name service confirms, field for field, and every row the name service
// has that the parsers do not is a systemd dynamic allocation.
func TestOracleAccounts(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, getentPath)
	c := collectorNamed(t, "accounts")
	g := collect.Guard(collect.Host(), c)

	pdata, _, err := g.ReadFile(passwdPath, readLimit)
	if err != nil {
		t.Fatalf("read %s: %v", passwdPath, err)
	}
	gdata, _, err := g.ReadFile(groupPath, readLimit)
	if err != nil {
		t.Fatalf("read %s: %v", groupPath, err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("accounts oracle reached outside the collector's declaration: %v", v)
	}

	// passwd.
	users, _ := parsePasswd(pdata)
	wantUsers := map[oracleAccount]bool{}
	userByName := map[string]oracleAccount{}
	for _, a := range oracleGetentAccounts(oracleOutput(t, bin, "passwd")) {
		wantUsers[a] = true
		if _, dup := userByName[a.name]; !dup {
			userByName[a.name] = a
		}
	}
	gotUserNames := map[string]bool{}
	for _, r := range users {
		a := oracleAccount{name: r.name, uid: r.uid, gid: r.gid, home: r.home, shell: r.shell}
		gotUserNames[a.name] = true
		if !wantUsers[a] {
			t.Errorf("accounts: %s: parser %+v, getent passwd %+v", a.name, a, userByName[a.name])
		}
	}
	for _, name := range oracleSortedNames(userByName) {
		if a := userByName[name]; !gotUserNames[name] && !oracleDynamic(a.uid) {
			t.Errorf("accounts: getent passwd lists %s (uid %d), %s does not, and it is outside systemd's dynamic range %d..%d",
				name, a.uid, passwdPath, dynamicUIDMin, dynamicUIDMax)
		}
	}

	// group.
	groups, _ := parseGroup(gdata)
	wantGroups := map[oracleGroup]bool{}
	groupByName := map[string]oracleGroup{}
	for _, gr := range oracleGetentGroups(oracleOutput(t, bin, "group")) {
		wantGroups[gr] = true
		if _, dup := groupByName[gr.name]; !dup {
			groupByName[gr.name] = gr
		}
	}
	gotGroupNames := map[string]bool{}
	for _, r := range groups {
		gr := oracleGroup{name: r.name, gid: r.gid, members: strings.Join(r.members, ",")}
		gotGroupNames[gr.name] = true
		if !wantGroups[gr] {
			t.Errorf("accounts: group %s: parser %+v, getent group %+v", gr.name, gr, groupByName[gr.name])
		}
	}
	for _, name := range oracleSortedNames(groupByName) {
		if gr := groupByName[name]; !gotGroupNames[name] && !oracleDynamic(gr.gid) {
			t.Errorf("accounts: getent group lists %s (gid %d), %s does not, and it is outside systemd's dynamic range %d..%d",
				name, gr.gid, groupPath, dynamicUIDMin, dynamicUIDMax)
		}
	}
	t.Logf("oracle accounts: compared %d", len(users)+len(groups))
}

// oracleSortedNames keeps the getent-only report deterministic: a map's
// iteration order would put the same two findings in a different order on
// every run.
func oracleSortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// --- mountinfo ----------------------------------------------------------

// oracleMount is one mount as both sides see it.
type oracleMount struct {
	id     int
	fstype string
	target string
}

// findmntRow is one row of `findmnt -J`. The id is a JSON number on
// util-linux 2.39 and a JSON string on older releases, and json.Number
// accepts both.
type findmntRow struct {
	ID       json.Number  `json:"id"`
	FSType   string       `json:"fstype"`
	Target   string       `json:"target"`
	Children []findmntRow `json:"children"`
}

type findmntOutput struct {
	Filesystems []findmntRow `json:"filesystems"`
}

// oracleFindmnt flattens findmnt's tree — it nests a mount under the mount it
// is mounted on, which mountinfo expresses as a parent id — into the flat set
// mountinfo carries.
func oracleFindmnt(t *testing.T, stdout []byte) map[oracleMount]bool {
	t.Helper()
	var doc findmntOutput
	if err := json.Unmarshal(stdout, &doc); err != nil {
		t.Fatalf("findmnt -J output is not the JSON the oracle expects: %v", err)
	}
	out := map[oracleMount]bool{}
	var walk func(rows []findmntRow)
	walk = func(rows []findmntRow) {
		for _, r := range rows {
			id, err := strconv.Atoi(string(r.ID))
			if err != nil {
				t.Errorf("mountinfo: findmnt row for %q has id %q, which is not a number", r.Target, r.ID)
				continue
			}
			out[oracleMount{id: id, fstype: r.FSType, target: r.Target}] = true
			walk(r.Children)
		}
	}
	walk(doc.Filesystems)
	return out
}

// mountDiff is one attempt at the mountinfo comparison: how many rows the
// parser produced, and the two one-sided differences against findmnt.
type mountDiff struct {
	rows        int
	parserOnly  map[oracleMount]bool
	findmntOnly map[oracleMount]bool
}

// TestOracleMountinfo: the mount table muster parsed is the mount table
// util-linux reads out of the same file — the same ids, the same types, the
// same mount points, including the octal escapes both have to undo.
//
// The two sides cannot read the file at the same instant, and a mount table
// moves under both of them: sudo's PAM session mounts /run/user/0, snapd
// remounts its loopbacks, unattended-upgrades comes and goes. Softening the
// rule to "mostly equal" would let a real parser bug through, so the equality
// stays exact and the RACE is removed instead: the whole comparison runs
// twice, and only a difference that survived both attempts is reported. A
// transient row cannot be in two independent samples on the same side; a
// parser that drops or mangles a row is in every sample.
func TestOracleMountinfo(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, findmntPath)
	c := collectorNamed(t, "walk")
	g := collect.Guard(collect.Host(), c)

	attempt := func() mountDiff {
		data, _, err := g.ReadFile(mountinfoPath, mountinfoReadLimit)
		if err != nil {
			t.Fatalf("read %s: %v", mountinfoPath, err)
		}
		rows, err := parseMountinfo(data)
		if err != nil {
			t.Fatalf("parseMountinfo(%s): %v", mountinfoPath, err)
		}
		got := map[oracleMount]bool{}
		for _, r := range rows {
			got[oracleMount{id: r.id, fstype: r.fstype, target: r.mountPoint}] = true
		}
		want := oracleFindmnt(t, oracleOutput(t, bin, "-A", "-J", "-o", "ID,FSTYPE,TARGET"))
		d := mountDiff{rows: len(rows), parserOnly: map[oracleMount]bool{}, findmntOnly: map[oracleMount]bool{}}
		for m := range got {
			if !want[m] {
				d.parserOnly[m] = true
			}
		}
		for m := range want {
			if !got[m] {
				d.findmntOnly[m] = true
			}
		}
		return d
	}

	first, second := attempt(), attempt()
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("mountinfo oracle reached outside the collector's declaration: %v", v)
	}
	for _, m := range oracleSortedMounts(first.parserOnly) {
		if second.parserOnly[m] {
			t.Errorf("mountinfo: parser has %+v, findmnt does not", m)
		}
	}
	for _, m := range oracleSortedMounts(first.findmntOnly) {
		if second.findmntOnly[m] {
			t.Errorf("mountinfo: findmnt has %+v, the parser does not", m)
		}
	}
	// The row count, not the set size: two identical rows are two rows the
	// parser produced, and counting the set would report one.
	t.Logf("oracle mountinfo: compared %d", first.rows)
}

// oracleSortedMounts orders a mount set by id so a difference is reported the
// same way twice.
func oracleSortedMounts(set map[oracleMount]bool) []oracleMount {
	out := make([]oracleMount, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b oracleMount) int {
		if a.id != b.id {
			return a.id - b.id
		}
		return strings.Compare(a.target+"\x00"+a.fstype, b.target+"\x00"+b.fstype)
	})
	return out
}

// --- services -----------------------------------------------------------

// oracleShow asks systemd about one unit and returns the three properties the
// services table judges. It parses the Key=Value dump itself rather than
// through showValues, for the same reason the sshd pair parses `sshd -T`
// itself.
func oracleShow(t *testing.T, bin, unit string) (load, active, unitFile string) {
	t.Helper()
	for _, line := range oracleLines(oracleOutput(t, bin, "show", "-p", "LoadState,ActiveState,UnitFileState,SubState", unit)) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			load = v
		case "ActiveState":
			active = v
		case "UnitFileState":
			unitFile = v
		}
	}
	return load, active, unitFile
}

// oracleSuperHosted reports whether the collector consults the super-server
// reader for this row. It is setService's own condition (services.go): an
// inetd.conf name OR a server basename is enough, and a row that has either
// can have an enabled or active verdict systemd cannot account for.
func oracleSuperHosted(svc logicalService) bool {
	return len(svc.inetdNames) > 0 || len(svc.servers) > 0
}

// TestOracleServices: the per-service verdicts the collector published are
// what systemd itself says about the units behind them.
//
// enabled is the OR over the row's units of enabledFromUnitFile — the
// collector's own rule, reused deliberately: what is under test here is the
// sweep (which units were asked, and that every answer reached the verdict),
// not the rule's truth table, which the unit tests own.
//
// For a row a super-server can host (oracleSuperHosted) enabled is compared
// in one direction only, and active is not compared at all; for a row with
// fixed ports active is not compared either. In those cases the collector
// also counts a reachable port or an inetd/xinetd entry, neither of which
// systemd knows about, so a verdict above systemd's is the design and not a
// disagreement. A verdict BELOW systemd's never is, on any row.
func TestOracleServices(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, systemctlPath)
	b := build(t, "services", collect.Host())
	compared := 0
	for _, svc := range services {
		var wantEnabled, wantActive bool
		for _, u := range svc.units {
			load, active, unitFile := oracleShow(t, bin, u.name)
			if load == "not-found" {
				continue // systemd has no such unit: it contributes nothing
			}
			if active == "active" {
				wantActive = true
			}
			if enabledFromUnitFile(unitFile, active == "active") {
				wantEnabled = true
			}
		}
		e := env(t, b, "services."+svc.name+".enabled")
		if e.Status != facts.StatusOK {
			t.Errorf("services: %s.enabled is %s (%s), but systemctl answered for every unit", svc.name, e.Status, e.Reason)
			continue
		}
		compared++
		// G-17: for a row a super-server can host, setService may raise
		// enabled on an inetd.conf or xinetd.d entry systemd knows nothing
		// about, so that direction is the design and not a disagreement. The
		// other direction never is: systemd saying a unit will start and the
		// collector publishing false is a mismatch on every row.
		switch {
		case wantEnabled && e.Value != true:
			t.Errorf("services: %s.enabled: collector %v, systemctl %v", svc.name, e.Value, wantEnabled)
		case !wantEnabled && e.Value == true && !oracleSuperHosted(svc):
			t.Errorf("services: %s.enabled: collector %v, systemctl %v", svc.name, e.Value, wantEnabled)
		}
		if len(svc.ports) != 0 || oracleSuperHosted(svc) {
			continue // the collector counts a port or a super-server entry too
		}
		a := env(t, b, "services."+svc.name+".active")
		if a.Status != facts.StatusOK {
			t.Errorf("services: %s.active is %s (%s), but systemctl answered for every unit", svc.name, a.Status, a.Reason)
			continue
		}
		if a.Value != wantActive {
			t.Errorf("services: %s.active: collector %v, systemctl %v", svc.name, a.Value, wantActive)
		}
	}
	if compared == 0 {
		t.Error("services: no row could be compared, so this pair proved nothing")
	}
	t.Logf("oracle services: compared %d", compared)
}
