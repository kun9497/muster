//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
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
// Each test below reads the host the way the collector does — through
// collect.Host() under the collector's own guard — and asks the daemon or
// tool that owns those bytes what IT thinks they say. A fixture can only
// prove that a parser still answers what it answered yesterday; only the
// daemon can prove the answer is right.
//
// Three rules hold for every pair:
//
//   - The oracle's own output is parsed HERE, by code this file owns, never
//     by the function under test. An oracle that shares a parser with the
//     parser it judges cannot disagree with it.
//   - Nothing is written to the host's configuration, started, stopped or
//     installed. Every command is a query (`sshd -T`, `getent`, `findmnt`,
//     `systemctl show`, `sysctl -n`, `dpkg --verify` or `rpm -Va`,
//     `auditctl -s` and `-l`, `lastlog -u`, `getcap -r`, `visudo -c`), run
//     through the same exec discipline the collectors use. The one writer is
//     the keys pair's `ssh-keygen`, and it writes only under t.TempDir(),
//     which the test removes: no key reaches a declared path or a snapshot.
//   - A pair whose oracle binary is not on this machine skips, naming the
//     binary; that is the only skip an enabled run may produce — besides,
//     for the audit pair, J-1's "auditctl cannot reach the kernel" (exit 4
//     or 255, a container), and for the capabilities pair a run without
//     root (the walk needs it) or a container, whose overlay root the walk
//     reads as unsupported, and for the lastlog pair a host with no
//     /var/log/lastlog (shadow 4.15 and later) — and the CI job on the
//     runner VM, which has every binary and a running auditd, asserts
//     there are none.
//     A binary that IS there and refuses to answer fails the pair: a daemon
//     that will not print its own configuration is a finding, not a gap.
//
// LOW-12 — one assumption these pairs make about the host they run on. The
// accounts and group pairs ask getent for what /etc/passwd, /etc/group,
// /etc/shadow and the subid files say, so they hold only where NSS resolves
// those databases from the files alone: `passwd: files systemd` and
// `group: files systemd` on a stock Ubuntu or RHEL, which is what the CI
// runner and the init containers have. On a host whose /etc/nsswitch.conf
// also names sss, ldap or nis, getent answers from the directory as well and
// every account it adds looks like a row the parser missed. The pairs are
// opt-in (MUSTER_ORACLE=1) and the jobs that set it run on images we control,
// so nothing checks the NSS stack here; a self-hosted runner joined to a
// directory would see those false getent-only rows and should not enable the
// oracles.

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

// --- sysctl -------------------------------------------------------------

// The sysctl oracle binary, by absolute path. procps installs it in /usr/sbin
// on the Debian family and on a merged-/usr EL host; /sbin is the pre-merge
// spelling, and a host that has only that one is still a host whose sysctl
// can answer.
var sysctlOraclePaths = []string{"/usr/sbin/sysctl", "/sbin/sysctl"}

// sysctlOracleOutcome is what `sysctl -n <key>` said about one variable:
// either a value it printed, or a failure with the message it printed. The
// distinction the comparison needs is whether the failure was "there is no
// such knob on this kernel" — which is muster's absent — or anything else,
// which is a read that was refused and is muster's denied.
type sysctlOracleOutcome struct {
	value   int
	ok      bool
	missing bool
	message string
}

func (o sysctlOracleOutcome) String() string {
	if o.ok {
		return strconv.Itoa(o.value)
	}
	if o.missing {
		return "no such variable (" + o.message + ")"
	}
	return "could not be read (" + o.message + ")"
}

// oracleSysctlPath finds the oracle, or skips the pair naming both spellings.
func oracleSysctlPath(t *testing.T) string {
	t.Helper()
	for _, p := range sysctlOraclePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("oracle binary %s is not on this machine", strings.Join(sysctlOraclePaths, " or "))
	return ""
}

// oracleSysctlValue asks procps for one variable. Unlike oracleOutput a
// non-zero exit is an ANSWER here, not a failure of the pair: "cannot stat
// /proc/sys/…: No such file or directory" is procps saying the kernel has no
// such knob, which is exactly what muster reports as absent. Everything else
// — a refused read above all — is kept apart, so an unreadable file can never
// be mistaken for a knob that does not exist.
func oracleSysctlValue(t *testing.T, bin, key string) sysctlOracleOutcome {
	t.Helper()
	out := collect.RunCommand(context.Background(), collect.Command{
		Path: bin, Args: []string{"-n", key}, Timeout: 30 * time.Second, MaxOutput: 1 << 16,
	})
	line := bin + " -n " + key
	switch {
	case out.Err != nil:
		t.Fatalf("%s could not be run: %v", line, out.Err)
	case out.TimedOut:
		t.Fatalf("%s timed out", line)
	case out.Truncated:
		t.Fatalf("%s produced more output than the oracle reads", line)
	}
	msg := strings.TrimSpace(string(out.Stderr))
	if out.ExitCode != 0 {
		return sysctlOracleOutcome{
			missing: strings.Contains(msg, "No such file or directory"),
			message: msg,
		}
	}
	text := strings.TrimSpace(string(out.Stdout))
	n, err := strconv.Atoi(text)
	if err != nil {
		t.Fatalf("%s printed %q, which is not an integer", line, text)
	}
	return sysctlOracleOutcome{value: n, ok: true}
}

// F-8: the twelve kernel self-protection sysctls against procps.
//
// muster never runs sysctl — /proc/sys is the kernel's own answer and reading
// it needs no program (B-3) — so procps is a genuinely independent reader of
// the same bytes: it resolves the dotted name to a path by its own rules and
// prints what it finds. The pair therefore proves both halves of the runtime
// side at once, the name-to-path table of sysctlLeaves and readProcSys.
//
// Only the RUNTIME side is compared. The persisted side is the sysctl.d
// chain, and `sysctl -p` would apply files rather than report them — the one
// thing an oracle may not do (nothing is written, started or installed here).
//
// Three agreements are counted, and they are not the same statement:
// a value both sides read, a variable neither can find (a kernel without Yama,
// or fs.protected_fifos before 4.19), and a file neither may read (the five
// 0600 knobs of B-3, when this pair is run without root). Anything else is a
// mismatch naming the key and what each side said.
func TestOracleSysctl(t *testing.T) {
	oracleEnabled(t)
	bin := oracleSysctlPath(t)
	c := collectorNamed(t, "sysctl")
	g := collect.Guard(collect.Host(), c)

	compared := 0
	for _, l := range sysctlLeaves {
		have := readProcSys(g, l.path)
		want := oracleSysctlValue(t, bin, l.key)
		switch {
		case have.Status == facts.StatusOK && want.ok:
			if have.Value != want.value {
				t.Errorf("sysctl: %s (%s): muster %v, %s says %d", l.key, l.path, have.Value, bin, want.value)
			}
			compared++
		case have.Status == facts.StatusAbsent && want.missing:
			compared++
		case have.Status == facts.StatusDenied && !want.ok && !want.missing:
			compared++
		default:
			t.Errorf("sysctl: %s (%s): muster %s (%v%s), %s says %s",
				l.key, l.path, have.Status, have.Value, reasonSuffix(have.Reason), bin, want)
		}
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("sysctl oracle reached outside the collector's declaration: %v", v)
	}
	if compared == 0 {
		t.Error("sysctl: no variable could be compared, so this pair proved nothing")
	}
	t.Logf("oracle sysctl: compared %d", compared)
}

// reasonSuffix renders a degraded envelope's reason inside a mismatch line
// without printing an empty parenthesis for an ok one.
func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return ": " + reason
}

// --- package verification -----------------------------------------------

// oracleVerifyLineRE is the oracle's own reading of a verify row, for both
// tools: nine attribute columns (or "missing"), the optional file-type
// letter, and the path to the end of the line, from which a parenthesised
// trailer such as rpm's "(Permission denied)" is dropped. It is deliberately
// looser than the collector's grammar: a row the collector rejects still
// counts here, and the collector then fails the pair through
// stats.unparsed_head or through the count.
var oracleVerifyLineRE = regexp.MustCompile(`^(?:[SM5DLUGTP.?]{9}|missing)\s+(?:[a-z]\s+)?(/.*)$`)

var oracleVerifyTrailerRE = regexp.MustCompile(` \([^)]*\)$`)

// oracleVerifyTool is the package manager this host verifies with, chosen
// the way a reader of the host would: the dpkg database first, then rpm's.
func oracleVerifyTool(t *testing.T) (bin string, args []string) {
	t.Helper()
	switch {
	case oracleExists("/var/lib/dpkg/status"):
		return oracleBinary(t, "/usr/bin/dpkg"), []string{"--verify"}
	case oracleExists("/var/lib/rpm"):
		return oracleBinary(t, "/usr/bin/rpm"), []string{"-Va"}
	}
	t.Skip("no package database: neither /var/lib/dpkg/status nor /var/lib/rpm exists")
	return "", nil
}

func oracleExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// oracleVerifyRows is the path of every row the tool printed, and the lines
// that were not rows.
func oracleVerifyRows(stdout []byte) (paths []string, other []string) {
	for _, l := range oracleLines(stdout) {
		l = strings.TrimRight(l, "\r")
		if strings.TrimSpace(l) == "" {
			continue
		}
		m := oracleVerifyLineRE.FindStringSubmatch(l)
		if m == nil {
			other = append(other, l)
			continue
		}
		paths = append(paths, oracleVerifyTrailerRE.ReplaceAllString(m[1], ""))
	}
	return paths, other
}

// TestOracleVerify runs the package manager's verification itself and
// compares what it printed with what the pkgverify collector published: every
// path the collector lists is a row the tool printed, and the listed rows
// plus the filtered counts are exactly the rows the tool printed. The two
// runs are minutes apart on a live host; a file that changes between them
// shows as a mismatch with both counts in the log.
func TestOracleVerify(t *testing.T) {
	oracleEnabled(t)
	bin, args := oracleVerifyTool(t)
	line := bin + " " + strings.Join(args, " ")
	out := collect.RunCommand(context.Background(), collect.Command{
		Path: bin, Args: args, Timeout: 30 * time.Minute, MaxOutput: 64 << 20,
	})
	switch {
	case out.Err != nil:
		t.Fatalf("%s could not be run: %v", line, out.Err)
	case out.TimedOut:
		t.Fatalf("%s timed out", line)
	case out.Truncated:
		t.Fatalf("%s produced more output than the oracle reads", line)
	case out.ExitCode != 0 && out.ExitCode != 1:
		t.Fatalf("%s exited %d: %s", line, out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	}
	oraclePaths, other := oracleVerifyRows(out.Stdout)
	if len(other) != 0 {
		t.Logf("%s printed %d lines that are not rows, first %q", line, len(other), other[0])
	}

	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := collect.NewBuilder(reg)
	b.SetVerify(collect.VerifyOptions{Timeout: 30 * time.Minute})
	b.Begin("pkgverify")
	c := collectorNamed(t, "pkgverify")
	g := collect.Guard(collect.Host(), c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("pkgverify: %v", err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("pkgverify reached outside its declaration: %v", v)
	}
	if e := env(t, b, "packages.verify.complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("packages.verify.complete: %s %v%s", e.Status, e.Value, reasonSuffix(e.Reason))
	}
	stats := verifyRecord(t, b, "packages.verify.stats")
	if u, _ := stats["unparsed_head"].([]any); len(u) != 0 {
		t.Errorf("the collector could not parse rows the tool printed: %v", u)
	}

	oracleSet := map[string]bool{}
	for _, p := range oraclePaths {
		oracleSet[p] = true
	}
	listed := 0
	for _, key := range []string{"packages.verify.modified", "packages.verify.modified_config"} {
		if env(t, b, key).Truncated {
			t.Fatalf("%s is truncated; the path sets cannot be compared", key)
		}
		for _, r := range okList(t, b, key) {
			p, _ := r.(map[string]any)["path"].(string)
			if !oracleSet[p] {
				t.Errorf("%s lists %s, which %s did not print", key, p, line)
			}
			listed++
		}
	}
	filtered := 0
	counts := verifyRecord(t, b, "packages.verify.filtered_counts")
	for name, v := range counts {
		n, ok := v.(int)
		if !ok {
			t.Fatalf("filtered_counts.%s is %T, not an int", name, v)
		}
		if name != "config" { // a config row is listed in modified_config AND counted
			filtered += n
		}
	}
	if listed+filtered != len(oraclePaths) {
		t.Errorf("%s printed %d rows; muster listed %d and filtered %d (%v)", line, len(oraclePaths), listed, filtered, counts)
	}
	t.Logf("oracle verify: compared %d (listed %d, filtered %d)", len(oraclePaths), listed, filtered)
}

// --- audit --------------------------------------------------------------

// oracleAuditctl runs one auditctl query. Exit 4 (no CAP_AUDIT_CONTROL) and
// 255 (a pid namespace the kernel will not answer) are J-1's "cannot reach
// the kernel" — the container case, where there is nothing to compare — and
// the one skip this pair allows besides a missing binary.
func oracleAuditctl(t *testing.T, bin string, arg string) []byte {
	t.Helper()
	out := collect.RunCommand(context.Background(), collect.Command{
		Path: bin, Args: []string{arg}, Timeout: 30 * time.Second, MaxOutput: 8 << 20,
	})
	switch {
	case out.Err != nil:
		t.Fatalf("%s %s could not be run: %v", bin, arg, out.Err)
	case out.TimedOut:
		t.Fatalf("%s %s timed out", bin, arg)
	case out.ExitCode == 4 || out.ExitCode == 255:
		t.Skipf("auditctl cannot reach the kernel here (%s %s exited %d: %s)", bin, arg, out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	case out.ExitCode != 0:
		t.Fatalf("%s %s exited %d: %s", bin, arg, out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	case out.Truncated:
		t.Fatalf("%s %s produced more output than the oracle reads", bin, arg)
	}
	return out.Stdout
}

// oracleAuditEnabled is the enabled field of auditctl -s, read here.
func oracleAuditEnabled(t *testing.T, stdout []byte) int {
	t.Helper()
	for _, l := range oracleLines(stdout) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "enabled" {
			n, err := strconv.Atoi(f[1])
			if err != nil {
				t.Fatalf("auditctl -s: enabled %q is not an integer", f[1])
			}
			return n
		}
	}
	t.Fatalf("auditctl -s printed no enabled line:\n%s", stdout)
	return 0
}

// oracleAuditRuleCount is how many rules auditctl -l printed: every
// non-blank line but its "No rules".
func oracleAuditRuleCount(stdout []byte) int {
	n := 0
	for _, l := range oracleLines(stdout) {
		if s := strings.TrimSpace(l); s != "" && s != "No rules" {
			n++
		}
	}
	return n
}

// TestOracleAudit asks auditctl for the kernel's audit status and rule list
// and compares them with the audit collector's audit.status.enabled and
// audit.rules.loaded_count, read through the collector's own guard.
func TestOracleAudit(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, "/usr/sbin/auditctl")
	enabled := oracleAuditEnabled(t, oracleAuditctl(t, bin, "-s"))
	rules := oracleAuditRuleCount(oracleAuditctl(t, bin, "-l"))

	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := collect.NewBuilder(reg)
	b.Begin("audit")
	c := collectorNamed(t, "audit")
	g := collect.Guard(collect.Host(), c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("audit reached outside its declaration: %v", v)
	}

	compared := 0
	for _, pair := range []struct {
		key  string
		want int
	}{
		{"audit.status.enabled", enabled},
		{"audit.rules.loaded_count", rules},
	} {
		e := env(t, b, pair.key)
		switch {
		case e.Status != facts.StatusOK:
			t.Errorf("%s: muster %s%s, auditctl says %d", pair.key, e.Status, reasonSuffix(e.Reason), pair.want)
		case e.Value != pair.want:
			t.Errorf("%s: muster %v, auditctl says %d", pair.key, e.Value, pair.want)
		default:
			compared++
		}
	}
	t.Logf("oracle audit: compared %d", compared)
}

// --- units --------------------------------------------------------------

// oracleUnitsSample is how many in-scope units the units pair asks systemd
// about: enough to cover a daemon, a oneshot and a template instance on a
// stock host, few enough that the pair stays a handful of systemctl calls.
const oracleUnitsSample = 5

// oracleExecPath is the path= of the first `{ … }` command in a `systemctl
// show` ExecStart value — `{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D
// … }` — which is the executable systemd resolved, prefixes gone. "" when the
// value names no command.
func oracleExecPath(v string) string {
	_, rest, ok := strings.Cut(v, "path=")
	if !ok {
		return ""
	}
	p, _, _ := strings.Cut(rest, " ;")
	return strings.TrimSpace(p)
}

// oracleUser folds the two spellings of "runs as root": the collector's row
// says "" for a unit without User=, and `systemctl show` prints an empty
// User= for it.
func oracleUser(u string) string {
	if u == "" {
		return "root"
	}
	return u
}

// TestOracleUnits: for up to five root services whose unit file the collector
// read, systemd's own merged view of the unit (its file and drop-ins) runs
// the same first ExecStart executable, as the same user, as the collector's
// row says. A row whose first ExecStart the collector left unresolved (a
// bare name systemd looks up itself) is not sampled: its path is systemd's
// search, not the file's.
func TestOracleUnits(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, systemctlPath)
	b := build(t, "units", collect.Host())
	compared := 0
	for _, r := range okList(t, b, "units.root_services") {
		if compared == oracleUnitsSample {
			break
		}
		row := r.(map[string]any)
		if row["unit_file"] != "file" || row["read_status"] != "ok" {
			continue
		}
		var first map[string]any
		for _, e := range row["exec"].([]any) {
			if er := e.(map[string]any); er["directive"] == "ExecStart" {
				first = er
				break
			}
		}
		if first == nil || first["resolved"] != true {
			continue
		}
		unit := row["unit"].(string)
		var execStart, user, state string
		seen := false
		for _, line := range oracleLines(oracleOutput(t, bin, "show", "-p", "ExecStart,User,UnitFileState", unit)) {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k {
			case "ExecStart":
				if !seen {
					execStart, seen = v, true
				}
			case "User":
				user = v
			case "UnitFileState":
				state = v
			}
		}
		if got, want := first["path"], oracleExecPath(execStart); got != want {
			t.Errorf("units: %s (UnitFileState %s): first ExecStart collector %v, systemctl %q", unit, state, got, want)
		}
		if got, want := oracleUser(row["user"].(string)), oracleUser(user); got != want {
			t.Errorf("units: %s (UnitFileState %s): User collector %q, systemctl %q", unit, state, got, want)
		}
		compared++
	}
	if compared == 0 {
		t.Error("units: no root service with a read unit file and a resolved ExecStart, so this pair proved nothing")
	}
	t.Logf("oracle units: compared %d", compared)
}

// --- authorized_keys ----------------------------------------------------

const sshKeygenPath = "/usr/bin/ssh-keygen"

// oracleKeygen runs ssh-keygen and returns its exit code; unlike
// oracleOutput a non-zero exit is the caller's to judge, because `-t dsa`
// failing on a build without DSA is an answer, not a broken oracle.
func oracleKeygen(t *testing.T, args ...string) int {
	t.Helper()
	out := collect.RunCommand(context.Background(), collect.Command{
		Path: sshKeygenPath, Args: args, Timeout: 60 * time.Second, MaxOutput: 1 << 20,
	})
	if out.Err != nil || out.TimedOut {
		t.Fatalf("ssh-keygen %s could not be run: %v (timed out %v)", strings.Join(args, " "), out.Err, out.TimedOut)
	}
	return out.ExitCode
}

// oracleKeyTypes maps the type word of a .pub line to the name ssh-keygen -l
// prints in parentheses. The map is the oracle's knowledge of ssh-keygen's
// vocabulary, never a rule the parser has to follow.
var oracleKeyTypes = map[string]string{
	"ssh-ed25519":         "ED25519",
	"ecdsa-sha2-nistp256": "ECDSA",
	"ssh-rsa":             "RSA",
	"ssh-dss":             "DSA",
}

// TestOracleAuthorizedKeys is a parser oracle: it makes its own keys under
// t.TempDir(), writes an authorized_keys from their .pub lines — the first
// behind `restrict,command="x"` — and holds parseAuthorizedKeys's type, bits
// and fingerprint for every line to what `ssh-keygen -l -f` prints for the
// same .pub. Nothing under a declared path is read or written, and the
// directory goes with the test.
func TestOracleAuthorizedKeys(t *testing.T) {
	oracleEnabled(t)
	oracleBinary(t, sshKeygenPath)
	dir := t.TempDir()
	specs := []struct{ typ, bits string }{
		{"ed25519", ""},
		{"ecdsa", "256"},
		{"rsa", "3072"},
		{"dsa", ""},
	}
	type want struct{ typ, bits, fp string }
	var (
		file  strings.Builder
		wants []want
	)
	for _, s := range specs {
		f := dir + "/" + s.typ
		args := []string{"-t", s.typ, "-N", "", "-q", "-C", "muster-oracle", "-f", f}
		if s.bits != "" {
			args = append(args, "-b", s.bits)
		}
		if code := oracleKeygen(t, args...); code != 0 {
			if s.typ == "dsa" {
				t.Logf("ssh-keygen -t dsa exited %d: this build makes no DSA keys, so none is compared", code)
				continue
			}
			t.Fatalf("ssh-keygen -t %s exited %d", s.typ, code)
		}
		pub, err := os.ReadFile(f + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(oracleLines(oracleOutput(t, sshKeygenPath, "-l", "-f", f+".pub"))[0])
		if len(fields) < 3 {
			t.Fatalf("ssh-keygen -l -f %s.pub printed %q", f, fields)
		}
		wants = append(wants, want{typ: strings.Trim(fields[len(fields)-1], "()"), bits: fields[0], fp: fields[1]})
		if len(wants) == 1 {
			file.WriteString(`restrict,command="x" `)
		}
		file.WriteString(strings.TrimSpace(string(pub)) + "\n")
	}
	keys, unparsed := parseAuthorizedKeys([]byte(file.String()))
	if unparsed != 0 || len(keys) != len(wants) {
		t.Fatalf("keys: the parser read %d keys and %d unparsed lines from %d .pub lines", len(keys), unparsed, len(wants))
	}
	for i, k := range keys {
		w := wants[i]
		if oracleKeyTypes[k.Type] != w.typ || strconv.Itoa(k.Bits) != w.bits || k.Fingerprint != w.fp {
			t.Errorf("keys: line %d: parser %s %d %s, ssh-keygen -l %s %s %s", k.Line, k.Type, k.Bits, k.Fingerprint, w.typ, w.bits, w.fp)
		}
		if restricted := i == 0; k.Restricted != restricted {
			t.Errorf("keys: line %d: restricted %v, want %v (options %q)", k.Line, k.Restricted, restricted, k.Options)
		}
	}
	t.Logf("oracle keys: compared %d", len(keys))
}

// --- lastlog ------------------------------------------------------------

const lastlogBinPath = "/usr/bin/lastlog"

// oracleLastlog asks lastlog(8) about one account: "" for "**Never logged
// in**", else the login time in RFC 3339 UTC. The date is the last six
// fields of the second line, `%a %b %e %H:%M:%S %z %Y` (V-33 said five; the
// lab's lastlog printed six — the weekday is one): the port and host columns
// before it may be empty, so the line is not split by column.
func oracleLastlog(t *testing.T, name string) string {
	t.Helper()
	lines := oracleLines(oracleOutput(t, lastlogBinPath, "-u", name))
	if len(lines) < 2 {
		t.Fatalf("lastlog -u %s printed %d lines", name, len(lines))
	}
	if strings.Contains(lines[1], "**Never logged in**") {
		return ""
	}
	f := strings.Fields(lines[1])
	if len(f) < 7 {
		t.Fatalf("lastlog -u %s: %q has no date", name, lines[1])
	}
	when, err := time.Parse("Mon Jan 2 15:04:05 -0700 2006", strings.Join(f[len(f)-6:], " "))
	if err != nil {
		t.Fatalf("lastlog -u %s: %q: %v", name, lines[1], err)
	}
	return when.UTC().Format(time.RFC3339)
}

// TestOracleLastlog: the collector's accounts.lastlog rows for root and for
// the account running the test — the one sudo was invoked by when SUDO_UID
// is set (V-33) — say what lastlog(8) prints for them. A comparison where
// neither side has a date proves only that both say "never", which a decoder
// that read nothing would also say, so the pair counts the dated ones apart
// (V-62) and CI plants a login for the runner to make one. Where
// /var/log/lastlog is absent the fact is absent and shadow's lastlog exits 1
// on the missing file, so there is nothing to compare: the pair skips.
func TestOracleLastlog(t *testing.T) {
	oracleEnabled(t)
	oracleBinary(t, lastlogBinPath)
	b := build(t, "accounts", collect.Host())
	names := map[int]string{}
	for _, u := range okList(t, b, "accounts.users") {
		row := u.(map[string]any)
		if uid := row["uid"].(int); names[uid] == "" {
			names[uid] = row["name"].(string)
		}
	}
	self := os.Getuid()
	if s := os.Getenv("SUDO_UID"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("SUDO_UID %q: %v", s, err)
		}
		self = n
	}
	uids := []int{0}
	if self != 0 {
		uids = append(uids, self)
	}
	e := env(t, b, "accounts.lastlog")
	switch e.Status {
	case facts.StatusOK:
	case facts.StatusAbsent:
		t.Skipf("accounts.lastlog is absent (%s): lastlog(8) has no file to read either", e.Reason)
	default:
		t.Fatalf("accounts.lastlog is %s%s", e.Status, reasonSuffix(e.Reason))
	}
	got := map[int]string{}
	for _, r := range e.Value.([]any) {
		row := r.(map[string]any)
		got[row["uid"].(int)] = row["last_login"].(string)
	}
	compared, dated := 0, 0
	for _, uid := range uids {
		name := names[uid]
		if name == "" {
			t.Fatalf("lastlog: uid %d is not in accounts.users", uid)
		}
		want := oracleLastlog(t, name)
		if got[uid] != want {
			t.Errorf("lastlog: %s (uid %d): collector %q, lastlog -u %q", name, uid, got[uid], want)
		}
		compared++
		if want != "" || got[uid] != "" {
			dated++
		}
	}
	t.Logf("oracle lastlog: compared %d, dated %d", compared, dated)
}

// --- file capabilities --------------------------------------------------

const getcapPath = "/usr/sbin/getcap"

// oracleCapDirs are the directories the capabilities pair walks and asks
// getcap about (V-61): where executables live. /usr/share, /usr/local/lib,
// /usr/src, /usr/include and the rest are out — the CI collect excludes some
// of them for their size, and a pair that walked more than the collect does
// could run out of budget where the collect did not. The CI probe,
// /usr/local/bin/muster-cap-probe, is inside.
var oracleCapDirs = []string{"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/usr/local/bin", "/usr/local/sbin"}

// oracleCapExclude is every path the walk has to leave out for it to cover
// oracleCapDirs and nothing else: each top-level entry of / but /usr, each
// entry of /usr but bin, sbin, lib, libexec and local, and each entry of
// /usr/local but bin and sbin. WalkOptions.Include names container-storage
// roots only, so the narrowing is by exclusion.
func oracleCapExclude(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, level := range []struct {
		dir  string
		keep []string
	}{
		{"/", []string{"usr"}},
		{"/usr", []string{"bin", "sbin", "lib", "libexec", "local"}},
		{"/usr/local", []string{"bin", "sbin"}},
	} {
		entries, err := os.ReadDir(level.dir)
		if err != nil {
			if level.dir == "/usr/local" && os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		for _, e := range entries {
			if !slices.Contains(level.keep, e.Name()) {
				out = append(out, strings.TrimSuffix(level.dir, "/")+"/"+e.Name())
			}
		}
	}
	return out
}

// oracleCap is one file's capabilities as the pair compares them: the path,
// the canonical text of the set parseCapText reads, and the rootid.
type oracleCap struct {
	path, caps string
	rootid     int
}

// oracleGetcapLine splits one `getcap -r` line into its path and set. The
// text after the path may itself hold blanks (`cap_a=ep cap_b+i`, a trailing
// `[rootid=N]`), and so may the path, so no fixed blank is the separator: the
// split is the first blank whose remainder — past an old-libcap `= ` — is a
// capability text parseCapText accepts. A path's own words are never one: a
// clause needs an operator and known capability names.
func oracleGetcapLine(line string) (oracleCap, bool) {
	const rootidMark = " [rootid="
	for i := 0; i < len(line); i++ {
		if line[i] != ' ' {
			continue
		}
		p, rest := line[:i], strings.TrimSpace(line[i+1:])
		if strings.HasPrefix(rest, "= ") {
			rest = strings.TrimSpace(rest[2:])
		}
		rootid := 0
		if at := strings.LastIndex(rest, rootidMark); at >= 0 && strings.HasSuffix(rest, "]") {
			n, err := strconv.Atoi(rest[at+len(rootidMark) : len(rest)-1])
			if err != nil {
				continue
			}
			rootid, rest = n, rest[:at]
		}
		set, err := parseCapText(rest)
		if err != nil {
			continue
		}
		return oracleCap{path: p, caps: capText(set), rootid: rootid}, true
	}
	return oracleCap{}, false
}

// oracleGetcap reads `getcap -r` output in both libcap spellings — `path
// caps` (2.41 and later) and `path = caps` — with an optional trailing
// `[rootid=N]`. Only executables are kept: the walk opens nothing else for
// its attributes (a capability on a file nobody can execute is inert), and a
// file that is not one is logged, not compared.
func oracleGetcap(t *testing.T, stdout []byte) map[oracleCap]bool {
	t.Helper()
	out := map[oracleCap]bool{}
	for _, line := range oracleLines(stdout) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		c, ok := oracleGetcapLine(line)
		if !ok {
			t.Fatalf("getcap: %q is not a path and a capability text", line)
		}
		if fi, err := os.Lstat(c.path); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
			t.Logf("getcap lists %s, which is not an executable regular file: not compared", c.path)
			continue
		}
		out[c] = true
	}
	return out
}

// TestOracleCapabilities runs the walk in-process over oracleCapDirs alone and
// holds its walk.capabilities rows to `getcap -r` over the same directories,
// as a set of (path, canonical caps, rootid). A run that compares nothing
// fails, as the units pair does: the CI runner carries the planted probe, and
// a stock host its distribution's own capability files.
func TestOracleCapabilities(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, getcapPath)
	if os.Geteuid() != 0 {
		t.Skip("the walk needs root")
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := collect.NewBuilder(reg)
	b.SetWalk(collect.WalkOptions{Budget: 10 * time.Minute, MaxEntries: 6_000_000, Exclude: oracleCapExclude(t)})
	b.Begin("walk")
	c := collectorNamed(t, "walk")
	g := collect.Guard(collect.Host(), c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("walk: %v", err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("walk reached outside its declaration: %v", v)
	}
	// Printed before anything is asserted, so a walk cut short is read next
	// to its counts and stop reason rather than guessed at.
	complete := env(t, b, "walk.complete")
	t.Logf("walk.complete: %s %v%s", complete.Status, complete.Value, reasonSuffix(complete.Reason))
	if stats, err := json.Marshal(env(t, b, "walk.stats").Value); err == nil {
		t.Logf("walk.stats: %s", stats)
	}
	if e := env(t, b, "walk.capabilities"); e.Status == facts.StatusUnsupported {
		t.Skipf("walk.capabilities is unsupported here (%s): a container's overlay root", e.Reason)
	}
	if complete.Status != facts.StatusOK || complete.Value != true {
		t.Fatalf("walk.complete: %s %v%s", complete.Status, complete.Value, reasonSuffix(complete.Reason))
	}
	if env(t, b, "walk.capabilities").Truncated {
		t.Fatal("walk.capabilities is truncated; the sets cannot be compared")
	}
	got := map[oracleCap]bool{}
	for _, r := range okList(t, b, "walk.capabilities") {
		row := r.(map[string]any)
		set, err := parseCapText(row["caps"].(string))
		if err != nil {
			t.Fatalf("walk.capabilities %s: %q: %v", row["path"], row["caps"], err)
		}
		got[oracleCap{path: row["path"].(string), caps: capText(set), rootid: row["rootid"].(int)}] = true
	}
	args := []string{"-r"}
	for _, d := range oracleCapDirs {
		if fi, err := os.Lstat(d); err == nil && fi.IsDir() {
			args = append(args, d)
		}
	}
	// oracleOutput's 30 s is a query's budget; getcap -r reads an attribute
	// of every file under the six directories, which on the runner image is
	// hundreds of thousands.
	out := collect.RunCommand(context.Background(), collect.Command{
		Path: bin, Args: args, Timeout: 10 * time.Minute, MaxOutput: 8 << 20,
	})
	line := bin + " " + strings.Join(args, " ")
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
	want := oracleGetcap(t, out.Stdout)
	for _, c := range oracleSortedCaps(got) {
		if !want[c] {
			t.Errorf("capabilities: the walk lists %s %s (rootid %d), %s does not", c.path, c.caps, c.rootid, line)
		}
	}
	for _, c := range oracleSortedCaps(want) {
		if !got[c] {
			t.Errorf("capabilities: %s lists %s %s (rootid %d), the walk does not", line, c.path, c.caps, c.rootid)
		}
	}
	if len(want) == 0 {
		t.Fatalf("capabilities: %s found no executable with a capability, so this pair proved nothing", line)
	}
	t.Logf("oracle capabilities: compared %d", len(want))
}

// oracleSortedCaps keeps the mismatch report in path order, as
// oracleSortedNames does for the accounts pair.
func oracleSortedCaps(set map[oracleCap]bool) []oracleCap {
	out := make([]oracleCap, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b oracleCap) int {
		if c := strings.Compare(a.path, b.path); c != 0 {
			return c
		}
		return strings.Compare(a.caps, b.caps)
	})
	return out
}

// --- sudoers ------------------------------------------------------------

const visudoPath = "/usr/sbin/visudo"

// TestOracleSudoers only validates: `visudo -c -f /etc/sudoers` checks the
// whole include chain and must exit 0, and the collector must have resolved
// every rule it read. A policy comparison would need `sudo -l`, which runs
// sudo's policy on the host and is not a query. The one unresolved rule a
// valid host may have is a +netgroup principal, whose members live in the
// name service, not in the files; it is logged, not failed.
func TestOracleSudoers(t *testing.T) {
	oracleEnabled(t)
	bin := oracleBinary(t, visudoPath)
	oracleOutput(t, bin, "-c", "-f", "/etc/sudoers")
	b := build(t, "files", collect.Host())
	e := env(t, b, "sudo.rules_unresolved")
	if e.Status != facts.StatusOK {
		t.Fatalf("sudo.rules_unresolved is %s%s, but visudo read the files", e.Status, reasonSuffix(e.Reason))
	}
	if n := e.Value.(int); n != 0 {
		netgroups := 0
		for _, r := range okList(t, b, "sudo.rules") {
			if row := r.(map[string]any); row["kind"] == "netgroup" && row["resolved"] == false {
				netgroups++
			}
		}
		if netgroups == n {
			t.Logf("sudoers: %d rules name a +netgroup, whose members the files do not hold", n)
		} else {
			t.Errorf("sudoers: %d rules unresolved (%d of them +netgroup), on files visudo accepts", n, netgroups)
		}
	}
	t.Logf("oracle sudoers: compared 1")
}

// The getcap line splitter is the oracle's own parser, so it is pinned here
// on every Linux run rather than only when the oracles are enabled: both
// libcap spellings, a multi-clause text, a rootid, and a path with a blank.
func TestOracleGetcapLineSplits(t *testing.T) {
	ping, _ := parseCapText("cap_net_raw=ep")
	multi, _ := parseCapText("cap_net_raw=ep cap_setuid+i")
	for _, tc := range []struct {
		line string
		want oracleCap
	}{
		{"/usr/bin/ping cap_net_raw=ep", oracleCap{"/usr/bin/ping", capText(ping), 0}},
		{"/usr/bin/ping = cap_net_raw+ep", oracleCap{"/usr/bin/ping", capText(ping), 0}},
		{"/usr/bin/a b cap_net_raw=ep", oracleCap{"/usr/bin/a b", capText(ping), 0}},
		{"/usr/bin/x cap_net_raw=ep cap_setuid+i", oracleCap{"/usr/bin/x", capText(multi), 0}},
		{"/usr/bin/y cap_net_raw=ep [rootid=1000]", oracleCap{"/usr/bin/y", capText(ping), 1000}},
	} {
		got, ok := oracleGetcapLine(tc.line)
		if !ok || got != tc.want {
			t.Errorf("%q: %+v %v, want %+v", tc.line, got, ok, tc.want)
		}
	}
	if _, ok := oracleGetcapLine("/usr/bin/nothing"); ok {
		t.Error("a line without a capability text split")
	}
}
