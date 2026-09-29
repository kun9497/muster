//go:build linux

package collectors

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// P-4: the units collector. Every test runs it through build(), under the
// guard, so a stat of an undeclared executable fails the test (V-20).

const (
	etcUnits = "/etc/systemd/system"
	usrUnits = "/usr/lib/systemd/system"
)

func unitsAccess(listed ...string) *fsAccess {
	var out strings.Builder
	for _, u := range listed {
		fmt.Fprintf(&out, "%-30s loaded active running Some Description\n", u)
	}
	return &fsAccess{
		files:    map[string]string{},
		contents: map[string][]byte{},
		dirs:     map[string]bool{systemdMarker: true},
		links:    map[string]string{},
		stats:    map[string]statResult{},
		fails:    map[string]error{},
		cmds:     map[string]cmdResult{cmdKey(listUnitsCmd): {stdout: []byte(out.String())}},
	}
}

// unitText seeds a unit file or drop-in with the given content, root-owned 0644.
func unitText(a *fsAccess, p, content string) {
	a.contents[p] = []byte(content)
	a.stats[p] = statResult{mode: 0o644, kind: "regular"}
}

func exe(a *fsAccess, p string, mode, uid, gid uint32) {
	a.stats[p] = statResult{mode: mode, uid: uid, gid: gid, kind: "regular"}
}

func unitRows(t *testing.T, b *collect.Builder) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, r := range okList(t, b, "units.root_services") {
		m := r.(map[string]any)
		out[m["unit"].(string)] = m
	}
	return out
}

func execPaths(t *testing.T, row map[string]any) []string {
	t.Helper()
	var out []string
	for _, e := range row["exec"].([]any) {
		m := e.(map[string]any)
		out = append(out, m["directive"].(string)+" "+m["path"].(string))
	}
	return out
}

func filePaths(row map[string]any) []string {
	var out []string
	for _, f := range row["files"].([]any) {
		out = append(out, f.(map[string]any)["path"].(string))
	}
	return out
}

var execRowFields = []string{"directive", "path", "resolved", "stat_status", "stat_path", "exists", "kind",
	"mode", "uid", "gid", "group_writable", "other_writable"}

func checkEveryExecField(t *testing.T, row map[string]any) {
	t.Helper()
	for _, e := range row["exec"].([]any) {
		m := e.(map[string]any)
		for _, f := range execRowFields {
			if _, ok := m[f]; !ok {
				t.Errorf("%s exec row %v lacks %s", row["unit"], m, f)
			}
		}
	}
	for _, f := range []string{"unit", "enabled", "active", "user", "unit_file", "files", "exec", "read_status", "reason"} {
		if _, ok := row[f]; !ok {
			t.Errorf("row %v lacks %s", row["unit"], f)
		}
	}
}

func writableRows(t *testing.T, b *collect.Builder) []string {
	t.Helper()
	var out []string
	for _, r := range okList(t, b, "units.exec_writable") {
		m := r.(map[string]any)
		out = append(out, m["unit"].(string)+" "+m["path"].(string)+" "+m["why"].(string))
	}
	return out
}

func unresolvedCount(t *testing.T, b *collect.Builder) int {
	t.Helper()
	e := env(t, b, "units.exec_unresolved")
	if e.Status != facts.StatusOK {
		t.Fatalf("exec_unresolved: %+v", e)
	}
	return e.Value.(int)
}

func TestUnitsStockSSH(t *testing.T) {
	a := unitsAccess("ssh.service")
	a.links[etcUnits+"/multi-user.target.wants/ssh.service"] = "../../../usr/lib/systemd/system/ssh.service"
	a.files[usrUnits+"/ssh.service"] = "units/ssh.service"
	a.stats[usrUnits+"/ssh.service"] = statResult{mode: 0o644, kind: "regular"}
	exe(a, "/usr/sbin/sshd", 0o755, 0, 0)
	exe(a, "/bin/kill", 0o755, 0, 0)
	b := build(t, "units", a)

	rows := unitRows(t, b)
	row := rows["ssh.service"]
	if row == nil || len(rows) != 1 {
		t.Fatalf("rows %v", rows)
	}
	checkEveryExecField(t, row)
	if row["enabled"] != true || row["active"] != true || row["user"] != "" || row["unit_file"] != "file" || row["read_status"] != "ok" {
		t.Errorf("row %v", row)
	}
	if got := filePaths(row); !reflect.DeepEqual(got, []string{usrUnits + "/ssh.service"}) {
		t.Errorf("files %v", got)
	}
	want := []string{"ExecStartPre /usr/sbin/sshd", "ExecStart /usr/sbin/sshd", "ExecReload /usr/sbin/sshd", "ExecReload /bin/kill"}
	if got := execPaths(t, row); !reflect.DeepEqual(got, want) {
		t.Errorf("exec %v", got)
	}
	e := row["exec"].([]any)[3].(map[string]any)
	if e["exists"] != true || e["mode"] != 0o755 || e["uid"] != 0 || e["kind"] != "regular" || e["stat_status"] != "ok" || e["resolved"] != true {
		t.Errorf("stat fields %v", e)
	}
	if got := writableRows(t, b); len(got) != 0 {
		t.Errorf("exec_writable %v", got)
	}
	if n := unresolvedCount(t, b); n != 0 {
		t.Errorf("unresolved %d", n)
	}
	src := env(t, b, "units.root_services").Source
	if src == nil || src.Kind != "derived" || len(src.Inputs) != 2 || src.Inputs[0].Kind != "command" || src.Inputs[1].Path != usrUnits+"/ssh.service" {
		t.Errorf("source %+v", src)
	}
}

// A merged-/usr host spells /usr/bin/kill as /bin/kill; the read primitive
// refuses the symlinked /bin, so the collector reads /bin itself and stats
// the /usr spelling. A /bin that is not that link is not followed.
func TestUnitsMergedUsrAlias(t *testing.T) {
	seed := func(target string) *fsAccess {
		a := unitsAccess("k.service")
		unitText(a, usrUnits+"/k.service", "[Service]\nExecStart=/bin/kill -HUP 1\n")
		a.links["/bin"] = target
		a.fails["/bin/kill"] = fmt.Errorf("/bin/kill: %w", collect.ErrSymlink)
		exe(a, "/usr/bin/kill", 0o775, 0, 0)
		return a
	}
	b := build(t, "units", seed("usr/bin"))
	e := unitRows(t, b)["k.service"]["exec"].([]any)[0].(map[string]any)
	if e["stat_path"] != "/usr/bin/kill" || e["exists"] != true || e["group_writable"] != true {
		t.Errorf("row %v", e)
	}
	if got := writableRows(t, b); !reflect.DeepEqual(got, []string{"k.service /bin/kill group_writable"}) {
		t.Errorf("exec_writable %v", got)
	}

	b = build(t, "units", seed("/elsewhere/bin"))
	e = unitRows(t, b)["k.service"]["exec"].([]any)[0].(map[string]any)
	if e["stat_status"] != "symlink_in_path" || e["exists"] != false || e["mode"] != -1 {
		t.Errorf("row %v", e)
	}
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "k.service /bin/kill") {
		t.Errorf("exec_writable %+v", w)
	}
}

func TestUnitsGeneratedActiveService(t *testing.T) {
	a := unitsAccess("gen.service")
	unitText(a, "/run/systemd/generator.late/gen.service", "[Service]\nExecStart=/usr/bin/gen\n")
	exe(a, "/usr/bin/gen", 0o755, 0, 0)
	b := build(t, "units", a)
	row := unitRows(t, b)["gen.service"]
	if row == nil || row["enabled"] != false || row["active"] != true || row["unit_file"] != "file" {
		t.Fatalf("row %v", row)
	}
	if got := filePaths(row); !reflect.DeepEqual(got, []string{"/run/systemd/generator.late/gen.service"}) {
		t.Errorf("files %v", got)
	}
}

// V-4, V-34: an empty ExecStart= resets the list; a /dev/null link masks a
// drop-in name in a lower tree; an instance's own drop-in beats the
// template's of the same name, and the template's other drop-ins still apply
// in name order.
func TestUnitsDropInResetAndMask(t *testing.T) {
	a := unitsAccess("foo.service", "bar.service", "getty@tty1.service")
	unitText(a, usrUnits+"/foo.service", "[Service]\nExecStart=/usr/bin/foo\n")
	a.files[etcUnits+"/foo.service.d/override.conf"] = "units/dropin-reset.conf"
	a.stats[etcUnits+"/foo.service.d/override.conf"] = statResult{mode: 0o644, kind: "regular"}
	exe(a, "/usr/bin/foo", 0o755, 0, 0)
	exe(a, "/opt/app/bin/run", 0o755, 0, 0)

	unitText(a, usrUnits+"/bar.service", "[Service]\nExecStart=/usr/bin/bar\n")
	unitText(a, usrUnits+"/bar.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/usr/bin/evil\n")
	a.links[etcUnits+"/bar.service.d/override.conf"] = "/dev/null"
	exe(a, "/usr/bin/bar", 0o755, 0, 0)
	exe(a, "/usr/bin/evil", 0o777, 1000, 0)

	unitText(a, usrUnits+"/getty@.service", "[Service]\nExecStart=-/sbin/agetty --noclear %I $TERM\n")
	unitText(a, etcUnits+"/getty@tty1.service.d/10-x.conf", "[Service]\nExecStartPost=/usr/bin/inst\n")
	unitText(a, etcUnits+"/getty@.service.d/10-x.conf", "[Service]\nExecStartPost=/usr/bin/tpl\n")
	unitText(a, usrUnits+"/getty@.service.d/20-y.conf", "[Service]\nExecStopPost=/usr/bin/y\n")
	for _, p := range []string{"/sbin/agetty", "/usr/bin/inst", "/usr/bin/y"} {
		exe(a, p, 0o755, 0, 0)
	}
	exe(a, "/usr/bin/tpl", 0o777, 1000, 0)

	b := build(t, "units", a)
	rows := unitRows(t, b)
	if got := execPaths(t, rows["foo.service"]); !reflect.DeepEqual(got, []string{"ExecStart /opt/app/bin/run"}) {
		t.Errorf("foo exec %v", got)
	}
	if got := execPaths(t, rows["bar.service"]); !reflect.DeepEqual(got, []string{"ExecStart /usr/bin/bar"}) {
		t.Errorf("bar exec %v", got)
	}
	if got := filePaths(rows["bar.service"]); !reflect.DeepEqual(got, []string{usrUnits + "/bar.service"}) {
		t.Errorf("bar files %v", got)
	}
	g := rows["getty@tty1.service"]
	if got := execPaths(t, g); !reflect.DeepEqual(got, []string{"ExecStart /sbin/agetty", "ExecStartPost /usr/bin/inst", "ExecStopPost /usr/bin/y"}) {
		t.Errorf("getty exec %v", got)
	}
	wantFiles := []string{usrUnits + "/getty@.service", etcUnits + "/getty@tty1.service.d/10-x.conf", usrUnits + "/getty@.service.d/20-y.conf"}
	if got := filePaths(g); !reflect.DeepEqual(got, wantFiles) {
		t.Errorf("getty files %v", got)
	}
	if got := writableRows(t, b); len(got) != 0 {
		t.Errorf("exec_writable %v", got)
	}
}

func TestUnitsUserScopes(t *testing.T) {
	a := unitsAccess("web.service", "zero.service", "named.service")
	unitText(a, usrUnits+"/web.service", "[Service]\nExecStart=/usr/bin/web\n")
	a.files[etcUnits+"/web.service.d/user.conf"] = "units/user.conf"
	a.stats[etcUnits+"/web.service.d/user.conf"] = statResult{mode: 0o666, uid: 1000, kind: "regular"} // out of scope: never judged
	unitText(a, usrUnits+"/zero.service", "[Service]\nUser=www-data\nExecStart=/usr/bin/zero\n")
	unitText(a, etcUnits+"/zero.service.d/root.conf", "[Service]\nUser=0\n")
	unitText(a, usrUnits+"/named.service", "[Service]\nUser=root\nExecStart=/usr/bin/named\n")
	exe(a, "/usr/bin/web", 0o777, 1000, 0)
	exe(a, "/usr/bin/zero", 0o755, 0, 0)
	exe(a, "/usr/bin/named", 0o755, 0, 0)
	b := build(t, "units", a)
	rows := unitRows(t, b)
	if _, ok := rows["web.service"]; ok {
		t.Errorf("a www-data service is in scope: %v", rows["web.service"])
	}
	if rows["zero.service"]["user"] != "0" || rows["named.service"]["user"] != "root" {
		t.Errorf("rows %v", rows)
	}
	if got := writableRows(t, b); len(got) != 0 {
		t.Errorf("exec_writable %v", got)
	}
}

// Review Focus 4: a template instance reads its template's file; a first
// token carrying %I is not a path and is not stat-ed, whatever sits at the
// literal spelling.
func TestUnitsTemplateInstance(t *testing.T) {
	a := unitsAccess()
	a.links[etcUnits+"/getty.target.wants/getty@tty1.service"] = usrUnits + "/getty@.service"
	a.files[usrUnits+"/getty@.service"] = "units/getty@.service"
	a.stats[usrUnits+"/getty@.service"] = statResult{mode: 0o644, kind: "regular"}
	exe(a, "/sbin/agetty", 0o755, 0, 0)
	exe(a, "/usr/lib/getty/%I-prepare", 0o777, 1000, 0)
	b := build(t, "units", a)
	row := unitRows(t, b)["getty@tty1.service"]
	if row == nil || row["unit_file"] != "file" || row["enabled"] != true || row["active"] != false {
		t.Fatalf("row %v", row)
	}
	checkEveryExecField(t, row)
	if got := filePaths(row); !reflect.DeepEqual(got, []string{usrUnits + "/getty@.service"}) {
		t.Errorf("files %v", got)
	}
	e := row["exec"].([]any)[0].(map[string]any)
	if e["directive"] != "ExecStartPre" || e["resolved"] != false || e["exists"] != false || e["mode"] != -1 || e["uid"] != -1 || e["stat_status"] != "unresolved" {
		t.Errorf("the %%I row %v", e)
	}
	if n := unresolvedCount(t, b); n != 1 {
		t.Errorf("unresolved %d", n)
	}
	if got := writableRows(t, b); len(got) != 0 {
		t.Errorf("exec_writable %v", got)
	}
}

func TestUnitsWritableExecutables(t *testing.T) {
	a := unitsAccess("app.service")
	a.contents[etcUnits+"/app.service"] = []byte("[Service]\nExecStart=/opt/app/run\nExecStartPost=/usr/local/bin/mine\nExecStop=/usr/local/bin/link\n")
	a.stats[etcUnits+"/app.service"] = statResult{mode: 0o664, kind: "regular"}
	exe(a, "/opt/app/run", 0o775, 0, 1001)
	exe(a, "/usr/local/bin/mine", 0o755, 1000, 1000)
	a.links["/usr/local/bin/link"] = "/opt/app/run"
	b := build(t, "units", a)
	want := []string{
		"app.service /etc/systemd/system/app.service unit_file:group_writable",
		"app.service /opt/app/run group_writable",
		"app.service /usr/local/bin/mine owner",
	}
	if got := writableRows(t, b); !reflect.DeepEqual(got, want) {
		t.Errorf("exec_writable %v", got)
	}
	e := unitRows(t, b)["app.service"]["exec"].([]any)[2].(map[string]any)
	if e["kind"] != "symlink" || e["exists"] != true || e["other_writable"] != false {
		t.Errorf("symlink row %v", e)
	}
}

func TestUnitsUnreadableUnitFileIsAbsent(t *testing.T) {
	a := unitsAccess("secret.service")
	a.stats[etcUnits+"/secret.service"] = statResult{mode: 0o600, kind: "regular"}
	a.fails[etcUnits+"/secret.service"] = fmt.Errorf("%s: %w", etcUnits+"/secret.service", unix.EACCES)
	b := build(t, "units", a)
	w := env(t, b, "units.exec_writable")
	if w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "secret.service "+etcUnits+"/secret.service") {
		t.Errorf("exec_writable %+v", w)
	}
	row := unitRows(t, b)["secret.service"]
	if row["read_status"] != "denied" || !strings.HasPrefix(row["reason"].(string), etcUnits+"/secret.service") || row["unit_file"] != "file" {
		t.Errorf("row %v", row)
	}
	if e := env(t, b, "units.exec_unresolved"); e.Status != facts.StatusOK {
		t.Errorf("exec_unresolved %+v", e)
	}
}

func TestUnitsAliasInSameDirectory(t *testing.T) {
	a := unitsAccess()
	a.links[etcUnits+"/multi-user.target.wants/sshd.service"] = usrUnits + "/sshd.service"
	a.links[etcUnits+"/multi-user.target.wants/other.service"] = etcUnits + "/other.service"
	a.links[etcUnits+"/multi-user.target.wants/masked.service"] = usrUnits + "/masked.service"
	a.links[usrUnits+"/sshd.service"] = "ssh.service"
	a.files[usrUnits+"/ssh.service"] = "units/ssh.service"
	a.stats[usrUnits+"/ssh.service"] = statResult{mode: 0o644, kind: "regular"}
	a.links[etcUnits+"/other.service"] = "/opt/units/other.service"
	a.links[etcUnits+"/masked.service"] = "/dev/null"
	unitText(a, usrUnits+"/masked.service", "[Service]\nExecStart=/usr/bin/masked\n")
	exe(a, "/usr/sbin/sshd", 0o755, 0, 0)
	exe(a, "/bin/kill", 0o755, 0, 0)
	b := build(t, "units", a)
	rows := unitRows(t, b)
	if len(rows) != 2 {
		t.Errorf("rows %v", rows)
	}
	if r := rows["sshd.service"]; r["unit_file"] != "file" || !reflect.DeepEqual(filePaths(r), []string{usrUnits + "/ssh.service"}) || len(r["exec"].([]any)) != 4 {
		t.Errorf("alias row %v", r)
	}
	if r := rows["other.service"]; r["unit_file"] != "symlink" || len(r["exec"].([]any)) != 0 {
		t.Errorf("linked row %v", r)
	}
	if n := unresolvedCount(t, b); n != 1 {
		t.Errorf("unresolved %d", n)
	}
	// V-47: the linked unit's file is not read, so the answer is unknown.
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "other.service") {
		t.Errorf("exec_writable %+v", w)
	}
}

func TestUnitsExecOutsideDeclarationIsAbsent(t *testing.T) {
	a := unitsAccess("srv.service")
	unitText(a, usrUnits+"/srv.service", "[Service]\nExecStart=/srv/app/run\n")
	exe(a, "/srv/app/run", 0o777, 1000, 0)
	b := build(t, "units", a)
	w := env(t, b, "units.exec_writable")
	if w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "srv.service /srv/app/run") {
		t.Errorf("exec_writable %+v", w)
	}
	e := unitRows(t, b)["srv.service"]["exec"].([]any)[0].(map[string]any)
	if e["stat_status"] != "undeclared" || e["exists"] != false || e["mode"] != -1 || e["resolved"] != true {
		t.Errorf("row %v", e)
	}
}

func TestParseListUnitsAndFailures(t *testing.T) {
	a := unitsAccess()
	a.cmds[cmdKey(listUnitsCmd)] = cmdResult{file: "list_units.active"}
	b := build(t, "units", a)
	rows := unitRows(t, b)
	for _, u := range []string{"cron.service", "getty@tty1.service", "ssh.service", "systemd-journald.service", "unattended-upgrades.service"} {
		if r := rows[u]; r == nil || r["unit_file"] != "missing" || r["active"] != true {
			t.Errorf("%s: %v", u, r)
		}
	}
	if len(rows) != 5 || unresolvedCount(t, b) != 5 {
		t.Errorf("rows %d, unresolved %d", len(rows), unresolvedCount(t, b))
	}

	notBooted, err := (&fsAccess{}).read("list_units.notbooted")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		res  cmdResult
		want facts.Status
		text string
	}{
		"not booted": {cmdResult{stderr: string(notBooted), exitCode: 1}, facts.StatusUnsupported, "System has not been booted"},
		"no start":   {cmdResult{exitCode: -1, err: errors.New("exec: not found")}, facts.StatusUnsupported, "exec: not found"},
		"timeout":    {cmdResult{timedOut: true, exitCode: -1}, facts.StatusTimeout, "timed out"},
		"other exit": {cmdResult{stderr: "Failed to connect to bus\n", exitCode: 1}, facts.StatusError, "exited 1: Failed to connect to bus"},
	} {
		a := unitsAccess()
		a.cmds[cmdKey(listUnitsCmd)] = c.res
		b := build(t, "units", a)
		for _, k := range []string{"units.root_services", "units.exec_writable", "units.exec_unresolved"} {
			if e := env(t, b, k); e.Status != c.want || !strings.Contains(e.Reason, c.text) {
				t.Errorf("%s: %s = %+v", name, k, e)
			}
		}
	}
}

func TestUnitsNoSystemdAndCaps(t *testing.T) {
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := build(t, "units", &fsAccess{})
	n := 0
	for _, k := range reg.Keys {
		if k.Collector != "units" {
			continue
		}
		n++
		if e := env(t, b, k.Key); e.Status != facts.StatusUnsupported || e.Reason != "no systemd on this host or inside this container" {
			t.Errorf("%s: %+v", k.Key, e)
		}
	}
	if n != 3 {
		t.Errorf("%d units keys registered", n)
	}

	var many []string
	for i := 0; i < unitRowCap+1; i++ {
		many = append(many, fmt.Sprintf("u%03d.service", i))
	}
	b = build(t, "units", unitsAccess(many...))
	if rows := okList(t, b, "units.root_services"); len(rows) != unitRowCap {
		t.Errorf("%d rows", len(rows))
	}
	for _, k := range []string{"units.root_services", "units.exec_writable", "units.exec_unresolved"} {
		if e := env(t, b, k); !e.Truncated {
			t.Errorf("%s not truncated: %+v", k, e)
		}
	}
	if n := unresolvedCount(t, b); n != unitRowCap {
		t.Errorf("unresolved %d", n)
	}
}

// --- fix round 1 -------------------------------------------------------

// A lone ";" word runs a second command as root: it gets its own row and
// is judged.
func TestUnitsSemicolonSeparatesCommands(t *testing.T) {
	a := unitsAccess("semi.service")
	unitText(a, usrUnits+"/semi.service", "[Service]\nExecStartPre=/bin/true ; /opt/x/evil\nExecStart=/usr/bin/semi\n")
	exe(a, "/bin/true", 0o755, 0, 0)
	exe(a, "/opt/x/evil", 0o777, 0, 0)
	exe(a, "/usr/bin/semi", 0o755, 0, 0)
	b := build(t, "units", a)
	want := []string{"ExecStartPre /bin/true", "ExecStartPre /opt/x/evil", "ExecStart /usr/bin/semi"}
	if got := execPaths(t, unitRows(t, b)["semi.service"]); !reflect.DeepEqual(got, want) {
		t.Errorf("exec %v", got)
	}
	if got := writableRows(t, b); !reflect.DeepEqual(got, []string{"semi.service /opt/x/evil group_writable", "semi.service /opt/x/evil other_writable"}) {
		t.Errorf("exec_writable %v", got)
	}
}

// V-47: a linked unit file, and an active unit with no file, are unknown; an
// enabled-only unit whose .wants link dangles runs nothing.
func TestUnitsLinkedOrMissingActiveIsAbsent(t *testing.T) {
	a := unitsAccess()
	a.links[etcUnits+"/multi-user.target.wants/app.service"] = etcUnits + "/app.service"
	a.links[etcUnits+"/app.service"] = "/home/dev/app.service"
	b := build(t, "units", a)
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "app.service "+etcUnits+"/app.service (unit_file symlink)") {
		t.Errorf("linked: %+v", w)
	}

	b = build(t, "units", unitsAccess("ghost.service"))
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "ghost.service (unit_file missing)") {
		t.Errorf("active missing: %+v", w)
	}

	a = unitsAccess()
	a.links[etcUnits+"/multi-user.target.wants/gone.service"] = usrUnits + "/gone.service"
	b = build(t, "units", a)
	if got := writableRows(t, b); len(got) != 0 {
		t.Errorf("enabled-only missing: %v", got)
	}
	if r := unitRows(t, b)["gone.service"]; r["unit_file"] != "missing" || unresolvedCount(t, b) != 1 {
		t.Errorf("row %v", r)
	}
}

// V-46: a root-owned 0755 binary in a directory a non-root user may write
// can be replaced by that user.
func TestUnitsParentWritable(t *testing.T) {
	a := unitsAccess("p.service")
	unitText(a, usrUnits+"/p.service", "[Service]\nExecStart=/opt/app/run\n")
	a.stats["/opt/app/run"] = statResult{mode: 0o755, kind: "regular", parentUntrusted: true}
	b := build(t, "units", a)
	if got := writableRows(t, b); !reflect.DeepEqual(got, []string{"p.service /opt/app/run parent_writable"}) {
		t.Errorf("exec_writable %v", got)
	}
}

// A symlinked executable is followed one hop to a declared target, which is
// judged; a target outside the declaration is unknown.
func TestUnitsSymlinkedExecutableOneHop(t *testing.T) {
	a := unitsAccess("l.service")
	unitText(a, usrUnits+"/l.service", "[Service]\nExecStart=/usr/local/bin/app\n")
	a.links["/usr/local/bin/app"] = "../../../opt/app/current"
	exe(a, "/opt/app/current", 0o755, 1000, 1000)
	b := build(t, "units", a)
	e := unitRows(t, b)["l.service"]["exec"].([]any)[0].(map[string]any)
	if e["kind"] != "symlink" || e["stat_path"] != "/opt/app/current" || e["uid"] != 1000 || e["stat_status"] != "ok" {
		t.Errorf("row %v", e)
	}
	if got := writableRows(t, b); !reflect.DeepEqual(got, []string{"l.service /opt/app/current owner"}) {
		t.Errorf("exec_writable %v", got)
	}

	// D5-2: whoever may write the link's directory may replace the link, so
	// that directory is judged too.
	a = unitsAccess("l.service")
	unitText(a, usrUnits+"/l.service", "[Service]\nExecStart=/usr/local/bin/app\n")
	a.links["/usr/local/bin/app"] = "/opt/app/bin"
	a.untrustedDirs = map[string]bool{"/usr/local/bin": true}
	exe(a, "/opt/app/bin", 0o755, 0, 0)
	b = build(t, "units", a)
	if got := writableRows(t, b); !reflect.DeepEqual(got, []string{"l.service /usr/local/bin/app parent_writable"}) {
		t.Errorf("writable link directory: exec_writable %v", got)
	}

	// D5-4: a link whose target is missing: the link exists (exists, kind),
	// its target does not (stat_status, stat_path), and nothing is judged.
	a = unitsAccess("l.service")
	unitText(a, usrUnits+"/l.service", "[Service]\nExecStart=/usr/local/bin/app\n")
	a.links["/usr/local/bin/app"] = "/opt/app/gone"
	b = build(t, "units", a)
	e = unitRows(t, b)["l.service"]["exec"].([]any)[0].(map[string]any)
	if e["exists"] != true || e["kind"] != "symlink" || e["stat_status"] != "missing" || e["stat_path"] != "/opt/app/gone" || e["mode"] != -1 {
		t.Errorf("dangling link row %v", e)
	}
	if got := writableRows(t, b); len(got) != 0 {
		t.Errorf("dangling link: exec_writable %v", got)
	}

	a = unitsAccess("l.service")
	unitText(a, usrUnits+"/l.service", "[Service]\nExecStart=/usr/local/bin/app\n")
	a.links["/usr/local/bin/app"] = "/srv/app/run"
	exe(a, "/srv/app/run", 0o777, 1000, 0)
	b = build(t, "units", a)
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "l.service /usr/local/bin/app -> /srv/app/run") {
		t.Errorf("exec_writable %+v", w)
	}
}

// Minor 6: systemd's \x2d escape in an instance name is a glob escape to
// filepath.Glob; the name is quoted so its own drop-in directory matches.
func TestUnitsEscapedInstanceDropIn(t *testing.T) {
	unit := `systemd-fsck@dev-disk-by\x2duuid-1.service`
	a := unitsAccess(unit)
	unitText(a, usrUnits+"/systemd-fsck@.service", "[Service]\nExecStart=/usr/lib/systemd/systemd-fsck\n")
	unitText(a, etcUnits+"/"+unit+".d/10-x.conf", "[Service]\nExecStartPost=/usr/bin/inst\n")
	exe(a, "/usr/lib/systemd/systemd-fsck", 0o755, 0, 0)
	exe(a, "/usr/bin/inst", 0o755, 0, 0)
	b := build(t, "units", a)
	if got := execPaths(t, unitRows(t, b)[unit]); !reflect.DeepEqual(got, []string{"ExecStart /usr/lib/systemd/systemd-fsck", "ExecStartPost /usr/bin/inst"}) {
		t.Errorf("exec %v", got)
	}

	// D5-1: the escaped instance's own drop-in directory, unsearchable, is
	// the denial it is — the probe names the directory as it is on disk,
	// never an empty list read as "no drop-ins".
	a.deniedDirs = map[string]bool{etcUnits + "/" + unit + ".d": true}
	b = build(t, "units", a)
	row := unitRows(t, b)[unit]
	if row["read_status"] != "denied" || !strings.HasPrefix(row["reason"].(string), etcUnits+"/systemd-fsck@dev-disk-by") {
		t.Errorf("denied instance drop-in directory: row %v", row)
	}
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent {
		t.Errorf("exec_writable %+v, want absent naming the unit", w)
	}
}

// Minor 8: user@.service's User=%i names the instance; root's user manager
// stays in scope, another user's does not.
func TestUnitsUserInstance(t *testing.T) {
	a := unitsAccess("user@0.service", "user@1000.service")
	unitText(a, usrUnits+"/user@.service", "[Service]\nUser=%i\nExecStart=/usr/lib/systemd/systemd --user\n")
	exe(a, "/usr/lib/systemd/systemd", 0o755, 0, 0)
	b := build(t, "units", a)
	rows := unitRows(t, b)
	if r := rows["user@0.service"]; r == nil || r["user"] != "0" {
		t.Errorf("user@0 %v", r)
	}
	if _, ok := rows["user@1000.service"]; ok {
		t.Errorf("user@1000 is in scope")
	}
}

// Minor 10: an executable that cannot be stat-ed, and a drop-in that is a
// symlink other than a mask, are both unknown.
func TestUnitsExecStatDeniedAndSymlinkDropIn(t *testing.T) {
	a := unitsAccess("d.service")
	unitText(a, usrUnits+"/d.service", "[Service]\nExecStart=/usr/bin/hidden\n")
	a.fails["/usr/bin/hidden"] = fmt.Errorf("/usr/bin/hidden: %w", unix.EACCES)
	b := build(t, "units", a)
	e := unitRows(t, b)["d.service"]["exec"].([]any)[0].(map[string]any)
	if e["stat_status"] != "denied" || e["exists"] != false {
		t.Errorf("row %v", e)
	}
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "d.service /usr/bin/hidden") {
		t.Errorf("exec_writable %+v", w)
	}

	a = unitsAccess("s.service")
	unitText(a, usrUnits+"/s.service", "[Service]\nExecStart=/usr/bin/s\n")
	a.links[etcUnits+"/s.service.d/a.conf"] = "/opt/confs/a.conf"
	exe(a, "/usr/bin/s", 0o755, 0, 0)
	b = build(t, "units", a)
	if r := unitRows(t, b)["s.service"]; r["read_status"] != "error" || !strings.Contains(r["reason"].(string), etcUnits+"/s.service.d/a.conf") {
		t.Errorf("row %v", r)
	}
	if w := env(t, b, "units.exec_writable"); w.Status != facts.StatusAbsent || !strings.Contains(w.Reason, "s.service.d/a.conf") {
		t.Errorf("exec_writable %+v", w)
	}
}

// Minor 11: an empty unit file is a mask.
func TestUnitsEmptyUnitFileIsAMask(t *testing.T) {
	a := unitsAccess("empty.service")
	unitText(a, etcUnits+"/empty.service", "")
	unitText(a, usrUnits+"/empty.service", "[Service]\nExecStart=/usr/bin/x\n")
	b := build(t, "units", a)
	if rows := unitRows(t, b); len(rows) != 0 {
		t.Errorf("rows %v", rows)
	}
}

// Minor 9: a unit past the cap contributes nothing to exec_writable.
func TestUnitsPastTheCapFlagsNothing(t *testing.T) {
	var many []string
	for i := 0; i < unitRowCap+1; i++ {
		many = append(many, fmt.Sprintf("u%03d.service", i))
	}
	a := unitsAccess(many...)
	last := fmt.Sprintf("u%03d.service", unitRowCap)
	unitText(a, usrUnits+"/"+last, "[Service]\nExecStart=/usr/bin/bad\n")
	exe(a, "/usr/bin/bad", 0o777, 0, 0)
	for i := 0; i < unitRowCap; i++ {
		unitText(a, fmt.Sprintf("%s/u%03d.service", usrUnits, i), "[Service]\nExecStart=/usr/bin/ok\n")
	}
	exe(a, "/usr/bin/ok", 0o755, 0, 0)
	b := build(t, "units", a)
	w := env(t, b, "units.exec_writable")
	if w.Status != facts.StatusOK || !w.Truncated || len(w.Value.([]any)) != 0 {
		t.Errorf("exec_writable %+v", w)
	}
	if rows := okList(t, b, "units.root_services"); len(rows) != unitRowCap {
		t.Errorf("%d rows", len(rows))
	}
}
