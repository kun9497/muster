//go:build linux

package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// cmdResult is one canned command outcome for fsAccess.
type cmdResult struct {
	file     string // testdata file served as stdout
	stderr   string
	exitCode int
	timedOut bool
	err      error // set only when the command could not be started at all
}

// fsAccess serves declared paths from testdata and commands from canned
// outcomes. It implements all six Access methods (R46/R60), so a collector
// under test can never reach the real host.
type fsAccess struct {
	files    map[string]string    // host path -> testdata file name
	dirs     map[string]bool      // host path -> exists, but is not a readable file
	cmds     map[string]cmdResult // command line -> canned outcome
	fails    map[string]error     // host path -> error returned instead of content
	modes    map[string]uint32    // host path -> raw 0o7777 bits
	xattrs   map[string][]string  // host path -> extended attribute names
	writable map[string]bool      // host path -> Writable answer
}

func (a *fsAccess) read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("testdata", name))
}

func (a *fsAccess) mode(p string, def uint32) uint32 {
	if m, ok := a.modes[p]; ok {
		return m
	}
	return def
}

func (a *fsAccess) ReadFile(p string, _ int64) ([]byte, collect.ReadMeta, error) {
	if err, ok := a.fails[p]; ok {
		return nil, collect.ReadMeta{}, err
	}
	name, ok := a.files[p]
	if !ok {
		return nil, collect.ReadMeta{}, os.ErrNotExist
	}
	b, err := a.read(name)
	return b, collect.ReadMeta{Tier: "openat2", Size: int64(len(b)), Mode: a.mode(p, 0o644)}, err
}

func (a *fsAccess) Stat(p string) (collect.ReadMeta, error) {
	if err, ok := a.fails[p]; ok {
		return collect.ReadMeta{}, err
	}
	if _, ok := a.files[p]; ok {
		return collect.ReadMeta{Tier: "openat2", Mode: a.mode(p, 0o644)}, nil
	}
	if a.dirs[p] {
		return collect.ReadMeta{Tier: "openat2", Mode: a.mode(p, 0o755)}, nil
	}
	return collect.ReadMeta{}, os.ErrNotExist
}

// Glob matches the pattern against the fixture map with path.Match and
// returns the matches sorted, so a collector that depends on Glob order —
// sshd's Include expansion — is exercised deterministically.
func (a *fsAccess) Glob(pattern string) ([]string, error) {
	var out []string
	for p := range a.files {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	for p := range a.dirs {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (a *fsAccess) Llistxattr(p string) ([]string, error) {
	if err, ok := a.fails[p]; ok {
		return nil, err
	}
	return a.xattrs[p], nil
}

func (a *fsAccess) Writable(p string) bool { return a.writable[p] }

func (a *fsAccess) Run(_ context.Context, c collect.Command) collect.Output {
	line := strings.TrimSpace(c.Path + " " + strings.Join(c.Args, " "))
	r, ok := a.cmds[line]
	if !ok {
		return collect.Output{ExitCode: 127, Err: os.ErrNotExist} // no such binary here
	}
	var stdout []byte
	if r.file != "" {
		b, err := a.read(r.file)
		if err != nil {
			return collect.Output{ExitCode: -1, Err: err}
		}
		stdout = b
	}
	return collect.Output{
		Stdout:   stdout,
		Stderr:   []byte(r.stderr),
		ExitCode: r.exitCode,
		TimedOut: r.timedOut,
		Err:      r.err,
	}
}

func collectorNamed(t *testing.T, name string) collect.Collector {
	t.Helper()
	for _, c := range collect.All() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("collector %s is not registered", name)
	return collect.Collector{}
}

// build runs one collector under the guard and fails the test if it touched
// anything it did not declare (spec §11).
func build(t *testing.T, name string, a collect.Access) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	c := collectorNamed(t, name)
	g := collect.Guard(a, c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("%s touched undeclared targets: %v", name, v)
	}
	return b
}

func leaf(t *testing.T, b *collect.Builder, key string) any {
	t.Helper()
	cur := any(b.Tree())
	for _, s := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: not present", key)
		}
		cur = m[s]
	}
	return cur
}

func env(t *testing.T, b *collect.Builder, key string) facts.Envelope {
	t.Helper()
	e, ok := leaf(t, b, key).(facts.Envelope)
	if !ok {
		t.Fatalf("%s: not an envelope", key)
	}
	return e
}

// okList fetches an ok list-valued fact, reporting the envelope rather than
// panicking on a type assertion when the collector did not produce one.
func okList(t *testing.T, b *collect.Builder, key string) []any {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v", key, e)
	}
	list, ok := e.Value.([]any)
	if !ok {
		t.Fatalf("%s: value is %#v, not a list", key, e.Value)
	}
	return list
}

func setting(t *testing.T, b *collect.Builder, key string) facts.Setting {
	t.Helper()
	s, ok := leaf(t, b, key).(facts.Setting)
	if !ok {
		t.Fatalf("%s: not a setting", key)
	}
	return s
}

// --- sshd ---------------------------------------------------------------

func TestSshdRuntimeAndPersistedWithInclude(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{
			"/etc/ssh/sshd_config":                      "sshd_config",
			"/etc/ssh/sshd_config.d/50-cloud-init.conf": "sshd_config.d_50-cloud-init.conf",
		},
		cmds: map[string]cmdResult{"/usr/sbin/sshd -T": {file: "sshd_T.txt"}},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Value != "prohibit-password" || s.Effective.Value != "prohibit-password" {
		t.Errorf("runtime/effective %+v %+v", s.Runtime, s.Effective)
	}
	if s.Persisted.Value != "no" || s.Persisted.Source.Path != "/etc/ssh/sshd_config.d/50-cloud-init.conf" || s.Persisted.Source.Line != 2 {
		t.Errorf("persisted must come from the Include (first occurrence wins): %+v", s.Persisted)
	}
	if env(t, b, "sshd.collect_method").Value != "T" || env(t, b, "sshd.personas_collected").Value != false {
		t.Error("method/personas")
	}
}

func TestSshdFallsBackToParseWhenTUnavailable(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"}}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime != nil || s.Effective.Value != "yes" || !strings.Contains(s.Effective.Reason, "sshd -T unavailable") {
		t.Errorf("%+v", s)
	}
	if env(t, b, "sshd.collect_method").Value != "parse" {
		t.Error("method must be parse")
	}
}

// R59: a non-zero sshd -T exit is an error runtime side carrying the first
// stderr line and the command as its source, and the method is "parse"
// because -T did not answer.
func TestSshdNonZeroExitIsAnErrorRuntimeSide(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/ssh/sshd_config": "sshd_config"},
		cmds: map[string]cmdResult{"/usr/sbin/sshd -T": {
			exitCode: 255,
			stderr:   "/etc/ssh/sshd_config line 3: Bad configuration option\nsecond line\n",
		}},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Status != facts.StatusError {
		t.Fatalf("runtime %+v", s.Runtime)
	}
	if s.Runtime.Reason != "/etc/ssh/sshd_config line 3: Bad configuration option" {
		t.Errorf("reason must be the first stderr line: %q", s.Runtime.Reason)
	}
	if s.Runtime.Source == nil || s.Runtime.Source.Cmd != "/usr/sbin/sshd -T" {
		t.Errorf("source %+v", s.Runtime.Source)
	}
	if env(t, b, "sshd.collect_method").Value != "parse" {
		t.Error("method must be parse when -T exited non-zero")
	}
	if s.Effective.Status != facts.StatusOK || s.Effective.Value != "yes" {
		t.Errorf("effective must fall back to the ok persisted value: %+v", s.Effective)
	}
}

func TestSshdPermissionDeniedIsDeniedAndCopiedToEffective(t *testing.T) {
	a := &fsAccess{
		fails: map[string]error{"/etc/ssh/sshd_config": os.ErrPermission},
		cmds: map[string]cmdResult{"/usr/sbin/sshd -T": {
			exitCode: 1,
			stderr:   "/etc/ssh/sshd_config: Permission denied\n",
		}},
	}
	b := build(t, "sshd", a)
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Runtime == nil || s.Runtime.Status != facts.StatusDenied {
		t.Fatalf("runtime %+v", s.Runtime)
	}
	// R59: a non-ok persisted side is copied to effective unchanged, so the
	// reason still says why there is no value.
	if s.Persisted.Status != facts.StatusDenied || s.Effective.Status != facts.StatusDenied || s.Effective.Reason != s.Persisted.Reason {
		t.Errorf("persisted %+v effective %+v", s.Persisted, s.Effective)
	}
}

// R55/R75: an Include pointing outside the declaration is recorded on the
// persisted side and expansion stops; it is not a guard violation.
func TestSshdIncludeOutsideDeclarationIsRecordedNotViolated(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/ssh/sshd_config": "sshd_config_outside_include"}}
	b := build(t, "sshd", a) // build fails the test on any violation
	s := setting(t, b, "sshd.options.permit_root_login")
	if s.Persisted == nil || s.Persisted.Status != facts.StatusError {
		t.Fatalf("persisted %+v", s.Persisted)
	}
	if !strings.Contains(s.Persisted.Reason, "/etc/ssh/other/*.conf") ||
		!strings.Contains(s.Persisted.Reason, "outside the collector's declaration") {
		t.Errorf("reason %q", s.Persisted.Reason)
	}
}

// --- accounts -----------------------------------------------------------

func TestAccountsDerivesRuntimeAgeingWithoutStoringHashes(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs",
		"/etc/shadow":     "shadow",
		"/etc/passwd":     "passwd",
	}}
	b := build(t, "accounts", a)
	mx := setting(t, b, "accounts.login_defs.pass_max_days")
	if mx.Persisted.Value != 90 || mx.Persisted.Source.Line != 2 || mx.Runtime.Value != 99999 || mx.Runtime.Source.Kind != "derived" {
		t.Errorf("%+v %+v", mx.Persisted, mx.Runtime)
	}
	mn := setting(t, b, "accounts.login_defs.pass_min_days")
	if mn.Persisted.Value != 1 || mn.Runtime.Value != 0 {
		t.Errorf("%+v %+v", mn.Persisted, mn.Runtime)
	}
	if e := env(t, b, "accounts.login_defs.pass_min_len"); e.Value != 8 {
		t.Errorf("pass_min_len %+v", e)
	}
	users := okList(t, b, "accounts.users")
	if len(users) != 3 {
		t.Fatalf("users %+v", users)
	}
	for _, u := range users {
		for k, v := range u.(map[string]any) {
			if s, ok := v.(string); ok && strings.Contains(s, "hashhash") {
				t.Fatalf("hash leaked into %s=%q", k, s)
			}
		}
	}
	root := users[0].(map[string]any)
	if root["hash_algo"] != "$6$" || root["password_status"] != "hashed" {
		t.Errorf("%v", root)
	}
	if users[1].(map[string]any)["password_status"] != "locked" {
		t.Errorf("%v", users[1])
	}
	if users[2].(map[string]any)["hash_algo"] != "$y$" {
		t.Errorf("%v", users[2])
	}
}

func TestAccountsShadowDeniedIsDeniedNotAbsent(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd"},
		fails: map[string]error{"/etc/shadow": os.ErrPermission},
	}
	b := build(t, "accounts", a)
	if e := setting(t, b, "accounts.login_defs.pass_max_days").Runtime; e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
	if e := setting(t, b, "accounts.login_defs.pass_min_days").Runtime; e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
	users := okList(t, b, "accounts.users")
	if len(users) != 3 {
		t.Fatalf("users %v", users)
	}
	if _, present := users[0].(map[string]any)["password_status"]; present {
		t.Errorf("a shadow field appeared without shadow: %v", users[0])
	}
}

// --- sockets ------------------------------------------------------------

func TestSocketsParsesListeningAndLoopback(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}}
	b := build(t, "sockets", a)
	list := okList(t, b, "sockets.listening")
	if len(list) != 2 {
		t.Fatalf("%v", list)
	}
	first := list[0].(map[string]any)
	if first["port"] != 22 || first["loopback"] != false || first["proto"] != "tcp" ||
		first["addr"] != "0.0.0.0" || first["inode"] != 12345 {
		t.Errorf("%v", first)
	}
	if list[1].(map[string]any)["loopback"] != true {
		t.Errorf("%v", list[1])
	}
}

func TestSocketsParsesIPv6Loopback(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/proc/self/net/tcp":  "proc_net_tcp_empty",
		"/proc/self/net/tcp6": "proc_net_tcp6_loopback",
	}}
	b := build(t, "sockets", a)
	list := okList(t, b, "sockets.listening")
	if len(list) != 2 {
		t.Fatalf("%v", list)
	}
	if list[0].(map[string]any)["addr"] != "::1" || list[0].(map[string]any)["loopback"] != true {
		t.Errorf("%v", list[0])
	}
	if list[1].(map[string]any)["addr"] != "::" || list[1].(map[string]any)["loopback"] != false {
		t.Errorf("%v", list[1])
	}
}

// R50: an empty table serialises as [], never null.
func TestSocketsEmptyTableIsAnEmptyList(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/proc/self/net/tcp": "proc_net_tcp_empty"}}
	b := build(t, "sockets", a)
	e := env(t, b, "sockets.listening")
	if e.Status != facts.StatusOK {
		t.Fatalf("%+v", e)
	}
	list, ok := e.Value.([]any)
	if !ok || list == nil || len(list) != 0 {
		t.Errorf("want an empty non-nil list, got %#v", e.Value)
	}
}

func TestSocketsUnreadableTableIsNotAnEmptyList(t *testing.T) {
	a := &fsAccess{fails: map[string]error{"/proc/self/net/tcp": os.ErrPermission}}
	b := build(t, "sockets", a)
	if e := env(t, b, "sockets.listening"); e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
}

// --- files --------------------------------------------------------------

func TestFilesPasswdPermissionFacts(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/passwd": "passwd"}}
	b := build(t, "files", a)
	if env(t, b, "files.etc_passwd.mode").Value != 420 || env(t, b, "files.etc_passwd.uid").Value != 0 {
		t.Error("mode/uid")
	}
	if env(t, b, "files.etc_passwd.gid").Value != 0 {
		t.Error("gid")
	}
	if env(t, b, "files.etc_passwd.acl_present").Value != false {
		t.Error("acl_present")
	}
	if env(t, b, "files.etc_securetty").Status != facts.StatusAbsent {
		t.Error("securetty is absent on this fixture")
	}
	if env(t, b, "files.etc_securetty_lines").Status != facts.StatusAbsent {
		t.Error("securetty lines are absent on this fixture")
	}
}

// R51/R69: the raw 0o7777 bits are reported, so a setgid bit survives —
// FileMode.Perm() would have dropped it and reported a clean 0644.
func TestFilesPasswdModeKeepsTheHighBits(t *testing.T) {
	a := &fsAccess{
		files: map[string]string{"/etc/passwd": "passwd"},
		modes: map[string]uint32{"/etc/passwd": 0o2644},
	}
	b := build(t, "files", a)
	if got := env(t, b, "files.etc_passwd.mode").Value; got != 0o2644 {
		t.Errorf("mode %v, want %v", got, 0o2644)
	}
}

func TestFilesAclPresentFromXattr(t *testing.T) {
	a := &fsAccess{
		files:  map[string]string{"/etc/passwd": "passwd"},
		xattrs: map[string][]string{"/etc/passwd": {"security.selinux", "system.posix_acl_access"}},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_passwd.acl_present").Value != true {
		t.Error("acl_present must be true")
	}
}

func TestFilesNonAclXattrIsNotAnAcl(t *testing.T) {
	a := &fsAccess{
		files:  map[string]string{"/etc/passwd": "passwd"},
		xattrs: map[string][]string{"/etc/passwd": {"security.selinux"}},
	}
	b := build(t, "files", a)
	if env(t, b, "files.etc_passwd.acl_present").Value != false {
		t.Error("a selinux label is not an ACL")
	}
}

func TestFilesSecurettyLinesSkipBlanksAndComments(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/passwd": "passwd", "/etc/securetty": "securetty"}}
	b := build(t, "files", a)
	lines, ok := env(t, b, "files.etc_securetty_lines").Value.([]any)
	if !ok || len(lines) != 2 || lines[0] != "console" || lines[1] != "tty1" {
		t.Errorf("%#v", env(t, b, "files.etc_securetty_lines").Value)
	}
	rec, ok := env(t, b, "files.etc_securetty").Value.(map[string]any)
	if !ok || rec["mode"] != 0o644 {
		t.Errorf("%#v", env(t, b, "files.etc_securetty").Value)
	}
}

// --- services -----------------------------------------------------------

func showLine(unit string) string {
	return "/usr/bin/systemctl show -p LoadState,ActiveState,UnitFileState,SubState " + unit
}

// allUnitsNotFound cans a systemd that answers, and says every unit this
// collector asks about is unknown to it.
func allUnitsNotFound() map[string]cmdResult {
	out := map[string]cmdResult{}
	for _, u := range []string{
		"ssh.service", "sshd.service", "ssh.socket",
		"telnet.socket", "telnet.service", "telnetd.service",
		"inetd.service", "xinetd.service",
	} {
		out[showLine(u)] = cmdResult{file: "systemctl.notfound"}
	}
	return out
}

func servicesAccess(files map[string]string, cmds map[string]cmdResult) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	if cmds == nil {
		cmds = map[string]cmdResult{}
	}
	return &fsAccess{
		files: files,
		dirs:  map[string]bool{"/run/systemd/system": true},
		cmds:  cmds,
	}
}

func TestServicesUnsupportedWithoutSystemd(t *testing.T) {
	b := build(t, "services", &fsAccess{})
	for _, k := range []string{
		"services.ssh.installed", "services.ssh.active",
		"services.telnet.installed", "services.telnet.reachable",
	} {
		if e := env(t, b, k); e.Status != facts.StatusUnsupported {
			t.Errorf("%s: %+v", k, e)
		}
	}
}

func TestServicesSshInstalledAndActive(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{file: "systemctl.loaded.active"}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if env(t, b, "services.ssh.installed").Value != true || env(t, b, "services.ssh.active").Value != true {
		t.Errorf("ssh %+v %+v", env(t, b, "services.ssh.installed"), env(t, b, "services.ssh.active"))
	}
	if env(t, b, "services.telnet.installed").Value != false {
		t.Errorf("telnet installed %+v", env(t, b, "services.telnet.installed"))
	}
	// The only port-23 listener in that fixture is bound to 127.0.0.1.
	if env(t, b, "services.telnet.reachable").Value != false {
		t.Errorf("telnet reachable %+v", env(t, b, "services.telnet.reachable"))
	}
}

func TestServicesSshInstalledButInactive(t *testing.T) {
	cmds := allUnitsNotFound()
	cmds[showLine("ssh.service")] = cmdResult{file: "systemctl.loaded.inactive"}
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, cmds)
	b := build(t, "services", a)
	if env(t, b, "services.ssh.installed").Value != true || env(t, b, "services.ssh.active").Value != false {
		t.Errorf("ssh %+v %+v", env(t, b, "services.ssh.installed"), env(t, b, "services.ssh.active"))
	}
}

func TestServicesSshActiveIsAbsentWhenNoUnitIsLoaded(t *testing.T) {
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, allUnitsNotFound())
	b := build(t, "services", a)
	if env(t, b, "services.ssh.installed").Value != false {
		t.Errorf("installed %+v", env(t, b, "services.ssh.installed"))
	}
	if env(t, b, "services.ssh.active").Status != facts.StatusAbsent {
		t.Errorf("active %+v", env(t, b, "services.ssh.active"))
	}
}

// R63: a live xinetd telnet block counts as installed, and a non-loopback
// port-23 listener makes it reachable.
func TestServicesTelnetInstalledFromXinetdAndReachable(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp":   "proc_net_tcp_telnet",
		"/etc/xinetd.d/telnet": "xinetd.telnet",
	}, allUnitsNotFound())
	b := build(t, "services", a)
	if env(t, b, "services.telnet.installed").Value != true {
		t.Errorf("installed %+v", env(t, b, "services.telnet.installed"))
	}
	if env(t, b, "services.telnet.reachable").Value != true {
		t.Errorf("reachable %+v", env(t, b, "services.telnet.reachable"))
	}
}

func TestServicesTelnetInstalledFromInetdConf(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp": "proc_net_tcp",
		"/etc/inetd.conf":    "inetd.conf.telnet",
	}, allUnitsNotFound())
	b := build(t, "services", a)
	e := env(t, b, "services.telnet.installed")
	if e.Value != true || e.Source == nil || e.Source.Path != "/etc/inetd.conf" || e.Source.Line != 2 {
		t.Errorf("installed %+v %+v", e, e.Source)
	}
}

// R63: a comment line never counts, in either legacy file.
func TestServicesCommentedTelnetEntriesAreNotInstalled(t *testing.T) {
	a := servicesAccess(map[string]string{
		"/proc/self/net/tcp":   "proc_net_tcp",
		"/etc/inetd.conf":      "inetd.conf.commented",
		"/etc/xinetd.d/telnet": "xinetd.telnet.commented",
	}, allUnitsNotFound())
	b := build(t, "services", a)
	if env(t, b, "services.telnet.installed").Value != false {
		t.Errorf("a commented entry must not count: %+v", env(t, b, "services.telnet.installed"))
	}
}

// R41: with the socket table unreadable, reachable carries that read's
// envelope. A silent false would be a PASS on no evidence.
func TestServicesTelnetReachableCarriesTheSocketReadError(t *testing.T) {
	a := servicesAccess(nil, allUnitsNotFound())
	a.fails = map[string]error{"/proc/self/net/tcp": os.ErrPermission}
	b := build(t, "services", a)
	if e := env(t, b, "services.telnet.reachable"); e.Status != facts.StatusDenied {
		t.Errorf("%+v", e)
	}
	// installed stays independent of the socket read.
	if e := env(t, b, "services.telnet.installed"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("installed %+v", e)
	}
}

// A systemd host whose systemctl cannot be run has no unit evidence at all;
// reporting "not installed" there would be a PASS on nothing.
func TestServicesUnitQueryFailureIsNotASilentFalse(t *testing.T) {
	a := servicesAccess(map[string]string{"/proc/self/net/tcp": "proc_net_tcp"}, nil)
	b := build(t, "services", a)
	if e := env(t, b, "services.ssh.installed"); e.Status != facts.StatusError {
		t.Errorf("ssh installed %+v", e)
	}
	if e := env(t, b, "services.telnet.installed"); e.Status != facts.StatusError {
		t.Errorf("telnet installed %+v", e)
	}
	// reachable is still answerable from the socket table alone.
	if e := env(t, b, "services.telnet.reachable"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("reachable %+v", e)
	}
}

// --- os -----------------------------------------------------------------

func osAccess() *fsAccess {
	return &fsAccess{
		files: map[string]string{
			"/etc/os-release":                          "os-release",
			"/etc/hostname":                            "hostname",
			"/etc/machine-id":                          "machine-id",
			"/proc/sys/kernel/osrelease":               "kernel-osrelease",
			"/proc/sys/kernel/random/boot_id":          "boot-id",
			"/proc/uptime":                             "uptime",
			"/proc/version":                            "proc-version",
			"/proc/1/cgroup":                           "proc-1-cgroup",
			"/proc/1/comm":                             "proc-1-comm",
			"/sys/devices/virtual/dmi/id/product_name": "dmi-product-name",
		},
		dirs:     map[string]bool{"/run/systemd/system": true, "/var/lib/cloud": true},
		writable: map[string]bool{"/proc/sys/net": true},
	}
}

func TestOSFillsTheRunHeader(t *testing.T) {
	b := build(t, "os", osAccess())
	if len(b.Tree()) != 0 {
		t.Errorf("os writes no fact keys, got %v", b.Tree())
	}
	h := b.Header().Host
	if h.Hostname != "fixture-host" || h.Kernel != "6.8.0-31-generic" || h.UptimeS != 12345 {
		t.Errorf("%+v", h)
	}
	if h.OSRelease.ID != "ubuntu" || h.OSRelease.VersionID != "24.04" || h.OSRelease.Family != "debian" {
		t.Errorf("%+v", h.OSRelease)
	}
	sum := sha256.Sum256([]byte("0123456789abcdef0123456789abcdef"))
	if h.MachineIDHash != hex.EncodeToString(sum[:]) {
		t.Errorf("machine id hash %q", h.MachineIDHash)
	}
	if strings.Contains(h.MachineIDHash, "0123456789abcdef0123456789abcdef") {
		t.Error("the machine id itself must never be stored")
	}
	e := b.Header().Env
	if e.Container != "none" || e.Virt != "kvm" || e.WSL || !e.HasSystemd || !e.SysctlWritable || !e.CloudInit {
		t.Errorf("%+v", e)
	}
}

// R40: /etc/os-release is a symlink on Ubuntu 22.04/24.04 and Rocky/Alma 9,
// which the read primitive refuses; the canonical file is the fallback.
func TestOSFallsBackToUsrLibOSRelease(t *testing.T) {
	a := osAccess()
	delete(a.files, "/etc/os-release")
	a.fails = map[string]error{"/etc/os-release": collect.ErrSymlink}
	a.files["/usr/lib/os-release"] = "os-release"
	b := build(t, "os", a)
	if b.Header().Host.OSRelease.ID != "ubuntu" {
		t.Errorf("%+v", b.Header().Host.OSRelease)
	}
}

func TestOSDetectsDockerAndWSL(t *testing.T) {
	a := osAccess()
	a.dirs["/.dockerenv"] = true
	a.files["/proc/version"] = "proc-version-wsl"
	b := build(t, "os", a)
	if b.Header().Env.Container != "docker" {
		t.Errorf("container %q", b.Header().Env.Container)
	}
	if !b.Header().Env.WSL {
		t.Error("wsl")
	}
}

func TestOSVirtIsUnknownWhenDMIIsUnreadable(t *testing.T) {
	a := osAccess()
	delete(a.files, "/sys/devices/virtual/dmi/id/product_name")
	b := build(t, "os", a)
	if b.Header().Env.Virt != "unknown" {
		t.Errorf("virt %q", b.Header().Env.Virt)
	}
}

// --- walk ---------------------------------------------------------------

// R47/R76: stage 1 registers walk with nothing declared and it writes no
// keys, so U-25 stays MANUAL on a real stage-1 snapshot.
func TestWalkDeclaresAndWritesNothing(t *testing.T) {
	c := collectorNamed(t, "walk")
	if len(c.Declare.Reads) != 0 || len(c.Declare.Commands) != 0 {
		t.Errorf("walk must declare nothing in stage 1: %+v", c.Declare)
	}
	b := build(t, "walk", &fsAccess{})
	if len(b.Tree()) != 0 {
		t.Errorf("walk must write no keys: %v", b.Tree())
	}
}

// --- the declaration contract ------------------------------------------

func TestEveryCollectorStaysInsideItsDeclaration(t *testing.T) {
	a := &fsAccess{}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	for _, c := range collect.All() {
		g := collect.Guard(a, c)
		b := collect.NewBuilder(reg)
		if err := c.Run(context.Background(), g, b); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		if v := g.Violations(); len(v) != 0 {
			t.Errorf("%s touched undeclared targets: %v", c.Name, v)
		}
	}
}

func TestEveryDeclaredTargetIsAbsolute(t *testing.T) {
	for _, c := range collect.All() {
		for _, cmd := range c.Declare.Commands {
			if !strings.HasPrefix(cmd.Path, "/") {
				t.Errorf("%s: command path %q is not absolute", c.Name, cmd.Path)
			}
		}
		for _, r := range c.Declare.Reads {
			if !strings.HasPrefix(r, "/") {
				t.Errorf("%s: read %q is not absolute", c.Name, r)
			}
		}
	}
}

// R40: no collector may declare a path the read primitive is guaranteed to
// refuse — /proc/net/* and /sys/class/dmi/* are symlinks on every supported
// distribution.
func TestNoCollectorDeclaresAKnownSymlink(t *testing.T) {
	for _, c := range collect.All() {
		for _, r := range c.Declare.Reads {
			if strings.HasPrefix(r, "/proc/net/") || strings.HasPrefix(r, "/sys/class/dmi/") {
				t.Errorf("%s declares %q, which is a symlink the read primitive refuses", c.Name, r)
			}
		}
	}
}

// --- the real host ------------------------------------------------------

// hostLike is the smoke test's Access. It delegates to the same exported
// primitives the production hostAccess calls — collect.ReadFile,
// collect.Stat and collect.RunCommand — and applies the same
// /proc/self → /proc/<pid> rewrite, because internal/collect exports no
// accessor for hostAccess itself and Task 5 does not modify that package.
// Llistxattr and Writable cannot be reproduced from outside internal/collect
// (both go through its unexported no-follow open), so they answer
// conservatively here; none of the assertions below depends on either.
type hostLike struct{}

func (hostLike) rewrite(p string) string {
	const prefix = "/proc/self/"
	if strings.HasPrefix(p, prefix) {
		return "/proc/" + strconv.Itoa(os.Getpid()) + "/" + strings.TrimPrefix(p, prefix)
	}
	return p
}

func (h hostLike) ReadFile(p string, limit int64) ([]byte, collect.ReadMeta, error) {
	return collect.ReadFile(h.rewrite(p), limit)
}

func (h hostLike) Stat(p string) (collect.ReadMeta, error) { return collect.Stat(h.rewrite(p)) }

func (h hostLike) Glob(pattern string) ([]string, error) { return filepath.Glob(h.rewrite(pattern)) }

func (hostLike) Llistxattr(string) ([]string, error) { return nil, nil }

func (hostLike) Writable(string) bool { return false }

func (hostLike) Run(ctx context.Context, c collect.Command) collect.Output {
	return collect.RunCommand(ctx, c)
}

// TestSmokeOnTheRealHost runs three collectors against the real filesystem
// under the guard. It asserts shapes only: no host value is printed, logged
// or stored anywhere.
func TestSmokeOnTheRealHost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the smoke test collects as root")
	}
	if _, err := os.Stat("/proc/self/net/tcp"); err != nil {
		t.Skip("no /proc/self/net/tcp on this machine")
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	for _, name := range []string{"sockets", "os", "files"} {
		c := collectorNamed(t, name)
		g := collect.Guard(hostLike{}, c)
		if err := c.Run(context.Background(), g, b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := g.Violations(); len(v) != 0 {
			t.Fatalf("%s touched undeclared targets: %v", name, v)
		}
	}
	listening := env(t, b, "sockets.listening")
	if listening.Status != facts.StatusOK {
		t.Fatalf("sockets.listening status %s (%s)", listening.Status, listening.Reason)
	}
	if list, ok := listening.Value.([]any); !ok || list == nil {
		t.Fatal("sockets.listening must carry a non-nil list")
	}
	mode := env(t, b, "files.etc_passwd.mode")
	if mode.Status != facts.StatusOK {
		t.Fatalf("files.etc_passwd.mode status %s (%s)", mode.Status, mode.Reason)
	}
	if m, ok := mode.Value.(int); !ok || m < 0 || m > 0o7777 {
		t.Fatal("files.etc_passwd.mode must be permission bits in 0..0o7777")
	}
	if b.Header().Host.OSRelease.ID == "" {
		t.Fatal("run.host.os_release.id must not be empty")
	}
	t.Log("smoke: sockets, os and files collected under the guard with no violations")
}
