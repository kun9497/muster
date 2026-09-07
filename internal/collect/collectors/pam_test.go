//go:build linux

package collectors

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// ubuntuPAM is the pam-auth-update shape: @include of the common-* files.
func ubuntuPAM() *fsAccess {
	return &fsAccess{files: map[string]string{
		"/etc/pam.d/common-auth":     "pam/ubuntu/common-auth",
		"/etc/pam.d/common-account":  "pam/ubuntu/common-account",
		"/etc/pam.d/common-password": "pam/ubuntu/common-password",
		"/etc/pam.d/common-session":  "pam/ubuntu/common-session",
		"/etc/pam.d/login":           "pam/ubuntu/login",
		"/etc/pam.d/sshd":            "pam/ubuntu/sshd",
		"/etc/pam.d/su":              "pam/ubuntu/su",
		"/etc/pam.d/passwd":          "pam/ubuntu/passwd",
		"/etc/pam.d/other":           "pam/ubuntu/other",
	}}
}

// rockyPAM is the authselect shape: system-auth and password-auth are
// symlinks the primitive refuses, resolved into /etc/authselect by name.
func rockyPAM() *fsAccess {
	return &fsAccess{
		files: map[string]string{
			"/etc/pam.d/login":              "pam/rocky/login",
			"/etc/pam.d/sshd":               "pam/rocky/sshd",
			"/etc/pam.d/su":                 "pam/rocky/su",
			"/etc/pam.d/passwd":             "pam/rocky/passwd",
			"/etc/pam.d/other":              "pam/rocky/other",
			"/etc/pam.d/postlogin":          "pam/rocky/postlogin",
			"/etc/authselect/system-auth":   "pam/rocky/authselect-system-auth",
			"/etc/authselect/password-auth": "pam/rocky/authselect-password-auth",
		},
		fails: map[string]error{
			"/etc/pam.d/system-auth":   collect.ErrSymlink,
			"/etc/pam.d/password-auth": collect.ErrSymlink,
		},
	}
}

func stackLines(t *testing.T, b *collect.Builder, service, typ string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range okList(t, b, "pam.stacks") {
		m := r.(map[string]any)
		if m["service"] == service && (typ == "" || m["type"] == typ) {
			out = append(out, m)
		}
	}
	return out
}

// sourcePaths is the list of file paths an envelope's derived source cites,
// in the order the collector recorded them.
func sourcePaths(t *testing.T, e facts.Envelope) []string {
	t.Helper()
	if e.Source == nil {
		t.Fatalf("no source: %+v", e)
	}
	if e.Source.Kind != "derived" {
		t.Errorf("source kind %q, want derived", e.Source.Kind)
	}
	var out []string
	for _, in := range e.Source.Inputs {
		if in.Kind != "file" {
			t.Errorf("input kind %q, want file", in.Kind)
		}
		out = append(out, in.Path)
	}
	return out
}

func TestPAMTokensKeepABracketedControlWhole(t *testing.T) {
	got := pamTokens("auth\t[success=1 default=ignore]\tpam_unix.so nullok try_first_pass")
	want := []string{"auth", "[success=1 default=ignore]", "pam_unix.so", "nullok", "try_first_pass"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%q", got)
	}
	if got := pamTokens("account [default=bad success=ok user_unknown=ignore] pam_sss.so"); len(got) != 3 || got[1] != "[default=bad success=ok user_unknown=ignore]" {
		t.Errorf("%q", got)
	}
}

// R162: pam.d(5) - a "#" starts a comment that runs to the end of the line,
// so nothing after one is a module argument. Without the cut, "# deny others"
// would hand pam_wheel.so a deny argument and invert the fact.
func TestPAMMidLineCommentIsNotAnArgument(t *testing.T) {
	a := ubuntuPAM()
	a.files["/etc/pam.d/su"] = "pam/ubuntu/su-comment"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.su.wheel_required"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("%+v", e)
	}
	e := env(t, b, "pam.su.wheel_args")
	if e.Status != facts.StatusOK {
		t.Fatalf("wheel_args %+v", e)
	}
	if l := e.Value.([]any); len(l) != 1 || l[0] != "use_uid" {
		t.Errorf("wheel_args %v, want [use_uid]", l)
	}
	// A bracketed control field still survives the cut.
	var unix map[string]any
	for _, m := range stackLines(t, b, "su", "auth") {
		if m["path"] == pamDir+"/su" && m["module"] == "pam_unix.so" {
			unix = m
		}
	}
	if unix == nil {
		t.Fatalf("no pam_unix.so line in su's auth stack: %v", stackLines(t, b, "su", "auth"))
	}
	if unix["control"] != "[success=1 default=ignore]" {
		t.Errorf("control %v", unix["control"])
	}
	if args := unix["args"].([]any); len(args) != 1 || args[0] != "nullok" {
		t.Errorf("args %v, want [nullok]", args)
	}
}

// The Debian shape: @include splices every type of the named file where
// the directive stands; the marker comment names pam-auth-update.
func TestPAMExpandsDebianIncludes(t *testing.T) {
	b := build(t, "pam", ubuntuPAM())
	if e := env(t, b, "pam.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("parse_complete %+v", e)
	}
	layer := env(t, b, "pam.managing_layer")
	if layer.Value != "pam-auth-update" {
		t.Errorf("managing_layer %+v", layer)
	}
	// R155: the marker file that decided the answer is cited, exactly once.
	marker := 0
	for _, p := range sourcePaths(t, layer) {
		if p == pamDir+"/common-auth" {
			marker++
		}
	}
	if marker != 1 {
		t.Errorf("common-auth is cited %d times: %v", marker, sourcePaths(t, layer))
	}
	auth := stackLines(t, b, "login", "auth")
	// faildelay, nologin, then the three common-auth lines, then pam_group.
	want := []string{"pam_faildelay.so", "pam_nologin.so", "pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_group.so"}
	if len(auth) != len(want) {
		t.Fatalf("login auth stack %v", auth)
	}
	for i, w := range want {
		if auth[i]["module"] != w {
			t.Errorf("login auth[%d] = %v, want %s", i, auth[i]["module"], w)
		}
	}
	unix := auth[2]
	if unix["control"] != "[success=1 default=ignore]" || unix["path"] != "/etc/pam.d/common-auth" || unix["line"] != 2 {
		t.Errorf("%v", unix)
	}
	if args := unix["args"].([]any); len(args) != 1 || args[0] != "nullok" {
		t.Errorf("args %v", args)
	}
	if pw := stackLines(t, b, "passwd", "password"); len(pw) != 3 || pw[0]["module"] != "pam_unix.so" {
		t.Errorf("passwd password stack %v", pw)
	}
	if s := stackLines(t, b, "sudo", ""); len(s) != 0 {
		t.Errorf("sudo has no file in the fixture and must publish nothing: %v", s)
	}
	for _, m := range okList(t, b, "pam.stacks") {
		if m.(map[string]any)["control"] == "include" || m.(map[string]any)["control"] == "substack" {
			t.Errorf("an include directive leaked into the stacks: %v", m)
		}
	}
}

// The authselect shape: substack/include splice only the matching type,
// the symlinked system-auth resolves into /etc/authselect by name, and the
// optional "-" prefix is stripped from the type.
func TestPAMExpandsAuthselectSubstacks(t *testing.T) {
	b := build(t, "pam", rockyPAM())
	if e := env(t, b, "pam.parse_complete"); e.Value != true {
		t.Fatalf("parse_complete %+v", e)
	}
	if e := env(t, b, "pam.managing_layer"); e.Value != "authselect" {
		t.Errorf("managing_layer %+v", e)
	}
	auth := stackLines(t, b, "login", "auth")
	want := []string{"pam_env.so", "pam_faildelay.so", "pam_faillock.so", "pam_unix.so", "pam_faillock.so", "pam_sss.so", "pam_deny.so"}
	if len(auth) != len(want) {
		t.Fatalf("login auth stack %v", auth)
	}
	for i, w := range want {
		if auth[i]["module"] != w {
			t.Errorf("login auth[%d] = %v, want %s", i, auth[i]["module"], w)
		}
	}
	if auth[0]["path"] != "/etc/authselect/system-auth" || auth[0]["line"] != 1 {
		t.Errorf("the resolved path must be the authselect original: %v", auth[0])
	}
	// The source names the files that were actually read: the authselect
	// original, never the /etc/pam.d symlink the primitive refused.
	paths := sourcePaths(t, env(t, b, "pam.parse_complete"))
	if !slices.Contains(paths, "/etc/authselect/system-auth") {
		t.Errorf("inputs must name the authselect original: %v", paths)
	}
	if slices.Contains(paths, "/etc/pam.d/system-auth") {
		t.Errorf("inputs must not name the symlink that was never read: %v", paths)
	}
	// postlogin contributes session lines only, and only where a session
	// include names it; the auth include of postlogin splices nothing.
	sess := stackLines(t, b, "login", "session")
	if last := sess[len(sess)-1]; last["module"] != "pam_lastlog.so" {
		t.Errorf("login session stack must end with postlogin's lines: %v", sess)
	}
	// passwd's password stack: system-auth's four password lines via
	// substack, then the "-password" gnome-keyring line with its type
	// stripped of the dash, then postlogin's session lines are NOT spliced
	// (type mismatch).
	pw := stackLines(t, b, "passwd", "password")
	if len(pw) != 5 || pw[0]["module"] != "pam_pwquality.so" || pw[4]["module"] != "pam_gnome_keyring.so" || pw[4]["type"] != "password" {
		t.Errorf("passwd password stack %v", pw)
	}
	if s := stackLines(t, b, "sshd", "password"); len(s) != 4 || s[0]["path"] != "/etc/authselect/password-auth" {
		t.Errorf("sshd password stack %v", s)
	}
}

// An include that cannot be read is a parse problem, not a shorter stack:
// parse_complete is false and names the file; what was read is still
// published as evidence.
func TestPAMUnreadableIncludeIsIncomplete(t *testing.T) {
	a := rockyPAM()
	delete(a.files, "/etc/authselect/password-auth")
	b := build(t, "pam", a)
	e := env(t, b, "pam.parse_complete")
	if e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "/etc/pam.d/password-auth") {
		t.Errorf("%+v", e)
	}
	// R164: the fallback that was tried instead is named too, so a host whose
	// /etc/authselect does not hold the original is diagnosable from the
	// reason alone.
	if !strings.Contains(e.Reason, "/etc/authselect/password-auth") {
		t.Errorf("the reason must name the authselect original: %q", e.Reason)
	}
	if l := stackLines(t, b, "login", "auth"); len(l) != 7 {
		t.Errorf("login still expands: %v", l)
	}
	a = rockyPAM()
	a.fails["/etc/pam.d/sshd"] = os.ErrPermission
	e = env(t, build(t, "pam", a), "pam.parse_complete")
	if e.Value != false || !strings.Contains(e.Reason, "/etc/pam.d/sshd") {
		t.Errorf("a denied service file: %+v", e)
	}
}

func TestPAMIncludeLoopIsBounded(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/pam.d/login": "pam/loop-a", "/etc/pam.d/loop-b": "pam/loop-b"}}
	b := build(t, "pam", a)
	e := env(t, b, "pam.parse_complete")
	if e.Value != false || !strings.Contains(e.Reason, "loop") {
		t.Errorf("%+v", e)
	}
}

// A chain of nine distinct files never loops, so only the depth guard can
// stop it. maxPAMDepth is 8, so the ninth file is one level too deep.
func TestPAMIncludeDepthIsBounded(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/pam.d/login":  "pam/deep-1",
		"/etc/pam.d/deep-2": "pam/deep-2",
		"/etc/pam.d/deep-3": "pam/deep-3",
		"/etc/pam.d/deep-4": "pam/deep-4",
		"/etc/pam.d/deep-5": "pam/deep-5",
		"/etc/pam.d/deep-6": "pam/deep-6",
		"/etc/pam.d/deep-7": "pam/deep-7",
		"/etc/pam.d/deep-8": "pam/deep-8",
		"/etc/pam.d/deep-9": "pam/deep-9",
	}}
	e := env(t, build(t, "pam", a), "pam.parse_complete")
	if e.Value != false || !strings.Contains(e.Reason, "deeper than 8") {
		t.Errorf("%+v", e)
	}
}

func TestPAMNoPamDirectoryIsAbsent(t *testing.T) {
	b := build(t, "pam", &fsAccess{})
	for _, k := range []string{"pam.stacks", "pam.managing_layer", "pam.parse_complete"} {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
}

// globFailure breaks Glob for exactly one pattern, so a test can fail the
// pwquality.conf.d listing without also failing the /etc/pam.d listing the
// collector needs before it derives anything.
type globFailure struct {
	*fsAccess
	pattern string
	err     error
}

func (g *globFailure) Glob(p string) ([]string, error) {
	if p == g.pattern {
		return nil, g.err
	}
	return g.fsAccess.Glob(p)
}

func TestPAMParseKV(t *testing.T) {
	kv := parseKV([]byte("# c\nminlen = 12\nenforce_for_root\n  dcredit=-1  \nbad line here\n"))
	if kv["minlen"] != "12" || kv["dcredit"] != "-1" {
		t.Errorf("%v", kv)
	}
	if v, ok := kv["enforce_for_root"]; !ok || v != "" {
		t.Errorf("a bare flag is present with an empty value: %v", kv)
	}
	if _, ok := kv["bad line here"]; ok {
		t.Errorf("a line without = and with spaces is not a key: %v", kv)
	}
}

// Task 2 (the stock-Ubuntu trap): a perfect pwquality.conf enforces
// nothing while pam_pwquality is not stacked — enabled is false and every
// value is absent, never the conf file's numbers.
func TestPAMPwqualityNotStackedIsNotEnabled(t *testing.T) {
	a := ubuntuPAM()
	a.files["/etc/security/pwquality.conf"] = "pam/ubuntu/pwquality.conf"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.pwquality.enabled"); e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "not stacked") {
		t.Errorf("%+v", e)
	}
	// R157: the not-enabled answer cites the files that were actually read,
	// which is where the password stack really came from - not /etc/pam.d/passwd,
	// which only @includes it.
	if got := sourcePaths(t, env(t, b, "pam.pwquality.enabled")); !slices.Contains(got, "/etc/pam.d/common-password") {
		t.Errorf("inputs %v", got)
	}
	for _, k := range []string{"minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit", "required_classes", "enforce_for_root", "local_users_only"} {
		if e := env(t, b, "pam.pwquality."+k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent", k, e)
		}
	}
	if e := env(t, b, "pam.password.unix_hash"); e.Status != facts.StatusOK || e.Value != "yescrypt" {
		t.Errorf("unix_hash %+v", e)
	}
	if e := env(t, b, "pam.password.remember"); e.Status != facts.StatusAbsent {
		t.Errorf("remember %+v", e)
	}
}

func TestPAMPwqualityStackedOnDebian(t *testing.T) {
	a := ubuntuPAM()
	a.files["/etc/pam.d/common-password"] = "pam/ubuntu/common-password-pwquality"
	a.files["/etc/security/pwquality.conf"] = "pam/ubuntu/pwquality.conf"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.pwquality.enabled"); e.Value != true {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.pwquality.minlen"); e.Status != facts.StatusOK || e.Value != 14 || e.Source.Kind != "derived" || len(e.Source.Inputs) != 2 {
		t.Errorf("minlen %+v (conf file, then the module line)", e)
	}
	if got := sourcePaths(t, env(t, b, "pam.pwquality.minlen")); len(got) != 2 || got[0] != pwqualityConf || got[1] != "/etc/pam.d/common-password" {
		t.Errorf("inputs %v", got)
	}
	if e := env(t, b, "pam.pwquality.required_classes"); e.Value != 4 {
		t.Errorf("required_classes %+v", e)
	}
	if e := env(t, b, "pam.password.remember"); e.Status != facts.StatusOK || e.Value != 7 {
		t.Errorf("remember from pam_unix %+v", e)
	}
}

// Module arguments override the conf files, and a conf.d drop-in
// overrides pwquality.conf; a credit of -1 counts as a required class.
func TestPAMPwqualityPrecedence(t *testing.T) {
	a := rockyPAM()
	a.files["/etc/security/pwquality.conf"] = "pam/rocky/pwquality.conf"
	a.files["/etc/security/pwquality.conf.d/90-local.conf"] = "pam/rocky/90-local.conf"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.pwquality.enabled"); e.Value != true {
		t.Fatalf("%+v", e)
	}
	for k, want := range map[string]any{
		"minlen": 12, "minclass": 4, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0,
		"required_classes": 4, "enforce_for_root": true, "local_users_only": true,
	} {
		if e := env(t, b, "pam.pwquality."+k); e.Status != facts.StatusOK || e.Value != want {
			t.Errorf("%s = %+v, want %v", k, e, want)
		}
	}
	if e := env(t, b, "pam.pwquality.minlen"); len(e.Source.Inputs) != 3 || e.Source.Inputs[0].Path != "/etc/security/pwquality.conf" || e.Source.Inputs[1].Path != "/etc/security/pwquality.conf.d/90-local.conf" || e.Source.Inputs[2].Path != "/etc/authselect/system-auth" {
		t.Errorf("inputs %+v", e.Source.Inputs)
	}
	if e := env(t, b, "pam.password.unix_hash"); e.Value != "sha512" {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.password.remember"); e.Value != 5 {
		t.Errorf("%+v", e)
	}
	// Without the module argument the drop-in's 15 wins over the conf's 8.
	a = rockyPAM()
	a.files["/etc/authselect/system-auth"] = "pam/rocky/authselect-password-auth"
	a.files["/etc/security/pwquality.conf"] = "pam/rocky/pwquality.conf"
	a.files["/etc/security/pwquality.conf.d/90-local.conf"] = "pam/rocky/90-local.conf"
	if e := env(t, build(t, "pam", a), "pam.pwquality.minlen"); e.Value != 15 {
		t.Errorf("drop-in must override the conf: %+v", e)
	}
	// A credit of -1 is a required class even when minclass is lower.
	a = rockyPAM()
	a.files["/etc/security/pwquality.conf"] = "pam/rocky/credits.conf"
	if e := env(t, build(t, "pam", a), "pam.pwquality.required_classes"); e.Value != 3 {
		t.Errorf("three negative credits: %+v", e)
	}
}

// R148: a conf file that exists but cannot be read is the answer for every
// value it could have set — never the defaults dressed up as ok. The stack
// still says whether pwquality runs at all.
func TestPAMPwqualityUnreadableConfIsTheAnswer(t *testing.T) {
	a := rockyPAM()
	a.fails[pwqualityConf] = os.ErrPermission
	b := build(t, "pam", a)
	if e := env(t, b, "pam.pwquality.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("enabled must still follow the stack: %+v", e)
	}
	for _, k := range passwordKeys[1:10] {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, pwqualityConf+": ") {
			t.Errorf("%s = %+v", k, e)
		}
	}
	// The same for a drop-in listing that cannot even be made.
	g := &globFailure{fsAccess: rockyPAM(), pattern: pwqualityConfD, err: errors.New("boom")}
	b = build(t, "pam", g)
	if e := env(t, b, "pam.pwquality.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("enabled %+v", e)
	}
	for _, k := range passwordKeys[1:10] {
		e := env(t, b, k)
		if e.Status != facts.StatusError || !strings.HasPrefix(e.Reason, pwqualityConfD+": ") {
			t.Errorf("%s = %+v", k, e)
		}
	}
}

// R149: pam_pwhistory without remember= and without a pwhistory.conf still
// remembers 10 passwords — the module's own default — cited to the line
// that loads it.
func TestPAMPwhistoryDefaultRemember(t *testing.T) {
	a := ubuntuPAM()
	a.files["/etc/pam.d/common-password"] = "pam/ubuntu/common-password-pwhistory"
	e := env(t, build(t, "pam", a), "pam.password.remember")
	if e.Status != facts.StatusOK || e.Value != 10 {
		t.Errorf("%+v", e)
	}
	if e.Source == nil || len(e.Source.Inputs) != 1 || e.Source.Inputs[0].Path != "/etc/pam.d/common-password" {
		t.Errorf("source %+v", e.Source)
	}
	// R164: a pwhistory.conf that sets remember beats the module default, and
	// it is the file that is cited.
	a = ubuntuPAM()
	a.files["/etc/pam.d/common-password"] = "pam/ubuntu/common-password-pwhistory"
	a.files[pwhistoryConf] = "pam/ubuntu/pwhistory.conf"
	e = env(t, build(t, "pam", a), "pam.password.remember")
	if e.Status != facts.StatusOK || e.Value != 12 {
		t.Errorf("%+v", e)
	}
	if got := sourcePaths(t, e); len(got) != 1 || got[0] != pwhistoryConf {
		t.Errorf("inputs %v, want [%s]", got, pwhistoryConf)
	}
	// C3: a pwhistory.conf that exists but cannot be read is the answer, never
	// the module's default 10 dressed up as ok.
	a = ubuntuPAM()
	a.files["/etc/pam.d/common-password"] = "pam/ubuntu/common-password-pwhistory"
	a.fails = map[string]error{pwhistoryConf: os.ErrPermission}
	e = env(t, build(t, "pam", a), "pam.password.remember")
	if e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, pwhistoryConf+": ") {
		t.Errorf("%+v", e)
	}
}

// R152: the last hashing argument on the pam_unix line wins, as it does
// for the module itself — not the first one the documentation lists.
func TestPAMLastHashArgumentWins(t *testing.T) {
	a := ubuntuPAM()
	a.files["/etc/pam.d/common-password"] = "pam/ubuntu/common-password-twohashes"
	if e := env(t, build(t, "pam", a), "pam.password.unix_hash"); e.Status != facts.StatusOK || e.Value != "sha512" {
		t.Errorf("%+v", e)
	}
}

// R154a: an include that points outside the collector's declaration is a
// parse problem, and the file is never even asked for.
func TestPAMIncludeOutsideDeclarationIsAProblem(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/pam.d/login": "pam/outside"}}
	b := build(t, "pam", a)
	e := env(t, b, "pam.parse_complete")
	if e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "outside the collector's declaration") {
		t.Errorf("%+v", e)
	}
	if slices.Contains(a.reads, "/etc/foo/bar") {
		t.Errorf("the undeclared include was read: %v", a.reads)
	}
}

// R154b: a module given as an absolute path is the same module, but the
// published record keeps the path the file actually said.
func TestPAMModuleMatchesByBasename(t *testing.T) {
	a := ubuntuPAM()
	a.files["/etc/pam.d/common-password"] = "pam/ubuntu/common-password-abspath"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.password.unix_hash"); e.Status != facts.StatusOK || e.Value != "yescrypt" {
		t.Errorf("%+v", e)
	}
	pw := stackLines(t, b, "passwd", "password")
	if len(pw) != 3 || pw[0]["module"] != "/lib/x86_64-linux-gnu/security/pam_unix.so" {
		t.Errorf("the record keeps the absolute path verbatim: %v", pw)
	}
}

// R154c: a /etc/pam.d listing that fails is neither absent nor a value —
// it is the read error, on every key the collector owns.
func TestPAMGlobErrorIsReported(t *testing.T) {
	b := build(t, "pam", &fsAccess{globErr: errors.New("boom")})
	want := env(t, b, "pam.stacks")
	if want.Status != facts.StatusError || !strings.HasPrefix(want.Reason, pamDir+": ") {
		t.Fatalf("pam.stacks %+v", want)
	}
	all := append([]string{"pam.managing_layer", "pam.parse_complete"}, passwordKeys...)
	for _, k := range append(all, accessKeys...) {
		if e := env(t, b, k); e != want {
			t.Errorf("%s = %+v, want %+v", k, e, want)
		}
	}
}

// Every derived password key is an error, not a number, when the stacks
// are incomplete; and absent when there is no passwd service at all.
func TestPAMPasswordFactsFollowTheStackStatus(t *testing.T) {
	a := rockyPAM()
	delete(a.files, "/etc/authselect/system-auth")
	b := build(t, "pam", a)
	for _, k := range passwordKeys {
		if e := env(t, b, k); e.Status != facts.StatusError || !strings.Contains(e.Reason, "incomplete") {
			t.Errorf("%s = %+v", k, e)
		}
	}
	a = rockyPAM()
	delete(a.files, "/etc/pam.d/passwd")
	b = build(t, "pam", a)
	for _, k := range passwordKeys {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
}

// R155: common-auth decides the pam-auth-update answer even when no
// published service includes it. The expander then never read it — the
// stacks do not cite it — so managing_layer has to cite it itself, after
// the sorted inputs, which is where an appended citation can be told from
// an expanded one.
func TestPAMManagingLayerCitesTheMarkerFile(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/pam.d/login":       "pam/ubuntu/common-password",
		"/etc/pam.d/common-auth": "pam/ubuntu/common-auth",
	}}
	b := build(t, "pam", a)
	e := env(t, b, "pam.managing_layer")
	if e.Value != "pam-auth-update" {
		t.Fatalf("%+v", e)
	}
	want := []string{pamDir + "/login", pamDir + "/common-auth"}
	if got := sourcePaths(t, e); !slices.Equal(got, want) {
		t.Errorf("inputs %v, want %v", got, want)
	}
	if got := sourcePaths(t, env(t, b, "pam.stacks")); slices.Contains(got, pamDir+"/common-auth") {
		t.Errorf("the expander did read common-auth, so this proves nothing: %v", got)
	}
}

// R163: common-auth exists but cannot be read, so nothing here can say
// whether the pam-auth-update marker is in it. That read is the answer -
// "manual" would claim the host is unmanaged on the strength of a file
// nobody read.
func TestPAMManagingLayerUnreadableCommonAuth(t *testing.T) {
	a := ubuntuPAM()
	a.fails = map[string]error{pamDir + "/common-auth": os.ErrPermission}
	b := build(t, "pam", a)
	e := env(t, b, "pam.managing_layer")
	if e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, pamDir+"/common-auth: ") {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.parse_complete"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("parse_complete %+v", e)
	}
}

// Task 3: faillock is enabled only when every login-facing service stacks
// preauth, authfail and a reset line; arguments override faillock.conf.
func TestPAMFaillockEnabledWithPrecedence(t *testing.T) {
	a := rockyPAM()
	a.files["/etc/security/faillock.conf"] = "pam/rocky/faillock.conf"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.faillock.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("%+v", e)
	}
	for k, want := range map[string]any{"deny": 5, "unlock_time": 900, "fail_interval": 900, "root_unlock_time": 900, "even_deny_root": true} {
		if e := env(t, b, "pam.faillock."+k); e.Status != facts.StatusOK || e.Value != want {
			t.Errorf("%s = %+v, want %v", k, e, want)
		}
	}
	if e := env(t, b, "pam.faillock.deny"); len(e.Source.Inputs) != 3 || e.Source.Inputs[0].Path != "/etc/security/faillock.conf" || e.Source.Inputs[1].Line != 3 || e.Source.Inputs[2].Line != 5 {
		t.Errorf("inputs: conf, preauth line, authfail line - got %+v", e.Source.Inputs)
	}
	// sshd's stack (password-auth) without faillock: not enabled, values absent.
	a = rockyPAM()
	a.files["/etc/authselect/password-auth"] = "pam/rocky/authselect-password-auth-nofaillock"
	b = build(t, "pam", a)
	if e := env(t, b, "pam.faillock.enabled"); e.Value != false || !strings.Contains(e.Reason, "sshd") {
		t.Errorf("%+v (the reason names the service that lacks it)", e)
	}
	if e := env(t, b, "pam.faillock.deny"); e.Status != facts.StatusAbsent {
		t.Errorf("%+v", e)
	}
}

func TestPAMFaillockNotStackedOnDebian(t *testing.T) {
	b := build(t, "pam", ubuntuPAM())
	if e := env(t, b, "pam.faillock.enabled"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("%+v", e)
	}
	// R158: "not stacked" cites the files the stacks were expanded out of,
	// not /etc/pam.d/login, which holds includes and no auth module line.
	if got := sourcePaths(t, env(t, b, "pam.faillock.enabled")); !slices.Contains(got, "/etc/pam.d/common-auth") {
		t.Errorf("inputs %v", got)
	}
	for _, k := range []string{"deny", "unlock_time", "fail_interval", "even_deny_root", "root_unlock_time"} {
		if e := env(t, b, "pam.faillock."+k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
}

// R148: a faillock.conf that exists but cannot be read is the answer for
// every value it could have set; enabled still follows the stacks.
func TestPAMFaillockUnreadableConfIsTheAnswer(t *testing.T) {
	a := rockyPAM()
	a.fails[faillockConf] = os.ErrPermission
	b := build(t, "pam", a)
	if e := env(t, b, "pam.faillock.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("enabled must still follow the stack: %+v", e)
	}
	for _, k := range accessKeys[1:6] {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, faillockConf+": ") {
			t.Errorf("%s = %+v", k, e)
		}
	}
}

// R150: the preauth and authfail lines may carry different values. The
// authfail line is the one reported, and enabled says they disagree.
func TestPAMFaillockPreauthAndAuthfailDisagree(t *testing.T) {
	a := rockyPAM()
	a.files["/etc/authselect/system-auth"] = "pam/rocky/authselect-system-auth-mismatch"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.faillock.deny"); e.Status != facts.StatusOK || e.Value != 5 {
		t.Errorf("the authfail value is the one reported: %+v", e)
	}
	e := env(t, b, "pam.faillock.enabled")
	if e.Status != facts.StatusOK || e.Value != true || !strings.Contains(e.Reason, "disagree on deny") {
		t.Errorf("%+v", e)
	}
	if strings.Contains(e.Reason, "unlock_time") {
		t.Errorf("only the keys that differ are named: %+v", e)
	}
}

// R151: the reset half of the lockout may be an authsucc line in the auth
// phase instead of pam_faillock.so in the account phase.
func TestPAMFaillockAuthsuccIsAReset(t *testing.T) {
	a := rockyPAM()
	a.files["/etc/authselect/system-auth"] = "pam/rocky/authselect-system-auth-authsucc"
	a.files["/etc/authselect/password-auth"] = "pam/rocky/authselect-system-auth-authsucc"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.faillock.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("%+v (an authsucc line resets the counter)", e)
	}
	if e := env(t, b, "pam.faillock.deny"); e.Status != facts.StatusOK || e.Value != 5 {
		t.Errorf("%+v", e)
	}
}

func TestPAMSuWheel(t *testing.T) {
	b := build(t, "pam", rockyPAM())
	if e := env(t, b, "pam.su.wheel_required"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.su.wheel_control"); e.Value != "required" {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.su.wheel_group"); e.Value != "wheel" {
		t.Errorf("%+v (group= absent means wheel)", e)
	}
	if l := env(t, b, "pam.su.wheel_args").Value.([]any); len(l) != 1 || l[0] != "use_uid" {
		t.Errorf("%v", l)
	}
	// Commented out (the stock shape): not required, the details absent.
	b = build(t, "pam", ubuntuPAM())
	if e := env(t, b, "pam.su.wheel_required"); e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "no pam_wheel") {
		t.Errorf("%+v", e)
	}
	for _, k := range []string{"wheel_control", "wheel_group", "wheel_args"} {
		if e := env(t, b, "pam.su."+k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
	// Present with a control that does not restrict: the details are
	// reported, wheel_required is false and says why.
	a := ubuntuPAM()
	a.files["/etc/pam.d/su"] = "pam/ubuntu/su-wheel-sufficient"
	b = build(t, "pam", a)
	if e := env(t, b, "pam.su.wheel_required"); e.Value != false || !strings.Contains(e.Reason, "sufficient") {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.su.wheel_control"); e.Value != "sufficient" {
		t.Errorf("%+v", e)
	}
	// R158: an enforcing control with deny inverts the module - everyone in
	// the group is refused instead of everyone outside it - and group= names
	// the group the line really talks about.
	a = ubuntuPAM()
	a.files["/etc/pam.d/su"] = "pam/ubuntu/su-wheel-deny-group"
	b = build(t, "pam", a)
	if e := env(t, b, "pam.su.wheel_required"); e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "deny") {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.su.wheel_control"); e.Value != "required" {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.su.wheel_group"); e.Value != "admins" {
		t.Errorf("%+v", e)
	}
}

// R160: pam_faillock's args_parse splits every argument at "=" and hands the
// name to set_conf_opt, which sets the deny-root flag whatever value follows
// it - so even_deny_root=0 names the option too - and root_unlock_time set
// anywhere implies even_deny_root (pam_faillock(8)).
func TestPAMFaillockEvenDenyRootFollowsTheModule(t *testing.T) {
	a := rockyPAM()
	a.files["/etc/authselect/system-auth"] = "pam/rocky/authselect-system-auth-evendenyroot0"
	if e := env(t, build(t, "pam", a), "pam.faillock.even_deny_root"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("%+v (even_deny_root=0 still names the option)", e)
	}
	a = rockyPAM()
	a.files["/etc/authselect/system-auth"] = "pam/rocky/authselect-system-auth-evendenyroot"
	if e := env(t, build(t, "pam", a), "pam.faillock.even_deny_root"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("%+v", e)
	}
	// The conf file names it the same way, with or without a value.
	a = rockyPAM()
	a.files["/etc/security/faillock.conf"] = "pam/rocky/faillock.conf"
	if e := env(t, build(t, "pam", a), "pam.faillock.even_deny_root"); e.Value != true {
		t.Errorf("%+v", e)
	}
	// root_unlock_time on the authfail line and even_deny_root nowhere: the
	// module locks root out too, so the fact says so.
	a = rockyPAM()
	a.files["/etc/authselect/system-auth"] = "pam/rocky/authselect-system-auth-rootunlock"
	b := build(t, "pam", a)
	if e := env(t, b, "pam.faillock.even_deny_root"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("%+v (root_unlock_time implies even_deny_root)", e)
	}
	if e := env(t, b, "pam.faillock.root_unlock_time"); e.Status != facts.StatusOK || e.Value != 60 {
		t.Errorf("%+v", e)
	}
}

// R158: the branches a service file that does not exist reaches. Each group
// answers for itself, so a host missing one service still answers for the
// others.
func TestPAMAccessFactsEdgeCases(t *testing.T) {
	// (a) No login and no sshd: faillock has nothing to judge.
	a := rockyPAM()
	delete(a.files, "/etc/pam.d/login")
	delete(a.files, "/etc/pam.d/sshd")
	b := build(t, "pam", a)
	for _, k := range accessKeys[:6] {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
	if e := env(t, b, "pam.su.wheel_required"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("su is still judged: %+v", e)
	}
	// (b) No su file.
	a = rockyPAM()
	delete(a.files, "/etc/pam.d/su")
	b = build(t, "pam", a)
	for _, k := range accessKeys[6:10] {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
	if e := env(t, b, "pam.faillock.enabled"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("faillock is still judged: %+v", e)
	}
	// (c) login exists but no session stack loads pam_umask.so.
	a = ubuntuPAM()
	a.files["/etc/pam.d/common-session"] = "pam/ubuntu/common-session-noumask"
	b = build(t, "pam", a)
	e := env(t, b, "pam.umask_module.enabled")
	if e.Status != facts.StatusOK || e.Value != false || !strings.Contains(e.Reason, "login") {
		t.Errorf("%+v", e)
	}
	if got := sourcePaths(t, e); !slices.Contains(got, "/etc/pam.d/common-session") {
		t.Errorf("inputs %v", got)
	}
	if e := env(t, b, "pam.umask_module.args"); e.Status != facts.StatusAbsent {
		t.Errorf("%+v", e)
	}
	// (d) No login, sshd or other: umask has nothing to judge.
	a = rockyPAM()
	delete(a.files, "/etc/pam.d/login")
	delete(a.files, "/etc/pam.d/sshd")
	delete(a.files, "/etc/pam.d/other")
	b = build(t, "pam", a)
	for _, k := range accessKeys[10:12] {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
}

func TestPAMUmaskAndSecuretty(t *testing.T) {
	b := build(t, "pam", ubuntuPAM())
	if e := env(t, b, "pam.umask_module.enabled"); e.Value != true {
		t.Errorf("%+v", e)
	}
	if l := env(t, b, "pam.umask_module.args").Value.([]any); len(l) != 0 {
		t.Errorf("%v", l)
	}
	if e := env(t, b, "pam.securetty_enabled"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("%+v (the line is commented out)", e)
	}
	a := ubuntuPAM()
	a.files["/etc/pam.d/login"] = "pam/ubuntu/login-securetty"
	if e := env(t, build(t, "pam", a), "pam.securetty_enabled"); e.Value != true {
		t.Errorf("%+v", e)
	}
	b = build(t, "pam", rockyPAM())
	if l := env(t, b, "pam.umask_module.args").Value.([]any); len(l) != 1 || l[0] != "silent" {
		t.Errorf("postlogin's pam_umask args: %v", l)
	}
	// No login service at all: securetty is absent, umask falls back to sshd.
	a = rockyPAM()
	delete(a.files, "/etc/pam.d/login")
	b = build(t, "pam", a)
	if e := env(t, b, "pam.securetty_enabled"); e.Status != facts.StatusAbsent {
		t.Errorf("%+v", e)
	}
	if e := env(t, b, "pam.umask_module.enabled"); e.Value != true {
		t.Errorf("%+v", e)
	}
}

func TestPAMAccessFactsFollowTheStackStatus(t *testing.T) {
	a := rockyPAM()
	delete(a.files, "/etc/authselect/system-auth")
	b := build(t, "pam", a)
	for _, k := range accessKeys {
		if e := env(t, b, k); e.Status != facts.StatusError {
			t.Errorf("%s = %+v", k, e)
		}
	}
	b = build(t, "pam", &fsAccess{})
	for _, k := range append(append([]string{}, passwordKeys...), accessKeys...) {
		if e := env(t, b, k); e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v", k, e)
		}
	}
}
