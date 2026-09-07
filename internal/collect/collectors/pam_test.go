//go:build linux

package collectors

import (
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

// The Debian shape: @include splices every type of the named file where
// the directive stands; the marker comment names pam-auth-update.
func TestPAMExpandsDebianIncludes(t *testing.T) {
	b := build(t, "pam", ubuntuPAM())
	if e := env(t, b, "pam.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Fatalf("parse_complete %+v", e)
	}
	if e := env(t, b, "pam.managing_layer"); e.Value != "pam-auth-update" {
		t.Errorf("managing_layer %+v", e)
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
