//go:build linux

package collectors

import (
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

// Task 1: login.defs values that are not numbers are kept verbatim, the
// boundaries are integers, and a key must match whole (UMASKX is not UMASK).
func TestLoginDefsStringsAndBoundaries(t *testing.T) {
	a := &fsAccess{files: map[string]string{
		"/etc/login.defs": "login.defs_2b",
		"/etc/shadow":     "shadow_2b",
		"/etc/passwd":     "passwd",
	}}
	b := build(t, "accounts", a)
	for key, want := range map[string]any{
		"accounts.login_defs.umask":                "022",
		"accounts.login_defs.home_mode":            "0750",
		"accounts.login_defs.encrypt_method":       "SHA512",
		"accounts.login_defs.env_supath":           "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"accounts.login_defs.env_path":             "PATH=/usr/local/bin:/usr/bin:/bin",
		"accounts.login_defs.uid_min":              1000,
		"accounts.login_defs.sys_uid_max":          999,
		"accounts.login_defs.sha_crypt_min_rounds": 5000,
	} {
		if e := env(t, b, key); e.Status != facts.StatusOK || e.Value != want {
			t.Errorf("%s = %+v, want %v", key, e, want)
		}
	}
	if e := env(t, b, "accounts.login_defs.umask"); e.Source == nil || e.Source.Line != 10 {
		t.Errorf("umask must cite line 10 (the UMASK line, not the UMASKX decoy): %+v", e.Source)
	}
	w := setting(t, b, "accounts.login_defs.pass_warn_age")
	if w.Persisted == nil || w.Persisted.Value != 7 || w.Runtime == nil || w.Runtime.Value != 3 || w.Runtime.Source.Kind != "derived" {
		t.Errorf("pass_warn_age persisted %+v runtime %+v (runtime is the minimum warn over hashed rows: carol's 3)", w.Persisted, w.Runtime)
	}
}

func TestLoginDefsUnsetStringIsAbsent(t *testing.T) {
	a := &fsAccess{files: map[string]string{"/etc/login.defs": "login.defs", "/etc/passwd": "passwd", "/etc/shadow": "shadow"}}
	b := build(t, "accounts", a)
	if e := env(t, b, "accounts.login_defs.umask"); e.Status != facts.StatusAbsent {
		t.Errorf("UMASK is not in the stage-1 fixture: %+v", e)
	}
	if e := env(t, b, "accounts.login_defs.uid_min"); e.Status != facts.StatusOK || e.Value != 1000 {
		t.Errorf("UID_MIN 1000 is in the stage-1 fixture: %+v", e)
	}
}

func TestLoginDefsIntOrFallsBack(t *testing.T) {
	d := loginDefs{lines: []string{"UID_MIN abc", "SYS_UID_MAX 999"}}
	if got := d.intOr("UID_MIN", 1000); got != 1000 {
		t.Errorf("unparsable UID_MIN must fall back, got %d", got)
	}
	if got := d.intOr("SYS_UID_MAX", 999); got != 999 {
		t.Errorf("got %d", got)
	}
	if got := d.intOr("UID_MAX", 60000); got != 60000 {
		t.Errorf("unset UID_MAX must fall back, got %d", got)
	}
}
