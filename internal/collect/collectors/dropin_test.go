//go:build linux

package collectors

import (
	"os"
	"strings"
	"testing"
)

// The helper first (Ruling I-19): /etc shadows /run shadows /usr/local/lib shadows
// /usr/lib for the SAME basename; survivors apply in basename order; later wins.
func TestMergeDropinsShadowingAndOrder(t *testing.T) {
	a := timesyncAccess(map[string]string{
		"/etc/systemd/journald.conf":                      "journald.conf.main",       // Storage=auto
		"/usr/lib/systemd/journald.conf.d/10-vendor.conf": "journald.d.10-vendor",     // Storage=volatile (shadowed)
		"/etc/systemd/journald.conf.d/10-vendor.conf":     "journald.d.10-vendor-etc", // Storage=persistent
		"/run/systemd/journald.conf.d/20-runtime.conf":    "journald.d.20-runtime",    // ForwardToSyslog=yes
	}, nil)
	vals, inputs, err := mergeDropins(a, "/etc/systemd/journald.conf",
		[]string{"/etc/systemd/journald.conf.d", "/run/systemd/journald.conf.d",
			"/usr/local/lib/systemd/journald.conf.d", "/usr/lib/systemd/journald.conf.d"}, "*.conf")
	if err != nil {
		t.Fatal(err)
	}
	if vals["Storage"] != "persistent" || vals["ForwardToSyslog"] != "yes" {
		t.Errorf("vals: %+v", vals)
	}
	if len(inputs) != 3 {
		t.Errorf("inputs (shadowed file must NOT be read/listed): %+v", inputs)
	}
	// The shadowed vendor file must never have been opened at all.
	for _, p := range a.reads {
		if strings.HasPrefix(p, "/usr/lib/systemd/journald.conf.d/") {
			t.Errorf("a shadowed drop-in must not be read: %s", p)
		}
	}
	// The inputs are the files actually read, in the order they were applied.
	want := []string{
		"/etc/systemd/journald.conf",
		"/etc/systemd/journald.conf.d/10-vendor.conf",
		"/run/systemd/journald.conf.d/20-runtime.conf",
	}
	for i, w := range want {
		if i < len(inputs) && inputs[i].Path != w {
			t.Errorf("inputs[%d] = %s, want %s", i, inputs[i].Path, w)
		}
	}
	// The section is recorded alongside the bare key, so a caller that cares
	// which section set a value can ask for the qualified form.
	if vals["Journal/Storage"] != "persistent" {
		t.Errorf("qualified key: %+v", vals)
	}
}

// A main file that is not there is not an error: the daemon's compiled-in
// defaults apply, and the drop-ins are still merged.
func TestMergeDropinsMissingMainIsNotAnError(t *testing.T) {
	a := timesyncAccess(map[string]string{
		"/run/systemd/journald.conf.d/20-runtime.conf": "journald.d.20-runtime",
	}, nil)
	vals, inputs, err := mergeDropins(a, "/etc/systemd/journald.conf",
		[]string{"/etc/systemd/journald.conf.d", "/run/systemd/journald.conf.d"}, "*.conf")
	if err != nil {
		t.Fatal(err)
	}
	if vals["ForwardToSyslog"] != "yes" || len(inputs) != 1 {
		t.Errorf("vals %+v inputs %+v", vals, inputs)
	}
}

// R148: the FIRST read error of a file that EXISTS poisons the chain — a
// default guessed over an unreadable file would be fabricated evidence (C3).
func TestMergeDropinsUnreadableFileIsTheFirstReadError(t *testing.T) {
	a := timesyncAccess(map[string]string{
		"/etc/systemd/journald.conf":                   "journald.conf.main",
		"/run/systemd/journald.conf.d/20-runtime.conf": "journald.d.20-runtime",
	}, nil)
	a.fails["/etc/systemd/journald.conf"] = os.ErrPermission
	_, _, err := mergeDropins(a, "/etc/systemd/journald.conf",
		[]string{"/etc/systemd/journald.conf.d", "/run/systemd/journald.conf.d"}, "*.conf")
	if err == nil {
		t.Fatal("an existing but unreadable file must be reported")
	}
	e := dropinEnvelope(err)
	if e.Status != "denied" {
		t.Errorf("envelope: %+v", e)
	}
	if !strings.Contains(e.Reason, "/etc/systemd/journald.conf") {
		t.Errorf("the reason must name the file: %+v", e)
	}
}
