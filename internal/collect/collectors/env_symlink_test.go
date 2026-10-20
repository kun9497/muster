//go:build linux

package collectors

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// O-85: Ubuntu 24.04's libdebuginfod-common ships /etc/profile.d/debuginfod.sh
// as a symbolic link to its package data under /usr/share. The entry is read
// through that one level, so the link is neither an error on every
// env.shell.* key nor a hole in what the shell sources.

// envLinkProfile sets every value the seven keys judge, so a link that
// swallowed the read would show as a difference from the baseline.
const envLinkProfile = "TMOUT=600\nexport TMOUT\numask 022\nPATH=/usr/bin:/bin\n"

// envLinkDebuginfod is a synthetic stand-in for the shipped snippet: it sets
// DEBUGINFOD_URLS inside a conditional and touches neither TMOUT, umask nor
// PATH.
const envLinkDebuginfod = `# synthetic: a distribution's debuginfod profile snippet
if [ -z "$DEBUGINFOD_URLS" ]; then
    prefix="/usr"
    DEBUGINFOD_URLS=$(cat /dev/null "$prefix"/etc/debuginfod/*.urls 2>/dev/null | tr '\n' ' ' || :)
    [ -n "$DEBUGINFOD_URLS" ] && export DEBUGINFOD_URLS || unset DEBUGINFOD_URLS
    unset prefix
fi
`

const (
	envLinkEntry  = "/etc/profile.d/debuginfod.sh"
	envLinkTarget = "/usr/share/libdebuginfod-common/debuginfod.sh"
)

// linkedEntry seeds entry as a symbolic link to target the way the host
// primitive answers it: Readlink returns the stored text and a read of the
// entry itself is ErrSymlink.
func linkedEntry(a *fsAccess, entry, target string) {
	if a.links == nil {
		a.links = map[string]string{}
	}
	if a.fails == nil {
		a.fails = map[string]error{}
	}
	a.links[entry] = target
	a.fails[entry] = fmt.Errorf("%s: %w", entry, collect.ErrSymlink)
}

func TestEnvProfileDLinkToPackageDataIsRead(t *testing.T) {
	baseline := build(t, "env", &fsAccess{
		contents: map[string][]byte{
			"/etc/profile": []byte(envLinkProfile),
			envLinkEntry:   []byte(envLinkDebuginfod),
		},
		stats: map[string]statResult{"/usr/bin": {mode: 0o755, kind: "dir"}, "/bin": {mode: 0o755, kind: "dir"}},
	})
	a := &fsAccess{
		contents: map[string][]byte{
			"/etc/profile": []byte(envLinkProfile),
			envLinkTarget:  []byte(envLinkDebuginfod),
		},
		stats: map[string]statResult{"/usr/bin": {mode: 0o755, kind: "dir"}, "/bin": {mode: 0o755, kind: "dir"}},
	}
	linkedEntry(a, envLinkEntry, envLinkTarget)
	b := build(t, "env", a)
	for _, k := range envShellKeys {
		got, want := env(t, b, k), env(t, baseline, k)
		if got.Status != facts.StatusOK {
			t.Errorf("%s: %+v, want ok (a distribution's linked profile.d entry is read, O-85)", k, got)
			continue
		}
		if fmt.Sprintf("%#v", got.Value) != fmt.Sprintf("%#v", want.Value) {
			t.Errorf("%s: %#v, want %#v (the value without the link)", k, got.Value, want.Value)
		}
	}
	if !slices.Contains(a.reads, envLinkTarget) {
		t.Errorf("the link's target was never read: reads %v", a.reads)
	}
}

// A value set in the linked file is seen, and its row names the entry the
// shell sources.
func TestEnvProfileDLinkTargetSetsTMOUT(t *testing.T) {
	a := &fsAccess{contents: map[string][]byte{"/usr/share/x/y.sh": []byte("TMOUT=600\nexport TMOUT\n")}}
	linkedEntry(a, "/etc/profile.d/y.sh", "/usr/share/x/y.sh")
	b := build(t, "env", a)
	e := env(t, b, "env.shell.tmout")
	if e.Status != facts.StatusOK || e.Value != 600 {
		t.Fatalf("tmout %+v, want 600 from the linked file", e)
	}
	if e.Source == nil || e.Source.Path != "/etc/profile.d/y.sh" {
		t.Errorf("source %+v, want the profile.d entry", e.Source)
	}
	if env(t, b, "env.shell.tmout_exported").Value != true {
		t.Error("the linked file exports TMOUT")
	}
}

// Every other link is declined: the seven keys are absent naming the entry
// and its target, never an error, and nothing outside the declaration is read.
func TestEnvProfileDLinkDeclined(t *testing.T) {
	cases := []struct {
		name, target string
		seed         func(a *fsAccess)
	}{
		{name: "elsewhere", target: "/tmp/evil.sh"},
		{name: "relative", target: "../../usr/share/x/y.sh"},
		{name: "deeper", target: "/usr/share/x/y/z.sh"},
		{name: "unclean", target: "/usr/share/x/../y.sh"},
		{name: "chained", target: "/usr/share/x/y.sh", seed: func(a *fsAccess) {
			linkedEntry(a, "/usr/share/x/y.sh", "/tmp/evil.sh")
		}},
		{name: "not regular", target: "/usr/share/x/y.sh", seed: func(a *fsAccess) {
			a.fails = map[string]error{"/usr/share/x/y.sh": fmt.Errorf("/usr/share/x/y.sh: %w", collect.ErrNotRegular)}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := &fsAccess{contents: map[string][]byte{
				"/etc/profile": []byte(envLinkProfile),
				"/tmp/evil.sh": []byte("TMOUT=0\n"),
			}}
			if c.seed != nil {
				c.seed(a)
			}
			linkedEntry(a, "/etc/profile.d/z.sh", c.target)
			b := build(t, "env", a)
			for _, k := range envShellKeys {
				e := env(t, b, k)
				if e.Status != facts.StatusAbsent {
					t.Errorf("%s: %+v, want absent (a declined link, O-85)", k, e)
					continue
				}
				if !strings.HasPrefix(e.Reason, "/etc/profile.d/z.sh:") || !strings.Contains(e.Reason, c.target) {
					t.Errorf("%s: reason %q must name the entry and %s", k, e.Reason, c.target)
				}
			}
			if slices.Contains(a.reads, "/tmp/evil.sh") {
				t.Errorf("a declined target was read: %v", a.reads)
			}
		})
	}
}

// /etc/profile is a main configuration file: a symlink there stays the read's
// error (C4), the profile.d rule does not extend to it.
func TestEnvProfileLinkIsStillAnError(t *testing.T) {
	a := &fsAccess{contents: map[string][]byte{"/usr/share/x/profile": []byte(envLinkProfile)}}
	linkedEntry(a, "/etc/profile", "/usr/share/x/profile")
	b := build(t, "env", a)
	for _, k := range envShellKeys {
		if e := env(t, b, k); e.Status != facts.StatusError {
			t.Errorf("%s: %+v, want error (C4)", k, e)
		}
	}
}

// A package-data target that exists but cannot be read is the read's status
// (C3), path-prefixed with the entry; a dangling one contributes nothing, as
// an entry that does not exist.
func TestEnvProfileDLinkTargetUnreadableOrMissing(t *testing.T) {
	a := &fsAccess{fails: map[string]error{"/usr/share/x/y.sh": fmt.Errorf("/usr/share/x/y.sh: %w", os.ErrPermission)}}
	linkedEntry(a, "/etc/profile.d/y.sh", "/usr/share/x/y.sh")
	b := build(t, "env", a)
	for _, k := range envShellKeys {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied || !strings.HasPrefix(e.Reason, "/etc/profile.d/y.sh (a symbolic link to /usr/share/x/y.sh):") {
			t.Errorf("%s: %+v, want denied naming the entry and its target", k, e)
		}
	}

	d := &fsAccess{contents: map[string][]byte{"/etc/profile": []byte(envLinkProfile)}}
	linkedEntry(d, "/etc/profile.d/y.sh", "/usr/share/x/gone.sh")
	if e := env(t, build(t, "env", d), "env.shell.tmout"); e.Status != facts.StatusOK || e.Value != 600 {
		t.Errorf("a dangling link contributes nothing: tmout %+v, want 600 from /etc/profile", e)
	}
}
