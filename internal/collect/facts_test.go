//go:build linux

package collect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/facts"
)

func getRegistry(t *testing.T) *facts.Registry {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

// W-32: a collector reads a fact an earlier one set, through a glob it
// declared on Begin.
func TestBuilderGetReadsADeclaredFact(t *testing.T) {
	b := NewBuilder(getRegistry(t))
	b.Begin("firewall")
	b.Set("firewall.backend", facts.Envelope{Status: facts.StatusOK, Value: "ufw"})
	b.Begin("processes", "firewall.*")
	e, ok := b.Get("firewall.backend")
	if !ok || e.Status != facts.StatusOK || e.Value != "ufw" {
		t.Fatalf("Get = %+v %v", e, ok)
	}
	if _, ok := b.Get("firewall.nothing"); ok {
		t.Error("a key never set must not be found")
	}
	if _, ok := b.Get("firewall.restricts_inbound"); ok {
		t.Error("a registered key nobody set must not be found")
	}
}

// A setting is not read across collectors: Get answers (Envelope{}, false).
func TestBuilderGetOfASettingIsNotFound(t *testing.T) {
	b := NewBuilder(getRegistry(t))
	b.Begin("firewall")
	b.SetSetting("firewall.enabled", facts.Setting{Runtime: &facts.Envelope{Status: facts.StatusOK, Value: true}})
	b.Begin("processes", "firewall.*")
	if e, ok := b.Get("firewall.enabled"); ok || e.Status != "" {
		t.Errorf("Get(setting) = %+v %v, want (Envelope{}, false)", e, ok)
	}
}

func mustPanicUndeclared(t *testing.T, b *Builder, key, collector string) {
	t.Helper()
	defer func() {
		t.Helper()
		r := recover()
		want := "collect: " + collector + " reads undeclared fact " + key
		if r == nil || fmt.Sprint(r) != want {
			t.Errorf("Get(%s): recover = %v, want %q", key, r, want)
		}
	}()
	b.Get(key)
}

func TestBuilderGetOutsideTheDeclarationPanics(t *testing.T) {
	b := NewBuilder(getRegistry(t))
	b.Begin("firewall")
	b.Set("firewall.backend", facts.Envelope{Status: facts.StatusOK, Value: "ufw"})
	b.Begin("processes", "firewall.*")
	mustPanicUndeclared(t, b, "net.sysctl.ipv4_ip_forward", "processes")
	// The glob is anchored at the family: `firewall.*` is not `firewallx.*`.
	mustPanicUndeclared(t, b, "firewallx.backend", "processes")
	// path.Match's `*` stops only at `/`, so it DOES cross a dot: the family
	// glob covers its nested keys too.
	if _, ok := b.Get("firewall.default_policy.input"); ok {
		t.Error("a nested key nobody set must not be found")
	}

	// The licence is the CURRENT collector's: the next one declared nothing.
	b.Begin("sockets")
	mustPanicUndeclared(t, b, "firewall.backend", "sockets")

	// Begin again under the same name replaces, never accumulates.
	b.Begin("processes")
	mustPanicUndeclared(t, b, "firewall.backend", "processes")
}

// Begin keeps its own copy of the globs: a caller that reuses its slice
// cannot widen a collector's licence afterwards.
func TestBuilderBeginClonesTheGlobs(t *testing.T) {
	b := NewBuilder(getRegistry(t))
	globs := []string{"firewall.*"}
	b.Begin("processes", globs...)
	globs[0] = "*"
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "undeclared fact") {
			t.Errorf("recover = %v", r)
		}
	}()
	b.Get("os.id")
}
