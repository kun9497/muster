//go:build linux

package collectors

import (
	"context"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The three ruleset-read command lines, byte-identical to the Command
// declarations (Ruling H-21: the guard matches Path+Args exactly, and the
// test double keys its canned outcomes on the same rendering).
const (
	nftListRuleset = "/usr/sbin/nft list ruleset"
	iptablesSave   = "/usr/sbin/iptables-save"
	ip6tablesSave  = "/usr/sbin/ip6tables-save"
)

func firewallAccess(files map[string]string, cmds map[string]cmdResult) *fsAccess {
	return &fsAccess{files: files, cmds: cmds}
}

// buildBegun mirrors build() but calls Begin(name) first, so Builder.Worst
// counts this collector's keys. build() does not call Begin, which makes
// Worst there trivially ok (an empty key set); the H-17/H-19 degradation
// tests need the real per-collector key set the run populates (run.go calls
// Begin) to tell an unsupported (root) run from a denied (non-root) one.
func buildBegun(t *testing.T, name string, a collect.Access) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	b := collect.NewBuilder(reg)
	c := collectorNamed(t, name)
	b.Begin(name)
	g := collect.Guard(a, c)
	if err := c.Run(context.Background(), g, b); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if v := g.Violations(); len(v) != 0 {
		t.Fatalf("%s touched undeclared targets: %v", name, v)
	}
	return b
}

// A readable kernel ruleset: the backend is detected, the raw dump is
// captured, and the run stays complete.
func TestFirewallCapturesRulesetWhenReadable(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.drop"}},
	)
	b := buildBegun(t, "firewall", a)

	if e := env(t, b, "firewall.backend"); e.Status != facts.StatusOK {
		t.Fatalf("backend: %+v", e)
	}
	if e := env(t, b, "firewall.backend"); e.Value != "nftables" {
		t.Errorf("backend value %+v, want nftables", e)
	}
	if e := env(t, b, "firewall.raw_dumps"); e.Status != facts.StatusOK {
		t.Errorf("raw_dumps should be captured: %+v", e)
	}
	dumps := okList(t, b, "firewall.raw_dumps")
	if len(dumps) != 1 {
		t.Fatalf("raw_dumps %v, want exactly one record", dumps)
	}
	rec := dumps[0].(map[string]any)
	if rec["source"] != nftListRuleset {
		t.Errorf("dump source %v, want %q (H-21)", rec["source"], nftListRuleset)
	}
	if rec["truncated"] != false {
		t.Errorf("dump truncated %v, want false", rec["truncated"])
	}
	content, ok := rec["content"].(string)
	if !ok || !strings.Contains(content, "policy drop") {
		t.Errorf("dump content must carry the captured ruleset text: %v", rec["content"])
	}

	// T1: restricts_inbound absent, normalization_confidence "none" (the real
	// normalisation lands in Task 2); rules an empty ok list.
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusAbsent {
		t.Errorf("restricts_inbound %+v, want absent in T1", e)
	}
	if e := env(t, b, "firewall.normalization_confidence"); e.Status != facts.StatusOK || e.Value != "none" {
		t.Errorf("normalization_confidence %+v, want ok \"none\" in T1", e)
	}
	if r := okList(t, b, "firewall.rules"); len(r) != 0 {
		t.Errorf("rules %v, want an empty list in T1", r)
	}

	// enabled: runtime from the non-empty ruleset, persisted from the config.
	en := setting(t, b, "firewall.enabled")
	if en.Runtime == nil || en.Runtime.Status != facts.StatusOK || en.Runtime.Value != true {
		t.Errorf("enabled runtime %+v, want ok true (ruleset non-empty)", en.Runtime)
	}
	if en.Persisted == nil || en.Persisted.Status != facts.StatusOK || en.Persisted.Value != true {
		t.Errorf("enabled persisted %+v, want ok true (nftables.conf present)", en.Persisted)
	}
	// default_policy must set BOTH sides validly even though T1 does not model
	// the values (H-18): a sideless setting is malformed.
	for _, k := range []string{"firewall.default_policy.input", "firewall.default_policy.forward"} {
		s := setting(t, b, k)
		if s.Runtime == nil || s.Persisted == nil {
			t.Errorf("%s must set both sides: %+v", k, s)
		}
	}

	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok (a readable ruleset keeps the run complete)`, got)
	}
}

// Root without CAP_NET_ADMIN / no netlink / tool absent (e.g. the
// collect-contract container): every ruleset command fails while euid()==0.
// H-17/R220: this degrades to UNSUPPORTED, never denied/error, and the run
// stays complete (unsupported ranks as ok in Worst).
func TestFirewallRootNoCapabilityDegradesToUnsupported(t *testing.T) {
	withEUID(t, 0)
	a := firewallAccess(nil, map[string]cmdResult{
		nftListRuleset: {exitCode: 1, stderr: "Error: Could not process rule: Operation not permitted\n"},
		iptablesSave:   {exitCode: 4, stderr: "iptables-save: can't initialize iptables table `filter': Permission denied (you must be root?)\n"},
		ip6tablesSave:  {exitCode: 4, stderr: "ip6tables-save: Permission denied\n"},
	})
	b := buildBegun(t, "firewall", a)
	for _, k := range []string{"firewall.backend", "firewall.restricts_inbound", "firewall.normalization_confidence"} {
		e := env(t, b, k)
		if e.Status == facts.StatusDenied || e.Status == facts.StatusError {
			t.Errorf("%s = %s, must NOT be denied/error (would break the collect-contract complete invariant)", k, e.Status)
		}
	}
	if e := env(t, b, "firewall.backend"); e.Status != facts.StatusUnsupported {
		t.Errorf("backend = %s, want unsupported when the ruleset cannot be read as root", e.Status)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok (unsupported ranks ok, run stays complete)`, got)
	}
}

// The euid()!=0 companion (H-17, collect-nonroot honesty): the same total
// failure while NOT root is DENIED, not unsupported, so the firewall
// collector's Worst is denied and the run is honestly partial (H-19).
func TestFirewallNonRootRulesetFailureIsDenied(t *testing.T) {
	withEUID(t, 1000)
	a := firewallAccess(nil, map[string]cmdResult{
		nftListRuleset: {exitCode: 1, stderr: "Error: Operation not permitted\n"},
		iptablesSave:   {exitCode: 4, stderr: "Permission denied (you must be root?)\n"},
		ip6tablesSave:  {exitCode: 4, stderr: "Permission denied\n"},
	})
	b := buildBegun(t, "firewall", a)
	for _, k := range []string{"firewall.backend", "firewall.restricts_inbound", "firewall.normalization_confidence"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied {
			t.Errorf("%s = %s, want denied on a non-root ruleset failure", k, e.Status)
		}
	}
	if e := env(t, b, "firewall.backend"); !strings.Contains(e.Reason, "requires root") {
		t.Errorf("backend reason %q must name the privilege", e.Reason)
	}
	if got := b.Worst("firewall"); got != facts.StatusDenied {
		t.Errorf(`Worst("firewall") = %s, want denied (non-root run is honestly partial, H-19)`, got)
	}
}

// nft fails but iptables-save answers: the collector falls back, captures
// both the v4 and v6 dumps, and reports the iptables backend.
func TestFirewallFallsBackToIptablesSave(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/iptables/rules.v4": "iptables-save.accept"},
		map[string]cmdResult{
			nftListRuleset: {exitCode: 1, stderr: "sh: nft: command not found\n"},
			iptablesSave:   {file: "iptables-save.accept"},
			ip6tablesSave:  {file: "ip6tables-save.accept"},
		},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.backend"); e.Status != facts.StatusOK || e.Value != "iptables" {
		t.Errorf("backend %+v, want ok iptables", e)
	}
	dumps := okList(t, b, "firewall.raw_dumps")
	if len(dumps) != 2 {
		t.Fatalf("raw_dumps %v, want v4 and v6 records", dumps)
	}
	if dumps[0].(map[string]any)["source"] != iptablesSave {
		t.Errorf("first dump source %v, want %q", dumps[0].(map[string]any)["source"], iptablesSave)
	}
	if dumps[1].(map[string]any)["source"] != ip6tablesSave {
		t.Errorf("second dump source %v, want %q", dumps[1].(map[string]any)["source"], ip6tablesSave)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok`, got)
	}
}

// H-22: a dump whose capture hit the exec output cap marks the record
// truncated:true and forces normalization_confidence to "partial"; a value
// parsed out of a partial ruleset is not the whole answer.
func TestFirewallTruncatedDumpIsPartialConfidence(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.drop", truncated: true}},
	)
	b := buildBegun(t, "firewall", a)
	rec := okList(t, b, "firewall.raw_dumps")[0].(map[string]any)
	if rec["truncated"] != true {
		t.Errorf("a truncated capture must set the record truncated:true: %v", rec)
	}
	if e := env(t, b, "firewall.normalization_confidence"); e.Status != facts.StatusOK || e.Value != "partial" {
		t.Errorf("normalization_confidence %+v, want ok \"partial\" on a truncated dump (H-22)", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusAbsent {
		t.Errorf("restricts_inbound %+v, want absent (H-22)", e)
	}
}
