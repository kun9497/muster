//go:build linux

package collectors

import (
	"context"
	"os"
	"reflect"
	"slices"
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

	// T2: the drop-policy input base chain normalises to full confidence and a
	// restricted verdict, and the rules the chain carries are parsed as
	// evidence.
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("restricts_inbound %+v, want ok true (policy drop)", e)
	}
	if e := env(t, b, "firewall.normalization_confidence"); e.Status != facts.StatusOK || e.Value != "full" {
		t.Errorf("normalization_confidence %+v, want ok \"full\"", e)
	}
	if r := okList(t, b, "firewall.rules"); len(r) == 0 {
		t.Errorf("rules %v, want the parsed input-chain rules as evidence", r)
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

// H-16, the confident-restricted case: an nft input base chain with
// "policy drop" → full confidence, restricts_inbound ok:true, and the runtime
// default policy reads drop.
func TestFirewallNftDropIsRestricted(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.drop"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
		t.Fatalf("confidence: %+v", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("restricts_inbound: %+v", e)
	}
	if s := setting(t, b, "firewall.default_policy.input"); s.Runtime == nil || s.Runtime.Status != facts.StatusOK || s.Runtime.Value != "drop" {
		t.Errorf("default_policy.input runtime %+v, want ok drop", s.Runtime)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok`, got)
	}
}

// H-16, the confident-unrestricted case: an iptables *filter with
// ":INPUT ACCEPT" carrying ZERO "-A INPUT" rules demonstrably does nothing
// inbound → full confidence, restricts_inbound ok:false.
func TestFirewallIptablesAcceptIsNotRestricted(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/iptables/rules.v4": "iptables-save.open"},
		map[string]cmdResult{
			nftListRuleset: {exitCode: 1, stderr: "sh: nft: command not found\n"},
			iptablesSave:   {file: "iptables-save.open"},
		},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
		t.Fatalf("confidence %+v, want full (accept + zero rules is determinable)", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("restricts_inbound %+v, want ok false", e)
	}
	if s := setting(t, b, "firewall.default_policy.input"); s.Runtime == nil || s.Runtime.Value != "accept" {
		t.Errorf("default_policy.input runtime %+v, want ok accept", s.Runtime)
	}
}

// H-16, the anti-false-FAIL case: a firewalld-shape nft input base chain with
// "policy accept" that CARRIES rules (a jump into the zone dispatch and a
// terminal reject) restricts inbound in practice even though its base policy
// is accept. It must NEVER be a confident ok:false FAIL — it degrades to
// partial confidence and restricts_inbound ABSENT (→ MANUAL).
func TestFirewallAcceptWithRulesIsPartialAbsent(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/firewalld/firewalld.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.firewalld"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value == "full" {
		t.Fatalf("must not claim full on an unmodelled ruleset: %+v", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusAbsent {
		t.Errorf("restricts_inbound must be ABSENT at partial confidence (→ MANUAL): %+v", e)
	}
	// The absent reason must point a reviewer back at the raw evidence.
	if e := env(t, b, "firewall.restricts_inbound"); !strings.Contains(e.Reason, "raw_dumps") {
		t.Errorf("absent reason %q should reference firewall.raw_dumps", e.Reason)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok (partial is not a failure of the collector)`, got)
	}
}

// S2, the anti-false-FAIL guard for earlier inbound hooks: a filter INPUT
// chain that is policy accept with ZERO rules would be a confident ok:false on
// its own, but a `type filter hook ingress` chain that carries a drop rule
// means the ruleset does restrict inbound. It must NEVER be a confident
// ok:false — it degrades to partial + restricts_inbound ABSENT (→ MANUAL).
func TestFirewallNftIngressRulesBlockConfidentOpen(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.ingress-drop"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence %+v, want partial (an ingress filter chain carries rules, S2)", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusAbsent {
		t.Errorf("restricts_inbound %+v, want ABSENT — never a confident ok:false when an earlier inbound hook carries rules (S2)", e)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok (partial is not a collector failure)`, got)
	}
}

// S2 for the iptables path: a *filter :INPUT ACCEPT with zero -A INPUT rules
// alone is a confident ok:false, but a *raw PREROUTING drop is an earlier
// inbound-path rule the *filter view does not see. It must degrade to partial
// + restricts_inbound ABSENT, not a confident ok:false FAIL.
func TestFirewallIptablesRawPreroutingBlocksConfidentOpen(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/iptables/rules.v4": "iptables-save.raw-drop"},
		map[string]cmdResult{
			nftListRuleset: {exitCode: 1, stderr: "sh: nft: command not found\n"},
			iptablesSave:   {file: "iptables-save.raw-drop"},
		},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence %+v, want partial (a *raw PREROUTING rule is inbound-path, S2)", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusAbsent {
		t.Errorf("restricts_inbound %+v, want ABSENT (S2)", e)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok`, got)
	}
}

// N1: a type nat INPUT base chain (policy accept, zero rules — created by any
// iptables-nft save/restore) must NOT demote a hardened `filter INPUT drop`
// host to MANUAL. Only filter chains are weighed, so the host stays full +
// restricts_inbound ok:true.
func TestFirewallNatInputChainIgnored(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.nat-input-drop"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
		t.Errorf("confidence %+v, want full (a type nat INPUT chain must not demote a filter INPUT drop, N1)", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("restricts_inbound %+v, want ok true (N1)", e)
	}
	if got := b.Worst("firewall"); got != facts.StatusOK {
		t.Errorf(`Worst("firewall") = %s, want ok`, got)
	}
}

// H-16, multiple input base chains that AGREE: an nft ruleset with an ip and
// an ip6 input base chain both "policy drop" stays full + restricts_inbound
// ok:true (the old "exactly one input chain" rule would have made every
// dual-stack host permanently MANUAL).
func TestFirewallDualStackDropIsRestricted(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.dualstack-drop"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
		t.Fatalf("confidence %+v, want full (both families agree drop)", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("restricts_inbound %+v, want ok true", e)
	}
}

// A line inside a chain body that is not blank yet carries no fields must be
// skipped, not indexed: trimSpaceASCII trims only space and tab, while
// strings.Fields also treats a form feed as space, so such a line reached the
// chain body's f[0] read. The nightly fuzz run of FuzzParseNftRuleset found
// it; the input is the committed crasher.
func TestParseNftRulesetFieldlessLineInChain(t *testing.T) {
	bases, rules := parseNftRuleset("{\nchain {\n\f")
	if len(bases) != 0 {
		t.Errorf("base chains = %+v, want none (nothing declares a hook and no chain closes)", bases)
	}
	if len(rules) != 0 {
		t.Errorf("rules = %v, want none (a chain outside a table block is no chain)", rules)
	}
}

// fwRowsOf returns firewall.rules as rows, asserting that every row carries the
// fourteen fields of W-4 and W-59 and nothing else.
func fwRowsOf(t *testing.T, b *collect.Builder) []fwRule {
	t.Helper()
	fields := []string{"action", "chain", "ctstate", "daddr", "depth", "dport", "family", "iif", "proto", "raw", "saddr", "table", "unmodelled", "via_chain"}
	var rows []fwRule
	for _, v := range okList(t, b, "firewall.rules") {
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("a firewall.rules row is %T, not a record", v)
		}
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, fields) {
			t.Fatalf("row fields %v, want %v", keys, fields)
		}
		rows = append(rows, fwRuleFromRecord(m))
	}
	return rows
}

// X-8: ufw's chains under iptables-save fold into the INPUT base chain; the
// `allow 80/tcp` accept is a depth-2 row via INPUT (INPUT → ufw-before-input →
// ufw-user-input), and nothing of FORWARD or OUTPUT is folded.
func TestFirewallFoldsUfwChains(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/ufw/ufw.conf": "ufw.conf"},
		map[string]cmdResult{
			nftListRuleset: {exitCode: 1, stderr: "sh: nft: command not found\n"},
			iptablesSave:   {file: "iptables-save.ufw-allow-80"},
			ip6tablesSave:  {exitCode: 1, stderr: "ip6tables-save: not found\n"},
		},
	)
	b := buildBegun(t, "firewall", a)
	rows := fwRowsOf(t, b)
	var http []fwRule
	for _, r := range rows {
		if r.ViaChain != "INPUT" || r.Family != "v4" {
			t.Errorf("row %+v is not folded under the v4 INPUT", r)
		}
		if strings.Contains(r.Chain, "forward") || strings.Contains(r.Chain, "output") {
			t.Errorf("a FORWARD/OUTPUT chain was folded: %+v", r)
		}
		if r.Dport == "80" {
			http = append(http, r)
		}
	}
	want := fwRule{Chain: "ufw-user-input", ViaChain: "INPUT", Table: "filter", Depth: 2, Family: "v4", Proto: "tcp", Dport: "80", Action: "accept",
		Raw: "-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT"}
	if len(http) != 1 || http[0] != want {
		t.Fatalf("the allow 80/tcp rows %+v, want exactly %+v", http, want)
	}
	if e := env(t, b, "firewall.backend"); e.Value != "ufw" {
		t.Errorf("backend %+v, want ufw", e)
	}
}

// W-36, W-54, W-55: ufw's stock before/after chains decide — under both
// iptables-save (v4 and the ip6tables-save twin) and the iptables-nft
// `nft list ruleset` rendering (ip and ip6 tables), with `limit 22/tcp` and
// `allow 80/tcp`: no folded INPUT row is opaque, and in each family the tcp
// port rules are exactly 22 (ufw-user-limit-accept's ACCEPT, carrying its
// jump's tcp/22) and 80.
func TestFirewallUfwBeforeRulesDecide(t *testing.T) {
	read := func(file string) string {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	dump := func(source, file string) map[string]any {
		return map[string]any{"source": source, "content": read(file), "truncated": false}
	}
	for _, c := range []struct {
		name string
		cr   capture
	}{
		{"iptables-save", capture{tool: "iptables", ok: true, dumps: []any{
			dump(iptablesSave, "testdata/iptables-save.ufw-allow-80"), dump(ip6tablesSave, "testdata/ip6tables-save.ufw-allow-80")}}},
		{"nft", capture{tool: "nft", ok: true, dumps: []any{dump(nftListRuleset, "testdata/nft.ruleset.ufw-allow-80")}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			bases, rows := normalizeRuleset(c.cr)
			if len(bases) == 0 {
				t.Fatal("no base chain parsed")
			}
			tcpPorts := map[string][]string{}
			count := map[string]int{}
			for _, r := range rows {
				if r.ViaChain != "INPUT" || r.Table != "filter" {
					t.Errorf("row not under a filter INPUT: %+v", r)
				}
				count[r.Family]++
				switch classifyRule(r) {
				case "opaque", "any_port":
					t.Errorf("%s row: %+v", classifyRule(r), r)
				case "port_rule":
					if r.Proto == "tcp" {
						tcpPorts[r.Family] = append(tcpPorts[r.Family], r.Dport)
					}
				}
			}
			for _, fam := range []string{"v4", "v6"} {
				if !slices.Equal(tcpPorts[fam], []string{"22", "80"}) {
					t.Errorf("%s tcp port rules %v, want [22 80]", fam, tcpPorts[fam])
				}
			}
			// v4: INPUT 6 + ufw-before-input 13 + ufw-logging-deny 2 (under
			// ct state invalid) + ufw-not-local 5 + ufw-logging-deny 2 again
			// (under not-local's limit) + ufw-user-input 4 + ufw-user-limit 2
			// + ufw-user-limit-accept 1 + ufw-after-input 7 +
			// ufw-skip-to-policy-input 7 (once per distinct jump) +
			// ufw-after-logging-input 1. v6 has no not-local chain and 18
			// before-input rules: 6 + 18 + 2 + 4 + 2 + 1 + 6 + 6 + 1.
			if count["v4"] != 50 || count["v6"] != 46 || len(count) != 2 {
				t.Errorf("rows per family %v, want v4 50 and v6 46", count)
			}
		})
	}
}

// W-44: folding never changes the confidence. ufw's INPUT is policy drop and
// carries only jumps; with its user chains folded in (accepts among them) it
// stays full + restricts_inbound ok:true. An accept-policy INPUT whose only
// rule is a jump into a chain of accepts stays partial, as before the fold.
func TestFirewallFoldedRulesDoNotChangeConfidence(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/ufw/ufw.conf": "ufw.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.ufw-allow-80"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
		t.Errorf("confidence %+v, want full", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("restricts_inbound %+v, want ok true", e)
	}
	deep := 0
	for _, r := range fwRowsOf(t, b) {
		if r.Depth > 0 && r.Action == "accept" {
			deep++
		}
	}
	if deep == 0 {
		t.Error("no folded accept: the test no longer exercises the fold")
	}

	const acceptJump = "table ip filter {\n" +
		"\tchain INPUT {\n\t\ttype filter hook input priority filter; policy accept;\n\t\tjump user\n\t}\n" +
		"\tchain user {\n\t\ttcp dport 22 accept\n\t}\n}\n"
	a = firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {stdout: []byte(acceptJump)}},
	)
	b = buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence %+v, want partial (an accept-policy chain carries rules)", e)
	}
	if rows := fwRowsOf(t, b); len(rows) != 2 || rows[1].Depth != 1 || rows[1].Dport != "22" {
		t.Errorf("rows %+v, want the jump and the folded accept", rows)
	}
}

// X-9: ufw installed but disabled leaves the kernel ruleset empty — no input
// base chain and no inbound rule. That is no firewall: full confidence and
// restricts_inbound ok:false, with the reason said, no longer partial.
func TestFirewallInactiveUfwNormalisesFull(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/ufw/ufw.conf": "ufw.conf.disabled"},
		map[string]cmdResult{nftListRuleset: {stdout: []byte{}}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.backend"); e.Value != "ufw" {
		t.Fatalf("backend %+v, want ufw", e)
	}
	if e := env(t, b, "firewall.normalization_confidence"); e.Status != facts.StatusOK || e.Value != "full" {
		t.Errorf("confidence %+v, want ok full (X-9)", e)
	}
	e := env(t, b, "firewall.restricts_inbound")
	if e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("restricts_inbound %+v, want ok false (X-9)", e)
	}
	if e.Reason != "no input base chain and no inbound rule: nothing restricts inbound" {
		t.Errorf("restricts_inbound reason %q", e.Reason)
	}
	if rows := fwRowsOf(t, b); len(rows) != 0 {
		t.Errorf("rows %+v, want none", rows)
	}
	en := setting(t, b, "firewall.enabled")
	if en.Persisted == nil || en.Persisted.Value != false {
		t.Errorf("enabled persisted %+v, want ok false (ENABLED=no)", en.Persisted)
	}
}

// W-4: a bridge table's input chain is not an input base chain. Here it would
// have made the policies disagree (bridge drop, inet accept) and its accept
// would have been a row; ignored, the inet accept chain with no rules decides.
func TestFirewallBridgeTableIsIgnored(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.bridge-input"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
		t.Errorf("confidence %+v, want full (the bridge chain does not count)", e)
	}
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("restricts_inbound %+v, want ok false", e)
	}
	if rows := fwRowsOf(t, b); len(rows) != 0 {
		t.Errorf("rows %+v, want none (the bridge table's rule is not a row)", rows)
	}
	if s := setting(t, b, "firewall.default_policy.input"); s.Runtime == nil || s.Runtime.Value != "accept" {
		t.Errorf("default_policy.input runtime %+v, want accept (the inet chain alone)", s.Runtime)
	}
}

// Every row carries its family and the raw line; the dual-stack nft fixture's
// ip and ip6 input chains give v4 and v6 rows.
func TestFirewallRowsCarryFamilyAndRaw(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {file: "nft.ruleset.dualstack-drop"}},
	)
	b := buildBegun(t, "firewall", a)
	families := map[string]bool{}
	for _, r := range fwRowsOf(t, b) {
		families[r.Family] = true
		if r.Raw == "" || r.Depth != 0 || r.ViaChain != r.Chain {
			t.Errorf("base-chain row %+v: want raw, depth 0, via_chain = chain", r)
		}
	}
	if !families["v4"] || !families["v6"] {
		t.Errorf("families %v, want v4 and v6", families)
	}
}

// A blank line inside a chain body is an administrator's spacing, never a
// rule: the parse must be identical to the same ruleset written without it.
func TestParseNftRulesetBlankLineInChainIsIgnored(t *testing.T) {
	const packed = "table inet filter {\n" +
		"\tchain input {\n" +
		"\t\ttype filter hook input priority filter; policy drop;\n" +
		"\t\tct state established,related accept\n" +
		"\t\ttcp dport 22 accept\n" +
		"\t}\n" +
		"}\n"
	const spaced = "table inet filter {\n" +
		"\tchain input {\n" +
		"\t\ttype filter hook input priority filter; policy drop;\n" +
		"\t\tct state established,related accept\n" +
		"\n" +
		"\t  \t\n" +
		"\t\ttcp dport 22 accept\n" +
		"\t}\n" +
		"}\n"
	wantBases, wantRules := parseNftRuleset(packed)
	if len(wantBases) != 1 || len(wantRules[chainKey{"inet", "filter", "input"}]) != 2 {
		t.Fatalf("the packed ruleset itself parsed as %+v / %v, want one base chain and two rules", wantBases, wantRules)
	}
	gotBases, gotRules := parseNftRuleset(spaced)
	if !reflect.DeepEqual(gotBases, wantBases) {
		t.Errorf("base chains with blank lines = %+v, want %+v", gotBases, wantBases)
	}
	if !reflect.DeepEqual(gotRules, wantRules) {
		t.Errorf("rules with blank lines = %v, want %v", gotRules, wantRules)
	}
}

// W-57: nft answers with an empty ruleset while iptables-legacy holds the
// rules (`:INPUT DROP` in x_tables). That is no proof of "no firewall": the
// confidence is partial, restricts_inbound absent, and the legacy dump joins
// the evidence.
func TestFirewallNftEmptyButLegacyFullIsPartial(t *testing.T) {
	a := firewallAccess(
		map[string]string{"/etc/ufw/ufw.conf": "ufw.conf"},
		map[string]cmdResult{
			nftListRuleset: {stdout: []byte{}},
			iptablesSave:   {file: "iptables-save.ufw-allow-80"},
		},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence %+v, want partial", e)
	}
	e := env(t, b, "firewall.restricts_inbound")
	if e.Status != facts.StatusAbsent || e.Reason != "nft ruleset empty but iptables-legacy carries rules; see firewall.raw_dumps" {
		t.Errorf("restricts_inbound %+v, want absent with the legacy reason", e)
	}
	dumps := okList(t, b, "firewall.raw_dumps")
	if len(dumps) != 2 || dumps[1].(map[string]any)["source"] != iptablesSave {
		t.Errorf("raw_dumps %v, want the nft dump and the iptables-save cross-check", dumps)
	}

	// iptables-nft's own warning that legacy tables exist counts the same.
	a = firewallAccess(nil, map[string]cmdResult{
		nftListRuleset: {stdout: []byte{}},
		iptablesSave:   {stdout: []byte("# Warning: iptables-legacy tables present, use iptables-legacy-save to see them\n")},
	})
	b = buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence with the legacy warning %+v, want partial", e)
	}

	// S1: the real iptables-nft prints that warning on stderr, with an empty
	// dump on stdout. It counts the same, and the record carries it.
	const warning = "# Warning: iptables-legacy tables present, use iptables-legacy to see them\n"
	a = firewallAccess(nil, map[string]cmdResult{
		nftListRuleset: {stdout: []byte{}},
		iptablesSave:   {stdout: []byte{}, stderr: warning},
	})
	b = buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence with the legacy warning on stderr %+v, want partial", e)
	}
	dumps = okList(t, b, "firewall.raw_dumps")
	if len(dumps) != 2 {
		t.Fatalf("raw_dumps %v, want the nft dump and the iptables-save cross-check", dumps)
	}
	if rec := dumps[1].(map[string]any); rec["stderr"] != warning || rec["content"] != "" {
		t.Errorf("cross-check record %v, want the warning as stderr and an empty content", rec)
	}
	if _, ok := dumps[0].(map[string]any)["stderr"]; ok {
		t.Errorf("nft record %v carries a stderr it never had", dumps[0])
	}
}

// The inverse of W-57: both readings empty (or an accept INPUT with no rule)
// stays X-9's full + ok:false.
func TestFirewallNftAndLegacyEmptyStaysFull(t *testing.T) {
	for name, legacy := range map[string]string{
		"empty":  "",
		"accept": "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n",
	} {
		t.Run(name, func(t *testing.T) {
			a := firewallAccess(
				map[string]string{"/etc/ufw/ufw.conf": "ufw.conf.disabled"},
				map[string]cmdResult{nftListRuleset: {stdout: []byte{}}, iptablesSave: {stdout: []byte(legacy)}},
			)
			b := buildBegun(t, "firewall", a)
			if e := env(t, b, "firewall.normalization_confidence"); e.Value != "full" {
				t.Errorf("confidence %+v, want full", e)
			}
			if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != false {
				t.Errorf("restricts_inbound %+v, want ok false", e)
			}
		})
	}
}

// M-4: a chain's own `comment "…"` line is no rule — no row, and it does not
// make an accept-policy chain "carry rules".
func TestParseNftRulesetChainCommentIsInert(t *testing.T) {
	const ruleset = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n" +
		"\t\tcomment \"the host's input chain\"\n\t}\n}\n"
	bases, by := parseNftRuleset(ruleset)
	if len(bases) != 1 || bases[0].hasRules {
		t.Errorf("bases %+v, want one input chain carrying no rule", bases)
	}
	if rules := by[chainKey{"inet", "filter", "input"}]; len(rules) != 0 {
		t.Errorf("rows %+v, want none", rules)
	}
}

// R-2: Debian's stock nftables.conf (an inet input chain, policy accept, no
// rule) loaded beside a ufw running on iptables-legacy. The accept-no-rules
// reading is no proof either: partial, restricts_inbound absent.
func TestFirewallNftAcceptNoRulesButLegacyFullIsPartial(t *testing.T) {
	const stock = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n" +
		"\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t}\n}\n"
	a := firewallAccess(
		map[string]string{"/etc/ufw/ufw.conf": "ufw.conf"},
		map[string]cmdResult{nftListRuleset: {stdout: []byte(stock)}, iptablesSave: {file: "iptables-save.ufw-allow-80"}},
	)
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence %+v, want partial", e)
	}
	e := env(t, b, "firewall.restricts_inbound")
	if e.Status != facts.StatusAbsent || e.Reason != "nft input chains accept with no rule but iptables-legacy carries rules; see firewall.raw_dumps" {
		t.Errorf("restricts_inbound %+v, want absent with the legacy reason", e)
	}

	// The same nft ruleset with an empty legacy side stays full + ok:false.
	a = firewallAccess(
		map[string]string{"/etc/nftables.conf": "nftables.conf"},
		map[string]cmdResult{nftListRuleset: {stdout: []byte(stock)}, iptablesSave: {stdout: []byte{}}},
	)
	b = buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.restricts_inbound"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("restricts_inbound %+v, want ok false", e)
	}
}

// R-4: a truncated legacy dump marks the raw_dumps envelope truncated, as a
// truncated primary dump does.
func TestFirewallTruncatedLegacyDumpMarksRawDumps(t *testing.T) {
	a := firewallAccess(nil, map[string]cmdResult{
		nftListRuleset: {stdout: []byte{}},
		iptablesSave:   {stdout: []byte("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"), truncated: true},
	})
	b := buildBegun(t, "firewall", a)
	if e := env(t, b, "firewall.raw_dumps"); !e.Truncated {
		t.Errorf("raw_dumps %+v, want the envelope truncated", e)
	}
	if e := env(t, b, "firewall.normalization_confidence"); e.Value != "partial" {
		t.Errorf("confidence %+v, want partial (W-61)", e)
	}
}
