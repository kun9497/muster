package collectors

import (
	"strings"
	"testing"
)

// The exposure verdict over hand-built rule tables (spec P-3, W-5, W-6).
// Addresses are RFC 5737 / RFC 3849 documentation ranges.

func lsn(proto, family, addr string, port int) listener {
	return listener{Proto: proto, Family: family, Addr: addr, Port: port, Loopback: isLoopback(addr), LinkLocal: isLinkLocal(addr),
		OwnerStatus: "ok", Owners: []owner{{Pid: 700, Name: "daemon", Package: "pkg"}}}
}

func accept(fam, chain, rest string) fwRule {
	r := fwRule{Chain: chain, ViaChain: "input", Table: "filter", Family: fam, Action: "accept", Raw: rest + " accept"}
	for _, f := range strings.Fields(rest) {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "proto":
			r.Proto = v
		case "dport":
			r.Dport = strings.ReplaceAll(v, "_", " ")
		case "saddr":
			r.Saddr = v
		case "daddr":
			r.Daddr = v
		case "iif":
			r.Iif = v
		case "ct":
			r.Ctstate = v
		case "unmodelled":
			r.Unmodelled = true
		}
	}
	return r
}

func truePtr() *bool  { v := true; return &v }
func falsePtr() *bool { v := false; return &v }

// full is a decided, restricting firewall over the given rows.
func full(rules ...fwRule) exposureInputs {
	return exposureInputs{Confidence: "full", Restricts: truePtr(), Rules: rules, BindV6Only: 0, HasV6: false}
}

func expRow(t *testing.T, rows []exposureRow, service, addr string) exposureRow {
	t.Helper()
	for _, r := range rows {
		if r.Service == service && r.Addr == addr {
			return r
		}
	}
	t.Fatalf("no row %s on %s in %+v", service, addr, rows)
	return exposureRow{}
}

func decided(t *testing.T, ls []listener, in exposureInputs) ([]exposureRow, []exposureRow) {
	t.Helper()
	rows, exposed, _, reason := decideExposure(ls, in)
	if reason != "" {
		t.Fatalf("undecided: %s", reason)
	}
	return rows, exposed
}

// Review Focus 1: policy drop; iif lo accept; ct state established,related
// accept; tcp dport 22 accept — 5432 on 0.0.0.0 is filtered, 22 exposed.
func TestExposureStateAndLoopbackAcceptsDoNotExpose(t *testing.T) {
	in := full(
		accept("inet", "input", "iif=lo"),
		accept("inet", "input", "ct=established,related"),
		accept("inet", "input", "proto=tcp dport=22"),
	)
	in.HasV6 = true
	rows, exposed := decided(t, []listener{lsn("tcp", "v4", "0.0.0.0", 5432), lsn("tcp", "v4", "0.0.0.0", 22)}, in)
	if r := expRow(t, rows, "tcp/5432", "0.0.0.0"); r.Exposed || r.Via != viaFiltered {
		t.Errorf("5432 %+v, want filtered", r)
	}
	if len(exposed) != 1 || exposed[0].Service != "tcp/22" || exposed[0].Via != viaRule || exposed[0].RuleChain != "input" {
		t.Errorf("exposed %+v, want tcp/22 via rule", exposed)
	}
}

func TestExposureOpenPolicyExposesEveryNonLoopback(t *testing.T) {
	in := exposureInputs{Confidence: "full", Restricts: falsePtr(), HasV6: true}
	ls := []listener{lsn("tcp", "v4", "0.0.0.0", 5432), lsn("udp", "v6", "::", 53), lsn("tcp", "v4", "127.0.0.1", 631), lsn("tcp", "v6", "::1", 631)}
	rows, exposed := decided(t, ls, in)
	if len(rows) != 2 || len(exposed) != 2 {
		t.Fatalf("rows %+v exposed %+v, want the two non-loopback listeners exposed", rows, exposed)
	}
	for _, r := range exposed {
		if r.Via != viaOpen {
			t.Errorf("%+v, want via open_policy", r)
		}
	}
}

func TestExposureAnyPortRule(t *testing.T) {
	in := full(accept("v4", "input", "saddr=192.0.2.0/24"), accept("v4", "input", "proto=tcp dport=22"))
	_, exposed := decided(t, []listener{lsn("tcp", "v4", "0.0.0.0", 5432)}, in)
	if len(exposed) != 1 || exposed[0].Via != viaAnyPort || exposed[0].RuleSource != "192.0.2.0/24" {
		t.Errorf("exposed %+v, want tcp/5432 via any_port_rule from 192.0.2.0/24", exposed)
	}
	// An accept with a daddr and no port names one address, not every port:
	// it is opaque, never an any-port rule.
	in = full(accept("v4", "input", "daddr=192.0.2.1"))
	if _, _, _, reason := decideExposure([]listener{lsn("tcp", "v4", "0.0.0.0", 5432)}, in); reason == "" {
		t.Error("an accept with a daddr and no port was decided")
	}
}

func TestExposurePortRuleRangeAndSet(t *testing.T) {
	in := full(
		accept("v4", "input", "proto=tcp dport=8000-8080"),
		accept("v4", "input", "proto=udp dport=1000:2000"),
		accept("v4", "input", "proto=tcp dport={_22,_443_}"),
		accept("v4", "input", "proto=tcp dport=25,587,993"),
	)
	ls := []listener{
		lsn("tcp", "v4", "0.0.0.0", 8000), lsn("tcp", "v4", "0.0.0.0", 8080), lsn("tcp", "v4", "0.0.0.0", 8081),
		lsn("udp", "v4", "0.0.0.0", 1500), lsn("tcp", "v4", "0.0.0.0", 1500),
		lsn("tcp", "v4", "0.0.0.0", 443), lsn("tcp", "v4", "0.0.0.0", 444),
		lsn("tcp", "v4", "0.0.0.0", 587), lsn("udp", "v4", "0.0.0.0", 587),
	}
	rows, _ := decided(t, ls, in)
	want := map[string]bool{"tcp/8000": true, "tcp/8080": true, "tcp/8081": false, "udp/1500": true, "tcp/1500": false,
		"tcp/443": true, "tcp/444": false, "tcp/587": true, "udp/587": false}
	for svc, exp := range want {
		if r := expRow(t, rows, svc, "0.0.0.0"); r.Exposed != exp {
			t.Errorf("%s exposed %v, want %v (%+v)", svc, r.Exposed, exp, r)
		}
	}
}

func TestExposureOpaqueRuleIsManual(t *testing.T) {
	op := accept("v4", "ufw-user-input", "proto=tcp unmodelled")
	op.Raw = "-A ufw-user-input -p tcp -m owner --uid-owner 0 -j ACCEPT"
	in := full(op, accept("v4", "input", "proto=tcp dport=22"))
	rows, exposed, opaque, reason := decideExposure([]listener{lsn("tcp", "v4", "0.0.0.0", 5432)}, in)
	if want := "opaque accept rule in ufw-user-input (filter, v4): -A ufw-user-input -p tcp -m owner --uid-owner 0 -j ACCEPT"; reason != want {
		t.Errorf("reason %q, want %q", reason, want)
	}
	if len(opaque) != 1 || opaque[0].Raw != op.Raw {
		t.Errorf("opaque %+v", opaque)
	}
	if len(exposed) != 0 || len(rows) != 1 || rows[0].Via != viaUndecided {
		t.Errorf("rows %+v exposed %+v, want one undecided row", rows, exposed)
	}
	// An opaque row of the other family does not stop a v4-only listener.
	in = full(accept("v6", "input", "proto=tcp unmodelled"), accept("v4", "input", "proto=tcp dport=22"))
	in.HasV6 = true
	if _, _, _, reason := decideExposure([]listener{lsn("tcp", "v4", "0.0.0.0", 5432)}, in); reason != "" {
		t.Errorf("a v6 opaque row stopped a v4 listener: %s", reason)
	}
	// ...but an inet one does.
	in = full(accept("inet", "input", "proto=tcp unmodelled"))
	if _, _, _, reason := decideExposure([]listener{lsn("tcp", "v4", "0.0.0.0", 5432)}, in); !strings.Contains(reason, "(filter, inet)") {
		t.Errorf("an inet opaque row did not stop a v4 listener: %q", reason)
	}
}

func TestExposurePartialConfidenceIsManual(t *testing.T) {
	in := full(accept("v4", "input", "proto=tcp dport=22"))
	in.Confidence, in.Restricts = "partial", nil
	rows, exposed, _, reason := decideExposure([]listener{lsn("tcp", "v4", "0.0.0.0", 22)}, in)
	if reason != "normalization confidence is partial" {
		t.Errorf("reason %q", reason)
	}
	if len(exposed) != 0 || rows[0].Via != viaUndecided {
		t.Errorf("rows %+v exposed %+v", rows, exposed)
	}
}

func TestExposureNoChainInFamilyExposesV6(t *testing.T) {
	in := full(accept("v4", "INPUT", "proto=tcp dport=22"))
	in.HasV6, in.BindV6Only = true, 1
	ls := []listener{lsn("tcp", "v6", "::", 5432), lsn("tcp", "v4", "0.0.0.0", 5432)}
	rows, _ := decided(t, ls, in)
	if r := expRow(t, rows, "tcp/5432", "::"); !r.Exposed || r.Via != viaNoChain {
		t.Errorf(":: row %+v, want exposed via no_chain_in_family", r)
	}
	if r := expRow(t, rows, "tcp/5432", "0.0.0.0"); r.Exposed {
		t.Errorf("0.0.0.0 row %+v, want filtered", r)
	}
	// A v6 drop base chain with no rule leaves no row; the base families
	// still name it, so the v6 listener is filtered, not unchained.
	in.BaseFamilies = map[string]bool{"v4": true, "v6": true}
	rows, _ = decided(t, ls, in)
	if r := expRow(t, rows, "tcp/5432", "::"); r.Exposed {
		t.Errorf("with an empty v6 drop chain the :: row %+v, want filtered", r)
	}
	// The rule is symmetric: a v6 chain alone leaves v4 unchained.
	in = full(accept("v6", "INPUT", "proto=tcp dport=22"))
	in.HasV6 = true
	if _, exposed := decided(t, []listener{lsn("tcp", "v4", "0.0.0.0", 5432)}, in); len(exposed) != 1 || exposed[0].Via != viaNoChain {
		t.Errorf("a v4 listener beside a v6-only chain: exposed %+v, want via no_chain_in_family", exposed)
	}
	// Without IPv6 on the host no v6 family is enabled to be unchained.
	in = full(accept("v4", "INPUT", "proto=tcp dport=22"))
	if _, exposed := decided(t, []listener{lsn("tcp", "v4", "0.0.0.0", 5432)}, in); len(exposed) != 0 {
		t.Errorf("a v4-only host: exposed %+v, want none", exposed)
	}
}

func TestExposureInetChainCoversBoth(t *testing.T) {
	in := full(accept("inet", "input", "proto=tcp dport=22"))
	in.HasV6, in.BindV6Only = true, 1
	ls := []listener{lsn("tcp", "v6", "::", 22), lsn("tcp", "v4", "0.0.0.0", 22), lsn("tcp", "v6", "::", 5432), lsn("tcp", "v4", "0.0.0.0", 5432)}
	rows, _ := decided(t, ls, in)
	for _, addr := range []string{"::", "0.0.0.0"} {
		if r := expRow(t, rows, "tcp/22", addr); !r.Exposed || r.Via != viaRule {
			t.Errorf("tcp/22 on %s %+v, want exposed via rule", addr, r)
		}
		if r := expRow(t, rows, "tcp/5432", addr); r.Exposed {
			t.Errorf("tcp/5432 on %s %+v, want filtered (inet covers both, no family is unchained)", addr, r)
		}
	}
}

// S7: an inet input chain beside a chain of one concrete family covers the
// other family too. nftables.service's `table inet filter` plus a legacy
// script's `table ip filter` INPUT DROP: a v6 listener on a port no rule
// admits is filtered by the inet chain, never no_chain_in_family because v6
// has no chain of its own.
func TestExposureInetChainCoversTheFamilyBesideAConcreteOne(t *testing.T) {
	in := full(accept("inet", "input", "proto=tcp dport=22"))
	in.HasV6, in.BindV6Only = true, 1
	in.BaseFamilies = map[string]bool{"inet": true, "v4": true}
	ls := []listener{lsn("tcp", "v6", "::", 5432), lsn("tcp", "v6", "2001:db8::10", 5433)}
	rows, exposed := decided(t, ls, in)
	if len(exposed) != 0 {
		t.Errorf("exposed %+v, want none", exposed)
	}
	for _, c := range []struct {
		service, addr string
	}{{"tcp/5432", "::"}, {"tcp/5433", "2001:db8::10"}} {
		if r := expRow(t, rows, c.service, c.addr); r.Exposed || r.Via != viaFiltered {
			t.Errorf("%s on %s %+v, want filtered by the inet chain, not no_chain_in_family", c.service, c.addr, r)
		}
	}
}

func TestExposureDualStackBindAsksBothFamilies(t *testing.T) {
	in := full(accept("v4", "INPUT", "proto=tcp dport=80"), accept("v6", "INPUT", "proto=tcp dport=22"))
	in.HasV6 = true
	ls := []listener{lsn("tcp", "v6", "::", 80)}
	_, exposed := decided(t, ls, in)
	if len(exposed) != 1 || exposed[0].Via != viaRule || !strings.Contains(exposed[0].RuleRaw, "80") {
		t.Errorf("bindv6only 0: exposed %+v, want tcp/80 via the v4 rule", exposed)
	}
	in.BindV6Only = 1
	if _, exposed := decided(t, ls, in); len(exposed) != 0 {
		t.Errorf("bindv6only 1: exposed %+v, want none", exposed)
	}
}

func TestExposureLinkLocalIsACandidate(t *testing.T) {
	in := full(accept("v6", "input", "proto=udp dport=546"), accept("v4", "input", "proto=tcp dport=22"))
	in.HasV6 = true
	ls := []listener{lsn("udp", "v6", "fe80::1", 546), lsn("tcp", "v4", "169.254.1.1", 8080)}
	rows, exposed := decided(t, ls, in)
	if r := expRow(t, rows, "udp/546", "fe80::1"); !r.LinkLocal || !r.Exposed {
		t.Errorf("fe80::1 %+v, want a link-local exposed row", r)
	}
	if r := expRow(t, rows, "tcp/8080", "169.254.1.1"); !r.LinkLocal || r.Exposed || r.Family != "v4" {
		t.Errorf("169.254.1.1 %+v, want a link-local filtered v4 row", r)
	}
	if len(exposed) != 1 {
		t.Errorf("exposed %+v", exposed)
	}
}

func TestExposureLoopbackNeverListed(t *testing.T) {
	in := exposureInputs{Confidence: "full", Restricts: falsePtr(), HasV6: true}
	ls := []listener{lsn("tcp", "v4", "127.0.0.53", 53), lsn("tcp", "v4", "127.1.2.3", 9000), lsn("tcp", "v6", "::1", 631)}
	// A row the socket table did not flag as loopback is still loopback by
	// its address.
	ls[1].Loopback = false
	rows, exposed := decided(t, ls, in)
	if len(rows) != 0 || len(exposed) != 0 {
		t.Errorf("rows %+v exposed %+v, want none", rows, exposed)
	}
}

func TestExposureServiceSpelling(t *testing.T) {
	if s := serviceOf("tcp6", 22); s != "tcp/22" {
		t.Errorf("serviceOf(tcp6, 22) = %q", s)
	}
	if s := serviceOf("UDP", 68); s != "udp/68" {
		t.Errorf("serviceOf(UDP, 68) = %q", s)
	}
	in := full(accept("v6", "input", "proto=tcp dport=22"))
	in.HasV6, in.BindV6Only = true, 1
	l := lsn("tcp6", "", "2001:db8::10", 22)
	rows, exposed := decided(t, []listener{l}, in)
	if rows[0].Service != "tcp/22" || rows[0].Proto != "tcp" || rows[0].Family != "v6" || len(exposed) != 1 {
		t.Errorf("rows %+v exposed %+v, want tcp/22 over v6, exposed by the tcp rule", rows, exposed)
	}
}

func TestExposureIrrelevantRulesDoNotBlock(t *testing.T) {
	in := full(
		accept("v4", "input", "proto=icmp"),
		fwRule{Chain: "input", Table: "filter", Family: "v4", Action: "log", Raw: "log prefix x"},
		fwRule{Chain: "input", Table: "filter", Family: "v4", Action: "drop", Unmodelled: true, Raw: "tcp flags syn drop"},
		accept("v4", "input", "proto=tcp dport=22"),
	)
	rows, exposed := decided(t, []listener{lsn("tcp", "v4", "0.0.0.0", 22), lsn("tcp", "v4", "0.0.0.0", 3306)}, in)
	if len(exposed) != 1 || exposed[0].Service != "tcp/22" || expRow(t, rows, "tcp/3306", "0.0.0.0").Via != viaFiltered {
		t.Errorf("rows %+v exposed %+v", rows, exposed)
	}
}

// A kernel-held socket is a listener like any other; its exposed row shows
// pid -1. The owner shown otherwise is the lowest pid.
func TestExposureExposedRowOwner(t *testing.T) {
	in := exposureInputs{Confidence: "full", Restricts: falsePtr()}
	k := lsn("udp", "v4", "0.0.0.0", 51820)
	k.OwnerStatus, k.Owners = "kernel", []owner{}
	two := lsn("tcp", "v4", "0.0.0.0", 22)
	two.Owners = []owner{{Pid: 812, Name: "sshd", Package: "openssh-server"}, {Pid: 1, Name: "systemd", Package: "systemd"}}
	_, exposed := decided(t, []listener{k, two}, in)
	for _, r := range exposed {
		m := r.exposedRecord()
		switch r.Service {
		case "udp/51820":
			if m["pid"] != -1 || m["name"] != "" || m["package"] != "" {
				t.Errorf("kernel row %v", m)
			}
		case "tcp/22":
			if m["pid"] != 1 || m["name"] != "systemd" {
				t.Errorf("tcp/22 row %v, want the lowest pid", m)
			}
		}
	}
	if len(exposed) != 2 {
		t.Errorf("exposed %+v", exposed)
	}
}

// With nothing to decide, a partial firewall does not stop the verdict:
// nothing listens off loopback, so nothing is exposed.
func TestExposureNoCandidateIsDecided(t *testing.T) {
	in := exposureInputs{Confidence: "partial"}
	rows, exposed, _, reason := decideExposure([]listener{lsn("tcp", "v4", "127.0.0.1", 631)}, in)
	if reason != "" || len(rows) != 0 || len(exposed) != 0 {
		t.Errorf("reason %q rows %+v exposed %+v", reason, rows, exposed)
	}
}

// W-76: IPv6 disabled by sysctl is no enabled family. A v4-only ruleset does
// not leave v6 unchained; a dual-stack socket is decided by its v4 side; a
// socket only v6 traffic reaches is unreachable.
func TestExposureIPv6DisabledIsNotAFamily(t *testing.T) {
	in := full(accept("v4", "INPUT", "proto=tcp dport=22"))
	in.HasV6, in.V6Disabled = true, true
	ls := []listener{lsn("tcp", "v6", "::", 5432), lsn("tcp", "v6", "::", 22), lsn("tcp", "v6", "2001:db8::10", 8080)}
	rows, _ := decided(t, ls, in)
	if r := expRow(t, rows, "tcp/5432", "::"); r.Exposed || r.Via != viaFiltered {
		t.Errorf("[::]:5432 %+v, want filtered by its v4 side", r)
	}
	if r := expRow(t, rows, "tcp/22", "::"); !r.Exposed || r.Via != viaRule {
		t.Errorf("[::]:22 %+v, want exposed by the v4 rule", r)
	}
	if r := expRow(t, rows, "tcp/8080", "2001:db8::10"); r.Exposed || r.Via != viaV6Off {
		t.Errorf("a v6 address %+v, want via ipv6_disabled", r)
	}
	in.BindV6Only = 1
	rows, _ = decided(t, ls, in)
	if r := expRow(t, rows, "tcp/22", "::"); r.Exposed || r.Via != viaV6Off {
		t.Errorf("bindv6only 1: [::]:22 %+v, want via ipv6_disabled", r)
	}
	// Enabled again: the old reading.
	in.BindV6Only, in.V6Disabled = 0, false
	rows, _ = decided(t, ls, in)
	if r := expRow(t, rows, "tcp/5432", "::"); !r.Exposed || r.Via != viaNoChain {
		t.Errorf("IPv6 on: [::]:5432 %+v, want via no_chain_in_family", r)
	}
}

// W-75: a dual-stack socket is decided when one family exposes it, whatever
// the other's opacity; it stays undecided when the only family that could
// decide it filters and the other is opaque.
func TestExposureDualStackOpacity(t *testing.T) {
	op4 := accept("v4", "INPUT", "proto=tcp unmodelled")
	op4.Raw = "-A INPUT -p tcp -m owner --uid-owner 0 -j ACCEPT"
	op6 := accept("v6", "INPUT", "proto=tcp unmodelled")
	op6.Raw = "-A INPUT -p tcp -m owner --uid-owner 0 -j ACCEPT"
	ls := []listener{lsn("tcp", "v6", "::", 5432)}
	for _, c := range []struct {
		name    string
		rules   []fwRule
		exposed bool
		reason  string
	}{
		{"v4 opaque, v6 filters", []fwRule{op4, accept("v6", "INPUT", "proto=tcp dport=22")}, false, "(filter, v4)"},
		{"v4 opaque, v6 accepts", []fwRule{op4, accept("v6", "INPUT", "proto=tcp dport=5432")}, true, ""},
		{"v6 opaque, v4 filters", []fwRule{op6, accept("v4", "INPUT", "proto=tcp dport=22")}, false, "(filter, v6)"},
		{"v6 opaque, v4 accepts", []fwRule{op6, accept("v4", "INPUT", "proto=tcp dport=5432")}, true, ""},
	} {
		in := full(c.rules...)
		in.HasV6 = true
		rows, exposed, _, reason := decideExposure(ls, in)
		switch {
		case c.exposed && (len(exposed) != 1 || exposed[0].Via != viaRule || reason != ""):
			t.Errorf("%s: exposed %+v reason %q, want exposed via rule", c.name, exposed, reason)
		case !c.exposed && (len(exposed) != 0 || rows[0].Via != viaUndecided || !strings.Contains(reason, c.reason)):
			t.Errorf("%s: rows %+v reason %q, want undecided naming %s", c.name, rows, reason, c.reason)
		}
	}
}
