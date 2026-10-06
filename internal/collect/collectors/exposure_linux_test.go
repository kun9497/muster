//go:build linux

package collectors

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The exposure verdict through the processes collector, and over the
// firewall's own parsers (linux-tagged: parseIptablesSave and
// normalizeRuleset live in firewall.go).

// ufwCapture is the iptables-save rendering of a ufw host with `limit 22/tcp`
// and `allow 80/tcp` (Task 2's fixture), as the firewall collector captured it.
func ufwCapture(t *testing.T) capture {
	t.Helper()
	data, err := os.ReadFile("testdata/iptables-save.ufw-allow-80")
	if err != nil {
		t.Fatal(err)
	}
	return capture{tool: "iptables", ok: true, dumps: []any{map[string]any{"source": iptablesSave, "content": string(data), "truncated": false}}}
}

// W-36: ufw's stock chains, folded as normalizeRuleset folds them, decide:
// 80 is exposed by ufw-user-input's accept, 22 through the limit chain, and
// nothing else is.
func TestExposureUfwDumpDecidesHTTP(t *testing.T) {
	cr := ufwCapture(t)
	_, rules := normalizeRuleset(cr)
	in := exposureInputs{Confidence: "full", Restricts: truePtr(), Rules: rules, Backend: "ufw", BaseFamilies: inputBaseFamilies(cr.dumps)}
	ls := []listener{lsn("tcp", "v4", "0.0.0.0", 80), lsn("tcp", "v4", "0.0.0.0", 22), lsn("tcp", "v4", "0.0.0.0", 5432)}
	rows, exposed, opaque, reason := decideExposure(ls, in)
	if reason != "" || len(opaque) != 0 {
		t.Fatalf("undecided: %q, opaque %+v", reason, opaque)
	}
	if r := expRow(t, rows, "tcp/80", "0.0.0.0"); !r.Exposed || r.Via != viaRule || r.RuleChain != "ufw-user-input" {
		t.Errorf("tcp/80 %+v, want exposed via rule in ufw-user-input", r)
	}
	if r := expRow(t, rows, "tcp/22", "0.0.0.0"); !r.Exposed || r.Via != viaRule || r.RuleChain != "ufw-user-limit-accept" {
		t.Errorf("tcp/22 %+v, want exposed via rule in ufw-user-limit-accept", r)
	}
	if r := expRow(t, rows, "tcp/5432", "0.0.0.0"); r.Exposed || r.Via != viaFiltered {
		t.Errorf("tcp/5432 %+v, want filtered", r)
	}
	if len(exposed) != 2 {
		t.Errorf("exposed %+v", exposed)
	}
}

// inputBaseFamilies names a family whose input base chain carries no rule,
// so firewall.rules has no row of it; when nft answered, an iptables-save
// dump a cross-check appended is not read.
func TestInputBaseFamiliesReadsEmptyChains(t *testing.T) {
	v4 := map[string]any{"source": iptablesSave, "content": "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"}
	v6 := map[string]any{"source": ip6tablesSave, "content": "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"}
	if got := inputBaseFamilies([]any{v4, v6}); !got["v4"] || !got["v6"] || len(got) != 2 {
		t.Errorf("iptables dumps: %v, want v4 and v6", got)
	}
	nft := map[string]any{"source": nftListRuleset, "content": "table ip6 filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"}
	if got := inputBaseFamilies([]any{nft, v4}); !got["v6"] || len(got) != 1 {
		t.Errorf("nft dump + appended legacy dump: %v, want v6 alone", got)
	}
}

// seedFirewall prepares a builder holding the firewall facts as the firewall
// collector writes them, from a capture normalised the collector's way.
func seedFirewall(t *testing.T, cr capture, confidence string, restricts facts.Envelope, backend string) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := collect.NewBuilder(reg)
	_, rules := normalizeRuleset(cr)
	recs := make([]any, 0, len(rules))
	for _, r := range rules {
		recs = append(recs, r.record())
	}
	src := &facts.Source{Kind: "command", Cmd: iptablesSave}
	b.Begin("firewall")
	b.Set("firewall.backend", collect.OK(backend, src))
	b.Set("firewall.rules", collect.OK(recs, src))
	b.Set("firewall.raw_dumps", collect.OK(cr.dumps, src))
	b.Set("firewall.normalization_confidence", collect.OK(confidence, src))
	b.Set("firewall.restricts_inbound", restricts)
	return b
}

// seedFirewallFailed is the firewall collector's degraded write: every
// runtime key carries the same envelope.
func seedFirewallFailed(t *testing.T, deg facts.Envelope) *collect.Builder {
	t.Helper()
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	b := collect.NewBuilder(reg)
	b.Begin("firewall")
	for _, k := range []string{"firewall.backend", "firewall.restricts_inbound", "firewall.normalization_confidence", "firewall.rules", "firewall.raw_dumps"} {
		b.Set(k, deg)
	}
	return b
}

// webHost listens on 22 (sshd), 80 (nginx), 5432 (postgres) on 0.0.0.0 and
// 631 (cupsd) on loopback.
func webHost() *fsAccess {
	tcp := procNetHeader +
		tcpRow(0, "00000000", 22, 7, tcpListen) +
		tcpRow(1, "00000000", 80, 8, tcpListen) +
		tcpRow(2, "00000000", 5432, 9, tcpListen) +
		tcpRow(3, "0100007F", 631, 10, tcpListen)
	return procHost([]byte(tcp), initProc(nil), kthreadd,
		sshdProc(map[int]string{3: "socket:[7]"}),
		fakeProc{pid: 900, ppid: 1, uid: 33, name: "nginx", exe: "/usr/sbin/nginx", fds: map[int]string{6: "socket:[8]"}},
		fakeProc{pid: 950, ppid: 1, uid: 113, name: "postgres", exe: "/usr/lib/postgresql/14/bin/postgres", fds: map[int]string{5: "socket:[9]"}},
		fakeProc{pid: 960, ppid: 1, uid: 0, name: "cupsd", exe: "/usr/sbin/cupsd", fds: map[int]string{7: "socket:[10]"}},
	)
}

var exposureKeys = []string{"exposure.listeners", "exposure.exposed", "exposure.opaque_rules", "exposure.stats"}

func TestProcessesWritesExposureFromTheFirewallFacts(t *testing.T) {
	b := seedFirewall(t, ufwCapture(t), "full", collect.OK(true, nil), "ufw")
	buildOn(t, "processes", webHost(), b)
	exposed := okList(t, b, "exposure.exposed")
	got := map[string]map[string]any{}
	for _, r := range exposed {
		m := r.(map[string]any)
		got[m["service"].(string)] = m
	}
	if len(got) != 2 || got["tcp/80"] == nil || got["tcp/22"] == nil {
		t.Fatalf("exposure.exposed %v, want tcp/22 and tcp/80", exposed)
	}
	if h := got["tcp/80"]; h["pid"] != 900 || h["name"] != "nginx" || h["via"] != "rule" || h["rule_chain"] != "ufw-user-input" || h["family"] != "v4" {
		t.Errorf("tcp/80 row %v", h)
	}
	if s := got["tcp/22"]; s["package"] != "openssh-server" || s["rule_chain"] != "ufw-user-limit-accept" {
		t.Errorf("tcp/22 row %v", s)
	}
	rows := okList(t, b, "exposure.listeners")
	if len(rows) != 3 {
		t.Errorf("exposure.listeners %v, want the three non-loopback listeners", rows)
	}
	for _, r := range rows {
		if m := r.(map[string]any); m["service"] == "tcp/5432" && (m["exposed"] != false || m["via"] != "filtered") {
			t.Errorf("tcp/5432 %v, want filtered", m)
		}
	}
	if o := okList(t, b, "exposure.opaque_rules"); len(o) != 0 {
		t.Errorf("opaque_rules %v", o)
	}
	st := env(t, b, "exposure.stats").Value.(map[string]any)
	if st["confidence"] != "full" || st["manual_reason"] != "" || st["listeners"] != 3 || st["exposed"] != 2 ||
		st["filtered"] != 1 || st["loopback"] != 1 || st["kernel_owned"] != 0 || st["folded_rules"] != 50 {
		t.Errorf("stats %v", st)
	}
}

// An opaque accept stops the verdict: exposure.exposed is absent naming it,
// and the stats and opaque_rules carry it where a report reader finds it.
func TestProcessesExposureOpaqueRuleIsAbsent(t *testing.T) {
	cr := capture{tool: "iptables", ok: true, dumps: []any{map[string]any{"source": iptablesSave,
		"content": "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp -m owner --uid-owner 0 -j ACCEPT\nCOMMIT\n", "truncated": false}}}
	b := seedFirewall(t, cr, "full", collect.OK(true, nil), "iptables")
	buildOn(t, "processes", webHost(), b)
	e := env(t, b, "exposure.exposed")
	want := "opaque accept rule in INPUT (filter, v4): -A INPUT -p tcp -m owner --uid-owner 0 -j ACCEPT"
	if e.Status != facts.StatusAbsent || e.Reason != want {
		t.Errorf("exposure.exposed %+v, want absent %q", e, want)
	}
	if st := env(t, b, "exposure.stats").Value.(map[string]any); st["manual_reason"] != want || st["opaque_rules"] != 1 {
		t.Errorf("stats %v", st)
	}
	if o := okList(t, b, "exposure.opaque_rules"); len(o) != 1 {
		t.Errorf("opaque_rules %v", o)
	}
}

func TestProcessesExposurePartialConfidenceIsAbsent(t *testing.T) {
	b := seedFirewall(t, ufwCapture(t), "partial", collect.Absent("firewall confidence partial"), "firewalld")
	buildOn(t, "processes", webHost(), b)
	if e := env(t, b, "exposure.exposed"); e.Status != facts.StatusAbsent || e.Reason != "normalization confidence is partial" {
		t.Errorf("exposure.exposed %+v", e)
	}
	if e := env(t, b, "exposure.listeners"); e.Status != facts.StatusOK {
		t.Errorf("exposure.listeners %+v: evidence stays readable", e)
	}
	if st := env(t, b, "exposure.stats").Value.(map[string]any); st["manual_reason"] != "normalization confidence is partial" {
		t.Errorf("stats %v", st)
	}
}

func TestProcessesExposureErrorsWhenFirewallFactsMissing(t *testing.T) {
	b := build(t, "processes", webHost())
	for _, k := range exposureKeys {
		if e := env(t, b, k); e.Status != facts.StatusError || !strings.Contains(e.Reason, "firewall.normalization_confidence") {
			t.Errorf("%s = %+v, want error naming firewall.normalization_confidence", k, e)
		}
	}
}

func TestProcessesExposureCarriesTheFirewallStatus(t *testing.T) {
	for _, deg := range []facts.Envelope{
		collect.Unsupported("no readable kernel firewall ruleset: nft: not found"),
		collect.Denied("reading the kernel firewall ruleset requires root"),
	} {
		b := seedFirewallFailed(t, deg)
		buildOn(t, "processes", webHost(), b)
		for _, k := range exposureKeys {
			if e := env(t, b, k); e.Status != deg.Status || !strings.Contains(e.Reason, deg.Reason) {
				t.Errorf("%s = %+v, want %s carrying %q", k, e, deg.Status, deg.Reason)
			}
		}
	}
}

func TestProcessesExposureCarriesDeniedListeners(t *testing.T) {
	a := webHost()
	a.deniedDirs = map[string]bool{"/proc/950/fd": true}
	b := seedFirewall(t, ufwCapture(t), "full", collect.OK(true, nil), "ufw")
	buildOn(t, "processes", a, b)
	for _, k := range []string{"exposure.exposed", "exposure.listeners"} {
		if e := env(t, b, k); e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "/proc/950/fd") {
			t.Errorf("%s = %+v, want denied naming /proc/950/fd", k, e)
		}
	}
	if e := env(t, b, "exposure.opaque_rules"); e.Status != facts.StatusOK {
		t.Errorf("opaque_rules %+v: the firewall was read", e)
	}
}

// A masked procfs leaves the processes collector early; the exposure keys are
// still written, carrying the socket read's status.
func TestProcessesExposureWrittenOnAnEarlyReturn(t *testing.T) {
	a := webHost()
	delete(a.contents, "/proc/self/net/tcp")
	b := seedFirewall(t, ufwCapture(t), "full", collect.OK(true, nil), "ufw")
	buildOn(t, "processes", a, b)
	if e := env(t, b, "exposure.exposed"); e.Status != facts.StatusUnsupported {
		t.Errorf("exposure.exposed %+v, want unsupported", e)
	}
}

// A socket on :: on a host whose bindv6only cannot be read cannot be told
// v6-only from dual-stack: exposure.exposed carries the read's status (C3).
func TestProcessesExposureBindV6OnlyUnreadable(t *testing.T) {
	a := webHost()
	a.contents["/proc/self/net/tcp6"] = []byte(procNetHeader + tcpRow(0, "00000000000000000000000000000000", 8080, 11, tcpListen))
	a.links[procPath(900, "fd/7")] = "socket:[11]"
	a.fails["/proc/sys/net/ipv6/bindv6only"] = fmt.Errorf("%s: %w", "/proc/sys/net/ipv6/bindv6only", unix.EACCES)
	b := seedFirewall(t, ufwCapture(t), "full", collect.OK(true, nil), "ufw")
	buildOn(t, "processes", a, b)
	if e := env(t, b, "exposure.exposed"); e.Status != facts.StatusDenied || !strings.Contains(e.Reason, "bindv6only") {
		t.Errorf("exposure.exposed %+v, want denied naming bindv6only", e)
	}
	// Readable and 0: the :: socket asks the v4 rules too; ufw's v4 table has
	// no accept for 8080, and no v6 chain exists while v4 has one.
	delete(a.fails, "/proc/sys/net/ipv6/bindv6only")
	a.contents["/proc/sys/net/ipv6/bindv6only"] = []byte("0\n")
	b = seedFirewall(t, ufwCapture(t), "full", collect.OK(true, nil), "ufw")
	buildOn(t, "processes", a, b)
	for _, r := range okList(t, b, "exposure.exposed") {
		if m := r.(map[string]any); m["service"] == "tcp/8080" && m["via"] != "no_chain_in_family" {
			t.Errorf("tcp/8080 on :: %v, want via no_chain_in_family", m)
		}
	}
}
